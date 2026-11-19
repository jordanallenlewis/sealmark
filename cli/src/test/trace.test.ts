import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { failureRewriter, makeSecretScrubber } from "../report/redact.js";
import { CallIndex, MAX_LINKED_CALLS, TraceRecorder } from "../trace.js";
import type { RunResult } from "../types.js";
import { FAST, cliKit, srv } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-trace-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, toyConfig, writeYaml } = cliKit(() => dir);

interface Line {
  seq: number;
  ms: number;
  session: number;
  dir: "send" | "recv";
  message: { id?: number | string; method?: string; result?: unknown; error?: unknown; params?: unknown };
}

const parse = (text: string): Line[] =>
  text
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Line);

describe("trace: recorder", () => {
  it("numbers the messages, keeps their direction and session, and writes one JSON object per line", () => {
    const t = new TraceRecorder();
    t.record({ session: 0, dir: "send", message: { jsonrpc: "2.0", id: 1, method: "initialize" } });
    t.record({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: 1, result: {} } });
    const lines = parse(t.text());
    assert.deepEqual(lines.map((l) => [l.seq, l.session, l.dir, l.message.id]), [
      [1, 0, "send", 1],
      [2, 0, "recv", 1],
    ]);
    assert.ok(lines.every((l) => typeof l.ms === "number" && l.ms >= 0));
    assert.ok(t.text().endsWith("\n"));
  });

  it("scrubs a secret anywhere in a message before it is kept", () => {
    const secret = "sk-live-0123456789abcdef";
    const t = new TraceRecorder();
    t.record({ session: 1, dir: "send", message: { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "q", arguments: { token: secret, nested: [`Bearer ${secret}`] } } } });
    t.record({ session: 1, dir: "recv", message: { jsonrpc: "2.0", id: 7, result: { content: [{ type: "text", text: `echo ${secret}` }] } } });
    const out = t.text(makeSecretScrubber([secret]));
    assert.ok(!out.includes(secret), out);
    assert.equal(parse(out).length, 2);
    // The recorder keeps the message as it was; only the written text is rewritten (the rewrite depends on the run's result).
    assert.ok(t.text().includes(secret));
  });

  it("rewrites a JWT and a sandbox path the way a report does", () => {
    const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzbS13aG8tMDEyMzQ1NjcifQ.c2lnbmF0dXJlLWJ5dGVzLWhlcmU";
    const t = new TraceRecorder();
    t.record({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: 3, result: { content: [{ type: "text", text: `token ${jwt} at /var/tmp/sealmark-0123456789/root/a.txt` }] } } });
    const out = t.text(failureRewriter({ secrets: [] }));
    assert.ok(!out.includes(jwt), out);
    assert.match(out, /\{jwt\}/);
    assert.ok(!out.includes("/var/tmp/sealmark-0123456789"), out);
    assert.equal(t.text(failureRewriter({ redact: false })).includes(jwt), true);
  });

  it("stops keeping messages at the size cap and says how many it dropped", () => {
    const t = new TraceRecorder(400);
    for (let i = 0; i < 20; i++) t.record({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: i, result: { text: "x".repeat(50) } } });
    const lines = t.text().split("\n").filter(Boolean);
    const last = JSON.parse(lines[lines.length - 1]) as { truncated?: boolean; dropped?: number; limit_bytes?: number };
    assert.equal(last.truncated, true);
    assert.equal(last.limit_bytes, 400);
    assert.equal((last.dropped ?? 0) + lines.length - 1, 20);
    assert.ok(Buffer.byteLength(lines.slice(0, -1).join("\n")) <= 400);
  });

  it("returns the line number of a kept message, and nothing for a dropped one", () => {
    const t = new TraceRecorder(200);
    assert.equal(t.record({ session: 0, dir: "send", message: { jsonrpc: "2.0", id: 1, method: "ping" } }), 1);
    let last: number | undefined = 1;
    for (let i = 0; i < 10; i++) last = t.record({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: i, result: { text: "x".repeat(50) } } });
    assert.equal(last, undefined);
  });

  it("never throws on a message it cannot serialise", () => {
    const t = new TraceRecorder();
    const loop: Record<string, unknown> = { jsonrpc: "2.0", id: 1 };
    loop.self = loop;
    assert.doesNotThrow(() => t.record({ session: 0, dir: "recv", message: loop }));
    assert.doesNotThrow(() => t.record({ session: 0, dir: "recv", message: { id: 2n } }));
    assert.doesNotThrow(() => t.text());
  });
});

describe("trace: call index", () => {
  const send = (session: number, id: number, name: string, args: unknown) => ({ session, dir: "send" as const, message: { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } } });
  const recv = (session: number, id: number) => ({ session, dir: "recv" as const, message: { jsonrpc: "2.0", id, result: { content: [] } } });

  it("finds the request with this tool and these arguments, and its reply, in the sessions asked for", () => {
    const ix = new CallIndex();
    ix.observe(send(0, 5, "read", { path: "a", n: 1 }), 10);
    ix.observe(recv(0, 5), 11);
    ix.observe(send(1, 5, "read", { path: "a", n: 1 }), 12);
    ix.observe(recv(1, 5), 13);
    // key order does not matter
    assert.deepEqual(ix.find([0], "read", { n: 1, path: "a" }), { calls: [{ session: 0, request: 10, response: 11 }] });
    assert.deepEqual(ix.find([0, 1], "read", { path: "a", n: 1 }), { calls: [{ session: 0, request: 10, response: 11 }, { session: 1, request: 12, response: 13 }] });
    assert.equal(ix.find([2], "read", { path: "a", n: 1 }), undefined);
    assert.equal(ix.find([0], "read", { path: "b", n: 1 }), undefined);
    assert.equal(ix.find([0], "write", { path: "a", n: 1 }), undefined);
  });

  it("links no line the trace did not keep, and no reply that is a server request", () => {
    const ix = new CallIndex();
    ix.observe(send(0, 1, "t", {}), undefined);
    ix.observe(recv(0, 1), 3);
    assert.equal(ix.find([0], "t", {}), undefined);
    ix.observe(send(0, 2, "t", { a: 1 }), 4);
    ix.observe({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: 2, method: "sampling/createMessage", params: {} } }, 5);
    ix.observe(recv(0, 2), undefined);
    assert.deepEqual(ix.find([0], "t", { a: 1 }), { calls: [{ session: 0, request: 4 }] });
  });

  it("ignores everything that is not a tools/call request, and a reply in another session", () => {
    const ix = new CallIndex();
    ix.observe({ session: 0, dir: "send", message: { jsonrpc: "2.0", id: 1, method: "tools/list" } }, 1);
    ix.observe({ session: 0, dir: "send", message: { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 9 } } }, 2);
    ix.observe({ session: 0, dir: "send", message: null }, 3);
    ix.observe(send(0, 7, "t", { a: 1 }), 4);
    ix.observe(recv(1, 7), 5);
    assert.deepEqual(ix.find([0], "t", { a: 1 }), { calls: [{ session: 0, request: 4 }] });
    assert.equal(ix.find([0], "t", undefined), undefined);
  });

  it("gives a request the harness cancelled no reply, even when one comes late", () => {
    const ix = new CallIndex();
    ix.observe(send(0, 4, "slow", {}), 1);
    ix.observe({ session: 0, dir: "send", message: { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 4, reason: "timeout" } } }, 2);
    ix.observe(recv(0, 4), 3);
    assert.deepEqual(ix.find([0], "slow", {}), { calls: [{ session: 0, request: 1 }] });
  });

  it("matches a reply whose id is the request's number written as a string, as the SDK does", () => {
    const ix = new CallIndex();
    ix.observe(send(0, 3, "t", {}), 1);
    ix.observe({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: "3", result: {} } }, 2);
    assert.deepEqual(ix.find([0], "t", {}), { calls: [{ session: 0, request: 1, response: 2 }] });
    ix.observe(send(0, 8, "u", {}), 3);
    ix.observe({ session: 0, dir: "recv", message: { jsonrpc: "2.0", id: "x8", result: {} } }, 4);
    assert.deepEqual(ix.find([0], "u", {}), { calls: [{ session: 0, request: 3 }] });
  });

  it("keeps at most MAX_LINKED_CALLS links and counts the rest", () => {
    const ix = new CallIndex();
    for (let i = 0; i < MAX_LINKED_CALLS + 3; i++) ix.observe(send(0, i, "t", {}), i + 1);
    const r = ix.find([0], "t", {});
    assert.equal(r?.calls.length, MAX_LINKED_CALLS);
    assert.equal(r?.more, 3);
    assert.deepEqual(r?.calls.map((c) => c.request), Array.from({ length: MAX_LINKED_CALLS }, (_, i) => i + 1));
  });
});

describe("cli: run --trace", { timeout: 300_000 }, () => {
  it("writes every JSON-RPC message of the run, and the report is the same as without it", () => {
    const cfg = toyConfig("trace.yaml", "nosql");
    const tracePath = join(dir, "run.trace.jsonl");
    const traced = sealmark(["run", "--config", cfg, ...FAST, "--format", "json", "--trace", tracePath]);
    assert.equal(traced.code, 0, traced.err);
    assert.ok(existsSync(tracePath), traced.err);
    assert.match(traced.err, /trace written to .*run\.trace\.jsonl/);
    const lines = parse(readFileSync(tracePath, "utf8"));
    assert.ok(lines.length > 4, `only ${lines.length} lines`);
    assert.equal(lines[0].dir, "send");
    assert.equal(lines[0].message.method, "initialize");
    const methods = new Set(lines.filter((l) => l.dir === "send").map((l) => l.message.method));
    for (const m of ["initialize", "tools/list", "tools/call"]) assert.ok(methods.has(m), `no ${m} in ${[...methods].join(", ")}`);
    // Every request the harness sent and that was answered has its reply in the same session.
    const answered = new Set(lines.filter((l) => l.dir === "recv" && l.message.id !== undefined).map((l) => `${l.session}:${l.message.id}`));
    const asked = lines.filter((l) => l.dir === "send" && l.message.id !== undefined && l.message.method === "tools/list");
    assert.ok(asked.length > 0);
    for (const a of asked) assert.ok(answered.has(`${a.session}:${a.message.id}`), `tools/list ${a.session}:${a.message.id} has no reply`);
    assert.deepEqual(lines.map((l) => l.seq), lines.map((_, i) => i + 1));

    const plain = sealmark(["run", "--config", cfg, ...FAST, "--format", "json"]);
    assert.equal(plain.code, 0, plain.err);
    const verdicts = (out: string) => {
      const r = JSON.parse(out) as RunResult;
      return { hash: r.config?.hash, packs: Object.fromEntries(Object.entries(r.packs).map(([k, p]) => [k, `${p?.status}:${p?.grade?.letter ?? "-"}`])), checks: r.checks.map((c) => `${c.id}:${c.verdict}`) };
    };
    assert.deepEqual(verdicts(traced.out), verdicts(plain.out));
  });

  it("with several servers writes one trace per server, the server name before the extension", () => {
    const cfg = writeYaml("trace-matrix.yaml", `schema_version: 1\nname: matrix\nversion: 1.0.0\nservers:\n  clean:\n    ${srv("nosql")}\n  other:\n    ${srv("nosql")}\n`);
    const p = join(dir, "m.trace.jsonl");
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json", "--trace", p]);
    assert.equal(r.code, 0, r.err);
    for (const n of ["clean", "other"]) {
      const f = join(dir, `m.trace.${n}.jsonl`);
      assert.ok(existsSync(f), `${f} missing: ${r.err}`);
      assert.equal(parse(readFileSync(f, "utf8"))[0].message.method, "initialize");
    }
    assert.ok(!existsSync(p));
  });

  it("an unwritable --trace path is a usage error before anything starts", () => {
    const cfg = toyConfig("trace2.yaml", "nosql");
    // A path under a regular file can never be created.
    const r = sealmark(["run", "--config", cfg, ...FAST, "--trace", join(cfg, "t.jsonl")]);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /--trace/);
  });

  it("links each check to the trace sessions its test area used, and only with --trace", () => {
    // The net toy, so two test areas run and the link has to tell their sessions apart: net opens sessions of its own.
    const NET = fileURLToPath(new URL("../toy/net.js", import.meta.url));
    const sandboxes = join(dir, "sandboxes");
    mkdirSync(sandboxes, { recursive: true });
    const cfg = writeYaml("trace4.yaml", `name: links\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([NET, "--mode", "good"])}\nsandbox:\n  dir: ${JSON.stringify(sandboxes)}\n`);
    const tracePath = join(dir, "links.trace.jsonl");
    const TWO = ["--pack", "core", "--pack", "net", "--timeout-probe", "2", "--fail-under", "none"];
    const traced = sealmark(["run", "--config", cfg, ...TWO, "--format", "json", "--trace", tracePath]);
    assert.equal(traced.code, 0, traced.err);
    const inTrace = new Set(parse(readFileSync(tracePath, "utf8")).map((l) => l.session));
    const r = JSON.parse(traced.out) as RunResult;
    const owner = new Map<number, string>();
    let linked = 0;
    for (const c of r.checks) {
      // refusal-quality is computed afterwards from every pack's evidence, so no one session decided it.
      if (c.id === "refusal-quality") {
        assert.equal(c.trace, undefined);
        continue;
      }
      assert.ok(c.trace && c.trace.sessions.length > 0, `${c.id} has no trace link`);
      for (const n of c.trace.sessions) {
        assert.ok(inTrace.has(n), `${c.id} names session ${n}, which is not in the trace`);
        // a session belongs to one test area
        assert.equal(owner.get(n) ?? c.pack, c.pack, `session ${n} is named by ${owner.get(n)} and ${c.pack}`);
        owner.set(n, c.pack);
      }
      linked++;
    }
    assert.ok(linked > 3, `only ${linked} checks linked`);
    assert.ok(r.checks.filter((c) => c.pack === "core" && c.id !== "refusal-quality").every((c) => c.trace?.sessions.includes(0)), "core checks do not name the first session");

    assert.ok(owner.size > 1 && new Set(owner.values()).size > 1, `sessions of only one test area: ${JSON.stringify([...owner])}`);

    const plain = sealmark(["run", "--config", cfg, ...TWO, "--format", "json"]);
    assert.equal(plain.code, 0, plain.err);
    assert.ok((JSON.parse(plain.out) as RunResult).checks.every((c) => c.trace === undefined), "a check names trace sessions without --trace");
  });

  /** Every evidence link must point to a tools/call request with that tool and those arguments, in a session of the check, and to its reply. Returns the linked packs. */
  const checkLinks = (r: RunResult, traceText: string): { packs: Set<string>; linked: number } => {
    const bySeq = new Map(parse(traceText).map((l) => [l.seq, l]));
    const canon = (v: unknown): string => JSON.stringify(v, (_k, x: unknown) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x));
    const packs = new Set<string>();
    let linked = 0;
    for (const c of r.checks) {
      for (const e of c.evidence) {
        if (!e.trace) continue;
        assert.notEqual(c.id, "refusal-quality", "refusal-quality evidence is linked");
        assert.ok(e.tool && e.args !== undefined, `${c.id}: a link on evidence with no tool call`);
        assert.ok(e.trace.calls.length > 0);
        for (const call of e.trace.calls) {
          assert.ok(c.trace?.sessions.includes(call.session), `${c.id}: linked session ${call.session} is not one of the check's sessions`);
          const req = bySeq.get(call.request);
          assert.ok(req, `${c.id}: line ${call.request} is not in the trace`);
          assert.equal(req.session, call.session);
          assert.equal(req.dir, "send");
          assert.equal(req.message.method, "tools/call");
          const params = req.message.params as { name: string; arguments?: unknown };
          assert.equal(params.name, e.tool);
          assert.equal(canon(params.arguments ?? {}), canon(e.args));
          if (call.response !== undefined) {
            const res = bySeq.get(call.response);
            assert.ok(res && res.dir === "recv" && res.session === call.session && res.message.id === req.message.id && res.seq > req.seq, `${c.id}: line ${call.response} is not the reply to ${call.request}`);
          }
        }
        linked++;
        packs.add(c.pack);
      }
    }
    return { packs, linked };
  };

  it("links a call's evidence to the request with that tool and those arguments, and its reply, in the check's own sessions", () => {
    // net opens sessions of its own, so a link has to stay inside the check's test area.
    const NET = fileURLToPath(new URL("../toy/net.js", import.meta.url));
    const sandboxes = join(dir, "sandboxes5");
    mkdirSync(sandboxes, { recursive: true });
    const cfg = writeYaml("trace5.yaml", `name: calls\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([NET, "--mode", "good"])}\nsandbox:\n  dir: ${JSON.stringify(sandboxes)}\n`);
    const tracePath = join(dir, "calls.trace.jsonl");
    const TWO = ["--pack", "core", "--pack", "net", "--timeout-probe", "2", "--fail-under", "none"];
    const traced = sealmark(["run", "--config", cfg, ...TWO, "--format", "json", "--trace", tracePath]);
    assert.equal(traced.code, 0, traced.err);
    const { packs, linked } = checkLinks(JSON.parse(traced.out) as RunResult, readFileSync(tracePath, "utf8"));
    assert.ok(linked > 3, `only ${linked} evidence lines linked`);
    assert.ok(packs.has("net"), `links only in ${[...packs].join(", ")}`);

    const plain = sealmark(["run", "--config", cfg, ...TWO, "--format", "json"]);
    assert.equal(plain.code, 0, plain.err);
    const p = JSON.parse(plain.out) as RunResult;
    assert.ok(p.checks.every((c) => c.evidence.every((e) => e.trace === undefined)), "evidence is linked without --trace");
    const verdicts = (x: RunResult) => ({ packs: Object.fromEntries(Object.entries(x.packs).map(([k, v]) => [k, `${v?.status}:${v?.grade?.letter ?? "-"}`])), checks: x.checks.map((c) => `${c.id}:${c.verdict}`) });
    assert.deepEqual(verdicts(JSON.parse(traced.out) as RunResult), verdicts(p));
  });

  it("fs: links evidence whose arguments are what was sent, and not evidence shown with sandbox placeholders", () => {
    const FS = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
    const sandboxes = join(dir, "sandboxes7");
    mkdirSync(sandboxes, { recursive: true });
    const cfg = writeYaml("trace7.yaml", `name: fs-calls\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([FS, "--mode", "traverse", "--root", "{sandbox}"])}\nsandbox:\n  dir: ${JSON.stringify(sandboxes)}\n`);
    const tracePath = join(dir, "fs.trace.jsonl");
    const traced = sealmark(["run", "--config", cfg, "--pack", "fs", "--timeout-probe", "2", "--fail-under", "none", "--format", "json", "--trace", tracePath]);
    assert.ok(traced.code === 0 || traced.code === 1 || traced.code === 3, traced.err);
    const r = JSON.parse(traced.out) as RunResult;
    const { packs } = checkLinks(r, readFileSync(tracePath, "utf8"));
    assert.ok(packs.has("fs"), "no fs evidence linked");
    const shown = r.checks.filter((c) => c.pack === "fs").flatMap((c) => c.evidence).filter((e) => e.tool && JSON.stringify(e.args ?? null).includes("{sandbox}"));
    assert.ok(shown.length > 0, "the fs toy run has no placeholder evidence to check");
    assert.ok(shown.every((e) => e.trace === undefined), "evidence shown with {sandbox} is linked");
  });

  it("links a failed core check's evidence to the call that failed it", () => {
    // robust-r5 typeerror: a schema-invalid call ends in an unhandled runtime error, recorded with its tool and arguments.
    const TOY = fileURLToPath(new URL("../toy/robust-r5.js", import.meta.url));
    const cfg = writeYaml("trace6.yaml", `name: core-calls\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--mode", "typeerror"])}\n`);
    const tracePath = join(dir, "core.trace.jsonl");
    const traced = sealmark(["run", "--config", cfg, "--pack", "core", "--timeout-probe", "6", "--fail-under", "none", "--format", "json", "--trace", tracePath]);
    assert.ok(traced.code === 0 || traced.code === 1, traced.err);
    const r = JSON.parse(traced.out) as RunResult;
    assert.notEqual(r.checks.find((c) => c.id === "robust-input")?.verdict, "pass");
    const { packs } = checkLinks(r, readFileSync(tracePath, "utf8"));
    assert.ok(packs.has("core"), "no core evidence linked");
    assert.ok(r.checks.find((c) => c.id === "robust-input")!.evidence.some((e) => e.trace && e.code === "robust.internal-error"), "the failing call is not linked");
  });

  it("without --trace no trace file is written", () => {
    const cfg = toyConfig("trace3.yaml", "nosql");
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json", "--out", join(dir, "plain.json")]);
    assert.equal(r.code, 0, r.err);
    assert.ok(!/trace written/.test(r.err));
  });
});
