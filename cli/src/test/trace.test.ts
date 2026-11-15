import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { failureRewriter, makeSecretScrubber } from "../report/redact.js";
import { TraceRecorder } from "../trace.js";
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

  it("never throws on a message it cannot serialise", () => {
    const t = new TraceRecorder();
    const loop: Record<string, unknown> = { jsonrpc: "2.0", id: 1 };
    loop.self = loop;
    assert.doesNotThrow(() => t.record({ session: 0, dir: "recv", message: loop }));
    assert.doesNotThrow(() => t.record({ session: 0, dir: "recv", message: { id: 2n } }));
    assert.doesNotThrow(() => t.text());
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

  it("without --trace no trace file is written", () => {
    const cfg = toyConfig("trace3.yaml", "nosql");
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json", "--out", join(dir, "plain.json")]);
    assert.equal(r.code, 0, r.err);
    assert.ok(!/trace written/.test(r.err));
  });
});
