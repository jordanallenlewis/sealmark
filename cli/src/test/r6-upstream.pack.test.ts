// Round 6, package P6: the `upstream` pack against the credential toy (toy/cred-r6.ts) with a fake upstream stub and a fake log.
// The stub, the log observer and the identities are fakes written against the interfaces of the design notes 2.2 (types.ts).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { McpSession } from "../mcp.js";
import { pack } from "../packs/upstream.js";
import { CRED_TOY_MODES, startCredToy, type CredToyMode } from "../toy/cred-r6.js";
import type { CheckResult, EffectiveConfig, IdentityName, LogObserver, PackCtx, PackId, SealmarkConfig, UpstreamMode, UpstreamRequest, UpstreamStub, Verdict } from "../types.js";
import { effectiveFor } from "./packctx.js";

const tmp = mkdtempSync(join(tmpdir(), "sm-r6-up-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

// ---- fakes ------------------------------------------------------------------------------------------------

interface FakeStub extends UpstreamStub {
  modeLog: { mode: UpstreamMode; delayMs?: number }[];
}

async function fakeStub(): Promise<FakeStub> {
  const reqs: UpstreamRequest[] = [];
  const errorCanary = `sm-upstream-err-${randomBytes(4).toString("hex")}`;
  const modeLog: FakeStub["modeLog"] = [];
  let mode: UpstreamMode = "normal";
  let delayMs = 0;
  const timers = new Set<NodeJS.Timeout>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const u = new URL(req.url ?? "/", "http://stub");
      const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
      const body = Buffer.concat(chunks).toString("utf8");
      const respond = (status: number, text: string, held: number) => {
        reqs.push({ id: reqs.length + 1, at: Date.now(), method: req.method ?? "GET", path: u.pathname, query: u.search, headers, body, bodyTruncated: false, reply: { status, bytes: text.length, ruleId: mode === "normal" ? "default" : `mode:${mode}`, delayMs: held }, minted: [] });
        res.writeHead(status, { "content-type": "application/json" });
        res.end(text);
      };
      // Recorded on arrival, answered after the hold, like the real stub.
      if (mode === "error") return respond(500, JSON.stringify({ error: errorCanary, received: { authorization: headers.authorization ?? null } }), 0);
      const normal = JSON.stringify({ rows: [{ id: 1 }], count: 1 });
      if (mode === "slow") {
        const held = delayMs;
        reqs.push({ id: reqs.length + 1, at: Date.now(), method: req.method ?? "GET", path: u.pathname, query: u.search, headers, body, bodyTruncated: false, reply: { status: 200, bytes: normal.length, ruleId: "mode:slow", delayMs: held }, minted: [] });
        const t = setTimeout(() => {
          timers.delete(t);
          if (!res.destroyed) {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(normal);
          }
        }, held);
        timers.add(t);
        return;
      }
      respond(200, normal, 0);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  const find = (needle: string, since = 0) => reqs.filter((r) => r.id > since && JSON.stringify([r.path, r.query, r.headers, r.body]).toLowerCase().includes(needle.toLowerCase()));
  return {
    kind: "http",
    url: `http://127.0.0.1:${port}`,
    port,
    errorCanary,
    modeLog,
    mark: () => reqs.length,
    requests: (since = 0) => reqs.filter((r) => r.id > since),
    find,
    setMode(m, o) {
      mode = m;
      delayMs = o?.delayMs ?? 0;
      modeLog.push({ mode: m, ...(o?.delayMs !== undefined ? { delayMs: o.delayMs } : {}) });
    },
    setOverride() {},
    async waitFor(needle, _t, since) {
      return find(needle, since);
    },
    async close() {
      for (const t of timers) clearTimeout(t);
      await new Promise<void>((r) => {
        server.close(() => r());
        server.closeAllConnections();
      });
    },
  };
}

function fakeLog(): LogObserver & { push(s: string): void } {
  let buf = "";
  return {
    sources: ["launched"],
    push: (s) => void (buf += s),
    mark: () => buf.length,
    since: (m) => buf.slice(m),
    all: () => buf,
    find: (needle, since = 0) => buf.indexOf(needle, since),
  };
}

// ---- a run --------------------------------------------------------------------------------------------------

interface Setup {
  mode: CredToyMode;
  /** Replaces the server headers the config declares (default `Authorization: Bearer {bearer}`). */
  headers?: Record<string, string>;
  url?: string | null;
  probes?: unknown[];
  checks?: EffectiveConfig["checks"];
  backendTimeoutMs?: number;
  noLog?: boolean;
  noStub?: boolean;
  failOpenAs?: boolean;
}

const BEARERS = { a: `sm-bearer-a-${randomBytes(6).toString("hex")}`, b: `sm-bearer-b-${randomBytes(6).toString("hex")}` };
const PROBES = [{ tool: "lookup", args: { id: "rec-1" } }];

async function runPack(s: Setup): Promise<{ checks: CheckResult[]; stub: FakeStub; log: ReturnType<typeof fakeLog>; ctx: PackCtx }> {
  const stub = await fakeStub();
  const log = fakeLog();
  const toy = await startCredToy(s.mode, { backend: stub.url, backendTimeoutMs: s.backendTimeoutMs ?? 1500, log: (l) => log.push(`${l}\n`) });
  const sessions: McpSession[] = [];
  const specFor = (name: IdentityName | null) => ({ url: toy.url, ...(name ? { headers: { Authorization: `Bearer ${BEARERS[name]}` } } : {}) });
  const open = async (name: IdentityName | null) => {
    if (s.failOpenAs) throw new Error("HTTP 401: the server rejects this token");
    const sess = await McpSession.open(specFor(name), { vars: {}, dsns: {} }, { connectTimeoutMs: 5000 });
    sessions.push(sess);
    return sess;
  };
  try {
    const first = await McpSession.open(specFor("a"), { vars: {}, dsns: {} }, { connectTimeoutMs: 5000 });
    const tools = first.tools;
    await first.close();
    const classification = classifyTools({ tools }).classification;
    const raw: SealmarkConfig = { name: "cred", version: "0.0.1", server: { url: s.url === null ? undefined : (s.url ?? toy.url), headers: s.headers ?? { Authorization: "Bearer {bearer}" } } };
    const eff = effectiveFor(raw, ["upstream" as PackId], { dir: tmp, parent: tmp }, { probes: (s.probes ?? PROBES) as EffectiveConfig["probes"], ...(s.checks ? { checks: s.checks } : {}) });
    const extra = {
      ...(s.noStub ? {} : { upstream: stub }),
      ...(s.noLog ? {} : { serverLog: log }),
      identity: { identities: [{ name: "a" as const, bearer: BEARERS.a }, { name: "b" as const, bearer: BEARERS.b }], openAs: open },
    };
    const ctx = { pack: "upstream" as PackId, config: eff, tools, classification, sandboxEnabled: true, open: () => open("a"), active: false, timeoutProbeSec: 2, hangMs: 2000, log: () => {}, ...extra } as PackCtx;
    const checks = await pack.run(ctx);
    return { checks, stub, log, ctx };
  } finally {
    for (const x of sessions) await x.close().catch(() => {});
    await toy.close();
    await stub.close();
  }
}

const verdicts = (cs: CheckResult[]): Record<string, Verdict> => Object.fromEntries(cs.map((c) => [c.id, c.verdict]));
const IDS = ["upstream-credential", "upstream-credential-echo", "log-secret", "upstream-error-leak", "upstream-slow"] as const;
const row = (cred: Verdict, echo: Verdict, leak: Verdict, slow: Verdict, logv: Verdict): Record<string, Verdict> => ({
  "upstream-credential": cred,
  "upstream-credential-echo": echo,
  "upstream-error-leak": leak,
  "upstream-slow": slow,
  "log-secret": logv,
});

// ---- tests -------------------------------------------------------------------------------------------------

describe("upstream pack: every toy mode", () => {
  const expected: Record<CredToyMode, Record<string, Verdict>> = {
    good: row("pass", "pass", "pass", "pass", "pass"),
    static: row("fail", "pass", "pass", "pass", "pass"),
    swap: row("fail", "pass", "pass", "pass", "pass"),
    logged: row("pass", "pass", "pass", "pass", "fail"),
    // an echo is graded once, by upstream-credential-echo: error-leak needs the relayed error body (the canary) next to the credential
    echoed: row("pass", "fail", "pass", "pass", "pass"),
    leak: row("pass", "pass", "fail", "pass", "pass"),
    hang: row("pass", "pass", "pass", "fail", "pass"),
    "anon-static": row("fail", "pass", "pass", "pass", "pass"),
    "anon-open": row("pass", "pass", "pass", "pass", "pass"),
  };
  assert.deepEqual([...CRED_TOY_MODES].sort(), Object.keys(expected).sort());
  for (const mode of CRED_TOY_MODES) {
    it(`${mode}`, async () => {
      const r = await runPack({ mode, backendTimeoutMs: 1500, checks: { "upstream-slow": { enabled: true, severity: null, expected_sec: 1 } } });
      assert.deepEqual(verdicts(r.checks), expected[mode], JSON.stringify(r.checks.map((c) => [c.id, c.verdict, c.summary])));
      assert.deepEqual(r.checks.map((c) => c.id), [...IDS]);
      // the stub mode is back to normal after every use
      const modes = r.stub.modeLog.map((m) => m.mode);
      assert.deepEqual(modes, ["error", "normal", "slow", "normal"]);
      // evidence never holds a minted token
      const dump = JSON.stringify(r.checks);
      assert.ok(!dump.includes(BEARERS.a) && !dump.includes(BEARERS.b), "a bearer value reached the result");
    });
  }
});

describe("upstream pack: what each fail says", () => {
  it("swap names the other identity; static says static; anonymous says anonymous", async () => {
    const s = await runPack({ mode: "swap", checks: { "upstream-slow": { enabled: false, severity: null } } });
    const c = s.checks.find((x) => x.id === "upstream-credential")!;
    assert.match(c.summary, /identity b reached the upstream with identity a's credential/);
    assert.ok(c.evidence.some((e) => e.code === "upstream.credential-swapped" && e.outcome.includes("{bearer:a}")));
    const t = await runPack({ mode: "static", checks: { "upstream-slow": { enabled: false, severity: null } } });
    assert.match(t.checks[0]!.summary, /neither identity's \(a static credential\)/);
    const u = await runPack({ mode: "anon-static", checks: { "upstream-slow": { enabled: false, severity: null } } });
    assert.match(u.checks[0]!.summary, /anonymous call reached the upstream carrying a credential/);
  });

  it("logged: the log excerpt has the bearer rewritten", async () => {
    const r = await runPack({ mode: "logged", checks: { "upstream-slow": { enabled: false, severity: null } } });
    const c = r.checks.find((x) => x.id === "log-secret")!;
    assert.equal(c.verdict, "fail");
    assert.match(c.evidence[0]!.excerpt ?? "", /\{bearer:a\}|\{bearer:b\}/);
    assert.ok(!JSON.stringify(c).includes(BEARERS.a));
  });

  it("leak: the relayed error body is the evidence, with the token scrubbed", async () => {
    const r = await runPack({ mode: "leak", checks: { "upstream-slow": { enabled: false, severity: null } } });
    const c = r.checks.find((x) => x.id === "upstream-error-leak")!;
    assert.equal(c.verdict, "fail");
    assert.ok(c.evidence.some((e) => e.code === "upstream.error-leak" && /\{bearer:a\}/.test(e.excerpt ?? "")));
  });
});

describe("upstream pack: na and inconclusive wording", () => {
  const off = { "upstream-slow": { enabled: false, severity: null } } as EffectiveConfig["checks"];
  it("applies: no stub is a refusal naming the key", async () => {
    const r = await runPack({ mode: "good", noStub: true, checks: off });
    assert.deepEqual(pack.applies(r.ctx), { ok: false, reason: "no upstream stub: set `upstream.kind: http` (flag --upstream) and use `{upstream}` in the server config" });
  });

  it("a stdio server: the identity checks are na", async () => {
    const r = await runPack({ mode: "good", url: null, checks: off });
    for (const id of ["upstream-credential", "upstream-credential-echo", "upstream-error-leak", "log-secret"]) {
      const c = r.checks.find((x) => x.id === id)!;
      assert.equal(c.verdict, "na", id);
      assert.match(c.summary, /stdio server has no per-caller credential/);
    }
  });

  it("headers without {bearer}: na, and the text says what to write", async () => {
    const r = await runPack({ mode: "good", headers: { Authorization: "Bearer fixed" }, checks: off });
    for (const id of ["upstream-credential", "upstream-credential-echo", "upstream-error-leak", "log-secret"]) {
      const c = r.checks.find((x) => x.id === id)!;
      assert.equal(c.verdict, "na", id);
      assert.match(c.summary, /set `server\.headers\.Authorization: Bearer \{bearer\}`/);
    }
  });

  it("no probes: every check is inconclusive with the no-valid-call reason, and nothing is called", async () => {
    const r = await runPack({ mode: "good", probes: [] });
    assert.deepEqual(verdicts(r.checks), row("inconclusive", "inconclusive", "inconclusive", "inconclusive", "inconclusive"));
    for (const c of r.checks) assert.match(c.summary, /no valid call: add a `probes:` entry without `check`/);
    assert.equal(r.stub.requests().length, 0);
    assert.deepEqual(r.stub.modeLog, []);
  });

  it("a probe with a check does not count as a valid call", async () => {
    const r = await runPack({ mode: "good", probes: [{ id: "p", check: { id: "custom-x", label: "x", scope: "server" }, tool: "lookup", args: { id: "x" } }] });
    assert.equal(r.checks[0]!.verdict, "inconclusive");
  });

  it("a server that refuses the minted token: inconclusive, and the text names identities.a", async () => {
    const r = await runPack({ mode: "good", failOpenAs: true, checks: off });
    const c = r.checks.find((x) => x.id === "upstream-credential")!;
    assert.equal(c.verdict, "inconclusive");
    assert.match(c.summary, /identities\.a and identities\.b/);
  });

  it("no server log: log-secret is na with the reason", async () => {
    const r = await runPack({ mode: "good", noLog: true, checks: off });
    const c = r.checks.find((x) => x.id === "log-secret")!;
    assert.equal(c.verdict, "na");
    assert.match(c.summary, /no server log/);
  });

  it("checks.<id>.enabled: false is na; severity maps to critical/advisory", async () => {
    const r = await runPack({
      mode: "good",
      checks: { "upstream-slow": { enabled: false, severity: null }, "log-secret": { enabled: false, severity: null }, "upstream-credential": { enabled: true, severity: "scored" }, "upstream-credential-echo": { enabled: true, severity: "critical" }, "upstream-error-leak": { enabled: true, severity: "advisory" } },
    });
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    assert.equal(by["upstream-slow"]!.verdict, "na");
    assert.match(by["upstream-slow"]!.summary, /disabled by config/);
    assert.equal(by["log-secret"]!.verdict, "na");
    assert.equal(by["upstream-credential"]!.critical, false);
    assert.equal(by["upstream-credential-echo"]!.critical, true);
    assert.equal(by["upstream-error-leak"]!.advisory, true);
  });
});

describe("upstream pack: describe()", () => {
  it("documents the five checks, none advisory, only the credential check critical", () => {
    const docs = pack.describe();
    assert.deepEqual(docs.map((d) => d.id), [...IDS]);
    assert.deepEqual(docs.filter((d) => d.critical).map((d) => d.id), ["upstream-credential"]);
    assert.ok(docs.every((d) => d.pack === ("upstream" as PackId) && !d.advisory && d.scope.startsWith("server") && d.probes.length > 0));
  });
});

describe("upstream pack: upstream-slow", () => {
  it("honours expected_sec: the stub holds expected_sec + 5 s", async () => {
    const r = await runPack({ mode: "good", backendTimeoutMs: 1500, checks: { "upstream-slow": { enabled: true, severity: null, expected_sec: 2 } } });
    assert.deepEqual(r.stub.modeLog.find((m) => m.mode === "slow"), { mode: "slow", delayMs: 7000 });
    assert.equal(verdicts(r.checks)["upstream-slow"], "pass");
    assert.match(r.checks.find((c) => c.id === "upstream-slow")!.summary, /within 4 s/);
  });

  it("falls back to timeout_probe_sec when expected_sec is not set", async () => {
    const r = await runPack({ mode: "good", backendTimeoutMs: 1500 });
    assert.deepEqual(r.stub.modeLog.find((m) => m.mode === "slow"), { mode: "slow", delayMs: 2 * 1000 + 5000 });
  });

  it("a hanging server is a fail whose text states the bound", async () => {
    const r = await runPack({ mode: "hang", checks: { "upstream-slow": { enabled: true, severity: null, expected_sec: 1 } } });
    const c = r.checks.find((x) => x.id === "upstream-slow")!;
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /did not answer within 3 s/);
  });
});
