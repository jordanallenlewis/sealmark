// Round 6, package rules-agent: the rules of `probes:` against a real HTTP server (toy/rules-r6.ts) and a recorder that plays the upstream
// backend. The recorder implements the surface probes use of the harness's stub (mark, requests, setOverride, minted tokens); the stub
// itself belongs to the harness package, so what is shown here is that the clauses catch the broken modes of a real forwarding server.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import type { ProbeSpec } from "../config/model.js";
import { McpSession } from "../mcp.js";
import { runProbe, validateProbes, type PlanInput, type RulesRequest, type RulesUpstream, type UpstreamReplySpec } from "../probes.js";
import { RULES_TOY_MODES, startRulesToy, type RulesToy, type RulesToyMode } from "../toy/rules-r6.js";

const BEARER_A = "Bearer sm-bearer-a-0123456789ab";
const BEARER_B = "Bearer sm-bearer-b-0123456789ab";

/** A backend that records what it receives and answers with the probe's scripted reply (or a default), like the harness stub. */
class Recorder implements RulesUpstream {
  reqs: RulesRequest[] = [];
  override: UpstreamReplySpec | undefined;
  overrides = 0;
  private server!: http.Server;
  url = "";
  async start(): Promise<void> {
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const u = new URL(req.url ?? "/", "http://x");
        const minted: string[] = [];
        const mint = (s: string) => s.replace(/\{upstream_token\}/g, () => (minted.push(`sm-row-${randomBytes(4).toString("hex")}`), minted.at(-1)!));
        const r = this.override ?? { status: 200, json: { rows: [{ count: 3 }] } };
        let body = r.json !== undefined ? mint(JSON.stringify(r.json)) : mint(r.body ?? "");
        if (r.bytes && body.length < r.bytes) body += " ".repeat(r.bytes - body.length);
        this.reqs.push({ method: req.method ?? "GET", path: u.pathname, query: u.search, headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)])), body: Buffer.concat(chunks).toString("utf8"), minted });
        res.writeHead(r.status ?? 200, { "content-type": "application/json" });
        res.end(body);
      });
    });
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", () => resolve()));
    this.url = `http://127.0.0.1:${(this.server.address() as { port: number }).port}`;
  }
  mark(): number {
    return this.reqs.length;
  }
  requests(since = 0): RulesRequest[] {
    return this.reqs.slice(since);
  }
  setOverride(r: UpstreamReplySpec | undefined): void {
    this.override = r;
    this.overrides++;
  }
  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.server.close(() => resolve());
      this.server.closeAllConnections();
    });
  }
}

const CHECK = (id: string) => ({ id, label: id, scope: "server", critical: true });
const SPECS: Record<string, object> = {
  agg: { id: "agg-never-rows", check: CHECK("custom-aggregate-only"), tool: "count_rows", args: { table: "sales.public.orders" }, upstream: { reply: { status: 200, json: { rows: [{ id: 1, note: "{upstream_token}" }, { id: 2, note: "{upstream_token}" }] } } }, expect: { is_error: false, upstream: { requests: "any", token_echoed: false } } },
  cap: { id: "big-reply-capped", check: CHECK("custom-byte-cap"), tool: "query", args: { sql: "SELECT * FROM sales.public.orders WHERE 'sm-{token}' = 'sm-{token}'" }, upstream: { reply: { bytes: 3 * 1024 * 1024, body: "{\"rows\":[\"{upstream_token}\"]}" } }, expect: { response: { max_bytes: 1048576 } } },
  tag: { id: "submitter-tag", check: CHECK("custom-submitter-tag"), tool: "query", args: { sql: "SELECT 1 AS sm_{token}" }, expect: { upstream: { requests: "any", all_matching: "\"submitter\":\"mcp:" } } },
  cred: { id: "cred-passthrough", check: CHECK("custom-cred"), tool: "count_rows", args: { table: "sales.public.orders" }, expect: { upstream: { requests: "any", header: { Authorization: { equals: BEARER_A } } } } },
  credB: { id: "cred-b", check: CHECK("custom-cred-b"), tool: "count_rows", args: { table: "sales.public.orders" }, identity: "b", expect: { upstream: { requests: "any", header: { Authorization: { equals: BEARER_B } } } } },
  anon: { id: "cred-anon", check: CHECK("custom-cred-anon"), tool: "count_rows", args: { table: "sales.public.orders" }, identity: "none", expect: { is_error: true } },
};

describe("r6 rules against a real HTTP server and a backend recorder", { timeout: 240_000 }, () => {
  const backend = new Recorder();
  const toys: Partial<Record<RulesToyMode, RulesToy>> = {};
  before(async () => {
    await backend.start();
    for (const m of RULES_TOY_MODES) toys[m] = await startRulesToy(m, { backend: backend.url });
  });
  after(async () => {
    for (const t of Object.values(toys)) await t?.close();
    await backend.close();
  });

  const open = (mode: RulesToyMode, authorization: string | null) =>
    McpSession.open({ url: toys[mode]!.url, ...(authorization ? { headers: { Authorization: authorization } } : {}) }, { vars: {}, dsns: {}, env: {} }, { connectTimeoutMs: 15_000 });

  /** Runs one named probe against the toy in `mode`, as identity a on `session`, and gives the outcome. */
  async function probe(mode: RulesToyMode, key: string) {
    const session = await open(mode, BEARER_A);
    try {
      const classification = classifyTools({ tools: session.tools, sqlTools: [{ tool: "query", arg: "sql" }] }).classification;
      const input: PlanInput = { tools: session.tools, classification, upstream: { kind: "http", mintsTokens: true }, transport: "http" };
      const p = validateProbes([SPECS[key] as ProbeSpec], input).probes[0]!;
      const openAs = async (who: "a" | "b" | null) => open(mode, who === "b" ? BEARER_B : who === "a" ? BEARER_A : null);
      return await runProbe(p, { session, active: false, upstream: backend, openAs });
    } finally {
      await session.close();
    }
  }

  it("good: aggregate-only, byte cap, submitter tag and credential passthrough all hold", async () => {
    for (const key of ["agg", "cap", "tag", "cred", "credB"]) {
      const o = await probe("good", key);
      assert.equal(o.verdict, "pass", `${key}: ${o.reason ?? ""} ${o.clauses.map((c) => `${c.clause}: ${c.detail}`).join("; ")}`);
    }
  });

  it("agg-raw-rows fails the aggregate-only rule: a row the backend returned reached the response (token_echoed)", async () => {
    const o = await probe("agg-raw-rows", "agg");
    assert.equal(o.verdict, "fail");
    assert.match(o.clauses.find((c) => !c.ok)!.detail, /echoed in the response/);
    assert.equal((await probe("agg-raw-rows", "cap")).verdict, "pass", "the other rules are unchanged in this mode");
  });

  it("bytecap-missing fails the byte cap: the 3 MiB backend reply was relayed (response.max_bytes)", async () => {
    const o = await probe("bytecap-missing", "cap");
    assert.equal(o.verdict, "fail");
    assert.match(o.clauses.find((c) => !c.ok)!.detail, /the response was \d+ byte\(s\), limit 1048576/);
    assert.equal((await probe("bytecap-missing", "agg")).verdict, "pass");
  });

  it("the scripted reply is set for the probe and cleared after it: the next probe sees the default backend again", async () => {
    const before = backend.overrides;
    await probe("good", "agg");
    assert.equal(backend.overrides, before + 2, "set once, cleared once");
    assert.equal(backend.override, undefined);
    const o = await probe("good", "tag");
    assert.equal(o.verdict, "pass");
  });

  it("identity b reaches the backend with b's own credential, not a's; the forwarded body carries the toy's submitter tag", async () => {
    const m = backend.mark();
    const o = await probe("good", "credB");
    assert.equal(o.verdict, "pass");
    const seen = backend.requests(m);
    assert.ok(seen.length >= 1);
    assert.ok(seen.every((r) => r.headers.authorization === BEARER_B), "only b's token reached the backend during that probe");
    assert.match(seen[0]!.body, /"submitter":"mcp:toy"/);
  });

  it("identity none cannot open a session on a server that requires a credential: the probe is inconclusive and says why", async () => {
    const o = await probe("good", "anon");
    assert.equal(o.verdict, "inconclusive");
    assert.match(o.reason!, /could not open a session as identity none/);
  });

  it("a wrong expectation fails with the request in the detail (credential a expected, b sent)", async () => {
    const session = await open("good", BEARER_B);
    try {
      const classification = classifyTools({ tools: session.tools }).classification;
      const p = validateProbes([SPECS.cred as ProbeSpec], { tools: session.tools, classification, upstream: { kind: "http" }, transport: "http" }).probes[0]!;
      const o = await runProbe(p, { session, active: false, upstream: backend });
      assert.equal(o.verdict, "fail");
      assert.match(o.clauses.find((c) => !c.ok)!.detail, /header that does not match/);
    } finally {
      await session.close();
    }
  });
});

describe("toy rules-r6 as a program", () => {
  it("prints the endpoint, serves MCP and exits on SIGTERM; a missing --backend is exit 2", async () => {
    const script = fileURLToPath(new URL("../toy/rules-r6.js", import.meta.url));
    const bad = spawn(process.execPath, [script, "--mode", "good"], { stdio: ["ignore", "ignore", "pipe"] });
    const code = await new Promise<number | null>((resolve) => bad.on("exit", resolve));
    assert.equal(code, 2);
    const child = spawn(process.execPath, [script, "--mode", "good", "--backend", "http://127.0.0.1:1"], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      const line = await new Promise<string>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("no listening line")), 15_000);
        child.stdout.on("data", (d: Buffer) => {
          if (/listening http:\/\/127\.0\.0\.1:\d+\/mcp/.test(String(d))) {
            clearTimeout(t);
            resolve(String(d).trim());
          }
        });
      });
      const url = line.replace(/^listening /, "");
      const s = await McpSession.open({ url, headers: { Authorization: BEARER_A } }, { vars: {}, dsns: {}, env: {} }, { connectTimeoutMs: 15_000 });
      assert.deepEqual(s.tools.map((t) => t.name).sort(), ["count_rows", "list_tables", "query"]);
      const r = await s.call("count_rows", { table: "sales.public.orders" }, 10_000);
      assert.equal(r.isError, true, "the backend at 127.0.0.1:1 is unreachable: a short error, not a stack");
      assert.match(r.text, /the backend did not answer in time/);
      await s.close();
    } finally {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.on("exit", resolve));
    }
  });
});
