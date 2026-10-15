// Round 6, package rules-agent: the new clauses of `probes:` at run time, against a fake session, a fake upstream stub and a fake log
// (the harness package's real observers are not on this branch; the interfaces are the pinned ones, the design notes).
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import type { ProbeSpec } from "../config/model.js";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { pack, runProbe, validateProbes, type PlanInput, type PlannedProbe, type RulesLog, type RulesRequest, type RulesUpstream, type UpstreamReplySpec } from "../probes.js";
import type { PackCtx } from "../types.js";

const T = (name: string, description: string, props: Record<string, { type: string }>, required: string[]): ToolInfo => ({ name, description, inputSchema: { type: "object", properties: props, required } });
const TOOLS: ToolInfo[] = [T("count_rows", "Count rows.", { table: { type: "string" } }, ["table"]), T("query", "Run a SQL query", { sql: { type: "string" } }, ["sql"])];
const CLASSIFICATION = classifyTools({ tools: TOOLS, sqlTools: [{ tool: "query", arg: "sql" }] }).classification;
const INPUT: PlanInput = { tools: TOOLS, classification: CLASSIFICATION, upstream: { kind: "http", mintsTokens: true }, transport: "http" };

const plan = (spec: object): PlannedProbe[] => validateProbes([spec as ProbeSpec], INPUT).probes;
const one = (spec: object): PlannedProbe => plan(spec)[0]!;

/** A recorder with the surface of the stub that probes use. */
class FakeUpstream implements RulesUpstream {
  reqs: RulesRequest[] = [];
  /** What setOverride saw, in order (undefined = cleared). */
  overrides: (UpstreamReplySpec | undefined)[] = [];
  mark(): number {
    return this.reqs.length;
  }
  requests(since = 0): RulesRequest[] {
    return this.reqs.slice(since);
  }
  setOverride(r: UpstreamReplySpec | undefined): void {
    this.overrides.push(r);
  }
  get current(): UpstreamReplySpec | undefined {
    return this.overrides.at(-1);
  }
}
const req = (o: Partial<RulesRequest> = {}): RulesRequest => ({ method: "POST", path: "/sql", query: "", headers: { authorization: "Bearer sm-bearer-a-0123456789ab" }, body: "{\"sql\":\"SELECT 1\",\"submitter\":\"mcp:a\"}", minted: [], ...o });

class FakeLog implements RulesLog {
  text = "";
  mark(): number {
    return this.text.length;
  }
  since(m: number): string {
    return this.text.slice(m);
  }
}

interface Script {
  /** Requests the "server" sends to the stub during the call. */
  forward?: RulesRequest[];
  /** What the stub holds while the call runs (read from the fake upstream). */
  during?: (u: FakeUpstream) => void;
  text?: string;
  isError?: boolean;
  log?: string;
  throws?: boolean;
}
function session(up: FakeUpstream | undefined, script: Script, log?: FakeLog): McpSession & { calls: { name: string; args: unknown }[]; closedCount: number } {
  const s = {
    calls: [] as { name: string; args: unknown }[],
    closedCount: 0,
    closed: false,
    async call(name: string, args: unknown): Promise<CallResult> {
      s.calls.push({ name, args });
      if (script.throws) throw new Error("transport blew up");
      script.during?.(up!);
      for (const r of script.forward ?? []) up?.reqs.push(r);
      if (script.log && log) log.text += script.log;
      return { isError: script.isError === true, text: script.text ?? "{\"count\":3}", elapsedMs: 1, timedOut: false, closed: false };
    },
    async close() {
      s.closedCount++;
    },
  };
  return s as unknown as McpSession & typeof s;
}

const TABLE = { tool: "count_rows", args: { table: "sales.public.orders" } };
const verdictOf = async (spec: object, up: FakeUpstream | undefined, script: Script, extra: { log?: FakeLog; openAs?: (i: "a" | "b" | null) => Promise<McpSession> } = {}) => {
  const s = session(up, script, extra.log);
  const o = await runProbe(one(spec), { session: s, active: false, ...(up ? { upstream: up } : {}), ...(extra.log ? { serverLog: extra.log } : {}), ...(extra.openAs ? { openAs: extra.openAs } : {}) });
  return { o, s };
};

describe("r6 rules: expect.upstream", () => {
  it("requests: any / none", async () => {
    const up = new FakeUpstream();
    assert.equal((await verdictOf({ ...TABLE, expect: { upstream: { requests: "any" } } }, up, { forward: [req()] })).o.verdict, "pass");
    const none = await verdictOf({ ...TABLE, expect: { upstream: { requests: "any" } } }, up, {});
    assert.equal(none.o.verdict, "fail");
    assert.match(none.o.clauses[0]!.detail, /expected a request to reach the upstream, none did/);
    assert.equal((await verdictOf({ ...TABLE, expect: { upstream: { requests: "none" } } }, up, {})).o.verdict, "pass");
    const leaked = await verdictOf({ ...TABLE, expect: { upstream: { requests: "none" } } }, up, { forward: [req()] });
    assert.equal(leaked.o.verdict, "fail");
    assert.match(leaked.o.clauses[0]!.detail, /expected no request to reach the upstream, 1 did: POST \/sql/);
  });

  it("only counts requests since the probe's own mark", async () => {
    const up = new FakeUpstream();
    up.reqs.push(req(), req());
    assert.equal((await verdictOf({ ...TABLE, expect: { upstream: { requests: "none" } } }, up, {})).o.verdict, "pass");
  });

  it("none_matching and all_matching read 'METHOD path?query', the headers and the body", async () => {
    const up = new FakeUpstream();
    const spec = (u: object) => ({ ...TABLE, expect: { upstream: u } });
    const r = req({ query: "?a=1", body: "SELECT count(*) FROM t -- submitter=mcp" });
    assert.equal((await verdictOf(spec({ none_matching: "DROP|DELETE" }), up, { forward: [r] })).o.verdict, "pass");
    const hit = await verdictOf(spec({ none_matching: "count\\(\\*\\)" }), up, { forward: [r] });
    assert.equal(hit.o.verdict, "fail");
    assert.match(hit.o.clauses[0]!.detail, /matched \/count\\\(\\\*\\\)\/: POST \/sql\?a=1/);
    assert.equal((await verdictOf(spec({ all_matching: "submitter=" }), up, { forward: [r, r] })).o.verdict, "pass");
    assert.equal((await verdictOf(spec({ all_matching: "^POST /sql\\?a=1\\nauthorization: Bearer " }), up, { forward: [r] })).o.verdict, "pass", "path, query and the header lines are in the text");
    const miss = await verdictOf(spec({ all_matching: "submitter=" }), up, { forward: [r, req({ body: "SELECT 2" })] });
    assert.equal(miss.o.verdict, "fail");
    assert.match(miss.o.clauses[0]!.detail, /did not match/);
  });

  it("all_matching and header with no request at all are inconclusive, never a vacuous pass", async () => {
    const up = new FakeUpstream();
    const a = await verdictOf({ ...TABLE, expect: { upstream: { all_matching: "submitter=" } } }, up, {});
    assert.equal(a.o.verdict, "inconclusive");
    assert.match(a.o.reason!, /no request reached the upstream stub.*vacuously/);
    const h = await verdictOf({ ...TABLE, expect: { upstream: { header: { Authorization: { matches: "^Bearer " } } } } }, up, {});
    assert.equal(h.o.verdict, "inconclusive");
    // a definite failure outranks an unjudged clause
    const both = await verdictOf({ ...TABLE, expect: { is_error: true, upstream: { all_matching: "x" } } }, up, {});
    assert.equal(both.o.verdict, "fail");
  });

  it("header: equals and matches, names compared lower-case, over every request", async () => {
    const up = new FakeUpstream();
    const ok = { ...TABLE, expect: { upstream: { header: { Authorization: { equals: "Bearer sm-bearer-a-0123456789ab" }, "X-Sub": { matches: "^mcp:" } } } } };
    const good = req({ headers: { authorization: "Bearer sm-bearer-a-0123456789ab", "x-sub": "mcp:a" } });
    assert.equal((await verdictOf(ok, up, { forward: [good, good] })).o.verdict, "pass");
    const bad = await verdictOf(ok, up, { forward: [good, req({ headers: { authorization: "Bearer other", "x-sub": "mcp:a" } })] });
    assert.equal(bad.o.verdict, "fail");
    assert.match(bad.o.clauses.find((c) => !c.ok)!.detail, /header that does not match/);
    const none = await verdictOf(ok, up, { forward: [req({ headers: { authorization: "Bearer sm-bearer-a-0123456789ab" } })] });
    assert.match(none.o.clauses.find((c) => !c.ok)!.detail, /had no x-sub header/);
  });

  it("token_echoed: true and false against what the stub minted, inconclusive when nothing was minted", async () => {
    const up = new FakeUpstream();
    const spec = (want: boolean) => ({ ...TABLE, upstream: { reply: { json: { rows: [{ id: 1, note: "{upstream_token}" }] } } }, expect: { upstream: { token_echoed: want } } });
    const minted = req({ minted: ["sm-row-deadbeef"] });
    // the aggregate-only tool does not show the row: token_echoed false holds
    assert.equal((await verdictOf(spec(false), up, { forward: [minted], text: "{\"count\":1}" })).o.verdict, "pass");
    // the leaky tool echoes it
    const leaky = await verdictOf(spec(false), up, { forward: [minted], text: "{\"rows\":[{\"note\":\"sm-row-deadbeef\"}]}" });
    assert.equal(leaky.o.verdict, "fail");
    assert.match(leaky.o.clauses[0]!.detail, /echoed in the response/);
    assert.equal((await verdictOf(spec(true), up, { forward: [minted], text: "sm-row-deadbeef" })).o.verdict, "pass");
    const nothing = await verdictOf(spec(false), up, { forward: [req()], text: "{\"count\":1}" });
    assert.equal(nothing.o.verdict, "inconclusive");
    assert.match(nothing.o.reason!, /minted no \{upstream_token\}/);
  });

  it("is inconclusive, and calls nothing, when the stub is not running", async () => {
    const { o, s } = await verdictOf({ ...TABLE, expect: { upstream: { requests: "any" } } }, undefined, {});
    assert.equal(o.verdict, "inconclusive");
    assert.match(o.reason!, /needs the upstream stub, which is not running: set upstream\.kind: http/);
    assert.equal(s.calls.length, 0);
  });
});

describe("r6 rules: upstream.reply", () => {
  it("sets the scripted reply for the call and clears it afterwards; {token} is filled, {upstream_token} left for the stub", async () => {
    const up = new FakeUpstream();
    let during: UpstreamReplySpec | undefined;
    const spec = { ...TABLE, upstream: { reply: { status: 200, json: { rows: [{ id: 1, note: "{upstream_token}", tag: "x-{token}" }] } } }, expect: { is_error: false } };
    const { o } = await verdictOf(spec, up, { during: (u) => (during = u.current) });
    assert.equal(o.verdict, "pass");
    assert.equal(up.overrides.length, 2, "set once, cleared once");
    assert.equal(up.overrides.at(-1), undefined);
    const rows = (during!.json as { rows: { note: string; tag: string }[] }).rows;
    assert.equal(rows[0]!.note, "{upstream_token}");
    assert.match(rows[0]!.tag, /^x-sm-[0-9a-f]{12}$/);
  });

  it("clears the reply even when the call throws", async () => {
    const up = new FakeUpstream();
    await assert.rejects(verdictOf({ ...TABLE, upstream: { reply: { body: "x" } }, expect: { is_error: false } }, up, { throws: true }), /transport blew up/);
    assert.equal(up.current, undefined);
    assert.equal(up.overrides.length, 2);
  });

  it("does not touch the stub for a probe without upstream.reply", async () => {
    const up = new FakeUpstream();
    await verdictOf({ ...TABLE, expect: { is_error: false } }, up, {});
    assert.equal(up.overrides.length, 0);
  });
});

describe("r6 rules: expect.log, expect.response, expect.is_error unchanged", () => {
  it("log.not_matches and log.matches read the server log since the probe's mark", async () => {
    const log = new FakeLog();
    log.text = "Authorization: Bearer old\n";
    const spec = (l: object) => ({ ...TABLE, expect: { log: l } });
    assert.equal((await verdictOf(spec({ not_matches: "Bearer" }), undefined, { log: "handled request\n" }, { log })).o.verdict, "pass", "earlier lines are not read");
    const leak = await verdictOf(spec({ not_matches: "Bearer" }), undefined, { log: "Authorization: Bearer sm-x\n" }, { log });
    assert.equal(leak.o.verdict, "fail");
    assert.match(leak.o.clauses[0]!.detail, /matched \/Bearer\/ during the call/);
    assert.equal((await verdictOf(spec({ matches: "handled" }), undefined, { log: "handled\n" }, { log })).o.verdict, "pass");
    assert.equal((await verdictOf(spec({ matches: "audit" }), undefined, { log: "handled\n" }, { log })).o.verdict, "fail");
  });

  it("log clauses are inconclusive without a log observer", async () => {
    const { o } = await verdictOf({ ...TABLE, expect: { log: { not_matches: "Bearer" } } }, undefined, {});
    assert.equal(o.verdict, "inconclusive");
    assert.match(o.reason!, /there is no server log to read/);
  });

  it("response.max_bytes counts UTF-8 bytes of the reply", async () => {
    const spec = (n: number) => ({ ...TABLE, expect: { response: { max_bytes: n } } });
    assert.equal((await verdictOf(spec(10), undefined, { text: "héllo" })).o.verdict, "pass", "6 bytes");
    const big = await verdictOf(spec(5), undefined, { text: "héllo" });
    assert.equal(big.o.verdict, "fail");
    assert.match(big.o.clauses[0]!.detail, /the response was 6 byte\(s\), limit 5/);
  });

  it("the old clauses still decide pass and fail", async () => {
    assert.equal((await verdictOf({ ...TABLE, expect: { is_error: true } }, undefined, {})).o.verdict, "fail");
    assert.equal((await verdictOf({ ...TABLE, expect: { is_error: true, text: { matches: "denied" } } }, undefined, { isError: true, text: "denied" })).o.verdict, "pass");
  });
});

describe("r6 rules: identity", () => {
  const spec = (identity: string) => ({ ...TABLE, identity, expect: { is_error: false } });

  it("identity b opens a fresh session with openAs('b') and closes it; none uses openAs(null)", async () => {
    const asked: (string | null)[] = [];
    const other = session(undefined, {});
    const openAs = async (i: "a" | "b" | null) => (asked.push(i), other);
    const own = session(undefined, {});
    const b = await runProbe(one(spec("b")), { session: own, active: false, openAs });
    assert.equal(b.verdict, "pass");
    assert.deepEqual(asked, ["b"]);
    assert.equal(other.calls.length, 1, "the call was made on the identity's session");
    assert.equal(own.calls.length, 0, "not on the probe's own session");
    assert.equal(other.closedCount, 1);
    await runProbe(one(spec("none")), { session: own, active: false, openAs });
    assert.deepEqual(asked, ["b", null]);
  });

  it("identity a (or none given) uses the session it was handed", async () => {
    const own = session(undefined, {});
    const openAs = async () => assert.fail("must not be called");
    await runProbe(one(spec("a")), { session: own, active: false, openAs });
    await runProbe(one({ ...TABLE, expect: { is_error: false } }), { session: own, active: false, openAs });
    assert.equal(own.calls.length, 2);
  });

  it("is inconclusive, naming {bearer}, when per-caller identities are not available, or the session cannot be opened", async () => {
    const own = session(undefined, {});
    const none = await runProbe(one(spec("b")), { session: own, active: false });
    assert.equal(none.verdict, "inconclusive");
    assert.match(none.reason!, /identity: b needs per-caller identities: use an HTTP server and write \{bearer\} in server\.headers/);
    const refused = await runProbe(one(spec("none")), { session: own, active: false, openAs: async () => Promise.reject(new Error("401 unauthorized")) });
    assert.equal(refused.verdict, "inconclusive");
    assert.match(refused.reason!, /could not open a session as identity none: 401 unauthorized/);
    assert.equal(own.calls.length, 0);
  });
});

describe("r6 rules: the custom pack folds expansions into one check", () => {
  const ctxFor = (probes: object[], up: FakeUpstream, scripts: Script[]): PackCtx => {
    let i = 0;
    const s = {
      closed: false,
      async call(): Promise<CallResult> {
        const sc = scripts[i++] ?? {};
        for (const r of sc.forward ?? []) up.reqs.push(r);
        return { isError: sc.isError === true, text: sc.text ?? "ok", elapsedMs: 1, timedOut: false, closed: false };
      },
      async close() {},
    } as unknown as McpSession;
    return {
      pack: "custom",
      config: { probes, timeouts: { probe_ms: 5000 }, checks: {}, server: { url: "http://127.0.0.1:1/mcp" }, env: {}, origins: {}, value: { upstream: { kind: "http" } } },
      tools: TOOLS,
      classification: CLASSIFICATION,
      open: async () => s,
      active: false,
      canaries: [],
      upstream: up,
    } as unknown as PackCtx;
  };

  it("matrix cells share the check; one failing cell fails the check and names the cell", async () => {
    const up = new FakeUpstream();
    const probes = [
      { id: "scope", check: { id: "custom-scope", label: "refuses out of scope", scope: "server", critical: true }, tool: "count_rows", args: { table: "{matrix.table}" }, matrix: { table: ["hr.private.salaries", "sales", "sales.public"] }, expect: { is_error: true, upstream: { requests: "none" } } },
    ];
    // the third cell leaks: it is answered successfully and reaches the stub
    const ctx = ctxFor(probes, up, [{ isError: true }, { isError: true }, { isError: false, forward: [req()] }]);
    const results = await pack.run(ctx);
    assert.equal(results.length, 1);
    const c = results[0]!;
    assert.equal(c.id, "custom-scope");
    assert.equal(c.verdict, "part", "two cells passed, one failed");
    assert.match(c.summary, /scope\[table=sales\.public\]/);
    assert.equal(c.evidence.length, 3);
    assert.ok(c.evidence.some((e) => (e.verifiedBy as string) === "upstream"), "the failing clause is attributed to the upstream observer");
    assert.deepEqual(c.evidence.map((e) => e.code), ["probe:scope[table=hr.private.salaries]:pass", "probe:scope[table=sales]:pass", "probe:scope[table=sales.public]:fail"]);
  });

  it("applies() accepts the new clauses when the stub is declared and refuses them when it is not", () => {
    const up = new FakeUpstream();
    const probes = [{ id: "u", check: { id: "custom-u", label: "l", scope: "server" }, tool: "count_rows", args: { table: "t" }, expect: { upstream: { requests: "any" } } }];
    assert.deepEqual(pack.applies(ctxFor(probes, up, [])), { ok: true });
    const noStub = ctxFor(probes, up, []);
    (noStub as unknown as { upstream?: unknown }).upstream = undefined;
    (noStub.config as unknown as { value: object }).value = {};
    assert.throws(() => pack.applies(noStub), /expect\.upstream needs the upstream stub: set upstream\.kind: http/);
  });
});
