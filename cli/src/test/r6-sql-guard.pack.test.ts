import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { REFERENCE_CORPUS, STATEMENT_CORPUS, namesFor, render } from "../packs/sql-guard-corpus.js";
import { SETTLE_MS, pack } from "../packs/sql-guard.js";
import type { CheckResult } from "../types.js";
import { FakeSession, FakeUpstream, QUERY_TOOL, byId, err, makeCtx, ok, timeout, type Behavior } from "./r6-sql-guard.rig.js";

// Round 6, P5: the sql-guard pack against the pinned upstream-stub shape, with a scripted fake session. The real stub and the real
// toy matrix are the integration package's; r6-sql-guard.toy.test.ts runs the pack against the toy with a loopback recorder.

const ALLOW = ["sales.public.orders"];

/** Which corpus entry a rendered statement is (by re-rendering every template with the token found in it), or "control" / "huge-limit". */
function idOf(sql: string): string | undefined {
  const token = /sm[-_]([0-9a-f]{8})/i.exec(sql)?.[1]?.toLowerCase();
  if (!token) return undefined;
  for (const allow of [ALLOW, [], ["sales.public."]]) {
    const n = namesFor(allow, ".", token);
    for (const e of STATEMENT_CORPUS) if (render(e.sql, token, n) === sql) return e.id;
    for (const e of REFERENCE_CORPUS) if (render(e.sql, token, n) === sql) return e.id;
  }
  if (/ LIMIT 1000000$/.test(sql)) return "huge-limit";
  return "control";
}

/** A fake server that forwards the control (rewritten by `wrap`) and exactly the listed corpus ids, and refuses everything else. */
const leaking = (ids: string[], wrap: (sql: string) => string = (s) => `SELECT * FROM (${s}) AS sm LIMIT 1000`): Behavior => (sql) => {
  const id = idOf(sql);
  if (id === "control" || id === "huge-limit") return { forward: id === "huge-limit" ? wrap(sql.replace(/ LIMIT 1000000$/, "")) : wrap(sql), reply: ok() };
  if (id && ids.includes(id)) return { forward: sql, reply: ok() };
  return { reply: err("Error: only SELECT statements are allowed") };
};

async function run(behavior: Behavior, o: Parameters<typeof makeCtx>[2] = { allow: ALLOW }) {
  const stub = new FakeUpstream();
  const session = new FakeSession(o.tools ?? [QUERY_TOOL], stub, behavior);
  const { ctx, opened } = makeCtx(stub, session, o);
  const checks = await pack.run(ctx);
  return { checks, stub, session, opened };
}

const verdicts = (checks: CheckResult[]) => Object.fromEntries(checks.map((c) => [c.id, c.verdict]));

describe("sql-guard pack", () => {
  beforeEach(() => {
    SETTLE_MS.value = 0;
  });

  it("a guard that forwards only the control and the near miss passes every check", async () => {
    const { checks } = await run(leaking(["comment-hidden"]));
    assert.deepEqual(verdicts(checks), { "sql-guard-statements": "pass", "sql-guard-references": "pass", "sql-guard-rowcap": "pass" });
    assert.ok(checks.every((c) => c.pack === ("sql-guard" as never)));
    assert.equal(byId(checks, "sql-guard-statements").critical, true);
    assert.equal(byId(checks, "sql-guard-references").critical, true);
    assert.equal(byId(checks, "sql-guard-rowcap").critical, false);
  });

  it("uses one session for the whole pack and closes it", async () => {
    const { session, opened } = await run(leaking([]));
    assert.equal(opened(), 1);
    assert.equal(session.closed, true);
  });

  it("the control is the first exact scope.allow entry in a SELECT; with no scope it is SELECT 1", async () => {
    const scoped = await run(leaking([]));
    assert.match(String(scoped.session.calls[0]!.args.sql), /^SELECT \* FROM sales\.public\.orders WHERE 'sm-[0-9a-f]{8}' = 'sm-[0-9a-f]{8}'$/);
    const bare = await run(leaking([]), {});
    assert.match(String(bare.session.calls[0]!.args.sql), /^SELECT 1 AS sm_[0-9a-f]{8}$/);
  });

  it("checks.sql-guard-statements.control_sql replaces the control", async () => {
    const { session } = await run(leaking([]), { allow: ALLOW, checks: { "sql-guard-statements": { enabled: true, severity: null, control_sql: "SELECT 7 AS sm_{token}" } } });
    assert.match(String(session.calls[0]!.args.sql), /^SELECT 7 AS sm_[0-9a-f]{8}$/);
  });

  describe("control", () => {
    it("a control that does not reach the upstream makes every check inconclusive, never pass", async () => {
      const { checks } = await run(() => ({ reply: err("Error: forbidden") }));
      assert.deepEqual(verdicts(checks), { "sql-guard-statements": "inconclusive", "sql-guard-references": "inconclusive", "sql-guard-rowcap": "inconclusive" });
      assert.match(byId(checks, "sql-guard-statements").summary, /no control statement reached the upstream/);
    });

    it("the corpus is not sent when the control did not reach", async () => {
      const { session } = await run(() => ({ reply: err() }));
      assert.equal(session.calls.length, 1);
    });

    it("a control that answers ok without forwarding is inconclusive too (served locally)", async () => {
      const { checks } = await run(() => ({ reply: ok("cached") }));
      assert.equal(byId(checks, "sql-guard-statements").verdict, "inconclusive");
      assert.match(byId(checks, "sql-guard-statements").summary, /answered without forwarding/);
    });

    it("a control that times out is inconclusive", async () => {
      const { checks } = await run(() => ({ reply: timeout() }));
      assert.equal(byId(checks, "sql-guard-statements").verdict, "inconclusive");
      assert.match(byId(checks, "sql-guard-statements").summary, /timed out/);
    });
  });

  describe("statement families", () => {
    for (const e of STATEMENT_CORPUS.filter((x) => !x.nearMiss)) {
      it(`${e.id} reaching the upstream fails the check and names the entry`, async () => {
        const { checks } = await run(leaking([e.id]));
        const c = byId(checks, "sql-guard-statements");
        assert.equal(c.verdict, "fail");
        assert.match(c.summary, new RegExp(`\\b${e.id}\\b`));
        const hit = c.evidence.filter((x) => x.code === "sql-guard.reached");
        assert.equal(hit.length, 1);
        assert.match(hit[0]!.probe, new RegExp(`^statement ${e.id}: `));
        assert.equal(hit[0]!.verifiedBy, "upstream");
        assert.ok(hit[0]!.excerpt?.includes("sm_"));
        assert.deepEqual(Object.keys(hit[0]!.args as object), ["sql"]);
        // the other checks do not move
        assert.equal(byId(checks, "sql-guard-references").verdict, "pass");
      });
    }

    it("comment-hidden reaching the upstream is a near miss, not a leak", async () => {
      const { checks } = await run(leaking(["comment-hidden"]));
      const c = byId(checks, "sql-guard-statements");
      assert.equal(c.verdict, "pass");
      assert.equal(c.evidence.filter((x) => x.code === "sql-guard.near-miss").length, 1);
      assert.equal(c.evidence.filter((x) => x.code === "sql-guard.reached").length, 0);
    });

    it("every refusal is kept as evidence with the reply text, for refusal-quality", async () => {
      const { checks } = await run(leaking([]));
      const refusals = byId(checks, "sql-guard-statements").evidence.filter((x) => x.code === "sql-guard.refused");
      assert.equal(refusals.length, STATEMENT_CORPUS.length);
      assert.ok(refusals.every((x) => x.excerpt === "Error: only SELECT statements are allowed"));
    });

    it("a forwarder that answers late is still seen once the probes are done (the settle)", async () => {
      SETTLE_MS.value = 30;
      const stub = new FakeUpstream();
      const behavior = leaking([]);
      const session = new FakeSession([QUERY_TOOL], stub, (sql, a) => {
        if (idOf(sql) === "drop") setTimeout(() => stub.record(JSON.stringify({ sql })), 10);
        return behavior(sql, a);
      });
      const checks = await pack.run(makeCtx(stub, session, { allow: ALLOW }).ctx);
      assert.equal(byId(checks, "sql-guard-statements").verdict, "fail");
      assert.match(byId(checks, "sql-guard-statements").summary, /drop/);
    });

    it("probes that never got an answer are unjudged: all of them gives inconclusive, some of them a note", async () => {
      const behavior = leaking([]);
      const allDead = await run((sql, a) => (idOf(sql) === "control" ? behavior(sql, a) : { reply: timeout() }));
      assert.equal(byId(allDead.checks, "sql-guard-statements").verdict, "inconclusive");
      const someDead = await run((sql, a) => (idOf(sql) === "insert" ? { reply: timeout() } : behavior(sql, a)));
      const c = byId(someDead.checks, "sql-guard-statements");
      assert.equal(c.verdict, "pass");
      assert.match(c.summary, /1 unjudged/);
    });

    it("a leak beats unjudged probes", async () => {
      const behavior = leaking(["delete"]);
      const { checks } = await run((sql, a) => (idOf(sql) === "insert" ? { reply: timeout() } : behavior(sql, a)));
      assert.equal(byId(checks, "sql-guard-statements").verdict, "fail");
    });
  });

  describe("references", () => {
    for (const e of REFERENCE_CORPUS) {
      it(`${e.id} reaching the upstream fails the check`, async () => {
        const { checks } = await run(leaking([e.id]));
        const c = byId(checks, "sql-guard-references");
        assert.equal(c.verdict, "fail");
        assert.match(c.summary, new RegExp(`\\b${e.id}\\b`));
        assert.match(c.evidence.find((x) => x.code === "sql-guard.reached")!.probe, new RegExp(`^reference ${e.id}: `));
        assert.equal(byId(checks, "sql-guard-statements").verdict, "pass");
      });
    }

    it("the out-of-scope name is in the container of the first allow entry", async () => {
      const { session } = await run(leaking([]));
      const sent = session.calls.map((c) => String(c.args.sql));
      assert.ok(sent.some((s) => /FROM sales\.public\.outside_sm_[0-9a-f]{8} WHERE/.test(s)));
      assert.ok(sent.some((s) => /FROM "sales"\."public"\."outside_sm_[0-9a-f]{8}"/.test(s)));
    });

    it("is na without scope.allow, with the key to set, and the corpus is not sent", async () => {
      const { checks, session } = await run(leaking([]), {});
      const c = byId(checks, "sql-guard-references");
      assert.equal(c.verdict, "na");
      assert.match(c.summary, /scope\.allow/);
      assert.ok(!session.calls.some((x) => /outside_sm_/.test(String(x.args.sql))));
      assert.equal(byId(checks, "sql-guard-statements").verdict, "pass");
    });

    it("a prefix-only allow list works: the control is SELECT 1 and the out-of-scope name sits outside the prefix", async () => {
      const stub = new FakeUpstream();
      const session = new FakeSession([QUERY_TOOL], stub, (sql) => (/^SELECT 1 AS sm_[0-9a-f]{8}( LIMIT 1000000)?$/.test(sql) ? { forward: sql, reply: ok() } : { reply: err() }));
      const { ctx } = makeCtx(stub, session, { allow: ["sales.public."] });
      const checks = await pack.run(ctx);
      const sent = session.calls.map((c) => String(c.args.sql));
      assert.match(sent[0]!, /^SELECT 1 AS sm_/);
      assert.ok(sent.some((s) => /FROM sales\.outside_sm_/.test(s)));
      assert.equal(byId(checks, "sql-guard-references").verdict, "pass");
    });
  });

  describe("row cap", () => {
    const wrapTo = (n: number) => (sql: string) => `SELECT * FROM (${sql}) AS sm LIMIT ${n}`;

    it("pass: the wrapper forwards a limit at or below the cap, whatever the client asked for", async () => {
      const { checks } = await run(leaking([], wrapTo(1000)));
      const c = byId(checks, "sql-guard-rowcap");
      assert.equal(c.verdict, "pass");
      assert.match(c.summary, /reached the upstream as 1000 \(cap 10000\)/);
    });

    it("fail: the huge client LIMIT is forwarded as written", async () => {
      const behavior: Behavior = (sql) => {
        const id = idOf(sql);
        return id === "control" || id === "huge-limit" ? { forward: sql, reply: ok() } : { reply: err() };
      };
      const c = byId((await run(behavior)).checks, "sql-guard-rowcap");
      assert.equal(c.verdict, "fail");
      assert.match(c.summary, /forwarded as 1000000, above the cap of 10000/);
    });

    it("fail: a wrapper that keeps the client's larger outer LIMIT", async () => {
      const c = byId((await run(leaking([], (s) => `SELECT * FROM (${s}) AS sm LIMIT 1000000`))).checks, "sql-guard-rowcap");
      assert.equal(c.verdict, "fail");
    });

    it("part: no cap visible at the wire, with the note that says how to test a reply cap", async () => {
      // the huge-limit probe is refused, the control is forwarded bare
      const behavior: Behavior = (sql) => {
        const id = idOf(sql);
        return id === "control" ? { forward: sql, reply: ok() } : { reply: err() };
      };
      const c = byId((await run(behavior)).checks, "sql-guard-rowcap");
      assert.equal(c.verdict, "part");
      assert.match(c.summary, /no LIMIT, FETCH FIRST or TOP at the wire/);
      assert.match(c.summary, /upstream\.reply.*expect\.upstream\.token_echoed/);
    });

    it("a refused huge-limit probe falls back on the control's own limit", async () => {
      const behavior: Behavior = (sql) => (idOf(sql) === "control" ? { forward: `${sql} LIMIT 500`, reply: ok() } : { reply: err() });
      assert.equal(byId((await run(behavior)).checks, "sql-guard-rowcap").verdict, "pass");
      const over: Behavior = (sql) => (idOf(sql) === "control" ? { forward: `${sql} LIMIT 50000`, reply: ok() } : { reply: err() });
      assert.equal(byId((await run(over)).checks, "sql-guard-rowcap").verdict, "fail");
    });

    it("FETCH FIRST and TOP are recognised", async () => {
      const fetch = byId((await run(leaking([], (s) => `SELECT * FROM (${s}) AS sm FETCH FIRST 1000 ROWS ONLY`))).checks, "sql-guard-rowcap");
      assert.equal(fetch.verdict, "pass");
      const top = byId((await run(leaking([], (s) => `SELECT TOP 1000 * FROM (${s}) AS sm`))).checks, "sql-guard-rowcap");
      assert.equal(top.verdict, "pass");
    });

    it("nested wrappers take the outer limit", async () => {
      const nested = (s: string) => `SELECT * FROM (SELECT * FROM (${s}) AS a LIMIT 5000000) AS b LIMIT 800`;
      assert.equal(byId((await run(leaking([], nested))).checks, "sql-guard-rowcap").verdict, "pass");
      const loose = (s: string) => `SELECT * FROM (SELECT * FROM (${s}) AS a LIMIT 5) AS b LIMIT 90000`;
      assert.equal(byId((await run(leaking([], loose))).checks, "sql-guard-rowcap").verdict, "fail");
    });

    it("checks.sql-guard-rowcap.row_cap moves the line", async () => {
      const o = (n: number) => ({ allow: ALLOW, checks: { "sql-guard-rowcap": { enabled: true, severity: null, row_cap: n } } });
      assert.equal(byId((await run(leaking([], wrapTo(1000)), o(500))).checks, "sql-guard-rowcap").verdict, "fail");
      assert.equal(byId((await run(leaking([], wrapTo(1000)), o(1000))).checks, "sql-guard-rowcap").verdict, "pass");
    });

    it("the huge-limit probe is the control with LIMIT appended (a control that ends in ; is handled)", async () => {
      const { session } = await run(leaking([]), { allow: ALLOW, checks: { "sql-guard-statements": { enabled: true, severity: null, control_sql: "SELECT 2 AS sm_{token};" } } });
      assert.ok(session.calls.some((c) => /^SELECT 2 AS sm_[0-9a-f]{8} LIMIT 1000000$/.test(String(c.args.sql))));
    });
  });

  describe("tools and arguments", () => {
    it("sql_tools[].args are sent on every call", async () => {
      const tool = { ...QUERY_TOOL, inputSchema: { type: "object", properties: { sql: { type: "string" }, database: { type: "string" } }, required: ["sql", "database"] } };
      const { session } = await run(leaking([]), { allow: ALLOW, tools: [tool], sqlTools: [{ tool: "query", arg: "sql", args: { database: "sales" } }] });
      assert.ok(session.calls.length > 30);
      assert.ok(session.calls.every((c) => c.args.database === "sales"), "every call carries database");
    });

    it("an array-shaped SQL argument is sent as [sql] and still judged", async () => {
      const tool = { ...QUERY_TOOL, inputSchema: { type: "object", properties: { statements: { type: "array", items: { type: "string" } } }, required: ["statements"] } };
      const stub = new FakeUpstream();
      const session = new FakeSession([tool], stub, leaking(["delete"]), "statements");
      const { ctx } = makeCtx(stub, session, { allow: ALLOW, tools: [tool], sqlTools: [{ tool: "query", arg: "statements", shape: "array" }] });
      const checks = await pack.run(ctx);
      assert.ok(Array.isArray(session.calls[0]!.args.statements));
      assert.match(byId(checks, "sql-guard-statements").summary, /delete/);
    });

    it("a tool declared as a writer is not probed and is named", async () => {
      const stub = new FakeUpstream();
      const writer = { ...QUERY_TOOL, name: "execute" };
      const session = new FakeSession([QUERY_TOOL, writer], stub, leaking([]));
      const { ctx } = makeCtx(stub, session, { allow: ALLOW, tools: [QUERY_TOOL, writer], sqlTools: [{ tool: "query", arg: "sql" }, { tool: "execute", arg: "sql", role: "writer" }] });
      const checks = await pack.run(ctx);
      assert.ok(session.calls.every((c) => c.name === "query"));
      assert.match(byId(checks, "sql-guard-statements").summary, /not probed \(declared as writers\): execute/);
    });
  });

  describe("coverage", () => {
    it("counts the control and the probes the server processed, and lists the tool as probed", async () => {
      const { checks } = await run(leaking([]));
      const c = byId(checks, "sql-guard-statements");
      assert.deepEqual(c.coverage!.probed, ["query"]);
      assert.equal(c.coverage!.validCalls, 1 + STATEMENT_CORPUS.length);
    });

    it("a validation error does not count", async () => {
      const behavior = leaking([]);
      const { checks } = await run((sql, a) => (idOf(sql) === "insert" ? { reply: { ...err("Invalid params: expected string for sql"), rpcError: "-32602 Invalid params" } } : behavior(sql, a)));
      assert.equal(byId(checks, "sql-guard-statements").coverage!.validCalls, STATEMENT_CORPUS.length);
    });

    it("a tool whose control did not reach is not covered, with the reason", async () => {
      const { checks } = await run(() => ({ reply: err("Error: forbidden") }));
      const cov = byId(checks, "sql-guard-statements").coverage!;
      assert.deepEqual(cov.probed, []);
      assert.equal(cov.validCalls, 0);
      assert.match(cov.notCovered[0]!.reason, /never reached the upstream/);
    });
  });

  describe("applies, config", () => {
    it("applies only with a SQL tool and a stub, and says which is missing", () => {
      const stub = new FakeUpstream();
      assert.deepEqual(pack.applies(makeCtx(stub, undefined, { allow: ALLOW }).ctx), { ok: true });
      const noStub = pack.applies(makeCtx(stub, undefined, { noStub: true }).ctx);
      assert.equal(noStub.ok, false);
      assert.match((noStub as { reason: string }).reason, /upstream\.kind: http/);
      const noSql = pack.applies(makeCtx(stub, undefined, { tools: [{ name: "ping", inputSchema: { type: "object", properties: {} } }], sqlTools: [] }).ctx);
      assert.equal(noSql.ok, false);
      assert.match((noSql as { reason: string }).reason, /no tool takes a SQL string/);
    });

    it("a tool the classifier calls SQL (no sql_tools entry) is probed", async () => {
      const stub = new FakeUpstream();
      const tool = { ...QUERY_TOOL, name: "fetch_rows", inputSchema: { type: "object", properties: { stmt: { type: "string" } }, required: ["stmt"] } };
      const session = new FakeSession([tool], stub, leaking([]), "stmt");
      const { ctx } = makeCtx(stub, session, { allow: ALLOW, tools: [tool], sqlTools: [] });
      (ctx as { classification: unknown }).classification = [{ tool: "fetch_rows", class: "sql", confidence: "high", params: { sql: "stmt" }, unfillable: [], reasons: [] }];
      assert.deepEqual(pack.applies(ctx), { ok: true });
      await pack.run(ctx);
      assert.ok(session.calls.length > 30);
    });

    it("enabled: false reports na and sends nothing for that check; severity re-weights", async () => {
      const off = { enabled: false, severity: null };
      const { checks } = await run(leaking(["insert"]), { allow: ALLOW, checks: { "sql-guard-statements": off, "sql-guard-rowcap": { enabled: true, severity: "critical" } } });
      assert.equal(byId(checks, "sql-guard-statements").verdict, "na");
      assert.equal(byId(checks, "sql-guard-statements").summary, "disabled by config");
      assert.equal(byId(checks, "sql-guard-rowcap").critical, true);
    });

    it("a session that cannot be opened is inconclusive for every check, naming why", async () => {
      const stub = new FakeUpstream();
      const { ctx } = makeCtx(stub, undefined, { allow: ALLOW, open: async () => { throw new Error("spawn failed"); } });
      const checks = await pack.run(ctx);
      assert.ok(checks.every((c) => c.verdict === "inconclusive" && /spawn failed/.test(c.summary)));
    });
  });
});
