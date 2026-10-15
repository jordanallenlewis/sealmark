import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { McpSession } from "../mcp.js";
import { SETTLE_MS, pack } from "../packs/sql-guard.js";
import type { CheckResult, PackId } from "../types.js";
import { FakeUpstream, QUERY_TOOL, byId, makeCtx, startRecorder } from "./r6-sql-guard.rig.js";

// Round 6, P5: the pack against the real stdio toy (toy/sqlguard-r6.ts) whose `query` tool POSTs to a backend, with a loopback
// recorder as the stub. This is the toy matrix of the package; the integration package runs the full fixture.

const TOY = fileURLToPath(new URL("../toy/sqlguard-r6.js", import.meta.url));
let rec: Awaited<ReturnType<typeof startRecorder>>;
before(async () => {
  rec = await startRecorder();
  SETTLE_MS.value = 100;
});
after(async () => {
  await rec.close();
});

async function runMode(mode: string, allow = ["sales.public."]): Promise<{ checks: CheckResult[]; stub: FakeUpstream }> {
  const spec = { command: process.execPath, args: [TOY, "--mode", mode, "--backend", rec.url, "--allow", "sales.public."], env: {} };
  const open = () => McpSession.open(spec, { vars: {}, dsns: {} });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const { ctx } = makeCtx(rec.stub, undefined, { allow, tools, open });
  assert.deepEqual(pack.applies(ctx), { ok: true });
  return { checks: await pack.run(ctx), stub: rec.stub };
}

const v = (checks: CheckResult[]) => [byId(checks, "sql-guard-statements").verdict, byId(checks, "sql-guard-references").verdict, byId(checks, "sql-guard-rowcap").verdict];
const reachedIds = (c: CheckResult) => c.evidence.filter((e) => e.code === "sql-guard.reached").map((e) => e.probe.split(":")[0]!.split(" ")[1]);

describe("sql-guard against the toy server", () => {
  it("the toy forwards a query to the backend as POST /sql with the SQL in a JSON body", async () => {
    const spec = { command: process.execPath, args: [TOY, "--backend", rec.url], env: {} };
    const s = await McpSession.open(spec, { vars: {}, dsns: {} });
    try {
      const mark = rec.stub.mark();
      const r = await s.call("query", { sql: "SELECT 1 AS sm_wire" });
      assert.equal(r.isError, false);
      const [req] = rec.stub.find("sm_wire", mark);
      assert.equal(req!.method, "POST");
      assert.equal(req!.path, "/sql");
      assert.equal(typeof JSON.parse(req!.body).sql, "string");
      assert.match(JSON.parse(req!.body).sql, /SELECT 1 AS sm_wire/);
      assert.equal(s.tools.some((t) => t.name === QUERY_TOOL.name), true);
    } finally {
      await s.close();
    }
  });

  it("good: every check passes", async () => {
    const { checks } = await runMode("good");
    assert.deepEqual(v(checks), ["pass", "pass", "pass"]);
    assert.ok(checks.every((c) => (c.pack as PackId) === ("sql-guard" as PackId)));
  });

  it("comment-ok (a comment that looks hostile is forwarded as a comment): statements pass", async () => {
    const { checks } = await runMode("comment-ok");
    assert.deepEqual(v(checks), ["pass", "pass", "pass"]);
  });

  it("open (no guard): statements and references fail, row cap fails", async () => {
    const { checks } = await runMode("open");
    assert.deepEqual(v(checks), ["fail", "fail", "fail"]);
    const reached = reachedIds(byId(checks, "sql-guard-statements"));
    for (const id of ["insert", "drop", "stacked", "cte-dml", "obfuscated", "unparseable", "unbalanced"]) assert.ok(reached.includes(id), `${id} reached`);
    assert.ok(!reached.includes("comment-hidden"));
  });

  it("fail-open: unparseable and unbalanced input is forwarded, nothing else", async () => {
    const { checks } = await runMode("fail-open");
    assert.deepEqual(v(checks), ["fail", "pass", "pass"]);
    assert.deepEqual(reachedIds(byId(checks, "sql-guard-statements")).sort(), ["unbalanced", "unparseable"]);
  });

  it("first-keyword: DML hidden behind a leading SELECT or WITH is forwarded", async () => {
    const { checks } = await runMode("first-keyword");
    const reached = reachedIds(byId(checks, "sql-guard-statements"));
    assert.equal(byId(checks, "sql-guard-statements").verdict, "fail");
    for (const id of ["cte-dml", "stacked"]) assert.ok(reached.includes(id), `${id} reached`);
  });

  it("first-ref: only the first table reference is checked", async () => {
    const { checks } = await runMode("first-ref");
    assert.deepEqual(v(checks).slice(0, 2), ["pass", "fail"]);
    const reached = reachedIds(byId(checks, "sql-guard-references"));
    for (const id of ["join", "comma-join", "subquery-where", "union"]) assert.ok(reached.includes(id), `${id} reached`);
  });

  it("no-rowcap: the huge LIMIT is forwarded as written", async () => {
    const { checks } = await runMode("no-rowcap");
    assert.deepEqual(v(checks), ["pass", "pass", "fail"]);
  });

  it("passthrough: a wrapper that keeps the client's larger LIMIT fails the row cap", async () => {
    const { checks } = await runMode("passthrough");
    assert.deepEqual(v(checks), ["pass", "pass", "fail"]);
  });

  it("fetch-first (an outer FETCH FIRST instead of LIMIT) is a near miss: row cap passes", async () => {
    const { checks } = await runMode("fetch-first");
    assert.deepEqual(v(checks), ["pass", "pass", "pass"]);
  });

  it("refuse-all: every control fails, so every check is inconclusive, never pass", async () => {
    const { checks } = await runMode("refuse-all");
    assert.deepEqual(v(checks), ["inconclusive", "inconclusive", "inconclusive"]);
  });
});
