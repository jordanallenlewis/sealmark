import assert from "node:assert/strict";
import { after, before, describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { TemplateCtx } from "../config.js";
import { startEmbedded, type EmbeddedHandle } from "../embedded.js";
import { gradePack } from "../grade.js";
import { McpSession } from "../mcp.js";
import { runDb, type DbCtx } from "../packs/db.js";
import { coverageNotes, discoverSqlTools } from "../packs/shared.js";
import { runHarness } from "../run.js";
import { ROLES, adminDsn, provision, roleDsn, type PgTarget, type Role } from "../seed.js";
import type { CheckResult, RunResult, SealmarkConfig, Verdict } from "../types.js";
import { freePort, gradeOf, quiet, startAllEmbedded, verdicts } from "./helpers.js";

// The toy modes in toy/db-extra.ts, against the expected-results table in the design notes
// Column order: read-only, write-gate (advisory), rls, mutating-sql, pii, pii-masked, db-rowcap, db-timeout.
const IDS = ["read-only", "write-gate", "rls", "mutating-sql", "pii", "pii-masked", "db-rowcap", "db-timeout"];
const EXPECTED: Record<string, { v: Verdict[]; db: string; pct: number; raw?: string; capped?: boolean }> = {
  writers: { v: ["part", "fail", "pass", "fail", "pass", "pass", "fail", "fail"], db: "D", pct: 50, raw: "D", capped: false },
  textrefusal: { v: ["pass", "na", "pass", "pass", "pass", "pass", "pass", "pass"], db: "A", pct: 100 },
  gated: { v: ["pass", "pass", "pass", "pass", "pass", "pass", "pass", "pass"], db: "A", pct: 100 },
};

const TOY_EXTRA = fileURLToPath(new URL("../toy/db-extra.js", import.meta.url));
const extraConfig = (mode: string, extraArgs: string[] = []): SealmarkConfig => ({ name: `toy-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [TOY_EXTRA, "--mode", mode, ...extraArgs], env: {} } });

/** Free ports that differ from one another: three concurrent freePort() calls could otherwise hand out the same one. */
async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

const TIMEOUT_SEC = 3;
const runs: Record<string, RunResult> = {};
const direct: Record<string, { checks: CheckResult[]; found: ReturnType<typeof discoverSqlTools>["tools"] }> = {};
const handles: EmbeddedHandle[] = [];
let skipReason: string | undefined;

async function viaHarness(target: PgTarget, mode: string, packs: ("core" | "db")[] = ["core", "db"]): Promise<RunResult> {
  return runHarness({ config: extraConfig(mode, ["--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)]), packs, packsExplicit: true, pg: adminDsn(target), yes: true, timeoutProbeSec: TIMEOUT_SEC, log: quiet });
}

/** runDb with a hand-built context: for what the pipeline cannot express yet (array tools, thresholds from config). */
async function viaRunDb(target: PgTarget, mode: string, over: Partial<DbCtx> = {}) {
  await provision(target);
  const spec = extraConfig(mode, ["--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)]).server;
  const tctx = (role: Role): TemplateCtx => ({ vars: { dsn: roleDsn(target, role) }, dsns: Object.fromEntries(ROLES.map((r) => [r, roleDsn(target, r)])) });
  const open = (role: Role) => McpSession.open(spec, tctx(role), {});
  const probe = await open("admin");
  const found = discoverSqlTools(probe.tools).tools;
  await probe.close();
  const checks = await runDb({ target, sqlTools: found, open, timeoutSec: TIMEOUT_SEC, log: quiet, ...over });
  return { checks, found };
}

describe("db pack against the db-extra toy servers (embedded Postgres)", { timeout: 600_000 }, () => {
  before(async () => {
    if (process.env.SEALMARK_SKIP_DB === "1") {
      skipReason = "SEALMARK_SKIP_DB=1";
      return;
    }
    try {
      await import("embedded-postgres");
    } catch (e) {
      throw new Error(`embedded-postgres could not be loaded (${(e as Error).message}), so the db pack tests cannot run. Install it, or set SEALMARK_SKIP_DB=1 to skip them on purpose.`);
    }
    // Every run re-provisions the same seed database, so runs that share an instance go one after another. Three instances keep the file fast.
    const ports = await distinctPorts(3);
    await startAllEmbedded(handles, ports);
    const [a, b, c] = handles.map((h) => h.target);
    await Promise.all([
      (async () => {
        runs.writers = await viaHarness(a, "writers");
      })(),
      (async () => {
        runs.textrefusal = await viaHarness(b, "textrefusal");
        runs.planner = await viaHarness(b, "planner", ["db"]);
        runs.ddlstrict = await viaHarness(b, "ddlstrict", ["db"]);
        direct.refusecap = await viaRunDb(b, "refusecap", { expectedSec: 2, slowSql: "SELECT pg_sleep(40)" });
      })(),
      (async () => {
        runs.gated = await viaHarness(c, "gated");
        direct.arrayq = await viaRunDb(c, "arrayq", { rowCap: 500 });
      })(),
    ]);
  }, { timeout: 420_000 }); // a hook is not bounded by its suite's timeout

  after(async () => {
    for (const h of handles) await h.stop();
  });

  const skip = (t: TestContext) => {
    if (skipReason) t.skip(skipReason);
    return Boolean(skipReason);
  };
  const check = (r: RunResult, id: string) => r.checks.find((c) => c.id === id)!;

  for (const [mode, want] of Object.entries(EXPECTED)) {
    it(`${mode}: db verdicts and grade match the expected-results table`, (t) => {
      if (skip(t)) return;
      const r = runs[mode];
      const got = verdicts(r, "db");
      assert.deepEqual(IDS.map((id) => got[id]), want.v, `verdicts for ${mode}: ${JSON.stringify(got)}`);
      const g = gradeOf(r, "db");
      assert.ok(g, "db pack should be graded");
      assert.equal(g.letter, want.db);
      assert.equal(g.pct, want.pct);
      assert.equal(g.capped, Boolean(want.capped));
      if (want.raw) assert.equal(g.raw, want.raw);
      assert.equal(gradeOf(r, "core")?.letter, "A", "core is A on every one of these servers");
    });
  }

  // Round 5 (sql-3, sql-8): create_table takes neither a SELECT nor an INSERT, so it used to be "not covered"; CREATE TABLE is now the third control.
  it("writers: write_query is a probed tool; create_table (SELECT and INSERT controls fail) is controlled through CREATE TABLE and gets the DDL case", (t) => {
    if (skip(t)) return;
    const r = runs.writers;
    const ro = check(r, "read-only");
    assert.deepEqual(ro.coverage?.probed.slice().sort(), ["create_table", "read_query", "write_query"]);
    assert.deepEqual(ro.coverage?.notCovered, []);
    // Read probes skip the writers, and say so.
    for (const id of ["rls", "pii", "pii-masked", "db-rowcap", "db-timeout"]) {
      const c = check(r, id);
      assert.deepEqual(c.coverage?.probed, ["read_query"], id);
      for (const w of ["write_query", "create_table"]) assert.ok(c.coverage?.notCovered.some((n) => n.tool === w && n.reason === "declared writer tool: read probes do not apply"), `${id} ${w}`);
    }
    // mutating-sql probes the reader with the corpus and the DDL-only tool with its one core case.
    const mut = check(r, "mutating-sql");
    assert.deepEqual(mut.coverage?.probed.slice().sort(), ["create_table", "read_query"]);
    const ddl = mut.evidence.find((e) => e.tool === "create_table");
    assert.equal(ddl?.code, "db.mut.executed.ddl", "create_table runs stacked statements, so the INSERT behind the CREATE TABLE ran");
    assert.equal(ddl?.verifiedBy, "db-state");
    assert.match(ddl?.probe ?? "", /^CREATE TABLE sm_ddl_stacked \(x int\); INSERT INTO probe_t/);
    assert.match(mut.summary, /DDL then write in one call \(DDL-only tool\)/);
    // The run-level lines name nothing: every tool was exercised.
    assert.deepEqual(coverageNotes(r.checks, "db"), []);
    // The controls: reader control on read_query, writer control (verified in the database) on write_query, CREATE TABLE control on create_table.
    const codes = ro.evidence.map((e) => `${e.tool}:${e.code}`);
    assert.ok(codes.includes("read_query:db.control.reader"), codes.join(" "));
    assert.ok(codes.includes("write_query:db.control.writer"), codes.join(" "));
    assert.ok(codes.includes("create_table:db.control.writer-failed") && codes.includes("create_table:db.control.ddl"), codes.join(" "));
  });

  it("ddlstrict (near miss): a create_table that refuses stacked input is controlled, probed, and blocks the stacked write", (t) => {
    if (skip(t)) return;
    const r = runs.ddlstrict;
    const mut = check(r, "mutating-sql");
    assert.equal(mut.verdict, "pass", mut.summary);
    assert.match(mut.summary, /^all 19 mutation forms blocked on the 1 probed SQL tool \(read_query\); the stacked write was blocked on the DDL-only tool create_table$/);
    const ddl = mut.evidence.find((e) => e.tool === "create_table");
    assert.equal(ddl?.code, "db.mut.blocked.ddl");
    assert.match(ddl?.outcome ?? "", /only a single CREATE TABLE statement is allowed/);
    assert.deepEqual(check(r, "read-only").coverage?.notCovered, []);
    assert.equal(check(r, "read-only").verdict, "pass");
  });

  it("writers: a core corpus case that ran through a tool with no approval parameter fails the write gate; ddlstrict leaves it n/a", (t) => {
    if (skip(t)) return;
    assert.equal(check(runs.writers, "write-gate").verdict, "fail");
    const wg = check(runs.ddlstrict, "write-gate");
    assert.equal(wg.verdict, "na");
    assert.match(wg.summary, /create_table blocked every plain write and declare no approval parameter/);
  });

  it("writers: the read-only summary names the tool that wrote and the one that blocked", (t) => {
    if (skip(t)) return;
    const ro = check(runs.writers, "read-only");
    assert.match(ro.summary, /writes executed through write_query \(declared writer tool; exclude it under tools\.exclude if writes are intended\) and blocked on read_query/);
    assert.equal(check(runs.writers, "write-gate").verdict, "fail");
    // mutating-sql lists what ran.
    const mut = check(runs.writers, "mutating-sql");
    assert.match(mut.summary, /^EXECUTED: stacked statements \(DROP\), stacked statements \(INSERT\)/);
    assert.match(mut.summary, /function with side effects \(defeats any prefix filter by construction\)/);
    // 19 corpus forms on read_query plus the one DDL case on create_table (round 5).
    assert.match(mut.summary, /\d+ of 20 blocked$/);
  });

  it("writers: the summary lines quote the probe that decided, not a control read; db-timeout says 'no timeout within Ns (expected Ns)' and names the probe", (t) => {
    if (skip(t)) return;
    const ro = check(runs.writers, "read-only");
    assert.ok(ro.evidence.some((e) => e.code === "db.control.reader"), "the control reads are still in the evidence");
    assert.equal(ro.evidence[0].code, "db.ro.executed", "evidence[0] is what the summary quotes");
    const to = check(runs.writers, "db-timeout");
    assert.equal(to.verdict, "fail");
    assert.equal(to.summary, `no statement timeout within ${TIMEOUT_SEC + 8}s (expected ${TIMEOUT_SEC}s): SELECT pg_sleep(${TIMEOUT_SEC + 20}) on read_query`);
    assert.equal(to.evidence[0].code, "db.timeout.running");
  });

  it("textrefusal: the instant plain-text refusal of pg_sleep is 'refused before execution', then the CPU-bound fallback is cancelled", (t) => {
    if (skip(t)) return;
    const c = check(runs.textrefusal, "db-timeout");
    assert.equal(c.verdict, "pass");
    assert.match(c.evidence[0].probe, /CROSS JOIN/, "the fallback that decided leads, not the refused pg_sleep");
    assert.equal(c.evidence[0].code, "db.timeout.fallback.cancelled");
    assert.ok(c.evidence.some((e) => /refused before execution/.test(e.outcome)), JSON.stringify(c.evidence.map((e) => e.outcome)));
    assert.ok(c.evidence.some((e) => /CROSS JOIN/.test(e.probe) && /statement ended after/.test(e.outcome)));
    assert.ok(c.evidence.some((e) => e.code === "db.timeout.refused-fast"));
  });

  it("textrefusal: plain-text refusals are found in core too, and the server database errors are database-enforced", (t) => {
    if (skip(t)) return;
    const robust = check(runs.textrefusal, "robust-input");
    assert.equal(robust.verdict, "pass");
    assert.ok(robust.evidence.some((e) => e.code === "robust.text-refusal"));
    assert.equal(check(runs.textrefusal, "pii").enforcedBy, "database");
    assert.equal(check(runs.textrefusal, "pii").coverage?.outcome, "denied");
  });

  it("planner: a plan is not rows, so no SQL tool is controlled and nothing passes", (t) => {
    if (skip(t)) return;
    const r = runs.planner;
    assert.equal(r.packs.db?.status, "inconclusive");
    assert.match(r.packs.db?.reason ?? "", /no SQL tool could run a basic read/);
    assert.match(r.packs.db?.reason ?? "", /returned a plan, not rows/);
    // db-privilege (advisory, once registered) is about which role the server connected as, which a plan-only server still shows.
    assert.ok(!r.checks.some((c) => c.pack === "db" && c.verdict === "pass" && c.id !== "db-privilege"));
    assert.deepEqual(r.checks.find((c) => c.id === "write-gate")?.verdict, "na");
    assert.deepEqual(check(r, "rls").coverage?.notCovered.map((n) => n.tool), ["query"]);
  });

  it("gated: a writer with an approval parameter that refused the plain write passes the gate, and is covered by read-only", (t) => {
    if (skip(t)) return;
    const r = runs.gated;
    const wg = check(r, "write-gate");
    assert.equal(wg.verdict, "pass");
    assert.match(wg.summary, /every writer tool \(write_query\) has an approval parameter \(confirm\)/);
    assert.match(wg.summary, /the harness never approves/);
    assert.ok(check(r, "read-only").coverage?.probed.includes("write_query"));
    assert.ok(check(r, "read-only").evidence.some((e) => e.code === "db.control.gated"));
    assert.ok(check(r, "rls").coverage?.notCovered.some((n) => n.tool === "write_query"));
    // Advisory: not scored.
    assert.equal(wg.advisory, true);
  });

  it("arrayq: an array-of-SQL tool is discovered with shape array and probed with [sql]; rowCap moves the threshold", (t) => {
    if (skip(t)) return;
    const { checks, found } = direct.arrayq;
    assert.deepEqual(found, [{ tool: "run_queries", arg: "queries", role: "reader", shape: "array" }]);
    const got = Object.fromEntries(checks.map((c) => [c.id, c.verdict]));
    assert.deepEqual(IDS.map((id) => got[id]), ["pass", "na", "pass", "pass", "pass", "pass", "fail", "pass"], JSON.stringify(got));
    const cap = checks.find((c) => c.id === "db-rowcap")!;
    assert.match(cap.evidence[0].outcome, /cap threshold 500/);
    assert.deepEqual(cap.evidence[0].args, { queries: ["SELECT id, payload FROM big_table ORDER BY id"] });
    assert.deepEqual(checks.find((c) => c.id === "read-only")?.coverage?.probed, ["run_queries"]);
    assert.equal(gradePack("db", checks)?.pct, 85.71);
  });

  it("refusecap: a plain-text 'result too large' counts as a cap; expected_sec and slow_sql are used", (t) => {
    if (skip(t)) return;
    const { checks } = direct.refusecap;
    const got = Object.fromEntries(checks.map((c) => [c.id, c.verdict]));
    assert.deepEqual(IDS.map((id) => got[id]), ["pass", "na", "pass", "pass", "pass", "pass", "pass", "pass"], JSON.stringify(got));
    const cap = checks.find((c) => c.id === "db-rowcap")!;
    assert.match(cap.evidence[0].outcome, /^refused as too large/);
    const to = checks.find((c) => c.id === "db-timeout")!;
    assert.match(to.evidence[0].probe, /SELECT pg_sleep\(40\) with a 2s expectation/);
    assert.equal(to.evidence[0].args && JSON.stringify(to.evidence[0].args), JSON.stringify({ sql: "SELECT pg_sleep(40)" }));
  });
});
