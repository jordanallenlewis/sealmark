import assert from "node:assert/strict";
import { after, before, describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { TemplateCtx } from "../config.js";
import { startAllEmbedded, freePort, quiet, TOY } from "./helpers.js";
import { type EmbeddedHandle } from "../embedded.js";
import { McpSession } from "../mcp.js";
import { MUTATION_CORPUS, describe as describeDb, runDb } from "../packs/db.js";
import { discoverSqlTools } from "../packs/shared.js";
import { ROLES, provision, roleDsn, type PgTarget, type Role } from "../seed.js";
import type { CheckResult } from "../types.js";

// Round 3, sql-pack, item sp-2: three corpus cases added to mutating-sql (all non-core), each proven by a policy toy
// (toy/db-policy.ts) that blocks the older forms and runs the new one, and by the good toy, which blocks all of them.
const TOY_POLICY = fileURLToPath(new URL("../toy/db-policy.js", import.meta.url));
const TIMEOUT_SEC = 3;

const NEW_CASES = ["PREPARE and EXECUTE in one call", "function with side effects in FROM", "EXPLAIN ANALYZE runs the statement"] as const;
const OLD_TWO_CALL = "PREPARE then EXECUTE";
const OLD_SELECT_LIST_FN = "function with side effects (defeats any prefix filter by construction)";

async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

async function viaRunDb(target: PgTarget, command: string, args: string[]): Promise<CheckResult[]> {
  await provision(target);
  const spec = { command: process.execPath, args: [command, ...args, "--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)], env: {} };
  const tctx = (role: Role): TemplateCtx => ({ vars: { dsn: roleDsn(target, role) }, dsns: Object.fromEntries(ROLES.map((r) => [r, roleDsn(target, r)])) });
  const open = (role: Role) => McpSession.open(spec, tctx(role), {});
  const probe = await open("admin");
  const found = discoverSqlTools(probe.tools).tools;
  await probe.close();
  return runDb({ target, sqlTools: found, open, timeoutSec: TIMEOUT_SEC, log: quiet });
}

/** The ids of the corpus cases whose effect the harness found in the database. */
function executed(checks: CheckResult[]): string[] {
  const m = checks.find((c) => c.id === "mutating-sql")!;
  return m.evidence.flatMap((e) => {
    const x = /^EXECUTED: (.*); the database changed$/.exec(e.outcome);
    return x ? [x[1]] : [];
  });
}

const handles: EmbeddedHandle[] = [];
const runs: Record<string, CheckResult[]> = {};
let skipReason: string | undefined;

describe("mutating-sql corpus: three new cases, each proven by a policy toy (embedded Postgres)", { timeout: 600_000 }, () => {
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
    const ports = await distinctPorts(3);
    await startAllEmbedded(handles, ports);
    const [a, b, c] = handles.map((h) => h.target);
    await Promise.all([
      (async () => {
        runs.pooled = await viaRunDb(a, TOY_POLICY, ["--mode", "pooled"]);
        runs.good = await viaRunDb(a, TOY, ["--mode", "good"]);
      })(),
      (async () => {
        runs.selectlist = await viaRunDb(b, TOY_POLICY, ["--mode", "selectlist"]);
      })(),
      (async () => {
        runs.explainok = await viaRunDb(c, TOY_POLICY, ["--mode", "explainok"]);
      })(),
    ]);
  }, { timeout: 420_000 });

  after(async () => {
    for (const h of handles) await h.stop();
  });

  const skip = (t: TestContext) => {
    if (skipReason) t.skip(skipReason);
    return Boolean(skipReason);
  };
  const verdictOf = (mode: string, id: string) => runs[mode].find((c) => c.id === id)?.verdict;

  it("the corpus has 19 cases (round 5 added three terminator cases); the three round 3 cases are non-core and last, in the published order", () => {
    assert.equal(MUTATION_CORPUS.length, 19);
    assert.deepEqual(MUTATION_CORPUS.slice(16).map((c) => [c.id, c.kind, c.core]), [
      ["PREPARE and EXECUTE in one call", "prepared", false],
      ["function with side effects in FROM", "indirect-fn", false],
      ["EXPLAIN ANALYZE runs the statement", "explain", false],
    ]);
    assert.deepEqual(MUTATION_CORPUS.slice(16).map((c) => c.steps), [
      ["PREPARE p2 AS INSERT INTO probe_t VALUES (9012,'prep1'); EXECUTE p2"],
      ["SELECT * FROM sm_mutate()"],
      ["EXPLAIN ANALYZE INSERT INTO probe_t (id, v) VALUES (9013, 'explain')"],
    ]);
    assert.equal(MUTATION_CORPUS.filter((c) => c.core).length, 7, "the core set is the four of round 3 plus the ROLLBACK, END and ABORT escapes (round 5)");
    assert.equal(new Set(MUTATION_CORPUS.map((c) => c.id)).size, 19, "ids are unique: they are what the verification closures are keyed by");
    const doc = describeDb().find((d) => d.id === "mutating-sql")!;
    assert.equal(doc.probes.length, 19);
    assert.deepEqual(doc.probes.slice(16).map((p) => p.id), [...NEW_CASES]);
  });

  it("pooled: PREPARE and EXECUTE in one call runs, the two-call form does not (a fresh connection per call)", (t) => {
    if (skip(t)) return;
    const ran = executed(runs.pooled);
    assert.ok(ran.includes("PREPARE and EXECUTE in one call"), ran.join(" | "));
    assert.ok(!ran.includes(OLD_TWO_CALL), ran.join(" | "));
    assert.deepEqual(ran, ["PREPARE and EXECUTE in one call"], "nothing else runs on this toy");
    assert.equal(verdictOf("pooled", "mutating-sql"), "part");
  });

  // Round 4 (D6): the two-call form ends in 'prepared statement "p" does not exist' when a pool hands EXECUTE to another connection.
  // That is not a block, and the summary no longer counts it as one.
  it("pooled: the two-call PREPARE/EXECUTE is reported as not executed because of connection pooling, not as blocked", (t) => {
    if (skip(t)) return;
    const m = runs.pooled.find((c) => c.id === "mutating-sql")!;
    const e = m.evidence.find((x) => x.probe.startsWith("PREPARE p AS INSERT"));
    assert.equal(e?.code, "db.mut.pool-rotated", JSON.stringify(e));
    assert.match(e?.outcome ?? "", /^not executed: the pool handed EXECUTE to another connection \(not a block\)/);
    assert.match(m.summary, /^EXECUTED: PREPARE and EXECUTE in one call; 17 of 19 blocked, 1 not executed because of connection pooling$/);
    assert.ok(!m.evidence.some((x) => x !== e && x.code === "db.mut.pool-rotated"), "only the two-call form is relabelled");
  });

  // Round 5 (sql-8): the write gate is computed after the corpus; a non-core case that executed no longer reads as "no write concept".
  it("pooled: write-gate says plain writes were blocked and names the corpus case that executed through the tool (n/a, advisory)", (t) => {
    if (skip(t)) return;
    const wg = runs.pooled.find((c) => c.id === "write-gate")!;
    assert.equal(wg.verdict, "na", wg.summary);
    assert.equal(wg.summary, "plain writes were blocked (see mutating-sql: a corpus case executed through query)");
    assert.equal(runs.good.find((c) => c.id === "write-gate")!.summary.slice(0, 16), "no write concept");
  });

  it("good (near miss): a server that blocks the two-call form with its own refusal still counts it as blocked, with no pooling note", (t) => {
    if (skip(t)) return;
    const m = runs.good.find((c) => c.id === "mutating-sql")!;
    assert.ok(!m.evidence.some((x) => x.code === "db.mut.pool-rotated"));
    assert.doesNotMatch(m.summary, /connection pooling/);
  });

  it("selectlist: only the function in FROM runs; the same function in the select list is blocked", (t) => {
    if (skip(t)) return;
    const ran = executed(runs.selectlist);
    assert.deepEqual(ran, ["function with side effects in FROM"]);
    assert.ok(!ran.includes(OLD_SELECT_LIST_FN));
    assert.equal(verdictOf("selectlist", "mutating-sql"), "part");
  });

  it("explainok: only EXPLAIN ANALYZE of a write runs", (t) => {
    if (skip(t)) return;
    assert.deepEqual(executed(runs.explainok), ["EXPLAIN ANALYZE runs the statement"]);
    assert.equal(verdictOf("explainok", "mutating-sql"), "part");
  });

  it("good: all 19 forms stay blocked (its BEGIN READ ONLY transaction stops the three new ones too)", (t) => {
    if (skip(t)) return;
    assert.deepEqual(executed(runs.good), []);
    const m = runs.good.find((c) => c.id === "mutating-sql")!;
    assert.equal(m.verdict, "pass");
    assert.match(m.summary, /^all 19 mutation forms blocked on the 1 probed SQL tool \(query\)$/);
    assert.equal(m.evidence.length, 19);
    for (const id of NEW_CASES) {
      const c = MUTATION_CORPUS.find((x) => x.id === id)!;
      assert.ok(m.evidence.some((e) => e.probe === c.steps.join("  →  ") && /^blocked or ineffective/.test(e.outcome)), id);
    }
  });

  it("each case runs on its own toy only: no new case runs on another policy toy or on good", (t) => {
    if (skip(t)) return;
    const owner: Record<string, string> = { pooled: NEW_CASES[0], selectlist: NEW_CASES[1], explainok: NEW_CASES[2] };
    for (const mode of ["pooled", "selectlist", "explainok", "good"]) {
      const ran = executed(runs[mode]).filter((id) => (NEW_CASES as readonly string[]).includes(id));
      assert.deepEqual(ran, owner[mode] ? [owner[mode]] : [], mode);
    }
  });

  it("the policy toys are near misses everywhere else: plain writes blocked, rls and pii enforced by the database", (t) => {
    if (skip(t)) return;
    for (const mode of ["pooled", "selectlist", "explainok"]) {
      assert.equal(verdictOf(mode, "read-only"), "pass", mode);
      assert.equal(verdictOf(mode, "rls"), "pass", mode);
      assert.equal(verdictOf(mode, "pii"), "pass", mode);
      assert.equal(verdictOf(mode, "pii-masked"), "pass", mode);
    }
  });
});
