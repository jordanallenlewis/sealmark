import assert from "node:assert/strict";
import { after, before, describe, it, type TestContext } from "node:test";
import { CHECKS } from "../config/schema.js";
import { startEmbedded, type EmbeddedHandle } from "../embedded.js";
import type { PgTarget } from "../seed.js";
import { runHarness } from "../run.js";
import { adminDsn } from "../seed.js";
import type { RunResult, Verdict } from "../types.js";
import { freePort, gradeOf, quiet, startAllEmbedded, toyConfig, verdicts } from "./helpers.js";

// the expected grades, with cap-timeout split into db-rowcap and
// db-timeout, pii-masked added; 7 scored checks). Column order: read-only, write-gate (advisory), rls, mutating-sql, pii,
// pii-masked, db-rowcap, db-timeout.
const IDS = ["read-only", "write-gate", "rls", "mutating-sql", "pii", "pii-masked", "db-rowcap", "db-timeout"];
const EXPECTED: Record<string, { v: Verdict[]; core: string; db: string; pct: number; raw?: string; capped?: boolean }> = {
  good: { v: ["pass", "na", "pass", "pass", "pass", "pass", "pass", "pass"], core: "A", db: "A", pct: 100 },
  owner: { v: ["pass", "na", "fail", "pass", "fail", "pass", "pass", "pass"], core: "A", db: "D", pct: 71.43, raw: "C", capped: true },
  leaky: { v: ["fail", "fail", "pass", "fail", "pass", "pass", "fail", "fail"], core: "A", db: "F", pct: 42.86 },
};

/** Free ports that differ from one another: three concurrent freePort() calls could otherwise hand out the same one. */
async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

const TIMEOUT_SEC = 3;
const handles: EmbeddedHandle[] = [];
let skipReason: string | undefined;
const results: Record<string, RunResult> = {};
const extra: Record<string, RunResult> = {};

function args(mode: string): string[] {
  const a = ["--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)];
  return mode === "owner" ? [...a, "--owner-dsn", "{dsn:admin}"] : a;
}

describe("db pack against toy servers (embedded Postgres)", { timeout: 600_000 }, () => {
  before(async () => {
    // The three critical db checks live behind this suite, so a missing database must fail the build unless skipping is explicit.
    if (process.env.SEALMARK_SKIP_DB === "1") {
      skipReason = "SEALMARK_SKIP_DB=1";
      return;
    }
    try {
      await import("embedded-postgres");
    } catch (e) {
      throw new Error(`embedded-postgres could not be loaded (${(e as Error).message}), so the db pack tests cannot run. Install it, or set SEALMARK_SKIP_DB=1 to skip them on purpose.`);
    }
    // Every run re-provisions the same seed database, so runs that share an instance go one after another. The slow servers
    // (no timeout, so the harness waits out the full window) each get an instance, which keeps the file under a minute.
    const ports = await distinctPorts(3);
    await startAllEmbedded(handles, ports);
    const [a, b, c] = handles.map((h) => h.target);
    const full = (target: PgTarget, mode: string) =>
      runHarness({ config: toyConfig(mode, args(mode)), packs: ["core", "db"], packsExplicit: true, pg: adminDsn(target), yes: true, timeoutProbeSec: TIMEOUT_SEC, log: quiet });
    // Servers that fool the harness if it only looks at database state: one that ignores the role it was given, one that dies on writes.
    const trap = (target: PgTarget, key: string, mode: string, dsnArg: string) =>
      runHarness({
        config: toyConfig(mode, ["--dsn", dsnArg, "--timeout", String(TIMEOUT_SEC)]),
        packs: ["db"],
        packsExplicit: true,
        pg: adminDsn(target),
        yes: true,
        timeoutProbeSec: TIMEOUT_SEC,
        log: quiet,
      }).then((r) => {
        extra[key] = r;
      });
    await Promise.all([
      (async () => {
        results.good = await full(a, "good");
        results.owner = await full(a, "owner");
        await trap(a, "pinned", "leaky", "{dsn:analyst}");
      })(),
      (async () => {
        results.leaky = await full(b, "leaky");
      })(),
      trap(c, "crashwrite", "crashwrite", "{dsn}"),
    ]);
  }, { timeout: 420_000 }); // a hook is not bounded by its suite's timeout

  after(async () => {
    for (const h of handles) await h.stop();
  });

  const skip = (t: TestContext) => {
    if (skipReason) t.skip(skipReason);
    return Boolean(skipReason);
  };

  for (const [mode, want] of Object.entries(EXPECTED)) {
    it(`${mode}: db verdicts and grades match the expected-results table`, (t) => {
      if (skip(t)) return;
      const r = results[mode];
      const got = verdicts(r, "db");
      assert.deepEqual(IDS.map((id) => got[id]), want.v, `verdicts for ${mode}: ${JSON.stringify(got)}`);
      const db = gradeOf(r, "db");
      assert.ok(db, "db pack should be graded");
      assert.equal(db.letter, want.db);
      assert.equal(db.pct, want.pct);
      assert.equal(db.capped, Boolean(want.capped));
      if (want.raw) assert.equal(db.raw, want.raw);
      assert.equal(gradeOf(r, "core")?.letter, want.core);
    });
  }

  it("a server pinned to the analyst role for every session is inconclusive, not credited with blocking writes", (t) => {
    if (skip(t)) return;
    const db = extra.pinned.packs.db;
    assert.equal(db?.status, "inconclusive");
    assert.match(db?.reason ?? "", /did not connect as the requested database role/);
    assert.ok(!extra.pinned.checks.some((c) => c.verdict === "pass"));
  });

  it("a server pinned to the analyst role is also named by db-privilege (advisory), once the methodology package registers the check", (t) => {
    if (skip(t)) return;
    const p = extra.pinned.checks.find((c) => c.id === "db-privilege");
    if (!CHECKS.some((c) => c.id === "db-privilege")) {
      assert.equal(p, undefined, "not registered: the pack does not emit it");
      return;
    }
    assert.equal(p?.verdict, "fail");
    assert.equal(p?.advisory, true);
    assert.match(p?.summary ?? "", /as admin, connected as sm_analyst/);
  });

  it("a server that dies on its first write gets inconclusive write checks, not a pass", (t) => {
    if (skip(t)) return;
    const got = verdicts(extra.crashwrite, "db");
    assert.equal(got["read-only"], "inconclusive");
    assert.equal(got["write-gate"], "na");
    assert.equal(got["mutating-sql"], "inconclusive");
    // The admin session is started again, so the checks that do not need writes still run.
    assert.equal(got.rls, "pass");
    assert.equal(got.pii, "pass");
    assert.equal(got["pii-masked"], "pass");
    assert.equal(got["db-rowcap"], "fail");
    assert.equal(got["db-timeout"], "fail");
    const g = gradeOf(extra.crashwrite, "db")!;
    assert.equal(g.provisional, true);
    // the design notes 1.6: C, 60% (3 of 5 scored).
    assert.equal(g.letter, "C");
    assert.equal(g.pct, 60);
  });

  it("good: rls and pii say who enforced them, and pii records that the raw column was denied", (t) => {
    if (skip(t)) return;
    const rls = results.good.checks.find((c) => c.id === "rls")!;
    const pii = results.good.checks.find((c) => c.id === "pii")!;
    assert.equal(rls.enforcedBy, "database");
    assert.equal(pii.enforcedBy, "database");
    assert.match(rls.summary, /^DB-enforced: the server passed the policy through and added no filtering of its own/);
    assert.ok(rls.evidence.every((e) => e.enforcedBy === "database"));
    assert.equal(pii.coverage?.outcome, "denied");
    assert.ok(pii.evidence.some((e) => e.code === "db.pii.denied"));
  });

  it("owner: a leak is a fail whose enforcement is unknown, and pii records leaked", (t) => {
    if (skip(t)) return;
    const pii = results.owner.checks.find((c) => c.id === "pii")!;
    assert.equal(pii.verdict, "fail");
    assert.equal(pii.enforcedBy, "unknown");
    assert.equal(pii.coverage?.outcome, "leaked");
    // The owner reads the masked view too (seed 0.2 grants it to sm_admin).
    assert.equal(results.owner.checks.find((c) => c.id === "pii-masked")?.verdict, "pass");
  });

  it("good: the controls name the tool that is the control reader and every check carries coverage", (t) => {
    if (skip(t)) return;
    // audit and db-privilege are advisory observations of the session, not probes of a tool: they carry no coverage.
    for (const c of results.good.checks.filter((x) => x.pack === "db" && x.id !== "audit" && x.id !== "db-privilege")) {
      assert.ok(c.coverage, c.id);
      assert.deepEqual(c.coverage.probed, ["query"], c.id);
      assert.deepEqual(c.coverage.notCovered, [], c.id);
      assert.ok((c.coverage.validCalls ?? 0) > 0, c.id);
    }
    const ro = results.good.checks.find((c) => c.id === "read-only")!;
    assert.ok(ro.evidence.some((e) => e.code === "db.control.reader" && /sm_admin/.test(e.outcome)));
    // run.ts folds the valid calls into RunResult.coverage (addendum 1.4).
    assert.ok((results.good.coverage?.validCalls ?? 0) > 0);
    assert.notEqual(results.good.coverage?.level, "hygiene-only");
    assert.equal(results.good.badge?.eligible, false, "a run without a loaded configuration cannot claim the standard profile");
  });

  it("owner: seed 0.2 is recorded", (t) => {
    if (skip(t)) return;
    assert.match(results.owner.db?.seed ?? "", /seed 0.2/);
  });

  it("good: the database checks were verified from database state", (t) => {
    if (skip(t)) return;
    const ro = results.good.checks.find((c) => c.id === "read-only")!;
    assert.ok(ro.evidence.some((e) => e.verifiedBy === "db-state"));
  });

  it("good: the result records the db block for a --pg run", (t) => {
    if (skip(t)) return;
    const db = results.good.db;
    assert.equal(db?.mode, "external");
    assert.deepEqual(db?.roles.slice().sort(), ["admin", "analyst", "support"]);
  });
});
