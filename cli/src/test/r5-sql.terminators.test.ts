import assert from "node:assert/strict";
import { after, before, describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { TemplateCtx } from "../config.js";
import { startAllEmbedded, freePort, quiet, TOY } from "./helpers.js";
import { type EmbeddedHandle } from "../embedded.js";
import { McpSession } from "../mcp.js";
import { MUTATION_CORPUS, describe as describeDb, runDb } from "../packs/db.js";
import { discoverSqlTools } from "../packs/shared.js";
import { ROLES, StateReader, provision, roleDsn, type PgTarget, type Role } from "../seed.js";
import type { CheckResult } from "../types.js";

// Round 5, package sql, item sql-5: one transaction-escape case per terminator keyword Postgres accepts.
//   toy/db-blockcommit  a read-only-transaction reader that refuses only the word COMMIT -> fails mutating-sql on ROLLBACK, END and ABORT
//   toy/server (good)   the read-only-transaction reader that refuses every stacked form  -> blocks all 19 (near miss)
const BLOCKCOMMIT = fileURLToPath(new URL("../toy/db-blockcommit.js", import.meta.url));
const TIMEOUT_SEC = 3;
const ESCAPES = ["COMMIT then write (read-only transaction escape)", "ROLLBACK then write (read-only transaction escape)", "END then write (read-only transaction escape)", "ABORT then write (read-only transaction escape)"];

async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

const sessionFor = (target: PgTarget, command: string, args: string[]) => {
  const spec = { command: process.execPath, args: [command, ...args, "--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)], env: {} };
  const tctx = (role: Role): TemplateCtx => ({ vars: { dsn: roleDsn(target, role) }, dsns: Object.fromEntries(ROLES.map((r) => [r, roleDsn(target, r)])) });
  return { spec, open: (role: Role) => McpSession.open(spec, tctx(role), {}) };
};

async function viaRunDb(target: PgTarget, command: string, args: string[]): Promise<CheckResult[]> {
  await provision(target);
  const { open } = sessionFor(target, command, args);
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
let targets: PgTarget[] = [];
let skipReason: string | undefined;

describe("mutating-sql: every transaction terminator is a case (embedded Postgres)", { timeout: 600_000 }, () => {
  before(async () => {
    if (process.env.SEALMARK_SKIP_DB === "1") {
      skipReason = "SEALMARK_SKIP_DB=1";
      return;
    }
    const ports = await distinctPorts(2);
    await startAllEmbedded(handles, ports);
    targets = handles.map((h) => h.target);
    await Promise.all([
      (async () => {
        runs.blockcommit = await viaRunDb(targets[0], BLOCKCOMMIT, []);
      })(),
      (async () => {
        runs.good = await viaRunDb(targets[1], TOY, ["--mode", "good"]);
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
  const mutating = (mode: string) => runs[mode].find((c) => c.id === "mutating-sql")!;

  it("the corpus has 19 cases and 7 core cases, one terminator case each for COMMIT, ROLLBACK, END and ABORT", () => {
    assert.equal(MUTATION_CORPUS.length, 19);
    assert.equal(MUTATION_CORPUS.filter((c) => c.core).length, 7);
    const esc = MUTATION_CORPUS.filter((c) => c.kind === "txn-escape");
    assert.deepEqual(esc.map((c) => c.id), ESCAPES);
    assert.ok(esc.every((c) => c.core));
    assert.deepEqual(esc.map((c) => c.steps[0].split(";")[0]), ["COMMIT", "ROLLBACK", "END", "ABORT"]);
    assert.equal(new Set(MUTATION_CORPUS.map((c) => c.id)).size, 19, "ids are unique: the verification closures are keyed by them");
    const ids = esc.map((c) => /VALUES \((\d+),/.exec(c.steps[0])![1]);
    assert.equal(new Set(ids).size, 4, "each case has its own probe_t id");
  });

  it("explain mutating-sql names the four terminators and says why COMMIT WORK and AND CHAIN are not cases", () => {
    const doc = describeDb().find((d) => d.id === "mutating-sql")!;
    assert.equal(doc.probes.length, 19);
    assert.deepEqual(doc.probes.filter((p) => p.kind === "txn-escape").map((p) => p.text.split(";")[0]), ["COMMIT", "ROLLBACK", "END", "ABORT"]);
    assert.match(doc.falsePositive, /COMMIT, ROLLBACK, END, ABORT/);
    assert.match(doc.falsePositive, /COMMIT WORK/);
    assert.match(doc.falsePositive, /AND CHAIN/);
  });

  it("db-blockcommit: refuses the word COMMIT and runs the write after ROLLBACK, END and ABORT, so mutating-sql fails on exactly those three", (t) => {
    if (skip(t)) return;
    const m = mutating("blockcommit");
    assert.equal(m.verdict, "fail", m.summary);
    assert.deepEqual(executed(runs.blockcommit), ESCAPES.slice(1), "COMMIT is blocked by the word filter; the other three run; nothing else runs");
    assert.match(m.summary, /^EXECUTED: ROLLBACK then write .*, END then write .*, ABORT then write .*; 16 of 19 blocked$/);
    const commit = m.evidence.find((e) => e.probe.startsWith("COMMIT;"));
    assert.equal(commit?.code, "db.mut.blocked.txn-escape");
    assert.match(commit?.outcome ?? "", /COMMIT is not allowed/);
    for (const kw of ["ROLLBACK", "END", "ABORT"]) {
      const e = m.evidence.find((x) => x.probe.startsWith(`${kw};`));
      assert.equal(e?.code, "db.mut.executed.txn-escape", kw);
      assert.equal(e?.verifiedBy, "db-state", kw);
    }
  });

  it("db-blockcommit: the harness's own read of the database finds the rows (the verdict does not rest on the server's word)", async (t) => {
    if (skip(t)) return;
    const { open } = sessionFor(targets[0], BLOCKCOMMIT, []);
    await provision(targets[0]);
    const s = await open("admin");
    const state = new StateReader(targets[0]);
    await state.connect();
    try {
      const wrote = async (sql: string, id: number) => {
        const r = await s.call("query", { sql }, 30_000);
        return { r, row: await state.probeRow(id) };
      };
      assert.equal((await wrote("COMMIT; INSERT INTO probe_t (id, v) VALUES (9005, 'x')", 9005)).row, false);
      assert.equal((await wrote("ROLLBACK; INSERT INTO probe_t (id, v) VALUES (9014, 'x')", 9014)).row, true);
      assert.equal((await wrote("END; INSERT INTO probe_t (id, v) VALUES (9015, 'x')", 9015)).row, true);
      assert.equal((await wrote("ABORT; INSERT INTO probe_t (id, v) VALUES (9016, 'x')", 9016)).row, true);
      assert.equal((await wrote("SELECT 1; INSERT INTO probe_t (id, v) VALUES (9002, 'x')", 9002)).row, false, "the read-only transaction still stops the stacked form");
    } finally {
      await state.end();
      await s.close();
    }
  });

  it("good (near miss): the read-only-transaction reader blocks all 19 forms", (t) => {
    if (skip(t)) return;
    const m = mutating("good");
    assert.equal(m.verdict, "pass", m.summary);
    assert.match(m.summary, /^all 19 mutation forms blocked on the 1 probed SQL tool \(query\)$/);
    assert.deepEqual(executed(runs.good), []);
  });

  // sql-8: the write gate is computed after the corpus, so it cannot say "no write concept" about a server whose corpus wrote.
  it("write-gate: a core case that executed through a tool with no approval parameter fails it (blockcommit); a clean reader leaves it n/a (good)", (t) => {
    if (skip(t)) return;
    const wg = runs.blockcommit.find((c) => c.id === "write-gate")!;
    assert.equal(wg.verdict, "fail", wg.summary);
    assert.match(wg.summary, /^writes executed with no confirmation step: a core mutating-sql case ran through query, which has no approval parameter/);
    assert.equal(wg.evidence[0]?.code, "db.wg.no-gate");
    const good = runs.good.find((c) => c.id === "write-gate")!;
    assert.equal(good.verdict, "na");
    assert.match(good.summary, /^no write concept/);
  });
});
