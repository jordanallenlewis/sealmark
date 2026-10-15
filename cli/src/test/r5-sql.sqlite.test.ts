// Round 5, package sql, items sql-1 to sql-4 (the sqlite pack). Every toy is toy/sqlite-r5 and needs no setAuthorizer, so these run on Node 22.13 and newer.
//   fresh-stacked   a fresh connection per call, stacked statements run and rows come back   -> sqlite-file-read and sqlite-file-write fail
//   fresh-blind     as above, but every call answers "OK": only the fixture file shows it    -> sqlite-file-read fails, found by db-state
//   fresh-single    near miss: a fresh connection per call, one statement per call           -> sqlite-file-read and sqlite-file-write pass
//   ddl-stacked     a DDL-only tool that runs stacked statements, plus a clean reader          -> both fail
//   ddl-strict      near miss: the DDL-only tool refuses stacked input                         -> both pass
//   other-engine    sqlite_version() answers with another engine's error                       -> every check inconclusive
//   plaincap        a plain-text cap message with zero rows                                    -> sqlite-rowcap passes
//   uncontrolled    a clean reader plus a tool no control form can drive                       -> both file checks are part, never pass
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { describeAll } from "../packs/index.js";
import { fingerprintOf } from "../packs/sqlite.js";
import { createCanaryDb, createSqliteFixture, tableHasValue } from "../sqlite-fixtures.js";
import { DatabaseSync } from "node:sqlite";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, RunResult } from "../types.js";
import { quiet } from "./helpers.js";

const TOY = fileURLToPath(new URL("../toy/sqlite-r5.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} };
const OFF = { enabled: false, severity: null } as const;
const FILE_CHECKS_ONLY = { "sqlite-timeout": OFF, "sqlite-rowcap": OFF, "sqlite-mutating-sql": OFF, "sqlite-read-only": OFF, "sqlite-extension-load": OFF };
const ROWCAP_ONLY = { "sqlite-timeout": OFF, "sqlite-file-read": OFF, "sqlite-file-write": OFF, "sqlite-mutating-sql": OFF, "sqlite-read-only": OFF, "sqlite-extension-load": OFF };

const MODES = {
  "fresh-stacked": FILE_CHECKS_ONLY,
  "fresh-blind": FILE_CHECKS_ONLY,
  "fresh-single": FILE_CHECKS_ONLY,
  "ddl-stacked": FILE_CHECKS_ONLY,
  "ddl-strict": FILE_CHECKS_ONLY,
  "other-engine": {},
  plaincap: ROWCAP_ONLY,
  uncontrolled: FILE_CHECKS_ONLY,
} as const;
type Name = keyof typeof MODES;

let dir: string;
let parent: string;
const results = {} as Record<Name, RunResult>;

function config(name: Name) {
  return { name: `toy-sqlite-r5-${name}`, version: "0.0.1", server: { command: process.execPath, args: [TOY, "--mode", name, "--db", "{sqlite_path}"], env: {} } };
}
function effective(name: Name): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: config(name), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent }, checks: MODES[name] };
}
const check = (name: Name, id: string): CheckResult => {
  const c = results[name].checks.find((x) => x.id === id);
  assert.ok(c, `${id} missing for ${name}`);
  return c;
};

describe("sqlite engine fingerprint (a pure rule over the reply)", () => {
  const res = (text: string, o: Partial<{ isError: boolean; rpcError: string }> = {}) => ({ isError: false, text, ...o });

  it("a 3.x.y answer confirms SQLite", () => {
    assert.deepEqual(fingerprintOf(res('[{"sm_v":"3.45.0"}]')), { engine: "sqlite", version: "3.45.0" });
    assert.equal(fingerprintOf(res("3.46.1")).engine, "sqlite");
    assert.equal(fingerprintOf(res('[{"sm_v":"3.50.4"}]')).engine, "sqlite");
  });

  it("another engine's error, or an answer that is no version, is `other`, with the reply quoted", () => {
    const e = fingerprintOf(res("Catalog Error: Scalar Function with name sqlite_version does not exist!", { isError: true }));
    assert.equal(e.engine, "other");
    assert.match((e as { reply: string }).reply, /^Catalog Error/);
    const d = fingerprintOf(res("DuckDB: Binder Error: nope", { isError: true }));
    assert.deepEqual([d.engine, (d as { names?: string }).names], ["other", "DuckDB"]);
    assert.equal(fingerprintOf(res("Parser Error: syntax error at or near 'sm_v'", { rpcError: "Parser Error: syntax error" })).engine, "other");
    assert.equal(fingerprintOf(res("no such function: sqlite_version", { isError: true })).engine, "other");
    assert.equal(fingerprintOf(res('[{"sm_v":"1.1.3"}]')).engine, "other", "an answer that is not a SQLite version is not SQLite");
    assert.equal(fingerprintOf(res("1.1.3 3.0")).engine, "other");
  });

  it("a plain refusal says nothing about the engine: `unconfirmed`", () => {
    for (const text of ["Error: only SELECT statements are allowed", "not authorized", "Only read statements are permitted"]) assert.equal(fingerprintOf(res(text, { isError: true })).engine, "unconfirmed", text);
    assert.equal(fingerprintOf(res("", { rpcError: "function calls are not allowed" })).engine, "unconfirmed");
    assert.equal(fingerprintOf(res("Error: only SELECT is allowed (3.45.0)")).engine, "unconfirmed", "a refusal that mentions a version is still a refusal");
  });
});

describe("tableHasValue: the harness reads a copy of the other file out of the fixture itself", () => {
  let tmp: string;
  before(() => {
    tmp = mkdtempSync(join(tmpdir(), "sealmark-r5-copy-"));
  });
  after(() => rmSync(tmp, { recursive: true, force: true }));

  it("true only when the table exists and holds the value; false when absent; the copy form is what puts it there", () => {
    const fixture = join(tmp, "fixture.sqlite");
    const canary = join(tmp, "secret.db");
    createSqliteFixture(fixture);
    createCanaryDb(canary, "sm-fscanary-test");
    assert.equal(tableHasValue(fixture, "sm_rd_x", "sm-fscanary-test"), false, "no such table");
    const db = new DatabaseSync(fixture);
    try {
      db.exec(`ATTACH '${canary}' AS a; CREATE TABLE sm_rd_x AS SELECT v FROM a.secret`);
    } finally {
      db.close();
    }
    assert.equal(tableHasValue(fixture, "sm_rd_x", "sm-fscanary-test"), true);
    assert.equal(tableHasValue(fixture, "sm_rd_x", "another"), false);
    assert.equal(tableHasValue(join(tmp, "missing.sqlite"), "sm_rd_x", "x"), undefined, "an unreadable file is unknown, not absent");
  });
});

describe("sqlite pack round 5 (toy/sqlite-r5)", { timeout: 360_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r5-sqlite-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const names = Object.keys(MODES) as Name[];
    const all = await Promise.all(names.map((n) => runHarness({ config: config(n), effective: effective(n), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2, log: quiet })));
    names.forEach((n, i) => (results[n] = all[i]));
  }, { timeout: 340_000 });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  describe("sql-2: file-read forms the two-call ATTACH then SELECT misses", () => {
    it("fresh-stacked: the one-call ATTACH and SELECT shows the canary on a server that opens a connection per call, so the check fails", () => {
      const c = check("fresh-stacked", "sqlite-file-read");
      assert.equal(c.verdict, "fail", c.summary);
      assert.match(c.summary, /attached and read through every tool/);
      const two = c.evidence.find((e) => e.code === "sqlite.file-read.blocked" && !e.probe.includes("one call") && e.args !== undefined && (e.args as unknown[]).length === 2);
      assert.ok(two, "the two-call form alone is clean (a fresh connection per call), which is the false pass this fixes");
      const hit = c.evidence.find((e) => e.code === "sqlite.file-read.canary-leaked");
      assert.match(hit?.outcome ?? "", /ATTACH and SELECT in one call/);
      assert.match(hit?.excerpt ?? "", /sm-fscanary-[0-9a-f]{16}/);
      assert.match(hit?.probe ?? "", /ATTACH '\{canary\}\/secret\.db' AS sm_a_\w+; SELECT v FROM sm_a_\w+\.secret/);
    });

    it("fresh-blind: a tool that never returns rows is judged by the fixture file the harness reads itself (db-state)", () => {
      const c = check("fresh-blind", "sqlite-file-read");
      assert.equal(c.verdict, "fail", c.summary);
      const hit = c.evidence.find((e) => e.code === "sqlite.file-read.canary-leaked");
      assert.equal(hit?.verifiedBy, "db-state");
      assert.match(hit?.outcome ?? "", /was copied into the fixture database \(table sm_rd_\w+, read by the harness from the file\)/);
      assert.match(hit?.probe ?? "", /CREATE TABLE sm_rd_\w+ AS SELECT v FROM sm_\w+\.secret/);
      assert.equal(hit?.excerpt, undefined, "nothing came back in a response; nothing is quoted");
      assert.ok(c.evidence.some((e) => e.outcome.startsWith("no canary token in the response") && e.verifiedBy === "response"), "the one-call SELECT form showed nothing: only the file did");
    });

    it("fresh-single (near miss): a connection and one statement per call is clean, and every form is in the evidence", () => {
      const c = check("fresh-single", "sqlite-file-read");
      assert.equal(c.verdict, "pass", c.summary);
      const labels = c.evidence.map((e) => e.outcome);
      for (const form of ["ATTACH and SELECT in one call", "ATTACH and copy into the fixture in one call", "ATTACH, then copy into the fixture, in two calls"]) {
        assert.ok(labels.some((l) => l.includes(form)), form);
      }
      assert.ok(c.evidence.some((e) => /only one statement per call/.test(e.outcome)), "the stacked forms were refused in the server's words");
      assert.ok(c.evidence.every((e) => e.code === "sqlite.file-read.blocked"));
      assert.equal(c.coverage?.notCovered.some((n) => n.tool === "query"), false);
    });
  });

  describe("sql-3: the DDL control, and uncontrolled tools", () => {
    it("ddl-stacked: create_table is controlled through CREATE TABLE, and the prefixed forms read and write another file, so both checks fail", () => {
      const r = check("ddl-stacked", "sqlite-file-read");
      assert.equal(r.verdict, "fail", r.summary);
      const hit = r.evidence.find((e) => e.code === "sqlite.file-read.canary-leaked");
      assert.equal(hit?.tool, "create_table");
      assert.equal(hit?.verifiedBy, "db-state");
      assert.match(hit?.probe ?? "", /^CREATE TABLE sm_p_\w+ \(x\); ATTACH /);
      assert.match(r.summary, /through create_table; not through read_query/);
      const w = check("ddl-stacked", "sqlite-file-write");
      assert.equal(w.verdict, "fail", w.summary);
      assert.ok(w.evidence.some((e) => e.tool === "create_table" && e.code === "sqlite.file-write.created" && /vac-\w+\.db \(new\)/.test(e.outcome)), JSON.stringify(w.evidence.map((e) => e.outcome)));
      assert.ok(w.evidence.filter((e) => e.tool === "read_query").every((e) => e.code === "sqlite.file-write.blocked"), "the clean reader is not blamed");
    });

    it("ddl-strict (near miss): the same DDL-only tool refusing stacked input is controlled, probed, and clean on both checks", () => {
      const r = check("ddl-strict", "sqlite-file-read");
      assert.equal(r.verdict, "pass", r.summary);
      assert.ok(r.evidence.some((e) => e.tool === "create_table" && e.code === "sqlite.file-read.blocked" && /only a single CREATE TABLE statement is allowed/.test(e.outcome)));
      assert.equal(r.coverage?.notCovered.some((n) => n.tool === "create_table"), false, "it was controlled, so it is not listed as uncontrolled");
      const w = check("ddl-strict", "sqlite-file-write");
      assert.equal(w.verdict, "pass", w.summary);
      assert.ok(w.evidence.some((e) => e.tool === "create_table" && /CREATE TABLE sm_p_\w+ \(x\); VACUUM INTO/.test(e.probe)), "the DDL-prefixed forms were sent");
    });

    it("uncontrolled: a tool no control form can drive makes both file checks part, never a pass, and is named", () => {
      for (const id of ["sqlite-file-read", "sqlite-file-write"]) {
        const c = check("uncontrolled", id);
        assert.equal(c.verdict, "part", `${id}: ${c.summary}`);
        assert.match(c.summary, /run_script could not be controlled \(no control read, INSERT or CREATE TABLE worked\), so the check cannot say it refuses/);
        assert.ok(c.coverage?.notCovered.some((n) => n.tool === "run_script" && /neither a control read nor a control write nor a control CREATE TABLE worked/.test(n.reason)), id);
      }
    });
  });

  describe("sql-1: the engine is confirmed, not assumed from {sqlite_path}", () => {
    it("other-engine: every check is inconclusive, with the fingerprint reply quoted and the corpus declared not applicable", () => {
      const checks = results["other-engine"].checks.filter((c) => c.pack === "sqlite");
      assert.equal(checks.length, 7);
      for (const c of checks) {
        assert.equal(c.verdict, "inconclusive", `${c.id}: ${c.summary}`);
        assert.match(c.summary, /^the server's engine did not answer like SQLite \(sqlite_version\(\): Catalog Error: Scalar Function with name sqlite_version does not exist!\); the sqlite corpus does not apply$/);
        assert.equal(c.evidence[0]?.code, "sqlite.engine.other");
        assert.equal(c.evidence[0]?.probe, "SELECT sqlite_version() AS sm_v");
      }
    });

    it("a graded SQLite toy still grades: the fingerprint passed on every other mode", () => {
      for (const n of ["fresh-single", "ddl-strict", "plaincap"] as Name[]) {
        for (const c of results[n].checks.filter((x) => x.pack === "sqlite" && x.verdict !== "na")) assert.notEqual(c.verdict, "inconclusive", `${n} ${c.id}: ${c.summary}`);
      }
    });
  });

  describe("sql-4: a plain-text cap message with zero rows is a cap", () => {
    it("plaincap: sqlite-rowcap passes, and says the reply was an answer, not a refusal", () => {
      const c = check("plaincap", "sqlite-rowcap");
      assert.equal(c.verdict, "pass", c.summary);
      assert.match(c.evidence[0].outcome, /^answered with no rows as too large: Result set too large: more than 1000 rows/);
      assert.equal(c.evidence[0].code, "sqlite.rowcap.capped");
    });
  });

  it("describe() lists the new forms and the DDL control, and the engine fingerprint", () => {
    const docs = describeAll().filter((d) => d.pack === "sqlite");
    const probes = (id: string) => docs.find((d) => d.id === id)!.probes.map((p) => p.id);
    assert.deepEqual(probes("sqlite-file-read").filter((p) => !p.startsWith("read-")), ["attach-read", "attach-read-one-call", "attach-copy-one-call", "attach-copy-two-calls", "ddl-prefixed-copy"]);
    assert.ok(probes("sqlite-file-write").includes("attach-new-one-call") && probes("sqlite-file-write").includes("ddl-prefixed-vacuum"));
    assert.ok(probes("sqlite-read-only").includes("ddl-control") && probes("sqlite-read-only").includes("engine-fingerprint"));
    assert.ok(docs.find((d) => d.id === "sqlite-file-read")!.verifiedBy.includes("db-state"));
    assert.match(docs.find((d) => d.id === "sqlite-file-read")!.falsePositive, /part at best, never a pass/);
  });

  it("every run removed its sandbox", () => {
    assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
    for (const n of Object.keys(MODES) as Name[]) assert.equal(results[n].sandbox?.cleanedUp, true, n);
  });
});
