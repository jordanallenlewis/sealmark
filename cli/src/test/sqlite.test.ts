import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CHECKS } from "../config/schema.js";
import { describeAll } from "../packs/index.js";
import { refused } from "../packs/shared.js";
import { classifyExtensionLoad, controlReadPasses, pack } from "../packs/sqlite.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import { SQLITE_BIG_ROWS, createCanaryDb, createSqliteFixture, ensureSqliteFixture, loadSqlite, probeRowExists, readFixture, readState, sqlPath, tableExists } from "../sqlite-fixtures.js";
import type { CallResult } from "../mcp.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, PackId, RunResult, Verdict } from "../types.js";
import { quiet } from "./helpers.js";

const TOY = fileURLToPath(new URL("../toy/sqlite.js", import.meta.url));
const sqlite = loadSqlite();
const NEEDS_AUTHORIZER_MSG = "the good toy needs node:sqlite setAuthorizer (Node 24.10 or newer)";
const HAS_AUTHORIZER = typeof (sqlite?.DatabaseSync.prototype as { setAuthorizer?: unknown } | undefined)?.setAuthorizer === "function";
/** `skip` value for tests that read the shared `settings` run, which uses the good toy server. */
const NEEDS_AUTHORIZER: string | false = HAS_AUTHORIZER ? false : NEEDS_AUTHORIZER_MSG;
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};

type Mode = "good" | "ro" | "filter" | "open" | "writers" | "planner";
const IDS = ["sqlite-read-only", "sqlite-mutating-sql", "sqlite-file-read", "sqlite-file-write", "sqlite-extension-load", "sqlite-rowcap", "sqlite-timeout"] as const;

function config(mode: Mode, dbArg = "{sqlite_path}") {
  return { name: `toy-sqlite-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [TOY, "--mode", mode, "--db", dbArg], env: {} } };
}

type Over = Omit<Partial<EffectiveConfig>, "sandbox"> & { sandbox?: Partial<EffectiveConfig["sandbox"]> };

function effective(mode: Mode, over: Over = {}, dbArg?: string, packs: PackId[] = ["sqlite"]): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: config(mode, dbArg), packs, packsExplicit: true, timeoutProbeSec: 2 });
  const { sandbox, ...rest } = over;
  return { ...base, integrity: INTEGRITY, cwd: dir, ...rest, sandbox: { ...base.sandbox, dir: parent, ...sandbox } };
}

const run = (mode: Mode, over: Over = {}, dbArg?: string) => runHarness({ config: config(mode, dbArg), effective: effective(mode, over, dbArg), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2, log: quiet });

const verdictsOf = (r: RunResult): Record<string, Verdict> => Object.fromEntries(r.checks.filter((c) => c.pack === "sqlite").map((c) => [c.id, c.verdict]));
const check = (r: RunResult, id: string): CheckResult => {
  const c = r.checks.find((x) => x.id === id);
  assert.ok(c, `check ${id} missing`);
  return c;
};
const grade = (r: RunResult) => {
  const p = r.packs.sqlite;
  assert.equal(p?.status, "graded", `sqlite pack status: ${p?.status} ${p?.reason ?? ""}`);
  return p.grade!;
};

/**
 * The expected-results table of the design notes (the `writers` row is derived the same way).
 * The `writers` row changed with the writer-tool file checks: its write_query runs any statement on a read-write connection, so
 * VACUUM INTO and ATTACH through it write and read files outside the database. Before, the declared writer was left out of the
 * file checks and the row read pass/pass for sqlite-file-read and sqlite-file-write (a false pass); it now fails both, F at 35.71% instead of C at 64.29%.
 */
const TABLE: Record<Exclude<Mode, "planner">, { v: Record<(typeof IDS)[number], Verdict>; letter: string; pct: number; raw: string; capped: boolean }> = {
  good: { v: { "sqlite-read-only": "pass", "sqlite-mutating-sql": "pass", "sqlite-file-read": "pass", "sqlite-file-write": "pass", "sqlite-extension-load": "pass", "sqlite-rowcap": "pass", "sqlite-timeout": "pass" }, letter: "A", pct: 100, raw: "A", capped: false },
  ro: { v: { "sqlite-read-only": "pass", "sqlite-mutating-sql": "pass", "sqlite-file-read": "fail", "sqlite-file-write": "fail", "sqlite-extension-load": "pass", "sqlite-rowcap": "pass", "sqlite-timeout": "pass" }, letter: "D", pct: 71.43, raw: "C", capped: true },
  filter: { v: { "sqlite-read-only": "pass", "sqlite-mutating-sql": "fail", "sqlite-file-read": "pass", "sqlite-file-write": "pass", "sqlite-extension-load": "fail", "sqlite-rowcap": "fail", "sqlite-timeout": "fail" }, letter: "F", pct: 42.86, raw: "F", capped: false },
  open: { v: { "sqlite-read-only": "fail", "sqlite-mutating-sql": "fail", "sqlite-file-read": "fail", "sqlite-file-write": "fail", "sqlite-extension-load": "fail", "sqlite-rowcap": "fail", "sqlite-timeout": "fail" }, letter: "F", pct: 0, raw: "F", capped: false },
  writers: { v: { "sqlite-read-only": "part", "sqlite-mutating-sql": "pass", "sqlite-file-read": "fail", "sqlite-file-write": "fail", "sqlite-extension-load": "pass", "sqlite-rowcap": "fail", "sqlite-timeout": "fail" }, letter: "F", pct: 35.71, raw: "F", capped: false },
};

const WAL_CASE = { id: "wal-write", core: false, steps: ["PRAGMA journal_mode = wal", "INSERT INTO probe_t (id, v) VALUES (9101, 'wal')"], executed: "probe_row:9101" };

describe("sqlite pack", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-sqlite-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const jobs: Record<string, () => Promise<RunResult>> = {
      ro: () => run("ro"),
      filter: () => run("filter"),
      open: () => run("open", { checks: { "sqlite-mutating-sql": { enabled: true, severity: null, corpus: { add: [WAL_CASE], remove: [] } } } }),
      writers: () => run("writers"),
      planner: () => run("planner"),
      // Settings in one quick run: a disabled check, a lowered row cap, a severity override, a corpus addition and removal, and a kept sandbox.
      settings: () =>
        run("good", {
          sandbox: { keep: true },
          checks: {
            "sqlite-timeout": { enabled: false, severity: null },
            "sqlite-rowcap": { enabled: true, severity: null, row_cap: 500 },
            "sqlite-file-read": { enabled: true, severity: "advisory" },
            "sqlite-mutating-sql": { enabled: true, severity: null, corpus: { add: [{ id: "custom-insert", core: true, steps: ["INSERT INTO probe_t (id, v) VALUES (9100, 'custom')"], executed: "probe_row:9100" }], remove: ["upsert"] } },
          },
        }),
      noPlaceholder: () => run("good", {}, "literal-fixture.sqlite"),
      noSandbox: () => run("good", { sandbox: { enabled: false } }),
      duckdb: () => run("good", {}, "{duckdb_path}"),
    };
    if (HAS_AUTHORIZER) jobs.good = () => run("good");
    const names = Object.keys(jobs);
    const all = await Promise.all(names.map((n) => jobs[n]()));
    names.forEach((n, i) => (results[n] = all[i]));
  });

  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  describe("the toy servers match the expected-results table", () => {
    for (const mode of Object.keys(TABLE) as (keyof typeof TABLE)[]) {
      it(`${mode}`, { skip: mode === "good" && !HAS_AUTHORIZER ? "the good toy needs node:sqlite setAuthorizer (Node 24.10 or newer)" : false }, () => {
        const want = TABLE[mode];
        const r = results[mode];
        assert.deepEqual(verdictsOf(r), want.v);
        const g = grade(r);
        assert.equal(g.letter, want.letter, `letter ${g.letter} pct ${g.pct}`);
        assert.equal(g.pct, want.pct);
        assert.equal(g.raw, want.raw);
        assert.equal(g.capped, want.capped);
        assert.equal(g.scored, 7);
      });
    }

    it("planner: a control that returns a plan is inconclusive, never a pass anywhere", () => {
      const r = results.planner;
      assert.equal(r.packs.sqlite?.status, "inconclusive");
      assert.ok(r.checks.filter((c) => c.pack === "sqlite").every((c) => c.verdict === "inconclusive"), JSON.stringify(verdictsOf(r)));
      assert.match(check(r, "sqlite-read-only").summary, /no SQL tool could run a basic read/);
      assert.ok(check(r, "sqlite-read-only").evidence.some((e) => /plan, not rows/.test(e.outcome)));
    });
  });

  describe("verification is by the harness, from files", () => {
    it("good: the fixture hash is identical before and after every probe", { skip: !HAS_AUTHORIZER }, () => {
      const lines = results.good.checks.flatMap((c) => c.evidence).filter((e) => e.verifiedBy === "db-state");
      const hashes = lines.map((e) => /sha256 ([0-9a-f]{12})/.exec(e.outcome)?.[1]);
      assert.ok(hashes.length >= 13, `expected at least 13 db-state lines, got ${hashes.length}`);
      assert.ok(hashes.every((h) => h !== undefined), "every db-state line carries the hash");
      assert.equal(new Set(hashes).size, 1, "one hash across all probes");
      assert.ok(lines.every((e) => !/\bchanged\b/.test(e.outcome) || /unchanged/.test(e.outcome)));
    });

    it("good: the engine's silence about a stacked statement is reported as that, not as a refusal", { skip: !HAS_AUTHORIZER }, () => {
      const e = check(results.good, "sqlite-mutating-sql").evidence.find((x) => x.probe.startsWith("SELECT 1; INSERT"));
      assert.match(e?.outcome ?? "", /only the first statement ran/);
    });

    it("open: the canary database's token appears in the evidence", () => {
      const e = check(results.open, "sqlite-file-read").evidence[0];
      assert.match(e.excerpt ?? "", /sm-fscanary-[0-9a-f]{16}/);
      assert.equal(e.code, "sqlite.file-read.canary-leaked");
      assert.match(e.probe, /ATTACH '\{canary\}\/secret\.db'/);
    });

    it("ro: ATTACH of an existing file and VACUUM INTO both work under a read-only connection", () => {
      const read = check(results.ro, "sqlite-file-read").evidence[0];
      assert.match(read.excerpt ?? "", /sm-fscanary-/);
      const write = check(results.ro, "sqlite-file-write");
      assert.ok(write.evidence.some((e) => /VACUUM INTO/.test(e.probe) && /canary\/vac-[0-9a-f]+\.db \(new\)/.test(e.outcome)), write.evidence.map((e) => e.outcome).join(" | "));
      assert.ok(write.evidence.some((e) => /ATTACH/.test(e.probe) && e.code === "sqlite.file-write.blocked"), "a new file cannot be attached read-only");
    });

    it("filter: WITH ... INSERT and PRAGMA writes run, and the summary lists the executed case ids", () => {
      const c = check(results.filter, "sqlite-mutating-sql");
      // Round 5 (sql-8): the stacked insert was accepted and only its first statement ran; that is ineffective, not blocked, and is counted apart.
      assert.match(c.summary, /^EXECUTED: cte-insert, pragma-user-version, pragma-journal-mode; 6 of 10 blocked, 1 ineffective \(accepted, only the first statement ran\)$/);
      assert.ok(c.evidence.some((e) => /comment-obfuscation/.test(e.outcome) && /blocked/.test(e.outcome)), "the comment form is stopped by the text filter");
    });

    it("filter: extension loading is recognised as attempted from the engine's own error text", () => {
      const e = check(results.filter, "sqlite-extension-load").evidence[0];
      assert.equal(e.code, "sqlite.extension.attempted");
      assert.match(e.outcome, /tried to load a library/);
    });

    it("open: a write in write-ahead-log mode is caught from the logical content, and the -wal file is a note, not a write", () => {
      const c = check(results.open, "sqlite-mutating-sql");
      const e = c.evidence.find((x) => /EXECUTED: wal-write/.test(x.outcome));
      assert.ok(e, c.evidence.map((x) => x.outcome).join(" | "));
      assert.match(c.summary, /wal-write/);
      const note = c.evidence.find((x) => x.code === "sqlite.sidecar");
      assert.match(note?.outcome ?? "", /fixture\.sqlite-wal.*noted, not counted as a write/);
    });

    it("good: no sidecar note, and nothing was created outside the fixture", { skip: !HAS_AUTHORIZER }, () => {
      assert.ok(!results.good.checks.some((c) => c.evidence.some((e) => e.code === "sqlite.sidecar")));
      assert.ok(check(results.good, "sqlite-file-write").evidence.every((e) => e.code === "sqlite.file-write.blocked"));
    });
  });

  describe("engines that refuse or never answer", () => {
    it("a refusal of the runaway query is judged on a second form, and a server that never answers is a fail", () => {
      const c = check(results.filter, "sqlite-timeout");
      assert.match(c.evidence[0].outcome, /no query timeout within 10 s \(expected 2 s plus an 8 s margin\); a server that cancels later than that is not seen: set --timeout-probe to its value/);
    });

    it("good: the runaway query is cancelled by the server itself", { skip: !HAS_AUTHORIZER }, () => {
      const e = check(results.good, "sqlite-timeout").evidence[0];
      assert.equal(e.code, "sqlite.timeout.cancelled");
      assert.match(e.outcome, /query ended after [34]\.\ds/);
    });

    it("rowcap counts distinct rows and reports a capped response as under the threshold", { skip: !HAS_AUTHORIZER }, () => {
      assert.match(check(results.good, "sqlite-rowcap").evidence[0].outcome, /1,000 row\(s\) came back, under the 10,000 threshold/);
      assert.match(check(results.open, "sqlite-rowcap").evidence[0].outcome, /200,000 row\(s\) came back \(cap threshold 10,000\)/);
    });
  });

  describe("tool roles", () => {
    it("writers: the declared writer tool is probed by read-only and by the three file checks, listed as not covered for the rest", () => {
      const ro = check(results.writers, "sqlite-read-only");
      assert.deepEqual([...(ro.coverage?.probed ?? [])].sort(), ["read_query", "write_query"]);
      assert.ok(!ro.coverage?.notCovered.some((n) => n.tool === "write_query"));
      assert.match(ro.summary, /^writes executed through write_query \(declared writer tool; exclude it under tools\.exclude if writes are intended\) and blocked on read_query$/);
      for (const id of ["sqlite-file-read", "sqlite-file-write", "sqlite-extension-load"]) {
        const c = check(results.writers, id);
        assert.deepEqual([...(c.coverage?.probed ?? [])].sort(), ["read_query", "write_query"], id);
        assert.ok(!c.coverage?.notCovered.some((n) => n.tool === "write_query"), id);
      }
      for (const id of ["sqlite-mutating-sql", "sqlite-rowcap", "sqlite-timeout"]) {
        const c = check(results.writers, id);
        assert.deepEqual(c.coverage?.probed, ["read_query"], id);
        const n = c.coverage?.notCovered.find((x) => x.tool === "write_query");
        assert.match(n?.reason ?? "", /^declared writer tool: the (mutation corpus|row-cap probe|timeout probe) does not apply/, id);
      }
    });

    it("writers: a write_query that runs any statement fails the file checks, naming the tool and the clean one", () => {
      for (const [id, probe] of [["sqlite-file-write", /VACUUM INTO/], ["sqlite-file-read", /ATTACH/]] as const) {
        const c = check(results.writers, id);
        assert.equal(c.verdict, "fail", id);
        assert.match(c.summary, /write_query/, id);
        assert.match(c.summary, /not through read_query/, id);
        assert.ok(c.evidence.some((e) => e.tool === "write_query" && probe.test(e.probe) && /sqlite\.file-(?:read|write)\.(?:canary-leaked|created)/.test(e.code ?? "")), id);
      }
    });

    it("every tool the checks called with a valid argument is in coverage", () => {
      const c = check(results.ro, "sqlite-mutating-sql");
      assert.deepEqual(c.coverage?.probed, ["query"]);
      assert.ok((c.coverage?.validCalls ?? 0) > 10);
      assert.ok(results.ro.coverage && results.ro.coverage.validCalls > 10);
    });
  });

  describe("applicability", () => {
    it("is not applicable without a {sqlite_path} placeholder", () => {
      const p = results.noPlaceholder.packs.sqlite;
      assert.equal(p?.status, "na");
      assert.match(p?.reason ?? "", /no \{sqlite_path\} placeholder/);
      assert.equal(results.noPlaceholder.checks.filter((c) => c.pack === "sqlite").length, 0);
    });

    it("is not applicable with --no-sandbox", () => {
      const p = results.noSandbox.packs.sqlite;
      assert.equal(p?.status, "na");
      assert.match(p?.reason ?? "", /sandbox is off/);
    });

    it("DuckDB is planned: {duckdb_path} reports it as not shipped", () => {
      const p = results.duckdb.packs.sqlite;
      assert.equal(p?.status, "na");
      assert.match(p?.reason ?? "", /DuckDB grading is planned/);
    });

    it("applies() says why on a hand-built context", () => {
      const ctx = { config: effective("good"), tools: [], classification: [], active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet, pack: "sqlite" as const, open: async () => assert.fail("must not open") };
      const a = pack.applies(ctx as never);
      assert.equal(a.ok, false);
      assert.match(a.ok ? "" : a.reason, /sandbox/);
    });
  });

  describe("configuration", () => {
    it("checks.<id>.enabled: false reports n/a and the other checks still run", { skip: NEEDS_AUTHORIZER }, () => {
      const r = results.settings;
      const t = check(r, "sqlite-timeout");
      assert.equal(t.verdict, "na");
      assert.equal(t.summary, "disabled by config");
      assert.equal(check(r, "sqlite-extension-load").verdict, "pass");
    });

    it("checks.sqlite-rowcap.row_cap lowers the threshold (500 < the toy's 1,000-row cap)", { skip: NEEDS_AUTHORIZER }, () => {
      const c = check(results.settings, "sqlite-rowcap");
      assert.equal(c.verdict, "fail");
      assert.match(c.evidence[0].outcome, /cap threshold 500/);
    });

    it("severity: advisory takes a check out of the score", { skip: NEEDS_AUTHORIZER }, () => {
      const r = results.settings;
      const c = check(r, "sqlite-file-read");
      assert.equal(c.advisory, true);
      assert.equal(c.critical, false);
      const g = grade(r);
      assert.equal(g.scored, 5);
      assert.equal(g.pct, 80);
      assert.equal(g.letter, "B");
    });

    it("corpus.add adds a case read by the harness's own state readers, corpus.remove drops one by id", { skip: NEEDS_AUTHORIZER }, () => {
      const c = check(results.settings, "sqlite-mutating-sql");
      assert.equal(c.verdict, "pass");
      assert.ok(c.evidence.some((e) => /custom-insert/.test(e.outcome)));
      assert.ok(!c.evidence.some((e) => /upsert/.test(e.outcome)));
      assert.match(c.summary, /^all 10 mutation forms blocked/);
    });
  });

  describe("cleanup", () => {
    it("leaves the pristine fixture in the sandbox root and nothing of ours in the canary directory", async () => {
      const sb = results.settings.sandbox;
      assert.ok(sb?.kept, "the settings run kept its sandbox");
      assert.ok(sb.dir);
      const root = join(sb.dir, "root");
      const fixture = join(root, "fixture.sqlite");
      assert.ok(existsSync(fixture));
      const s = await readState(fixture);
      assert.ok(s.ok);
      assert.equal(s.journalMode, "delete");
      assert.equal(s.userVersion, 0);
      assert.equal(probeRowExists(fixture, 9010), true);
      assert.equal(probeRowExists(fixture, 9100), false);
      assert.deepEqual(readdirSync(root).filter((n) => n.startsWith("fixture.sqlite")), ["fixture.sqlite"]);
      assert.deepEqual(readdirSync(join(sb.dir, "canary")).sort(), ["secret.txt"]);
      assert.ok(!existsSync(join(sb.dir, "sqlite-pristine")));
    });

    it("every other run deleted its sandbox and left no process behind", () => {
      const left = readdirSync(parent).filter((n) => n.startsWith("sealmark-"));
      assert.equal(left.length, 1, `only the kept sandbox remains, found ${left.join(", ")}`);
      for (const [name, r] of Object.entries(results)) {
        if (name === "settings") continue;
        assert.equal(r.sandbox?.cleanedUp, true, name);
        assert.deepEqual(r.sandbox?.leftoverProcesses, [], name);
      }
    });
  });

  describe("describe()", () => {
    const docs = pack.describe();

    it("lists exactly the sqlite check ids the config schema knows, each once", () => {
      assert.deepEqual(docs.map((d) => d.id).sort(), CHECKS.filter((c) => c.pack === "sqlite").map((c) => c.id).sort());
      assert.equal(new Set(docs.map((d) => d.id)).size, docs.length);
    });

    it("covers every check id a run emitted, and the registry carries the same docs", () => {
      const ids = new Set(docs.map((d) => d.id));
      for (const r of Object.values(results)) for (const c of r.checks.filter((x) => x.pack === "sqlite")) assert.ok(ids.has(c.id), c.id);
      const reg = describeAll().filter((d) => d.pack === "sqlite");
      assert.deepEqual(reg.map((d) => d.id), docs.map((d) => d.id));
      assert.equal(new Set(describeAll().map((d) => d.id)).size, describeAll().length, "ids are unique across packs");
    });

    it("states criticality, thresholds and scope, and the criticality matches what a run emits", () => {
      const byId = Object.fromEntries(docs.map((d) => [d.id, d]));
      assert.deepEqual(docs.filter((d) => d.critical).map((d) => d.id).sort(), ["sqlite-extension-load", "sqlite-file-read", "sqlite-file-write", "sqlite-mutating-sql"]);
      assert.equal(byId["sqlite-rowcap"].thresholds.row_cap.default, 10_000);
      assert.equal(byId["sqlite-rowcap"].thresholds.row_cap.configKey, "checks.sqlite-rowcap.row_cap");
      assert.equal(byId["sqlite-timeout"].thresholds.expected_sec.standardLocked, true);
      for (const d of docs) {
        assert.match(d.scope, /^(server|database|environment)/);
        assert.ok(d.falsePositive.length > 20 && d.falseNegative.length > 20, d.id);
        assert.equal(d.since, "0.2-draft");
        assert.equal(d.status, "shipped");
        const emitted = results.ro.checks.find((c) => c.id === d.id);
        assert.equal(emitted?.critical, d.critical, d.id);
      }
    });

    it("publishes DuckDB probes as planned, never as run", () => {
      const planned = docs.flatMap((d) => d.probes).filter((p) => p.kind === "duckdb-planned");
      assert.ok(planned.length >= 5);
      assert.ok(planned.every((p) => /planned, not run in this release/.test(p.text)));
    });

    it("the published corpus names only harness-owned targets (placeholders), never a real path, host or server", () => {
      const texts = docs.flatMap((d) => d.probes.map((p) => p.text));
      assert.ok(texts.length > 15);
      for (const t of texts) {
        assert.ok(!/[A-Za-z]:[\\/]|\/(?:tmp|home|Users|etc|var)\b|\/\/|@modelcontextprotocol|https?:/.test(t), t);
        if (/'[^']*[\\/][^']*'/.test(t)) assert.match(t, /\{canary\}/, t);
      }
    });
  });

  describe("text rules", () => {
    const res = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: false, text, elapsedMs: 5, timedOut: false, closed: false, ...o });

    it("refused: an error flag, an RPC error, or a refusal that opens the response; a data row that mentions error is not a refusal", () => {
      assert.equal(refused(res("", { isError: true })), true);
      assert.equal(refused(res("", { rpcError: "boom" })), true);
      assert.equal(refused(res("Error: only SELECT is allowed")), true);
      assert.equal(refused(res("Only read statements are permitted")), true);
      assert.equal(refused(res('[{"msg":"error in the data"}]')), false);
      assert.equal(refused(res('[{"id":1}]')), false);
    });

    it("control read: the token and the count must both be there; a plan (even one that quotes the token) and a refusal are not rows", () => {
      assert.equal(controlReadPasses(res('[{"t":"sm-ctl-1","n":100}]'), "sm-ctl-1"), true);
      assert.equal(controlReadPasses(res('[{"t":"sm-ctl-1","n":99}]'), "sm-ctl-1"), false);
      assert.equal(controlReadPasses(res('[{"t":"sm-ctl-1","n":100,"note":"search results"}]'), "sm-ctl-1"), true, "lowercase words in data are not a plan");
      assert.equal(controlReadPasses(res("SCAN customers"), "sm-ctl-1"), false);
      assert.equal(controlReadPasses(res("QUERY PLAN\n`--SCAN customers 100 sm-ctl-1"), "sm-ctl-1"), false);
      assert.equal(controlReadPasses(res("addr  opcode         p1\n0     Init           0   String8 sm-ctl-1 100"), "sm-ctl-1"), false);
      assert.equal(controlReadPasses(res("Error: sm-ctl-1 100"), "sm-ctl-1"), false);
    });

    it("extension load: the engine's own wording decides, and unrecognised text is not a pass", () => {
      assert.equal(classifyExtensionLoad(res("The specified module could not be found.\r\n", { isError: true })), "attempted");
      assert.equal(classifyExtensionLoad(res("cannot open shared object file: No such file or directory", { isError: true })), "attempted");
      assert.equal(classifyExtensionLoad(res("dlopen(/x/sm-ext, 0x000A): tried: '/x/sm-ext' (no such file)", { isError: true })), "attempted");
      assert.equal(classifyExtensionLoad(res("IO Error: Extension \"x\" could not be loaded", { isError: true })), "attempted");
      assert.equal(classifyExtensionLoad(res("not authorized", { isError: true })), "denied");
      assert.equal(classifyExtensionLoad(res("not authorized to use function: load_extension", { isError: true })), "denied");
      assert.equal(classifyExtensionLoad(res("no such function: load_extension", { isError: true })), "denied");
      assert.equal(classifyExtensionLoad(res("Error: extension loading is disabled")), "denied");
      assert.equal(classifyExtensionLoad(res('[{"load_extension(\'x\')":null}]')), "unknown");
      assert.equal(classifyExtensionLoad(res("something odd happened")), "unknown");
    });

    it("extension load: an unrecognised engine error returned as plain text is unknown, and the check's documentation says what that means (round 3, sp-3)", () => {
      assert.equal(classifyExtensionLoad(res("Database error: the engine said something new")), "unknown");
      // Round 4 (D1): a server that flags the same text as an error has refused, but a refusal that says nothing about loading is not a
      // denial of loading, so it is unknown too (the check then sends a form the tool accepts, and is inconclusive if that says nothing either).
      assert.equal(classifyExtensionLoad(res("Database error: the engine said something new", { isError: true })), "unknown");
      assert.equal(classifyExtensionLoad(res("SELECT queries are not allowed for write_query", { isError: true })), "unknown");
      const doc = pack.describe().find((d) => d.id === "sqlite-extension-load")!;
      assert.match(doc.falsePositive, /Wording the harness does not recognise, including a refusal of every form that never mentions loading, is reported as inconclusive, never as a pass/);
      assert.match(doc.falsePositive, /A generic refusal \("SELECT queries are not allowed"\) is not a denial of loading/);
    });
  });
});

describe("sqlite fixtures", { skip: sqlite ? false : "node:sqlite is not available on this Node" }, () => {
  let tmp: string;
  before(() => {
    tmp = mkdtempSync(join(tmpdir(), "sealmark-sqlite-fx-"));
  });
  after(() => rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  it("builds the documented schema: 100 customers, a 200,000-row big_table, probe_t with row 9010, a masked view", () => {
    const p = join(tmp, "a.sqlite");
    createSqliteFixture(p);
    const got = readFixture(p, (db) => ({
      customers: (db.prepare("SELECT count(*) AS n FROM customers").get() as { n: number }).n,
      big: (db.prepare("SELECT count(*) AS n FROM big_table").get() as { n: number }).n,
      probe: db.prepare("SELECT id, v FROM probe_t").all().length,
      masked: (db.prepare("SELECT email FROM customers_masked LIMIT 1").get() as { email: string }).email,
      raw: (db.prepare("SELECT email FROM customers LIMIT 1").get() as { email: string }).email,
      tenants: (db.prepare("SELECT count(*) AS n FROM tenants").get() as { n: number }).n,
      orders: (db.prepare("SELECT count(*) AS n FROM orders").get() as { n: number }).n,
      mode: (db.prepare("PRAGMA journal_mode").get() as { journal_mode: string }).journal_mode,
    }));
    assert.deepEqual(got, { customers: 100, big: SQLITE_BIG_ROWS, probe: 1, masked: "c***@example.test", raw: "cust1001@example.test", tenants: 2, orders: 100, mode: "delete" });
    assert.equal(tableExists(p, "audit_probe"), true);
  });

  it("the fixture stays small enough for the file observer to hash it (under 8 MiB)", async () => {
    const p = join(tmp, "size.sqlite");
    createSqliteFixture(p);
    const { statSync } = await import("node:fs");
    assert.ok(statSync(p).size < 8 * 1024 * 1024, String(statSync(p).size));
  });

  it("readState is stable across reads and moves when the content moves, even when the file bytes do not", async () => {
    const p = join(tmp, "state.sqlite");
    createSqliteFixture(p);
    const a = await readState(p);
    const b = await readState(p);
    assert.ok(a.ok && b.ok);
    assert.deepEqual(a, b);
    const w = new sqlite!.DatabaseSync(p);
    w.exec("PRAGMA journal_mode = wal");
    w.exec("INSERT INTO probe_t VALUES (1, 'x')");
    const c = await readState(p);
    w.close();
    assert.ok(c.ok);
    assert.notEqual(c.logical, a.logical);
    assert.equal(c.journalMode, "wal");
  });

  it("ensureSqliteFixture creates once and leaves an existing file alone", () => {
    const p = join(tmp, "ensure.sqlite");
    assert.equal(ensureSqliteFixture(p), true);
    assert.equal(ensureSqliteFixture(p), false);
  });

  it("the canary database holds exactly the token", () => {
    const p = join(tmp, "secret.db");
    createCanaryDb(p, "sm-fscanary-test");
    assert.deepEqual(readFixture(p, (db) => db.prepare("SELECT v FROM secret").all().map((r) => (r as { v: string }).v)), ["sm-fscanary-test"]);
  });

  it("sqlPath gives forward slashes and doubles quotes", () => {
    assert.equal(sqlPath("C:\\a\\b'c"), "C:/a/b''c");
  });

});
