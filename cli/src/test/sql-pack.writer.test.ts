// A declared writer tool is probed for the file checks (VACUUM INTO, ATTACH, load_extension), because those probes are
// verified by the file observer and the canary token and need no read control. The toy servers are in src/toy/sqlite-rwsplit.ts.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { describeAll } from "../packs/index.js";
import { sqliteRefused } from "../packs/sqlite.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { CallResult } from "../mcp.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, RunResult } from "../types.js";
import { quiet } from "./helpers.js";

const TOY = fileURLToPath(new URL("../toy/sqlite-rwsplit.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };
const MODES = ["escape", "refuse", "blind", "plain"] as const;
type Mode = (typeof MODES)[number];

let dir: string;
let parent: string;
const results = {} as Record<Mode, RunResult>;

function config(mode: Mode) {
  return { name: `toy-sqlite-rwsplit-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [TOY, "--mode", mode, "--db", "{sqlite_path}"], env: {} } };
}

// The runaway-query probe takes a full wait window on a server that never answers it, so only `plain` (which refuses it at once) runs it.
const OFF = { enabled: false, severity: null } as const;

function effective(mode: Mode): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: config(mode), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent }, checks: mode === "plain" ? {} : { "sqlite-timeout": OFF } };
}

const run = (mode: Mode) => runHarness({ config: config(mode), effective: effective(mode), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2, log: quiet });

const check = (r: RunResult, id: string): CheckResult => {
  const c = r.checks.find((x) => x.id === id);
  assert.ok(c, `check ${id} missing`);
  return c;
};
const FILE_CHECKS = ["sqlite-file-read", "sqlite-file-write", "sqlite-extension-load"];

describe("sqlite pack: a declared writer tool is probed for the file checks", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-sqlite-rw-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const all = await Promise.all(MODES.map((m) => run(m)));
    MODES.forEach((m, i) => (results[m] = all[i]));
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  describe("escape: write_query runs VACUUM INTO and ATTACH against any path", () => {
    it("fails sqlite-file-write, and the file the harness observed is named in the evidence", () => {
      const c = check(results.escape, "sqlite-file-write");
      assert.equal(c.verdict, "fail", c.summary);
      assert.match(c.summary, /write_query/);
      assert.match(c.summary, /read_query/, "the clean tool is named too");
      const hit = c.evidence.find((e) => e.tool === "write_query" && /VACUUM INTO/.test(e.probe));
      assert.ok(hit, JSON.stringify(c.evidence.map((e) => [e.tool, e.probe])));
      assert.match(hit.outcome, /canary\/vac-[0-9a-f]+\.db \(new\)/);
      assert.equal(hit.verifiedBy, "fs-observer");
      assert.equal(hit.code, "sqlite.file-write.created");
      const clean = c.evidence.filter((e) => e.tool === "read_query");
      assert.ok(clean.length && clean.every((e) => e.code === "sqlite.file-write.blocked"));
    });

    it("fails sqlite-file-read: the canary token comes back through write_query", () => {
      const c = check(results.escape, "sqlite-file-read");
      assert.equal(c.verdict, "fail", c.summary);
      const hit = c.evidence.find((e) => e.tool === "write_query");
      assert.equal(hit?.code, "sqlite.file-read.canary-leaked");
      assert.match(hit?.excerpt ?? "", /sm-fscanary-[0-9a-f]{16}/);
    });

    it("probes write_query for all three file checks and does not list it as not covered", () => {
      for (const id of FILE_CHECKS) {
        const c = check(results.escape, id);
        assert.deepEqual([...(c.coverage?.probed ?? [])].sort(), ["read_query", "write_query"], id);
        assert.ok(!c.coverage?.notCovered.some((n) => n.tool === "write_query"), `${id}: ${JSON.stringify(c.coverage?.notCovered)}`);
      }
    });

    it("the checks a writer is expected to fail anyway still leave it out, with a reason that fits the probe", () => {
      for (const id of ["sqlite-mutating-sql", "sqlite-rowcap", "sqlite-timeout"]) {
        const c = results.escape.checks.find((x) => x.id === id);
        if (!c || c.verdict === "na") continue;
        assert.deepEqual(c.coverage?.probed, ["read_query"], id);
        const n = c.coverage?.notCovered.find((x) => x.tool === "write_query");
        assert.ok(n, id);
        assert.doesNotMatch(n.reason, /read probes do not apply/, `${id}: the wording must say which probes do not apply`);
      }
    });

    it("the evidence args carry the exact SQL sent, one entry per call, not annotation text", () => {
      const c = check(results.escape, "sqlite-file-write");
      const vac = c.evidence.find((e) => e.tool === "write_query" && /VACUUM INTO/.test(e.probe));
      assert.deepEqual(vac?.args, { sql: vac?.probe });
      const att = c.evidence.find((e) => e.tool === "write_query" && /ATTACH/.test(e.probe));
      assert.ok(Array.isArray(att?.args));
      const sent = (att?.args as { sql: string }[]).map((a) => a.sql);
      assert.equal(sent.length, 2);
      assert.match(sent[0], /^ATTACH '\{canary\}\/att-[0-9a-f]+\.db' AS sm_a$/);
      assert.equal(sent[1], "CREATE TABLE sm_a.t (x)");
    });
  });

  describe("refuse (the near miss): write_query refuses VACUUM, ATTACH and load_extension by name", () => {
    it("passes sqlite-file-write and sqlite-file-read, with the writer probed and the refusals on record", () => {
      for (const id of ["sqlite-file-write", "sqlite-file-read"]) {
        const c = check(results.refuse, id);
        assert.equal(c.verdict, "pass", `${id}: ${c.summary}`);
        assert.deepEqual([...(c.coverage?.probed ?? [])].sort(), ["read_query", "write_query"], id);
        assert.ok(c.evidence.some((e) => e.tool === "write_query" && /not allowed/.test(e.outcome)), id);
      }
    });

    it("passes sqlite-extension-load: the refusal is taken from the writer's own answer", () => {
      const c = check(results.refuse, "sqlite-extension-load");
      assert.equal(c.verdict, "pass", c.summary);
      assert.ok(c.evidence.some((e) => e.tool === "write_query" && e.code === "sqlite.extension.denied"));
    });
  });

  describe("blind: write_query accepts ATTACH but never returns rows", () => {
    // Round 4 (D2): before, the writer's ATTACH could be neither confirmed nor ruled out (inconclusive). The ATTACH is now followed through
    // the controlled reader on the same session; blind opens a connection per call, so the reader cannot see it and the check is a pass.
    // The leaking counterpart (one shared connection) is tested in r4-sql.fileread.test.ts.
    it("the writer's ATTACH is followed through read_query, which cannot see it (a connection per call), so sqlite-file-read passes", () => {
      const c = check(results.blind, "sqlite-file-read");
      assert.equal(c.verdict, "pass", c.summary);
      assert.match(c.summary, /write_query accepted an ATTACH, but the reader on the same session could not read what it attached/);
      assert.ok(!c.coverage?.notCovered.some((n) => n.tool === "write_query"), JSON.stringify(c.coverage?.notCovered));
    });

    it("sqlite-file-write is decided by the file observer alone: VACUUM INTO and a new attached database are refused, nothing appears", () => {
      const c = check(results.blind, "sqlite-file-write");
      assert.equal(c.verdict, "pass", c.summary);
      assert.ok(c.evidence.some((e) => e.tool === "write_query"));
    });

    it("sqlite-extension-load is decided from the engine's own error text, which the writer passes through", () => {
      const c = check(results.blind, "sqlite-extension-load");
      assert.equal(c.verdict, "pass", c.summary);
      const e = c.evidence.find((x) => x.tool === "write_query");
      assert.equal(e?.code, "sqlite.extension.denied");
      assert.match(e?.outcome ?? "", /not authorized/);
    });
  });

  describe("plain: engine errors come back as 'Database error: ...' text with no error flag", () => {
    it("a rejected stacked statement is evidenced as a refusal, not as 'only the first statement ran'", () => {
      const c = check(results.plain, "sqlite-mutating-sql");
      assert.equal(c.verdict, "pass", c.summary);
      const e = c.evidence.find((x) => x.probe.startsWith("SELECT 1; INSERT"));
      assert.match(e?.outcome ?? "", /blocked or ineffective: stacked-insert \(Database error: You can only execute one statement at a time\.\)/);
      assert.doesNotMatch(e?.outcome ?? "", /only the first statement ran/);
    });

    it("a runaway query refused in text is 'not measured' (n/a), not a failed timeout", () => {
      const c = check(results.plain, "sqlite-timeout");
      assert.equal(c.verdict, "na", c.summary);
      assert.match(c.summary, /not measured/);
      assert.ok(c.evidence.some((e) => /refused before execution/.test(e.outcome)));
    });

    it("the file probes still read the writer's plain-text refusals as refusals", () => {
      assert.equal(check(results.plain, "sqlite-file-write").verdict, "pass");
      assert.equal(check(results.plain, "sqlite-file-read").verdict, "pass");
    });

    it("rowcap evidence: the annotation stays in the probe text and args carry only the SQL sent", () => {
      const e = check(results.plain, "sqlite-rowcap").evidence[0];
      assert.match(e.probe, /\(200,000 rows exist\)$/);
      assert.deepEqual(e.args, { sql: "SELECT id, payload FROM big_table ORDER BY id" });
    });
  });

  describe("describe() and cleanup", () => {
    it("file-write's false-positive note discloses the narrow exclusion instead of saying 'None known'", () => {
      const doc = describeAll().find((d) => d.id === "sqlite-file-write");
      assert.ok(doc);
      assert.doesNotMatch(doc.falsePositive, /^None known/);
      assert.match(doc.falsePositive, /declared writer/i);
      assert.match(doc.falsePositive, /neither a control read nor a control write/i);
    });

    it("every run removed its sandbox and left nothing in the canary directory", () => {
      assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
      for (const m of MODES) {
        assert.equal(results[m].sandbox?.cleanedUp, true, m);
        assert.deepEqual(results[m].sandbox?.leftoverProcesses, [], m);
      }
    });
  });

  describe("sqliteRefused", () => {
    const res = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: false, text, elapsedMs: 5, timedOut: false, closed: false, ...o });

    it("recognises the engine's own error prefixes in plain text, as well as the shared refusal wording", () => {
      assert.equal(sqliteRefused(res("Database error: near \"INSERT\": syntax error")), true);
      assert.equal(sqliteRefused(res("sqlite3.OperationalError: no such table: nope")), true);
      assert.equal(sqliteRefused(res("SQLite error: attempt to write a readonly database")), true);
      assert.equal(sqliteRefused(res("Error: only SELECT is allowed")), true);
      assert.equal(sqliteRefused(res("", { isError: true })), true);
    });

    it("a data row that mentions a database error is not a refusal", () => {
      assert.equal(sqliteRefused(res('[{"msg":"Database error: in the data"}]')), false);
      assert.equal(sqliteRefused(res("the Database error: rate is 0")), false);
      assert.equal(sqliteRefused(res('[{"id":1}]')), false);
    });
  });
});
