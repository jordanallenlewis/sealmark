// Round 4, package sql, item D1: sqlite-extension-load is decided from what the engine says about loading, never from the fact that a
// probe was refused. A writer that refuses the SELECT form is sent a form it accepts.
//   toy/sqlite-exthole  extension loading is on behind a read tool and a write tool that filter by statement type -> fail
//   toy/sqlite-extdeny  the near miss: the same filters, loading off                                              -> pass
//   toy/sqlite-extdeny --mode mute  every form is refused without a word about loading                             -> inconclusive
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyExtensionLoad, extensionForms } from "../packs/sqlite.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { CallResult } from "../mcp.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, RunResult } from "../types.js";
import { quiet } from "./helpers.js";

const HOLE = fileURLToPath(new URL("../toy/sqlite-exthole.js", import.meta.url));
const DENY = fileURLToPath(new URL("../toy/sqlite-extdeny.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} };
const OFF = { enabled: false, severity: null } as const;
// Only the extension check is under test: the other slow sqlite checks are switched off.
const ONLY_EXT = { "sqlite-timeout": OFF, "sqlite-rowcap": OFF, "sqlite-mutating-sql": OFF, "sqlite-read-only": OFF, "sqlite-file-read": OFF, "sqlite-file-write": OFF };

const SERVERS = { hole: [HOLE], deny: [DENY], mute: [DENY, "--mode", "mute"] } as const;
type Name = keyof typeof SERVERS;

let dir: string;
let parent: string;
const results = {} as Record<Name, RunResult>;

function config(name: Name) {
  return { name: `toy-sqlite-ext-${name}`, version: "0.0.1", server: { command: process.execPath, args: [...SERVERS[name], "--db", "{sqlite_path}"], env: {} } };
}

function effective(name: Name): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: config(name), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent }, checks: ONLY_EXT };
}

const ext = (name: Name): CheckResult => {
  const c = results[name].checks.find((x) => x.id === "sqlite-extension-load");
  assert.ok(c, "sqlite-extension-load missing");
  return c;
};

const res = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: false, text, elapsedMs: 5, timedOut: false, closed: false, ...o });

describe("sqlite-extension-load: the engine's words decide, a generic refusal does not", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-sqlite-ext-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const names = Object.keys(SERVERS) as Name[];
    const all = await Promise.all(names.map((n) => runHarness({ config: config(n), effective: effective(n), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2, log: quiet })));
    names.forEach((n, i) => (results[n] = all[i]));
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  describe("classifyExtensionLoad", () => {
    it("a generic refusal says nothing about loading: unknown, flagged as an error or not", () => {
      assert.equal(classifyExtensionLoad(res("SELECT queries are not allowed for write_query", { isError: true })), "unknown");
      assert.equal(classifyExtensionLoad(res("only SELECT queries are allowed", { isError: true })), "unknown");
      assert.equal(classifyExtensionLoad(res("this statement is not allowed", { isError: true })), "unknown");
      assert.equal(classifyExtensionLoad(res("", { isError: true })), "unknown");
      assert.equal(classifyExtensionLoad(res("", { rpcError: "Invalid params" })), "unknown");
      assert.equal(classifyExtensionLoad(res("Error: query is forbidden")), "unknown");
      assert.equal(classifyExtensionLoad(res("Error: unsupported statement type", { isError: true })), "unknown", "unsupported is about loading only next to extension or load");
      assert.equal(classifyExtensionLoad(res("payload is disabled for this tool", { isError: true })), "unknown", "payload is not the word load");
    });

    it("wording about loading is a denial, with the bare words only near extension or load", () => {
      for (const t of [
        "not authorized",
        "not authorized to use function: load_extension",
        "no such function: load_extension",
        "load_extension is disabled",
        "load_extension is not allowed",
        "extension loading is not enabled",
        "Error: extension loading is disabled",
        "not allowed to load extensions",
        "loading extensions is forbidden",
        "the load of this library is prohibited",
        "extensions are not supported",
      ]) {
        assert.equal(classifyExtensionLoad(res(t, { isError: true })), "denied", t);
      }
      assert.equal(classifyExtensionLoad(res("no such function: lower", { isError: true })), "unknown", "only load_extension counts");
    });

    it("an attempted load wins over denial wording in the same text", () => {
      assert.equal(classifyExtensionLoad(res("dlopen(/x/sm-ext, 0x000A): tried: '/x/sm-ext' (no such file)", { isError: true })), "attempted");
      assert.equal(classifyExtensionLoad(res("cannot open shared object file; loading is disabled elsewhere", { isError: true })), "attempted");
    });
  });

  describe("extensionForms", () => {
    it("the SELECT form goes first; a writer then gets an INSERT and an UPDATE, a reader a SELECT with a WHERE", () => {
      const w = extensionForms("writer", "/c").map((f) => f.sql);
      assert.deepEqual(w, [
        "SELECT load_extension('/c/sm-ext')",
        "INSERT INTO probe_t (id, v) VALUES (9100, load_extension('/c/sm-ext'))",
        "UPDATE probe_t SET v = load_extension('/c/sm-ext') WHERE id = 9010",
      ]);
      assert.deepEqual(extensionForms("reader", "/c").map((f) => f.sql), ["SELECT load_extension('/c/sm-ext')", "SELECT 1 WHERE load_extension('/c/sm-ext') IS NULL"]);
    });
  });

  describe("exthole: loading is enabled behind a writer that refuses the SELECT form", () => {
    it("fails: the INSERT form reaches the loader, and the evidence says the SELECT form was refused first", () => {
      const c = ext("hole");
      assert.equal(c.verdict, "fail", c.summary);
      const w = c.evidence.find((e) => e.tool === "write_query");
      assert.equal(w?.code, "sqlite.extension.attempted");
      assert.match(w?.outcome ?? "", /through the INSERT form, after the SELECT form was refused without a word about extensions/);
      assert.deepEqual((w?.args as { sql: string }[]).map((a) => a.sql.split("(")[0].trim()), ["SELECT load_extension", "INSERT INTO probe_t"]);
      assert.equal(c.evidence.find((e) => e.tool === "read_query")?.code, "sqlite.extension.attempted", "the reader's SELECT form reaches the loader directly");
    });
  });

  describe("extdeny (the near miss): the same filters with loading disabled", () => {
    it("passes: the writer's refusal of the SELECT form is not taken as a denial, its answer to the INSERT form is", () => {
      const c = ext("deny");
      assert.equal(c.verdict, "pass", c.summary);
      const w = c.evidence.find((e) => e.tool === "write_query");
      assert.equal(w?.code, "sqlite.extension.denied");
      assert.match(w?.outcome ?? "", /through the INSERT form/);
      assert.match(w?.outcome ?? "", /not authorized/);
    });
  });

  describe("mute: every form is refused without a word about loading", () => {
    it("is inconclusive, never a pass, and says why", () => {
      const c = ext("mute");
      assert.equal(c.verdict, "inconclusive", c.summary);
      assert.match(c.summary, /the server refused the probe forms without saying anything about extension loading \(read_query, write_query\)/);
      const w = c.evidence.find((e) => e.tool === "write_query");
      assert.equal(w?.code, "sqlite.extension.unknown");
      assert.equal((w?.args as unknown[]).length, 3, "the SELECT, INSERT and UPDATE forms were all tried");
      const r = c.evidence.find((e) => e.tool === "read_query");
      assert.equal((r?.args as unknown[]).length, 2, "the SELECT and WHERE forms were tried");
    });
  });

  it("every run removed its sandbox", () => {
    assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
    for (const n of Object.keys(SERVERS) as Name[]) assert.equal(results[n].sandbox?.cleanedUp, true, n);
  });
});
