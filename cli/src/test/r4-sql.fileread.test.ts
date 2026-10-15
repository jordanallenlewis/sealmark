// Round 4, package sql, item D2: sqlite-file-read follows a writer's ATTACH through the controlled reader on the same session.
//   toy/sqlite-rwleaky                one shared connection; read_query reads what write_query attached      -> fail, both tools named
//   toy/sqlite-rwleaky --mode guarded the ATTACH persists but the reader refuses to read it                  -> pass, with the reason
//   toy/sqlite-rwsplit --mode blind   a connection per call: nothing the writer attached survives            -> pass (was inconclusive)
//   toy/sqlite-rwsplit --mode escape  the writer shows the canary itself                                     -> fail (unchanged)
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { describeAll } from "../packs/index.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, RunResult } from "../types.js";
import { quiet } from "./helpers.js";

const LEAKY = fileURLToPath(new URL("../toy/sqlite-rwleaky.js", import.meta.url));
const SPLIT = fileURLToPath(new URL("../toy/sqlite-rwsplit.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} };
const OFF = { enabled: false, severity: null } as const;
const ONLY_READ = { "sqlite-timeout": OFF, "sqlite-rowcap": OFF, "sqlite-mutating-sql": OFF, "sqlite-read-only": OFF, "sqlite-extension-load": OFF };

const SERVERS = {
  leaky: [LEAKY],
  guarded: [LEAKY, "--mode", "guarded"],
  blind: [SPLIT, "--mode", "blind"],
  escape: [SPLIT, "--mode", "escape"],
} as const;
type Name = keyof typeof SERVERS;

let dir: string;
let parent: string;
const results = {} as Record<Name, RunResult>;

function config(name: Name) {
  return { name: `toy-sqlite-read-${name}`, version: "0.0.1", server: { command: process.execPath, args: [...SERVERS[name], "--db", "{sqlite_path}"], env: {} } };
}

function effective(name: Name): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: config(name), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent }, checks: ONLY_READ };
}

const read = (name: Name): CheckResult => {
  const c = results[name].checks.find((x) => x.id === "sqlite-file-read");
  assert.ok(c, "sqlite-file-read missing");
  return c;
};

describe("sqlite-file-read: a writer's ATTACH is followed through the controlled reader", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-sqlite-fr-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const names = Object.keys(SERVERS) as Name[];
    const all = await Promise.all(names.map((n) => runHarness({ config: config(n), effective: effective(n), packs: ["sqlite"], packsExplicit: true, timeoutProbeSec: 2, log: quiet })));
    names.forEach((n, i) => (results[n] = all[i]));
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }));

  it("rwleaky: fails, and the evidence names the tool that attached and the tool that read", () => {
    const c = read("leaky");
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /attached through write_query and read through read_query/);
    const hit = c.evidence.find((e) => e.tool === "write_query");
    assert.equal(hit?.code, "sqlite.file-read.canary-leaked");
    assert.match(hit?.outcome ?? "", /attached through write_query, read through read_query/);
    assert.match(hit?.excerpt ?? "", /sm-fscanary-[0-9a-f]{16}/);
    assert.match(hit?.probe ?? "", /\(through read_query\)/, "the follow-up calls are in the probe text");
    assert.equal((hit?.args as unknown[]).length, 2, "args carry only what write_query was sent");
    assert.equal(c.evidence.find((e) => e.tool === "read_query")?.code, "sqlite.file-read.blocked", "read_query refuses the ATTACH itself");
  });

  it("rwleaky guarded (near miss): the alias is visible but the reader refuses to read it, which is clean, with the reason", () => {
    const c = read("guarded");
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /write_query accepted an ATTACH, but the reader on the same session could not read what it attached/);
    const e = c.evidence.find((x) => x.tool === "write_query");
    assert.equal(e?.code, "sqlite.file-read.blocked");
    assert.match(e?.outcome ?? "", /the ATTACH persisted \(the alias is in the reader's database list\) but read_query refused to read it/);
  });

  it("rwsplit blind (near miss): a fresh connection per call is clean, no longer inconclusive", () => {
    const c = read("blind");
    assert.equal(c.verdict, "pass", c.summary);
    const e = c.evidence.find((x) => x.tool === "write_query");
    assert.equal(e?.code, "sqlite.file-read.blocked");
    assert.match(e?.outcome ?? "", /the ATTACH did not persist for the reader: the server uses a fresh connection per call/);
    assert.ok(!c.coverage?.notCovered.some((n) => n.tool === "write_query"), JSON.stringify(c.coverage?.notCovered));
  });

  it("rwsplit escape: still fails, through the writer itself (no follow-up through the reader was needed)", () => {
    const c = read("escape");
    assert.equal(c.verdict, "fail", c.summary);
    const hit = c.evidence.find((e) => e.tool === "write_query");
    assert.equal(hit?.code, "sqlite.file-read.canary-leaked");
    assert.doesNotMatch(hit?.outcome ?? "", /read through/);
  });

  it("the check's documentation describes the three cases", () => {
    const doc = describeAll().find((d) => d.id === "sqlite-file-read");
    assert.ok(doc);
    assert.match(doc.falsePositive, /followed through the controlled reader on the same session/);
    assert.match(doc.falsePositive, /fresh connection per call/);
    assert.match(doc.falsePositive, /no controlled reader to ask/);
  });

  it("every run removed its sandbox", () => {
    assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
    for (const n of Object.keys(SERVERS) as Name[]) assert.equal(results[n].sandbox?.cleanedUp, true, n);
  });
});
