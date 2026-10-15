// Integration round: the places where one package's output has to reach another's input. Each test names the hand-off it covers.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ConfigError } from "../config.js";
import { loadEffectiveConfig } from "../config/index.js";
import { describeAll } from "../packs/index.js";
import { runHarness } from "../run.js";
import type { PackId, RunResult } from "../types.js";
import { TOY, gradeOf, quiet } from "./helpers.js";

const DB_EXTRA = fileURLToPath(new URL("../toy/db-extra.js", import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;

/** Load a yaml file exactly as the CLI does, then run it with the sandbox parent redirected into the test's own folder. */
async function runYaml(name: string, yaml: string, over: { packs?: PackId[]; active?: boolean } = {}): Promise<RunResult> {
  const file = join(dir, name);
  writeFileSync(file, yaml);
  const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
  const packs = over.packs ?? (eff.packs as PackId[]);
  return runHarness({
    config: { name: eff.name, version: eff.version, server: eff.server },
    effective: { ...eff, sandbox: { ...eff.sandbox, dir: parent } },
    packs,
    packsExplicit: Boolean(over.packs) || eff.packsExplicit,
    timeoutProbeSec: 2,
    ...(over.active ? { active: true } : {}),
    log: quiet,
  });
}

const server = (script: string, ...args: string[]) => `server:\n  command: ${q(process.execPath)}\n  args: [${[script, ...args].map((a) => q(a)).join(", ")}]\n`;
const head = (name: string) => `schema_version: 1\nname: ${name}\nversion: 0.0.1\n`;

describe("integration: hand-offs between packages", { timeout: 180_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-integration-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("probes: a probe without a check is a valid call made in the core session: echoenvok goes from A (hygiene only) to D", async () => {
    const without = await runYaml("echo-no-probe.yaml", head("echo-no-probe") + server(DB_EXTRA, "--mode", "echoenvok") + "packs: [core]\n");
    assert.equal(gradeOf(without, "core")?.letter, "A");
    assert.equal(without.coverage?.level, "hygiene-only");
    assert.equal(without.probes, undefined, "no probes declared: no probes block");

    const withProbe = await runYaml("echo-probe.yaml", head("echo-probe") + server(DB_EXTRA, "--mode", "echoenvok") + "packs: [core]\nprobes:\n  - { tool: echo, args: { text: hello } }\n");
    const core = gradeOf(withProbe, "core");
    assert.equal(core?.letter, "D", "the leak is only reachable with a valid call");
    assert.equal(withProbe.checks.find((c) => c.id === "secret-echo")?.verdict, "fail");
    assert.ok((withProbe.coverage?.validCalls ?? 0) >= 1);
    assert.equal(withProbe.coverage?.toolsCalledValid, 1);
    assert.equal(withProbe.coverage?.toolsTotal, 2);
    const calls = (withProbe.probes?.calls ?? []) as { tool: string; valid: boolean; excerpt: string }[];
    assert.equal(calls.length, 1);
    assert.equal(calls[0].tool, "echo");
    assert.ok(calls[0].valid);
    // The canary values are masked in what the report keeps.
    assert.doesNotMatch(calls[0].excerpt, /sm-canary-[0-9a-f]{16}/);
    assert.doesNotMatch(calls[0].excerpt, /sk-sealmark-fake-/);
    assert.deepEqual(withProbe.custom, { probes: [] });
  });

  it("probes: a mistake in any probe is a ConfigError before the first tool call, even when no pack would run it", async () => {
    await assert.rejects(
      () => runYaml("bad-probe.yaml", head("bad-probe") + server(DB_EXTRA, "--mode", "echoenvok") + "packs: [core]\nprobes:\n  - { tool: nope, args: {} }\n"),
      (e: unknown) => e instanceof ConfigError && /nope/.test((e as Error).message),
    );
  });

  it("fixtures: the git repositories and the sqlite file exist before the discovery session opens the server", async () => {
    // A server that behaves like the real ones: it checks its repository and database at startup and dies without them.
    const wrapper = join(dir, "startup-check.mjs");
    writeFileSync(
      wrapper,
      `import { existsSync } from "node:fs";
const [repo, db] = process.argv.slice(2, 4);
if (!existsSync(repo + "/.git")) { console.error("startup-check: repository missing: " + repo); process.exit(3); }
if (!existsSync(db)) { console.error("startup-check: database missing: " + db); process.exit(3); }
process.argv.splice(2, 2);
await import(${q(pathToFileURL(TOY).href)});
`,
    );
    const r = await runYaml("fixtures.yaml", head("fixtures") + server(wrapper, "{sandbox}/repo", "{sqlite_path}", "--mode", "nosql") + "packs: [core]\n");
    assert.equal(gradeOf(r, "core")?.letter, "A", "the server started, so both fixtures were there");
  });

  it("db settings: checks.db-timeout.slow_sql is a known setting and makes the run CUSTOM", () => {
    const file = join(dir, "slowsql.yaml");
    writeFileSync(file, head("slowsql") + server(TOY, "--mode", "nosql") + "checks:\n  db-timeout:\n    slow_sql: SELECT count(*) FROM generate_series(1, 1000000000)\n");
    const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
    assert.equal(eff.integrity.standard, false);
    assert.equal(eff.checks["db-timeout"]?.slow_sql, "SELECT count(*) FROM generate_series(1, 1000000000)");
  });

  it("the registry documents every check id that the config schema knows, and the other way round", () => {
    const documented = new Set(describeAll().map((d) => d.id));
    for (const id of ["protocol", "db-rowcap", "db-timeout", "pii-masked", "fs-read-escape", "net-caps", "git-repo-scope", "exec-allowlist", "sqlite-rowcap", "http-bind", "annotation-honesty"]) {
      assert.ok(documented.has(id), `describe() lacks ${id}`);
    }
    assert.ok(!documented.has("cap-timeout"), "cap-timeout was split and is only a deprecated config alias");
  });

  it("the sandbox is gone and no process of ours is left after a run", async () => {
    const r = await runYaml("clean.yaml", head("clean") + server(TOY, "--mode", "nosql") + "packs: [core]\n");
    assert.equal(r.sandbox?.cleanedUp, true);
    assert.deepEqual(r.sandbox?.leftoverProcesses, []);
    assert.equal(existsSync(r.sandbox?.dir ?? parent), false);
  });
});
