import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classificationBlock } from "../classify.js";
import { EXIT_CODES, SIGNAL_EXIT_CODES } from "../cli-spec.js";
import { ConfigError, checkReplay, computeHash, loadEffectiveConfig, replayNotes, standardHash, type EffectiveConfig, type LoadOptions } from "../config/index.js";
import { importManual, scanClients, type ImportEnv } from "../config/import.js";
import { realPaths } from "../config/placeholders.js";
import { dsnHint, runInit, suggestReplacements, type FileSink, type WizardIO } from "../config/wizard.js";
import { diagnoseStartup, runDoctor } from "../doctor.js";
import { packsApplied } from "../report/common.js";
import { runHarness } from "../run.js";
import type { PackId, RunResult } from "../types.js";
import { FAST, TOY, cliKit } from "./helpers.js";

const POSIX = process.platform !== "win32";
const FIXTURES = fileURLToPath(new URL("../../src/test/fixtures/config/", import.meta.url));
const toyPath = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));
const q = JSON.stringify;

let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-r4cc-"));
});
after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";
const CHECK = "probes:\n  - id: p1\n    check: { id: custom-p1, label: P1, scope: 'server (x)' }\n    tool: t\n";

function proj(yaml: string): string {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), yaml);
  return dir;
}
const load = (yaml: string, o: Partial<LoadOptions> = {}): EffectiveConfig => loadEffectiveConfig({ cwd: proj(yaml), isolated: true, env: {}, ...o });

// ---------------------------------------------------------------------------------------------------------
// G5: a CUSTOM run with custom checks or plugins has its own hash
// ---------------------------------------------------------------------------------------------------------

describe("G5: config.hash covers custom checks and plugins, and moves only then", () => {
  it("standardHash() is the pinned value, and a run with no probes and no plugins carries exactly it", () => {
    assert.equal(standardHash(), readFileSync(join(FIXTURES, "standard.hash.txt"), "utf8").trim());
    const c = load(BASE);
    assert.equal(c.integrity.hash, standardHash());
    assert.equal(c.integrity.standard, true);
    assert.equal("custom_checks" in c.integrity.locked, false, "a standard run's locked block has no custom keys");
    assert.equal("plugins" in c.integrity.locked, false);
  });

  it("a plain probe without a check keeps the standard hash (adding coverage never weakens a run)", () => {
    const c = load(`${BASE}probes:\n  - id: p1\n    tool: t\n`);
    assert.equal(c.integrity.hash, standardHash());
    assert.equal(c.integrity.standard, true);
  });

  it("one check probe gives a different hash, a CUSTOM run, and the check id in config.locked", () => {
    const c = load(`${BASE}${CHECK}`);
    assert.notEqual(c.integrity.hash, standardHash());
    assert.equal(c.integrity.standard, false);
    assert.deepEqual(c.integrity.locked.custom_checks, ["custom-p1"]);
    assert.equal(computeHash(c.integrity.locked), c.integrity.hash, "the recorded locked block hashes to the recorded hash");
    assert.ok(c.integrity.standardDiff.some((d) => d.path === "probes"));
  });

  it("different check ids hash differently; the order they are declared in does not matter", () => {
    const two = (a: string, b: string) => load(`${BASE}probes:\n  - id: a\n    check: { id: ${a}, label: A, scope: 'server (x)' }\n    tool: t\n  - id: b\n    check: { id: ${b}, label: B, scope: 'server (x)' }\n    tool: t\n`).integrity.hash;
    assert.equal(two("custom-x", "custom-y"), two("custom-y", "custom-x"));
    assert.notEqual(two("custom-x", "custom-y"), two("custom-x", "custom-z"));
  });

  it("a plugin gives a different hash and its module in config.locked", () => {
    const c = load(`${BASE}plugins:\n  - module: ./my-pack.mjs\n`);
    assert.notEqual(c.integrity.hash, standardHash());
    assert.equal(c.integrity.standard, false);
    assert.deepEqual(c.integrity.locked.plugins, ["./my-pack.mjs"]);
  });

  it("empty custom keys do not move the hash (the digest is unchanged when nothing custom is in play)", () => {
    const c = load(BASE);
    assert.equal(computeHash({ ...c.integrity.locked, custom_checks: [], plugins: [] }), c.integrity.hash);
  });

  it("replaying a CUSTOM report warns that probes are the user's to declare, and does not refuse", () => {
    const original = load(`${BASE}${CHECK}`);
    const report = JSON.parse(JSON.stringify(original.integrity)) as typeof original.integrity;
    assert.equal(checkReplay(report), undefined, "a genuine custom report is replayable");
    const bare = load(BASE, { replay: report });
    assert.match(bare.warnings.join("\n"), /the report was a CUSTOM run with custom checks \(custom-p1\); --replay restores the locked settings only, so declare the same probes: yourself/);
    assert.notEqual(bare.integrity.hash, original.integrity.hash, "without the probes the replayed run is a different run");
    const declared = load(`${BASE}${CHECK}`, { replay: report });
    assert.equal(declared.integrity.hash, original.integrity.hash, "declaring the same check gives the same hash");
  });

  it("a replay's custom record is names only: objects in it are a forgery, and strings are never loaded", () => {
    const rep = load(BASE).integrity;
    const forged = { ...rep.locked, plugins: [{ module: "../evil.mjs" }] };
    assert.match(checkReplay({ ...rep, locked: forged, hash: computeHash(forged) }) ?? "", /may not set: plugins/);
    const names = { ...rep.locked, plugins: ["./some-plugin.mjs"] };
    const report = { ...rep, locked: names, hash: computeHash(names) };
    assert.equal(checkReplay(report), undefined);
    const cfg = load(BASE, { replay: report });
    assert.deepEqual(cfg.plugins, [], "a name in a report never becomes a plugin");
    assert.match(replayNotes(report).join(""), /plugins \(\.\/some-plugin\.mjs\).*declare the same plugins:/);
  });

  it("a forged name cannot write control characters into the warning", () => {
    const note = replayNotes({ locked: { custom_checks: ["a\u001b[31mb"] } }).join("");
    assert.equal(/\u001b/.test(note), false);
  });
});

// ---------------------------------------------------------------------------------------------------------
// G4: run and doctor warn about real paths
// ---------------------------------------------------------------------------------------------------------

describe("G4: a server given a real path is warned about", () => {
  const warn = (extra: string) => load(`schema_version: 1\nserver:\n  command: node\n${extra}`).warnings.filter((w) => /real path/.test(w));

  it("an absolute path in server.env names the variable and says what to type", () => {
    const w = warn("  args: [srv.js]\n  env:\n    MEMORY_FILE_PATH: /srv/real/memory.jsonl\n");
    assert.equal(w.length, 1);
    assert.equal(w[0], "server.env MEMORY_FILE_PATH points at a real path on this machine; valid calls may read or write it. Use {sandbox}/<name> to keep the run inside the harness's directory.");
  });

  it("an absolute path in server.args is named by its index", () => {
    assert.match(warn("  args: [srv.js, --data, /srv/real/data]\n").join("\n"), /^server\.args\[2\] points at a real path/);
  });

  it("nothing is said for {sandbox} values, system variables, launcher directories, placeholders or the program being run", () => {
    assert.deepEqual(warn("  args: [/opt/srv/dist/server.js, --directory, /srv/proj, --root, '{sandbox}/x', --db, '{sqlite_path}']\n  env:\n    HOME: /home/someone\n    DATA_FILE: '{sandbox}/store.json'\n    OTHER: ${SOMEWHERE:-}/x\n"), []);
  });

  it("with several servers each warning names its server", () => {
    const c = load("schema_version: 1\nservers:\n  a:\n    command: node\n    args: [srv.js]\n    env: { STORE: /srv/real/a }\n  b:\n    command: node\n    args: [srv.js]\n");
    assert.deepEqual(c.warnings.filter((w) => /real path/.test(w)).map((w) => w.split(" ")[0]), ["servers.a.env"]);
  });

  it("realPaths reports the same values init would have offered to replace", () => {
    assert.deepEqual(realPaths({ args: ["--root=/srv/x", "--cwd", "/srv/y", "plain"], env: { PATH: "/usr/bin", KEEP: "/srv/z" } }).map((r) => r.id), ["args[0]", "env.KEEP"]);
  });
});

// ---------------------------------------------------------------------------------------------------------
// G3: init never leaves the harness pointed at a user's real file
// ---------------------------------------------------------------------------------------------------------

describe("G3: init offers harness-owned targets for real files and database paths", () => {
  const HOME = "/home/tester";
  const CWD = "/home/tester/proj";
  const clientEnv = (servers: Record<string, unknown>): ImportEnv => ({
    platform: "linux",
    home: HOME,
    cwd: CWD,
    env: {},
    read: (p) => (p === `${HOME}/.cursor/mcp.json` ? JSON.stringify({ mcpServers: servers }) : undefined),
    list: () => [],
  });
  const SERVERS = {
    memory: { command: "npx", args: ["-y", "some-memory-server"], env: { MEMORY_FILE_PATH: "/home/tester/notes/real.jsonl" } },
    store: { command: "npx", args: ["-y", "some-store-server", "--db-path", "./test.db"] },
    other: { command: "srv", args: ["--database", "/var/lib/app/state"], env: { SSL_CERT_FILE: "/etc/ssl/cert.pem", HOME: "/home/tester" } },
  };
  const none = { isDir: () => false, isFile: () => false };
  const server = (name: string) => scanClients(clientEnv(SERVERS), { clients: ["cursor"] }).servers.find((s) => s.name === name)!;

  it("an env variable that names a data file is offered {sandbox}/<basename>", () => {
    const [s] = suggestReplacements(server("memory"), none);
    assert.equal(s.kind, "sandbox-file");
    assert.equal(s.value, "{sandbox}/real.jsonl");
    assert.equal(s.placeholder, "{sandbox}/real.jsonl");
    assert.deepEqual(s.target, { field: "env", key: "MEMORY_FILE_PATH" });
    assert.match(s.reason, /a file the server reads or writes: inside the sandbox the harness owns it and your real file is never touched/);
  });

  it("an existing file is offered the sandbox copy even without a data extension or a telling variable name", () => {
    const spec = { ...server("memory"), spec: { command: "c", args: ["--out", "/srv/x/report"] }, local: {}, routed: [] };
    assert.deepEqual(suggestReplacements(spec, { isDir: () => false, isFile: () => false }), []);
    assert.equal(suggestReplacements(spec, { isDir: () => false, isFile: (p) => p === "/srv/x/report" })[0].value, "{sandbox}/report");
  });

  it("a relative --db-path gets {sqlite_path}, with or without an extension; a bare database name is left alone", () => {
    const rel = suggestReplacements(server("store"), none);
    assert.equal(rel.length, 1);
    assert.equal(rel[0].kind, "sqlite");
    assert.equal(rel[0].value, "{sqlite_path}");
    const spec = (args: string[]) => ({ ...server("store"), spec: { command: "c", args }, local: {}, routed: [] });
    assert.equal(suggestReplacements(spec(["--db-path", "data/store"]), none)[0].value, "{sqlite_path}");
    assert.equal(suggestReplacements(spec(["--database=/var/lib/app/state"]), none)[0].value, "--database={sqlite_path}");
    assert.deepEqual(suggestReplacements(spec(["--database", "mydb"]), none), []);
    assert.deepEqual(suggestReplacements(spec(["--db", "postgres://u@h/db"]), none).map((s) => s.kind), ["dsn"]);
  });

  it("a credential file and a system variable are left alone", () => {
    assert.deepEqual(suggestReplacements(server("other"), none).filter((s) => s.target.field === "env"), []);
  });

  it("--yes writes the replacements, so the written config holds no path of the user's machine", async () => {
    const written = new Map<string, string>();
    const sink: FileSink = { write: (p, c) => void written.set(p, c) };
    const out = await runInit({ env: clientEnv(SERVERS), configPath: join(CWD, "sealmark.yaml"), clients: ["cursor"], select: ["memory", "store"], sink, readText: () => undefined, suggest: none });
    const yaml = written.get(join(CWD, "sealmark.yaml"))!;
    assert.match(yaml, /MEMORY_FILE_PATH: "?\{sandbox\}\/real\.jsonl"?/);
    assert.match(yaml, /\{sqlite_path\}/);
    assert.equal(yaml.includes("/home/tester"), false);
    assert.equal(yaml.includes("test.db"), false);
    assert.equal(out.applied.length, 2);
    assert.match(out.messages.join("\n"), /memory: env\.MEMORY_FILE_PATH \/home\/tester\/notes\/real\.jsonl -> \{sandbox\}\/real\.jsonl/);
  });

  it("a path left as it was (declined, or never offered) is commented in the written config", async () => {
    const written = new Map<string, string>();
    const sink: FileSink = { write: (p, c) => void written.set(p, c) };
    await runInit({ env: clientEnv(SERVERS), configPath: join(CWD, "sealmark.yaml"), clients: ["cursor"], select: ["other"], sink, readText: () => undefined, suggest: none });
    assert.match(written.get(join(CWD, "sealmark.yaml"))!, /# note \(other\): server\.env SSL_CERT_FILE points at a real path on this machine; valid calls may read or write it\. Use \{sandbox\}\/<name>/);
  });

  it("interactively, a declined replacement stays and is commented", async () => {
    const written = new Map<string, string>();
    const sink: FileSink = { write: (p, c) => void written.set(p, c) };
    const io: WizardIO = { ask: async (_q, d) => (/replace/.test(_q) ? "n" : (d ?? "")), write: () => {} };
    await runInit({ env: clientEnv(SERVERS), configPath: join(CWD, "sealmark.yaml"), clients: ["cursor"], select: ["memory"], io, sink, readText: () => undefined, suggest: none });
    const yaml = written.get(join(CWD, "sealmark.yaml"))!;
    assert.match(yaml, /\/home\/tester\/notes\/real\.jsonl/);
    assert.match(yaml, /# note \(memory\): server\.env MEMORY_FILE_PATH points at a real path/);
  });

  it("init --from offers {dsn} for a database server with no connection string, and says nothing otherwise", () => {
    const e = clientEnv({});
    const imp = (command: string, args: string[], env?: Record<string, string>) => importManual({ name: "x", command, args, env }, e);
    assert.match(dsnHint(imp("uvx", ["toy-postgres-server"])) ?? "", /add --dsn \{dsn\}/);
    assert.match(dsnHint(imp("npx", ["-y", "@scope/mysql-mcp"])) ?? "", /--dsn \{dsn\}/);
    assert.equal(dsnHint(imp("uvx", ["toy-postgres-server", "--dsn", "{dsn}"])), undefined);
    assert.equal(dsnHint(imp("uvx", ["toy-postgres-server", "postgresql://u@127.0.0.1/db"])), undefined);
    assert.equal(dsnHint(imp("uvx", ["toy-sqlite-server", "--db-path", "x.db"])), undefined);
    assert.equal(dsnHint(imp("npx", ["-y", "@scope/weather-server"])), undefined);
  });

  it("init --from asks before adding the flag, and adds it only on a yes", async () => {
    const run = async (answer: string) => {
      const written = new Map<string, string>();
      const sink: FileSink = { write: (p, c) => void written.set(p, c) };
      const io: WizardIO = { ask: async (q) => (/--dsn/.test(q) ? answer : ""), write: () => {} };
      await runInit({ env: clientEnv({}), configPath: join(CWD, "sealmark.yaml"), fromCommand: "uvx toy-postgres-server", io, sink, readText: () => undefined, suggest: none });
      return written.get(join(CWD, "sealmark.yaml"))!;
    };
    assert.match(await run("y"), /--dsn\n?\s*- "?\{dsn\}"?|\{dsn\}/);
    assert.equal((await run("n")).includes("{dsn}"), false);
  });
});

// ---------------------------------------------------------------------------------------------------------
// G1, G6: the CLI
// ---------------------------------------------------------------------------------------------------------

describe("G1 and G6: the command line", { timeout: 240_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(root, "cli-"));
  });
  const { sealmark, toyConfig, writeYaml } = cliKit(() => dir);
  const sub = (name: string) => mkdtempSync(join(dir, `${name}-`));

  it("G1: --format summary --out file prints the grade line on stderr (the summary went to a file)", () => {
    const d = sub("g1");
    const r = sealmark(["run", "--config", toyConfig("g1.yaml", "nosql"), ...FAST, "--format", "summary", "--out", join(d, "s.txt")], d);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^core [A-F]/m, "the grade line is on stderr");
    assert.equal(r.out, "", "stdout stays empty");
    assert.match(readFileSync(join(d, "s.txt"), "utf8"), /S E A L M A R K/, "the summary is in the file");
  });

  it("G1: the summary on the console is not repeated on stderr", () => {
    const d = sub("g1b");
    const alone = sealmark(["run", "--config", toyConfig("g1b.yaml", "nosql"), ...FAST, "--format", "summary"], d);
    assert.match(alone.out, /S E A L M A R K/);
    assert.doesNotMatch(alone.err, /^core [A-F]/m);
    const several = sealmark(["run", "--config", toyConfig("g1c.yaml", "nosql"), ...FAST, "--format", "summary", "--format", "json", "--out-dir", join(d, "o")], d);
    assert.match(several.out, /S E A L M A R K/);
    assert.doesNotMatch(several.err, /^core [A-F]/m);
  });

  it("G1: a json report to a file still prints the line", () => {
    const d = sub("g1d");
    const r = sealmark(["run", "--config", toyConfig("g1d.yaml", "nosql"), ...FAST, "--format", "json", "--out", join(d, "r.json")], d);
    assert.match(r.err, /^core [A-F]/m);
  });

  it("G4: run prints the real-path warning before the run and keeps it in the report", () => {
    const d = sub("g4");
    const cfg = writeYaml("g4.yaml", `schema_version: 1\nname: g4\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([TOY, "--mode", "nosql"])}\n  env:\n    MEMORY_FILE_PATH: ${q(join(d, "never-created.jsonl"))}\n`);
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json", "--out", join(d, "r.json")], d);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /warning: server\.env MEMORY_FILE_PATH points at a real path on this machine/);
    const rep = JSON.parse(readFileSync(join(d, "r.json"), "utf8")) as RunResult;
    assert.ok((rep.warnings ?? []).some((w) => /MEMORY_FILE_PATH points at a real path/.test(w)));
    assert.equal(existsSync(join(d, "never-created.jsonl")), false, "the harness did not create it");
  });

  it("G4: doctor prints the same warning", () => {
    const d = sub("g4d");
    const cfg = writeYaml("g4d.yaml", `schema_version: 1\nname: g4\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([TOY, "--mode", "nosql"])}\n  env:\n    MEMORY_FILE_PATH: ${q(join(d, "never-created.jsonl"))}\npacks: [core]\n`);
    const r = sealmark(["doctor", "--config", cfg], d);
    assert.match(r.err, /warning: server\.env MEMORY_FILE_PATH points at a real path/);
  });

  it("G6: --fail-under a is read as A, and says so once", () => {
    const c = load(BASE, { flags: { "fail-under": "a" } });
    assert.equal(c.output.exit_policy.fail_under, "A");
    assert.deepEqual(c.warnings.filter((w) => /fail-under/.test(w)), ["--fail-under a read as A"]);
    assert.deepEqual(load(BASE, { flags: { "fail-under": "A" } }).warnings.filter((w) => /fail-under/.test(w)), []);
    assert.deepEqual(load(BASE, { flags: { "fail-under": "none" } }).warnings.filter((w) => /fail-under/.test(w)), []);
  });

  it("G6: a map-valued difference from the standard names the file it was set in, not 'default'", () => {
    const c = load(`${BASE}tools:\n  overrides:\n    some_tool: { class: path }\n`);
    const d = c.integrity.standardDiff.find((e) => e.path === "tools.overrides");
    assert.ok(d, JSON.stringify(c.integrity.standardDiff));
    assert.match(d.origin, /sealmark\.yaml:\d+/);
  });

  it("G6: the exit-code table names the A* rule, the inconclusive rule and the signal codes", () => {
    assert.deepEqual([...EXIT_CODES, ...SIGNAL_EXIT_CODES].map((e) => e.code), [0, 1, 2, 3, 4, 129, 130, 143]);
    const help = sealmark(["--help"]).out;
    assert.match(help, /provisional A\* is below an A gate/);
    assert.match(help, /\n {2}130 {2}interrupted by SIGINT/);
    const described = JSON.parse(sealmark(["describe", "--json"]).out) as { cli: { exitCodes: { code: number }[] } };
    assert.deepEqual(described.cli.exitCodes.map((e) => e.code), [0, 1, 2, 3, 4, 129, 130, 143]);
  });

  it("G6: --out /dev/null is writable (the probe file is not written next to a device)", { skip: !POSIX || !existsSync("/dev/null") }, () => {
    const d = sub("devnull");
    const r = sealmark(["run", "--config", toyConfig("devnull.yaml", "nosql"), ...FAST, "--format", "json", "--out", "/dev/null"], d);
    assert.equal(r.code, 0, r.err);
    assert.doesNotMatch(r.err, /Cannot write/);
  });

  it("G6: a bare --fixture says which command to type", () => {
    const r = sealmark(["--fixture", "fs", "--into", "somewhere"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /missing command: did you mean sealmark run --fixture fs --into somewhere/);
  });

  it("G2: doctor and run print the same packs applied line", { skip: !POSIX }, () => {
    const d = sub("g2");
    const cfg = writeYaml("g2.yaml", `schema_version: 1\nname: g2\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([TOY, "--mode", "nosql"])}\npacks: [core]\n`);
    const doc = sealmark(["doctor", "--config", cfg], d).out;
    const run = sealmark(["run", "--config", cfg, "--timeout-probe", "2", "--fail-under", "none", "--format", "text"], d).out;
    const line = (t: string) => /^ *packs applied: .*$/m.exec(t)?.[0]?.trim();
    assert.equal(line(doc), "packs applied: core");
    assert.equal(line(run), line(doc));
  });
});

// ---------------------------------------------------------------------------------------------------------
// G2: doctor lists core, as run does, for configurations with more than one pack
// ---------------------------------------------------------------------------------------------------------

describe("G2: doctor's packs applied line equals the run's", { timeout: 240_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(root, "g2-"));
    mkdirSync(join(dir, "sandboxes"));
  });
  const cfgFor = (args: string[], extra: string): EffectiveConfig => {
    const file = join(dir, `c${n++}.yaml`);
    writeFileSync(file, `schema_version: 1\nname: g2\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: ${q(args)}\nsandbox:\n  dir: ${q(join(dir, "sandboxes"))}\n${extra}`);
    return loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
  };
  const both = async (cfg: EffectiveConfig, packs: PackId[]) => {
    const d = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
    const r = await runHarness({ config: { name: cfg.name, version: cfg.version, server: cfg.server }, effective: cfg, packs, packsExplicit: true, timeoutProbeSec: 2, log: () => {} });
    const last = (rows: string[]) => rows.filter((l) => /packs applied/.test(l)).pop();
    return { doctor: last(d.servers[0]!.classificationText ?? []), run: last(classificationBlock(r.classification ?? [], packsApplied(r))) };
  };

  it("core only", async () => {
    const x = await both(cfgFor([TOY, "--mode", "nosql"], "packs: [core]\n"), ["core"]);
    assert.equal(x.doctor, "  packs applied: core");
    assert.equal(x.doctor, x.run);
  });

  it("core and fs", async () => {
    const x = await both(cfgFor([toyPath("fs"), "--mode", "good", "--root", "{sandbox}"], "packs: [core, fs]\n"), ["core", "fs"]);
    assert.equal(x.doctor, "  packs applied: core, fs");
    assert.equal(x.doctor, x.run);
  });

  it("a pack that was not asked for is not listed, core included", async () => {
    const x = await both(cfgFor([toyPath("fs"), "--mode", "good", "--root", "{sandbox}"], "packs: [fs]\n"), ["fs"]);
    assert.equal(x.doctor, "  packs applied: fs");
    assert.equal(x.doctor, x.run);
  });
});

// ---------------------------------------------------------------------------------------------------------
// G6: doctor hints and the cold-cache window
// ---------------------------------------------------------------------------------------------------------

describe("G6: doctor", { timeout: 120_000 }, () => {
  const hint = (stderr: string, usesDsn = false) => diagnoseStartup("the server closed", stderr, { command: "srv", timeoutMs: 10_000, usesDsn }).join("\n");

  it("a server that wants a connection string is told to add --dsn {dsn}", () => {
    for (const s of ["Error: DATABASE_URL is not set", "No database configured", "missing connection string", "pass a database url"]) {
      assert.match(hint(s), /the server may need a database connection string: add --dsn \{dsn\} \(or the env it reads\) under server\.args or server\.env; the db pack fills it/, s);
    }
  });

  it("the hint is not given when the config already uses {dsn}, or when stderr says nothing of the kind", () => {
    assert.doesNotMatch(hint("DATABASE_URL is not set", true), /--dsn/);
    assert.doesNotMatch(hint("segmentation fault"), /--dsn/);
  });

  describe("a cold launcher cache", () => {
    let dir: string;
    let fake: string;
    before(() => {
      dir = mkdtempSync(join(root, "cold-"));
      mkdirSync(join(dir, "sb"));
      // A launcher named npx that does nothing and fails: no network, no package, only the start line is looked at.
      mkdirSync(join(dir, "bin"));
      fake = join(dir, "bin", "npx");
      writeFileSync(fake, "#!/bin/sh\nexit 1\n");
      chmodSync(fake, 0o755);
    });
    const cfg = (): EffectiveConfig => {
      const d = join(dir, `c${n++}`);
      mkdirSync(d);
      writeFileSync(join(d, "sealmark.yaml"), `schema_version: 1\nname: cold\nserver:\n  command: ${q(fake)}\n  args: ["-y", "some-uncached-package"]\nsandbox:\n  dir: ${q(join(dir, "sb"))}\n`);
      return loadEffectiveConfig({ cwd: d, env: {}, isolated: true });
    };
    const start = async (o: object): Promise<string[]> => {
      const lines: string[] = [];
      await runDoctor({ cfg: cfg(), handleSignals: false, log: (l) => lines.push(l), which: () => fake, ...o });
      return lines.filter((l) => /^starting /.test(l));
    };
    const cold = () => ({ name: "some-uncached-package", source: "not found" as const });

    it("waits 60 s and says why when the package is not in the cache", { skip: !POSIX }, async () => {
      const [l] = await start({ resolve: cold });
      assert.match(l, /limit 60 s; some-uncached-package is not in the npx cache yet, so the first start downloads it/);
    });

    it("keeps 10 s when the package is cached, and never overrides an explicit --connect-timeout", { skip: !POSIX }, async () => {
      const [cached] = await start({ resolve: () => ({ name: "p", version: "1.0.0", source: "npx-cache" as const }) });
      assert.match(cached, /limit 10 s\)/);
      const [explicit] = await start({ resolve: cold, startupTimeoutMs: 3000 });
      assert.match(explicit, /limit 3 s\)/);
    });
  });
});
