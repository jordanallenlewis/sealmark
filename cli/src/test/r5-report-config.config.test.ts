import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig, renderShow, standardHash, type EffectiveConfig, type LoadOptions } from "../config/index.js";
import { importManual, type ImportEnv } from "../config/import.js";
import { realPaths, unknownPlaceholders } from "../config/placeholders.js";
import { guessName, packageNameNear, runInit, suggestReplacements, type FileSink } from "../config/wizard.js";
import { describeAllJson } from "../describe.js";
import { buildJsonSchema } from "../config/schema.js";
import { runHarness } from "../run.js";
import type { PackId } from "../types.js";

const HANG = fileURLToPath(new URL("../toy/hang.js", import.meta.url));
const q = JSON.stringify;
const POSIX = process.platform !== "win32";

let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-r5rc-"));
});
after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";
function proj(yaml: string): string {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), yaml);
  return dir;
}
const load = (yaml: string, o: Partial<LoadOptions> = {}): EffectiveConfig => loadEffectiveConfig({ cwd: proj(yaml), isolated: true, env: {}, ...o });
const failure = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return "";
};

// ---------------------------------------------------------------------------------------------------------
// --replay of a run whose custom pack was auto-added
// ---------------------------------------------------------------------------------------------------------

describe("--replay of a report whose custom pack was added automatically", { timeout: 900_000 }, () => {
  let dir: string;
  let parent: string;
  const CHECK = `check: { id: custom-note-acked, label: "A note is acknowledged", critical: false, scope: "server (note tool)" }`;
  const PROBES = `probes:\n  - { id: note-ack, ${CHECK}, tool: note, args: { text: hello }, expect: { text: { matches: "^noted" } } }\n`;
  const file = (): string => {
    const f = join(dir, `c${n++}.yaml`);
    writeFileSync(f, `schema_version: 1\nname: replay-toy\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "iserror"]\nsandbox:\n  dir: ${q(parent)}\n${PROBES}`);
    return f;
  };
  const go = async (replay?: unknown) => {
    const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file() }, env: {}, isolated: true, ...(replay ? { replay: replay as LoadOptions["replay"] } : {}) });
    const r = await runHarness({ config: { name: eff.name, version: eff.version, server: eff.server }, effective: eff, packs: eff.packs as PackId[], packsExplicit: eff.packsExplicit, timeoutProbeSec: 2, log: () => {} });
    return { eff, r };
  };

  before(() => {
    dir = mkdtempSync(join(root, "replay-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });

  it("the replayed run declares custom again, with the probes the user wrote, and reaches the report's hash", async () => {
    // The original run: the default pack list, so custom was added because a check probe was declared.
    const first = await (async () => {
      const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file() }, env: {}, isolated: true });
      assert.equal(eff.packsExplicit, false);
      const r = await runHarness({ config: { name: eff.name, version: eff.version, server: eff.server }, effective: eff, packs: eff.packs as PackId[], packsExplicit: false, timeoutProbeSec: 2, log: () => {} });
      return r;
    })();
    assert.ok(first.packs.custom, "the original run added the custom pack");
    const report = JSON.parse(JSON.stringify(first.config)) as unknown;
    assert.equal(first.config!.standard, false);

    const again = await go(report);
    assert.equal(again.eff.packsExplicit, false, "a replayed pack list is the report's record, not a list the user chose");
    assert.ok(again.r.packs.custom, "custom ran again");
    assert.equal(again.r.config!.hash, first.config!.hash, "the replayed run has the hash the report had");
  });

  it("near miss: a pack list the user wrote is still explicit (custom is not added to it); a replayed list is not", () => {
    assert.equal(load(`${BASE}packs: [core]\n`).packsExplicit, true);
    assert.equal(load(BASE).packsExplicit, false);
    const report = JSON.parse(JSON.stringify(load(BASE).integrity)) as unknown;
    const replayed = load(BASE, { replay: report as LoadOptions["replay"] });
    assert.equal(replayed.packsExplicit, false);
    assert.deepEqual([...replayed.packs].sort(), [...load(BASE).packs].sort(), "the replayed list holds the same packs");
  });
});

// ---------------------------------------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------------------------------------

describe("init offers {sandbox}/repo for a repository argument and rewrites --from paths", () => {
  const env: ImportEnv = { platform: "linux", home: "/home/me", cwd: "/home/me/proj", env: {}, read: () => undefined } as unknown as ImportEnv;
  const spec = (args: string[]) => ({ ...importManual({ name: "git", command: "uvx", args }, env), local: {}, routed: [] as string[] });
  const dirs = { isDir: (p: string) => p === "/home/me/work/repo" || p === "/home/me/data", isFile: () => false };

  it("--repository <dir>, --repo=<dir> and a value after a repository flag become {sandbox}/repo, whatever exists on disk", () => {
    const a = suggestReplacements(spec(["toy-repo-tool", "--repository", "/home/me/work/repo"]), dirs);
    assert.equal(a.length, 1);
    assert.equal(a[0]!.value, "{sandbox}/repo");
    assert.equal(a[0]!.placeholder, "{sandbox}/repo");
    assert.equal(suggestReplacements(spec(["toy-repo-tool", "--repo=/home/me/work/repo"]), dirs)[0]!.value, "--repo={sandbox}/repo");
    assert.equal(suggestReplacements(spec(["toy-repo-tool", "--repository", "/does/not/exist"]), dirs)[0]!.value, "{sandbox}/repo");
    assert.equal(suggestReplacements(spec(["toy-repo-tool", "--repository", "."]), dirs)[0]!.value, "{sandbox}/repo", "a relative repository is a real one too");
  });

  it("near misses: a URL, a placeholder and an ordinary directory argument are not treated as the repository", () => {
    assert.deepEqual(suggestReplacements(spec(["srv", "--repository", "https://example.test/x.git"]), dirs), []);
    assert.deepEqual(suggestReplacements(spec(["srv", "--repository", "{sandbox}/repo"]), dirs), []);
    assert.equal(suggestReplacements(spec(["srv", "--root", "/home/me/data"]), dirs)[0]!.value, "{sandbox}", "a plain directory still gets {sandbox}");
  });

  it("init --from with --yes takes the suggestions: the written config holds no path of this machine", async () => {
    const written = new Map<string, string>();
    const sink: FileSink = { write: (p, c) => void written.set(p, c) };
    const configPath = join("/proj", "sealmark.yaml");
    const out = await runInit({ env, configPath, fromCommand: "uvx toy-repo-tool --repository /home/me/work/repo --data /home/me/data", sink, readText: () => undefined, suggest: dirs });
    const yaml = written.get(configPath)!;
    assert.match(yaml, /--repository/);
    assert.match(yaml, /\{sandbox\}\/repo/);
    assert.equal(yaml.includes("/home/me/work/repo"), false);
    assert.equal(yaml.includes("/home/me/data"), false);
    assert.equal(out.applied.length, 2);
    assert.equal(out.messages.filter((m) => /-> \{sandbox\}/.test(m)).length, 2);
  });

  it("init --from-url is unchanged: a URL has no path to rewrite", async () => {
    const written = new Map<string, string>();
    const out = await runInit({ env, configPath: join("/proj", "sealmark.yaml"), fromUrl: "https://example.test/mcp", sink: { write: (p, c) => void written.set(p, c) }, readText: () => undefined, suggest: dirs });
    assert.deepEqual(out.applied, []);
    assert.match(written.get(join("/proj", "sealmark.yaml"))!, /url: https:\/\/example\.test\/mcp/);
  });
});

describe("init names the server after its package when the program file is index.js", () => {
  it("a generic entry file takes the package name, or the directory when there is no package.json", () => {
    const pkg = (name: string) => (file: string) => (file.includes("/proj/dist/") ? name : undefined);
    assert.equal(guessName("node", ["/srv/proj/dist/index.js"], pkg("@scope/mcp-server-toyweather")), "toyweather");
    assert.equal(guessName("node", ["/srv/proj/dist/index.js"]), "proj");
    assert.equal(guessName("node", ["/srv/weather-mcp/build/main.py"]), "weather");
    assert.equal(guessName("node", ["C:\\x\\dist\\server.js"]), "server", "a specific file name is kept (unchanged)");
    assert.equal(guessName("node", ["index.js"]), "index", "nothing to go on: the file name");
  });

  it("packageNameNear reads the nearest package.json up to four levels and survives a broken one", () => {
    const files: Record<string, string> = { "/a/b/package.json": "{ not json", "/a/package.json": q({ name: "@s/real" }) };
    const read = (p: string) => files[p];
    assert.equal(packageNameNear("/a/b/dist/index.js", read), "@s/real");
    assert.equal(packageNameNear("/z/dist/index.js", read), undefined);
  });
});

// ---------------------------------------------------------------------------------------------------------
// unknown placeholders
// ---------------------------------------------------------------------------------------------------------

describe("a misspelled placeholder is a warning with a did-you-mean", () => {
  it("names the place and the closest known placeholder, and says the server receives the literal text", () => {
    const c = load("schema_version: 1\nserver:\n  command: node\n  args: [srv.js, --db, '{sqlite_pth}']\n");
    assert.ok(c.warnings.includes("unknown placeholder {sqlite_pth} in server.args[2]; did you mean {sqlite_path}? the server will receive the literal text"), c.warnings.join("\n"));
  });

  it("covers command, url, env and headers, a role DSN, and names none when nothing is close", () => {
    const found = unknownPlaceholders({ command: "run-{sandbx}", url: "http://h/{lisetner}", args: ["{dsn:analst}"], env: { K: "{totally_unrelated_word}" }, headers: { H: "{tokn}" } });
    assert.deepEqual(
      found.map((u) => [u.where, u.word, u.suggestion]),
      [
        ["server.command", "sandbx", "sandbox"],
        ["server.url", "lisetner", "listener"],
        ["server.args[0]", "dsn:analst", "dsn:analyst"],
        ["server.env K", "totally_unrelated_word", undefined],
        ["server.headers H", "tokn", "token"],
      ],
    );
  });

  it("known placeholders, ${VAR} references, JSON and shell braces are not reported", () => {
    const quiet = unknownPlaceholders({ command: "node", args: ["{sandbox}/x", "{sqlite_path}", "{dsn}", "{dsn:admin}", "{token}", "{dir}", "${HOME}/x", '{"a": 1}', "{}", "{1,2}", "{a,b}"], env: { P: "{canary}" } });
    assert.deepEqual(quiet, []);
  });

  it("with several servers each warning names its server", () => {
    const c = load("schema_version: 1\nservers:\n  a:\n    command: node\n    args: [srv.js, '{sandbxo}']\n  b:\n    command: node\n    args: [srv.js]\n");
    assert.ok(c.warnings.some((w) => w.startsWith("unknown placeholder {sandbxo} in servers.a.args[1]; did you mean {sandbox}?")), c.warnings.join("\n"));
  });
});

describe("the real-path warning skips a program and an executable file", () => {
  it("the first argument after a node or python launcher is the program, not data", () => {
    assert.deepEqual(realPaths({ command: "node", args: ["--no-warnings", "/opt/srv/bin/run-server", "--root", "/srv/data"] }, () => false).map((r) => r.id), ["args[3]"]);
    assert.deepEqual(realPaths({ command: "/usr/bin/python3", args: ["/opt/srv/serve"] }, () => false), []);
  });

  it("another command keeps the warning for the same path: a near-miss that must still warn", () => {
    assert.deepEqual(realPaths({ command: "my-server", args: ["/opt/srv/bin/run-server"] }, () => false).map((r) => r.id), ["args[0]"]);
  });

  it("an executable file is a program; a data file is not", () => {
    assert.deepEqual(realPaths({ command: "x", args: ["--bin", "/usr/local/bin/helper", "--data", "/srv/store"] }, (p) => p === "/usr/local/bin/helper").map((r) => r.id), ["args[3]"]);
    assert.deepEqual(realPaths({ command: "x", env: { LAUNCHER: "/opt/launch" } }, (p) => p === "/opt/launch"), []);
  });

  it("the default check reads the file system: a real executable file is skipped (POSIX)", { skip: !POSIX }, () => {
    assert.deepEqual(realPaths({ command: "x", args: [process.execPath] }), []);
    assert.equal(realPaths({ command: "x", args: [root] }).length, 1, "a directory is data");
  });
});

// ---------------------------------------------------------------------------------------------------------
// server.rootless and sql_tools[].args
// ---------------------------------------------------------------------------------------------------------

describe("server.rootless", () => {
  it("validates as a boolean, reaches the server spec, and keeps the standard hash and STANDARD label", () => {
    const c = load(`${BASE}  rootless: true\n`);
    assert.equal((c.server as { rootless?: boolean }).rootless, true);
    assert.equal(c.integrity.standard, true);
    assert.equal(c.integrity.hash, standardHash());
    assert.equal("rootless" in (load(BASE).server as object), false, "unset stays unset");
    assert.match(failure(() => load(`${BASE}  rootless: yes-please\n`)), /rootless.*expected true or false/);
  });

  it("is also a key of servers.<name>, and an unknown key under server is still refused", () => {
    const c = load("schema_version: 1\nservers:\n  a:\n    command: node\n    args: [srv.js]\n    rootless: true\n  b:\n    command: node\n    args: [srv.js]\n");
    assert.equal((c.servers[0]!.spec as { rootless?: boolean }).rootless, true);
    assert.equal((c.servers[1]!.spec as { rootless?: boolean }).rootless, undefined);
    assert.match(failure(() => load(`${BASE}  rootles: true\n`)), /unknown key "rootles".*did you mean "rootless"/);
  });

  it("config show prints it when set, describe --json lists it unlocked, and the JSON Schema carries it", () => {
    assert.match(renderShow(load(`${BASE}  rootless: true\n`)), /rootless: true/);
    const key = describeAllJson().configKeys.find((k) => k.path === "server.rootless");
    assert.ok(key);
    assert.equal(key.type, "boolean");
    assert.equal(key.standardLocked, false);
    assert.equal(key.default, false);
    assert.equal(describeAllJson().configKeys.find((k) => k.path === "servers.*.rootless")?.standardLocked, false);
    const props = (buildJsonSchema().properties as Record<string, { properties: Record<string, unknown> }>).server.properties;
    assert.ok("rootless" in props);
  });
});

describe("sql_tools[].args", () => {
  const withArgs = (args: string) => `${BASE}sql_tools:\n  - { tool: run_query, arg: sql, args: ${args} }\n`;

  it("accepts scalars: strings, numbers and booleans, as written", () => {
    const c = load(withArgs("{ database: main, limit: 5, readonly: true }"));
    assert.deepEqual(c.sqlTools, [{ tool: "run_query", arg: "sql", args: { database: "main", limit: 5, readonly: true } }]);
    assert.equal(c.integrity.hash, standardHash(), "unlocked: the hash does not move");
    assert.equal(c.integrity.standard, true);
  });

  it("rejects a list, a mapping and null, and the SQL argument itself", () => {
    assert.match(failure(() => load(withArgs("{ database: [a, b] }"))), /sql_tools\[0\]\.args\.database.*expected a string, a number or true\/false, got a list/);
    assert.match(failure(() => load(withArgs("{ database: { x: 1 } }"))), /expected a string, a number or true\/false, got a mapping/);
    assert.match(failure(() => load(withArgs("{ sql: 'select 1' }"))), /"sql" is the SQL argument the harness fills/);
  });

  it("a misspelled key of the entry is still refused, and describe documents args", () => {
    assert.match(failure(() => load(`${BASE}sql_tools:\n  - { tool: t, arg: sql, arg2: x }\n`)), /unknown key "arg2"/);
    assert.match(describeAllJson().configKeys.find((k) => k.path === "sql_tools")!.description, /args: \{ <parameter>/);
  });

  it("the entry without args is unchanged", () => {
    assert.deepEqual(load(`${BASE}sql_tools:\n  - { tool: t, arg: sql }\n`).sqlTools, [{ tool: "t", arg: "sql" }]);
  });
});
