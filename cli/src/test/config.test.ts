import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { INIT_TEMPLATE, loadConfig } from "../config.js";
import { SCHEMA_FILE, schemaText, standardProfileText } from "../config/gen-schema.js";
import {
  CHECKS,
  ConfigError,
  SCHEMA,
  STANDARD_PACKS,
  checkReplay,
  computeHash,
  describeProfiles,
  displaySpec,
  expand,
  loadEffectiveConfig,
  loadUserProfiles,
  migrateText,
  placeholdersUsed,
  renderShow,
  standardHash,
  userConfigPath,
  usesPlaceholders,
  type EffectiveConfig,
  type LoadOptions,
} from "../config/index.js";
import { displayPath } from "../config/loader.js";
import { LOCKED_LEAVES } from "../config/schema.js";

/** Fixtures are not compiled: resolve them in src/ from dist/test/. */
const FIX = fileURLToPath(new URL("../../src/test/fixtures/config/", import.meta.url));
/** Fixtures are compared as text; a Windows checkout with autocrlf must not matter. */
const lf = (s: string) => s.split("\r\n").join("\n");
const fixture = (name: string) => lf(readFileSync(join(FIX, name), "utf8"));

let root: string;
let counter = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-config-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";

/** A fresh project directory holding the given files. */
function proj(files: Record<string, string>): string {
  const dir = join(root, `p${counter++}`);
  mkdirSync(dir, { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

function load(dir: string, o: Partial<LoadOptions> = {}): EffectiveConfig {
  return loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, ...o });
}

function failure(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `expected a ConfigError, got ${String(e)}`);
    return e.message;
  }
  assert.fail("expected a ConfigError");
}

const plain = (extra = "") => load(proj({ "sealmark.yaml": BASE + extra }));

describe("schema table", () => {
  it("gives every leaf a description, a since and a unique path", () => {
    const seen = new Set<string>();
    for (const l of SCHEMA) {
      assert.ok(l.description.trim().length > 10, `${l.path} needs a description`);
      assert.match(l.since, /^0\.\d+-draft$/, `${l.path} needs a since`);
      assert.ok(!seen.has(l.path), `duplicate path ${l.path}`);
      seen.add(l.path);
    }
  });

  it("locks every threshold, severity, enabled flag and corpus list of every check", () => {
    const locked = new Set(LOCKED_LEAVES.map((l) => l.path));
    for (const c of CHECKS) {
      // A candidate check (shipped advisory ahead of the standard) is deliberately not locked: that is what keeps the standard hash where it is.
      if (c.candidate) continue;
      assert.ok(locked.has(`checks.${c.id}.enabled`), `${c.id}.enabled`);
      assert.ok(locked.has(`checks.${c.id}.severity`), `${c.id}.severity`);
      if (c.corpus) assert.ok(locked.has(`checks.${c.id}.corpus.add`) && locked.has(`checks.${c.id}.corpus.remove`), `${c.id}.corpus`);
    }
  });

  it("leaves a candidate check unlocked, with its two settings and no corpus leaves", () => {
    const locked = new Set(LOCKED_LEAVES.map((l) => l.path));
    const candidates = CHECKS.filter((c) => c.candidate);
    assert.deepEqual(candidates.map((c) => c.id), [
      "db-privilege",
      "refusal-quality",
      "instructions-hygiene",
      "scope-escape",
      "sql-guard-statements",
      "sql-guard-references",
      "sql-guard-rowcap",
      "upstream-credential",
      "upstream-credential-echo",
      "log-secret",
      "upstream-error-leak",
      "upstream-slow",
    ]);
    for (const c of candidates) {
      for (const k of ["enabled", "severity"]) {
        const leaf = SCHEMA.find((l) => l.path === `checks.${c.id}.${k}`);
        assert.ok(leaf, `${c.id}.${k} exists`);
        assert.ok(!leaf.standardLocked && !locked.has(leaf.path), `${c.id}.${k} is not locked`);
      }
      assert.ok(!c.corpus && !SCHEMA.some((l) => l.path.startsWith(`checks.${c.id}.corpus`)), `${c.id} has no corpus leaves`);
    }
  });

  it("keeps the committed JSON Schema and the shipped standard profile in step with the table", () => {
    assert.equal(lf(readFileSync(SCHEMA_FILE, "utf8")), schemaText(), "run npm run build to regenerate cli/schema/sealmark.schema.json");
    const shipped = lf(readFileSync(new URL("../../src/config/profiles/standard.yaml", import.meta.url), "utf8"));
    assert.equal(shipped, standardProfileText(), "run npm run build && npm run gen:standard");
  });

  it("generates a JSON Schema that describes the file layout", () => {
    const s = JSON.parse(schemaText()) as { properties: Record<string, { properties?: Record<string, unknown> }>; additionalProperties: boolean; definitions: { profile: { properties: Record<string, unknown> } } };
    assert.equal(s.additionalProperties, false);
    assert.ok(s.properties.checks.properties?.["db-rowcap"]);
    assert.ok(s.definitions.profile.properties.extends);
    assert.equal("server" in s.definitions.profile.properties, false, "a profile cannot set the server");
  });
});

describe("layers and precedence", () => {
  const USER_YAML = "timeout_probe_sec: 30\n";

  /** One leaf (timeout_probe_sec) set in every layer; `skip` removes layers from the top. */
  function withLayers(skip: readonly string[], profile = true) {
    const has = (k: string) => !skip.includes(k);
    const dir = proj({
      "sealmark.yaml": BASE + (has("project") ? "timeout_probe_sec: 20\n" : ""),
      "sealmark.local.yaml": has("local") ? "timeout_probe_sec: 25\n" : "",
    });
    const userDir = join(root, `user${counter++}`);
    mkdirSync(join(userDir, "sealmark"), { recursive: true });
    if (has("user")) writeFileSync(join(userDir, "sealmark", "config.yaml"), USER_YAML);
    const env: Record<string, string> = { APPDATA: userDir, XDG_CONFIG_HOME: userDir, HOME: userDir, USERPROFILE: userDir };
    if (has("env")) env.SEALMARK_TIMEOUT_PROBE_SEC = "40";
    const flags: Record<string, unknown> = {};
    if (has("flag")) flags["timeout-probe"] = "50";
    if (profile) flags.profile = "quick";
    return loadEffectiveConfig({ cwd: dir, env, flags, isolated: false });
  }

  it("resolves one leaf set at every layer: flag > env > local > project > user > profile > default", () => {
    const expected: [string[], number, string, string][] = [
      [[], 50, "flag", "flag --timeout-probe"],
      [["flag"], 40, "env", "env SEALMARK_TIMEOUT_PROBE_SEC"],
      [["flag", "env"], 25, "local", "sealmark.local.yaml"],
      [["flag", "env", "local"], 20, "project", "sealmark.yaml"],
      [["flag", "env", "local", "project"], 30, "user", "config.yaml"],
      [["flag", "env", "local", "project", "user"], 3, "profile", "profile:quick"],
    ];
    for (const [skip, value, layer, source] of expected) {
      const c = withLayers(skip);
      assert.equal(c.timeoutProbeSec, value, `skip ${skip.join(",") || "nothing"}`);
      const o = c.origins["/timeout_probe_sec"];
      assert.equal(o.layer, layer);
      assert.ok(o.source.endsWith(source) || o.source === source, `${o.source} should end with ${source}`);
    }
    const std = withLayers(["flag", "env", "local", "project", "user"], false);
    assert.equal(std.timeoutProbeSec, 10);
    assert.equal(std.origins["/timeout_probe_sec"].source, "profile:standard");
    assert.deepEqual(std.origins["/sandbox/keep"], { layer: "default", source: "default" });
  });

  it("records file and line for file-sourced values", () => {
    const c = withLayers(["flag", "env"]);
    assert.equal(c.origins["/timeout_probe_sec"].line, 1);
    const p = withLayers(["flag", "env", "local"]);
    assert.equal(p.origins["/timeout_probe_sec"].line, 5);
  });

  it("finds the user file at %APPDATA%\\sealmark\\config.yaml and ~/.config/sealmark/config.yaml", () => {
    assert.equal(userConfigPath({ APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, "win32", "C:\\Users\\a"), "C:\\Users\\a\\AppData\\Roaming\\sealmark\\config.yaml");
    assert.equal(userConfigPath({}, "win32", "C:\\Users\\a"), "C:\\Users\\a\\AppData\\Roaming\\sealmark\\config.yaml");
    assert.equal(userConfigPath({ XDG_CONFIG_HOME: "/x/cfg" }, "linux", "/home/a"), "/x/cfg/sealmark/config.yaml");
    assert.equal(userConfigPath({}, "linux", "/home/a"), "/home/a/.config/sealmark/config.yaml");
    assert.equal(userConfigPath({ SEALMARK_USER_CONFIG: "none" }, "win32", "C:\\Users\\a"), undefined);
    assert.equal(userConfigPath({ SEALMARK_USER_CONFIG: "D:\\mine.yaml" }, "win32", "C:\\Users\\a"), "D:\\mine.yaml");
  });

  it("never reads the real environment: only the env passed in decides", () => {
    const dir = proj({ "sealmark.yaml": BASE });
    const c = loadEffectiveConfig({ cwd: dir, env: { SEALMARK_USER_CONFIG: "none" }, isolated: false });
    assert.deepEqual(c.files, [join(dir, "sealmark.yaml")]);
  });

  it("applies list-vs-mergeable semantics", () => {
    const dir = proj({
      "sealmark.yaml": `${BASE}packs: [core, fs]\ntools:\n  exclude: [admin_*]\n`,
      "sealmark.local.yaml": "packs: [core]\ntools:\n  exclude: [debug_*, admin_*]\n",
    });
    const c = load(dir, { env: { SEALMARK_TOOLS__EXCLUDE: "extra_*" } });
    assert.deepEqual(c.packs, ["core"], "packs is a plain list: the higher layer replaces it");
    assert.deepEqual(c.tools.exclude, ["admin_*", "debug_*", "extra_*"], "tools.exclude is mergeable: appended and de-duplicated across layers");
    assert.deepEqual(c.tools.include, ["*"]);
    const narrowed = load(proj({ "sealmark.yaml": `${BASE}tools:
  include: [read_*]
` }));
    assert.deepEqual(narrowed.tools.include, ["read_*"], "include replaces its catch-all default instead of appending to it");
    assert.equal(narrowed.integrity.standard, false);
    assert.deepEqual(c.server.args, ["srv.js"]);
  });

  it("appends corpus add and remove across layers", () => {
    const dir = proj({
      "sealmark.yaml": `${BASE}checks:\n  net-loopback-ssrf:\n    corpus:\n      add: ["http://127.0.0.2:{port}/t/{token}"]\n      remove: ["0.0.0.0"]\n`,
      "sealmark.local.yaml": `checks:\n  net-loopback-ssrf:\n    corpus:\n      add: ["http://localhost:{port}/x/{token}"]\n      remove: ["127.1"]\n`,
    });
    const c = load(dir);
    assert.deepEqual(c.checks["net-loopback-ssrf"].corpus, { add: ["http://127.0.0.2:{port}/t/{token}", "http://localhost:{port}/x/{token}"], remove: ["0.0.0.0", "127.1"] });
  });

  it("lets null delete a key: scalars fall back to the built-in default, map entries disappear", () => {
    const dir = proj({
      "sealmark.yaml": `${BASE.replace("  args: [srv.js]\n", "  args: [srv.js]\n  env: { A: 1, B: 2 }\n")}checks:\n  db-rowcap: { row_cap: 5 }\n`,
      "sealmark.local.yaml": "server:\n  env: { B: null, C: 3 }\nchecks:\n  db-rowcap: { row_cap: null }\n",
    });
    const c = load(dir);
    assert.equal(c.checks["db-rowcap"].row_cap, 10000);
    assert.equal(c.origins["/checks/db-rowcap/row_cap"].source, "default", "null clears everything below it, profile included");
    assert.deepEqual(c.server.env, { A: "1", C: "3" });
    assert.equal("/server/env/B" in c.origins, false);
  });

  it("merges maps key-wise across layers", () => {
    const dir = proj({
      "sealmark.yaml": `${BASE}tools:\n  overrides:\n    read_it: { class: path, params: { path: file } }\n`,
      "sealmark.local.yaml": "tools:\n  overrides:\n    legacy: { class: opaque }\n    read_it: { params: { content: body } }\n".replace("{ params: { content: body } }", "{ class: path, params: { content: body } }"),
    });
    const c = load(dir);
    assert.deepEqual(c.tools.overrides, { read_it: { class: "path", params: { path: "file", content: "body" } }, legacy: { class: "opaque" } });
  });
});

describe("environment variables", () => {
  const dir = () => proj({ "sealmark.yaml": BASE });

  it("maps SEALMARK_A__B onto the schema and types the value", () => {
    const c = load(dir(), {
      env: {
        SEALMARK_PACKS: "core,fs",
        SEALMARK_SANDBOX__DIR: "D:\\tmp\\sm",
        SEALMARK_CHECKS__DB_ROWCAP__ROW_CAP: "250",
        SEALMARK_NET__ALLOW_DNS: "yes",
        SEALMARK_SERVER__ENV__FOO: "bar",
        SEALMARK_CANARY: "ignored: the harness's own canary",
      },
    });
    assert.deepEqual(c.packs, ["core", "fs"]);
    assert.equal(c.sandbox.dir, "D:\\tmp\\sm");
    assert.equal(c.checks["db-rowcap"].row_cap, 250);
    assert.equal(c.net.allow_dns, true);
    assert.equal(c.server.env?.FOO, "bar");
    assert.deepEqual(c.origins["/checks/db-rowcap/row_cap"], { layer: "env", source: "env SEALMARK_CHECKS__DB_ROWCAP__ROW_CAP" });
  });

  it("names the env variable in a typing error, with the same wording as a YAML error", () => {
    const m = failure(() => load(dir(), { env: { SEALMARK_CHECKS__CAP_TIMEOUT__TIMEOUT_SEC: "abc" } }));
    assert.match(m, /^env SEALMARK_CHECKS__CAP_TIMEOUT__TIMEOUT_SEC: expected a number, got string "abc"/);
    const y = failure(() => load(proj({ "sealmark.yaml": `${BASE}timeout_probe_sec: abc\n` })));
    assert.match(y, /sealmark\.yaml:5: timeout_probe_sec: expected a number, got string "abc"/);
    assert.match(failure(() => load(dir(), { env: { SEALMARK_SANDBOX__KEEP: "maybe" } })), /^env SEALMARK_SANDBOX__KEEP: expected true or false, got string "maybe"/);
    assert.match(failure(() => load(dir(), { env: { SEALMARK_CHECKS__DB_ROWCAP__ROW_CAP: "0" } })), /must be at least 1, got 0/);
  });

  it("rejects unknown names with a did-you-mean and sections used as settings", () => {
    assert.match(failure(() => load(dir(), { env: { SEALMARK_PAKCS: "core" } })), /^env SEALMARK_PAKCS: unknown setting "pakcs"; did you mean SEALMARK_PACKS\?/);
    assert.match(failure(() => load(dir(), { env: { SEALMARK_SANDBOX: "x" } })), /sandbox is a section, not a setting/);
    assert.match(failure(() => load(dir(), { env: { SEALMARK_SANDBOX__DIR__X: "x" } })), /sandbox\.dir is a single setting/);
  });

  it("never lets files or environment set the safety flags", () => {
    assert.match(failure(() => load(dir(), { env: { SEALMARK_ACTIVE: "1" } })), /^env SEALMARK_ACTIVE: active can only be set with --active on the command line/);
    assert.match(failure(() => load(dir(), { env: { SEALMARK_YES: "true" } })), /yes can only be set with --yes/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${BASE}active: true\n` }))), /sealmark\.yaml:5: active can only be set with --active on the command line/);
    assert.equal(load(dir(), { flags: { active: true, yes: true } }).active, true);
    assert.equal(load(dir()).active, false);
  });

  it("lets null in the environment reset a setting", () => {
    const d = proj({ "sealmark.yaml": `${BASE}timeout_probe_sec: 20\n` });
    assert.equal(load(d, { env: { SEALMARK_TIMEOUT_PROBE_SEC: "null" } }).timeoutProbeSec, 10);
  });
});

describe("flags", () => {
  const d = () => proj({ "sealmark.yaml": BASE });

  it("maps flags 1:1 onto schema paths", () => {
    const c = load(d(), {
      flags: { pack: ["core", "db"], "timeout-probe": "2", "fail-under": "b", format: "json", out: "r.json", "connect-timeout": "5", embedded: false, pg: "postgres://u:p@h/postgres", yes: true, "no-sandbox": true, "keep-sandbox": true, "sandbox-dir": "X:\\s", "pack-timeout": "30" },
    });
    assert.deepEqual(c.packs, ["core", "db"]);
    assert.equal(c.packsExplicit, true);
    assert.equal(c.timeoutProbeSec, 2);
    assert.equal(c.hangMs, 2000);
    assert.equal(c.output.exit_policy.fail_under, "B");
    assert.deepEqual(c.output.formats, ["json"]);
    assert.equal(c.output.out, "r.json");
    assert.equal(c.timeouts.connect_ms, 5000);
    assert.equal(c.db.embedded, false);
    assert.equal(c.db.pg, "postgres://u:p@h/postgres");
    assert.equal(c.sandbox.enabled, false);
    assert.equal(c.sandbox.keep, true);
    assert.equal(c.sandbox.dir, "X:\\s");
    assert.equal(c.sandbox.pack_timeout_sec, 30);
    assert.equal(c.origins["/output/formats"].source, "flag --format");
    assert.equal(load(d(), { flags: { sandbox: false } }).sandbox.enabled, false);
  });

  it("--url, --start, --header, --start-timeout, --name and --soft-fail describe the server with no config file", () => {
    const empty = proj({});
    const c = load(empty, {
      flags: { url: "http://localhost:8000/mcp", start: 'my-server --port 8000 "two words"', header: ["Authorization: Bearer t", "X-Team:demo"], "start-timeout": "7", name: "svc", "soft-fail": true },
    });
    assert.equal(c.server.url, "http://localhost:8000/mcp");
    assert.equal(c.server.command, "my-server");
    assert.deepEqual(c.server.args, ["--port", "8000", "two words"]);
    assert.deepEqual(c.server.headers, { Authorization: "Bearer t", "X-Team": "demo" });
    assert.equal(c.server.start_timeout_sec, 7);
    assert.equal(c.name, "svc");
    assert.equal(c.output.exit_policy.soft_fail, true);
    assert.equal(c.origins["/server/url"].source, "flag --url");
    assert.match(failure(() => load(empty, { flags: { url: "http://x", header: ["nocolon"] } })), /^--header: expected "Name: value", got "nocolon"/);
    assert.match(failure(() => load(empty, { flags: { start: 'npx "oops' } })), /--start/);
    assert.match(failure(() => load(empty)), /^No server is configured\. Name it on the command line, no file needed:\n {2}sealmark run --url [^]*\nor run "sealmark init" to write a sealmark\.yaml\.$/);
  });

  it("CI=true selects the ci profile unless one is chosen; a laptop gets standard", () => {
    const d = proj({ "sealmark.yaml": BASE });
    assert.equal(load(d, { env: { CI: "true" } }).profile, "ci");
    assert.equal(load(d, { env: { CI: "1" } }).profile, "ci");
    assert.equal(load(d, { env: {} }).profile, "standard");
    assert.equal(load(d, { env: { CI: "false" } }).profile, "standard");
    assert.equal(load(d, { env: { CI: "true" }, flags: { profile: "standard" } }).profile, "standard");
    assert.equal(load(proj({ "sealmark.yaml": `${BASE}profile: strict\n` }), { env: { CI: "true" } }).profile, "strict");
    assert.deepEqual(load(d, { env: { CI: "true" } }).output.formats, ["summary", "junit", "json"]);
  });

  it("shows a config path relative to the cwd even when the cwd is reached through a symlink (macOS /var -> /private/var)", { skip: process.platform === "win32" }, () => {
    const real = proj({ "sealmark.yaml": BASE });
    const alias = `${real}-alias`;
    symlinkSync(real, alias);
    assert.equal(displayPath(join(alias, "sealmark.yaml"), real), "sealmark.yaml");
    assert.equal(displayPath(join(real, "sealmark.yaml"), alias), "sealmark.yaml");
    assert.equal(displayPath(join(alias, "not-yet.yaml"), real), "not-yet.yaml", "a file that does not exist yet");
    assert.equal(displayPath("/elsewhere/x.yaml", real), "/elsewhere/x.yaml");
  });

  it("command + url must be set in the same place: a url from another layer never turns a stdio server into a launch", () => {
    const stdio = proj({ "sealmark.yaml": "name: x\nserver: { command: my-server, args: ['{sandbox}'] }\n" });
    assert.match(failure(() => load(stdio, { flags: { url: "http://localhost:8000/mcp" } })), /server\.command \(from sealmark\.yaml:\d+\) and server\.url \(from flag --url\) are set in different places/);
    assert.match(failure(() => load(stdio, { env: { SEALMARK_SERVER__URL: "http://localhost:8000/mcp" } })), /server\.url \(from env SEALMARK_SERVER__URL\) are set in different places/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": "name: x\nserver: { command: my-server }\n", "sealmark.local.yaml": "server: { url: http://localhost:8000/mcp }\n" }))), /set in different places/);
    // the same place is fine: both in one file, or --start and --url together on the command line
    const both = load(proj({ "sealmark.yaml": "name: x\nserver: { command: my-server, url: 'http://localhost:8000/mcp' }\n" }));
    assert.equal(both.server.url, "http://localhost:8000/mcp");
    const flags = load(proj({}), { flags: { start: "my-server --port 8000", url: "http://localhost:8000/mcp" } });
    assert.deepEqual([flags.server.command, flags.server.url], ["my-server", "http://localhost:8000/mcp"]);
    const envBoth = load(proj({}), { env: { SEALMARK_SERVER__COMMAND: "my-server", SEALMARK_SERVER__URL: "http://localhost:8000/mcp" } });
    assert.equal(envBoth.server.command, "my-server");
  });

  it("server.url must be an http(s) URL (a bare host:port would wait for the timeout and then blame the start-up time)", () => {
    assert.match(failure(() => load(proj({}), { flags: { url: "localhost:8000/mcp" } })), /server\.url must start with http:\/\/ or https:\/\/ \(got "localhost:8000\/mcp"\)/);
    assert.equal(load(proj({}), { flags: { url: "${BASE_URL}/mcp" }, env: { BASE_URL: "http://localhost:8000" } }).server.url, "${BASE_URL}/mcp", "a placeholder is allowed to supply the scheme");
  });

  it("a relative --start command is relative to where it was typed, not to the config file", () => {
    const d = proj({ "sealmark.yaml": BASE });
    const c = load(d, { flags: { start: "./bin/server --x", url: "http://localhost:1/mcp" } });
    assert.equal(c.server.command, join(resolve(d), "bin", "server").split("\\").join("/"));
  });

  it("CI=true does not switch profiles for someone who asked for a specific output or gate", () => {
    const d = proj({ "sealmark.yaml": BASE });
    for (const flags of [{ out: "r.txt" }, { format: "json" }, { "out-dir": "o" }]) assert.equal(load(d, { env: { CI: "true" }, flags }).profile, "standard", JSON.stringify(flags));
    // A gate flag does not change the output, so it must not switch off the log summary and the report files.
    for (const flags of [{ "fail-under": "C" }, { "fail-under": "A" }, { "soft-fail": true }]) assert.equal(load(d, { env: { CI: "true" }, flags }).profile, "ci", JSON.stringify(flags));
    assert.equal(load(d, { env: { CI: "true" } }).profile, "ci");
  });

  it("reports bad flag values by flag name", () => {
    assert.match(failure(() => load(d(), { flags: { "timeout-probe": "abc" } })), /^--timeout-probe: expected a number, got string "abc"/);
    assert.match(failure(() => load(d(), { flags: { "timeout-probe": "0" } })), /^--timeout-probe: must be greater than 0, got 0/);
    assert.match(failure(() => load(d(), { flags: { "fail-under": "Z" } })), /^--fail-under: expected one of A, B, C, D, F/);
    assert.match(failure(() => load(d(), { flags: { format: "xml" } })), /^--format: expected one of text, json/);
    assert.match(failure(() => load(d(), { flags: { pack: ["web"] } })), /^--pack: unknown pack "web" \(use core, db, sqlite, fs, net, git, exec, http, effects, custom, scope, sql-guard, upstream\)/);
  });

  it("reads the project file named by --config", () => {
    const dir = proj({ "other.yaml": `${BASE}name: other\n` });
    assert.equal(load(dir, { flags: { config: "other.yaml" } }).name, "other");
    assert.match(failure(() => load(dir, { flags: { config: "nope.yaml" } })), /Cannot read nope\.yaml\. Run "sealmark init"/);
  });
});

describe("strict validation", () => {
  it("reports unknown keys with did-you-mean and file:line, and collects every error", () => {
    const dir = proj({ "typo.yaml": fixture("typo.yaml") });
    const m = failure(() => load(dir, { flags: { config: "typo.yaml" } }));
    const lines = m.split("\n");
    assert.equal(lines.length, 3, m);
    assert.equal(lines[0], 'typo.yaml:9: unknown key "timout_sec" under checks.cap-timeout; did you mean "timeout_sec"?');
    assert.equal(lines[1], 'typo.yaml:11: unknown key "keepp" under sandbox; did you mean "keep"?');
    assert.match(lines[2], /^typo\.yaml:12: sandbox\.max_mib: expected an integer, got string "lots"/);
  });

  it("flags unknown top-level keys and wrong container types", () => {
    assert.match(failure(() => plain("pakcs: [core]\n")), /sealmark\.yaml:5: unknown key "pakcs"; did you mean "packs"\?/);
    assert.match(failure(() => plain("sandbox: yes please\n")), /sealmark\.yaml:5: sandbox: expected a mapping, got string "yes please"/);
    assert.match(failure(() => plain("checks:\n  rls:\n    enabled: 1\n")), /sealmark\.yaml:7: checks\.rls\.enabled: expected true or false, got number 1/);
    assert.match(failure(() => plain("checks:\n  rlz: { enabled: false }\n")), /unknown key "rlz" under checks; did you mean "rls"\?/);
  });

  it("reports YAML syntax errors with a line", () => {
    assert.match(failure(() => load(proj({ "sealmark.yaml": "server: [unclosed\n" }))), /^sealmark\.yaml:\d+: /);
    assert.match(failure(() => load(proj({ "sealmark.yaml": "a: 1\na: 2\n" }))), /sealmark\.yaml:2: .*unique/i);
  });

  it("keeps the 0.1 messages for the original keys", () => {
    const e = (yaml: string) => failure(() => load(proj({ "sealmark.yaml": yaml })));
    assert.match(e("name: x\n"), /"server" is required \(command \+ args, or url\)/);
    assert.match(e("server: {}\n"), /server needs "command" \(stdio\) or "url" \(HTTP\)/);
    // command + url is allowed since 0.1.3: Sealmark starts the command and waits for the url.
    const both = load(proj({ "sealmark.yaml": "name: x\nserver: { command: a, url: http://x, start_timeout_sec: 5 }\n" }));
    assert.deepEqual([both.server.command, both.server.url, both.server.start_timeout_sec], ["a", "http://x", 5]);
    assert.match(e("server: { command: a, args: nope }\n"), /server\.args: expected a list/);
    assert.match(e("server: { command: a, env: [x] }\n"), /server\.env: expected a mapping/);
    assert.match(e(`${BASE}packs: [core, web]\n`), /packs\[1\]: unknown pack "web" \(use core, db,/);
    assert.match(e("\n"), /sealmark\.yaml is empty\./);
    assert.match(e("server: { command: a, args: ['{dsn:nobody}'] }\n"), /unknown role in \{dsn:nobody\} \(use analyst, support, admin\)/);
    assert.match(failure(() => load(proj({}))), /^No server is configured\./);
  });

  it("coerces numbers in env, args and version the way 0.1 did", () => {
    const c = load(proj({ "sealmark.yaml": "schema_version: 1\nversion: 1.0\nserver: { command: a, args: [1, two], env: { PORT: 3000 } }\n" }));
    assert.equal(c.version, "1");
    assert.deepEqual(c.server.args, ["1", "two"]);
    assert.deepEqual(c.server.env, { PORT: "3000" });
  });
});

describe("schema version and migrations", () => {
  it("refuses a newer schema_version and tells the user to upgrade", () => {
    const m = failure(() => load(proj({ "sealmark.yaml": "schema_version: 2\nserver: { command: a }\n" })));
    assert.match(m, /sealmark\.yaml:1: schema_version 2 is newer than this sealmark understands \(1\); upgrade sealmark/);
    assert.throws(() => migrateText("schema_version: 2\nserver: { command: a }\n"), /upgrade sealmark/);
  });

  it("warns, but loads, when schema_version is missing", () => {
    const c = load(proj({ "sealmark.yaml": "server: { command: a }\n" }));
    assert.equal(c.schemaVersion, 1);
    assert.equal(c.warnings.length, 1);
    assert.match(c.warnings[0], /sealmark\.yaml: no schema_version; reading it as 1/);
  });

  it("points an older file at sealmark config migrate", () => {
    assert.match(failure(() => load(proj({ "sealmark.yaml": fixture("v0.yaml") }))), /schema_version 0 is older than 1; run "sealmark config migrate sealmark\.yaml"/);
  });

  it("migrates the v0 fixture to the expected v1 YAML, and the result loads cleanly", () => {
    const r = migrateText(fixture("v0.yaml"), "v0.yaml");
    assert.equal(r.from, 0);
    assert.equal(r.to, 1);
    assert.equal(r.text, fixture("v0.expected.yaml"));
    assert.match(r.diff, /-\d+: timeout_probe: 5/);
    assert.match(r.diff, /\+\d+: timeout_probe_sec: 5/);
    const c = load(proj({ "sealmark.yaml": r.text }));
    assert.equal(c.timeoutProbeSec, 5);
    assert.equal(c.output.exit_policy.fail_under, "B");
    assert.equal(c.output.format, "json");
    assert.equal(c.checks["db-timeout"].expected_sec, 7);
    assert.equal(c.checks["db-rowcap"].row_cap, 500);
    assert.deepEqual(c.warnings, []);
    assert.equal(migrateText(r.text).changed, false, "migrating a current file changes nothing");
  });

  it("adds schema_version to a file that lacks it", () => {
    const r = migrateText("# mine\nserver: { command: a }\n");
    assert.equal(r.text, "schema_version: 1\n# mine\nserver: {command: a}\n");
  });

  it("keeps the deprecated cap-timeout name working with a warning", () => {
    const c = plain("checks:\n  cap-timeout:\n    row_cap: 7\n    timeout_sec: 3\n    enabled: false\n");
    assert.equal(c.checks["db-rowcap"].row_cap, 7);
    assert.equal(c.checks["db-timeout"].expected_sec, 3);
    assert.equal(c.checks["db-rowcap"].enabled, false);
    assert.equal(c.checks["db-timeout"].enabled, false);
    assert.equal(c.warnings.filter((w) => /cap-timeout\.\w+ is deprecated/.test(w)).length, 3);
    assert.equal(c.origins["/checks/db-rowcap/row_cap"].line, 7);
  });
});

describe("profiles", () => {
  const golden = JSON.parse(fixture("profiles.golden.json")) as Record<string, { standard: boolean; diff: unknown[]; reasons: string[] }>;

  it("matches the golden diff against standard for every shipped profile", () => {
    const got = Object.fromEntries(describeProfiles().map((p) => [p.name, { standard: p.standard, diff: p.diff, reasons: p.reasons.map((r) => r.path) }]));
    assert.deepEqual(got, golden);
  });

  it("calls standard and ci STANDARD and quick, strict, paranoid CUSTOM", () => {
    assert.deepEqual(Object.fromEntries(Object.entries(golden).map(([k, v]) => [k, v.standard])), { standard: true, quick: false, ci: true, strict: false, paranoid: false });
    for (const [name, std] of [["standard", true], ["quick", false], ["ci", true], ["strict", false], ["paranoid", false]] as const) {
      const c = load(proj({ "sealmark.yaml": BASE }), { flags: { profile: name } });
      assert.equal(c.integrity.standard, std, name);
      assert.equal(c.profile, name);
    }
  });

  it("applies the quick profile's settings and keeps exec off the standard pack list", () => {
    const c = load(proj({ "sealmark.yaml": BASE }), { flags: { profile: "quick" } });
    assert.deepEqual(c.packs, ["core", "fs", "net", "http"]);
    assert.equal(c.packsExplicit, true);
    assert.equal(c.timeoutProbeSec, 3);
    assert.equal(c.checks["db-rowcap"].enabled, false);
    assert.equal(c.checks["fs-size-cap"].enabled, false);
    assert.equal(STANDARD_PACKS.includes("exec"), false);
  });

  it("resolves user profiles with extends, in a file or the user file", () => {
    const yaml = `${BASE}profile: team\nprofiles:\n  base:\n    checks:\n      db-rowcap: { row_cap: 20000 }\n  team:\n    extends: base\n    timeout_probe_sec: 4\n  tidy:\n    extends: ci\n`;
    const c = load(proj({ "sealmark.yaml": yaml }));
    assert.deepEqual(c.profileChain, ["standard", "base", "team"]);
    assert.equal(c.checks["db-rowcap"].row_cap, 20000);
    assert.equal(c.timeoutProbeSec, 4);
    assert.equal(c.integrity.standard, false);
    assert.equal(c.origins["/timeout_probe_sec"].source, "profile:team");
    const tidy = load(proj({ "sealmark.yaml": yaml }), { flags: { profile: "tidy" } });
    assert.equal(tidy.integrity.standard, true, "a user profile on top of ci changes nothing locked");
    assert.deepEqual(tidy.output.formats, ["summary", "junit", "json"], "what ci sets is inherited");
    assert.equal(tidy.output.exit_policy.fail_under, "A", "ci sets no gate of its own; the default A applies");
    const listed = describeProfiles(loadUserProfiles({ cwd: proj({ "sealmark.yaml": yaml }), isolated: true, env: {} }));
    assert.deepEqual(listed.map((p) => p.name), ["standard", "quick", "ci", "strict", "paranoid", "base", "team", "tidy"]);
    assert.equal(listed.find((p) => p.name === "team")?.standard, false);
  });

  it("rejects cycles, unknown profiles, shipped names, and project keys inside a profile", () => {
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${BASE}profile: a\nprofiles:\n  a: { extends: b }\n  b: { extends: a }\n` }))), /profile cycle: a -> b -> a/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": BASE }), { flags: { profile: "quik" } })), /unknown profile "quik".*did you mean "quick"\?/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${BASE}profiles:\n  quick: { packs: [core] }\n` }))), /profile "quick" is a shipped profile and cannot be redefined/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${BASE}profiles:\n  p:\n    server: { command: x }\n` }))), /sealmark\.yaml:7: "server" cannot be set inside a profile/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${BASE}profiles:\n  p:\n    timout_probe_sec: 3\n` }))), /sealmark\.yaml:7: unknown key "timout_probe_sec" under profiles\.p; did you mean "timeout_probe_sec"\?/);
  });
});

describe("integrity: STANDARD vs CUSTOM", () => {
  const std = (extra = "", o: Partial<LoadOptions> = {}) => load(proj({ "sealmark.yaml": BASE + extra }), o);

  it("is STANDARD for a plain run, with no differences", () => {
    const c = plain();
    assert.equal(c.integrity.standard, true);
    assert.deepEqual(c.integrity.standardDiff, []);
    assert.equal(c.integrity.methodology, "0.3-draft");
    assert.equal(c.integrity.profile, "standard");
    assert.equal(c.packsExplicit, false);
  });

  it("stays STANDARD with --active, extra packs, probes without a check, other output and a different server", () => {
    assert.equal(std("", { flags: { active: true } }).integrity.standard, true);
    assert.equal(std("", { flags: { active: true } }).active, true);
    assert.equal(std(`packs: [${[...STANDARD_PACKS, "exec", "custom"].join(", ")}]\n`).integrity.standard, true);
    assert.equal(std("probes:\n  - tool: echo\n    args: { text: '{token}' }\n").integrity.standard, true);
    assert.equal(std("output: { format: json, verbosity: verbose }\nsandbox: { keep: true, dir: 'D:\\\\tmp' }\ntimeouts: { connect_ms: 120000 }\n").integrity.standard, true);
    assert.equal(std("", { flags: { profile: "ci" } }).integrity.standard, true);
  });

  const triggers: { name: string; yaml?: string; flags?: Record<string, unknown>; env?: Record<string, string>; path: string }[] = [
    { name: "a threshold is loosened", yaml: "checks:\n  db-rowcap: { row_cap: 20000 }\n", path: "checks.db-rowcap.row_cap" },
    { name: "the probe wait is changed", yaml: "timeout_probe_sec: 20\n", path: "timeout_probe_sec" },
    { name: "fs-size-cap pass_mib is raised", yaml: "checks:\n  fs-size-cap: { pass_mib: 32 }\n", path: "checks.fs-size-cap.pass_mib" },
    { name: "a corpus entry is removed", yaml: "checks:\n  net-loopback-ssrf:\n    corpus: { remove: ['0.0.0.0'] }\n", path: "checks.net-loopback-ssrf.corpus.remove" },
    { name: "a corpus case is added", yaml: "checks:\n  mutating-sql:\n    corpus:\n      add: [{ id: my-case, steps: ['SELECT my_fn()'], executed: 'probe_row:9200' }]\n", path: "checks.mutating-sql.corpus.add" },
    { name: "a check is disabled", yaml: "checks:\n  rls: { enabled: false }\n", path: "checks.rls.enabled" },
    { name: "a severity is changed", yaml: "checks:\n  pii: { severity: advisory }\n", path: "checks.pii.severity" },
    { name: "a custom check is written", yaml: "probes:\n  - id: p1\n    check: { id: custom-p1, label: P1, scope: 'server (x)' }\n    tool: t\n", path: "probes" },
    { name: "a plugin is declared", yaml: "plugins:\n  - module: ./checks/s3.mjs\n", path: "plugins" },
    { name: "--no-sandbox", flags: { sandbox: false }, path: "sandbox.enabled" },
    { name: "the environment is not scrubbed", yaml: "sandbox: { scrub_env: false }\n", path: "sandbox.scrub_env" },
    { name: "the quick profile", flags: { profile: "quick" }, path: "profile" },
    { name: "the strict profile", flags: { profile: "strict" }, path: "profile" },
    { name: "the paranoid profile", flags: { profile: "paranoid" }, path: "net.allow_dns" },
    { name: "tools are excluded", yaml: "tools: { exclude: [admin_*] }\n", path: "tools.exclude" },
    { name: "a classifier override is set", yaml: "tools:\n  overrides:\n    legacy: { class: opaque }\n", path: "tools.overrides" },
    { name: "a standard pack is dropped", flags: { pack: ["core", "db"] }, path: "packs" },
    { name: "a control URL is given", env: { SEALMARK_NET__CONTROL_URL: "http://127.0.0.1:9/ok" }, path: "net.control_url" },
  ];
  for (const t of triggers) {
    it(`is CUSTOM when ${t.name}`, () => {
      const c = std(t.yaml ?? "", { flags: t.flags, env: t.env });
      assert.equal(c.integrity.standard, false);
      assert.ok(c.integrity.standardDiff.some((d) => d.path === t.path), `${t.path} in ${JSON.stringify(c.integrity.standardDiff.map((d) => d.path))}`);
      for (const d of c.integrity.standardDiff) assert.ok(d.origin.length > 0);
    });
  }

  it("says where a difference came from", () => {
    const c = std("checks:\n  db-rowcap: { row_cap: 20000 }\n", { env: { SEALMARK_TIMEOUT_PROBE_SEC: "20" } });
    const origins = Object.fromEntries(c.integrity.standardDiff.map((d) => [d.path, d.origin]));
    assert.equal(origins["checks.db-rowcap.row_cap"], "sealmark.yaml:6");
    assert.equal(origins.timeout_probe_sec, "env SEALMARK_TIMEOUT_PROBE_SEC");
  });

  it("gives the same hash for every standard run, whatever the server command", () => {
    const a = load(proj({ "sealmark.yaml": BASE }));
    const b = load(proj({ "sealmark.yaml": "schema_version: 1\nname: other\nserver:\n  url: http://localhost:8000/mcp\n  headers: { Authorization: x }\n" }));
    const c = load(proj({ "sealmark.yaml": BASE }), { flags: { active: true, profile: "ci", "keep-sandbox": true } });
    const d = load(proj({ "sealmark.yaml": BASE + `packs: [${[...STANDARD_PACKS, "exec"].join(", ")}]\n` }));
    assert.equal(a.integrity.hash, b.integrity.hash);
    assert.equal(a.integrity.hash, c.integrity.hash);
    assert.equal(a.integrity.hash, d.integrity.hash, "adding a pack does not change the standard hash");
    assert.equal(a.integrity.hash, standardHash());
    assert.notEqual(std("timeout_probe_sec: 20\n").integrity.hash, a.integrity.hash);
    assert.notEqual(std("", { flags: { pack: ["core", "fs"] } }).integrity.hash, a.integrity.hash);
  });

  it("pins the standard hash for methodology 0.3-draft (update standard.hash.txt only with a methodology change)", () => {
    assert.equal(standardHash(), fixture("standard.hash.txt").trim());
  });

  it("a plain STANDARD run carries the pinned hash, and the hash recomputes from the embedded locked leaves", () => {
    const c = plain();
    assert.equal(c.integrity.hash, fixture("standard.hash.txt").trim());
    assert.equal(computeHash(c.integrity.locked, "0.3-draft"), fixture("standard.hash.txt").trim());
    assert.notEqual(computeHash(c.integrity.locked, "0.2-draft"), c.integrity.hash, "the methodology string is part of the digest");
  });

  it("embeds the full locked subset so a third party can reproduce the run", () => {
    const c = plain();
    assert.equal(c.integrity.locked["checks.db-rowcap.row_cap"], 10000);
    assert.deepEqual(c.integrity.locked.packs, [...STANDARD_PACKS].sort());
    assert.equal(computeHash(c.integrity.locked), c.integrity.hash);
    assert.equal(Object.keys(c.integrity.locked).some((k) => k.startsWith("server")), false, "the server command is not a locked leaf");
  });

  it("replays a report: the same locked leaves reproduce the same hash", () => {
    const original = std("timeout_probe_sec: 20\nchecks:\n  db-rowcap: { row_cap: 50 }\n");
    assert.equal(original.integrity.standard, false);
    const dir = proj({ "sealmark.yaml": BASE.replace("srv.js", "different.js") });
    const replayed = load(dir, { replay: original.integrity });
    assert.equal(replayed.timeoutProbeSec, 20);
    assert.equal(replayed.checks["db-rowcap"].row_cap, 50);
    assert.equal(replayed.integrity.hash, original.integrity.hash);
    assert.equal(replayed.origins["/timeout_probe_sec"].layer, "replay");
    assert.equal(replayed.server.args?.[0], "different.js", "the server comes from the local files");
    const std2 = load(proj({ "sealmark.yaml": BASE }), { replay: plain().integrity });
    assert.equal(std2.integrity.standard, true);
  });

  it("refuses a tampered or foreign replay", () => {
    const rep = plain().integrity;
    const tampered = { ...rep, locked: { ...rep.locked, "checks.db-rowcap.row_cap": 99999 } };
    assert.match(failure(() => load(proj({ "sealmark.yaml": BASE }), { replay: tampered })), /^--replay: config\.locked does not match config\.hash/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": BASE }), { replay: { ...rep, methodology: "0.1-draft" } })), /methodology 0\.1-draft/);
    assert.match(checkReplay({}) ?? "", /only reports from sealmark 0\.2 or later/);
  });
});

describe("show", () => {
  const yaml = `${BASE.replace("  args: [srv.js]\n", "  args: [srv.js, '{sandbox}']\n  env: { API_KEY: sk-live-123, PORT: 3000 }\n")}timeout_probe_sec: 20\n`;
  const cfg = () => load(proj({ "sealmark.yaml": yaml }), { flags: { "timeout-probe": "4", pg: "postgres://admin:hunter2@h:5432/postgres" } });

  it("prints YAML with a trailing origin comment per leaf", () => {
    const text = renderShow(cfg(), { origins: true });
    assert.match(text, /^schema_version: 1 {3}# sealmark\.yaml:1$/m);
    assert.match(text, /^timeout_probe_sec: 4 {3}# flag --timeout-probe$/m);
    assert.match(text, /^ {4}row_cap: 10000 {3}# profile:standard$/m);
    assert.match(text, /^ {2}keep: false {3}# default$/m);
    assert.match(text, /^packs: \[core, db, sqlite, fs, net, git, http, effects\] {3}# profile:standard$/m);
    assert.match(text, /^ {2}args: \[srv\.js, "\{sandbox\}"\] {3}# sealmark\.yaml:\d+$/m);
  });

  it("never prints secrets and never expands placeholders", () => {
    const text = renderShow(cfg(), { origins: true });
    assert.ok(!text.includes("sk-live-123") && !text.includes("hunter2"), text);
    assert.match(text, /API_KEY: "?<redacted>"?/);
    assert.match(text, /pg: "?<redacted>"?/);
    assert.match(text, /\{sandbox\}/);
    assert.match(text, /PORT: "3000"|PORT: '3000'/);
  });

  it("emits JSON with one origin per JSON pointer", () => {
    const j = JSON.parse(renderShow(cfg(), { json: true })) as { value: { timeout_probe_sec: number; server: { env: Record<string, string> } }; origins: Record<string, { layer: string; source: string; line?: number }> };
    assert.equal(j.value.timeout_probe_sec, 4);
    assert.equal(j.value.server.env.API_KEY, "<redacted>");
    assert.deepEqual(j.origins["/timeout_probe_sec"], { layer: "flag", source: "flag --timeout-probe" });
    assert.equal(j.origins["/server/command"].layer, "project");
    assert.equal(j.origins["/server/command"].line, 3);
  });

  it("strips credentials from a server URL", () => {
    const c = load(proj({ "sealmark.yaml": "schema_version: 1\nserver: { url: 'http://u:pw@localhost:8000/mcp' }\n" }));
    assert.ok(!renderShow(c).includes("u:pw@"));
    assert.ok(renderShow(c).includes("http://localhost:8000/mcp"));
  });
});

describe("placeholders and the 0.1 compatibility surface", () => {
  it("keeps usesPlaceholders a database gate and sees harness placeholders separately", () => {
    assert.equal(usesPlaceholders({ command: "x", args: ["{dsn}"] }), true);
    assert.equal(usesPlaceholders({ command: "x", args: ["{sandbox}"] }), false);
    assert.deepEqual([...placeholdersUsed({ command: "x", args: ["{sandbox}", "{sandbox_home}", "{dsn:admin}", "{sqlite_path}"], env: { A: "{listener}" } })].sort(), ["dsn:admin", "listener", "sandbox", "sandbox_home", "sqlite_path"]);
  });

  it("expands database placeholders as before and leaves harness placeholders until supplied", () => {
    const ctx = { vars: { dsn: "postgres://x", sandbox: "C:\\s\\root" }, dsns: { admin: "postgres://a" } };
    assert.equal(expand("{dsn} {dsn:admin} {host}", ctx), "postgres://x postgres://a ");
    assert.equal(expand("--root {sandbox} --dir {dir} {canary}", ctx), "--root C:\\s\\root --dir C:\\s\\root {canary}");
    assert.equal(expand("${HOME_X}/${MISSING:-fallback}/{sandbox}", { ...ctx, env: { home_x: "h" } }), "h/fallback/C:\\s\\root");
  });

  it("redacts secret-looking literals but not placeholders or env references", () => {
    const d = displaySpec({ command: "x", args: ["a"], env: { API_KEY: "sk-1", TOKEN: "{sandbox}", AUTH_TOKEN: "${TOK}", PLAIN: "v" }, headers: { Authorization: "Bearer z" } });
    assert.deepEqual(d.env, { API_KEY: "<redacted>", TOKEN: "{sandbox}", AUTH_TOKEN: "${TOK}", PLAIN: "v", "header:Authorization": "<redacted>" });
  });

  it("refuses placeholders that cannot be filled for a server", () => {
    assert.match(failure(() => plain("").server && load(proj({ "sealmark.yaml": "server: { command: a, args: ['{canary}'] }\n" }))), /\{canary\} cannot be used in the server configuration/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": "server: { command: a, args: ['{token}'] }\n" }))), /\{token\} cannot be used/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": "server: { command: a, args: ['{sqlite_path}', '{duckdb_path}'] }\n" }))), /cannot both be used; one engine per server config/);
    assert.equal(load(proj({ "sealmark.yaml": "server: { command: a, args: ['{sqlite_path}'] }\n" })).server.args?.[0], "{sqlite_path}");
  });

  it("loadConfig still returns the 0.1 view", () => {
    const dir = proj({ "sealmark.yaml": "name: legacy\nversion: 2.0.0\nserver:\n  command: node\n  args: [a.js]\n  headers: { X-Key: abc }\nsql_tools:\n  - { tool: query, arg: sql }\n" });
    const c = loadConfig(join(dir, "sealmark.yaml"));
    assert.deepEqual(c, { name: "legacy", version: "2.0.0", server: { command: "node", args: ["a.js"], env: {}, headers: { "X-Key": "abc" } }, sql_tools: [{ tool: "query", arg: "sql" }] });
    assert.equal("packs" in c, false, "packs appear only when the file chose them");
    assert.deepEqual(loadConfig(join(proj({ "sealmark.yaml": `${BASE}packs: [core]\n` }), "sealmark.yaml")).packs, ["core"]);
    assert.throws(() => loadConfig(join(dir, "missing.yaml")), /Cannot read/);
  });

  it("ships an init template that loads", () => {
    assert.match(INIT_TEMPLATE, /^# yaml-language-server: \$schema=/);
    const c = load(proj({ "sealmark.yaml": INIT_TEMPLATE }));
    assert.equal(c.schemaVersion, 1);
    assert.deepEqual(c.warnings, []);
    assert.equal(c.integrity.standard, true);
  });

  it("round-trips Windows paths written as quoted YAML", () => {
    const c = load(proj({ "windows-paths.yaml": fixture("windows-paths.yaml") }), { flags: { config: "windows-paths.yaml" } });
    assert.equal(c.server.command, "C:\\Program Files\\nodejs\\node.exe");
    assert.deepEqual(c.server.args, ["D:\\work\\srv\\index.js", "--root", "{sandbox}"]);
    assert.equal(c.server.env?.DATA_DIR, "E:\\data\\sm");
    assert.equal(c.sandbox.dir, "D:\\tmp\\sealmark runs");
    assert.equal(c.integrity.standard, true, "sandbox.dir is a location, not a grade setting");
  });
});

describe("structured settings", () => {
  const bad = (yaml: string) => failure(() => plain(yaml));

  it("validates corpus additions against the pack's corpus schema", () => {
    assert.match(bad("checks:\n  mutating-sql:\n    corpus:\n      add: [{ id: c, steps: ['SELECT 1'], executed: 'run_code()' }]\n"), /executed must be probe_row:<id> or table_exists:<name>/);
    assert.match(bad("checks:\n  mutating-sql:\n    corpus:\n      add: [{ id: c, steps: [], executed: 'probe_row:1' }]\n"), /needs at least 1 item/);
    assert.match(bad("checks:\n  mutating-sql:\n    corpus:\n      add: [{ steps: ['SELECT 1'], executed: 'probe_row:1' }]\n"), /missing required key "id"/);
    assert.match(bad("checks:\n  mutating-sql:\n    corpus:\n      add: [{ id: c, step: ['x'], executed: 'probe_row:1' }]\n"), /unknown key "step" under checks\.mutating-sql\.corpus\.add\[0\]; did you mean "steps"\?/);
  });

  it("never lets a network corpus entry aim at a non-loopback address", () => {
    for (const host of ["169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.9", "8.8.8.8", "example.com", "0xa9fea9fe", "2852039166"]) {
      assert.match(bad(`checks:\n  net-loopback-ssrf:\n    corpus:\n      add: ['http://${host}/t/{token}']\n`), /is not loopback; network corpus entries may only target the harness listener/, host);
    }
    for (const host of ["127.0.0.1", "127.1", "localhost", "[::1]", "0x7f000001", "2130706433", "{listener}"]) {
      const c = plain(`checks:\n  net-loopback-ssrf:\n    corpus:\n      add: ['http://${host}:{port}/t/{token}']\n`);
      assert.equal(c.checks["net-loopback-ssrf"].corpus?.add.length, 1, host);
    }
    assert.equal(plain("checks:\n  net-scheme-allowlist:\n    corpus:\n      add: ['data:text/plain,sm-{token}']\n").checks["net-scheme-allowlist"].corpus?.add.length, 1);
  });

  it("requires harness-owned targets in file, git and exec corpora", () => {
    assert.match(bad("checks:\n  fs-read-escape:\n    corpus:\n      add: ['C:\\\\Windows\\\\win.ini']\n"), /literal target .* must use \{sandbox\}/);
    assert.match(bad("checks:\n  fs-read-escape:\n    corpus:\n      add: ['/etc/passwd']\n"), /literal target/);
    assert.equal(plain("checks:\n  fs-read-escape:\n    corpus:\n      add: ['{sandbox}/../x', '..\\\\canary\\\\a.txt']\n").checks["fs-read-escape"].corpus?.add.length, 2);
  });

  it("validates probes: shape, regexes, sandbox-only files, scope text and duplicate ids", () => {
    const probe = (body: string) => `probes:\n  - ${body}\n`;
    assert.match(bad(probe("tool: t\n    expect: { text: { matches: '(' } }")), /not a valid regular expression/);
    assert.match(bad(probe("tool: t\n    expect: { files: { unchanged: ['C:/secret.txt'] } }")), /custom probes observe only the sandbox/);
    assert.match(bad(probe("tool: t\n    expect: { listener: sometimes }")), /expected one of none, hit, any/);
    assert.match(bad(probe("id: p\n    tool: t\n    check: { id: custom-p, label: L, scope: 'the internet' }")), /scope must start with "server", "database" or "environment"/);
    assert.match(bad(probe("check: { id: custom-p, label: L, scope: 'server (x)' }\n    tool: t")), /needs an "id"/);
    assert.match(bad(`${probe("id: a\n    tool: t")}  - id: a\n    tool: u\n`), /duplicate probe id "a"/);
    assert.match(bad(probe("args: {}")), /missing required key "tool"/);
    const ok = plain(probe("tool: read_file\n    args: { path: '{sandbox}/ok.txt' }\n    expect: { is_error: false, files: { unchanged: ['{canary}/secret.txt'] }, listener: none }"));
    assert.equal(ok.probes.length, 1);
    assert.equal(ok.integrity.standard, true);
  });

  it("validates tools.overrides, sql_tools and plugins", () => {
    assert.match(bad("tools:\n  overrides:\n    x: { class: shell }\n"), /expected one of sql, path, url, command, git, text, opaque/);
    assert.match(bad("tools:\n  overrides:\n    x: { params: {} }\n"), /missing required key "class"/);
    assert.match(bad("sql_tools:\n  - { tool: q }\n"), /missing required key "arg"/);
    assert.match(bad("sql_tools:\n  - { tool: q, arg: sql, role: boss }\n"), /expected one of reader, writer, unknown/);
    assert.match(bad("plugins:\n  - { options: {} }\n"), /missing required key "module"/);
    const c = plain("sql_tools:\n  - { tool: q, arg: sql, role: writer, shape: array }\n");
    assert.deepEqual(c.sqlTools, [{ tool: "q", arg: "sql", role: "writer", shape: "array" }]);
  });

  it("supports several servers and selecting one", () => {
    const yaml = "schema_version: 1\nservers:\n  fs: { command: node, args: [fs.js, '{sandbox}'] }\n  web: { url: 'http://localhost:9/mcp' }\n";
    const dir = proj({ "sealmark.yaml": yaml });
    const all = load(dir);
    assert.deepEqual(all.servers.map((s) => s.name), ["fs", "web"]);
    assert.equal(all.server.command, "node");
    assert.deepEqual(load(dir, { flags: { server: "web" } }).servers.map((s) => s.name), ["web"]);
    assert.deepEqual(load(dir, { flags: { server: "all" } }).serverNames, ["fs", "web"]);
    assert.match(failure(() => load(dir, { flags: { server: "fss" } })), /no server named "fss" is configured \(configured: fs, web\); did you mean "fs"\?/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": `${yaml}server: { command: x }\n` }))), /set either server or servers, not both/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": "schema_version: 1\nservers:\n  a: {}\n" }))), /servers\.a needs "command"/);
  });

  it("derives the robust-input hang threshold from the probe wait unless set", () => {
    assert.equal(plain().hangMs, 10000);
    assert.equal(plain("timeout_probe_sec: 1\n").hangMs, 2000);
    assert.equal(plain("checks:\n  robust-input: { hang_ms: 5000 }\n").hangMs, 5000);
  });

  it("warns when the exec pack is listed without --active", () => {
    const listed = plain("packs: [core, exec]\n");
    assert.ok(listed.warnings.some((w) => /exec pack is listed .* but runs only with --active/.test(w)));
    assert.equal(load(proj({ "sealmark.yaml": BASE + "packs: [core, exec]\n" }), { flags: { active: true } }).warnings.some((w) => /exec/.test(w)), false);
  });
});
