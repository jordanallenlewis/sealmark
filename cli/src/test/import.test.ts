import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { expand } from "../config.js";
import {
  candidates,
  describeServer,
  fullSpec,
  parseJsonc,
  scanClients,
  scrubLiteral,
  selectServers,
  slashes,
  translate,
  uniqueNames,
  type ClientId,
  type ImportEnv,
  type ImportedServer,
} from "../config/import.js";
import {
  InitError,
  applySuggestions,
  ensureGitignore,
  guessName,
  planInit,
  readlineIO,
  runInit,
  splitCommandLine,
  suggestReplacements,
  type FileSink,
  type WizardIO,
} from "../config/wizard.js";
import type { ServerSpec } from "../types.js";

/** Fixtures are not compiled: resolve them in src/ from dist/test/. */
const FIX = fileURLToPath(new URL("../../src/test/fixtures/clients/", import.meta.url));
const lf = (s: string) => s.split("\r\n").join("\n");
const fixture = (name: string) => readFileSync(join(FIX, name), "utf8");
const golden = (name: string): string | undefined => {
  const p = join(FIX, "golden", name);
  return existsSync(p) ? lf(readFileSync(p, "utf8")) : undefined;
};

// A Windows machine that exists only in this file: nothing here reads the real home directory.
const HOME = "C:\\Users\\tester";
const CWD = "C:\\Users\\tester\\work\\demo";
const FILES: Record<string, string> = {
  [`${HOME}\\AppData\\Roaming\\Claude\\claude_desktop_config.json`]: fixture("claude-desktop.json"),
  [`${HOME}\\.claude.json`]: fixture("claude-code-user.json"),
  [`${CWD}\\.mcp.json`]: fixture("claude-code-mcp.json"),
  [`${HOME}\\.cursor\\mcp.json`]: fixture("cursor.json"),
  [`${CWD}\\.vscode\\mcp.json`]: fixture("vscode.json"),
  [`${HOME}\\.copilot\\mcp-config.json`]: fixture("copilot-cli.json"),
};
const winEnv = (over: Partial<ImportEnv> = {}): ImportEnv => ({
  platform: "win32",
  home: HOME,
  cwd: CWD,
  env: { APPDATA: `${HOME}\\AppData\\Roaming`, LOCALAPPDATA: `${HOME}\\AppData\\Local` },
  read: (p) => FILES[p],
  list: () => [],
  ...over,
});

const CLIENTS: ClientId[] = ["claude-desktop", "claude-code", "cursor", "vscode", "copilot-cli"];
const ANSWERS = { "pg-password": "fake-pg-pass-123", "data-dir": "D:/data/fake" };

/** Every fake secret that appears in the fixtures or is answered during init. None may reach sealmark.yaml. */
const FAKE_SECRETS = ["sk-fake-0000000000000000", "sk-fake-github-0000000000000000", "fakepw", "fake-key-123", "fake-pg-pass-123"];

const byId = (r: { servers: ImportedServer[] }, id: string) => {
  const s = r.servers.find((x) => x.id === id);
  assert.ok(s, `server ${id} not found among ${r.servers.map((x) => x.id).join(", ")}`);
  return s;
};

let work: string;
before(() => {
  work = mkdtempSync(join(tmpdir(), "sealmark-import-"));
});
after(() => rmSync(work, { recursive: true, force: true }));

describe("parseJsonc", () => {
  it("reads comments, trailing commas and a BOM, and leaves comment-like text inside strings alone", () => {
    const v = parseJsonc('\uFEFF{ // c\n "a": "http://x/y", /* b */ "b": [1, 2,], "c": "//not a comment", }') as Record<string, unknown>;
    assert.deepEqual(v, { a: "http://x/y", b: [1, 2], c: "//not a comment" });
  });
  it("still rejects broken JSON", () => {
    assert.throws(() => parseJsonc('{ "a": }'));
  });
});

describe("translate", () => {
  const tc = { projectDir: CWD, home: HOME, inputs: {} as Record<string, string | undefined> };
  it("keeps environment references and rewrites ${env:X}", () => {
    assert.equal(translate("${TOKEN}", tc).main, "${TOKEN}");
    assert.equal(translate("${TOKEN:-dflt}", tc).main, "${TOKEN:-dflt}");
    assert.equal(translate("${env:TOKEN}", tc).main, "${TOKEN}");
    assert.equal(translate("${env:TOKEN:-x}", tc).main, "${TOKEN:-x}");
  });
  it("resolves workspace and home variables to forward-slash paths and flags the result machine-specific", () => {
    const t = translate("${workspaceFolder}/data;${userHome}/x;${workspaceFolderBasename}${pathSeparator}${/}", tc);
    assert.equal(t.main, "C:/Users/tester/work/demo/data;C:/Users/tester/x;demo//");
    assert.equal(t.machine, true);
    assert.equal(translate("${cwd}", tc).main, "C:/Users/tester/work/demo");
  });
  it("replaces ${input:id} by a reference and fills the local text only when answered", () => {
    const open = translate("a-${input:my-key}", tc);
    assert.equal(open.main, "a-${SEALMARK_INPUT_MY_KEY}");
    assert.equal(open.local, "a-${SEALMARK_INPUT_MY_KEY}");
    assert.deepEqual(open.inputIds, ["my-key"]);
    const answered = translate("a-${input:my-key}", { ...tc, inputs: { "my-key": "fake-value" } });
    assert.equal(answered.main, "a-${SEALMARK_INPUT_MY_KEY}");
    assert.equal(answered.local, "a-fake-value");
  });
  it("passes unknown variables through with a warning", () => {
    const t = translate("${config:foo.bar}", tc);
    assert.equal(t.main, "${config:foo.bar}");
    assert.match(t.warnings[0], /\$\{config:\.\.\.\} is not translated/);
  });
  it("converts Windows drive paths to forward slashes and nothing else", () => {
    assert.equal(slashes("D:\\repos\\demo"), "D:/repos/demo");
    assert.equal(slashes("--root=D:\\repos\\demo"), "--root=D:/repos/demo");
    assert.equal(slashes("a\\b"), "a\\b");
    assert.equal(slashes("^\\d+$"), "^\\d+$");
  });
});

describe("scrubLiteral", () => {
  it("catches URL passwords, secret query parameters and token shapes, and nothing ordinary", () => {
    assert.deepEqual(scrubLiteral("postgresql://app:fakepw@localhost/db", "X"), { safe: "postgresql://app:${X_PASSWORD}@localhost/db", secret: true });
    assert.deepEqual(scrubLiteral("https://h.example.test/m?api_key=abc&team=a#f", "X"), { safe: "https://h.example.test/m?api_key=${X_API_KEY}&team=a#f", secret: true });
    assert.deepEqual(scrubLiteral("sk-fake-0000000000000000", "X"), { safe: "${X}", secret: true });
    for (const ok of ["https://h.example.test/m?team=a", "postgresql://app@localhost/db", "C:/Users/x", "--units", "${A}", "postgres://u:${PW}@h/d"]) {
      assert.equal(scrubLiteral(ok, "X").secret, false, ok);
    }
  });
});

describe("candidates", () => {
  const paths = (e: ImportEnv) => candidates(e).map((c) => `${c.client}:${c.path}`);
  it("lists the Windows locations", () => {
    const p = paths(winEnv());
    for (const want of [
      `claude-desktop:${HOME}\\AppData\\Roaming\\Claude\\claude_desktop_config.json`,
      `claude-code:${HOME}\\.claude.json`,
      `claude-code:${CWD}\\.mcp.json`,
      `cursor:${HOME}\\.cursor\\mcp.json`,
      `cursor:${CWD}\\.cursor\\mcp.json`,
      `vscode:${CWD}\\.vscode\\mcp.json`,
      `copilot-cli:${HOME}\\.copilot\\mcp-config.json`,
    ]) {
      assert.ok(p.includes(want), `missing ${want}`);
    }
  });
  it("lists the macOS and Linux locations", () => {
    const mac = paths({ ...winEnv(), platform: "darwin", home: "/Users/t", cwd: "/Users/t/p", env: {} });
    assert.ok(mac.includes("claude-desktop:/Users/t/Library/Application Support/Claude/claude_desktop_config.json"));
    assert.ok(mac.includes("claude-code:/Users/t/p/.mcp.json"));
    const linux = paths({ ...winEnv(), platform: "linux", home: "/home/t", cwd: "/home/t/p", env: { XDG_CONFIG_HOME: "/cfg" } });
    assert.ok(linux.includes("claude-desktop:/cfg/Claude/claude_desktop_config.json"));
    assert.ok(linux.includes("vscode:/cfg/Code/User/mcp.json"));
    assert.ok(linux.includes("copilot-cli:/home/t/.copilot/mcp-config.json"));
  });
  it("finds the Microsoft Store install of Claude Desktop and marks it assumed", () => {
    const e = winEnv({ list: (d) => (d.endsWith("Packages") ? ["Claude_pzs8sxrjxfjjc", "Other_x"] : []) });
    const store = candidates(e).filter((c) => c.assumed && c.client === "claude-desktop");
    assert.equal(store.length, 1);
    assert.match(store[0].path, /Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude_desktop_config\.json$/);
  });
  it("can be limited to some clients", () => {
    assert.deepEqual([...new Set(candidates(winEnv(), ["cursor"]).map((c) => c.client))], ["cursor"]);
  });
});

describe("scanClients", () => {
  const scan = scanClients(winEnv());

  it("finds every fixture server and reports files, skipped entries and broken files", () => {
    assert.deepEqual(
      scan.servers.map((s) => s.id),
      [
        "claude-desktop/user/filesystem",
        "claude-desktop/user/memory",
        "claude-desktop/user/weather",
        "claude-code/user/github",
        "claude-code/local/appdb",
        "claude-code/project/search",
        "claude-code/project/legacy",
        "cursor/user/fs",
        "cursor/user/tools",
        "cursor/user/remote",
        "vscode/project/pg",
        "vscode/project/data",
        "vscode/project/api",
        "vscode/project/pyserver",
        "copilot-cli/user/local-git",
        "copilot-cli/user/everything",
      ],
    );
    assert.deepEqual(scan.skipped.map((s) => s.name), ["broken"]);
    assert.equal(scan.files.filter((f) => f.found).length, 6);
    const bad = scanClients(winEnv({ read: (p) => (p.endsWith("mcp.json") && p.includes(".cursor") ? "{ nope" : FILES[p]) }));
    assert.match(bad.files.find((f) => f.client === "cursor" && f.found)!.error!, /not valid JSON/);
    assert.equal(bad.servers.some((s) => s.client === "cursor"), false);
  });

  it("matches Claude Code's per-project entries by directory, ignoring slash style, and no others", () => {
    assert.ok(scan.servers.some((s) => s.name === "appdb"));
    assert.equal(scan.servers.some((s) => s.name === "elsewhere"), false);
    const upper = scanClients(winEnv({ cwd: "c:\\users\\TESTER\\work\\demo\\" }), { clients: ["claude-code"] });
    assert.ok(upper.servers.some((s) => s.name === "appdb"), "case and trailing separator must not matter on Windows");
    const linux = scanClients(
      winEnv({ platform: "linux", home: "/home/t", cwd: "/home/t/p", env: {}, read: (p) => (p === "/home/t/.claude.json" ? '{"projects":{"/home/t/p":{"mcpServers":{"a":{"command":"x"}}},"/home/t/P":{"mcpServers":{"b":{"command":"y"}}}}}' : undefined) }),
    );
    assert.deepEqual(linux.servers.map((s) => s.name), ["a"], "POSIX paths are case-sensitive");
  });

  it("reads each client's shape: type, url, headers, env, comments", () => {
    const gh = byId(scan, "claude-code/user/github");
    assert.equal(gh.transport, "http");
    assert.equal(gh.spec.url, "https://mcp.example.test/github/");
    assert.equal(byId(scan, "claude-code/project/legacy").transport, "sse");
    assert.equal(byId(scan, "copilot-cli/user/local-git").transport, "stdio", 'Copilot CLI calls stdio servers "local"');
    assert.equal(byId(scan, "vscode/project/pyserver").transport, "stdio", "VS Code file has comments and trailing commas");
    assert.equal(byId(scan, "vscode/project/api").transport, "http");
  });

  it("translates client interpolation", () => {
    const search = byId(scan, "claude-code/project/search");
    assert.deepEqual(search.spec.args, ["-y", "@example/search-mcp", "--index", "${SEARCH_INDEX:-docs}"]);
    assert.deepEqual(search.spec.env, { SEARCH_API_KEY: "${SEARCH_API_KEY}", REGION: "${REGION:-eu}" });
    assert.deepEqual(search.local, {}, "references are not secrets");
    const fs = byId(scan, "cursor/user/fs");
    assert.equal(fs.spec.args![2], "C:/Users/tester/work/demo", "${workspaceFolder} is the project directory");
    assert.equal(fs.machineSpecific, true);
    const tools = byId(scan, "cursor/user/tools");
    assert.equal(tools.spec.args![0], "C:/Users/tester/mcp/server.js", "${userHome} is resolved, not written as ~");
    assert.equal(tools.spec.env!.API_TOKEN, "${TOOLS_TOKEN}", "${env:X} becomes ${X}");
    assert.equal(byId(scan, "copilot-cli/user/local-git").spec.args![2], "D:/repos/demo", "Windows paths use forward slashes");
    assert.equal(byId(scan, "claude-desktop/user/filesystem").spec.args![2], "C:/Users/tester/Documents/notes");
  });

  it("keeps secrets out of the project spec and in the local overrides", () => {
    const w = byId(scan, "claude-desktop/user/weather");
    assert.deepEqual(w.spec.env, { WEATHER_API_KEY: "${WEATHER_API_KEY}", UNITS: "metric" });
    assert.deepEqual(w.local.env, { WEATHER_API_KEY: "sk-fake-0000000000000000" });
    assert.deepEqual(w.routed, ["env.WEATHER_API_KEY"]);
    const gh = byId(scan, "claude-code/user/github");
    assert.equal(gh.spec.headers!.Authorization, "${SEALMARK_GITHUB_AUTHORIZATION}");
    assert.equal(gh.spec.headers!.Accept, "application/json");
    assert.equal(gh.local.headers!.Authorization, "Bearer sk-fake-github-0000000000000000");
    const db = byId(scan, "claude-code/local/appdb");
    assert.equal(db.spec.args![2], "postgresql://app:${SEALMARK_APPDB_ARG2_PASSWORD}@localhost:5432/appdb");
    assert.equal(db.local.args![2], "postgresql://app:fakepw@localhost:5432/appdb");
    assert.equal(byId(scan, "cursor/user/remote").spec.url, "https://remote.example.test/mcp?api_key=${SEALMARK_REMOTE_URL_API_KEY}&team=a");
    const printed = JSON.stringify(scan.servers.map((s) => ({ spec: s.spec, line: describeServer(s), routed: s.routed, warnings: s.warnings })));
    for (const secret of FAKE_SECRETS) assert.equal(printed.includes(secret), false, `${secret} leaked into printable fields`);
  });

  it("routes input variables to the local file only when answered, and warns when not", () => {
    const open = byId(scan, "vscode/project/pg");
    assert.equal(open.spec.env!.PGPASSWORD, "${SEALMARK_INPUT_PG_PASSWORD}");
    assert.deepEqual(open.local, {});
    assert.match(open.warnings.join("\n"), /"pg-password" were not answered; set SEALMARK_INPUT_PG_PASSWORD/);
    assert.deepEqual(open.inputs, [{ id: "pg-password", description: "Postgres password", password: true }]);
    const answered = scanClients(winEnv(), { inputs: ANSWERS });
    const pg = byId(answered, "vscode/project/pg");
    assert.equal(pg.spec.env!.PGPASSWORD, "${SEALMARK_INPUT_PG_PASSWORD}");
    assert.deepEqual(pg.local.env, { PGPASSWORD: "fake-pg-pass-123" });
    assert.deepEqual(byId(answered, "vscode/project/data").local.args, ["server.js", "--dir", "D:/data/fake"]);
    assert.deepEqual(byId(answered, "vscode/project/api").local.headers, { "X-Api-Key": "fake-pg-pass-123" });
    assert.deepEqual(byId(answered, "vscode/project/pg").warnings, []);
  });

  it("warns about settings sealmark cannot honour and about the SSE transport", () => {
    const py = byId(scan, "vscode/project/pyserver");
    assert.match(py.warnings.join("\n"), /cwd is ignored/);
    assert.match(py.warnings.join("\n"), /envFile is not read/);
    assert.match(byId(scan, "claude-code/project/legacy").warnings[0], /legacy SSE transport/);
  });

  it("routes a secret-looking flag's value, in both the --flag=value and the --flag value forms", () => {
    const e = winEnv({ read: (p) => (p === `${CWD}\\.mcp.json` ? JSON.stringify({ mcpServers: { s: { command: "srv", args: ["--api-key=lit1", "--token", "lit2", "--name", "ok", "--key-count", "3"] } } }) : undefined) });
    const s = scanClients(e, { clients: ["claude-code"] }).servers[0];
    assert.deepEqual(s.spec.args, ["--api-key=${SEALMARK_S_API_KEY}", "--token", "${SEALMARK_S_TOKEN}", "--name", "ok", "--key-count", "${SEALMARK_S_KEY_COUNT}"]);
    assert.deepEqual(s.local.args, ["--api-key=lit1", "--token", "lit2", "--name", "ok", "--key-count", "3"]);
    assert.deepEqual(s.routed, ["args[0]", "args[2]", "args[6]"]);
  });
});

describe("selectServers and uniqueNames", () => {
  const scan = scanClients(winEnv());
  it("selects by id, client/name, unique name and all, and says why a query failed", () => {
    assert.deepEqual(selectServers(scan.servers, ["cursor/user/fs"]).chosen.map((s) => s.name), ["fs"]);
    assert.deepEqual(selectServers(scan.servers, ["cursor/fs", "weather"]).chosen.map((s) => s.name), ["fs", "weather"]);
    assert.equal(selectServers(scan.servers, ["all"]).chosen.length, scan.servers.length);
    assert.match(selectServers(scan.servers, ["nope"]).problems[0], /no imported server matches "nope"/);
    const twin = [scan.servers[0], { ...scan.servers[0], id: "cursor/user/filesystem", client: "cursor" as const }];
    assert.match(selectServers(twin, ["filesystem"]).problems[0], /matches 2 servers/);
  });
  it("makes names unique with the client name, then a number", () => {
    const a = { ...scan.servers[0], id: "a", name: "git", client: "cursor" as const };
    const b = { ...scan.servers[0], id: "b", name: "git", client: "vscode" as const };
    const c = { ...scan.servers[0], id: "c", name: "git", client: "vscode" as const };
    const d = { ...scan.servers[0], id: "d", name: "my server", client: "vscode" as const };
    const names = uniqueNames([a, b, c, d]);
    assert.deepEqual([...names.values()], ["git-cursor", "git-vscode", "git-vscode-2", "my-server"]);
  });
});

describe("generated config files", () => {
  const render = (client: ClientId, inputs: Record<string, string> = {}) => {
    const r = scanClients(winEnv(), { clients: [client], inputs });
    const plan = planInit({ servers: r.servers, configPath: join(CWD, "sealmark.yaml") });
    return { r, plan, config: lf(plan.files.find((f) => f.kind === "config")!.content), local: plan.files.find((f) => f.kind === "local")?.content };
  };
  const cases: [string, ClientId, Record<string, string>][] = [
    ["claude-desktop", "claude-desktop", {}],
    ["claude-code", "claude-code", {}],
    ["cursor", "cursor", {}],
    ["vscode", "vscode", {}],
    ["vscode-answered", "vscode", ANSWERS],
    ["copilot-cli", "copilot-cli", {}],
  ];

  for (const [name, client, inputs] of cases) {
    it(`${name}: matches the golden sealmark.yaml and sealmark.local.yaml`, () => {
      const { config, local } = render(client, inputs);
      if (process.env.SEALMARK_UPDATE_GOLDEN === "1") {
        writeFileSync(join(FIX, "golden", `${name}.sealmark.yaml`), config);
        if (local) writeFileSync(join(FIX, "golden", `${name}.sealmark.local.yaml`), lf(local));
      }
      assert.equal(config, golden(`${name}.sealmark.yaml`), "sealmark.yaml differs from the golden file");
      const gl = golden(`${name}.sealmark.local.yaml`);
      assert.equal(local === undefined ? undefined : lf(local), gl, "sealmark.local.yaml differs from the golden file");
    });
  }

  it("never writes a fake secret into sealmark.yaml, and puts each one in sealmark.local.yaml", () => {
    const all = scanClients(winEnv(), { inputs: ANSWERS });
    const plan = planInit({ servers: all.servers, configPath: join(CWD, "sealmark.yaml") });
    const config = plan.files.find((f) => f.kind === "config")!.content;
    const local = plan.files.find((f) => f.kind === "local")!.content;
    for (const s of FAKE_SECRETS) {
      assert.equal(config.includes(s), false, `${s} is in sealmark.yaml`);
      assert.ok(local.includes(s), `${s} is missing from sealmark.local.yaml`);
    }
    assert.equal(plan.files.find((f) => f.kind === "local")!.mode, 0o600);
  });

  for (const [name, client, inputs] of cases) {
    it(`${name}: loads through the strict config loader, and the two files merge to the full server settings`, () => {
      const { r, plan } = render(client, inputs);
      // The plan's paths point at the virtual project; write the same text into a real temp directory.
      const real = mkdtempSync(join(work, "rt-"));
      for (const f of plan.files) if (f.kind !== "gitignore") writeFileSync(join(real, f.kind === "config" ? "sealmark.yaml" : "sealmark.local.yaml"), f.content);
      // A ${VAR} reference that is not set is a configuration error now, so define each one the files refer to.
      const env: Record<string, string> = {};
      for (const f of plan.files) for (const m of f.content.matchAll(/\$\{((?!SEALMARK_(?!INPUT_))[A-Za-z_][A-Za-z0-9_]*)\}/g)) env[m[1]] = "set-for-the-test"; // other SEALMARK_* names are read as settings
      const cfg = loadEffectiveConfig({ cwd: real, env, isolated: true });
      const norm = (s: ServerSpec) => ({ command: s.command, url: s.url, args: s.args ?? [], env: s.env ?? {}, headers: s.headers ?? {} });
      assert.equal(cfg.servers.length, r.servers.length);
      const named = uniqueNames(r.servers);
      for (const s of r.servers) {
        const loaded = cfg.servers.find((x) => x.name === named.get(s.id));
        assert.ok(loaded, `${s.id} did not load`);
        assert.deepEqual(norm(loaded.spec), norm(fullSpec(s)), `${s.id}: merged settings differ from what the client had`);
      }
    });
  }

  it("a reference written for a secret resolves from the environment at run time", () => {
    const w = byId(scanClients(winEnv()), "claude-desktop/user/weather");
    const ctx = { vars: {}, dsns: {}, env: { WEATHER_API_KEY: "from-env" } };
    assert.equal(expand(w.spec.env!.WEATHER_API_KEY, ctx), "from-env");
  });

  it("writes one server as `server:` and several as `servers:`, with unique names", () => {
    const r = scanClients(winEnv());
    const one = planInit({ servers: [byId(r, "cursor/user/fs")], configPath: join(CWD, "sealmark.yaml") }).files[0].content;
    assert.match(one, /^name: fs\nserver:\n/m);
    const two = planInit({ servers: [byId(r, "cursor/user/fs"), byId(r, "cursor/user/tools")], configPath: join(CWD, "sealmark.yaml") }).files[0].content;
    assert.match(two, /^servers:\n {2}fs:\n/m);
    assert.match(two, /^ {2}tools:\n/m);
  });
});

describe("suggestReplacements", () => {
  const dirs = new Set(["C:/Users/tester/Documents/notes", "C:/Users/tester/work/demo", "D:/repos/demo"]);
  const opts = { isDir: (p: string) => dirs.has(p), isFile: () => false };
  const scan = scanClients(winEnv(), { inputs: ANSWERS });

  it("offers {sandbox} for a directory argument", () => {
    const [s] = suggestReplacements(byId(scan, "claude-desktop/user/filesystem"), opts);
    assert.equal(s.kind, "sandbox");
    assert.equal(s.placeholder, "{sandbox}");
    assert.equal(s.value, "{sandbox}");
    assert.deepEqual(s.target, { field: "arg", index: 2 });
    assert.equal(s.shown, "C:/Users/tester/Documents/notes");
  });
  it("offers {dsn} for a Postgres URL and shows it without credentials", () => {
    const [s] = suggestReplacements(byId(scan, "claude-code/local/appdb"), opts);
    assert.equal(s.kind, "dsn");
    assert.equal(s.shown, "postgresql://localhost:5432/appdb");
    assert.equal(JSON.stringify(s).includes("fakepw"), false);
  });
  it("keeps a --flag= prefix, and skips launcher options and system variables", () => {
    const spec = (args: string[], env: Record<string, string> = {}): ImportedServer => ({ ...scan.servers[0], id: "x", spec: { command: "c", args, env }, local: {}, routed: [] });
    assert.equal(suggestReplacements(spec(["--root=D:/repos/demo"]), opts)[0].value, "--root={sandbox}");
    assert.deepEqual(suggestReplacements(spec(["--directory", "D:/repos/demo"]), opts), [], "uvx --directory is where the launcher runs");
    assert.deepEqual(suggestReplacements(spec([], { HOME: "D:/repos/demo", PATH: "D:/repos/demo" }), opts), []);
    assert.equal(suggestReplacements(spec([], { DATA_DIR: "D:/repos/demo" }), opts)[0].target.field, "env");
    assert.equal(suggestReplacements(spec(["D:/repos/missing"]), opts).length, 0, "a path that is not a directory is left alone");
  });
  it("offers {sqlite_path} / {duckdb_path} for database files, one engine per server", () => {
    const spec = (args: string[]): ImportedServer => ({ ...scan.servers[0], id: "x", spec: { command: "c", args }, local: {}, routed: [] });
    assert.equal(suggestReplacements(spec(["--db-path", "C:/data/app.sqlite"]), opts)[0].placeholder, "{sqlite_path}");
    assert.equal(suggestReplacements(spec(["--db=C:/data/a.duckdb"]), opts)[0].value, "--db={duckdb_path}");
    assert.equal(suggestReplacements(spec(["C:/data/a.db", "C:/data/b.duckdb"]), opts).length, 1);
  });

  it("applySuggestions replaces the value and removes the secret it carried from the local overrides", () => {
    const db = byId(scan, "claude-code/local/appdb");
    const done = applySuggestions(db, suggestReplacements(db, opts));
    assert.deepEqual(done.spec.args, ["-y", "@example/postgres-mcp", "{dsn}"]);
    assert.equal(done.local.args, undefined);
    assert.deepEqual(done.routed, []);
    assert.equal(JSON.stringify(done).includes("fakepw"), false);
    const fs = byId(scan, "cursor/user/fs");
    const changed = applySuggestions(fs, suggestReplacements(fs, opts));
    assert.equal(changed.spec.args![2], "{sandbox}");
    assert.equal(fs.spec.args![2], "C:/Users/tester/work/demo", "the input is not mutated");
  });
  it("keeps other secrets in the local overrides when only one argument is replaced", () => {
    const e = winEnv({ read: (p) => (p === `${CWD}\\.mcp.json` ? JSON.stringify({ mcpServers: { s: { command: "srv", args: ["--token=lit", "D:\\repos\\demo"] } } }) : undefined) });
    const s = scanClients(e, { clients: ["claude-code"] }).servers[0];
    const done = applySuggestions(s, suggestReplacements(s, opts));
    assert.deepEqual(done.spec.args, ["--token=${SEALMARK_S_TOKEN}", "{sandbox}"]);
    assert.deepEqual(done.local.args, ["--token=lit", "{sandbox}"]);
    assert.deepEqual(done.routed, ["args[0]"]);
  });
});

describe("splitCommandLine and guessName", () => {
  it("splits like a shell for quotes and leaves Windows backslashes alone", () => {
    assert.deepEqual(splitCommandLine('npx -y @modelcontextprotocol/server-filesystem {sandbox}'), ["npx", "-y", "@modelcontextprotocol/server-filesystem", "{sandbox}"]);
    assert.deepEqual(splitCommandLine('"C:\\Program Files\\nodejs\\node.exe" "my server.js" --a="b c" \'d e\' ""'), ["C:\\Program Files\\nodejs\\node.exe", "my server.js", "--a=b c", "d e", ""]);
    assert.deepEqual(splitCommandLine('say "he said \\"hi\\""'), ["say", 'he said "hi"']);
    assert.throws(() => splitCommandLine('npx "oops'), InitError);
  });
  it("names the server from the package", () => {
    assert.equal(guessName("npx", ["-y", "@modelcontextprotocol/server-filesystem", "{sandbox}"]), "filesystem");
    assert.equal(guessName("uvx", ["mcp-server-git"]), "git");
    assert.equal(guessName("npx", ["-y", "pkg@1.2.3"]), "pkg");
    assert.equal(guessName("node", ["C:\\x\\dist\\server.js"]), "server");
    assert.equal(guessName("tool", []), "tool");
  });
});

describe("ensureGitignore", () => {
  it("creates, appends once, keeps line endings, and recognises equivalent patterns", () => {
    assert.deepEqual(ensureGitignore(undefined, ["sealmark.local.yaml"]), { text: "# sealmark: machine-specific values and secrets\nsealmark.local.yaml\n", added: ["sealmark.local.yaml"] });
    const first = ensureGitignore("node_modules\ndist", ["sealmark.local.yaml"]);
    assert.equal(first.text, "node_modules\ndist\n\n# sealmark: machine-specific values and secrets\nsealmark.local.yaml\n");
    assert.deepEqual(ensureGitignore(first.text, ["sealmark.local.yaml"]), { text: first.text, added: [] }, "idempotent");
    assert.equal(ensureGitignore("a\r\nb\r\n", ["sealmark.local.yaml"]).text, "a\r\nb\r\n\r\n# sealmark: machine-specific values and secrets\r\nsealmark.local.yaml\r\n");
    for (const covered of ["/sealmark.local.yaml\n", "*.local.yaml\n", "sealmark.local.*\n"]) assert.deepEqual(ensureGitignore(covered, ["sealmark.local.yaml"]).added, [], covered);
    assert.deepEqual(ensureGitignore("# sealmark.local.yaml\n", ["sealmark.local.yaml"]).added, ["sealmark.local.yaml"], "a comment is not an ignore rule");
    assert.deepEqual(ensureGitignore("!sealmark.local.yaml\n", ["sealmark.local.yaml"]).added, ["sealmark.local.yaml"], "a negation is not an ignore rule");
  });
});

describe("runInit", () => {
  const memory = () => {
    const written = new Map<string, string>();
    const sink: FileSink = { write: (p, c) => void written.set(p, c) };
    return { written, sink };
  };
  const base = (extra: object) => ({ env: winEnv(), configPath: join(CWD, "sealmark.yaml"), readText: (p: string) => (written.has(p) ? written.get(p) : undefined), sink, suggest: { isDir: (p: string) => p === "C:/Users/tester/work/demo" }, ...extra });
  let written: Map<string, string>;
  let sink: FileSink;
  const fresh = () => {
    ({ written, sink } = memory());
  };

  it("non-interactive: several servers and no choice takes the defaults, which is all of them, and says so and how to narrow", async () => {
    fresh();
    const out = await runInit(base({}));
    assert.equal(out.template, false);
    assert.equal(out.selected.length, 16);
    assert.match(out.messages.join(" "), /16 MCP servers found .*all of them are taken.* --server <name>/);
    assert.ok(written.has(join(CWD, "sealmark.yaml")));
  });

  it("non-interactive: --server picks servers; replacements that point at harness-owned targets are accepted", async () => {
    fresh();
    const out = await runInit(base({ select: ["cursor/fs", "claude-code/appdb"] }));
    assert.equal(out.template, false);
    assert.deepEqual(out.applied.map((a) => a.placeholder).sort(), ["{dsn}", "{sandbox}"]);
    const config = lf(written.get(join(CWD, "sealmark.yaml"))!);
    assert.match(config, /- "\{sandbox\}"|- '\{sandbox\}'/);
    assert.match(config, /- "\{dsn\}"|- '\{dsn\}'/);
    assert.equal(written.has(join(CWD, "sealmark.local.yaml")), false, "the only secret was replaced by {dsn}, so there is nothing local");
    assert.match(written.get(join(CWD, ".gitignore"))!, /^sealmark\.local\.yaml$/m);
    assert.ok(out.messages.some((m) => /replace|->/.test(m)));
  });

  it("writes sealmark.local.yaml with restricted mode when secrets remain, and gitignores it", async () => {
    fresh();
    const modes: Record<string, number | undefined> = {};
    const sink2: FileSink = { write: (p, c, m) => void (written.set(p, c), (modes[p] = m)) };
    const out = await runInit({ ...base({ select: ["weather"] }), sink: sink2 });
    assert.equal(modes[join(CWD, "sealmark.local.yaml")], 0o600);
    assert.match(written.get(join(CWD, "sealmark.local.yaml"))!, /WEATHER_API_KEY: sk-fake-0000000000000000/);
    assert.deepEqual(out.plan!.routed, [{ server: "weather", items: ["env.WEATHER_API_KEY"] }]);
    assert.equal(lf(written.get(join(CWD, "sealmark.yaml"))!).includes("sk-fake"), false);
  });

  it("refuses to overwrite existing files without --force", async () => {
    fresh();
    written.set(join(CWD, "sealmark.yaml"), "x");
    await assert.rejects(runInit(base({ select: ["weather"] })), /already exists\. Use --force/);
    written.delete(join(CWD, "sealmark.yaml"));
    written.set(join(CWD, "sealmark.local.yaml"), "x");
    await assert.rejects(runInit(base({ select: ["weather"] })), /sealmark\.local\.yaml already exists/);
    await runInit(base({ select: ["weather"], force: true }));
    assert.match(written.get(join(CWD, "sealmark.local.yaml"))!, /WEATHER_API_KEY/);
  });

  it("an unknown or ambiguous --server is an error that lists what exists", async () => {
    fresh();
    await assert.rejects(runInit(base({ select: ["nope"] })), /no imported server matches "nope"\. Servers found: claude-desktop\/user\/filesystem/);
  });

  it("falls back to the template when no client configuration exists", async () => {
    fresh();
    const out = await runInit(base({ env: winEnv({ read: () => undefined }) }));
    assert.equal(out.template, true);
    assert.match(written.get(join(CWD, "sealmark.yaml"))!, /^# sealmark\.yaml/m);
  });

  it("--from writes a config from a one-liner and keeps what the user typed", async () => {
    fresh();
    const out = await runInit(base({ fromCommand: "npx -y @modelcontextprotocol/server-filesystem {sandbox}", env: winEnv({ read: () => undefined }) }));
    assert.equal(out.template, false);
    const config = lf(written.get(join(CWD, "sealmark.yaml"))!);
    assert.match(config, /^name: filesystem$/m);
    assert.match(config, /command: npx/);
    assert.match(config, /"@modelcontextprotocol\/server-filesystem"/);
    assert.match(config, /\{sandbox\}/);
    await assert.rejects(runInit(base({ fromCommand: "", force: true })), /--from needs a command/);
  });

  it("--from-url writes an HTTP config", async () => {
    fresh();
    await runInit(base({ fromUrl: "https://example.test/mcp", env: winEnv({ read: () => undefined }) }));
    const config = lf(written.get(join(CWD, "sealmark.yaml"))!);
    assert.match(config, /^name: example\.test$/m);
    assert.match(config, /url: https:\/\/example\.test\/mcp/);
    await assert.rejects(runInit(base({ fromUrl: "not a url", force: true })), /needs a full URL/);
  });

  it("interactive: asks which servers, asks for input values, and asks about each replacement", async () => {
    fresh();
    const asked: string[] = [];
    const answers = ["11,12", "fake-pg-pass-123", "D:/data/fake"];
    const io: WizardIO = {
      ask: async (q) => {
        asked.push(q);
        return answers.shift() ?? "";
      },
      askSecret: async (q) => {
        asked.push(q);
        return answers.shift() ?? "";
      },
      write: () => {},
    };
    // 11 and 12 in the listing are the VS Code servers pg and data (the order is asserted in the scanClients test)
    const out = await runInit({ ...base({}), io });
    assert.deepEqual(out.selected.map((s) => s.name), ["pg", "data"]);
    assert.match(asked[0], /Which should sealmark grade/);
    assert.match(asked[1], /Value for pg-password \(Postgres password\)/);
    assert.match(asked[2], /Value for data-dir/);
    assert.equal(out.selected[0].local.env!.PGPASSWORD, "fake-pg-pass-123");
    assert.match(written.get(join(CWD, "sealmark.local.yaml"))!, /PGPASSWORD: fake-pg-pass-123/);
    assert.equal(lf(written.get(join(CWD, "sealmark.yaml"))!).includes("fake-pg-pass-123"), false);
  });

  it("interactive: declining a replacement keeps the original value", async () => {
    fresh();
    const answers = ["n"];
    const io: WizardIO = { ask: async () => answers.shift() ?? "", write: () => {} };
    const out = await runInit({ ...base({ select: ["cursor/fs"] }), io });
    assert.deepEqual(out.applied, []);
    assert.match(written.get(join(CWD, "sealmark.yaml"))!, /C:\/Users\/tester\/work\/demo/);
  });

  it("dryRun writes nothing", async () => {
    fresh();
    const out = await runInit(base({ select: ["weather"], dryRun: true }));
    assert.equal(written.size, 0);
    assert.deepEqual(out.written, []);
    assert.equal(out.plan!.files.length, 3);
  });
});

describe("runInit on the real file system", () => {
  it("writes files that load, and a second run needs --force", async () => {
    const dir = mkdtempSync(join(work, "real-"));
    const configPath = join(dir, "sealmark.yaml");
    const env = winEnv({ platform: process.platform, home: dir, cwd: dir, env: {}, read: () => undefined });
    const out = await runInit({ env, configPath, fromCommand: `"${process.execPath}" server.js --token=lit-token-1` });
    assert.equal(out.written.length, 3);
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    assert.equal(cfg.server.command, process.execPath.replace(/\\/g, "/"), "the command is written with forward slashes, which Node accepts on Windows");
    assert.deepEqual(cfg.server.args, ["server.js", "--token=lit-token-1"], "the local file's argument list replaces the project file's");
    assert.equal(readFileSync(configPath, "utf8").includes("lit-token-1"), false);
    assert.match(readFileSync(join(dir, ".gitignore"), "utf8"), /sealmark\.local\.yaml/);
    await assert.rejects(runInit({ env, configPath, fromCommand: "x" }), /already exists/);
  });
});

describe("readlineIO", () => {
  it("asks with a default, hides a secret, and closes", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let seen = "";
    output.on("data", (d: Buffer) => (seen += d.toString()));
    const io = readlineIO(input, output);
    input.write("\n");
    assert.equal(await io.ask("Pick one:", "all"), "all");
    input.write("  typed  \n");
    assert.equal(await io.ask("Name:"), "typed");
    input.write("fake-secret-value\n");
    assert.equal(await io.askSecret!("Key:"), "fake-secret-value");
    io.write("done\n");
    io.close();
    assert.match(seen, /Pick one: \[all\] /);
    assert.match(seen, /Key: \(input is hidden\)/);
    assert.equal(seen.includes("fake-secret-value"), false, "the secret is never written to the terminal");
    assert.match(seen, /done\n$/);
  });

  it("keeps lines that arrive together, and fails clearly when the input ends", async () => {
    const input = new PassThrough();
    const io = readlineIO(input, new PassThrough());
    input.write("first\nsecond\n");
    assert.equal(await io.ask("a?"), "first");
    assert.equal(await io.ask("b?"), "second");
    input.end();
    await assert.rejects(io.ask("c?"), /the input ended before every question was answered/);
    io.close();
  });
});
