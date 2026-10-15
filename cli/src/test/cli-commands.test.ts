import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { cliKit } from "./helpers.js";
import { parseXml } from "./shape.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-cli-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml, writeConfig, toyConfig, noClients, readJson } = cliKit(() => dir);

describe("cli: subcommands that do not run a server", { timeout: 120_000 }, () => {
  it("--version and --help", () => {
    assert.match(sealmark(["--version"]).out, /^sealmark \d+\.\d+\.\d+\n$/);
    const h = sealmark(["--help"]);
    assert.equal(h.code, 0);
    assert.match(h.out, /usage:\n {2}sealmark init/);
    assert.match(h.out, /exit codes:\n {2}0 /);
    assert.match(h.out, /--baseline <file>/);
  });

  it("config show prints the merged configuration with origins, and --json parses", () => {
    const cfg = toyConfig("nosql.yaml", "nosql");
    const text = sealmark(["config", "show", "--config", cfg, "--origins", "--profile", "quick"]);
    assert.equal(text.code, 0, text.err);
    assert.match(text.out, /^profile: quick {3}# flag --profile$/m);
    assert.match(text.out, /# profile:quick/);
    const json = JSON.parse(sealmark(["config", "show", "--config", cfg, "--json"]).out) as { value: { name: string }; origins: Record<string, unknown> };
    assert.equal(json.value.name, "cli-test");
    assert.ok(Object.keys(json.origins).length > 10);
  });

  it("config show redacts a secret in the server env", () => {
    const cfg = writeYaml("secret.yaml", `schema_version: 1\nname: s\nserver:\n  command: node\n  env:\n    SOME_TOKEN: "abc-very-secret-123"\n`);
    const r = sealmark(["config", "show", "--config", cfg]);
    assert.ok(!r.out.includes("abc-very-secret-123"));
  });

  it("config profiles lists shipped profiles with their standard-ness", () => {
    const text = sealmark(["config", "profiles"]);
    assert.equal(text.code, 0, text.err);
    assert.match(text.out, /^standard +shipped +yes/m);
    assert.match(text.out, /^quick +shipped +no/m);
    const json = JSON.parse(sealmark(["config", "profiles", "--json"]).out) as { profiles: { name: string; standard: boolean }[] };
    assert.deepEqual(json.profiles.slice(0, 3).map((p) => [p.name, p.standard]), [["standard", true], ["quick", false], ["ci", true]]);
  });

  it("config migrate rewrites an old file, keeps a backup, and is a no-op the second time", () => {
    const sub = mkdtempSync(join(dir, "migrate-"));
    const file = join(sub, "sealmark.yaml");
    writeFileSync(file, `schema_version: 0\nname: legacy\nserver:\n  command: node\ntimeout_probe: 5\nfail_under: B\n`);
    const r = sealmark(["config", "migrate"], sub);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /migrated .* from schema_version 0 to 1/);
    assert.match(readFileSync(file, "utf8"), /timeout_probe_sec: 5/);
    assert.match(readFileSync(`${file}.bak`, "utf8"), /timeout_probe: 5/);
    const again = sealmark(["config", "migrate"], sub);
    assert.equal(again.code, 0);
    assert.match(again.err, /already at schema_version 1/);
    const newer = writeYaml("newer.yaml", "schema_version: 99\nname: x\nserver: { command: node }\n");
    const n = sealmark(["config", "migrate", "--config", newer]);
    assert.equal(n.code, 2);
    assert.match(n.err, /upgrade sealmark/);
  });

  it("describe --json, list-checks and explain read the check registry", () => {
    const d = JSON.parse(sealmark(["describe", "--json"]).out) as { format: string; checks: { id: string }[]; cli: { commands: { name: string }[] } };
    assert.equal(d.format, "sealmark.describe/1");
    assert.ok(d.checks.some((c) => c.id === "protocol"));
    assert.ok(d.cli.commands.some((c) => c.name === "run"));
    const list = JSON.parse(sealmark(["list-checks", "--json", "--pack", "core"]).out) as { checks: { id: string; pack: string }[] };
    assert.ok(list.checks.length >= 4 && list.checks.every((c) => c.pack === "core"));
    assert.match(sealmark(["list-checks"]).out, /^ID +PACK +SEVERITY/m);
    assert.equal(sealmark(["list-checks", "--pack", "nope"]).code, 2);
    const e = sealmark(["explain", "protocol"]);
    assert.equal(e.code, 0, e.err);
    assert.match(e.out, /^protocol {2}\(pack core\)/);
    const miss = sealmark(["explain", "protocoll"]);
    assert.equal(miss.code, 2);
    assert.match(miss.err, /did you mean "protocol"/);
    assert.equal(sealmark(["explain"]).code, 2);
  });
});

const MODELINE = /^# yaml-language-server: \$schema=\.\/node_modules\/sealmark\/schema\/sealmark\.schema\.json\n/;
const HINT = /^# Editor schema: npm i -D sealmark adds \.\/node_modules\/sealmark\/schema\/sealmark\.schema\.json; the hosted copy is https:\/\/sealmark\.dev\/schema\/v1\/sealmark\.schema\.json after the next site deploy\n/;

describe("cli: init", { timeout: 120_000 }, () => {
  it("--from writes a loadable config, forward slashes, and gitignores the local file", () => {
    const cwd = mkdtempSync(join(dir, "from-"));
    const r = sealmark(["init", "--from", 'npx -y @scope/pkg@1.2.3 "C:\\Program Files\\data" {sandbox}'], cwd, noClients());
    assert.equal(r.code, 0, r.err);
    const text = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
    // No node_modules/sealmark/schema here, so the modeline would be an unresolved reference: a comment says how to get the schema instead.
    assert.match(text, HINT);
    assert.ok(!text.includes("yaml-language-server"), "no modeline in a bare directory");
    assert.match(text, /C:\/Program Files\/data/, "init writes forward slashes");
    assert.match(readFileSync(join(cwd, ".gitignore"), "utf8"), /^sealmark\.local\.yaml$/m);
    const shown = JSON.parse(sealmark(["config", "show", "--json"], cwd).out) as { value: { server: { command: string; args: string[] } } };
    assert.equal(shown.value.server.command, "npx");
    assert.deepEqual(shown.value.server.args, ["-y", "@scope/pkg@1.2.3", "C:/Program Files/data", "{sandbox}"]);
    const again = sealmark(["init", "--from", "x"], cwd, noClients());
    assert.equal(again.code, 2, "refuses to overwrite");
    assert.match(again.err, /already exists/);
  });

  it("--from-url writes a url server; a bad url or an empty --from is exit 2 and writes nothing", () => {
    const cwd = mkdtempSync(join(dir, "url-"));
    assert.equal(sealmark(["init", "--from-url", "http://127.0.0.1:9/mcp"], cwd, noClients()).code, 0);
    const shown = JSON.parse(sealmark(["config", "show", "--json"], cwd).out) as { value: { server: { url: string } } };
    assert.equal(shown.value.server.url, "http://127.0.0.1:9/mcp");
    const other = mkdtempSync(join(dir, "url-"));
    assert.equal(sealmark(["init", "--from-url", "not a url"], other, noClients()).code, 2);
    assert.equal(sealmark(["init", "--from", "  "], other, noClients()).code, 2);
    assert.equal(sealmark(["init", "--from", "a", "--from-url", "http://x/"], other, noClients()).code, 2);
    assert.ok(!existsSync(join(other, "sealmark.yaml")), "nothing is left behind after an error");
  });

  it("imports the MCP servers a client has configured (and does not touch the real ones in these tests)", () => {
    const cwd = mkdtempSync(join(dir, "client-"));
    writeFileSync(join(cwd, ".mcp.json"), JSON.stringify({ mcpServers: { demo: { command: "node", args: ["server.js", "--key", "literal-key-0123456789"], env: { MY_API_TOKEN: "tok-literal-1234567890" } } } }));
    const r = sealmark(["init", "--client", "claude-code"], cwd, noClients());
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /sealmark\.local\.yaml/);
    const yaml = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
    assert.ok(!yaml.includes("tok-literal-1234567890"), "a secret never goes into the committed file");
    assert.ok(existsSync(join(cwd, "sealmark.local.yaml")));
    assert.equal(sealmark(["init", "--client", "nope"], cwd, noClients()).code, 2);
  });

  it("with no client configuration it writes the commented template", () => {
    const cwd = mkdtempSync(join(dir, "tpl-"));
    const r = sealmark(["init"], cwd, noClients());
    assert.equal(r.code, 0, r.err);
    const text = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
    assert.match(text, HINT);
    assert.ok(!text.includes("yaml-language-server"), "no modeline in a bare directory");
    assert.match(r.err, /no MCP client configuration found/);
    assert.equal(sealmark(["config", "show", "--json"], cwd).code, 0, "the file still loads");
  });

  it("with node_modules/sealmark/schema/sealmark.schema.json installed it writes the modeline, for the template and for --from", () => {
    const cwd = mkdtempSync(join(dir, "installed-"));
    mkdirSync(join(cwd, "node_modules", "sealmark", "schema"), { recursive: true });
    writeFileSync(join(cwd, "node_modules", "sealmark", "schema", "sealmark.schema.json"), "{}");
    assert.equal(sealmark(["init"], cwd, noClients()).code, 0);
    const text = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
    assert.match(text, MODELINE);
    assert.ok(!text.includes("# Editor schema:"), "the comment is for the bare directory only");
    const from = mkdtempSync(join(dir, "installed-from-"));
    mkdirSync(join(from, "node_modules", "sealmark", "schema"), { recursive: true });
    writeFileSync(join(from, "node_modules", "sealmark", "schema", "sealmark.schema.json"), "{}");
    assert.equal(sealmark(["init", "--from", "node server.js"], from, noClients()).code, 0);
    assert.match(readFileSync(join(from, "sealmark.yaml"), "utf8"), MODELINE);
  });

  it("a node_modules/sealmark without the schema file, or launched by npx, still gets the comment (how it was launched does not matter, the file does)", () => {
    const cwd = mkdtempSync(join(dir, "pkg-only-"));
    mkdirSync(join(cwd, "node_modules", "sealmark"), { recursive: true });
    writeFileSync(join(cwd, "node_modules", "sealmark", "package.json"), '{"name":"sealmark"}');
    assert.equal(sealmark(["init", "--from", "node server.js"], cwd, { ...noClients(), npm_command: "run-script" }).code, 0);
    assert.match(readFileSync(join(cwd, "sealmark.yaml"), "utf8"), HINT);
  });
});

describe("cli: doctor and --fixture", { timeout: 120_000 }, () => {
  it("doctor reports a working toy server and exits 0", () => {
    const r = sealmark(["doctor", "--config", toyConfig("nosql.yaml", "nosql")]);
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /^sealmark doctor/);
    assert.match(r.out, /Classification:/);
    assert.match(r.out, /\nPacks\n/);
    const json = JSON.parse(sealmark(["doctor", "--json", "--config", toyConfig("nosql.yaml", "nosql")]).out) as { ok: boolean; exitCode: number };
    assert.equal(json.ok, true);
  });

  it("doctor exits 4 when the server cannot start, and 2 for an unknown --server", () => {
    const r = sealmark(["doctor", "--config", writeConfig("dead2.yaml", process.execPath, ["-e", "0"])]);
    assert.equal(r.code, 4, r.out);
    assert.match(r.out, /FAIL/);
    const m = sealmark(["doctor", "--config", toyConfig("nosql.yaml", "nosql"), "--server", "ghost"]);
    assert.equal(m.code, 2);
  });

  it("--fixture sqlite writes the sandbox's fixture database; unknown and unavailable fixtures are exit 2", () => {
    const into = join(dir, "fixture-out");
    const r = sealmark(["run", "--fixture", "sqlite", "--into", into]);
    if (r.code === 2 && /node:sqlite is not available/.test(r.err)) return; // Node older than 22.13
    assert.equal(r.code, 0, r.err);
    assert.ok(existsSync(join(into, "fixture.sqlite")));
    assert.equal(sealmark(["run", "--fixture", "sqlite", "--into", into]).code, 2, "refuses to overwrite");
    assert.equal(sealmark(["run", "--fixture", "nope"]).code, 2);
    assert.equal(sealmark(["run", "--fixture", "duckdb"]).code, 2);
  });
});

describe("shape helpers", () => {
  it("the xml parser used by the format tests accepts what the renderers emit", () => {
    assert.equal(parseXml('<?xml version="1.0"?><a x="1"><!-- c --><b/>t &amp; u</a>').children.length, 1);
  });
});

