import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { INIT_TEMPLATE, TEMPLATE_COMMAND } from "../config.js";
import { cliKit, TOY } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-usability-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, noClients } = cliKit(() => dir);
const fresh = (name: string) => mkdtempSync(join(dir, `${name}-`));

describe("the init template cannot grade a real server by accident", { timeout: 120_000 }, () => {
  it("names no real package, and its server command is the placeholder", () => {
    assert.ok(!/@modelcontextprotocol\/server-/.test(INIT_TEMPLATE), "no real, named package in the template");
    assert.ok(!/\bnpx -y\b|"-y"/.test(INIT_TEMPLATE.split("\n").filter((l) => !l.trimStart().startsWith("#")).join("\n")), "no active npx line in the template");
    assert.match(INIT_TEMPLATE, new RegExp(`^ {2}command: ${TEMPLATE_COMMAND}$`, "m"));
    assert.match(INIT_TEMPLATE, /REPLACE THIS/);
  });

  it("init writes it, config show loads it, and run refuses it with exit 2 and a clear message (no server is started)", () => {
    const cwd = fresh("tpl");
    const init = sealmark(["init"], cwd, noClients());
    assert.equal(init.code, 0, init.err);
    assert.ok(existsSync(join(cwd, "sealmark.yaml")));
    assert.equal(sealmark(["config", "show"], cwd).code, 0, "the template is a valid configuration");
    const run = sealmark(["run", "--pack", "core"], cwd, noClients());
    assert.equal(run.code, 2, run.out + run.err);
    assert.match(run.err, /server\.command is still "your-mcp-server"/);
    assert.match(run.err, /init --from/);
  });

  it("doctor fails on the placeholder without looking for it on PATH or downloading anything", () => {
    const cwd = fresh("tpl-doctor");
    assert.equal(sealmark(["init"], cwd, noClients()).code, 0);
    const r = sealmark(["doctor"], cwd, noClients());
    assert.notEqual(r.code, 0, r.out);
    assert.match(r.out, /server\.command is still the placeholder "your-mcp-server"/);
    assert.doesNotMatch(r.out, /npx.*downloads|was not found/);
  });

  it("once the command is replaced the same file runs", () => {
    const cwd = fresh("tpl-edit");
    sealmark(["init"], cwd, noClients());
    const file = join(cwd, "sealmark.yaml");
    writeFileSync(file, readFileSync(file, "utf8").replace(`command: ${TEMPLATE_COMMAND}`, `command: ${JSON.stringify(process.execPath)}`).replace("args: []", `args: ${JSON.stringify([TOY, "--mode", "nosql"])}`));
    const r = sealmark(["run", "--pack", "core", "--timeout-probe", "2"], cwd, noClients());
    assert.equal(r.code, 0, r.err + r.out);
  });
});

describe("init without a terminal takes the defaults, including for several servers", { timeout: 120_000 }, () => {
  const mcp = JSON.stringify({ mcpServers: { alpha: { command: "node", args: ["a.js"] }, beta: { command: "node", args: ["b.js"] } } });

  for (const flags of [[], ["--yes"]]) {
    it(`sealmark init ${flags.join(" ")} with two servers in .mcp.json takes both, says so, and exits 0`, () => {
      const cwd = fresh("two");
      writeFileSync(join(cwd, ".mcp.json"), mcp);
      const r = sealmark(["init", "--client", "claude-code", ...flags], cwd, noClients());
      assert.equal(r.code, 0, r.err);
      assert.match(r.err, /2 MCP servers found \(.*alpha.*beta.*\)/);
      assert.match(r.err, /all of them are taken/);
      const yaml = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
      assert.match(yaml, /^servers:/m);
      assert.match(yaml, /alpha:/);
      assert.match(yaml, /beta:/);
      const shown = JSON.parse(sealmark(["config", "show", "--json"], cwd).out) as { value: { servers: Record<string, unknown> } };
      assert.deepEqual(Object.keys(shown.value.servers).sort(), ["alpha", "beta"]);
    });
  }

  it("--server still narrows the choice", () => {
    const cwd = fresh("two-pick");
    writeFileSync(join(cwd, ".mcp.json"), mcp);
    const r = sealmark(["init", "--client", "claude-code", "--server", "beta"], cwd, noClients());
    assert.equal(r.code, 0, r.err);
    assert.doesNotMatch(readFileSync(join(cwd, "sealmark.yaml"), "utf8"), /alpha/);
  });
});

describe("doctor and run agree on the packs that apply", { timeout: 120_000 }, () => {
  it("a database server (--dsn {dsn}) reports `packs applied: db`, not sqlite", () => {
    const cwd = fresh("doctor-db");
    writeFileSync(join(cwd, "sealmark.yaml"), `schema_version: 1\nname: t\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--mode", "good", "--dsn", "{dsn}"])}\n`);
    const r = sealmark(["doctor"], cwd, noClients());
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /packs applied: core, db\n/);
    assert.doesNotMatch(r.out, /packs applied: .*sqlite/);
    assert.match(r.out, /\n {2}db {7}would run/);
    assert.match(r.out, /\n {2}sqlite {3}n\/a {8}no \{sqlite_path\} placeholder/);
  });

  it("a SQL tool with no database placeholder lists no db or sqlite pack as applied", () => {
    const cwd = fresh("doctor-nodb");
    writeFileSync(join(cwd, "sealmark.yaml"), `schema_version: 1\nname: t\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--mode", "nosql"])}\n`);
    const r = sealmark(["doctor", "--json"], cwd, noClients());
    const j = JSON.parse(r.out) as { servers: { classificationText?: string[] }[] };
    const line = (j.servers[0]!.classificationText ?? []).find((l) => /packs applied/.test(l)) ?? "";
    assert.doesNotMatch(line, /\bdb\b|sqlite/);
  });
});
