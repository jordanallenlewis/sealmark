import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { schemaLineWanted } from "../config/wizard.js";
import { FAST, cliKit } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-ux-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, toyConfig, noClients } = cliKit(() => dir);

const lines = (s: string) => s.split("\n").filter((l) => l.trim() !== "");

describe("a usage error is one line and a hint, not the usage dump", () => {
  const short = (err: string) => {
    assert.ok(!/usage:|exit codes:|--fail-under <|\n {2}sealmark init/.test(err), `the usage dump is gone:\n${err.slice(0, 300)}`);
    assert.ok(lines(err).length <= 2, `at most an error and a hint:\n${err}`);
  };

  it("an unknown flag", () => {
    const r = sealmark(["run", "--bogus-flag"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /^sealmark: Unknown option '--bogus-flag'\n/);
    assert.match(r.err, /run sealmark --help for usage\n$/);
    assert.ok(!r.err.includes("To specify a positional argument"), "node's second sentence is trimmed");
    short(r.err);
  });

  it("a flag that does not apply to the command", () => {
    const r = sealmark(["list-checks", "--fail-under", "B"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /--fail-under does not apply to "sealmark list-checks"/);
    short(r.err);
  });

  it("an unknown command, and no command at all", () => {
    for (const args of [["frobnicate"], []]) {
      const r = sealmark(args);
      assert.equal(r.code, 2);
      assert.match(r.err, /run sealmark --help for usage/);
      short(r.err);
    }
  });

  it("an unknown check id says what to type next", () => {
    const r = sealmark(["explain", "nonexistent"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /unknown check "nonexistent"/);
    assert.match(r.err, /sealmark list-checks/);
    short(r.err);
  });

  it("explain with no id, and list-checks with an unknown pack", () => {
    const none = sealmark(["explain"]);
    assert.equal(none.code, 2);
    assert.match(none.err, /sealmark list-checks/);
    short(none.err);
    const pack = sealmark(["list-checks", "--pack", "nope"]);
    assert.equal(pack.code, 2);
    assert.match(pack.err, /sealmark list-checks to see every check id/);
    short(pack.err);
  });

  it("--help still prints the full usage", () => {
    const h = sealmark(["--help"]);
    assert.equal(h.code, 0);
    assert.match(h.out, /usage:\n {2}sealmark init/);
    assert.match(h.out, /exit codes:/);
  });
});

describe("init writes the $schema modeline only where it resolves", () => {
  const MODELINE = /^# yaml-language-server: \$schema=\.\/node_modules\/sealmark\/schema\/sealmark\.schema\.json\n/;
  const HINT = /^# Editor schema: npm i -D sealmark adds /;
  const npx = { npm_command: "exec" };
  const local = { npm_command: "run-script" };
  const installSchema = (cwd: string) => {
    mkdirSync(join(cwd, "node_modules", "sealmark", "schema"), { recursive: true });
    writeFileSync(join(cwd, "node_modules", "sealmark", "schema", "sealmark.schema.json"), "{}");
  };

  it("the decision: the modeline only where the schema file is installed, however sealmark was launched", () => {
    assert.equal(schemaLineWanted(true), true);
    assert.equal(schemaLineWanted(false), false);
  });

  it("with no installed schema file (npx, a global install, a project without sealmark): the template and --from output carry the hint comment, and still load", () => {
    for (const env of [npx, local, {}]) {
      const cwd = mkdtempSync(join(dir, "bare-"));
      const tpl = sealmark(["init"], cwd, { ...noClients(), ...env });
      assert.equal(tpl.code, 0, tpl.err);
      const text = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
      assert.ok(!text.includes("yaml-language-server"), text.slice(0, 200));
      assert.match(text, HINT);
      assert.equal(sealmark(["config", "show", "--json"], cwd, env).code, 0);

      const from = mkdtempSync(join(dir, "bare-from-"));
      assert.equal(sealmark(["init", "--from", "node server.js"], from, { ...noClients(), ...env }).code, 0);
      const fromText = readFileSync(join(from, "sealmark.yaml"), "utf8");
      assert.ok(!fromText.includes("yaml-language-server"));
      assert.match(fromText, HINT);
      assert.equal(sealmark(["config", "show", "--json"], from, env).code, 0);
    }
  });

  it("with the schema file installed beside the config: the modeline is written, via npx or not", () => {
    for (const env of [npx, local]) {
      const cwd = mkdtempSync(join(dir, "installed-"));
      installSchema(cwd);
      assert.equal(sealmark(["init", "--from", "node server.js"], cwd, { ...noClients(), ...env }).code, 0);
      assert.match(readFileSync(join(cwd, "sealmark.yaml"), "utf8"), MODELINE);
      const tpl = mkdtempSync(join(dir, "installed-tpl-"));
      installSchema(tpl);
      assert.equal(sealmark(["init"], tpl, { ...noClients(), ...env }).code, 0);
      assert.match(readFileSync(join(tpl, "sealmark.yaml"), "utf8"), MODELINE);
    }
  });

  it("a package folder without the schema file does not earn the modeline", () => {
    const cwd = mkdtempSync(join(dir, "pkg-only-"));
    mkdirSync(join(cwd, "node_modules", "sealmark"), { recursive: true });
    writeFileSync(join(cwd, "node_modules", "sealmark", "package.json"), '{"name":"sealmark"}');
    assert.equal(sealmark(["init", "--from", "node server.js"], cwd, { ...noClients(), ...npx }).code, 0);
    const text = readFileSync(join(cwd, "sealmark.yaml"), "utf8");
    assert.ok(!text.includes("yaml-language-server"));
    assert.match(text, HINT);
    assert.ok(existsSync(join(cwd, "sealmark.yaml")));
  });
});

describe("--verbosity verbose shows every robust-input call with its arguments", () => {
  const cfg = () => toyConfig("nosql.yaml", "nosql");

  it("verbose text lists each call (tool, variant, arguments, outcome); the default report does not", () => {
    const normal = sealmark(["run", "--config", cfg(), ...FAST]);
    assert.equal(normal.code, 0, normal.err);
    assert.ok(!normal.out.includes("schema-invalid call"), "no per-call lines by default");
    const verbose = sealmark(["run", "--config", cfg(), ...FAST, "--verbosity", "verbose"]);
    assert.equal(verbose.code, 0, verbose.err);
    assert.match(verbose.out, /\[protocol\] \S+: .+ \(schema-invalid call\) → (isError response|answered without isError|refused in text without isError)\n {12}args: \{/);
    assert.ok(verbose.out.split("\n").filter((l) => l.includes("(schema-invalid call)")).length >= 2, "one line per call, not one aggregate");
  });

  it("verbose markdown has them too, and no verdict or grade differs between the two runs", () => {
    const grades = (out: string) => out.split("\n").filter((l) => /^PACK |^\s+\[(PASS|PART|FAIL|INCL|N\/A )/.test(l)).join("\n");
    const normal = sealmark(["run", "--config", cfg(), ...FAST]);
    const verbose = sealmark(["run", "--config", cfg(), ...FAST, "--verbosity", "verbose"]);
    assert.equal(grades(verbose.out), grades(normal.out), "per-call evidence changes no verdict, grade or summary line");
    const md = sealmark(["run", "--config", cfg(), ...FAST, "--verbosity", "verbose", "--format", "markdown"]);
    assert.match(md.out, /\(schema-invalid call\) → .+ \(args: `\{/);
  });
});
