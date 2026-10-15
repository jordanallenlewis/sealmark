import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { CLOSING_LINE } from "../report.js";
import { METHODOLOGY } from "../config/index.js";
import type { RunResult } from "../types.js";
import { FAST, cliKit, q, srv } from "./helpers.js";
import { kids, validateJunit, validateSarifShape } from "./shape.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-cli-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml, writeConfig, toyConfig, noClients, readJson } = cliKit(() => dir);

describe("cli: servers matrix", { timeout: 300_000 }, () => {
  const cfg = () => writeYaml("matrix.yaml", `schema_version: 1\nname: matrix\nversion: 1.0.0\nservers:\n  clean:\n    ${srv("nosql")}\n  poisoned:\n    ${srv("poison")}\n`);

  it("runs every server, prints { runs } for json and exits with the worst code", () => {
    const r = sealmark(["run", "--config", cfg(), ...FAST, "--format", "json", "--fail-under", "B"]);
    const parsed = JSON.parse(r.out) as { runs: RunResult[] };
    assert.deepEqual(parsed.runs.map((x) => x.server.name), ["clean", "poisoned"]);
    assert.equal(parsed.runs[0].packs.core?.grade?.letter, "A");
    assert.equal(parsed.runs[1].packs.core?.grade?.letter, "D");
    assert.equal(r.code, 1, r.err);
    assert.match(r.err, /server poisoned: pack core graded D, below --fail-under B/);
    assert.match(r.err, /^clean: core A \(hygiene only\)/m);
  });

  it("--server picks one entry, and a single run is a plain RunResult", () => {
    const r = sealmark(["run", "--config", cfg(), ...FAST, "--format", "json", "--server", "clean"]);
    assert.equal(r.code, 0, r.err);
    const parsed = JSON.parse(r.out) as RunResult;
    assert.equal(parsed.server.name, "clean");
    assert.ok(!("runs" in parsed));
  });

  it("--server with an unknown name is a config error with a suggestion", () => {
    const r = sealmark(["run", "--config", cfg(), ...FAST, "--server", "cleen"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /no server named "cleen".*did you mean "clean"/);
  });

  it("text output prints one block per server and a Matrix summary", () => {
    const r = sealmark(["run", "--config", cfg(), ...FAST]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out.match(/^sealmark \S+ · methodology/gm)?.length, 2);
    assert.match(r.out, /Matrix:\n {2}clean +core A/);
  });
});

describe("cli: baseline ratchet", { timeout: 300_000 }, () => {
  const good = () => toyConfig("nosql.yaml", "nosql");
  const bad = () => toyConfig("bad.yaml", "bad");

  it("flags a regression and only a regression", () => {
    const base = join(dir, "ratchet-good.json");
    const w = sealmark(["run", "--config", good(), ...FAST, "--write-baseline", base, "--format", "json", "--out", join(dir, "w.json")]);
    assert.equal(w.code, 0, w.err);
    assert.match(w.err, /baseline written to /);
    // same server again: nothing regressed
    const same = sealmark(["run", "--config", good(), ...FAST, "--baseline", base, "--format", "json", "--out", join(dir, "same.json")]);
    assert.equal(same.code, 0, same.err);
    assert.doesNotMatch(same.err, /regression/);
    // a worse server: regression, exit 1, and the baseline is not overwritten
    const base2 = join(dir, "ratchet-worse.json");
    const worse = sealmark(["run", "--config", bad(), ...FAST, "--baseline", base, "--write-baseline", base2, "--format", "json", "--out", join(dir, "worse.json")]);
    assert.equal(worse.code, 1, worse.err);
    assert.match(worse.err, /regression: server cli-test, pack core: grade dropped A -> F/);
    assert.match(worse.err, /regression: server cli-test, check \w[\w-]*: pass -> fail/);
    assert.match(worse.err, /baseline not written to .*the run regressed against the baseline/);
    assert.ok(!existsSync(base2));
  });

  it("an improvement is not a regression; --fail-on regressions ignores --fail-under", () => {
    const badBase = join(dir, "ratchet-bad.json");
    const w = sealmark(["run", "--config", bad(), ...FAST, "--write-baseline", badBase, "--format", "json", "--out", join(dir, "b.json")]);
    assert.equal(w.code, 0, w.err);
    const better = sealmark(["run", "--config", good(), ...FAST, "--baseline", badBase, "--fail-under", "A", "--format", "json", "--out", join(dir, "better.json")]);
    assert.equal(better.code, 0, better.err);
    assert.match(better.err, /baseline: improved: server cli-test, pack core: grade rose F -> A/);
    // F is below --fail-under A, but nothing regressed against an F baseline
    const gate = sealmark(["run", "--config", bad(), ...FAST, "--baseline", badBase, "--fail-under", "A", "--format", "json", "--out", join(dir, "g1.json")]);
    assert.equal(gate.code, 1, gate.err);
    assert.match(gate.err, /below --fail-under A/);
    const only = sealmark(["run", "--config", bad(), ...FAST, "--baseline", badBase, "--fail-under", "A", "--fail-on", "regressions", "--format", "json", "--out", join(dir, "g2.json")]);
    assert.equal(only.code, 0, only.err);
  });
});

describe("cli: output formats", { timeout: 300_000 }, () => {
  it("--out-dir writes every format named in output.formats, each valid for its schema shape", () => {
    const cfg = writeYaml("formats.yaml", `schema_version: 1\nname: fmt\nversion: 1.0.0\nserver:\n  ${srv("poison", 2)}\noutput:\n  formats: [text, json, markdown, junit, sarif]\n`);
    const outDir = join(dir, "report-out");
    const r = sealmark(["run", "--fail-under", "none", "--config", cfg, ...FAST, "--out-dir", outDir]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, "");
    const text = readFileSync(join(outDir, "sealmark-report.txt"), "utf8");
    assert.match(text, /CUSTOM/);
    const json = readJson(join(outDir, "sealmark-report.json"));
    assert.equal(json.packs.core?.grade?.letter, "D");
    const md = readFileSync(join(outDir, "sealmark-report.md"), "utf8");
    assert.match(md, /^# Sealmark report: fmt 1\.0\.0\n/);
    const junit = validateJunit(readFileSync(join(outDir, "sealmark-report.junit.xml"), "utf8"));
    const core = junit.children.find((s) => s.attrs.name === "core")!;
    assert.equal(core.attrs.failures, "1", "the poisoning check fails");
    assert.ok(kids(core, "testcase").some((c) => kids(c, "failure").length === 1 && c.attrs.name.startsWith("tool-poisoning")));
    const sarif = validateSarifShape(readFileSync(join(outDir, "sealmark-report.sarif"), "utf8"));
    assert.ok(sarif.runs[0].results.some((x: { ruleId: string; level: string }) => x.ruleId === "tool-poisoning" && x.level === "error"));
    assert.match(r.err, /^core D \(hygiene only\) capped: critical fail: tool-poisoning · custom$/m);
  });

  it("--format junit, sarif and markdown to stdout are well formed", () => {
    const junit = sealmark(["run", "--fail-under", "none", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--format", "junit"]);
    assert.equal(junit.code, 0, junit.err);
    validateJunit(junit.out);
    const sarif = sealmark(["run", "--fail-under", "none", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--format", "sarif"]);
    validateSarifShape(sarif.out);
    const md = sealmark(["run", "--fail-under", "none", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--format", "markdown"]);
    assert.match(md.out, /^# Sealmark report: /);
  });

  it("--template shapes the body but the CUSTOM label and the closing sentence stay", () => {
    const tpl = writeYaml("t.hbs", "NAME={{server.name}} {{#each packList}}[{{id}} {{status}}]{{/each}}\n");
    const r = sealmark(["run", "--fail-under", "none", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--template", tpl]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, new RegExp(`^sealmark \\S+ · methodology ${METHODOLOGY.replace(/\./g, "\\.")} · CUSTOM`));
    assert.match(r.out, /NAME=cli-test \[core graded\]/);
    assert.ok(r.out.trimEnd().endsWith(CLOSING_LINE));
    assert.equal(sealmark(["run", "--fail-under", "none", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--template", join(dir, "nope.hbs")]).code, 2);
  });

  it("--verbosity quiet hides passing checks and progress lines", () => {
    const r = sealmark(["run", "--config", toyConfig("p.yaml", "poison"), ...FAST, "--verbosity", "quiet"]);
    assert.doesNotMatch(r.out, /\[PASS\]/);
    assert.match(r.out, /\[FAIL\] No tool-poisoning/);
    assert.doesNotMatch(r.err, /starting the server/);
  });
});

