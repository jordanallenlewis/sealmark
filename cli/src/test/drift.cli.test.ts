import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import type { RunResult } from "../types.js";
import { cliKit } from "./helpers.js";

const DRIFT_TOY = fileURLToPath(new URL("../toy/drift.js", import.meta.url));

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-drift-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeYaml, readJson } = cliKit(() => dir);

/**
 * The toy's v2 description carries a rug-pull sentence on purpose, which the core pack's tool-poisoning check rightly fails. The
 * drift tests switch that one check off (like any user may) so the only change between the two runs is the surface; one test below
 * keeps it on to show both signals side by side.
 */
const config = (mode: string, poisoning = false): string =>
  writeYaml(
    `drift-${mode}${poisoning ? "-plain" : ""}.yaml`,
    `schema_version: 1\nname: cli-test\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([DRIFT_TOY, "--mode", mode])}\n${poisoning ? "" : "checks:\n  tool-poisoning:\n    enabled: false\n"}`,
  );
// Toy servers grade below A on purpose, so the gate is off; the point here is the surface, not the grades.
const FLAGS = ["--pack", "core", "--timeout-probe", "2", "--fail-under", "none"];
const v1File = () => join(dir, "v1.json");
const v2File = () => join(dir, "v2.json");
const v1Plain = () => join(dir, "v1-plain.json");

describe("drift: the command line, v1 against v2 of the toy drift server", { timeout: 300_000 }, () => {
  before(() => {
    const a = sealmark(["run", "--config", config("v1"), ...FLAGS, "--write-baseline", v1File()]);
    assert.equal(a.code, 0, a.err);
    const b = sealmark(["run", "--config", config("v2"), ...FLAGS, "--write-baseline", v2File()]);
    assert.equal(b.code, 0, b.err);
    const c = sealmark(["run", "--config", config("v1", true), ...FLAGS, "--write-baseline", v1Plain()]);
    assert.equal(c.code, 0, c.err);
  });

  const against = (...extra: string[]) => sealmark(["run", "--config", config("v2"), ...FLAGS, "--baseline", v1File(), ...extra]);

  it("--fail-on drift exits 1 with six drift lines and the reason", () => {
    const r = against("--fail-on", "drift");
    assert.equal(r.code, 1, r.err);
    assert.equal(r.err.match(/^drift: /gm)?.length, 6, r.err);
    assert.match(r.err, /^drift: server \S+: tool removed: delete_note$/m);
    assert.match(r.err, /^drift: server \S+, tool search: required parameter added: tenant$/m);
    assert.match(r.err, /^drift: server \S+, tool search: parameter limit type number -> string$/m);
    assert.match(r.err, /^drift: server \S+: tool added: purge$/m);
    assert.match(r.err, /^drift: server \S+, tool read_note: description changed \(sha [0-9a-f]{8} -> [0-9a-f]{8}, \d+ -> \d+ chars\)$/m);
    assert.match(r.err, /^drift: server \S+, tool read_note: annotations changed readOnlyHint true -> false$/m);
    assert.match(r.err, /sealmark exit 1: the tool surface drifted against the baseline/);
    assert.ok(!r.err.includes("Ignore previous instructions"), "a description body never reaches the output");
  });

  it("--fail-on regressions leaves the exit code alone and says how to fail on drift", () => {
    const r = against("--fail-on", "regressions");
    assert.equal(r.code, 0, r.err);
    assert.equal(r.err.match(/^drift: /gm)?.length, 6, r.err);
    assert.match(r.err, /^note: 6 tool-surface change\(s\) do not affect the exit code; add --fail-on drift to fail on them$/m);
  });

  it("the rug-pull sentence is also a real tool-poisoning regression; drift and regression are separate signals", () => {
    const r = sealmark(["run", "--config", config("v2", true), ...FLAGS, "--baseline", v1Plain(), "--fail-on", "regressions"]);
    assert.equal(r.code, 1, r.err);
    assert.match(r.err, /^regression: .*check tool-poisoning: pass -> fail/m);
    assert.equal(r.err.match(/^drift: /gm)?.length, 6, r.err);
  });

  it("--fail-on any,drift exits 1 too", () => {
    const r = against("--fail-on", "any,drift");
    assert.equal(r.code, 1, r.err);
    assert.match(r.err, /the tool surface drifted against the baseline/);
  });

  it("drift is not asked for by default: the grades decide, and the labels are untouched", () => {
    const r = against();
    assert.equal(r.code, 0, r.err);
    const out = join(dir, "default-run.json");
    const j = against("--format", "json", "--out", out);
    assert.equal(j.code, 0, j.err);
    assert.equal(readJson(out).config?.standard, false, "a --pack core run is custom, whatever the surface");
  });

  it("sealmark diff v1.json v2.json prints the lines and exits 1", () => {
    const r = sealmark(["diff", v1File(), v2File()]);
    assert.equal(r.code, 1, r.err);
    assert.equal(r.out.match(/^drift: /gm)?.length, 6, r.out);
    assert.match(r.out, /^drift: server \S+: tool removed: delete_note$/m);
    assert.ok(!/^drift: .*Ignore previous/m.test(r.out));
  });

  it("sealmark diff v1.json v1.json exits 0 and says no change", () => {
    const r = sealmark(["diff", v1File(), v1File()]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out.trim(), "no change");
  });

  it("sealmark diff --json prints sealmark.diff/1 with the six entries", () => {
    const r = sealmark(["diff", v1File(), v2File(), "--json"]);
    assert.equal(r.code, 1, r.err);
    const body = JSON.parse(r.out) as { format: string; regressions: unknown[]; improvements: unknown[]; notes: unknown[]; drift: { kind: string; severity: string; tool?: string }[] };
    assert.equal(body.format, "sealmark.diff/1");
    assert.deepEqual(Object.keys(body), ["format", "regressions", "improvements", "notes", "drift"]);
    assert.deepEqual(body.drift.map((e) => `${e.severity}:${e.kind}:${e.tool}`), [
      "breaking:tool-removed:delete_note",
      "breaking:required-added:search",
      "breaking:param-type-changed:search",
      "notable:tool-added:purge",
      "notable:description-changed:read_note",
      "notable:annotation-changed:read_note",
    ]);
  });

  it("a baseline written before 0.2.1 (server.surface deleted by hand) still reports tools removed, and says what it could not compare", () => {
    const old = readJson(v1File());
    delete old.server.surface;
    const oldFile = join(dir, "v1-old.json");
    writeFileSync(oldFile, JSON.stringify(old));
    const r = sealmark(["diff", oldFile, v2File()]);
    assert.equal(r.code, 1, r.err);
    assert.match(r.out, /^drift: server \S+: tools removed: delete_note \(baseline has no tool surface: names and annotations only\)$/m);
    assert.match(r.out, /^drift: server \S+: tools added: purge \(baseline has no tool surface/m);
  });

  it("the JSON report carries server.surface after redaction, hashes and types only", () => {
    const run = readJson<RunResult>(v2File());
    const surface = run.server.surface!;
    assert.deepEqual(surface.map((t) => t.name), ["purge", "read_note", "search"]);
    const search = surface.find((t) => t.name === "search")!;
    assert.deepEqual(search.required, ["query", "tenant"]);
    assert.deepEqual(search.params, { limit: "string", query: "string", tenant: "string" });
    assert.match(search.descriptionHash, /^[0-9a-f]{64}$/);
    assert.match(search.inputSchemaHash, /^[0-9a-f]{64}$/);
    assert.deepEqual(surface.find((t) => t.name === "read_note")!.annotations, { readOnlyHint: false });
    assert.ok(!JSON.stringify(surface).includes("Ignore previous"), "no description text in the surface");
  });
});
