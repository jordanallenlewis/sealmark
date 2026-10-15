// Coverage counts a probe call only when the tool did something with it: a schema-valid call that the tool refused exercised no behaviour.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { discountUncounted, type ProbeCall, type ValidCalls } from "../probes.js";
import { coverageTag } from "../report/common.js";
import { runHarness } from "../run.js";
import type { CheckCoverage, PackId, RunResult } from "../types.js";

const HANG = fileURLToPath(new URL("../toy/hang.js", import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;

async function run(name: string, probes: string): Promise<RunResult> {
  const file = join(dir, name);
  writeFileSync(file, `schema_version: 1\nname: ${name.replace(/\W/g, "-")}\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "iserror"]\nsandbox:\n  dir: ${q(parent)}\npacks: [core]\nprobes:\n${probes}`);
  const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
  return runHarness({ config: { name: eff.name, version: eff.version, server: eff.server }, effective: eff, packs: eff.packs as PackId[], packsExplicit: true, timeoutProbeSec: 2, log: () => {} });
}

describe("harness-core: coverage counts only calls that succeeded", { timeout: 180_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-hc-coverage-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  it("a coverage-only probe the tool refuses leaves the level hygiene-only and warns, naming the probe", async () => {
    const r = await run("refused.yaml", `  - { id: lookup-missing, tool: lookup, args: { key: nobody } }\n`);
    assert.equal(r.coverage?.level, "hygiene-only");
    assert.equal(r.coverage?.validCalls, 0);
    assert.equal(r.coverage?.toolsCalledValid, 0);
    assert.match(coverageTag(r) ?? "", /^hygiene only/);
    assert.ok(r.warnings?.includes("probe lookup-missing returned an error and does not count toward coverage"), JSON.stringify(r.warnings));
    // The call was made and is on record; it is only not counted.
    const call = r.probes?.calls[0] as ProbeCall | undefined;
    assert.equal(call?.isError, true);
    assert.equal(call?.valid, true);
    assert.equal(call?.counted, false);
    // The tool is named as not covered by the robust-input check instead of silently dropped.
    const robust = r.checks.find((c) => c.id === "robust-input");
    assert.deepEqual(robust?.coverage?.notCovered.map((n) => n.tool), ["lookup"]);
  });

  it("a probe whose call succeeds raises the level, and the tag goes", async () => {
    const r = await run("accepted.yaml", `  - { id: lookup-known, tool: lookup, args: { key: known } }\n`);
    assert.equal(r.coverage?.level, "covered");
    assert.equal(r.coverage?.validCalls, 1);
    assert.equal(r.coverage?.toolsCalledValid, 1);
    assert.equal(coverageTag(r), undefined);
    assert.equal((r.probes?.calls[0] as ProbeCall | undefined)?.counted, true);
    assert.ok(!(r.warnings ?? []).some((w) => /does not count toward coverage/.test(w)));
  });

  it("a refused call next to a successful one: only the successful one counts", async () => {
    const r = await run("mixed.yaml", `  - { id: lookup-missing, tool: lookup, args: { key: nobody } }\n  - { id: note-ok, tool: note, args: { text: hi } }\n`);
    assert.equal(r.coverage?.validCalls, 1);
    assert.equal(r.coverage?.toolsCalledValid, 1);
    assert.deepEqual(r.checks.find((c) => c.id === "robust-input")?.coverage?.probed, ["note"]);
    assert.equal(r.warnings?.filter((w) => /does not count toward coverage/.test(w)).length, 1);
  });

  it("a call that succeeded but missed its expectation does not count either, and says so", async () => {
    const r = await run("missed.yaml", `  - { id: note-nomatch, tool: note, args: { text: hi }, expect: { text: { matches: "^never" } } }\n`);
    assert.equal(r.coverage?.level, "hygiene-only");
    assert.ok(r.warnings?.includes("probe note-nomatch did not hold its expectations and does not count toward coverage"), JSON.stringify(r.warnings));
  });
});

describe("harness-core: discountUncounted", () => {
  const call = (tool: string, counted: boolean): ProbeCall => ({ tool, args: {}, isError: !counted, elapsedMs: 1, excerpt: "", valid: true, counted, misses: [] });
  const v = (calls: ProbeCall[]): ValidCalls => ({
    calls,
    seen: [],
    validCalls: calls.filter((c) => c.counted).length,
    schemaValidCalls: calls.length,
    tools: [...new Set(calls.map((c) => c.tool))],
    countedTools: [...new Set(calls.filter((c) => c.counted).map((c) => c.tool))],
    warnings: [],
  });
  const cov: CheckCoverage = { probed: ["a", "b"], notCovered: [], validCalls: 2 };

  it("takes a tool whose only call was refused out of the probed list, with a reason", () => {
    const out = discountUncounted(cov, v([call("a", true), call("b", false)]), () => false);
    assert.deepEqual(out.probed, ["a"]);
    assert.equal(out.validCalls, 1);
    assert.deepEqual(out.notCovered.map((n) => n.tool), ["b"]);
  });

  it("keeps a tool that robust-input called validly itself, or that another call reached", () => {
    assert.deepEqual(discountUncounted(cov, v([call("a", true), call("b", false)]), (t) => t === "b").probed, ["a", "b"]);
    const both = discountUncounted(cov, v([call("a", true), call("a", false)]), () => false);
    assert.deepEqual(both.probed, ["a", "b"]);
    assert.equal(both.validCalls, 1);
  });

  it("returns the very same object when every call counted", () => {
    assert.equal(discountUncounted(cov, v([call("a", true), call("b", true)]), () => false), cov);
  });
});
