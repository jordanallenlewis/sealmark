import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { rejectedBeforeRunning, type CallResult } from "../mcp.js";
import { runHarness } from "../run.js";
import { coverageTag } from "../report/common.js";
import type { PackId, RunResult } from "../types.js";
import { cliKit, q } from "./helpers.js";

// The coverage rule (types.ts, CheckCoverage.validCalls): a call counts when it was schema-valid AND the server processed it.
// A tool that the config says is a URL tool but that answers every URL with a validation error was never exercised, so the
// run stays hygiene-only however many calls the net pack made.
const STRICT = fileURLToPath(new URL("../toy/time-strict.js", import.meta.url));
const NET = fileURLToPath(new URL("../toy/net.js", import.meta.url));
const PLUGIN_NAME ="inconclusive-plugin.mjs";

let dir: string;
let parent: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r4-coverage-"));
  parent = join(dir, "sandboxes");
  mkdirSync(parent);
  // A pack that reports a lot of "valid calls" and judges nothing: every check inconclusive.
  writeFileSync(
    join(dir, PLUGIN_NAME),
    `export default {
  id: "plugin:noop", version: "1.0.0", sealmark: "*",
  describe: () => [{ id: "noop-check", pack: "plugin:noop", label: "Noop", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  run: async () => [{ id: "noop-check", pack: "plugin:noop", label: "[plugin:noop] Noop", critical: false, scope: "server", verdict: "inconclusive", summary: "nothing could be judged", evidence: [], coverage: { probed: ["get_time"], notCovered: [], validCalls: 7 } }],
};\n`,
  );
});
after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));
const { writeYaml, sealmark } = cliKit(() => dir);

const asUrlTool = `tools:\n  overrides:\n    get_time: { class: url, params: { url: timezone } }\n`;
function runTime(name: string, mode: "strict" | "lenient", extra = asUrlTool): RunResult {
  const cfg = writeYaml(`${name}.yaml`, `name: ${name}\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([STRICT, "--mode", mode])}\nsandbox:\n  dir: ${q(parent)}\n${extra}`);
  const r = sealmark(["run", "--config", cfg, "--pack", "core", "--pack", "net", "--timeout-probe", "2", "--fail-under", "none", "--format", "json"]);
  assert.ok(r.out.trim().startsWith("{"), `no JSON report: ${r.err}`);
  return JSON.parse(r.out) as RunResult;
}

function runNet(mode: string): RunResult {
  const cfg = writeYaml(`net-${mode}.yaml`, `name: net-${mode}\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([NET, "--mode", mode])}\nsandbox:\n  dir: ${q(parent)}\n`);
  const r = sealmark(["run", "--config", cfg, "--pack", "core", "--pack", "net", "--timeout-probe", "2", "--fail-under", "none", "--format", "json"]);
  assert.ok(r.out.trim().startsWith("{"), `no JSON report: ${r.err}`);
  return JSON.parse(r.out) as RunResult;
}

describe("r4-harness: rejectedBeforeRunning tells a call that never reached the tool from one the tool refused", () => {
  const reply = (o: Partial<CallResult>): CallResult => ({ isError: false, text: "", elapsedMs: 1, timedOut: false, closed: false, ...o });
  it("protocol failures, timeouts and closed connections never reached the tool", () => {
    assert.equal(rejectedBeforeRunning(reply({ isError: true, rpcError: "MCP error -32602: Invalid params" })), true);
    assert.equal(rejectedBeforeRunning(reply({ isError: true, timedOut: true })), true);
    assert.equal(rejectedBeforeRunning(reply({ isError: true, closed: true })), true);
  });
  it("an isError text that says invalid or expected and names a parameter is a validation error", () => {
    assert.equal(rejectedBeforeRunning(reply({ isError: true, text: "Invalid arguments: expected string for property 'url'" })), true);
    assert.equal(rejectedBeforeRunning(reply({ isError: true, text: "invalid timezone: expected an IANA zone name" }), { timezone: "http://x/" }), true, "the sent key is named");
  });
  it("near-misses: a success, and a refusal that says nothing about the arguments, did reach the tool", () => {
    assert.equal(rejectedBeforeRunning(reply({ text: "ok" })), false);
    assert.equal(rejectedBeforeRunning(reply({ text: "invalid timezone: expected an IANA zone name" }), { timezone: "UTC" }), false, "not an error reply");
    assert.equal(rejectedBeforeRunning(reply({ isError: true, text: "access denied: that address is private" }), { url: "http://10.0.0.1/" }), false);
    assert.equal(rejectedBeforeRunning(reply({ isError: true, text: "service unavailable" })), false);
  });
});

describe("r4-harness: coverage counts calls the server processed", { timeout: 240_000 }, () => {
  it("a tool overridden to a URL class that answers every URL with a validation error leaves the run hygiene-only", () => {
    const r = runTime("strict-url", "strict");
    assert.equal(r.classification?.find((c) => c.tool === "get_time")?.class, "url", "the override took effect");
    assert.equal(r.coverage?.level, "hygiene-only", JSON.stringify({ coverage: r.coverage, net: r.packs.net }));
    assert.equal(r.coverage?.validCalls, 0);
    assert.equal(r.coverage?.toolsCalledValid, 0);
    assert.match(coverageTag(r) ?? "", /^hygiene only/);
    assert.ok(
      // The net pack's own counter (A6) already counts none of these calls, so the line is the pack's "not probed" reason; the
      // harness's "calls do not count" line is the backstop for a pack that reports more than it judged (the plugin case below).
      r.notCovered.some((l) => /the net pack's calls do not count toward coverage|was not probed by the net pack/.test(l)),
      `the report says what it did not count:\n${r.notCovered.join("\n")}`,
    );
  });

  it("a fetch tool whose every fetch failed (no network) judged nothing, so its calls do not count either", () => {
    const r = runNet("dead");
    assert.equal(r.packs.net?.status, "inconclusive", JSON.stringify(r.packs.net));
    // The net pack counts none of its errored fetches itself (A6); the harness backstop would drop them if it did.
    assert.ok(r.checks.filter((c) => c.pack === "net").every((c) => (c.coverage?.validCalls ?? 0) === 0), JSON.stringify(r.checks.filter((c) => c.pack === "net").map((c) => c.coverage)));
    assert.equal(r.coverage?.level, "hygiene-only", JSON.stringify(r.coverage));
    assert.equal(r.coverage?.validCalls, 0);
    assert.equal(r.coverage?.toolsCalledValid, 0);
  });

  it("near-miss: a fetch tool the net pack could judge is exercised, so its calls count and the tag is gone", () => {
    const r = runNet("good");
    assert.equal(r.packs.net?.status, "graded", JSON.stringify(r.packs.net));
    assert.notEqual(r.coverage?.level, "hygiene-only", JSON.stringify(r.coverage));
    assert.ok((r.coverage?.validCalls ?? 0) > 0);
    assert.equal(r.coverage?.toolsCalledValid, 1);
    assert.equal(coverageTag(r), undefined);
    assert.ok(!r.notCovered.some((l) => /calls do not count toward coverage/.test(l)), r.notCovered.join("\n"));
  });

  it("a pack whose checks are all inconclusive contributes no valid calls and no probed tools, whatever it reported", async () => {
    const cfg = writeYaml("plugin.yaml", `name: plugin\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([STRICT, "--mode", "strict"])}\nsandbox:\n  dir: ${q(parent)}\nplugins:\n  - { module: ./${PLUGIN_NAME} }\n`);
    const eff = loadEffectiveConfig({ cwd: dir, flags: { config: cfg }, env: {}, isolated: true });
    const r = await runHarness({ config: { name: eff.name, version: eff.version, server: eff.server }, effective: eff, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: () => {} });
    assert.ok(r.checks.some((c) => c.id === "noop-check" && c.coverage?.validCalls === 7), "the plugin did report 7 valid calls");
    assert.equal(r.coverage?.validCalls, 0, JSON.stringify(r.coverage));
    assert.equal(r.coverage?.level, "hygiene-only");
    assert.ok(r.notCovered.some((l) => /the plugin:noop pack's calls do not count toward coverage/.test(l)), r.notCovered.join("\n"));
    // Core had no valid call either, which is why the level is where it is.
    const packs = r.packs as Partial<Record<PackId, unknown>>;
    assert.ok(packs["plugin:noop" as PackId]);
  });
});
