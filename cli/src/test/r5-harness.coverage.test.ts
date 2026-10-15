import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import type { ProbeSpec } from "../config/model.js";
import { McpSession } from "../mcp.js";
import { reportsFailedUpstream, runProbe, runValidCalls, validateProbes } from "../probes.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import { createSandbox } from "../sandbox.js";
import type { ConfigIntegrity, EffectiveConfig, PackId, RunResult, Sandbox, SealmarkConfig } from "../types.js";
import { quiet } from "./helpers.js";

// Round 5, G10 (items h-3, h-4, h-5): coverage counts only calls that exercised a tool, and a custom `files.created` expectation does
// not depend on what an earlier pack left behind. Coverage is verdict-neutral: `badgeFor` never reads it.

const FETCH_TOY = fileURLToPath(new URL("../toy/r5-failed-fetch.js", import.meta.url));
const PROBES_TOY = fileURLToPath(new URL("../toy/probes.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} };

const toy = (script: string, mode: string): SealmarkConfig => ({ name: `toy-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [script, "--mode", mode], env: {} } });

let dir: string;
let parent: string;
let sb: Sandbox;

function effective(config: SealmarkConfig, probes: ProbeSpec[], packs: PackId[]): EffectiveConfig {
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: false, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, probes, sandbox: { ...base.sandbox, dir: parent } };
}
const run = (config: SealmarkConfig, probes: ProbeSpec[], packs: PackId[]): Promise<RunResult> =>
  runHarness({ config, effective: effective(config, probes, packs), packs, packsExplicit: false, timeoutProbeSec: 2, log: quiet });

describe("r5-harness: coverage counts only calls that exercised a tool", { timeout: 900_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r5-coverage-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    sb = await createSandbox({ dir: parent });
  });
  after(async () => {
    await sb.destroy().catch(() => {});
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  const open = (script: string, mode: string) => McpSession.open(toy(script, mode).server, { vars: {}, dsns: {} }, { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed" });

  describe("the vocabulary", () => {
    it("a reply that says the upstream request failed does not count; an ordinary one does; an isError reply is the rejection rule's, not this one's", () => {
      assert.equal(reportsFailedUpstream({ text: 'Error searching "x": TypeError: fetch failed' }), true);
      assert.equal(reportsFailedUpstream({ text: "search failed: ECONNREFUSED 10.0.0.1:443" }), true);
      assert.equal(reportsFailedUpstream({ text: "upstream: fetch failed" }), true);
      assert.equal(reportsFailedUpstream({ text: "Found 3 results for x" }), false);
      assert.equal(reportsFailedUpstream({ text: "" }), false);
      assert.equal(reportsFailedUpstream({ isError: true, text: "Error: fetch failed" }), false);
    });
  });

  describe("probes without a check (h-3)", () => {
    const probe: ProbeSpec = { id: "find", tool: "search", args: { query: "alpha" } };

    it("a probe whose reply says 'Error ...: fetch failed' without isError is a valid call but is not counted, and the warning names the rule", async () => {
      const s = await open(FETCH_TOY, "failed");
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        const v = await runValidCalls({ session: s, tools: s.tools, classification, sandbox: sb, active: false, probes: [probe] });
        assert.equal(v.calls[0]!.isError, false, "the toy never sets isError: that is the point");
        assert.equal(v.calls[0]!.valid, true);
        assert.equal(v.calls[0]!.counted, false);
        assert.equal(v.validCalls, 0);
        assert.deepEqual(v.countedTools, []);
        assert.ok(v.warnings.some((w) => /the reply reports a failed upstream request and does not count toward coverage/.test(w)), v.warnings.join("\n"));
      } finally {
        await s.close();
      }
    });

    it("near-miss: the same probe against an answering server is counted, with no warning", async () => {
      const s = await open(FETCH_TOY, "ok");
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        const v = await runValidCalls({ session: s, tools: s.tools, classification, sandbox: sb, active: false, probes: [probe] });
        assert.equal(v.calls[0]!.counted, true);
        assert.equal(v.validCalls, 1);
        assert.deepEqual(v.countedTools, ["search"]);
        assert.deepEqual(v.warnings, []);
      } finally {
        await s.close();
      }
    });

    it("an isError reply keeps its own warning (the rejection rule)", async () => {
      const s = await open(FETCH_TOY, "plain-error");
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        const v = await runValidCalls({ session: s, tools: s.tools, classification, sandbox: sb, active: false, probes: [probe] });
        assert.equal(v.validCalls, 0);
        assert.ok(v.warnings.some((w) => /returned an error and does not count toward coverage/.test(w)));
      } finally {
        await s.close();
      }
    });

    it("end to end: a run whose only probe failed upstream stays below 'covered' and the failed tool is not credited", async () => {
      const failed = await run(toy(FETCH_TOY, "failed"), [probe], ["core"]);
      const ok = await run(toy(FETCH_TOY, "ok"), [probe], ["core"]);
      assert.ok((failed.warnings ?? []).some((w) => /failed upstream request/.test(w)));
      assert.ok(!(ok.warnings ?? []).some((w) => /failed upstream request/.test(w)));
      assert.ok(failed.coverage!.validCalls < ok.coverage!.validCalls, `${JSON.stringify(failed.coverage)} vs ${JSON.stringify(ok.coverage)}`);
      assert.equal(failed.badge?.eligible, ok.badge?.eligible, "coverage is verdict-neutral: the badge does not move");
    });
  });

  describe("custom checks (h-4)", () => {
    const check = (id: string) => ({ id, label: `check ${id}`, critical: false, scope: "server (test)" });
    const probes: ProbeSpec[] = [
      { id: "say", check: check("custom-say"), tool: "echo", args: { text: "hi" }, expect: { is_error: false } },
      { id: "lookup", check: check("custom-lookup"), tool: "search", args: { query: "alpha" }, expect: { is_error: false } },
    ];

    it("one of two probes errors: only the other counts (toolsCalledValid is 1, validCalls is 1)", async () => {
      const r = await run(toy(FETCH_TOY, "plain-error"), probes, ["custom"]);
      const say = r.checks.find((c) => c.id === "custom-say")!;
      const lookup = r.checks.find((c) => c.id === "custom-lookup")!;
      assert.deepEqual(say.coverage?.probed, ["echo"]);
      assert.equal(say.coverage?.validCalls, 1);
      assert.deepEqual(lookup.coverage?.probed, [], "the errored call exercised nothing");
      assert.equal(lookup.coverage?.validCalls, 0);
      assert.equal(lookup.verdict, "fail", "the failed expectation is still a verdict");
      assert.equal(r.coverage!.toolsCalledValid, 1);
      assert.equal(r.coverage!.validCalls, 1);
    });

    it("a probe whose reply reports a failed upstream request does not count either", async () => {
      const r = await run(toy(FETCH_TOY, "failed"), probes, ["custom"]);
      assert.equal(r.checks.find((c) => c.id === "custom-lookup")!.coverage?.validCalls, 0);
      assert.equal(r.coverage!.toolsCalledValid, 1);
    });

    it("near-miss: when both answer, both count", async () => {
      const r = await run(toy(FETCH_TOY, "ok"), probes, ["custom"]);
      assert.equal(r.coverage!.toolsCalledValid, 2);
      assert.deepEqual(r.checks.filter((c) => c.pack === "custom").map((c) => c.coverage?.validCalls), [1, 1], "each check counted its own call");
    });
  });

  describe("files.created (h-5)", () => {
    const planFor = (s: McpSession, spec: ProbeSpec) => validateProbes([spec], { tools: s.tools, classification: classifyTools({ tools: s.tools }).classification, sandbox: sb }).probes[0]!;
    const spec = (id: string, content: string): ProbeSpec => ({ id, check: { id: `custom-${id}`, label: id, critical: false, scope: "server (test)" }, tool: "write_file", args: { path: `{sandbox}/${id}.txt`, content }, expect: { is_error: false, files: { created: [`{sandbox}/${id}.txt`] } } });

    it("holds when the file was there already (empty, left by an earlier call) and this call wrote its content", async () => {
      const s = await open(PROBES_TOY, "good");
      try {
        writeFileSync(join(sb.root, "pre.txt"), "");
        const o = await runProbe(planFor(s, spec("pre", "written by the probe")), { session: s, sandbox: sb, active: false });
        assert.equal(o.verdict, "pass", JSON.stringify(o.clauses));
        assert.match(o.clauses[1]!.detail, /existed and this call changed its content/);
        assert.equal(readFileSync(join(sb.root, "pre.txt"), "utf8"), "written by the probe");
      } finally {
        await s.close();
      }
    });

    it("near-miss: a file that was there and is not changed by the call is still 'not created'", async () => {
      const s = await open(PROBES_TOY, "good");
      try {
        writeFileSync(join(sb.root, "same.txt"), "unchanged");
        const o = await runProbe(planFor(s, spec("same", "unchanged")), { session: s, sandbox: sb, active: false });
        assert.equal(o.verdict, "fail");
        assert.match(o.clauses.map((c) => c.detail).join(" "), /was not created/);
      } finally {
        await s.close();
      }
    });

    it("a file that did not exist is created: the original meaning holds", async () => {
      const s = await open(PROBES_TOY, "good");
      try {
        const o = await runProbe(planFor(s, spec("fresh", "hello")), { session: s, sandbox: sb, active: false });
        assert.equal(o.verdict, "pass", JSON.stringify(o.clauses));
        assert.match(o.clauses.map((c) => c.detail).join(" "), /was created/);
      } finally {
        await s.close();
      }
    });
  });
});
