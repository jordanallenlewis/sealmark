import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { effectsGateReason, pack as effectsPack } from "../packs/effects.js";
import type { CheckResult, RunResult, SealmarkConfig, ToolClassification } from "../types.js";
import { gradeOf } from "./helpers.js";
import { directCtx, fsConfig, runPacks } from "./packctx.js";
import { decideExit } from "../report/exit.js";

// Round 5, git-5, git-6 and git-7: a read-only tool with no parameter is observed with {}; a URL tool that net showed to refuse loopback is n/a,
// not inconclusive, so a correctly guarded fetcher can be green under the ci profile; undeclared-writes runs when no tool is annotated.

const toy = fileURLToPath(new URL("../toy/effects-r5.js", import.meta.url));
const cfg = (mode: string): SealmarkConfig => ({ name: `toy-effects-r5-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [toy, "--mode", mode], env: {} } });

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const check = (name: string, id: string) => results[name].checks.find((c) => c.id === id)!;

describe("effects pack (round 5): no-argument controls and the loopback-refusing URL tool", { timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-effects-r5-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all([
      runPacks(cfg("noarg-writes"), ["effects"], where()).then((r) => (results.writes = r)),
      runPacks(cfg("noarg-clean"), ["effects"], where()).then((r) => (results.clean = r)),
      runPacks(cfg("url-guarded"), ["net", "effects"], where()).then((r) => (results.guarded = r)),
      runPacks(cfg("url-guarded"), ["effects"], where()).then((r) => (results.guardedAlone = r)),
    ]);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("noarg-writes: a read-only tool with no parameter that writes into the sandbox fails annotation-honesty (it was never called before)", () => {
    const c = check("writes", "annotation-honesty");
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /refresh_status/);
    const e = c.evidence.find((x) => x.tool === "refresh_status");
    assert.ok(e);
    assert.equal(e.code, "effects.readonly-write");
    assert.deepEqual(e.args, {}, "the control call is {}");
    assert.match(e.outcome, /pwned\.txt/);
    assert.equal(gradeOf(results.writes, "effects")?.letter, "F");
  });

  it("noarg-clean (near miss): the same tool that only returns text passes, and the call is counted", () => {
    const c = check("clean", "annotation-honesty");
    assert.equal(c.verdict, "pass", c.summary);
    assert.equal(c.coverage?.validCalls, 1);
    assert.deepEqual(c.coverage?.probed, ["refresh_status"]);
    assert.equal(gradeOf(results.clean, "effects")?.letter, "A");
  });

  it("with no annotation anywhere, undeclared-writes still runs (the gate needs an annotated tool or an unannotated path or repository tool)", () => {
    const tool = (name: string, cls: ToolClassification["class"], ann?: ToolClassification["annotations"]): ToolClassification => ({ tool: name, class: cls, confidence: "medium", params: cls === "path" ? { path: "path" } : {}, unfillable: [], reasons: [], ...(ann ? { annotations: ann } : {}) });
    const gate = (c: ToolClassification[]) => effectsGateReason(c, { active: false, sandboxEnabled: true });
    assert.equal(gate([tool("read_file", "path")]), undefined, "an unannotated path tool is enough");
    assert.equal(gate([tool("read_file", "path", { readOnlyHint: true })]), undefined, "an annotated one is too");
    assert.equal(gate([tool("fetch", "url")]), "no tool declares annotations and none is an unannotated path or repository tool, so there is nothing to compare with what the sandbox observed", "an unannotated URL tool is never undeclared-writes' business");
    assert.match(gate([])!, /harness-owned target/);
    assert.equal(gate([tool("refresh", "opaque", { readOnlyHint: true })]), undefined, "a read-only tool with nothing to fill is usable");
    assert.match(gate([tool("refresh", "opaque")])!, /harness-owned target/, "an unannotated opaque tool is not");
  });

  it("with no annotation on any tool the pack applies and undeclared-writes runs; the two honesty checks are n/a (item git-7, end to end)", async () => {
    const d = await directCtx(fsConfig("unannotated"), "effects", where());
    try {
      const bare = { ...d.ctx, classification: d.ctx.classification.map(({ annotations: _a, ...rest }) => rest) };
      assert.deepEqual(effectsPack.applies(bare), { ok: true });
      const out = await effectsPack.run(bare);
      const v = Object.fromEntries(out.map((c) => [c.id, c.verdict]));
      assert.deepEqual(v, { "annotation-honesty": "na", "openworld-honesty": "na", "undeclared-writes": "part" });
      const u = out.find((c) => c.id === "undeclared-writes")!;
      assert.match(u.summary, /read_file/, "the toy's read_file appends to a log in the sandbox");
      assert.ok(u.coverage?.probed.includes("read_file"));
    } finally {
      await d.close();
    }
  });

  it("undeclared-writes says every tool carries annotations when none is unannotated, without listing the other tools one by one", () => {
    const u = check("clean", "undeclared-writes");
    assert.equal(u.verdict, "na");
    assert.equal(u.summary, "every tool carries annotations, nothing to check");
    assert.deepEqual(u.coverage?.notCovered, []);
  });

  it("applies() and the gate helper share the one wording for the unannotated rule", async () => {
    const d = await directCtx(cfg("url-guarded"), "effects", where());
    try {
      const bare = { ...d.ctx, classification: d.ctx.classification.map((c) => ({ ...c, annotations: undefined })) };
      const a = effectsPack.applies(bare);
      assert.equal(a.ok ? "" : a.reason, effectsGateReason(bare.classification, { active: bare.active, sandboxEnabled: true }));
      assert.match(a.ok ? "" : a.reason, /no tool declares annotations and none is an unannotated path or repository tool/);
    } finally {
      await d.close();
    }
  });

  it("url-guarded: the tool refused the listener URL and net-loopback-ssrf passed for it, so effects is n/a, not inconclusive", () => {
    const net = results.guarded.checks.find((c) => c.id === "net-loopback-ssrf")!;
    assert.equal(net.verdict, "pass", net.summary);
    for (const id of ["annotation-honesty", "openworld-honesty"]) {
      const c = check("guarded", id);
      assert.equal(c.verdict, "na", `${id}: ${c.summary}`);
    }
    const a = check("guarded", "annotation-honesty");
    assert.match(a.summary, /fetch_page: the tool refuses loopback targets \(net-loopback-ssrf passed\), so no harness-owned control URL exists/);
    assert.ok(a.coverage?.notCovered.some((n) => n.tool === "fetch_page" && /refuses loopback targets/.test(n.reason)), "the tool is listed as not judged, with the reason");
    assert.equal(results.guarded.packs.effects?.status, "na", JSON.stringify(results.guarded.packs.effects));
    assert.equal(gradeOf(results.guarded, "net")?.letter, "A");
  });

  it("without a net pass in ctx.prior the same tool stays inconclusive: the refusal is not read as 'the tool is guarded' on the tool's word", () => {
    const a = check("guardedAlone", "annotation-honesty");
    assert.equal(a.verdict, "inconclusive", a.summary);
    assert.match(a.summary, /every control call failed/);
  });

  it("the ci policy (an A gate, an inconclusive pack counts as failing) exits 0 for the correctly guarded fetcher, and not 0 for the same tool without a net result", () => {
    const policy = { failUnder: "A" as const, treatInconclusiveAs: "fail" as const, criticalFail: 0, failOnGate: true, failOnRegressions: false, failOnDrift: false, regressions: [], drift: [], baseline: false };
    const ok = decideExit([results.guarded], policy);
    assert.equal(ok.code, 0, JSON.stringify(ok));
    assert.equal(results.guarded.packs.effects?.status, "na");
    assert.ok(results.guarded.checks.filter((c: CheckResult) => c.pack === "effects").every((c) => c.verdict === "na"));
    // Before this change that was the only outcome: effects inconclusive right after net passed, and the ci gate failed.
    const before = decideExit([results.guardedAlone], policy);
    assert.notEqual(before.code, 0, "without a net-loopback-ssrf pass in ctx.prior the refusal is still 'every control call failed' and nothing is graded");
  });
});
