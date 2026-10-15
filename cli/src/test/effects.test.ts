import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { REGISTRY } from "../packs/index.js";
import { describe as describeEffects, effectsGateReason, pack as effectsPack } from "../packs/effects.js";
import type { RunResult, Verdict } from "../types.js";
import { gradeOf, verdicts } from "./helpers.js";
import { directCtx, fsConfig, insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

const IDS = ["annotation-honesty", "openworld-honesty", "undeclared-writes"] as const;

/**
 * the design notes 2.6 and section 7: effects runs on the fs toy. annotation-honesty is critical, openworld-honesty is scored,
 * undeclared-writes is advisory and unscored, so the effects grade is 50%/75%/100% of the first two.
 */
const TABLE: Record<string, { v: [Verdict, Verdict, Verdict]; letter: string; pct: number }> = {
  good: { v: ["pass", "pass", "na"], letter: "A", pct: 100 },
  logger: { v: ["fail", "pass", "na"], letter: "D", pct: 50 },
  cachey: { v: ["part", "pass", "na"], letter: "B", pct: 75 },
  liar: { v: ["fail", "pass", "na"], letter: "D", pct: 50 },
  unannotated: { v: ["pass", "pass", "part"], letter: "A", pct: 100 },
};

describe("effects pack against the toy file server", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-effects-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const modes = [...Object.keys(TABLE), "deaf"];
    await Promise.all(
      modes.map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        // fs runs first so effects sees what a real run would leave behind (a .log file the logger has already appended to).
        results[m] = await runPacks(fsConfig(m, { trace: traces[m] }), ["fs", "effects"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  for (const [mode, row] of Object.entries(TABLE)) {
    it(`${mode}: verdicts and grade match the design table`, () => {
      const r = results[mode];
      const v = verdicts(r, "effects");
      assert.deepEqual(
        IDS.map((id) => v[id]),
        row.v,
        JSON.stringify(r.checks.filter((c) => c.pack === "effects").map((c) => [c.id, c.verdict, c.summary])),
      );
      const g = gradeOf(r, "effects");
      assert.ok(g, "graded");
      assert.equal(g.letter, row.letter);
      assert.equal(g.pct, row.pct);
    });
  }

  it("logger: the fs pack grades A while effects grades D (a read-only tool that writes is not an fs escape)", () => {
    assert.equal(gradeOf(results.logger, "fs")?.letter, "A");
    assert.equal(gradeOf(results.logger, "effects")?.letter, "D");
    const ann = results.logger.checks.find((c) => c.id === "annotation-honesty")!;
    assert.equal(ann.critical, true);
    const hit = ann.evidence.find((e) => e.code === "effects.readonly-write");
    assert.ok(hit);
    assert.equal(hit.tool, "read_file");
    assert.equal(hit.verifiedBy, "fs-observer");
    assert.match(hit.outcome, /root\/\.log/);
    assert.match(ann.summary, /read_file/);
    // the other two read-only tools were observed too, and are clean
    assert.deepEqual(ann.evidence.filter((e) => e.code === "effects.readonly-clean").map((e) => e.tool).sort(), ["list_dir", "stat"]);
  });

  it("a critical annotation fail caps the effects grade at D", () => {
    for (const m of ["logger", "liar"]) assert.deepEqual(gradeOf(results[m], "effects")!.criticalFails, ["annotation-honesty"]);
  });

  it("cachey: a cache file in the sandbox temp directory is a part, not a fail", () => {
    const ann = results.cachey.checks.find((c) => c.id === "annotation-honesty")!;
    assert.match(ann.summary, /only caches changed/);
    assert.ok(ann.evidence.some((e) => e.code === "effects.readonly-cache" && /tmp\//.test(e.outcome)));
    assert.equal(gradeOf(results.cachey, "effects")!.criticalFails.length, 0);
  });

  it("liar: a write tool declared read-only is caught by a harness-owned control write", () => {
    const ann = results.liar.checks.find((c) => c.id === "annotation-honesty")!;
    assert.ok(ann.evidence.some((e) => e.tool === "write_file" && e.code === "effects.readonly-write" && /root\/ann-/.test(e.outcome)));
  });

  it("unannotated: undeclared writes are listed, advisory, and do not touch the grade", () => {
    const u = results.unannotated.checks.find((c) => c.id === "undeclared-writes")!;
    assert.equal(u.advisory, true);
    assert.equal(u.critical, false);
    assert.equal(u.verdict, "part");
    assert.match(u.summary, /read_file/);
    assert.match(u.summary, /not scored/);
    assert.equal(gradeOf(results.unannotated, "effects")!.scored, 2);
  });

  it("deaf: control calls that all fail are inconclusive, never a pass", () => {
    const v = verdicts(results.deaf, "effects");
    assert.equal(v["annotation-honesty"], "inconclusive");
    assert.equal(v["openworld-honesty"], "inconclusive");
    assert.equal(results.deaf.packs.effects?.status, "inconclusive");
  });

  it("only harness-owned control arguments are sent: the control file, the root, or a new file inside the root", () => {
    for (const m of Object.keys(TABLE)) {
      const sandboxDir = results[m].sandbox!.dir!;
      const calls = readTrace(traces[m]);
      assert.ok(calls.length > 0);
      for (const t of calls) for (const p of stringArgs(t.args).filter((s) => /[\\/]|^file:/.test(s) && s.length > 2)) assert.ok(insideDir(sandboxDir, p), `${m}: ${t.tool} was sent ${p}`);
    }
  });

  it("scopes start with 'server', coverage lists the tools called, and the docs name every check", () => {
    const checks = results.good.checks.filter((c) => c.pack === "effects");
    for (const c of checks) assert.match(c.scope, /^server \(annotations vs what the sandbox observed/);
    assert.deepEqual(checks.find((c) => c.id === "annotation-honesty")!.coverage!.probed.sort(), ["list_dir", "read_file", "stat"]);
    assert.deepEqual(describeEffects().map((d) => d.id), [...IDS]);
    assert.ok(REGISTRY.some((p) => p === effectsPack));
  });

  it("sandboxes are removed", () => {
    assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
    for (const r of Object.values(results)) assert.equal(existsSync(r.sandbox!.dir!), false);
  });
});

describe("effects pack: applicability and configuration", { timeout: 300_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-effects-test2-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("is not applicable when no tool declares annotations and none is an unannotated path or repository tool, or when the sandbox is off", async () => {
    const d = await directCtx(fsConfig("good"), "effects", where());
    try {
      assert.deepEqual(effectsPack.applies(d.ctx), { ok: true });
      // Round 5: an unannotated path tool is enough (undeclared-writes needs no annotation); only a server whose usable tools are all unannotated URL tools has nothing to compare.
      const unannotated = d.ctx.classification.map(({ annotations: _a, ...rest }) => rest);
      assert.deepEqual(effectsPack.applies({ ...d.ctx, classification: unannotated }), { ok: true });
      const bare = { ...d.ctx, classification: unannotated.map((c) => ({ ...c, class: "url" as const, params: { url: "url" } })) };
      const a = effectsPack.applies(bare);
      assert.equal(a.ok, false);
      assert.match(a.ok ? "" : a.reason, /no tool declares annotations/);
      assert.equal(a.ok ? "" : a.reason, effectsGateReason(bare.classification, { active: bare.active, sandboxEnabled: true }), "applies() and the gate helper share one wording");
      assert.equal(effectsGateReason(d.ctx.classification, { active: d.ctx.active, sandboxEnabled: true }), undefined);
      const none = effectsPack.applies({ ...d.ctx, classification: [] });
      assert.equal(none.ok ? "" : none.reason, effectsGateReason([], { active: false, sandboxEnabled: true }));
      assert.match(none.ok ? "" : none.reason, /harness-owned target/);
      const off = effectsPack.applies({ ...d.ctx, sandboxEnabled: false });
      assert.equal(off.ok, false);
      assert.match(off.ok ? "" : off.reason, /sandbox is off/);
    } finally {
      await d.close();
    }
  });

  it("run.ts reports the pack as not applicable under --no-sandbox", async () => {
    const r = await runPacks(fsConfig("good"), ["effects"], where(), { sandbox: { enabled: false } });
    assert.equal(r.packs.effects?.status, "na");
    assert.match(r.packs.effects?.reason ?? "", /sandbox/);
  });

  it("a server whose read-only tools cannot be given a control argument gets na with the tools listed", async () => {
    const d = await directCtx(fsConfig("good"), "effects", where());
    try {
      // Pretend every tool deletes something: the harness has no harmless call for that.
      const odd = { ...d.ctx, tools: d.ctx.tools.map((t) => ({ ...t, name: `delete_${t.name}` })), classification: d.ctx.classification.map((c) => ({ ...c, tool: `delete_${c.tool}` })) };
      const out = await effectsPack.run(odd);
      const ann = out.find((c) => c.id === "annotation-honesty")!;
      assert.equal(ann.verdict, "na");
      assert.match(ann.summary, /could be given a harness-owned control argument \(delete_read_file: a delete tool has no harmless control call/);
      assert.ok(ann.coverage!.notCovered.length > 0);
    } finally {
      await d.close();
    }
  });

  it("checks.<id>.severity and enabled are honoured", async () => {
    const checks = { "annotation-honesty": { enabled: true, severity: "scored" as const }, "openworld-honesty": { enabled: false, severity: null } };
    const d = await directCtx(fsConfig("logger"), "effects", where(), { over: { checks } });
    try {
      const out = await effectsPack.run(d.ctx);
      const ann = out.find((c) => c.id === "annotation-honesty")!;
      assert.equal(ann.verdict, "fail");
      assert.equal(ann.critical, false, "downgraded from critical by checks.annotation-honesty.severity");
      assert.equal(out.find((c) => c.id === "openworld-honesty")!.verdict, "na");
      assert.match(out.find((c) => c.id === "openworld-honesty")!.summary, /disabled by config/);
    } finally {
      await d.close();
    }
  });
});
