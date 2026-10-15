import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { CheckConfig } from "../config/model.js";
import { gradePack } from "../grade.js";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { applyCheckConfig, describe as describeCore, refusalQuality, runCore, type CoreCtx } from "../packs/core.js";
import { applyDbChecksConfig, describe as describeDb } from "../packs/db.js";
import type { CheckResult, RunResult } from "../types.js";
import { check, cliKit } from "./helpers.js";

// checks.<id>.enabled and checks.<id>.severity must do for core and db what they already do for fs, net, http, exec and sqlite.

const reply = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: false, text, elapsedMs: 1, timedOut: false, closed: false, ...o });
const rejected = reply("text must be a string", { isError: true });
const tool = (name: string): ToolInfo => ({ name, description: `${name} does a thing`, inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }) as ToolInfo;
function stub(tools: ToolInfo[], checks?: Record<string, CheckConfig>) {
  const calls: string[] = [];
  const session = {
    tools,
    serverInfo: { name: "stub", version: "1.0.0" },
    capabilities: {},
    prompts: [],
    resources: [],
    listErrors: [],
    async call(name: string) {
      calls.push(name);
      return rejected;
    },
    async alive() {
      return true;
    },
  } as unknown as McpSession;
  const ctx: CoreCtx = { session, canaries: ["sm-canary-x"], seen: [], hangMs: 100, ...(checks ? { checks } : {}) };
  return { ctx, calls };
}
const cfg = (o: Partial<CheckConfig> = {}): CheckConfig => ({ enabled: true, severity: null, ...o });
const find = (cs: CheckResult[], id: string) => cs.find((c) => c.id === id)!;

describe("core honours checks.<id>.enabled and checks.<id>.severity", () => {
  it("enabled:false reports tool-poisoning n/a 'disabled by config' and the other three still run", async () => {
    const { ctx } = stub([tool("t")], { "tool-poisoning": cfg({ enabled: false }) });
    const cs = await runCore(ctx);
    const tp = find(cs, "tool-poisoning");
    assert.equal(tp.verdict, "na");
    assert.match(tp.summary, /^disabled by config/);
    assert.deepEqual(tp.evidence, []);
    for (const id of ["protocol", "robust-input", "secret-echo"]) assert.notEqual(find(cs, id).verdict, "na", id);
    assert.equal(gradePack("core", cs)?.scored, 3);
  });

  it("severity:advisory on secret-echo makes it advisory and non-critical, and gradePack leaves it out", async () => {
    const { ctx } = stub([tool("t")], { "secret-echo": cfg({ severity: "advisory" }) });
    const cs = await runCore(ctx);
    const se = find(cs, "secret-echo");
    assert.equal(se.advisory, true);
    assert.equal(se.critical, false);
    assert.equal(gradePack("core", cs)?.scored, 3);
  });

  it("severity:critical and severity:scored move a check in the other direction", () => {
    const base = check("robust-input", "fail");
    assert.equal(applyCheckConfig(base, cfg({ severity: "critical" })).critical, true);
    const adv = { ...check("audit", "na"), advisory: true };
    const scored = applyCheckConfig(adv, cfg({ severity: "scored" }));
    assert.equal(scored.critical, false);
    assert.equal(scored.advisory, undefined);
    assert.equal("advisory" in scored, false);
  });

  it("a disabled robust-input makes no calls at all and secret-echo may become inconclusive", async () => {
    const { ctx, calls } = stub([tool("t")], { "robust-input": cfg({ enabled: false }) });
    const cs = await runCore(ctx);
    assert.deepEqual(calls, []);
    assert.equal(find(cs, "robust-input").verdict, "na");
    assert.equal(find(cs, "secret-echo").verdict, "inconclusive");
  });

  it("with the shipped defaults every core check comes back as the very same object and keeps the describe() flags", async () => {
    const plain = await runCore(stub([tool("t")]).ctx);
    const dflt = await runCore(stub([tool("t")], Object.fromEntries(plain.map((c) => [c.id, cfg()]))).ctx);
    assert.deepEqual(dflt, plain);
    // refusal-quality is not part of runCore: the harness computes it after every pack has run (refusalQuality), so it is checked on its own.
    for (const doc of describeCore()) {
      const c = doc.id === "refusal-quality" ? refusalQuality([]) : find(plain, doc.id);
      assert.equal(c.critical, doc.critical, `${doc.id} critical`);
      assert.equal(Boolean(c.advisory), doc.advisory, `${doc.id} advisory`);
    }
  });
});

describe("db honours checks.<id>.enabled and checks.<id>.severity", () => {
  const all = (): CheckResult[] => describeDb().map((d) => ({ id: d.id, pack: "db", label: d.label, critical: d.critical, ...(d.advisory ? { advisory: true } : {}), scope: d.scope, verdict: "pass", summary: "x", evidence: [] }));

  it("severity:scored on write-gate and audit (the strict profile) removes advisory; the rest is untouched", () => {
    const out = applyDbChecksConfig(all(), { "write-gate": cfg({ severity: "scored" }), audit: cfg({ severity: "scored" }) });
    for (const id of ["write-gate", "audit"]) assert.equal(find(out, id).advisory, undefined, id);
    assert.equal(find(out, "rls").critical, true);
    assert.equal(out.length, all().length);
    assert.deepEqual(out.map((c) => c.id), all().map((c) => c.id));
  });

  it("enabled:false (the quick profile) reports db-rowcap and db-timeout n/a, also when the probes never ran", () => {
    const ran = applyDbChecksConfig(all(), { "db-rowcap": cfg({ enabled: false }), "db-timeout": cfg({ enabled: false }) });
    assert.deepEqual([find(ran, "db-rowcap").verdict, find(ran, "db-timeout").verdict], ["na", "na"]);
    const skipped = applyDbChecksConfig(all().filter((c) => c.id !== "db-rowcap"), { "db-rowcap": cfg({ enabled: false }) });
    assert.equal(find(skipped, "db-rowcap").verdict, "na");
    assert.match(find(skipped, "db-rowcap").summary, /disabled by config/);
    assert.deepEqual(skipped.map((c) => c.id), all().map((c) => c.id), "emission order is kept");
  });

  it("with defaults the list is returned untouched", () => {
    const list = all();
    assert.equal(applyDbChecksConfig(list, Object.fromEntries(list.map((c) => [c.id, cfg()]))), list);
    assert.equal(applyDbChecksConfig(list, undefined), list);
  });
});

describe("end to end: the config reaches core", () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-chchecks-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));
  const { sealmark, readJson } = cliKit(() => dir);
  const FS_TOY = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
  const START = ["--start", `${JSON.stringify(process.execPath)} ${JSON.stringify(FS_TOY)} --mode good --root {sandbox}`, "--pack", "core", "--timeout-probe", "2", "--fail-under", "none", "--format", "json"];
  it("SEALMARK_CHECKS__TOOL_POISONING__ENABLED=false makes core report it n/a and score 3 checks, CUSTOM", () => {
    const out = join(dir, "off.json");
    const r = sealmark(["run", ...START, "--out", out], dir, { SEALMARK_CHECKS__TOOL_POISONING__ENABLED: "false" });
    assert.equal(r.code, 0, r.err);
    const rep = readJson<RunResult>(out);
    const tp = rep.checks.find((c) => c.id === "tool-poisoning")!;
    assert.equal(tp.verdict, "na");
    assert.match(tp.summary, /disabled by config/);
    const g = rep.packs.core;
    assert.equal(g?.status === "graded" ? g.grade?.scored : undefined, 3);
    assert.equal(rep.config?.standard, false);
  });

  it("restating the default check settings changes nothing in the report (STANDARD grades are not touched)", () => {
    const a = join(dir, "a.json");
    const b = join(dir, "b.json");
    assert.equal(sealmark(["run", ...START, "--out", a]).code, 0);
    const file = join(dir, "sealmark.yaml");
    const yaml = ["protocol", "tool-poisoning", "robust-input", "secret-echo"].map((id) => `  ${id}: { enabled: true, severity: null }`).join("\n");
    cliKit(() => dir).writeYaml("sealmark.yaml", `checks:\n${yaml}\n`);
    assert.equal(sealmark(["run", ...START, "--config", file, "--out", b]).code, 0);
    const [ra, rb] = [readJson<RunResult>(a), readJson<RunResult>(b)];
    assert.deepEqual(rb.checks, ra.checks);
    assert.deepEqual(rb.packs, ra.packs);
    assert.equal(rb.config?.hash, ra.config?.hash);
    assert.deepEqual(rb.config?.standardDiff, ra.config?.standardDiff, "restating the defaults adds no difference");
  });
});
