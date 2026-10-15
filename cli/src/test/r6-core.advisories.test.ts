import assert from "node:assert/strict";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { McpSession, type ToolInfo } from "../mcp.js";
import { DEFAULT_ROUTING_PATTERNS, describe as describeCore, instructionsHygiene, refusalQuality, runCore, type CoreCtx } from "../packs/core.js";
import type { CheckResult, Evidence } from "../types.js";

// Round 6 (design 3.7, seam S10): the two core advisories. `refusalQuality(checks, cfg)` is what run.ts calls after the pack loop;
// `instructions-hygiene` runs inside core.

const evidence = (code: string, text: string, extra: Partial<Evidence> = {}): Evidence => ({ probe: `probe ${code}`, outcome: "refused", verifiedBy: "response", excerpt: text, code, ...extra });
const check = (id: string, pack: string, evs: Evidence[]): CheckResult => ({ id, pack: pack as CheckResult["pack"], label: id, critical: true, scope: "server", verdict: "pass", summary: "", evidence: evs });
const ROUTES = "table is not available. Available tables: orders (call list_tables). Retrying will not help.";
const DEAD = "forbidden";

/** n refusals, `routing` of them with a routing sentence. */
const refusals = (n: number, routing: number): CheckResult[] => [check("scope-escape", "scope", Array.from({ length: n }, (_, i) => evidence("scope.refused", i < routing ? ROUTES : DEAD)))];

describe("refusalQuality", () => {
  it("is advisory, in core, and named refusal-quality", () => {
    const r = refusalQuality(refusals(1, 1));
    assert.equal(r.id, "refusal-quality");
    assert.equal(r.pack, "core");
    assert.equal(r.advisory, true);
    assert.equal(r.critical, false);
  });

  it("n/a with no refusal recorded", () => {
    assert.equal(refusalQuality([]).verdict, "na");
    assert.equal(refusalQuality([check("x", "core", [evidence("fs.read-ok", DEAD)])]).verdict, "na");
  });

  it("the 90 % boundary: 9 of 10 passes, 8 of 10 is a part", () => {
    assert.equal(refusalQuality(refusals(10, 9)).verdict, "pass");
    assert.equal(refusalQuality(refusals(10, 10)).verdict, "pass");
    assert.equal(refusalQuality(refusals(10, 8)).verdict, "part");
  });

  it("the 50 % boundary: 5 of 10 is a part, 4 of 10 fails", () => {
    assert.equal(refusalQuality(refusals(10, 5)).verdict, "part");
    const f = refusalQuality(refusals(10, 4));
    assert.equal(f.verdict, "fail");
    assert.match(f.summary, /^4 of 10 refusal\(s\) say what to do instead/);
  });

  it("evidence lists the non-routing excerpts, at most 12", () => {
    const r = refusalQuality(refusals(20, 0));
    assert.equal(r.verdict, "fail");
    assert.equal(r.evidence.length, 12);
    assert.ok(r.evidence.every((e) => e.code === "refusal.dead-end" && e.excerpt === DEAD));
    const some = refusalQuality(refusals(10, 8));
    assert.equal(some.evidence.length, 2);
  });

  it("reads every code family the design names, and the outcome when no excerpt was kept", () => {
    const evs = [
      evidence("scope.refused", DEAD),
      evidence("sql-guard.refused", DEAD),
      evidence("net.ssrf-refused", DEAD),
      evidence("net.ssrf-refused-extra", DEAD),
      evidence("fs.link-refused", DEAD),
      { probe: "p", outcome: `refused: ${ROUTES}`, verifiedBy: "response" as const, code: "fs.escape-refused" },
      evidence("probe:custom-x:pass", "Error: forbidden"),
      evidence("net.ssrf-unreached", DEAD),
    ];
    const r = refusalQuality([check("a", "net", evs)]);
    // Seven refusals are read (net.ssrf-unreached is not one), one of them routes.
    assert.match(r.summary, /^1 of 7 refusal/);
  });

  it("a probe's reply that does not read as a refusal is not counted", () => {
    const r = refusalQuality([check("custom-x", "custom", [evidence("probe:p:pass", "rows: 3")])]);
    assert.equal(r.verdict, "na");
  });

  it("checks.refusal-quality.patterns replaces the default list", () => {
    const evs = [evidence("scope.refused", "ask the data steward")];
    assert.equal(refusalQuality([check("s", "scope", evs)]).verdict, "fail");
    const cfg = { checks: { "refusal-quality": { enabled: true, severity: null, patterns: ["data steward"] } } };
    assert.equal(refusalQuality([check("s", "scope", evs)], cfg).verdict, "pass");
    // A pattern that does not compile is ignored and the check still answers.
    const bad = { checks: { "refusal-quality": { enabled: true, severity: null, patterns: ["("] } } };
    assert.equal(refusalQuality([check("s", "scope", evs)], bad).verdict, "fail");
  });

  it("enabled: false is n/a; severity scored makes it count", () => {
    const off = refusalQuality(refusals(2, 0), { checks: { "refusal-quality": { enabled: false, severity: null } } });
    assert.equal(off.verdict, "na");
    assert.match(off.summary, /disabled by config/);
    const scored = refusalQuality(refusals(2, 0), { checks: { "refusal-quality": { enabled: true, severity: "scored" } } });
    assert.equal(scored.advisory, undefined);
  });

  it("does not read its own earlier result", () => {
    const first = refusalQuality(refusals(2, 0));
    const again = refusalQuality([...refusals(2, 0), first]);
    assert.equal(again.summary, first.summary);
  });

  it("the default list matches what it documents", () => {
    for (const p of DEFAULT_ROUTING_PATTERNS) assert.doesNotThrow(() => new RegExp(p, "i"));
    for (const t of ["use the list_tables tool", "try again later", "contact the owner", "this will not help", "is permanent", "do not retry", "use X instead", "only allowed tables"]) {
      assert.ok(DEFAULT_ROUTING_PATTERNS.some((p) => new RegExp(p, "i").test(t)), t);
    }
    assert.ok(!DEFAULT_ROUTING_PATTERNS.some((p) => new RegExp(p, "i").test("forbidden")));
  });
});

// ---------------------------------------------------------------------------------------------------------

const TOOLS = [
  { name: "list_tables", description: "Lists tables", inputSchema: { type: "object", properties: {} } },
  { name: "query", description: "Runs a SELECT", inputSchema: { type: "object", properties: { sql: { type: "string" }, row_limit: { type: "number" } }, required: ["sql"] } },
] as ToolInfo[];

const ctxFor = (instructions: string | undefined, checks?: CoreCtx["checks"]): CoreCtx => ({ session: { tools: TOOLS, instructions, prompts: [], resources: [] } as unknown as McpSession, canaries: [], seen: [], hangMs: 2000, ...(checks ? { checks } : {}) });
const DENY = { "instructions-hygiene": { enabled: true, severity: null, deny: ["you are a helpful assistant", "ACME"] } };

describe("instructions-hygiene (hand-built session)", () => {
  it("no instructions: n/a", () => {
    const c = instructionsHygiene(ctxFor(undefined));
    assert.equal(c.verdict, "na");
    assert.equal(c.advisory, true);
    assert.equal(c.pack, "core");
  });

  it("clean: pass (tools, backticked tools and parameters are known; SQL words are not tool names)", () => {
    const c = instructionsHygiene(ctxFor("Use `list_tables` first; `query` accepts a single SELECT. Set `row_limit` for big tables, and keep `LIMIT` small."));
    assert.equal(c.verdict, "pass", c.summary);
  });

  it("a snake_case or backticked name that is not a tool: fail with the name", () => {
    const c = instructionsHygiene(ctxFor("Use `list_tables` first. Export the result with `export_csv`, or call download_file."));
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /names 2 tool\(s\) the server does not offer \(.*export_csv/);
    assert.deepEqual(c.evidence.map((e) => e.code), ["instructions.unknown-tool", "instructions.unknown-tool"]);
    assert.ok(c.evidence.every((e) => e.verifiedBy === "static"));
    // A plain word in backticks that is not a tool is found too; a plain word in prose is not.
    assert.equal(instructionsHygiene(ctxFor("Call `refresh` when stale.")).verdict, "fail");
    assert.equal(instructionsHygiene(ctxFor("Refresh when stale.")).verdict, "pass");
  });

  it("a deny pattern hit: fail; with no pattern the clause is not run", () => {
    const text = "You are a helpful assistant for ACME Corp. Use `list_tables` first.";
    const c = instructionsHygiene(ctxFor(text, DENY));
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /matches 2 deny pattern\(s\)/);
    assert.ok(c.evidence.every((e) => e.code === "instructions.deny"));
    assert.equal(instructionsHygiene(ctxFor(text)).verdict, "pass");
    // A pattern that does not compile is skipped.
    assert.equal(instructionsHygiene(ctxFor(text, { "instructions-hygiene": { enabled: true, severity: null, deny: ["("] } })).verdict, "pass");
  });

  it("disabled by config: n/a", () => {
    const c = instructionsHygiene(ctxFor("Call `export_csv`.", { "instructions-hygiene": { enabled: false, severity: null } }));
    assert.equal(c.verdict, "na");
    assert.match(c.summary, /disabled by config/);
  });
});

describe("runCore carries the advisory", () => {
  it("describe() lists both advisories with advisory: true and the four scored checks unchanged", () => {
    const docs = describeCore();
    assert.deepEqual(docs.filter((d) => d.advisory).map((d) => d.id), ["refusal-quality", "instructions-hygiene"]);
    assert.deepEqual(docs.filter((d) => !d.advisory).map((d) => d.id), ["protocol", "tool-poisoning", "robust-input", "secret-echo"]);
    for (const d of docs.filter((x) => x.advisory)) {
      assert.equal(d.pack, "core");
      assert.equal(d.critical, false);
      assert.ok(d.configKeys.includes(`checks.${d.id}.enabled`));
    }
  });
});

// ---------------------------------------------------------------------------------------------------------

const TOY = fileURLToPath(new URL("../toy/poison-r6.js", import.meta.url));
const sessions: McpSession[] = [];
after(async () => {
  for (const s of sessions) await s.close().catch(() => {});
});

async function onToy(mode: string, checks?: CoreCtx["checks"]): Promise<CheckResult> {
  const s = await McpSession.open({ command: process.execPath, args: [TOY, "--mode", mode], env: {} }, { vars: {}, dsns: {} }, { cleanCwd: true });
  sessions.push(s);
  const out = await runCore({ session: s, canaries: [], seen: [], hangMs: 6000, ...(checks ? { checks } : {}) });
  return out.find((c) => c.id === "instructions-hygiene")!;
}

describe("instructions-hygiene on the toy server", { timeout: 120_000 }, () => {
  it("is the fifth core check, advisory and never critical, in the same run as the four scored ones", async () => {
    const s = await McpSession.open({ command: process.execPath, args: [TOY, "--mode", "unknown-tool"], env: {} }, { vars: {}, dsns: {} }, { cleanCwd: true });
    sessions.push(s);
    const out = await runCore({ session: s, canaries: [], seen: [], hangMs: 6000 });
    assert.deepEqual(out.map((c) => c.id), ["protocol", "tool-poisoning", "robust-input", "secret-echo", "instructions-hygiene"]);
    assert.equal(out[4].verdict, "fail");
    assert.equal(out[4].advisory, true);
    assert.equal(out[4].critical, false);
    assert.ok(out.slice(0, 4).every((c) => !c.advisory), "the four scored checks stay scored");
  });
  it("clean: pass", async () => assert.equal((await onToy("clean", DENY)).verdict, "pass"));
  it("none: n/a", async () => assert.equal((await onToy("none", DENY)).verdict, "na"));
  it("unknown-tool: fail through clause 1", async () => {
    const c = await onToy("unknown-tool");
    assert.equal(c.verdict, "fail");
    assert.ok(c.evidence.some((e) => e.code === "instructions.unknown-tool" && /export_csv/.test(e.outcome)));
  });
  it("deny-hit: pass without the pattern, fail with it", async () => {
    assert.equal((await onToy("deny-hit")).verdict, "pass");
    const c = await onToy("deny-hit", DENY);
    assert.equal(c.verdict, "fail");
    assert.ok(c.evidence.some((e) => e.code === "instructions.deny"));
  });
});
