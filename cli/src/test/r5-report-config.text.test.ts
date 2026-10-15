import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderMarkdown } from "../report/markdown.js";
import { renderReport, renderText } from "../report.js";
import { surfaceDrift } from "../report/drift.js";
import { renderSummary } from "../report/summary.js";
import { captureSurface } from "../surface.js";
import type { CheckResult, Letter, PackGrade, RunResult } from "../types.js";
import { check } from "./helpers.js";

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

function grade(pack: string, letter: Letter, o: Partial<PackGrade> = {}): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o };
}

function run(packs: RunResult["packs"], checks: CheckResult[] = [check("protocol", "pass")], over: Partial<RunResult> = {}): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "Toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["t"], sqlTools: [] },
    options: { packsRequested: ["core", "fs"], timeoutProbeSec: 10, sandbox: true },
    startedAt: "2026-10-13T00:00:00.000Z",
    durationMs: 5,
    packs,
    checks,
    notCovered: [],
    config: { hash: "sha256:aa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} },
    badge: { eligible: true },
    ...over,
  };
}

describe("the summary banner says when an inconclusive pack fails the gate", () => {
  const packs = { core: { status: "graded" as const, grade: grade("core", "A") }, fs: { status: "inconclusive" as const, reason: "no tool could be judged" } };

  it("treat_inconclusive_as fail: the banner is not the green line, and names the pack and the setting", () => {
    const out = strip(renderSummary([run(packs)], { gate: "B", treatInconclusiveAs: "fail" }));
    assert.match(out, /GATE NOT MET: fs inconclusive/);
    assert.match(out, /output\.exit_policy\.treat_inconclusive_as is fail/);
    assert.doesNotMatch(out, /ALL GRADED PACKS AT B OR BETTER/);
  });

  it("the default policy: the green line stays and says which packs were not graded", () => {
    const out = strip(renderSummary([run(packs)], { gate: "B" }));
    assert.match(out, /ALL GRADED PACKS AT B OR BETTER\s+\(worst grade: A; 1 pack not graded \(inconclusive\): fs\)/);
  });

  it("near miss: with nothing inconclusive the banner is exactly what it was", () => {
    const out = strip(renderSummary([run({ core: { status: "graded", grade: grade("core", "A") } })], { gate: "B", treatInconclusiveAs: "fail" }));
    assert.match(out, /ALL GRADED PACKS AT B OR BETTER\s+\(worst grade: A\)/);
  });

  it("a pack below the gate keeps the BELOW banner and adds the inconclusive line when the policy is fail", () => {
    const out = strip(renderSummary([run({ ...packs, core: { status: "graded", grade: grade("core", "C") } })], { gate: "B", treatInconclusiveAs: "fail" }));
    assert.match(out, /BELOW B: core C/);
    assert.match(out, /GATE NOT MET: fs inconclusive/);
  });
});

describe("the badge line never recommends a badge next to a grade the gate rejects", () => {
  const f = run({ core: { status: "graded", grade: grade("core", "A") }, fs: { status: "graded", grade: grade("fs", "F", { raw: "F", capped: true, criticalFails: ["fs-read-escape"] }) } });

  it("text: not recommended (fs F) when the gate is B; eligible when no gate is set or every pack meets it", () => {
    assert.match(renderText(f, { gate: "B" }), /Badge: not recommended \(fs F\)/);
    assert.match(renderText(f), /Badge: eligible/);
    assert.match(renderText(run({ core: { status: "graded", grade: grade("core", "A") } }), { gate: "B" }), /Badge: eligible/);
  });

  it("summary and markdown say the same; a provisional A* is below an A gate", () => {
    assert.match(strip(renderSummary([f], { gate: "B" })), /badge: not recommended \(fs F\)/);
    assert.match(renderMarkdown([f], { gate: "B" }), /Badge: not recommended \(fs F\)/);
    assert.match(renderMarkdown([f]), /Badge: eligible\./);
    const star = run({ core: { status: "graded", grade: grade("core", "A", { provisional: true }) } });
    assert.match(renderText(star, { gate: "A" }), /Badge: not recommended \(core A\*\)/);
  });

  it("a run that is not badge-eligible keeps its reason", () => {
    const custom = run({ core: { status: "graded", grade: grade("core", "A") } }, undefined, { badge: { eligible: false, reason: "custom run" } });
    assert.match(renderText(custom, { gate: "B" }), /Badge: not eligible: custom run\./);
  });
});

describe("the cap note prints only when the cap lowered the letter", () => {
  const capped = (raw: Letter, letter: Letter) => run({ fs: { status: "graded", grade: grade("fs", letter, { raw, capped: true, criticalFails: ["fs-read-escape"] }) } }, [check("fs-read-escape", "fail", { critical: true, pack: "fs" })]);

  it("a pack whose raw grade was C and whose letter is D says so, in text and markdown", () => {
    assert.match(renderText(capped("C", "D")), /Capped at D: critical fail\(s\): fs-read-escape\. Without the cap this would be C/);
    assert.match(renderMarkdown([capped("C", "D")]), /Capped at D by critical fail\(s\).*Without the cap this would be C\./);
    assert.match(strip(renderSummary([capped("C", "D")])), /capped at D/);
  });

  it("a pack that was an F anyway has no cap note: nothing was capped", () => {
    assert.doesNotMatch(renderText(capped("F", "F")), /Capped at D/);
    assert.doesNotMatch(renderMarkdown([capped("F", "F")]), /Capped at D/);
    assert.doesNotMatch(strip(renderSummary([capped("F", "F")])), /capped at/);
  });
});

describe("the surface records a parameter declared with anyOf as a type union", () => {
  const tool = (props: Record<string, unknown>) => [{ name: "t", description: "d", inputSchema: { type: "object", properties: props } }];
  const params = (props: Record<string, unknown>) => captureSurface(tool(props) as never, [])[0]!.params;

  it("anyOf, oneOf and allOf resolve to the members' types; a bare null member joins the union", () => {
    assert.deepEqual(params({ a: { anyOf: [{ type: "string" }, { type: "null" }] } }), { a: "string|null" });
    assert.deepEqual(params({ a: { oneOf: [{ type: "integer" }, { type: "string" }, { type: "integer" }] } }), { a: "integer|string" });
    assert.deepEqual(params({ a: { allOf: [{ type: "object" }] } }), { a: "object" });
    assert.deepEqual(params({ a: { anyOf: [{ type: "array", items: { type: "string" } }, { type: "null" }] } }), { a: "array<string>|null" });
  });

  it("near misses: a plain type is unchanged, and a member without a type leaves the whole union unknown", () => {
    assert.deepEqual(params({ a: { type: "string" }, b: { type: ["string", "null"] }, c: {} }), { a: "string", b: "string|null", c: "unknown" });
    assert.deepEqual(params({ a: { anyOf: [{ type: "string" }, { description: "anything" }] } }), { a: "unknown" });
  });

  it("drift sees a change from string|null to number|null, and not an old baseline's unknown", () => {
    const base = (p: unknown) => run({}, [], { server: { name: "Toy", version: "1.0.0", command: "x", env: {}, transport: "stdio", tools: ["t"], sqlTools: [], surface: captureSurface(tool({ a: p }) as never, []) } });
    const changed = surfaceDrift(base({ anyOf: [{ type: "string" }, { type: "null" }] }), base({ anyOf: [{ type: "number" }, { type: "null" }] }));
    assert.deepEqual(changed.filter((d) => d.kind === "param-type-changed").map((d) => [d.from, d.to]), [["string|null", "number|null"]]);
    const old = base({ anyOf: [{ type: "string" }, { type: "null" }] });
    old.server.surface![0]!.params = { a: "unknown" };
    assert.deepEqual(surfaceDrift(old, base({ anyOf: [{ type: "string" }, { type: "null" }] })).filter((d) => d.kind === "param-type-changed"), []);
  });
});

describe("drift compares the version the server announced, not a configured label", () => {
  const withVersion = (label: string, announced?: string) =>
    run({}, [], { server: { name: "Toy", version: label, command: "x", env: {}, transport: "stdio", tools: ["t"], sqlTools: [], surface: [], resolved: { configVersion: label, ...(announced ? { serverInfoVersion: announced } : {}) } } });
  const versionLines = (a: RunResult, b: RunResult) => surfaceDrift(a, b).filter((d) => d.kind === "server-version-changed");

  it("a baseline that carried a label and a run that did not, with the same announced version, drift not at all", () => {
    assert.deepEqual(versionLines(withVersion("2.0.0-label", "1.4.0"), withVersion("1.4.0", "1.4.0")), []);
  });

  it("a different announced version is reported, from and to", () => {
    const d = versionLines(withVersion("x", "1.4.0"), withVersion("x", "1.5.0"));
    assert.deepEqual(d.map((e) => [e.from, e.to]), [["1.4.0", "1.5.0"]]);
  });

  it("a report from before the resolved block compares by server.version as it always did", () => {
    const old = (v: string) => run({}, [], { server: { name: "Toy", version: v, command: "x", env: {}, transport: "stdio", tools: ["t"], sqlTools: [], surface: [] } });
    assert.equal(versionLines(old("1.0.0"), old("1.1.0")).length, 1);
    assert.equal(versionLines(old("1.0.0"), withVersion("1.1.0", "1.1.0")).length, 0, "the two are not measured the same way: nothing is claimed");
  });
});

describe("renderReport keeps working with the new options", () => {
  it("every format renders a run with an inconclusive pack and a gate", () => {
    const r = run({ core: { status: "graded", grade: grade("core", "A") }, fs: { status: "inconclusive", reason: "x" } });
    for (const f of ["text", "json", "markdown", "junit", "sarif", "summary", "badge", "shields"] as const) assert.ok(renderReport(f, [r], { gate: "B", treatInconclusiveAs: "fail" }).length > 0, f);
  });
});
