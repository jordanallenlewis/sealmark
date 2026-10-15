import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderReport, renderText } from "../report.js";
import { packsApplied, scoreText } from "../report/common.js";
import { renderSummary } from "../report/summary.js";
import type { CheckResult, PackGrade, RunResult } from "../types.js";

const grade = (pack: string, letter: PackGrade["letter"], o: Partial<PackGrade> = {}): PackGrade => ({ pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o });
const check = (id: string, verdict: CheckResult["verdict"], o: Partial<CheckResult> = {}): CheckResult => ({ id, pack: "core", label: id, critical: false, scope: "test", verdict, summary: "test", evidence: [], ...o });

function run(over: Partial<RunResult> = {}): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "Toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["a"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-12T00:00:00.000Z",
    durationMs: 1,
    packs: { core: { status: "graded", grade: grade("core", "B") } },
    checks: [check("c1", "pass"), check("c2", "pass"), check("c3", "pass"), check("c4", "part")],
    notCovered: [],
    ...over,
  };
}

describe("an advisory check prints one verdict tag", () => {
  const r = run({ checks: [check("protocol", "pass"), check("write-gate", "fail", { advisory: true, label: "Write gate" }), check("redirect", "na", { advisory: true, label: "Redirects" })] });
  const t = renderText(r);

  it("[FAIL] and [N/A ] carry the suffix '(advisory, not scored)' and no [ADV ] prefix", () => {
    assert.match(t, /\n {2}\[FAIL\] Write gate — test \(advisory, not scored\)\n/);
    assert.match(t, /\n {2}\[N\/A \] Redirects — test \(advisory, not scored\)\n/);
    assert.ok(!t.includes("[ADV"));
  });

  it("a scored check has no suffix", () => {
    assert.match(t, /\n {2}\[PASS\] protocol — test\n/);
  });
});

describe("one score fraction in text, markdown and the summary card", () => {
  it("scoreText prints points over scored and the percentage, plus the unscored count only when a check was left out", () => {
    assert.equal(scoreText(grade("core", "B"), 4), "3/4 points, 75%");
    assert.equal(scoreText(grade("core", "B", { points: 2, scored: 3, pct: 66.7 }), 5), "2/3 points, 66.7% · 2 of 5 checks not scored");
    assert.equal(scoreText(grade("core", "B", { points: 4, scored: 4, pct: 100 }), 4), "4/4 points, 100%");
  });

  it("the three formats print the same fraction for the same pack", () => {
    const g = grade("core", "B", { points: 2, scored: 3, pct: 66.7, excluded: ["c4"] });
    const x = run({ packs: { core: { status: "graded", grade: g } } });
    const want = "2/3 points, 66.7% · 1 of 4 checks not scored";
    assert.match(renderText(x), new RegExp(`PACK core {2}GRADE B {2}\\(${want.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\)`));
    assert.ok(renderReport("markdown", [x]).includes(`**Grade B** (${want})`));
    assert.match(renderSummary([x]), /2\/3 points/);
    assert.ok(!/scored\*?\s*│/.test(renderSummary([x])), "the card no longer says 'N/M scored'");
  });

  it("the summary card keeps the provisional star after the points", () => {
    const x = run({ packs: { core: { status: "graded", grade: grade("core", "B", { provisional: true }) } } });
    assert.match(renderSummary([x]), /3\/4 points\*/);
  });
});

describe("packs applied lists core and says none when nothing ran", () => {
  const cls = [{ tool: "read_file", class: "path" as const, confidence: "high" as const, params: { path: "path" }, unfillable: [], reasons: ['param "path"'] }];

  it("packsApplied includes core, in report order, and skips n/a packs", () => {
    const x = run({ packs: { core: { status: "graded", grade: grade("core", "A") }, fs: { status: "inconclusive", reason: "r" }, db: { status: "na", reason: "r" } } as RunResult["packs"] });
    assert.deepEqual(packsApplied(x), ["core", "fs"]);
  });

  it("text and markdown print the list", () => {
    const x = run({ classification: cls, packs: { core: { status: "graded", grade: grade("core", "A") }, fs: { status: "graded", grade: grade("fs", "A") } } });
    assert.match(renderText(x), /\n {2}packs applied: core, fs\n/);
    assert.match(renderReport("markdown", [x]), /\nPacks applied: core, fs\n/);
  });

  it("with core not requested and nothing else graded the line says none, not 'core only'", () => {
    const x = run({ classification: cls, packs: { core: { status: "na", reason: "pack not requested" }, db: { status: "na", reason: "no sql tool" } } as RunResult["packs"] });
    assert.deepEqual(packsApplied(x), []);
    assert.match(renderText(x), /\n {2}packs applied: none\n/);
    assert.match(renderReport("markdown", [x]), /\nPacks applied: none\n/);
    assert.ok(!renderText(x).includes("packs applied: core only"));
  });
});
