import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderSummary } from "../report/summary.js";
import type { CheckResult, Evidence, PackGrade, RunResult } from "../types.js";

const grade = (pack: string, letter: PackGrade["letter"]): PackGrade => ({ pack: pack as PackGrade["pack"], points: 1, scored: 2, pct: 50, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [] });

const ev = (probe: string, code?: string): Evidence => ({ probe, outcome: "o", verifiedBy: "response", ...(code ? { code } : {}) });

const failing = (evidence: Evidence[]): CheckResult => ({ id: "fs-traversal", pack: "fs", label: "Traversal", critical: false, scope: "test", verdict: "fail", summary: "a path escaped", evidence });

function run(checks: CheckResult[]): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["a"], sqlTools: [] },
    options: { packsRequested: ["fs"], timeoutProbeSec: 10 },
    startedAt: "2026-10-12T00:00:00.000Z",
    durationMs: 1,
    packs: { fs: { status: "graded", grade: grade("fs", "D") } },
    checks,
    notCovered: [],
  };
}

const evidenceLine = (out: string) => out.split("\n").find((l) => l.includes("evidence:")) ?? "";

describe("WHAT TO FIX quotes the deciding probe, not a control line", () => {
  it("skips a leading control line and a skip line and quotes the first real probe", () => {
    const k = failing([ev("control: read ok.txt", "fs.control.read"), ev("skipped: write tool", "fs.write.skipped"), ev("read ../canary", "fs.traversal")]);
    assert.match(evidenceLine(renderSummary([run([k])])), /evidence: read \.\.\/canary/);
  });

  it("a bare control code is a control line too", () => {
    const k = failing([ev("control: list", "git.control"), ev("the real probe", "git.arg-injection")]);
    assert.match(evidenceLine(renderSummary([run([k])])), /evidence: the real probe/);
  });

  it("falls back to the first evidence when every line is a control line", () => {
    const k = failing([ev("control: read ok.txt", "fs.control.read"), ev("control: list", "fs.control")]);
    assert.match(evidenceLine(renderSummary([run([k])])), /evidence: control: read ok\.txt/);
  });

  it("a code that merely contains the word control is not a control line", () => {
    const k = failing([ev("read the file", "fs.controller-bypass")]);
    assert.match(evidenceLine(renderSummary([run([k])])), /evidence: read the file/);
  });

  it("evidence without a code keeps its old place", () => {
    const k = failing([ev("first"), ev("second", "fs.x")]);
    assert.match(evidenceLine(renderSummary([run([k])])), /evidence: first/);
  });
});
