import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decideExit, type ExitPolicy } from "../report/exit.js";
import type { Letter, PackGrade, RunResult } from "../types.js";

function grade(pack: string, letter: Letter, provisional = false): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 4, scored: 4, pct: 100, raw: letter, letter, capped: false, criticalFails: [], provisional, excluded: [] };
}

function run(packs: Record<string, PackGrade>, name = "toy"): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name, version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: [], sqlTools: [] },
    options: { packsRequested: Object.keys(packs) as never, timeoutProbeSec: 10 },
    startedAt: "2026-10-12T00:00:00.000Z",
    durationMs: 1,
    packs: Object.fromEntries(Object.entries(packs).map(([id, g]) => [id, { status: "graded", grade: g }])),
    checks: [],
    notCovered: [],
  } as RunResult;
}

const policy = (failUnder: Letter | undefined, o: Partial<ExitPolicy> = {}): ExitPolicy => ({
  failUnder,
  treatInconclusiveAs: "pass",
  criticalFail: 0,
  failOnGate: true,
  failOnRegressions: true,
  failOnDrift: false,
  regressions: [],
  drift: [],
  baseline: false,
  ...o,
});

describe("a provisional grade at the A gate", () => {
  it("A* beside a plain A fails --fail-under A, with the message and the reason", () => {
    const d = decideExit([run({ core: grade("core", "A"), fs: grade("fs", "A", true) })], policy("A"));
    assert.equal(d.code, 1);
    assert.deepEqual(d.messages, ["pack fs graded A* (provisional: a critical check was inconclusive), which does not meet --fail-under A"]);
    assert.equal(d.reason, "a provisional grade does not meet the A gate");
  });

  it("A* meets a lower gate: --fail-under B exits 0", () => {
    const d = decideExit([run({ core: grade("core", "A"), fs: grade("fs", "A", true) })], policy("B"));
    assert.equal(d.code, 0);
    assert.deepEqual(d.messages, []);
  });

  it("a provisional B at the A gate is already below it: one 'below' message, not the provisional one", () => {
    const d = decideExit([run({ core: grade("core", "B", true) })], policy("A"));
    assert.equal(d.code, 1);
    assert.deepEqual(d.messages, ["pack core graded B, below --fail-under A"]);
    assert.equal(d.reason, "a graded pack is below the gate (A)");
  });

  it("a provisional B meets --fail-under B (the rule is specific to A)", () => {
    assert.equal(decideExit([run({ core: grade("core", "B", true) })], policy("B")).code, 0);
  });

  it("a plain A still passes the A gate", () => {
    assert.equal(decideExit([run({ core: grade("core", "A"), fs: grade("fs", "A") })], policy("A")).code, 0);
  });

  it("--fail-under none is off: an A* exits 0 and the reason says the gate is off", () => {
    const d = decideExit([run({ core: grade("core", "A", true) })], policy(undefined));
    assert.equal(d.code, 0);
    assert.equal(d.reason, "the gate is off (--fail-under none); grades do not affect the exit code");
  });

  it("when the grade gate is not deciding the exit code (--fail-on regressions), the provisional rule does not apply", () => {
    const d = decideExit([run({ core: grade("core", "A", true) })], policy("A", { failOnGate: false }));
    assert.equal(d.code, 0);
  });

  it("with several servers the message names the server that holds the provisional grade", () => {
    const d = decideExit([run({ core: grade("core", "A") }, "first"), run({ core: grade("core", "A", true) }, "second")], policy("A"));
    assert.equal(d.code, 1);
    assert.deepEqual(d.messages, ["server second: pack core graded A* (provisional: a critical check was inconclusive), which does not meet --fail-under A"]);
  });
});
