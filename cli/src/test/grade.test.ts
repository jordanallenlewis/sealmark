import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { LETTERS, gradePack, letterFor, meetsThreshold } from "../grade.js";
import { check } from "./helpers.js";

const passes = (n: number) => Array.from({ length: n }, (_, i) => check(`p${i}`, "pass"));

describe("grade", () => {
  it("maps percentages to letters at the published boundaries", () => {
    assert.deepEqual([100, 90, 89.9, 75, 74.9, 60, 59.9, 45, 44.9, 0].map(letterFor), ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]);
  });

  it("orders letters for the CI gate", () => {
    assert.deepEqual(LETTERS, ["F", "D", "C", "B", "A"]);
    assert.ok(meetsThreshold("A", "B"));
    assert.ok(meetsThreshold("B", "B"));
    assert.ok(!meetsThreshold("C", "B"));
    assert.ok(!meetsThreshold("F", "D"));
  });

  it("caps at D when a critical check fails, even with a high raw score", () => {
    const g = gradePack("core", [...passes(9), check("rls", "fail", { critical: true })])!;
    assert.equal(g.pct, 90);
    assert.equal(g.raw, "A");
    assert.equal(g.letter, "D");
    assert.equal(g.capped, true);
    assert.deepEqual(g.criticalFails, ["rls"]);
  });

  it("does not raise or flag a cap when the raw grade is already D or lower", () => {
    const g = gradePack("core", [check("rls", "fail", { critical: true }), check("a", "fail"), check("b", "fail")])!;
    assert.equal(g.raw, "F");
    assert.equal(g.letter, "F");
    assert.equal(g.capped, false);
    assert.deepEqual(g.criticalFails, ["rls"]);
  });

  it("scores part as half a point and ignores advisory checks", () => {
    const g = gradePack("core", [check("a", "pass"), check("b", "part"), check("adv", "fail", { advisory: true })])!;
    assert.equal(g.scored, 2);
    assert.equal(g.points, 1.5);
    assert.equal(g.pct, 75);
    assert.equal(g.letter, "B");
    assert.equal(g.capped, false);
  });

  it("marks a grade provisional when a critical check was inconclusive, and excludes it from the score", () => {
    const g = gradePack("core", [check("a", "pass"), check("b", "pass"), check("secret", "inconclusive", { critical: true }), check("c", "na")])!;
    assert.equal(g.provisional, true);
    assert.equal(g.scored, 2);
    assert.equal(g.letter, "A");
    assert.ok(g.excluded.includes("secret"));
    assert.ok(g.excluded.includes("c"));
  });

  it("is not provisional when only a non-critical check is inconclusive", () => {
    const g = gradePack("core", [check("a", "pass"), check("b", "inconclusive")])!;
    assert.equal(g.provisional, false);
  });

  it("returns null when nothing is scored, so no letter is invented", () => {
    assert.equal(gradePack("core", [check("a", "na"), check("b", "inconclusive", { critical: true }), check("adv", "pass", { advisory: true })]), null);
    assert.equal(gradePack("core", []), null);
  });

  it("only looks at checks of the requested pack", () => {
    const g = gradePack("db", [check("a", "pass", { pack: "db" }), check("x", "fail", { pack: "core", critical: true })])!;
    assert.equal(g.letter, "A");
    assert.equal(gradePack("db", [check("x", "pass", { pack: "core" })]), null);
  });
});
