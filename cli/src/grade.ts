import type { CheckResult, Letter, PackGrade, PackId } from "./types.js";

/** Worst to best, so an index comparison reads as "at least this good". */
export const LETTERS: Letter[] = ["F", "D", "C", "B", "A"];

export function letterFor(pct: number): Letter {
  if (pct >= 90) return "A";
  if (pct >= 75) return "B";
  if (pct >= 60) return "C";
  if (pct >= 45) return "D";
  return "F";
}

export function meetsThreshold(letter: Letter, min: Letter): boolean {
  return LETTERS.indexOf(letter) >= LETTERS.indexOf(min);
}

const POINTS: Partial<Record<CheckResult["verdict"], number>> = { pass: 1, part: 0.5, fail: 0 };

/**
 * Grade one pack. Returns null when nothing was scored: the caller then reports the pack as
 * not applicable or inconclusive and never invents a letter.
 */
export function gradePack(pack: PackId, checks: CheckResult[]): PackGrade | null {
  const mine = checks.filter((c) => c.pack === pack && !c.advisory);
  const scoredChecks = mine.filter((c) => c.verdict in POINTS);
  if (scoredChecks.length === 0) return null;
  const points = scoredChecks.reduce((sum, c) => sum + (POINTS[c.verdict] ?? 0), 0);
  const scored = scoredChecks.length;
  // Points move in halves, so this division is exact at every letter boundary.
  const exact = (points * 100) / scored;
  const raw = letterFor(exact);
  const criticalFails = scoredChecks.filter((c) => c.critical && c.verdict === "fail").map((c) => c.id);
  const letter: Letter = criticalFails.length && LETTERS.indexOf(raw) > 1 ? "D" : raw;
  return {
    pack,
    points,
    scored,
    pct: Math.round(exact * 100) / 100,
    raw,
    letter,
    capped: letter !== raw,
    criticalFails,
    provisional: mine.some((c) => c.critical && c.verdict === "inconclusive"),
    excluded: mine.filter((c) => c.verdict === "inconclusive" || c.verdict === "na").map((c) => c.id),
  };
}
