import type { Letter } from "../types.js";
import type { RenderOptions } from "../report.js";
import { orderedPackIds, isCandidatePack, isFailed, xmlEscape, type AnyRun } from "./common.js";

/**
 * `--format badge` (SVG) and `--format shields` (a shields.io endpoint document). Both are local and self-reported: nothing is
 * uploaded and nothing vouches for the result. The text is built from harness constants only (the methodology version, pack ids
 * and letters), never from the server's name or anything it said, so an image others embed carries no server-controlled text.
 * No overall letter is computed: the message lists one letter per graded pack, and the colour follows the worst of them.
 */

export interface BadgeText {
  label: string;
  message: string;
  color: string;
}

const LETTER_COLOR: Record<Letter, string> = { A: "brightgreen", B: "green", C: "yellow", D: "orange", F: "red" };
const LETTER_RANK: Letter[] = ["A", "B", "C", "D", "F"];
const FILL: Record<string, string> = { brightgreen: "#4c1", green: "#97ca00", yellow: "#dfb317", orange: "#fe7d37", red: "#e05d44", lightgrey: "#9f9f9f" };

const none = (label: string, why: string): BadgeText => ({ label, message: `no badge: ${why}`, color: "lightgrey" });

export function badgeText(r: AnyRun): BadgeText {
  const label = `sealmark ${r.sealmark.methodology}`;
  if (isFailed(r)) return none(label, "server failed");
  // Candidate packs (scope, sql-guard, upstream) are scored but not part of the standard: they never appear on the badge.
  const graded = orderedPackIds(r).filter((id) => !isCandidatePack(id)).flatMap((id) => {
    const p = r.packs[id];
    return p?.status === "graded" && p.grade ? [{ id, grade: p.grade }] : [];
  });
  if (r.badge?.eligible !== true) {
    const why = r.badge?.reason ?? "";
    if (why.startsWith("custom run")) return none(label, "custom run");
    if (why.startsWith("core-only")) return none(label, "core only");
    // A grade with a critical check left unmeasured (run.ts badgeFor) may drop, so it earns no badge yet.
    if (/provisional|inconclusive critical/.test(why)) return none(label, "provisional");
    return none(label, graded.length ? "not eligible" : "nothing graded");
  }
  if (!graded.length) return none(label, "nothing graded");
  const worst = graded.reduce((w, g) => (LETTER_RANK.indexOf(g.grade.letter) > LETTER_RANK.indexOf(w) ? g.grade.letter : w), "A" as Letter);
  const parts = graded.map((g) => `${g.id} ${g.grade.letter}${g.grade.provisional ? "*" : ""}`);
  return { label, message: [...parts, "self-reported"].join(" · "), color: LETTER_COLOR[worst] };
}

/** One side of the badge: 10 px of padding plus a fixed 6.5 px per character, so the width never depends on a font or a machine. */
const sideWidth = (s: string): number => 10 + Math.ceil([...s].length * 6.5);

export function renderBadge(runs: AnyRun[], o: RenderOptions): string {
  void o;
  const t = badgeText(runs[0]);
  const full = xmlEscape(`${t.label}: ${t.message}`);
  const left = sideWidth(t.label);
  const right = sideWidth(t.message);
  const total = left + right;
  const fill = FILL[t.color] ?? FILL.lightgrey;
  const text = (s: string, cx: number) =>
    `<text x="${cx}" y="15" fill="#010101" fill-opacity=".3">${xmlEscape(s)}</text><text x="${cx}" y="14">${xmlEscape(s)}</text>`;
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${full}"><title>${full}</title>` +
    `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>` +
    `<clipPath id="r"><rect width="${total}" height="20" rx="3"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${left}" height="20" fill="#555"/><rect x="${left}" width="${right}" height="20" fill="${fill}"/><rect width="${total}" height="20" fill="url(#s)"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">${text(t.label, left / 2)}${text(t.message, left + right / 2)}</g></svg>\n`
  );
}

export function renderShields(runs: AnyRun[], o: RenderOptions): string {
  void o;
  const t = badgeText(runs[0]);
  return JSON.stringify({ schemaVersion: 1, label: t.label, message: t.message, color: t.color }, null, 2) + "\n";
}
