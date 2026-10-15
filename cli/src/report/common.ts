import { CANDIDATE_PACKS, type CheckResult, type PackGrade, type PackId, type RunResult, type Suggestion, type Verdict } from "../types.js";
import { inertLines } from "./sanitize.js";

/** A server whose run ended in a harness failure (exit 4). Written to JSON so a matrix or a CI artifact never silently lacks it. */
export interface FailedRun {
  status: "failed";
  server: string;
  error: string;
  hint?: string;
  stderrFile?: string;
  sealmark: { version: string; methodology: string };
}

export type AnyRun = RunResult | FailedRun;
export const isFailed = (r: AnyRun): r is FailedRun => (r as FailedRun).status === "failed" && !("packs" in r);

export const CLOSING_LINE = "An A means these checks passed with this exact configuration. It is not a security endorsement; see methodology.";

/** A candidate pack (types.ts `CANDIDATE_PACKS`, the design notes): scored in its own pack, labelled in every report, left off the badge. */
export const isCandidatePack = (id: string): boolean => CANDIDATE_PACKS.includes(id as PackId);
/** The label every format prints next to a candidate pack's grade. */
export const CANDIDATE_LABEL = "candidate pack: not part of the standard profile";

/** core, db, sqlite, http, fs, net, git, exec, effects, the candidate packs, custom, then plugin packs in the order they ran. */
export const PACK_ORDER: PackId[] = ["core", "db", "sqlite", "http", "fs", "net", "git", "exec", "effects", ...CANDIDATE_PACKS, "custom"];

/** The round 6 fields of a result (`upstream`, `identities`, `suggestions`), read defensively: a report written before them has none. */
export function round6Fields(r: RunResult): {
  upstream?: RunResult["upstream"];
  identities?: RunResult["identities"];
  suggestions: Suggestion[];
} {
  return { upstream: r.upstream, identities: r.identities, suggestions: Array.isArray(r.suggestions) ? r.suggestions : [] };
}

/** `upstream: http stub {upstream}, 12 requests recorded (3 answered by a scripted reply)`, or undefined when no stub ran. */
export function upstreamLine(r: RunResult): string | undefined {
  const u = round6Fields(r).upstream;
  if (!u) return undefined;
  return `upstream: ${u.kind} stub ${u.url}, ${u.requests} request${u.requests === 1 ? "" : "s"} recorded (${u.scripted} answered by a scripted reply)`;
}

/** `identities: a, b (minted for this run)`, or undefined. Names only: the tokens are never printed. */
export function identitiesLine(r: RunResult): string | undefined {
  const i = round6Fields(r).identities;
  if (!i) return undefined;
  return `identities: ${i.names.join(", ")} (${i.source === "config" ? "from identities.* in the configuration" : "minted for this run"})`;
}

/**
 * `inert` is one physical line, which would turn a suggestion's YAML into a single line. The renderers make the whole result inert and then call this to put
 * the YAML back with its line structure, every line made inert on its own (`from` is the redacted result before inertDeep).
 */
export function withSuggestionLines<T extends RunResult>(inertResult: T, from: RunResult): T {
  const original = round6Fields(from).suggestions;
  if (!original.length) return inertResult;
  const inertFields = round6Fields(inertResult).suggestions;
  // Keep the inert copy of every other field (why, id, flags, tools); only config returns to multi-line.
  const suggestions = original.map((s, i) => ({ ...(inertFields[i] ?? s), config: typeof s.config === "string" ? inertLines(s.config) : "" }));
  return { ...inertResult, suggestions } as T;
}

/** The "Suggestions" block of the text report: what to add to sealmark.yaml (or pass as flags) and why. Empty without suggestions. */
export function suggestionLines(r: RunResult): string[] {
  const list = round6Fields(r).suggestions;
  if (!list.length) return [];
  const out = ["Suggestions:"];
  for (const s of list) {
    out.push(`  - [${s.kind}] ${s.why}`);
    if (s.flags?.length) out.push(`      flags: ${s.flags.join(" ")}`);
    if (s.config) {
      out.push("      sealmark.yaml:");
      for (const l of s.config.replace(/\s+$/, "").split("\n")) out.push(`        ${l}`);
    }
  }
  return out;
}
export function orderedPackIds(r: RunResult): PackId[] {
  const ids = Object.keys(r.packs) as PackId[];
  return [...PACK_ORDER.filter((p) => ids.includes(p)), ...ids.filter((p) => !PACK_ORDER.includes(p))];
}

export const TAG: Record<Verdict, string> = { pass: "PASS", part: "PART", fail: "FAIL", inconclusive: "INCL", na: "N/A " };
/** Worst first, so a failure is never buried under passes. */
export const SEVERITY: Verdict[] = ["fail", "part", "inconclusive", "pass", "na"];

const LETTER_ORDER = "ABCDF";

/** True when the critical-fail cap lowered the letter: a pack whose raw grade was already D or F was not changed by it, so no note about "the cap" is printed for it. */
export const capLoweredLetter = (g: PackGrade): boolean => g.capped && LETTER_ORDER.indexOf(g.raw) < LETTER_ORDER.indexOf(g.letter);

/**
 * The graded packs whose letter is below `gate` (a provisional A* counts as below an A gate, as the exit code does), as `core B`.
 * Empty without a gate: no letter is judged then.
 */
export function packsBelowGate(r: RunResult, gate: string | undefined): string[] {
  const g = gate?.toUpperCase();
  if (!g || !LETTER_ORDER.includes(g)) return [];
  const out: string[] = [];
  for (const id of orderedPackIds(r)) {
    const grade = r.packs[id]?.status === "graded" ? r.packs[id]?.grade : undefined;
    if (!grade) continue;
    const below = LETTER_ORDER.indexOf(grade.letter) > LETTER_ORDER.indexOf(g) || (g === "A" && grade.letter === "A" && grade.provisional);
    if (below) out.push(`${id} ${grade.letter}${grade.provisional ? "*" : ""}`);
  }
  return out;
}

/** The badge decision, said so that it never reads as a recommendation next to a grade the gate rejects: `not recommended (fs F)`. */
export function badgeLine(r: RunResult, gate?: string): string | undefined {
  if (!r.badge) return undefined;
  if (!r.badge.eligible) return `Badge: not eligible: ${r.badge.reason ?? "unspecified"}.`;
  const below = packsBelowGate(r, gate);
  if (below.length) return `Badge: not recommended (${below.join(", ")}): the run is eligible (a STANDARD run with a graded pack beyond core), but a graded pack is below the gate (${gate!.toUpperCase()}).`;
  return "Badge: eligible (a STANDARD run with a graded pack beyond core).";
}

export const pctText = (pct: number) => `${Math.round(pct * 10) / 10}%`;

/**
 * The one score fraction every format prints: `3/4 points, 75%`, and, when a check was left out of the score,
 * `· 1 of 5 checks not scored`. `totalNonAdvisory` is the number of non-advisory checks in the pack.
 */
export function scoreText(g: PackGrade, totalNonAdvisory: number): string {
  const base = `${g.points}/${g.scored} points, ${pctText(g.pct)}`;
  return totalNonAdvisory > g.scored ? `${base} · ${totalNonAdvisory - g.scored} of ${totalNonAdvisory} checks not scored` : base;
}

/** Scored checks first (worst verdict on top), then advisory ones. Order is otherwise stable. */
export function sortChecks(checks: CheckResult[]): CheckResult[] {
  const rank = (c: CheckResult) => (c.advisory ? SEVERITY.length : 0) + SEVERITY.indexOf(c.verdict);
  return checks.map((c, i) => ({ c, i })).sort((a, b) => rank(a.c) - rank(b.c) || a.i - b.i).map((x) => x.c);
}

/** `name version` without a double space when the version is empty (item 30). */
export const serverLabel = (r: RunResult) => [r.server.name, r.server.version].filter((x) => x && x.trim()).join(" ");

const short = (v: unknown, max = 70): string => {
  const t = typeof v === "string" ? v : JSON.stringify(v);
  const s = t === undefined ? "undefined" : t;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};

/** `STANDARD`, `CUSTOM (not the published methodology: 3 differences)`, or undefined when the run carries no configuration identity. */
export function standardLabel(r: RunResult): string | undefined {
  if (!r.config) return undefined;
  if (r.config.standard) return "STANDARD";
  const n = r.config.standardDiff.length;
  return `CUSTOM (not the published methodology: ${n} difference${n === 1 ? "" : "s"})`;
}

/** One line per difference from the standard profile. Empty for a standard run. */
export function diffLines(r: RunResult): string[] {
  if (!r.config || r.config.standard) return [];
  return r.config.standardDiff.map((d) => `  ${d.path}: standard ${short(d.standard)}, effective ${short(d.effective)}  (${d.origin})`);
}

/**
 * The integrity header. Every renderer prints it and no template can remove it: it is added around whatever a template produced.
 * Without a configuration identity (library callers, hand-built results) it is the 0.1 header.
 */
export function headerLine(r: RunResult): string {
  const std = standardLabel(r);
  return ["sealmark " + r.sealmark.version, `methodology ${r.sealmark.methodology}`, ...(std ? [std] : []), serverLabel(r)].filter(Boolean).join(" · ");
}

export function headerBlock(r: RunResult): string[] {
  const out = [headerLine(r), ...diffLines(r)];
  if (r.config && !r.config.standard) out.push("  Grades in this report are custom grades: they are not comparable to a STANDARD grade, and a custom run gets no badge.");
  return out;
}

/** The text after the core grade: hygiene-only / low coverage, with the valid-call count (addendum 1.4). */
export function coverageTag(r: RunResult): string | undefined {
  const c = r.coverage;
  if (!c || c.level === "covered") return undefined;
  const otherGraded = Object.entries(r.packs).some(([id, p]) => id !== "core" && p?.status === "graded");
  return `${otherGraded ? "low coverage" : "hygiene only"} · tools called with valid arguments: ${c.toolsCalledValid} of ${c.toolsTotal}`;
}

/**
 * `server-a 1.2.4 (npx-cache)`, or, when the package manager's cache held no match, the version the server announced with
 * the source said out loud, so a reader never mistakes the announced version for a resolved one.
 */
export function packageLabel(r: RunResult): string | undefined {
  const pkg = r.server.resolved?.package;
  if (!pkg) return undefined;
  // Several versions sit in the cache and none ran for certain: the line says so and what to type.
  const candidates = pkg.candidates;
  if (candidates?.length) {
    const announced = r.server.resolved?.serverInfoVersion;
    return `${pkg.name} unknown (several versions in the ${pkg.source.replace(/-cache$/, " cache")}: ${candidates.join(", ")}${announced ? `; the server announced ${announced}` : ""}; pin the version)`;
  }
  if (pkg.source === "not found" && r.server.resolved?.serverInfoVersion) return `${pkg.name} ${r.server.resolved.serverInfoVersion} (serverInfo version; the package was not found in the cache)`;
  // A package whose version could not be read is said so, not printed as "unknown" or as a name with a gap.
  const version = pkg.version;
  if (!version || version === "unknown") return `${pkg.name} (version unknown, ${pkg.source})`;
  return `${pkg.name} ${version} (${pkg.source})`;
}

/** The environment variables the server inherited from the caller's environment under the scrubbed sandbox env, as `inherited: A, B`. Undefined when there are none or the report predates the field. */
export function inheritedText(r: RunResult): string | undefined {
  const list = r.sandbox?.inherited;
  return list?.length ? `inherited: ${list.join(", ")}` : undefined;
}

/**
 * Where the finding is about: the configuration file the run used and the line of the selected server's `command`/`url`.
 * `config.line` is absent for a run with no config file or a report written by an older build, so a missing or invalid line is line 1. Undefined when the run had no configuration file.
 */
export function configLocation(r: RunResult): { file: string; line: number } | undefined {
  const cfg = r.config;
  if (!cfg?.path) return undefined;
  const file = cfg.path.split(/[\\/]/).pop() || "sealmark.yaml";
  const line = typeof cfg.line === "number" && Number.isInteger(cfg.line) && cfg.line >= 1 ? cfg.line : 1;
  return { file, line };
}

/** The classes a tool also matched at medium or higher, for the reader to check a mis-chosen primary class. Empty when none. */
export const secondaryText = (c: { secondary?: readonly string[]; reasons?: readonly string[] }): string =>
  // A secondary class the net pack consumes is already named in the tool's reasons ("secondary: url (probed by net)"): say it once.
  c.secondary?.length && !c.reasons?.some((x) => x.startsWith("secondary:")) ? `secondary: ${c.secondary.join(", ")}` : "";

/** Packs that took part in this run, core included (graded or inconclusive), in report order: the `packs applied:` line of the classification block. */
export function packsApplied(r: RunResult): PackId[] {
  return orderedPackIds(r).filter((id) => r.packs[id]?.status === "graded" || r.packs[id]?.status === "inconclusive");
}

/** `core A (hygiene only) · db D capped: critical fail: mutating-sql · custom` (addendum item 22). */
export function summaryLine(r: RunResult): string {
  const parts: string[] = [];
  for (const id of orderedPackIds(r)) {
    const p = r.packs[id];
    if (!p || p.status === "na") continue;
    if (p.status === "inconclusive") {
      parts.push(`${id} inconclusive`);
      continue;
    }
    if (!p.grade) continue;
    const g = p.grade;
    let s = `${id} ${g.letter}${g.provisional ? "*" : ""}`;
    if (id === "core" && r.coverage && r.coverage.level !== "covered" && !Object.entries(r.packs).some(([k, x]) => k !== "core" && x?.status === "graded")) s += " (hygiene only)";
    // A critical fail is named whether or not it capped the grade (an F stays an F), and a critical check at `part` is marked: the exit code never contradicts the line.
    if (g.capped) s += ` capped: critical fail: ${g.criticalFails.join(", ")}`;
    else if (g.criticalFails.length) s += ` critical fail: ${g.criticalFails.join(", ")}`;
    const criticalPart = r.checks.filter((c) => c.pack === id && c.critical && !c.advisory && c.verdict === "part").map((c) => c.id);
    if (criticalPart.length) s += ` critical part: ${criticalPart.join(", ")}`;
    parts.push(s);
  }
  if (!parts.length) parts.push("nothing graded");
  if (r.config && !r.config.standard) parts.push("custom");
  return parts.join(" · ");
}

export function xmlEscape(s: string): string {
  return s
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, "?")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
