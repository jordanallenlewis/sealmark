import type { CheckResult, PackId, RunResult } from "../types.js";
import { CLOSING_LINE, capLoweredLetter, coverageTag, headerBlock, isFailed, packsBelowGate, type AnyRun, type FailedRun } from "./common.js";
import { redactFailed, redactResult, type RedactOptions } from "./redact.js";
import { clipWidth, displayWidth, inert, inertDeep, wrapWidth } from "./sanitize.js";

/**
 * The `summary` format: what a person wants to see in a CI log at a glance. Grade cards, one row per check
 * (failures first), and a "what to fix" list that says which failure caps a grade. Passes stay short.
 * Machine readers use json/junit/sarif; this is for eyes. Colors only when asked for (see SummaryOptions.color).
 */
export interface SummaryOptions extends RedactOptions {
  /** ANSI colors. The CLI turns them on for a terminal or a CI log, and off for NO_COLOR and files. */
  color?: boolean;
  /** The gate letter the run was held to (for the verdict line). Without one the summary reports the worst grade and does not judge it. */
  gate?: string;
  /** `output.exit_policy.treat_inconclusive_as`. With `fail`, an inconclusive pack fails the gate and the banner says so. */
  treatInconclusiveAs?: "pass" | "fail";
}

const W = 76;
const LETTERS = "ABCDF";

// 5x5 block letters for the grade cards.
const GLYPH: Record<string, string[]> = {
  A: [" ### ", "#   #", "#####", "#   #", "#   #"],
  B: ["#### ", "#   #", "#### ", "#   #", "#### "],
  C: [" ####", "#    ", "#    ", "#    ", " ####"],
  D: ["#### ", "#   #", "#   #", "#   #", "#### "],
  F: ["#####", "#    ", "#### ", "#    ", "#    "],
  "-": ["     ", "     ", " --- ", "     ", "     "],
};

/** Most differences from the standard profile listed under the banner; the JSON report has them all. */
const MAX_DIFFS = 5;

const RANK: Record<string, number> = { fail: 0, part: 1, inconclusive: 2, pass: 3, na: 4 };

/** How many "not covered" lines the summary prints; the JSON report has them all. */
const MAX_NOT_COVERED = 8;

/** Evidence codes that say what the server did (the deciding observation), as against the control call that leads a result. */
const DECIDING_CODE = /(\.none|\.executed|\.leaked|\.attempted|\.created|-hit|-escape|-injection)$/;
const CONTROL_CODE = /(^|\.)control(\.|$)|\.skipped$/;

/** The line to cite for a check: the observation that decided it, else the first line that is not a control call, else the first line. */
function decidingEvidence(k: CheckResult): CheckResult["evidence"][number] | undefined {
  return k.evidence.find((e) => DECIDING_CODE.test(e.code ?? "") && !CONTROL_CODE.test(e.code ?? "")) ?? k.evidence.find((e) => !CONTROL_CODE.test(e.code ?? "")) ?? k.evidence[0];
}

/** Longest error or hint a failed run may print: it can carry the server's own last output. */
const MAX_ERROR = 2000;

/** Everything in a failed run came from the harness or the server, so all of it is made inert (after redaction) and wrapped to the table. */
function failed(run: FailedRun, o: SummaryOptions): string[] {
  const f = redactFailed(run, o);
  const hint = f.hint ? wrapWidth(inert(f.hint, MAX_ERROR), W - 10) : [];
  return [
    "",
    `${clipWidth(inert(f.server, 80), W - 10)}: FAILED`,
    ...wrapWidth(inert(f.error, MAX_ERROR), W - 2).map((l) => `  ${l}`),
    ...hint.map((l, i) => (i === 0 ? `  hint: ${l}` : `        ${l}`)),
    "",
  ];
}

export function renderSummary(runs: AnyRun[], o: SummaryOptions = {}): string {
  const out: string[] = [];
  for (const run of runs) {
    if (isFailed(run)) out.push(...failed(run, o));
    else out.push(...one(inertDeep(redactResult(run, o)), o));
  }
  // trimEnd, not a /\s*$/ regex: that backtracks quadratically on a long run of spaces.
  return out.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

function one(r: RunResult, o: SummaryOptions): string[] {
  const color = o.color === true;
  const sgr = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const green = sgr("32;1"), yellow = sgr("33;1"), red = sgr("31;1"), dim = sgr("2"), bold = sgr("1"), cyan = sgr("36;1");
  const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
  // r is already inert (see renderSummary), so the only escape sequences in a string are our own SGR codes.
  const pad = (s: string, n: number) => s + " ".repeat(Math.max(0, n - displayWidth(strip(s))));
  const center = (s: string, n: number) => {
    const t = Math.max(0, n - displayWidth(strip(s)));
    return " ".repeat(Math.floor(t / 2)) + s + " ".repeat(Math.ceil(t / 2));
  };
  const clip = clipWidth;
  const gradeColor = (g: string) => (g === "A" || g === "B" ? green : g === "C" ? yellow : red);
  const wrap = wrapWidth;
  const box = (lines: string[], width: number, heavy = false) => {
    const [tl, tr, bl, br, h, v] = heavy ? ["╔", "╗", "╚", "╝", "═", "║"] : ["┌", "┐", "└", "┘", "─", "│"];
    return [tl + h.repeat(width - 2) + tr, ...lines.map((l) => `${v} ${pad(l, width - 4)} ${v}`), bl + h.repeat(width - 2) + br];
  };
  const card = (title: string, letter: string, sub: string) => {
    const inner = 17;
    const glyph = Object.hasOwn(GLYPH, letter) ? GLYPH[letter] : GLYPH["-"];
    return box([center(bold(clip(title, inner - 2)), inner), ...glyph.map((row) => center(gradeColor(letter)(row), inner)), center(sub, inner)], inner + 4);
  };

  const gate = o.gate?.toUpperCase();
  const packs = Object.entries(r.packs) as [PackId, RunResult["packs"][PackId] & object][];
  const graded = packs.filter(([, p]) => p.status === "graded" && p.grade);
  const ungraded = packs.filter(([, p]) => !(p.status === "graded" && p.grade));
  const worst = graded.reduce((w, [, p]) => (LETTERS.indexOf(p.grade!.letter) > LETTERS.indexOf(w) ? p.grade!.letter : w), "A");
  // At the A gate a provisional A* does not meet the gate (the exit code says so: decideExit); lower gates are unchanged.
  const missesGate = (p: { grade?: { letter: string; provisional?: boolean } }) => LETTERS.indexOf(p.grade!.letter) > LETTERS.indexOf(gate!) || (gate === "A" && p.grade!.letter === "A" && p.grade!.provisional === true);
  const below = gate ? graded.filter(([, p]) => missesGate(p)) : [];
  /** `B` or `B*`: a provisional grade may drop once its inconclusive critical check can be measured, so it never prints bare. */
  const letterOf = (p: { grade?: { letter: string; provisional?: boolean } }) => `${p.grade!.letter}${p.grade!.provisional ? "*" : ""}`;
  const worstShown = worst + (graded.some(([, p]) => p.grade!.letter === worst && p.grade!.provisional) ? "*" : "");
  const anyProvisional = graded.some(([, p]) => p.grade!.provisional);
  const cov = coverageTag(r);
  const coreGraded = graded.some(([id]) => id === "core");

  const out: string[] = [""];
  const title = "S E A L M A R K   ·   MCP server conformance";
  const meta1 = clip(`${r.server.name}${r.server.version ? ` ${r.server.version}` : ""}  ·  ${r.config?.standard ? "STANDARD" : "CUSTOM"} profile`, W - 4);
  const meta2 = clip(`sealmark ${r.sealmark.version}  ·  methodology ${r.sealmark.methodology}`, W - 4);
  out.push(...box([center(cyan(title), W - 4), center(bold(meta1), W - 4), center(dim(meta2), W - 4)], W, true), "");

  if (r.config && !r.config.standard) {
    // headerBlock is [header line, ...one line per difference, the "custom grades" sentence]; the header line is the banner above.
    const rest = headerBlock(r).slice(1);
    const sentence = rest.pop()!.trim();
    const diffs = rest.slice(0, MAX_DIFFS).map((l) => clip(l, W));
    const n = r.config.standardDiff.length;
    out.push(yellow(`CUSTOM: ${n} setting${n === 1 ? " differs" : "s differ"} from standard`));
    out.push(...diffs.map((l) => dim(l)));
    if (rest.length > diffs.length) out.push(dim(`  ... and ${rest.length - diffs.length} more (the full list is in the JSON report)`));
    out.push(...wrap(sentence, W).map((l) => yellow(l)), "");
  }

  if (graded.length) {
    const cards = graded.map(([id, p]) => {
      const star = p.grade!.provisional ? "*" : "";
      const sub = capLoweredLetter(p.grade!) ? red(`capped at ${p.grade!.letter}${star}`) : id === "core" && cov ? yellow(`${cov.startsWith("low") ? "low coverage" : "hygiene only"}${star}`) : dim(`${p.grade!.points}/${p.grade!.scored} points${star}`);
      return card(id, p.grade!.letter, sub);
    });
    const per = Math.max(1, Math.floor((W + 1) / (cards[0][0].length + 1)));
    for (let i = 0; i < cards.length; i += per) {
      const row = cards.slice(i, i + per);
      for (let k = 0; k < row[0].length; k++) out.push(row.map((c) => c[k]).join(" "));
    }
    out.push("");
  }

  const inconclusiveIds = ungraded.filter(([, p]) => p.status === "inconclusive").map(([id]) => clip(id, 20));
  // A pack that could not be judged is not "graded", so the line below can be true while the run still exits 1: say which way it goes.
  const failsGate = Boolean(gate) && o.treatInconclusiveAs === "fail" && inconclusiveIds.length > 0;
  const inconclusiveNote = inconclusiveIds.length ? `${inconclusiveIds.length} pack${inconclusiveIds.length === 1 ? "" : "s"} not graded (inconclusive): ${inconclusiveIds.join(", ")}` : "";
  out.push(
    graded.length === 0
      ? red("NOTHING WAS GRADED")
      : !gate
        ? `${bold("WORST GRADE: ")}${gradeColor(worst)(worstShown)}${dim("   (no gate is set; --fail-under B makes a low grade fail the run)")}`
      : below.length
        ? `${red(`BELOW ${gate}: `)}${below.map(([id, p]) => `${clip(id, 20)} ${letterOf(p)}`).join(", ")}${dim(`   (worst grade: ${worstShown}${below.some(([, p]) => p.grade!.letter === gate && p.grade!.provisional) ? "; an A* does not meet the A gate" : ""})`)}`
        : failsGate
          ? `${red(`GATE NOT MET: ${inconclusiveIds.join(", ")} inconclusive`)}${dim(`   (graded packs are at ${gate} or better; output.exit_policy.treat_inconclusive_as is fail)`)}`
          : `${green(`ALL GRADED PACKS AT ${gate} OR BETTER`)}${dim(`   (worst grade: ${worstShown}${inconclusiveNote ? `; ${inconclusiveNote}` : ""})`)}`,
  );
  if (failsGate && below.length) out.push(red(`GATE NOT MET: ${inconclusiveIds.join(", ")} inconclusive (output.exit_policy.treat_inconclusive_as is fail)`));
  if (coreGraded && cov) {
    out.push(...wrap(`core: ${cov}`, W).map((l) => yellow(l)));
    if (r.coverage?.level === "hygiene-only") out.push(...wrap("Core is hygiene only: no tool was called with valid arguments, so this grade says nothing about what the tools do.", W).map((l) => dim(l)));
  }
  if (anyProvisional) out.push(dim("* Provisional: a critical check was inconclusive, so this grade may drop once that check can be measured."));
  // The same decision the text format prints, so a CI log that shows only the summary still says whether a badge may be used.
  if (r.badge) {
    const notRecommended = r.badge.eligible && packsBelowGate(r, gate).length > 0;
    const text = notRecommended ? `badge: not recommended (${packsBelowGate(r, gate).join(", ")}): eligible, but a graded pack is below the gate` : r.badge.eligible ? "badge: eligible" : `not badge-eligible: ${r.badge.reason ?? "no reason recorded"}`;
    out.push(...wrap(text, W).map((l) => (r.badge!.eligible && !notRecommended ? green(l) : notRecommended ? yellow(l) : dim(l))));
  }
  out.push("");

  const BADGE: Record<string, string> = { pass: green("[ PASS ]"), fail: red("[ FAIL ]"), part: yellow("[ PART ]"), inconclusive: yellow("[ ???? ]"), na: dim("[ n/a  ]") };
  const checks = [...r.checks].sort((a, b) => RANK[a.verdict] - RANK[b.verdict] || Number(!!a.advisory) - Number(!!b.advisory) || a.pack.localeCompare(b.pack) || a.id.localeCompare(b.id));
  out.push(bold("CHECKS"), dim("─".repeat(W)));
  for (const k of checks) {
    const flag = k.critical ? red("critical") : k.advisory ? dim("advisory") : "";
    out.push(`${BADGE[k.verdict]} ${pad(clip(`${k.pack}/${k.id}`, 26), 26)} ${pad(clip(k.label, 38), 38)} ${flag}`.trimEnd());
  }
  out.push(dim("─".repeat(W)));

  const fixes = checks.filter((k: CheckResult) => k.verdict === "fail" || ((k.verdict === "part" || k.verdict === "inconclusive") && !k.advisory));
  if (fixes.length) {
    out.push("", bold("WHAT TO FIX"));
    for (const k of fixes) {
      const caps = r.packs[k.pack]?.grade?.criticalFails.includes(k.id);
      const tag =
        (k.verdict === "fail" ? red("FAIL") : yellow(k.verdict.toUpperCase())) +
        (caps ? red(`  ← caps the ${k.pack} grade at D`) : "") +
        (k.critical && k.verdict === "part" ? yellow("  critical part") : "") +
        (k.advisory ? dim("  (advisory, not scored)") : "");
      out.push("", ` ${cyan("▸")} ${bold(clip(`${k.pack}/${k.id}`, 40))}  ${tag}`, ...wrap(k.summary, W - 6).map((l) => `     ${l}`));
      const ev = decidingEvidence(k);
      if (ev) out.push(dim(`     evidence: ${clip(ev.probe, W - 17)}`));
    }
  }

  // What the run could not cover, first lines only: the JSON report has the whole list.
  if (r.notCovered.length) {
    out.push("", bold(`NOT COVERED (${r.notCovered.length})`));
    for (const n of r.notCovered.slice(0, MAX_NOT_COVERED)) out.push(...wrap(n, W - 4).map((l, i) => dim(i === 0 ? `  - ${l}` : `    ${l}`)));
    if (r.notCovered.length > MAX_NOT_COVERED) out.push(dim(`  ... and ${r.notCovered.length - MAX_NOT_COVERED} more (the full list is in the JSON report)`));
  }

  // A pack that was asked for and could not be judged is not the same as one that does not apply here.
  const inconclusive = ungraded.filter(([, p]) => p.status === "inconclusive");
  const requested = r.options?.packsRequested;
  const notApplicable = ungraded.filter(([id, p]) => p.status !== "inconclusive" && (!requested || requested.includes(id)));
  if (inconclusive.length) out.push("", ...wrap(`inconclusive: ${inconclusive.map(([id, p]) => (p.reason ? `${id} (${p.reason})` : id)).join("; ")}`, W).map((l) => yellow(l)));
  if (notApplicable.length) out.push("", ...wrap(`not applicable: ${notApplicable.map(([id]) => id).join(", ")}  (the reasons are in the JSON report)`, W).map((l) => dim(l)));
  for (const w of r.warnings ?? []) out.push(...wrap(w, W - 9).map((l, i) => yellow(i === 0 ? `warning: ${l}` : `         ${l}`)));
  out.push("", ...wrap(CLOSING_LINE, W).map((l) => dim(l)), "");
  return out;
}
