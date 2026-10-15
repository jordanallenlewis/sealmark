import { classificationBlock } from "./classify.js";
import { applyTemplate, templateContext } from "./report/template.js";
import { renderJunit } from "./report/junit.js";
import { renderMarkdown } from "./report/markdown.js";
import { renderSummary } from "./report/summary.js";
import { listenerLabel, redactFailed, redactResult, type RedactOptions } from "./report/redact.js";
import { renderSarif } from "./report/sarif.js";
import { renderBadge, renderShields } from "./report/badge.js";
import { MAX_REPORT_FIELD, inert, inertDeep } from "./report/sanitize.js";
import {
  CANDIDATE_LABEL,
  CLOSING_LINE,
  TAG,
  badgeLine,
  capLoweredLetter,
  coverageTag,
  headerBlock,
  identitiesLine,
  inheritedText,
  isCandidatePack,
  isFailed,
  orderedPackIds,
  packageLabel,
  packsApplied,
  pctText,
  scoreText,
  secondaryText,
  sortChecks,
  suggestionLines,
  summaryLine,
  upstreamLine,
  withSuggestionLines,
  type AnyRun,
  type FailedRun,
} from "./report/common.js";
import type { CheckResult, PackId, RunResult, ToolClassification } from "./types.js";

export { CLOSING_LINE, summaryLine, type AnyRun, type FailedRun } from "./report/common.js";
export { isFailed } from "./report/common.js";

export type ReportFormat = "text" | "json" | "markdown" | "junit" | "sarif" | "summary" | "badge" | "shields";
export const FORMATS: readonly ReportFormat[] = ["text", "json", "markdown", "junit", "sarif", "summary", "badge", "shields"];
export const FORMAT_EXT: Record<ReportFormat, string> = { text: "txt", json: "json", markdown: "md", junit: "junit.xml", sarif: "sarif", summary: "summary.txt", badge: "badge.svg", shields: "shields.json" };

/** Longest error or hint a failed run may print: it can carry the server's own last output. */
const MAX_ERROR = 2000;

export interface RenderOptions extends RedactOptions {
  verbosity?: "quiet" | "normal" | "verbose";
  /** Text of a report template (Handlebars-style). Applies to the text and markdown formats; the integrity header is always added around it. */
  template?: string;
  /** summary format: ANSI colors, and the gate letter the verdict line compares against. */
  color?: boolean;
  gate?: string;
  /** `output.exit_policy.treat_inconclusive_as`: with `fail`, the summary says an inconclusive pack fails the gate. Absent: the summary says only that the packs were not graded. */
  treatInconclusiveAs?: "pass" | "fail";
}

// ---------------------------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------------------------

export function renderJson(r: RunResult, o: RenderOptions = {}): string {
  return JSON.stringify(redactResult(r, o), null, 2);
}

// ---------------------------------------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------------------------------------

function checkLines(c: CheckResult, verbose: boolean): string[] {
  const tail = c.advisory ? " (advisory, not scored)" : "";
  const out = [`  [${TAG[c.verdict]}] ${c.label} — ${c.summary}${tail}`, `        scope: ${c.scope}`];
  if (c.enforcedBy && c.enforcedBy !== "unknown") out.push(`        enforced by: ${c.enforcedBy}`);
  if (verbose) {
    for (const e of c.evidence) {
      const who = [e.role, e.tool].filter(Boolean).join("/");
      out.push(`        · [${e.verifiedBy}${who ? ` ${who}` : ""}] ${e.probe} → ${e.outcome}`);
      if (e.args !== undefined) out.push(`            args: ${JSON.stringify(e.args)}`);
    }
    for (const n of c.coverage?.notCovered ?? []) out.push(`        not covered: ${n.tool}: ${n.reason}`);
  }
  return out;
}

function sandboxLine(r: RunResult, o: RenderOptions): string | undefined {
  const s = r.sandbox;
  if (!s) return undefined;
  if (!s.enabled && r.server.launched) return "sandbox: not used: Sealmark started the server itself with your environment; the fs, git, exec, effects and sqlite packs did not run";
  if (!s.enabled && r.server.transport === "http") return "sandbox: not used: the server was already running over HTTP, so the harness did not start it; the fs, git, exec, effects and sqlite packs did not run";
  if (!s.enabled) return "sandbox: off (--no-sandbox): the server inherited your environment; the fs, git, exec, effects and sqlite packs did not run";
  // `dir` is already `{sandbox_dir}` unless redaction is off or the sandbox was kept, in which case the real path is what the reader needs.
  const parts = [s.dir ?? "(not created)", `env ${s.envMode}`];
  // A server Sealmark started itself runs inside the sandbox too (round 6): say so, so the reader does not assume it inherited their environment.
  if (r.server.launched) parts.push("the launched HTTP server was started inside the sandbox");
  // Which variables the server inherited from the caller (recorded by the harness; absent in older reports).
  const inherited = inheritedText(r);
  if (inherited) parts.push(inherited);
  // The port changes every run: it prints as {listener_port} unless redaction is off or the sandbox was kept (the markdown format does the same).
  if (s.listenerPort) parts.push(`listener ${listenerLabel(r, o)}`);
  if (s.active) parts.push("--active");
  parts.push(s.kept ? "kept (--keep-sandbox)" : s.cleanedUp ? "cleaned up" : `NOT cleaned up${s.leftoverProcesses.length ? ` (still running: ${s.leftoverProcesses.join(", ")})` : ""}`);
  return `sandbox: ${parts.join(" · ")}`;
}

/**
 * The classification block with a `secondary: <class>` line under each tool that matched another class, so a mis-chosen
 * primary class on a medium-confidence row is visible. The block itself is one header line, then one line per tool.
 */
function classificationLines(rows: ToolClassification[], applied: PackId[]): string[] {
  const block = classificationBlock(rows, applied);
  const out = [block[0]!];
  for (const [i, c] of rows.entries()) {
    out.push(block[i + 1]!);
    const sec = secondaryText(c);
    if (sec) out.push(`    ${sec}`);
  }
  return [...out, ...block.slice(rows.length + 1)];
}

function failedText(f: FailedRun): string {
  // Everything in a failed run came from the harness or the server, so all of it is made inert (the summary format does the same).
  const out = [`sealmark ${inert(f.sealmark.version, 80)} · server ${inert(f.server, 200)}: FAILED`, `  ${inert(f.error, MAX_ERROR)}`];
  if (f.hint) out.push(`  hint: ${inert(f.hint, MAX_ERROR)}`);
  if (f.stderrFile) out.push(`  server stderr saved to ${inert(f.stderrFile, 1000)}`);
  return out.join("\n") + "\n";
}

export function renderText(input: RunResult, o: RenderOptions = {}): string {
  // Every string in the result is server-controlled or derived from it: made inert once, here, after redaction.
  const redacted = redactResult(input, o);
  const r = withSuggestionLines(inertDeep(redacted, MAX_REPORT_FIELD), redacted);
  const verbosity = o.verbosity ?? "normal";
  const quiet = verbosity === "quiet";
  const out: string[] = [...headerBlock(r), ""];

  if (!quiet) {
    out.push(`server: ${r.server.command}`.replace(/ +$/, ""));
    const env = Object.entries(r.server.env);
    if (env.length) {
      out.push("env:");
      for (const [k, v] of env) out.push(`  ${k}=${v}`);
    } else out.push("env: (none)");
    const sql = r.server.sqlTools.map((t) => `${t.tool}(${t.arg})`).join(", ");
    out.push(`${r.server.transport} server, ${r.server.tools.length} tool(s): ${r.server.tools.join(", ") || "none"}${sql ? `; SQL tools: ${sql}` : ""}`);
    const pkg = packageLabel(r);
    if (pkg) out.push(`resolved package: ${pkg}`);
    out.push(r.db ? `db: ${r.db.mode} Postgres, seed ${r.db.seed}, roles ${r.db.roles.join(", ")}` : "db: not used");
    const sb = sandboxLine(r, o);
    if (sb) out.push(sb);
    const stub = upstreamLine(r);
    if (stub) out.push(stub);
    const ids = identitiesLine(r);
    if (ids) out.push(ids);
    out.push("");
    if (r.classification) out.push(...classificationLines(r.classification, packsApplied(r)), "");
  }

  let anyProvisional = false;
  let anyIncl = false;
  for (const id of orderedPackIds(r)) {
    const p = r.packs[id]!;
    const checks = r.checks.filter((c) => c.pack === id);
    if (p.status === "graded" && p.grade) {
      const g = p.grade;
      const total = checks.filter((c) => !c.advisory).length;
      anyProvisional ||= g.provisional;
      const tags: string[] = [];
      if (r.config && !r.config.standard) tags.push("custom grade");
      if (id === "core") {
        const cov = coverageTag(r);
        if (cov) tags.push(cov);
      }
      if (isCandidatePack(id)) tags.push(CANDIDATE_LABEL);
      out.push(`PACK ${id}  GRADE ${g.letter}${g.provisional ? "*" : ""}  (${scoreText(g, total)})${tags.length ? `  ${tags.join(" · ")}` : ""}`);
      if (id === "core" && r.coverage?.level === "hygiene-only" && !quiet) {
        out.push("  Core is hygiene only: no tool was called with valid arguments, so this grade says nothing about what the tools do.");
      }
    } else {
      out.push(`PACK ${id}  not graded${p.status === "inconclusive" ? " (inconclusive)" : ""}: ${p.reason ?? "no reason recorded"}`);
    }
    for (const c of sortChecks(checks)) {
      anyIncl ||= c.verdict === "inconclusive";
      if (quiet && (c.verdict === "pass" || c.verdict === "na")) continue;
      out.push(...checkLines(c, verbosity === "verbose"));
    }
    if (p.grade && capLoweredLetter(p.grade)) {
      const names = p.grade.criticalFails.map((f) => r.checks.find((c) => c.id === f)?.label ?? f);
      out.push(`  Capped at D: critical fail(s): ${names.join("; ")}. Without the cap this would be ${p.grade.raw} (${pctText(p.grade.pct)}).`);
    }
    out.push("");
  }

  if (anyProvisional) out.push("* Provisional: a critical check was inconclusive, so this grade may drop once that check can be measured.");
  if (anyIncl) out.push("INCL = inconclusive: the check could not run and is left out of the score.");
  if (anyProvisional || anyIncl) out.push("");

  const badge = badgeLine(r, o.gate);
  if (badge && !quiet) out.push(badge, "");

  if (r.notCovered.length && !quiet) {
    out.push("Not covered:");
    for (const n of r.notCovered) out.push(`  - ${n}`);
    out.push("");
  }
  if (r.warnings?.length) {
    out.push("Warnings:");
    for (const w of r.warnings) out.push(`  - ${w}`);
    out.push("");
  }
  const suggestions = suggestionLines(r);
  if (suggestions.length && !quiet) out.push(...suggestions, "");
  out.push(CLOSING_LINE);
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------------------------------------
// Several runs (a server matrix) and dispatch
// ---------------------------------------------------------------------------------------------------------

const RULE = "=".repeat(72);

function matrixSummary(runs: RunResult[]): string[] {
  const names = runs.map((r) => inert(r.server.name, 200));
  const w = Math.max(...names.map((n) => n.length));
  return ["Matrix:", ...runs.map((r, i) => `  ${names[i].padEnd(w)}  ${inert(summaryLine(r), MAX_REPORT_FIELD)}`)];
}

/** Renders one or several runs in `format`. JSON of several runs is `{ "runs": [...] }`; a single run is the RunResult itself. */
export function renderReport(format: ReportFormat, allRuns: AnyRun[], o: RenderOptions = {}): string {
  // A failed run's message can carry the server's own output (a launch that died printing its settings): scrub it once, here, for every format.
  const runs = allRuns.map((r) => (isFailed(r) ? redactFailed(r, o) : r));
  const ok = runs.filter((r): r is RunResult => !isFailed(r));
  const multi = runs.length > 1;
  switch (format) {
    case "json": {
      const redacted = runs.map((r) => (isFailed(r) ? r : redactResult(r, o)));
      return JSON.stringify(multi ? { runs: redacted } : redacted[0], null, 2);
    }
    case "text": {
      const blocks = runs.map((r) => {
        if (isFailed(r)) return failedText(r);
        return o.template ? applyTemplate(o.template, redactResult(r, o), "text") : renderText(r, o);
      });
      if (!multi) return blocks[0];
      return [...blocks.flatMap((b, i) => (i ? [RULE, b] : [b])), RULE, ...matrixSummary(ok), ""].join("\n").replace(/\n{3,}/g, "\n\n");
    }
    case "markdown":
      return renderMarkdown(runs, o);
    case "junit":
      return renderJunit(runs, o);
    case "sarif":
      return renderSarif(runs, o);
    case "summary":
      return renderSummary(runs, o);
    case "badge":
      return renderBadge(runs, o);
    case "shields":
      return renderShields(runs, o);
  }
}

export { templateContext };
