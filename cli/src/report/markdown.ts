import type { RunResult, ToolClassification } from "../types.js";
import { coreOnlyReason } from "../classify.js";
import { applyTemplate } from "./template.js";
import { CANDIDATE_LABEL, CLOSING_LINE, badgeLine, capLoweredLetter, coverageTag, diffLines, headerLine, identitiesLine, inheritedText, isCandidatePack, isFailed, orderedPackIds, packageLabel, packsApplied, round6Fields, scoreText, secondaryText, sortChecks, summaryLine, upstreamLine, withSuggestionLines, type AnyRun } from "./common.js";
import { listenerLabel, redactResult, type RedactOptions } from "./redact.js";
import { MAX_REPORT_FIELD, inert, inertDeep } from "./sanitize.js";

/** Longest error or hint a failed run may print: it can carry the server's own last output. */
const MAX_ERROR = 2000;

const VERDICT: Record<string, string> = { pass: "PASS", part: "PART", fail: "FAIL", inconclusive: "INCONCLUSIVE", na: "N/A" };

/** Escapes what would break a Markdown table cell or start unintended formatting. */
const cell = (s: string) => s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").replace(/</g, "&lt;");
const code = (s: string) => `\`${s.replace(/`/g, "'")}\``;

function classRow(c: ToolClassification): string {
  const why = coreOnlyReason(c);
  const sec = secondaryText(c);
  return `| ${cell(c.tool)} | ${c.class} | ${c.confidence} | ${cell(why ? `core only: ${why}` : [c.reasons.join(", "), sec].filter(Boolean).join("; "))} |`;
}

function one(r: RunResult, level: "#" | "##", verbose = false, ropts: RedactOptions = {}, gate?: string): string[] {
  const h = level;
  const sub = level === "#" ? "##" : "###";
  const out: string[] = [];
  out.push(`${h} Sealmark report: ${cell(r.server.name)}${r.server.version ? ` ${cell(r.server.version)}` : ""}`, "");
  out.push(`> ${headerLine(r).replace(/</g, "&lt;")}`);
  out.push("");
  const diff = diffLines(r);
  if (diff.length) {
    out.push("| Setting | Standard | Effective | Origin |", "|---|---|---|---|");
    for (const d of r.config!.standardDiff) out.push(`| ${code(d.path)} | ${cell(JSON.stringify(d.standard) ?? "")} | ${cell(JSON.stringify(d.effective) ?? "")} | ${cell(d.origin)} |`);
    out.push("", "Grades below are custom grades: they are not comparable to a STANDARD grade, and a custom run gets no badge.", "");
  }

  out.push(`${sub} Server`, "", `- Command: ${code(r.server.command)}`, `- Transport: ${r.server.transport}; ${r.server.tools.length} tool(s)`);
  const env = Object.entries(r.server.env);
  if (env.length) out.push(`- Environment: ${env.map(([k, v]) => code(`${k}=${v}`)).join(", ")}`);
  const pkg = packageLabel(r);
  if (pkg) out.push(`- Resolved package: ${code(pkg)}`);
  if (r.sandbox) {
    out.push(
      r.sandbox.enabled
        ? `- Sandbox: ${code(r.sandbox.dir ?? "")}, env ${r.sandbox.envMode}${inheritedText(r) ? `, ${inheritedText(r)}` : ""}${r.sandbox.listenerPort ? `, listener ${listenerLabel(r, ropts)}` : ""}, ${r.sandbox.kept ? "kept" : r.sandbox.cleanedUp ? "cleaned up" : "NOT cleaned up"}${r.server.launched ? "; the launched HTTP server was started inside the sandbox" : ""}`
        : r.server.launched
          ? "- Sandbox: not used; Sealmark started the server itself with your environment, and the fs, git, exec, effects and sqlite packs did not run"
          : r.server.transport === "http"
          ? "- Sandbox: not used; the server was already running over HTTP, so the harness did not start it, and the fs, git, exec, effects and sqlite packs did not run"
          : "- Sandbox: off (`--no-sandbox`); the fs, git, exec, effects and sqlite packs did not run",
    );
  }
  const stub = upstreamLine(r);
  if (stub) out.push(`- ${code(stub)}`);
  const ids = identitiesLine(r);
  if (ids) out.push(`- ${code(ids)}`);
  out.push("");

  out.push(`${sub} Summary`, "", `**${summaryLine(r)}**`, "");

  if (r.classification?.length) {
    out.push(`${sub} Classification`, "", "| Tool | Class | Confidence | Why |", "|---|---|---|---|", ...r.classification.map(classRow));
    const applied = packsApplied(r);
    out.push("", `Packs applied: ${applied.length ? applied.join(", ") : "none"}`, "");
  }

  for (const id of orderedPackIds(r)) {
    const p = r.packs[id]!;
    out.push(`${sub} Pack ${code(id)}`, "");
    if (p.status === "graded" && p.grade) {
      const g = p.grade;
      const total = r.checks.filter((c) => c.pack === id && !c.advisory).length;
      out.push(`**Grade ${g.letter}${g.provisional ? "*" : ""}**${r.config && !r.config.standard ? " (custom grade)" : ""} (${scoreText(g, total)})`);
      if (id === "core") {
        const cov = coverageTag(r);
        if (cov) out.push("", `_${cov}_`);
      }
      if (isCandidatePack(id)) out.push("", `_${CANDIDATE_LABEL}_`);
      if (capLoweredLetter(g)) out.push("", `Capped at D by critical fail(s): ${g.criticalFails.map(code).join(", ")}. Without the cap this would be ${g.raw}.`);
    } else out.push(`Not graded${p.status === "inconclusive" ? " (inconclusive)" : ""}: ${cell(p.reason ?? "no reason recorded")}`);
    const checks = sortChecks(r.checks.filter((c) => c.pack === id));
    if (checks.length) {
      out.push("", "| Result | Check | Summary | Scope |", "|---|---|---|---|");
      for (const c of checks) out.push(`| ${VERDICT[c.verdict]}${c.advisory ? " (advisory)" : ""}${c.critical ? " (critical)" : ""} | ${code(c.id)} ${cell(c.label)} | ${cell(c.summary)} | ${cell(c.scope)} |`);
    }
    // --verbosity verbose: every evidence line and probe argument, as the text format prints them.
    if (verbose) {
      for (const c of checks) {
        if (!c.evidence.length) continue;
        out.push("", `**Evidence for ${code(c.id)}**`, "");
        for (const e of c.evidence) {
          const who = [e.role, e.tool].filter(Boolean).join("/");
          out.push(`- [${e.verifiedBy}${who ? ` ${who}` : ""}] ${cell(e.probe)} → ${cell(e.outcome)}${e.args !== undefined ? ` (args: ${code(JSON.stringify(e.args))})` : ""}`);
        }
      }
    }
    out.push("");
  }

  if (r.badge) {
    const line = badgeLine(r, gate) ?? "";
    out.push(r.badge.eligible && !line.startsWith("Badge: not recommended") ? "Badge: eligible." : line, "");
  }
  if (r.notCovered.length) out.push(`${sub} Not covered`, "", ...r.notCovered.map((n) => `- ${cell(n)}`), "");
  if (r.warnings?.length) out.push(`${sub} Warnings`, "", ...r.warnings.map((n) => `- ${cell(n)}`), "");
  const suggestions = round6Fields(r).suggestions;
  if (suggestions.length) {
    out.push(`${sub} Suggestions`, "");
    for (const s of suggestions) {
      out.push(`- **${cell(s.kind)}**: ${cell(s.why)}${s.flags?.length ? ` Flags: ${code(s.flags.join(" "))}` : ""}`);
      if (s.config) out.push("", "  ```yaml", ...s.config.replace(/\s+$/, "").split("\n").map((l) => `  ${l.replace(/```/g, "'''")}`), "  ```");
    }
    out.push("");
  }
  out.push(`_${CLOSING_LINE}_`, "");
  return out;
}

export function renderMarkdown(runs: AnyRun[], o: RedactOptions & { template?: string; verbosity?: "quiet" | "normal" | "verbose"; gate?: string } = {}): string {
  const lines: string[] = [];
  const multi = runs.length > 1;
  if (multi) lines.push("# Sealmark matrix report", "");
  for (const run of runs) {
    if (isFailed(run)) {
      lines.push(`${multi ? "##" : "#"} Sealmark report: ${cell(inert(run.server, 200))}`, "", `**FAILED:** ${cell(inert(run.error, MAX_ERROR))}`, ...(run.hint ? ["", `Hint: ${cell(inert(run.hint, MAX_ERROR))}`] : []), "");
      continue;
    }
    // Every string in the result is server-controlled or derived from it: made inert once, here, after redaction.
    const redacted = redactResult(run, o);
    const r = withSuggestionLines(inertDeep(redacted, MAX_REPORT_FIELD), redacted);
    if (o.template) lines.push(applyTemplate(o.template, r, "markdown"));
    else lines.push(...one(r, multi ? "##" : "#", o.verbosity === "verbose", o, o.gate));
  }
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s*$/, "\n");
}
