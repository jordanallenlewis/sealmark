// The pull request comment of the Sealmark action: the body built from the JSON report (and, with a baseline, from what
// `sealmark diff --json` says), and how the action finds its own earlier comment. Plain Node, no dependencies, no network here.
// Server names, tool names and check text are server-controlled: they only ever appear inside a code span or a text block,
// where GitHub renders no mention, link, image or HTML, and they are cut to one line of bounded length first.

/** First line of every comment the action writes; it finds its own comment again by this. */
export const MARKER = "<!-- sealmark-action:comment -->";
/** GitHub refuses a comment over 65536 characters; the body stays well under. */
export const MAX_BODY = 60000;
const MAX_NAME = 200;
const MAX_LINE = 500;
const MAX_LINES = 30;
const MAX_ROWS = 50;

const EXIT = {
  0: "passed",
  1: "the gate failed: a grade below fail-under, an inconclusive pack counted as failing, or a regression or drift against the baseline that the gate counts",
  2: "usage or config error",
  3: "nothing was graded",
  4: "server or harness failure",
};

/** One line, no control characters, at most `max` characters. */
const oneLine = (value, max) => {
  // Format characters (bidi overrides, zero-width) go too: they could make a name read as another.
  const s = String(value ?? "").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").trim();
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
};
/** A code span inside a table cell: no backtick can end it and no pipe can end the cell. */
const span = (value, max = MAX_NAME) => `\`${oneLine(value, max).replace(/`/g, "'").replace(/\\/g, "\\\\").replace(/\|/g, "\\|")}\``;
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

function grades(run) {
  if (run?.status === "failed" && !run.packs) return undefined;
  return Object.entries(run?.packs ?? {})
    .filter(([, p]) => p?.status === "graded" && p.grade?.letter)
    .map(([id, p]) => `${id} ${p.grade.letter}`)
    .join(" · ");
}

function runsOf(report) {
  if (!report || typeof report !== "object") return [];
  return Array.isArray(report.runs) ? report.runs : [report];
}

function gradeTable(runs) {
  const rows = runs.slice(0, MAX_ROWS).map((run) => {
    const name = typeof run?.server === "string" ? run.server : (run?.server?.name ?? "");
    const g = grades(run);
    return `| ${span(name || "(unnamed)")} | ${g === undefined ? "did not start" : g ? span(g) : "nothing graded"} |`;
  });
  const out = ["| Server | Grades |", "|---|---|", ...rows];
  if (runs.length > MAX_ROWS) out.push("", `And ${runs.length - MAX_ROWS} more servers in the job log.`);
  return out;
}

const texts = (list) => (Array.isArray(list) ? list : []).map((e) => (typeof e === "string" ? e : e?.text)).filter((t) => typeof t === "string");

function baselineSection(diff) {
  if (diff === null) return ["**Against the baseline**: the comparison could not be made; the job log says why."];
  const regressions = texts(diff.regressions);
  const improvements = texts(diff.improvements);
  const notes = texts(diff.notes);
  const drift = (Array.isArray(diff.drift) ? diff.drift : []).filter((d) => typeof d?.text === "string");
  const sev = (s) => drift.filter((d) => d.severity === s).length;
  if (!regressions.length && !improvements.length && !notes.length && !drift.length) return ["**Against the baseline**: no regression and no tool-surface change."];
  const counts = `${plural(regressions.length, "regression")}, ${plural(improvements.length, "improvement")}, ${plural(drift.length, "tool-surface change")} (${sev("breaking")} breaking, ${sev("notable")} notable, ${sev("info")} info)`;
  const lines = [
    ...regressions.map((t) => `regression: ${t}`),
    ...drift.map((d) => `drift (${oneLine(d.severity, 20) || "info"}): ${d.text}`),
    ...improvements.map((t) => `improved: ${t}`),
    ...notes.map((t) => `note: ${t}`),
  ].map((l) => oneLine(l, MAX_LINE).replace(/`/g, "'"));
  const shown = lines.slice(0, MAX_LINES);
  if (lines.length > MAX_LINES) shown.push(`... and ${lines.length - MAX_LINES} more lines in the job log`);
  return [`**Against the baseline**: ${counts}.`, "", "```text", ...shown, "```"];
}

/**
 * The comment body. `report` is the parsed JSON report (undefined when none was written), `diff` the parsed output of
 * `sealmark diff --json <baseline> <report>` (undefined without a baseline, null when a baseline was set and the
 * comparison failed), `runUrl` the job's run page, `softFail` whether a failed gate was turned into exit 0.
 */
export function commentBody({ report, exitCode, diff, runUrl, version, softFail = false }) {
  const out = [MARKER, "### Sealmark", ""];
  const runs = runsOf(report);
  if (runs.length) out.push(...gradeTable(runs), "");
  else out.push("Sealmark wrote no report; the job log says why.", "");
  const meaning = exitCode === 0 && softFail ? "the job did not fail, but soft-fail is set, so a failed gate also exits 0 (the job log says whether it did)" : (EXIT[exitCode] ?? "an exit code Sealmark does not document");
  out.push(`**Exit ${exitCode}**: ${meaning}.`, "");
  if (diff === null || (diff && typeof diff === "object")) out.push(...baselineSection(diff), "");
  const where = [runUrl ? `[Job log and reports](${runUrl})` : "", version ? `sealmark ${oneLine(version, 40)}` : "the local Sealmark build"].filter(Boolean).join(" · ");
  out.push(`${where}. Grades from this job's own run, self-reported: not the sealmark.dev fleet grade.`);
  let body = `${out.join("\n")}\n`;
  if (body.length > MAX_BODY) body = `${body.slice(0, MAX_BODY - 80)}\n\nThe rest is in the job log.\n`;
  return body;
}

/**
 * The action's own earlier comment: the marker at the very start, written by the token's own login when it is known
 * (a personal token), else by a bot (the default GITHUB_TOKEN writes as github-actions[bot]). A person's comment that
 * quotes the marker is never edited.
 */
export function findOwnComment(comments, login) {
  return comments.find(
    (c) => c && typeof c === "object" && typeof c.id === "number" && typeof c.body === "string" && c.body.startsWith(MARKER) && (login ? c.user?.login === login : c.user?.type === "Bot"),
  );
}

/** The pull request number in a pull_request or pull_request_target event payload. */
export function prNumber(event) {
  const n = event?.pull_request?.number;
  return Number.isInteger(n) && n > 0 ? n : undefined;
}
