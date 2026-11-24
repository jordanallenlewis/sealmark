// Runs Sealmark for action.yml and turns the result into step outputs. Plain Node, no dependencies, Node >= 22.
// The inputs arrive as SEALMARK_INPUT_<UPPER_SNAKE> (composite actions do not populate INPUT_*); an empty string means unset.
// Secrets: bearer-env is the NAME of a variable. Only the literal "${NAME}" goes into argv (Sealmark expands it from
// its own environment), so the token never appears in a command line or a log. This file never prints a value from process.env.
import { randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { commentBody, findOwnComment, prNumber } from "./comment.mjs";

const input = (name) => (process.env[`SEALMARK_INPUT_${name}`] ?? "").trim();

/** Splits on whitespace; "double" and 'single' quotes group words (and may be empty). No escapes, no expansion, no shell. */
function splitArgs(text) {
  const out = [];
  let cur = "";
  let started = false;
  let quote = null;
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started) out.push(cur);
      cur = "";
      started = false;
    } else {
      cur += ch;
      started = true;
    }
  }
  if (quote) throw new Error(`args: a ${quote} quote is not closed`);
  if (started) out.push(cur);
  return out;
}

const list = (text) => text.split(",").map((s) => s.trim()).filter(Boolean);

/** The flags Sealmark gets, in order, from the inputs. */
function buildArgv(get = input) {
  const argv = ["run"];
  const one = (flag, name) => {
    const v = get(name);
    if (v) argv.push(flag, v);
  };
  one("--start", "START");
  one("--url", "URL");
  one("--config", "CONFIG");
  for (const p of list(get("PACK"))) argv.push("--pack", p);
  one("--fail-under", "FAIL_UNDER");
  if (get("SOFT_FAIL").toLowerCase() === "true") argv.push("--soft-fail");
  one("--baseline", "BASELINE");
  one("--write-baseline", "WRITE_BASELINE");
  one("--fail-on", "FAIL_ON");
  const bearerEnv = get("BEARER_ENV");
  if (bearerEnv) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(bearerEnv)) throw new Error("bearer-env takes the NAME of an environment variable (for example MCP_TOKEN), not the token");
    argv.push("--bearer", "${" + bearerEnv + "}");
  }
  argv.push(...splitArgs(get("ARGS")));
  return argv;
}

/**
 * badge input: "auto" (default) adds the self-reported badge formats only when the run is sure to grade one server: start or
 * url without a config, or a --server <name> other than "all" in args. The CLI refuses badge and shields for several servers
 * (exit 2 before any run), so a config that may hold several servers is left alone unless badge is "true".
 */
function badgeOn(get = input, extra = splitArgs(get("ARGS"))) {
  const mode = (get("BADGE") || "auto").toLowerCase();
  if (!["auto", "true", "false"].includes(mode)) throw new Error('badge: expected auto, true or false');
  if (mode !== "auto") return mode === "true";
  // The CLI keeps the last --server it is given, so the last one decides here too.
  let named;
  for (let i = 0; i < extra.length; i++) {
    if (extra[i] === "--server") named = extra[i + 1] ?? "";
    else if (extra[i].startsWith("--server=")) named = extra[i].slice("--server=".length);
  }
  if (named !== undefined) return named !== "" && named !== "all" && !named.includes(",");
  return !get("CONFIG");
}

/** comment input: "true" builds the PR comment (and posts it on a pull request event); empty or "false" does nothing. */
function commentOn(get = input) {
  const v = get("COMMENT").toLowerCase();
  if (v !== "" && v !== "true" && v !== "false") throw new Error("comment: expected true or false");
  return v === "true";
}

const SITE = "https://sealmark.dev";
/** sealmark.dev server ids: lower-case letters, digits and inner hyphens (the same rule as `sealmark badge --id`). */
const SITE_ID = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/;

/** README snippets for the sealmark.dev flat badge of one server: the same strings as `sealmark badge --id` and the site's copy buttons. */
function siteSnippets(id) {
  const page = `${SITE}/results/${id}/`;
  const image = `${SITE}/badge/${id}.svg`;
  return {
    markdown: `[![Sealmark](${image})](${page})`,
    html: `<a href="${page}"><img src="${image}" alt="Sealmark"></a>`,
    rst: `.. image:: ${image}\n   :target: ${page}\n   :alt: Sealmark`,
  };
}

function badgeId(get = input) {
  const id = get("BADGE_ID");
  if (id && !SITE_ID.test(id)) throw new Error("badge-id takes a sealmark.dev server id: lower-case letters, digits and hyphens, the last part of https://sealmark.dev/results/<id>/");
  return id;
}

/** `core A · db B` for one run, `failed` for a run that did not start. */
function runSummary(run) {
  if (run.status === "failed" && !run.packs) return "failed";
  const graded = Object.entries(run.packs ?? {}).filter(([, p]) => p?.status === "graded" && p.grade?.letter);
  return graded.map(([id, p]) => `${id} ${p.grade.letter}`).join(" · ");
}

function summaryOf(report) {
  const runs = Array.isArray(report?.runs) ? report.runs : report ? [report] : [];
  const parts = [];
  for (const run of runs) {
    const body = runSummary(run);
    if (!body && run.status !== "failed") continue;
    const name = typeof run.server === "string" ? run.server : (run.server?.name ?? "");
    parts.push(runs.length > 1 && name ? `${name}: ${body}` : body);
  }
  return parts.join(" | ");
}

/** Where to run Sealmark: the file in SEALMARK_ACTION_BIN under this Node (tests), else npx. Never a shell. */
function command(argv) {
  const bin = process.env.SEALMARK_ACTION_BIN;
  if (bin) return { cmd: process.execPath, args: [bin, ...argv] };
  const version = input("VERSION");
  if (!/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(version)) throw new Error('version: expected a version such as 0.2.1 (or a tag such as latest)');
  const args = ["-y", `sealmark@${version}`, ...argv];
  if (process.platform !== "win32") return { cmd: "npx", args };
  // Node refuses to spawn a .cmd file without a shell; setup-node puts npm's own script next to node.exe.
  const npxCli = join(dirname(process.execPath), "node_modules", "npm", "bin", "npx-cli.js");
  return existsSync(npxCli) ? { cmd: process.execPath, args: [npxCli, ...args] } : { cmd: "npx.cmd", args };
}

/** One GITHUB_OUTPUT entry: name=value, or the name<<DELIMITER form for a value with line breaks (the rst snippet). */
function outputLine(name, value) {
  if (!/[\r\n]/.test(value)) return `${name}=${value}\n`;
  let delimiter;
  do delimiter = `sealmark_${randomBytes(12).toString("hex")}`;
  while (value.includes(delimiter));
  return `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
}

/** The step summary's badge section: what this run's self-reported badge says, and the sealmark.dev snippets when badge-id is set. */
function badgeSummary(text, svg, id, snippets) {
  if (!text && !id) return "";
  const out = ["", "### Badge", ""];
  if (text) {
    out.push(`Self-reported badge of this run: \`${text.replace(/`/g, "'")}\``, "");
    if (svg) out.push("The SVG and the shields.io document are in the report directory. To show it in a README, commit one from a run on your main branch and reference it (the CLI README, section Badge, has the snippet).", "");
  }
  if (id) {
    out.push(`Badge from sealmark.dev for \`${id}\` (the public fleet's grade). The image exists only while that server's latest fleet run earns a badge, which ${SITE}/results/${id}/ then shows; otherwise it is a 404, so check the page before you paste:`, "");
    out.push("```markdown", snippets.markdown, "```", "", "```html", snippets.html, "```", "", "```rst", snippets.rst, "```", "");
  }
  return `${out.join("\n")}`;
}

function exitWith(code, message) {
  if (message) console.error(message);
  process.exit(code);
}

function main() {
  if (!input("START") && !input("URL") && !input("CONFIG")) exitWith(2, "sealmark action: set start and url (or config)");

  const reportDir = resolve(input("REPORT_DIR") || "sealmark-report");
  let argv;
  let cmd;
  let badge;
  let comment;
  try {
    argv = buildArgv();
    badgeId();
    badge = badgeOn();
    comment = commentOn();
    argv.push("--format", badge ? "summary,json,junit,sarif,badge,shields" : "summary,json,junit,sarif", "--out-dir", reportDir);
    cmd = command(argv);
  } catch (e) {
    exitWith(2, `sealmark action: ${e.message}`);
  }
  const bearerEnv = input("BEARER_ENV");
  console.log(`sealmark action: running ${process.env.SEALMARK_ACTION_BIN ? "the local build" : `sealmark@${input("VERSION")}`}${bearerEnv ? ` (bearer token from ${bearerEnv})` : ""}; reports go to ${reportDir}`);

  // Sealmark reads every SEALMARK_* variable as a setting and refuses one it does not know, so the action's own
  // variables stay out of its environment. Any other SEALMARK_* setting the workflow sets still reaches it.
  // That includes SEALMARK_INPUT_GITHUB_TOKEN: the token never reaches Sealmark or the server it starts.
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("SEALMARK_INPUT_") && k !== "SEALMARK_ACTION_BIN"));
  // Badge files left by an earlier run (a committed report directory, a reused self-hosted workspace) must never pass for this
  // run's badge: they are removed first, and only read back when this run asked for them.
  if (badge) for (const ext of ["badge.svg", "shields.json"]) rmSync(join(reportDir, `sealmark-report.${ext}`), { force: true });
  // The same for the comment: an old JSON report must never be posted as this run's grades.
  // A baseline that is the previous run's report in the same directory is kept: it is what this run is compared with.
  if (comment) for (const ext of ["json", "comment.md"]) {
    const old = join(reportDir, `sealmark-report.${ext}`);
    try {
      if (!(input("BASELINE") && resolve(input("BASELINE")) === old)) rmSync(old, { force: true });
    } catch {
      // A report directory that is not a directory: the CLI says so; the comment step warns later.
    }
  }
  const child = spawn(cmd.cmd, cmd.args, { stdio: "inherit", cwd: process.cwd(), env });
  child.on("error", (e) => exitWith(4, `sealmark action: could not start ${cmd.cmd}: ${e.code ?? e.message}`));
  child.on("close", (status, signal) => {
    finish(signal ? 4 : (status ?? 4), reportDir, badge, comment, env).catch((e) => exitWith(signal ? 4 : (status ?? 4), `sealmark action: ${e.message}`));
  });
}

/**
 * `sealmark diff --json <baseline> <report>`, parsed. Undefined without a baseline; null (and a warning) when a baseline was
 * set and the comparison could not be made, so the comment says so instead of looking like a run without a baseline.
 */
function baselineDiff(jsonPath, env) {
  const baseline = input("BASELINE");
  if (!baseline) return undefined;
  if (!jsonPath) return null;
  const cmd = command(["diff", baseline, jsonPath, "--json"]);
  const r = spawnSync(cmd.cmd, cmd.args, { cwd: process.cwd(), env, encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024 });
  let d;
  try {
    d = JSON.parse(r.stdout);
  } catch {
    d = undefined;
  }
  if (d?.format === "sealmark.diff/1") return d;
  warn(`comment: sealmark diff could not compare the baseline with this run (exit ${r.status ?? "none"}${r.error ? `, ${r.error.code ?? r.error.message}` : ""})`);
  return null;
}

const warn = (message) => console.log(`::warning::sealmark action: ${message.replace(/[\r\n]+/g, " ")}`);

/** GitHub REST call with the token; returns { status, json } and throws only when the API cannot be reached. */
async function gh(method, path, token, body) {
  const base = (process.env.GITHUB_API_URL || "https://api.github.com").replace(/\/+$/, "");
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sealmark-action", ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(20_000),
  });
  let json;
  try {
    json = await res.json();
  } catch {
    json = undefined;
  }
  return { status: res.status, json };
}

/** Posts the body as the PR's Sealmark comment, or updates the action's earlier one. Returns its URL, or "" (with a log line why). */
async function postComment(body, file) {
  const event = process.env.GITHUB_EVENT_NAME ?? "";
  if (event !== "pull_request" && event !== "pull_request_target") {
    console.log(`sealmark action: comment: not a pull_request event (${event || "no event"}), nothing posted; the body is in ${file}`);
    return "";
  }
  let number;
  try {
    number = prNumber(JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH ?? "", "utf8")));
  } catch {
    number = undefined;
  }
  const repo = process.env.GITHUB_REPOSITORY ?? "";
  const token = input("GITHUB_TOKEN");
  if (!number || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    warn(`could not tell which pull request this is, so the comment was not posted; the body is in ${file}`);
    return "";
  }
  if (!token) {
    warn(`github-token is empty, so the comment was not posted; the body is in ${file}`);
    return "";
  }
  const why = (status) =>
    `could not post the PR comment (HTTP ${status}). The job needs permissions: pull-requests: write, and a pull request from a fork gets a read-only token. The body is in ${file}`;
  try {
    // A personal token knows its own login; the default GITHUB_TOKEN cannot read /user and writes as a bot.
    const me = await gh("GET", "/user", token);
    const login = me.status === 200 && typeof me.json?.login === "string" ? me.json.login : undefined;
    let own;
    for (let page = 1; page <= 10 && !own; page++) {
      const list = await gh("GET", `/repos/${repo}/issues/${number}/comments?per_page=100&page=${page}`, token);
      if (list.status !== 200 || !Array.isArray(list.json)) {
        warn(why(list.status));
        return "";
      }
      own = findOwnComment(list.json, login);
      if (list.json.length < 100) break;
    }
    const r = own ? await gh("PATCH", `/repos/${repo}/issues/comments/${own.id}`, token, { body }) : await gh("POST", `/repos/${repo}/issues/${number}/comments`, token, { body });
    if (r.status !== 200 && r.status !== 201) {
      warn(why(r.status));
      return "";
    }
    const url = typeof r.json?.html_url === "string" ? r.json.html_url.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, "") : "";
    console.log(`sealmark action: comment ${own ? "updated" : "posted"}${url ? `: ${url}` : ""}`);
    return url;
  } catch (e) {
    warn(`could not post the PR comment (could not reach the API: ${e?.cause?.code ?? e?.name ?? "error"}). The body is in ${file}`);
    return "";
  }
}

/** Builds the comment from this run's report, writes it next to the reports and posts it on a pull request event. */
async function writeAndPostComment(code, reportDir, file, path, env) {
  let report;
  try {
    report = path("json") ? JSON.parse(readFileSync(file("json"), "utf8")) : undefined;
  } catch {
    report = undefined;
  }
  const server = process.env.GITHUB_SERVER_URL ?? "";
  const runUrl = /^https?:\/\/[^\s()]+$/.test(server) && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(process.env.GITHUB_REPOSITORY ?? "") && /^\d+$/.test(process.env.GITHUB_RUN_ID ?? "")
    ? `${server.replace(/\/+$/, "")}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : "";
  const body = commentBody({ report, exitCode: code, diff: baselineDiff(path("json"), env), runUrl, version: process.env.SEALMARK_ACTION_BIN ? "" : input("VERSION"), softFail: input("SOFT_FAIL").toLowerCase() === "true" });
  const commentFile = file("comment.md");
  mkdirSync(reportDir, { recursive: true });
  writeFileSync(commentFile, body);
  return { commentFile, commentUrl: await postComment(body, commentFile) };
}

async function finish(code, reportDir, badge, comment, env) {
  const file = (ext) => join(reportDir, `sealmark-report.${ext}`);
  const path = (ext) => (existsSync(file(ext)) ? file(ext) : "");
  const badgePath = (ext) => (badge ? path(ext) : "");
  let summary = "";
  if (existsSync(file("json"))) {
    try {
      summary = summaryOf(JSON.parse(readFileSync(file("json"), "utf8")));
    } catch {
      // A report that does not parse is left out of the summary; the CLI's own exit code still decides the job.
    }
  }
  // Outputs are single `name=value` lines: the summary can carry a server name, so control characters are dropped.
  summary = summary.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ").trim();

  // The badge text comes from the CLI's shields document, which it builds from harness constants only (methodology, pack ids, letters).
  let badgeText = "";
  if (badgePath("shields.json")) {
    try {
      const doc = JSON.parse(readFileSync(file("shields.json"), "utf8"));
      if (typeof doc?.label === "string" && typeof doc?.message === "string") badgeText = `${doc.label}: ${doc.message}`.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, " ").trim();
    } catch {
      // An unreadable badge document leaves badge-text empty; it never changes the exit code.
    }
  }
  // The PR comment: built from the report (and the baseline diff), written next to the reports, posted on a pull request event.
  let commentFile = "";
  let commentUrl = "";
  // Nothing in it may cost the other outputs or the exit code: a failure is a warning.
  if (comment) {
    try {
      ({ commentFile, commentUrl } = await writeAndPostComment(code, reportDir, file, path, env));
    } catch (e) {
      warn(`comment: ${e?.message ?? e}`);
    }
  }

  const id = input("BADGE_ID");
  const snippets = id ? siteSnippets(id) : { markdown: "", html: "", rst: "" };

  const outputs = {
    "exit-code": String(code),
    "report-dir": reportDir,
    json: path("json"),
    sarif: path("sarif"),
    junit: path("junit.xml"),
    summary,
    "badge": badgePath("badge.svg"),
    "shields": badgePath("shields.json"),
    "badge-text": badgeText,
    "badge-markdown": snippets.markdown,
    "badge-html": snippets.html,
    "badge-rst": snippets.rst,
    "comment": commentFile,
    "comment-url": commentUrl,
  };
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(outputs).map(([k, v]) => outputLine(k, v)).join(""));

  if (process.env.GITHUB_STEP_SUMMARY) {
    // `--format summary` next to other formats goes to the console, so the file is usually absent; the one-line grade stands in.
    const text = existsSync(file("summary.txt")) ? readFileSync(file("summary.txt"), "utf8").trimEnd() : summary;
    if (text) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Sealmark\n\n\`\`\`text\n${text}\n\`\`\`\n`);
    const section = badgeSummary(badgeText, badgePath("badge.svg"), id, snippets);
    if (section) appendFileSync(process.env.GITHUB_STEP_SUMMARY, section);
  }
  process.exit(code);
}

main();
