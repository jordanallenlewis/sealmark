// The action's comment step: posts the comment run.mjs wrote, or updates the one this action posted before. It runs after
// Sealmark and the server under test have exited, and it is the only step that gets the token (SEALMARK_INPUT_GITHUB_TOKEN).
// A server that left a process behind (new session, working directory outside the sandbox) could still read it: for a server
// you do not trust, run this step in a separate job. It never fails the job: every problem is a warning.
// Plain Node, no dependencies, Node >= 22. It never prints the token or any other value from process.env.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { findOwnComment, prNumber } from "./comment.mjs";

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
  // pull_request only: pull_request_target runs with the base repository's rights, and grading a fork's code there is
  // the classic way to hand a write token to untrusted code. Its comment would also show the base branch's grades.
  const event = process.env.GITHUB_EVENT_NAME ?? "";
  if (event !== "pull_request") {
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
  const token = (process.env.SEALMARK_INPUT_GITHUB_TOKEN ?? "").trim();
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

async function main() {
  const file = (process.env.SEALMARK_COMMENT_FILE ?? "").trim();
  let url = "";
  if (!file || !existsSync(file)) console.log("sealmark action: comment: no comment was written, nothing to post");
  else {
    try {
      url = await postComment(readFileSync(file, "utf8"), file);
    } catch (e) {
      warn(`comment: ${e?.message ?? e}`);
    }
  }
  // One `url=value` line: the URL comes from the API, so anything that could start another output line is dropped.
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `url=${url.replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, "")}\n`);
}

main().finally(() => process.exit(0));
