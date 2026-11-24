import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { hermeticEnv } from "./helpers.js";

// Run from dist/test, so the repository root is three levels up.
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const ACTION_DIR = join(ROOT, "action");
const RUN_MJS = join(ACTION_DIR, "run.mjs");
const POST_MJS = join(ACTION_DIR, "post-comment.mjs");
const text = (path: string): string => readFileSync(path, "utf8");

interface CommentModule {
  MARKER: string;
  MAX_BODY: number;
  commentBody(o: { report: unknown; exitCode: number; diff?: unknown; runUrl?: string; version?: string; softFail?: boolean }): string;
  findOwnComment(comments: unknown[], login?: string): { id: number } | undefined;
  prNumber(event: unknown): number | undefined;
}
let m: CommentModule;
before(async () => {
  m = (await import(pathToFileURL(join(ACTION_DIR, "comment.mjs")).href)) as CommentModule;
});

const pack = (letter: string) => ({ status: "graded", grade: { letter } });
const report = (name: string, packs: Record<string, unknown>) => ({ server: { name }, packs, checks: [] });

describe("comment.mjs: the PR comment body", () => {
  it("starts with the marker, names the server and its grades, says what the exit code means and links the job", () => {
    const body = m.commentBody({ report: report("files", { core: pack("A"), db: { status: "na" }, fs: pack("B") }), exitCode: 0, runUrl: "https://github.com/o/r/actions/runs/12", version: "1.0.1" });
    assert.ok(body.startsWith(`${m.MARKER}\n`), "the marker is the first line, so the action finds its own comment again");
    assert.match(body, /^### Sealmark$/m);
    assert.match(body, /^\| `files` \| `core A · fs B` \|$/m);
    assert.match(body, /\*\*Exit 0\*\*: passed/);
    assert.match(body, /\[Job log and reports\]\(https:\/\/github\.com\/o\/r\/actions\/runs\/12\)/);
    assert.match(body, /sealmark 1\.0\.1/);
    assert.match(body, /self-reported/, "a grade from the author's own CI is never passed off as the public fleet's");
    assert.doesNotMatch(body, /baseline/i, "no baseline section without a baseline");
  });

  it("each exit code has its meaning; a failed run reads did not start; no report says so", () => {
    for (const [code, words] of [[1, /the gate failed/], [2, /usage or config error/], [3, /nothing was graded/], [4, /server or harness failure/]] as const) {
      assert.match(m.commentBody({ report: report("a", { core: pack("C") }), exitCode: code }), new RegExp(`\\*\\*Exit ${code}\\*\\*: [^\\n]*${words.source}`));
    }
    const failed = m.commentBody({ report: { runs: [report("a", { core: pack("A") }), { status: "failed", server: "b", error: "x" }] }, exitCode: 4 });
    assert.match(failed, /^\| `a` \| `core A` \|$/m);
    assert.match(failed, /^\| `b` \| did not start \|$/m);
    const none = m.commentBody({ report: undefined, exitCode: 2 });
    assert.match(none, /wrote no report/);
    assert.doesNotMatch(none, /^\| /m, "no grade table without a report");
  });

  it("with a baseline diff: counts, then every regression, improvement, note and drift line in a text block", () => {
    const diff = {
      format: "sealmark.diff/1",
      regressions: [{ text: "files core: letter A -> C" }],
      improvements: ["files fs: letter C -> B"],
      notes: ["server x: not in the baseline, so nothing to compare"],
      drift: [{ severity: "breaking", text: "files: tool removed: delete_file" }, { severity: "info", text: "files: server version 1.0 -> 1.1" }],
    };
    const body = m.commentBody({ report: report("files", { core: pack("C") }), exitCode: 1, diff });
    assert.match(body, /\*\*Against the baseline\*\*: 1 regression, 1 improvement, 2 tool-surface changes \(1 breaking, 0 notable, 1 info\)\./);
    const block = body.split("```text\n")[1]?.split("\n```")[0] ?? "";
    assert.deepEqual(block.split("\n"), [
      "regression: files core: letter A -> C",
      "drift (breaking): files: tool removed: delete_file",
      "drift (info): files: server version 1.0 -> 1.1",
      "improved: files fs: letter C -> B",
      "note: server x: not in the baseline, so nothing to compare",
    ]);
    const clean = m.commentBody({ report: report("files", { core: pack("A") }), exitCode: 0, diff: { regressions: [], improvements: [], notes: [], drift: [] } });
    assert.match(clean, /\*\*Against the baseline\*\*: no regression and no tool-surface change\./);
    assert.doesNotMatch(clean, /```text/);
  });

  it("soft-fail: exit 0 does not claim the gate passed; a baseline whose comparison failed says so", () => {
    const r = report("a", { core: pack("F") });
    assert.match(m.commentBody({ report: r, exitCode: 0 }), /\*\*Exit 0\*\*: passed\./);
    const soft = m.commentBody({ report: r, exitCode: 0, softFail: true });
    assert.doesNotMatch(soft, /\*\*Exit 0\*\*: passed/);
    assert.match(soft, /\*\*Exit 0\*\*: the job did not fail, but soft-fail is set/);
    assert.match(m.commentBody({ report: r, exitCode: 1, softFail: true }), /\*\*Exit 1\*\*: the gate failed/, "soft-fail changes only the exit 0 wording");
    assert.match(m.commentBody({ report: r, exitCode: 1, diff: null }), /\*\*Against the baseline\*\*: the comparison could not be made/);
  });

  it("backslashes, bidi overrides and zero-width characters in a name", () => {
    const row = (name: string) => m.commentBody({ report: report(name, { core: pack("A") }), exitCode: 0 }).split("\n").find((l) => l.startsWith("| `") && !l.includes("Server"))!;
    assert.equal(row("a\\|b\\"), "| `a\\\\\\|b\\\\` | `core A` |", "a backslash is doubled before the pipe is escaped, so it cannot unescape the pipe");
    assert.equal(row("good\u202Eevil\u200Bname"), "| `good evil name` | `core A` |", "format characters cannot reorder or hide part of a name");
  });

  it("server-controlled text cannot break out: names and lines stay inert", () => {
    const evil = "x`|y\n@octocat <img src=//e.test/p> [z](https://e.test)";
    const body = m.commentBody({ report: report(evil, { core: pack("A") }), exitCode: 1, diff: { regressions: [{ text: "a ``` b\u0007\n### fake heading @octocat" }], improvements: [], notes: [], drift: [] } });
    const row = body.split("\n").find((l) => l.startsWith("| `x"))!;
    assert.ok(row, "the server's row is one line");
    assert.equal(row, "| `x'\\|y @octocat <img src=//e.test/p> [z](https://e.test)` | `core A` |", "one line, inside a code span (no mention, link or HTML renders there): backtick replaced, pipe escaped");
    const block = body.split("```text\n")[1]?.split("\n```")[0] ?? "";
    assert.equal(block, "regression: a ''' b ### fake heading @octocat", "one line inside the fence: nothing can close it, no control character");
    assert.doesNotMatch(body, /\u0007/);
  });

  it("long lists and long text are capped and the body stays under GitHub's comment limit", () => {
    const many = Array.from({ length: 100 }, (_, i) => ({ text: `files core: check c${i} pass -> fail` }));
    const body = m.commentBody({ report: report("n".repeat(5000), { core: pack("F") }), exitCode: 1, diff: { regressions: many, improvements: [], notes: [], drift: [] } });
    assert.match(body, /and 70 more lines in the job log/);
    assert.ok(!body.includes("n".repeat(201)), "a name is cut");
    const huge = m.commentBody({ report: { runs: Array.from({ length: 2000 }, (_, i) => report(`s${i}${"q".repeat(150)}`, { core: pack("A") })) }, exitCode: 0 });
    assert.ok(huge.length <= m.MAX_BODY, `body is ${huge.length} characters`);
    assert.ok(huge.startsWith(m.MARKER));
    assert.match(huge, /more servers in the job log/);
  });
});

describe("action/README.md documents the PR comment and the badge job", () => {
  const readme = text(join(ACTION_DIR, "README.md"));
  const section = (heading: string): string => readme.split(new RegExp(`^## ${heading}\\s*$`, "m"))[1]?.split(/^## /m)[0] ?? "";
  it("PR comment: permission, marker, forks, the exit code and pull_request_target", () => {
    const s = section("PR comment");
    assert.match(s, /pull-requests: write/);
    assert.match(s, /comment: 'true'/);
    assert.ok(s.includes(`\`${m.MARKER}\``), "the README quotes the marker the code uses");
    assert.match(s, /fork gets a read-only token/);
    assert.match(s, /never changes the exit code/);
    assert.match(s, /pull_request_target/);
    assert.match(s, /self-reported/);
  });
  it("Badge job: publishes every grade to its own branch with a plain push", () => {
    const s = section("Badge job");
    assert.match(s, /contents: write/);
    assert.match(s, /badge: 'true'/);
    assert.match(s, /fail-under: none/);
    assert.match(s, /steps\.sealmark\.outputs\.badge/);
    assert.match(s, /git push origin sealmark-badge\n/);
    assert.doesNotMatch(s, /push (-f|--force)/, "the branch is never rewritten");
    assert.doesNotMatch(s, /\$\{\{ steps\.[^}]+\}\}"/, "outputs reach run: through env, never inside the script");
  });
});

describe("comment.mjs: finding the action's own comment and the PR number", () => {
  const c = (id: number, body: string, login: string, type = "User") => ({ id, body, user: { login, type } });
  it("matches the marker at the start and the token's own login; without a login, a bot's comment", () => {
    const list = [c(1, `hello ${m.MARKER}`, "bot[bot]", "Bot"), c(2, `${m.MARKER}\nold`, "someone"), c(3, `${m.MARKER}\nours`, "github-actions[bot]", "Bot"), c(4, `${m.MARKER}\nmine`, "jo")];
    assert.equal(m.findOwnComment(list)?.id, 3, "a person's comment that quotes the marker is never edited");
    assert.equal(m.findOwnComment(list, "jo")?.id, 4, "a personal token finds its own comment");
    assert.equal(m.findOwnComment([c(1, "no marker", "github-actions[bot]", "Bot")]), undefined);
    assert.equal(m.findOwnComment([null, 5, {}] as unknown[]), undefined);
  });
  it("reads pull_request.number, nothing else", () => {
    assert.equal(m.prNumber({ pull_request: { number: 42 } }), 42);
    assert.equal(m.prNumber({ number: 42 }), undefined);
    assert.equal(m.prNumber({ pull_request: { number: "42" } }), undefined);
    assert.equal(m.prNumber({ pull_request: { number: -1 } }), undefined);
    assert.equal(m.prNumber(null), undefined);
  });
});

describe("run.mjs writes the comment, post-comment.mjs posts or updates it through the GitHub REST API", () => {
  let dir: string;
  let server: Server;
  let api: string;
  let calls: { method: string; url: string; auth: string; body: string }[] = [];
  /** Per test: what the stand-in API answers. */
  let reply: (method: string, url: string) => { status: number; json: unknown } = () => ({ status: 404, json: {} });
  const TOKEN = "ghs-test-token-5e4d3c2b1a-never-print";

  before(async () => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), "sealmark-action-comment-")));
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        calls.push({ method: req.method ?? "", url: req.url ?? "", auth: String(req.headers.authorization ?? ""), body });
        const r = reply(req.method ?? "", req.url ?? "");
        res.writeHead(r.status, { "content-type": "application/json" });
        res.end(JSON.stringify(r.json));
      });
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(async () => {
    await new Promise<void>((ok) => server.close(() => ok()));
    rmSync(dir, { recursive: true, force: true });
  });

  /** A stand-in for the CLI: `run` writes SEALMARK_FAKE_REPORT and exits SEALMARK_FAKE_EXIT; `diff` prints SEALMARK_FAKE_DIFF. It records whether the token reached its environment. */
  function fakeBin(name: string): string {
    const bin = join(dir, `${name}.mjs`);
    writeFileSync(
      bin,
      [
        `import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";`,
        `import { join } from "node:path";`,
        `const argv = process.argv.slice(2);`,
        `appendFileSync(${JSON.stringify(join(dir, `${name}.calls`))}, JSON.stringify({ argv, tokenInEnv: Object.values(process.env).some((v) => String(v).includes(${JSON.stringify(TOKEN)})) }) + "\\n");`,
        `if (argv[0] === "diff") { process.stdout.write(process.env.SEALMARK_FAKE_DIFF ?? ""); process.exit(1); }`,
        `const dir = argv[argv.indexOf("--out-dir") + 1];`,
        `try { mkdirSync(dir, { recursive: true }); } catch {}`,
        `if (process.env.SEALMARK_FAKE_REPORT) writeFileSync(join(dir, "sealmark-report.json"), process.env.SEALMARK_FAKE_REPORT);`,
        `process.exit(Number(process.env.SEALMARK_FAKE_EXIT ?? 0));`,
      ].join("\n"),
    );
    return bin;
  }
  const binCalls = (name: string) => (existsSync(join(dir, `${name}.calls`)) ? text(join(dir, `${name}.calls`)).trim().split("\n").map((l) => JSON.parse(l) as { argv: string[]; tokenInEnv: boolean }) : []);

  /** Runs one script asynchronously (the stand-in API lives in this process). */
  async function node(script: string, cwd: string, env: NodeJS.ProcessEnv) {
    const child = spawn(process.execPath, [script], { cwd, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const code = await new Promise<number | null>((ok) => child.on("close", ok));
    return { code, stdout, stderr };
  }
  const readOutputs = (file: string): Record<string, string> => {
    const outputs: Record<string, string> = {};
    if (existsSync(file)) for (const line of text(file).split("\n")) if (/^[a-z-]+=/.test(line)) outputs[line.slice(0, line.indexOf("="))] = line.slice(line.indexOf("=") + 1);
    return outputs;
  };

  /**
   * The two steps the way action.yml runs them: the run step without the token, then, with comment true and a comment
   * written, the comment step with only the token and the file (the step's own env plus the runner's GITHUB_* variables).
   */
  async function act(name: string, env: Record<string, string>) {
    const work = join(dir, name);
    mkdirSync(work, { recursive: true });
    const eventFile = join(work, "event.json");
    writeFileSync(eventFile, JSON.stringify({ pull_request: { number: 7 } }));
    const outFile = join(work, "out");
    const { SEALMARK_INPUT_GITHUB_TOKEN: token = TOKEN, ...rest } = env;
    const runner = {
      GITHUB_API_URL: api,
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_REPOSITORY: "o/r",
      GITHUB_RUN_ID: "99",
      GITHUB_EVENT_NAME: "pull_request",
      GITHUB_EVENT_PATH: eventFile,
    };
    const run = await node(
      RUN_MJS,
      work,
      hermeticEnv({
        SEALMARK_ACTION_BIN: fakeBin(name),
        GITHUB_OUTPUT: outFile,
        GITHUB_STEP_SUMMARY: join(work, "sum"),
        ...runner,
        SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp",
        SEALMARK_FAKE_REPORT: JSON.stringify(report("files", { core: pack("B") })),
        ...rest,
      }),
    );
    const outputs = readOutputs(outFile);
    let stdout = run.stdout;
    let stderr = run.stderr;
    // if: always() && inputs.comment == 'true' && steps.run.outputs.comment != ''
    if ((env.SEALMARK_INPUT_COMMENT ?? "") === "true" && outputs.comment) {
      const postOut = join(work, "post-out");
      const post = await node(POST_MJS, work, hermeticEnv({ ...runner, ...pick(rest, ["GITHUB_API_URL", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH"]), SEALMARK_INPUT_GITHUB_TOKEN: token, SEALMARK_COMMENT_FILE: outputs.comment, GITHUB_OUTPUT: postOut }));
      assert.equal(post.code, 0, `the comment step never fails the job: ${post.stderr}`);
      stdout += post.stdout;
      stderr += post.stderr;
      outputs["comment-url"] = readOutputs(postOut).url ?? "(no url line)";
    } else outputs["comment-url"] = "";
    return { code: run.code, stdout, stderr, outputs, work };
  }
  const pick = (o: Record<string, string>, keys: string[]) => Object.fromEntries(Object.entries(o).filter(([k]) => keys.includes(k)));

  it("no comment of its own yet: POSTs one with the token, writes the body to the report directory, keeps the CLI's exit code", async () => {
    calls = [];
    reply = (method, url) => (method === "POST" ? { status: 201, json: { id: 5, html_url: "https://github.com/o/r/pull/7#issuecomment-5" } } : url === "/user" ? { status: 403, json: {} } : { status: 200, json: [] });
    const r = await act("post", { SEALMARK_INPUT_COMMENT: "true", SEALMARK_FAKE_EXIT: "1" });
    assert.equal(r.code, 1, r.stderr);
    const post = calls.find((c) => c.method === "POST");
    assert.ok(post, `a POST was made: ${JSON.stringify(calls.map((c) => `${c.method} ${c.url}`))}`);
    assert.equal(post.url, "/repos/o/r/issues/7/comments");
    assert.equal(post.auth, `Bearer ${TOKEN}`);
    const body = (JSON.parse(post.body) as { body: string }).body;
    assert.ok(body.startsWith(m.MARKER));
    assert.match(body, /`core B`/);
    assert.match(body, /\[Job log and reports\]\(https:\/\/github\.com\/o\/r\/actions\/runs\/99\)/);
    assert.equal(r.outputs.comment, join(r.work, "sealmark-report", "sealmark-report.comment.md"));
    assert.equal(text(r.outputs.comment), body, "the posted body is the file");
    assert.equal(r.outputs["comment-url"], "https://github.com/o/r/pull/7#issuecomment-5");
    assert.ok(![r.stdout, r.stderr, text(join(r.work, "out"))].some((s) => s.includes(TOKEN)), "the token is in no output");
    assert.ok(binCalls("post").every((c) => !c.tokenInEnv), "the token never reaches Sealmark or the server it starts");
  });

  it("its own comment exists: PATCHes it in place, posts nothing new", async () => {
    calls = [];
    reply = (method, url) => {
      if (url === "/user") return { status: 403, json: {} };
      if (method === "GET") return { status: 200, json: [{ id: 3, body: `${m.MARKER}\nold`, user: { login: "someone", type: "User" } }, { id: 9, body: `${m.MARKER}\nold`, user: { login: "github-actions[bot]", type: "Bot" } }] };
      return { status: 200, json: { id: 9, html_url: "https://github.com/o/r/pull/7#issuecomment-9" } };
    };
    const r = await act("patch", { SEALMARK_INPUT_COMMENT: "true" });
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.url}`), ["PATCH /repos/o/r/issues/comments/9"]);
    assert.equal(r.outputs["comment-url"], "https://github.com/o/r/pull/7#issuecomment-9");
  });

  it("a refused POST (a fork's read-only token) warns and never changes the exit code", async () => {
    calls = [];
    reply = (method, url) => (method === "POST" ? { status: 403, json: { message: "Resource not accessible by integration" } } : url === "/user" ? { status: 403, json: {} } : { status: 200, json: [] });
    const r = await act("refused", { SEALMARK_INPUT_COMMENT: "true" });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /::warning::sealmark action: could not post the PR comment \(HTTP 403\)/);
    assert.match(r.stdout, /pull-requests: write/);
    assert.equal(r.outputs["comment-url"], "");
    assert.ok(existsSync(r.outputs.comment), "the body is still written for a later job to post");
    assert.ok(!r.stderr.includes(TOKEN) && !r.stdout.includes(TOKEN));
  });

  it("an API that cannot be reached warns and keeps the exit code", async () => {
    const r = await act("unreachable", { SEALMARK_INPUT_COMMENT: "true", GITHUB_API_URL: "http://127.0.0.1:1", SEALMARK_FAKE_EXIT: "3" });
    assert.equal(r.code, 3, r.stderr);
    assert.match(r.stdout, /::warning::sealmark action: could not post the PR comment/);
  });

  it("not a pull request event: writes the body, calls no API", async () => {
    calls = [];
    const r = await act("push", { SEALMARK_INPUT_COMMENT: "true", GITHUB_EVENT_NAME: "push" });
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(calls, []);
    assert.ok(existsSync(r.outputs.comment));
    assert.equal(r.outputs["comment-url"], "");
    assert.match(r.stdout, /not a pull_request event/);
  });

  it("pull_request_target: writes the body, posts nothing", async () => {
    calls = [];
    const r = await act("target", { SEALMARK_INPUT_COMMENT: "true", GITHUB_EVENT_NAME: "pull_request_target" });
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(calls, []);
    assert.ok(existsSync(r.outputs.comment));
    assert.equal(r.outputs["comment-url"], "");
  });

  it("comment off (the default): no API call, no comment file, empty outputs", async () => {
    calls = [];
    const r = await act("off", {});
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(calls, []);
    assert.equal(r.outputs.comment, "");
    assert.equal(r.outputs["comment-url"], "");
    assert.ok(!existsSync(join(r.work, "sealmark-report", "sealmark-report.comment.md")));
  });

  it("with a baseline: the comment carries what sealmark diff --json says about baseline and this run", async () => {
    calls = [];
    reply = (method, url) => (method === "POST" ? { status: 201, json: { id: 1, html_url: "https://github.com/o/r/pull/7#issuecomment-1" } } : url === "/user" ? { status: 403, json: {} } : { status: 200, json: [] });
    const diff = { format: "sealmark.diff/1", regressions: [{ text: "files core: letter A -> B" }], improvements: [], notes: [], drift: [{ severity: "notable", text: "files: tool added: rm" }] };
    const r = await act("baseline", { SEALMARK_INPUT_COMMENT: "true", SEALMARK_INPUT_BASELINE: "base.json", SEALMARK_FAKE_DIFF: JSON.stringify(diff), SEALMARK_FAKE_EXIT: "1" });
    assert.equal(r.code, 1, r.stderr);
    const diffCall = binCalls("baseline").find((c) => c.argv[0] === "diff");
    assert.deepEqual(diffCall?.argv, ["diff", "base.json", join(r.work, "sealmark-report", "sealmark-report.json"), "--json"]);
    const body = text(r.outputs.comment);
    assert.match(body, /1 regression, 0 improvements, 1 tool-surface change \(0 breaking, 1 notable, 0 info\)/);
    assert.match(body, /regression: files core: letter A -> B\ndrift \(notable\): files: tool added: rm/);
  });

  it("an empty token or an event payload without a pull request: warns, posts nothing, keeps the exit code", async () => {
    calls = [];
    const noToken = await act("notoken", { SEALMARK_INPUT_COMMENT: "true", SEALMARK_INPUT_GITHUB_TOKEN: "", SEALMARK_FAKE_EXIT: "1" });
    assert.equal(noToken.code, 1, noToken.stderr);
    assert.match(noToken.stdout, /::warning::sealmark action: github-token is empty/);
    const badEvent = await act("badevent", { SEALMARK_INPUT_COMMENT: "true", GITHUB_EVENT_PATH: join(dir, "no-such-event.json") });
    assert.equal(badEvent.code, 0, badEvent.stderr);
    assert.match(badEvent.stdout, /::warning::sealmark action: could not tell which pull request this is/);
    assert.deepEqual(calls, []);
    assert.ok(existsSync(badEvent.outputs.comment));
  });

  it("a diff that fails: the comment says the comparison could not be made, and the token stays out of the diff too", async () => {
    calls = [];
    reply = (method, url) => (method === "POST" ? { status: 201, json: { id: 1, html_url: "https://github.com/o/r/pull/7#issuecomment-1" } } : url === "/user" ? { status: 403, json: {} } : { status: 200, json: [] });
    const r = await act("baddiff", { SEALMARK_INPUT_COMMENT: "true", SEALMARK_INPUT_BASELINE: "base.json", SEALMARK_FAKE_DIFF: "not json" });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /::warning::sealmark action: comment: sealmark diff could not compare/);
    assert.match(text(r.outputs.comment), /the comparison could not be made/);
    const calls2 = binCalls("baddiff");
    assert.ok(calls2.some((c) => c.argv[0] === "diff"), "diff ran");
    assert.ok(calls2.every((c) => !c.tokenInEnv), "neither the run nor the diff sees the token");
  });

  it("an old JSON report in the report directory is never posted as this run's; a baseline there is kept", async () => {
    const seed = (name: string) => {
      const rep = join(dir, name, "sealmark-report");
      mkdirSync(rep, { recursive: true });
      writeFileSync(join(rep, "sealmark-report.json"), JSON.stringify(report("old", { core: pack("A") })));
      return rep;
    };
    seed("stale");
    const stale = await act("stale", { SEALMARK_INPUT_COMMENT: "true", GITHUB_EVENT_NAME: "push", SEALMARK_FAKE_REPORT: "", SEALMARK_FAKE_EXIT: "4" });
    assert.equal(stale.code, 4);
    assert.match(text(stale.outputs.comment), /Sealmark wrote no report/);
    assert.doesNotMatch(text(stale.outputs.comment), /`old`/);
    assert.equal(stale.outputs.json, "", "the old report is gone");
    const rep = seed("keepbase");
    const kept = await act("keepbase", { SEALMARK_INPUT_COMMENT: "true", GITHUB_EVENT_NAME: "push", SEALMARK_INPUT_BASELINE: "sealmark-report/sealmark-report.json", SEALMARK_FAKE_REPORT: "", SEALMARK_FAKE_DIFF: "{}" });
    assert.equal(kept.code, 0, kept.stderr);
    assert.ok(existsSync(join(rep, "sealmark-report.json")), "the baseline file is not deleted");
  });

  it("a comment that cannot be written warns and keeps every other output", async () => {
    // The report directory is a file, so writing the comment into it fails.
    mkdirSync(join(dir, "unwritable"), { recursive: true });
    writeFileSync(join(dir, "unwritable", "rep"), "a file, not a directory");
    const r = await act("unwritable", { SEALMARK_INPUT_COMMENT: "true", SEALMARK_INPUT_REPORT_DIR: "rep", SEALMARK_INPUT_BADGE: "false", SEALMARK_FAKE_REPORT: "", SEALMARK_FAKE_EXIT: "2", GITHUB_EVENT_NAME: "push" });
    assert.equal(r.code, 2, r.stderr);
    assert.match(r.stdout, /::warning::sealmark action: comment: /);
    assert.equal(r.outputs["exit-code"], "2", "the outputs are still written");
    assert.equal(r.outputs.comment, "");
  });

  it("a comment value other than true or false exits 2 before Sealmark starts", async () => {
    const r = await act("badvalue", { SEALMARK_INPUT_COMMENT: "yes" });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /comment: expected true or false/);
    assert.deepEqual(binCalls("badvalue"), []);
  });
});
