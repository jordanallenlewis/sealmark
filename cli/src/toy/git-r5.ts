// Toy git MCP server for the round-5 git pack checks: read tools that need an object, a file, a remote or a tag listing to answer, relative repository
// paths, and write-capable tools whose destination and clone source the harness can watch. Each mode checks the paths in one known way.
// Run: node dist/toy/git-r5.js --mode <m> --repo <allowed repository> [--trace <file>]
// Not part of the product surface.
//
//   strict           every tool refuses every repository but the configured one (links and relative paths resolved first), and every destination
//                    outside the directory the configured repository sits in; clone sources, `file://` ones included, are held to the same rule. The
//                    near miss: it passes git-repo-scope with every read and write tool judged
//   show-leaks       like strict, except git_show checks its path lexically: a link inside the configured repository that points at another
//                    repository is followed (absolute or relative)
//   relative-skip    like strict, except a relative repository path is used as it is, without any check
//   worktree-escape  like strict, except git_worktree_add creates its destination wherever it is told to
//   clone-canary     like strict, except git_clone accepts any source (a path or a file:// URL) outside the configured repository
//   empty-lists      like strict, except git_remote and git_tag answer with an empty list ("[]") whatever the repository holds: a well-formed
//                    success that shows nothing of the repository, so the check cannot judge those two tools (a part, never a pass)
//
// Read tools (annotated read-only): git_status{repo_path}, git_diff_staged{repo_path}, git_show{repo_path, object}, git_blame{repo_path, file_path},
// git_remote{repo_path}, git_tag{repo_path}. Write-capable tools: git_add{repo_path, files}, git_commit{repo_path, message},
// git_worktree_add{repo_path, destination}, git_clone{repo_path, destination} (repo_path is the source). Values that start with "-" are refused
// everywhere, so the argument-injection check passes in every mode.
import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const GIT_R5_MODES = ["strict", "show-leaks", "relative-skip", "worktree-escape", "clone-canary", "empty-lists"] as const;
type Mode = (typeof GIT_R5_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

function usage(msg: string): never {
  process.stderr.write(`toy git-r5 server: ${msg}\nusage: git-r5.js --mode <${GIT_R5_MODES.join("|")}> --repo <dir> [--trace <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, repo: { type: "string" }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!GIT_R5_MODES.includes(mode)) usage(`--mode must be one of ${GIT_R5_MODES.join(", ")}`);
if (!values.repo) usage("--repo is required");
const allowedRepo = resolve(values.repo);
/** Destinations must sit inside the directory the configured repository is in. */
const base = dirname(allowedRepo);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const inside = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

const SAFE = /^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/;

/** The repository a call names, after the checks of the mode (`lexical`: the path is not resolved through links). */
async function repoFor(input: unknown, o: { lexical?: boolean; source?: boolean; unchecked?: boolean } = {}): Promise<string> {
  if (typeof input !== "string" || !input) throw new Error("repo_path must be a non-empty string");
  let raw = input;
  if (o.source && /^file:\/\//i.test(raw)) raw = fileURLToPath(raw);
  else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) throw new Error(`Access denied: ${input} is not a local path`);
  // The server's working directory is the sandbox; a relative path is resolved against it.
  const abs = resolve(raw);
  if (o.unchecked || (mode === "relative-skip" && !isAbsolute(raw))) return abs;
  const allowedReal = await realpath(allowedRepo).catch(() => allowedRepo);
  if (o.lexical) {
    if (!inside(abs, allowedRepo)) throw new Error(`Access denied: ${input} is not the configured repository`);
    return abs;
  }
  const real = await realpath(abs).catch(() => abs);
  if (!inside(real, allowedReal)) throw new Error(`Access denied: ${input} is not the configured repository`);
  return real;
}

function destinationFor(input: unknown, o: { unchecked?: boolean } = {}): string {
  if (typeof input !== "string" || !input) throw new Error("destination must be a non-empty string");
  if (input.startsWith("-")) throw new Error(`Invalid destination: ${input}`);
  const abs = resolve(input);
  if (!o.unchecked && !inside(abs, base)) throw new Error(`Access denied: ${input} is outside the allowed directory`);
  return abs;
}

function git(repo: string, args: string[]): Promise<Reply> {
  return new Promise((done) => {
    execFile("git", ["-c", "user.name=toy", "-c", "user.email=toy@example.invalid", "-c", "commit.gpgsign=false", "-C", repo, ...args], { maxBuffer: 8 * 1024 * 1024, windowsHide: true, timeout: 20_000 }, (err, stdout, stderr) => {
      if (err) done(fail(`git failed: ${stderr.trim() || err.message}`));
      else done(ok(stdout || "(no output)"));
    });
  });
}

const server = new Server({ name: `sealmark-toy-git-r5-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
const readOnly = { readOnlyHint: true, openWorldHint: false };
const writes = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };
const repoProp = { type: "string", description: "Path to the git repository" };
const tool = (name: string, description: string, properties: Record<string, unknown>, required: string[], annotations: Record<string, boolean>) => ({
  name,
  description,
  inputSchema: { type: "object" as const, properties: { repo_path: repoProp, ...properties }, required: ["repo_path", ...required] },
  annotations,
});
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    tool("git_status", "Show the working tree status of a git repository.", {}, [], readOnly),
    tool("git_diff_staged", "Show the changes staged in the index of a git repository.", {}, [], readOnly),
    tool("git_show", "Show a commit or another object of a git repository.", { object: { type: "string", description: "The object to show" } }, ["object"], readOnly),
    tool("git_blame", "Show what revision and author last modified each line of a file in a git repository.", { file_path: { type: "string", description: "The file to blame" } }, ["file_path"], readOnly),
    tool("git_remote", "List the remotes of a git repository.", {}, [], readOnly),
    tool("git_tag", "List the tags of a git repository.", {}, [], readOnly),
    tool("git_add", "Add file contents to the index of a git repository.", { files: { type: "array", items: { type: "string" }, description: "Files to stage" } }, ["files"], writes),
    tool("git_commit", "Record the staged changes of a git repository as a commit.", { message: { type: "string", description: "The commit message" } }, ["message"], writes),
    tool("git_worktree_add", "Add a worktree of a git repository in a new directory.", { destination: { type: "string", description: "Where to create the worktree" } }, ["destination"], writes),
    tool("git_clone", "Clone a git repository into a new directory.", { destination: { type: "string", description: "Where to create the clone" } }, ["destination"], writes),
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    const name = req.params.name;
    if (name === "git_clone") {
      // The source is the repository parameter. clone-canary takes any local path or file:// URL; the other modes hold it to the configured repository.
      const source = await repoFor(args.repo_path, { source: true, unchecked: mode === "clone-canary" });
      const dest = destinationFor(args.destination);
      return await git(base, ["clone", "--", source, dest]);
    }
    const repo = await repoFor(args.repo_path, { lexical: mode === "show-leaks" && name === "git_show" });
    if (name === "git_status") return await git(repo, ["status", "--short"]);
    if (name === "git_diff_staged") return await git(repo, ["diff", "--staged"]);
    if (mode === "empty-lists" && (name === "git_remote" || name === "git_tag")) return ok("[]");
    if (name === "git_remote") return await git(repo, ["remote", "-v"]);
    if (name === "git_tag") return await git(repo, ["tag", "--list"]);
    if (name === "git_show") {
      const object = args.object;
      if (typeof object !== "string" || !SAFE.test(object)) return fail(`Invalid object: ${String(object)}`);
      return await git(repo, ["show", "--stat", "--format=%s", object]);
    }
    if (name === "git_blame") {
      const file = args.file_path;
      if (typeof file !== "string" || !SAFE.test(file) || file.split(/[\\/]/).includes("..")) return fail(`Invalid file: ${String(file)}`);
      return await git(repo, ["blame", "--show-name", "--", file]);
    }
    if (name === "git_add") {
      const files = args.files;
      if (!Array.isArray(files) || !files.length || files.some((f) => typeof f !== "string" || !SAFE.test(f))) return fail("Invalid files");
      return await git(repo, ["add", "--", ...(files as string[])]);
    }
    if (name === "git_commit") {
      const message = args.message;
      if (typeof message !== "string" || !message || message.startsWith("-")) return fail("Invalid message");
      return await git(repo, ["commit", "-m", message]);
    }
    if (name === "git_worktree_add") {
      const dest = destinationFor(args.destination, { unchecked: mode === "worktree-escape" });
      return await git(repo, ["worktree", "add", "--detach", "--", dest, "HEAD"]);
    }
    return fail(`unknown tool ${name}`);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
