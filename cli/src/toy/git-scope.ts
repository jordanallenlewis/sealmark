// Toy git MCP server used to test the prefix-confusion probe of the git pack. Each mode checks the repository path in one known way.
// Run: node dist/toy/git-scope.js --mode <m> --repo <allowed repository> [--trace <file>]
// Not part of the product surface.
//
//   startswith  the path must start with the configured repository, as a plain string: "<repo>-evil" gets through
//   strict      the path must be the configured repository or inside it (whole path segments): "<repo>-evil" is refused
//
// Both resolve symbolic links and ".." first, so only the prefix confusion differs. Revisions are validated in both modes.
// Tools: git_status{repo_path}, git_diff{repo_path, target} and git_diff_staged{repo_path}, all annotated read-only, and git_add{repo_path, files}
// (write-capable: stages files, with "--" and the same validation as a revision). `--tools write` offers only git_add, `--tools read` only the
// three read-only tools; the default offers all four. In `strict` mode this is the near miss for the staged-change and symlink probes: it passes.
import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const GIT_SCOPE_MODES = ["startswith", "strict"] as const;
type Mode = (typeof GIT_SCOPE_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

function usage(msg: string): never {
  process.stderr.write(`toy git-scope server: ${msg}\nusage: git-scope.js --mode <${GIT_SCOPE_MODES.join("|")}> --repo <dir> [--trace <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, repo: { type: "string" }, trace: { type: "string" }, tools: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!GIT_SCOPE_MODES.includes(mode)) usage(`--mode must be one of ${GIT_SCOPE_MODES.join(", ")}`);
if (!values.repo) usage("--repo is required");
const allowedRepo = resolve(values.repo);
const toolSet = values.tools ?? "all";
if (!["all", "read", "write"].includes(toolSet)) usage("--tools must be all, read or write");

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const inside = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  if (mode === "startswith") return c.startsWith(p);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

async function repoFor(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Error("repo_path must be a non-empty string");
  // The allowed repository may not exist yet when the harness only lists tools; it does when a call arrives.
  const real = await realpath(resolve(input)).catch(() => resolve(input));
  const allowedReal = await realpath(allowedRepo).catch(() => allowedRepo);
  if (!inside(real, allowedReal)) throw new Error(`Access denied: ${input} is not the configured repository`);
  return real;
}

function git(repo: string, args: string[]): Promise<Reply> {
  return new Promise((done) => {
    execFile("git", ["-C", repo, ...args], { maxBuffer: 8 * 1024 * 1024, windowsHide: true, timeout: 20_000 }, (err, stdout, stderr) => {
      if (err) done(fail(`git failed: ${stderr.trim() || err.message}`));
      else done(ok(stdout || "(no output)"));
    });
  });
}

const server = new Server({ name: `sealmark-toy-git-scope-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
const annotations = { readOnlyHint: true, openWorldHint: false };
const readTools = [
  {
    name: "git_status",
    description: "Show the working tree status of a git repository.",
    inputSchema: { type: "object" as const, properties: { repo_path: { type: "string", description: "Path to the git repository" } }, required: ["repo_path"] },
    annotations,
  },
  {
    name: "git_diff",
    description: "Show the differences between the working tree and a git revision.",
    inputSchema: {
      type: "object" as const,
      properties: { repo_path: { type: "string", description: "Path to the git repository" }, target: { type: "string", description: "Branch, tag or commit to compare with" } },
      required: ["repo_path", "target"],
    },
    annotations,
  },
  {
    name: "git_diff_staged",
    description: "Show the changes staged in the index of a git repository.",
    inputSchema: { type: "object" as const, properties: { repo_path: { type: "string", description: "Path to the git repository" } }, required: ["repo_path"] },
    annotations,
  },
];
const writeTools = [
  {
    name: "git_add",
    description: "Add file contents to the index of a git repository.",
    inputSchema: {
      type: "object" as const,
      properties: { repo_path: { type: "string", description: "Path to the git repository" }, files: { type: "array", items: { type: "string" }, description: "Files to stage" } },
      required: ["repo_path", "files"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  },
];
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [...(toolSet === "write" ? [] : readTools), ...(toolSet === "read" ? [] : writeTools)] }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    const repo = await repoFor(args.repo_path);
    if (req.params.name === "git_status") return await git(repo, ["status", "--short"]);
    if (req.params.name === "git_diff") {
      const target = args.target;
      if (typeof target !== "string" || !target) return fail("target must be a non-empty string");
      if (!/^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/.test(target)) return fail(`Invalid revision: ${target}`);
      return await git(repo, ["diff", target]);
    }
    if (req.params.name === "git_diff_staged") return await git(repo, ["diff", "--staged"]);
    if (req.params.name === "git_add") {
      const files = args.files;
      if (!Array.isArray(files) || !files.length || files.some((f) => typeof f !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/.test(f))) return fail("Invalid files");
      return await git(repo, ["add", "--", ...(files as string[])]);
    }
    return fail(`unknown tool ${req.params.name}`);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
