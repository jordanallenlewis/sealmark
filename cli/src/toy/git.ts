// Toy git MCP server used to test the git pack. Each mode misbehaves in one known way.
// Run: node dist/toy/git.js --mode <m> --repo <allowed repository> [--trace <file>]
// Not part of the product surface; the expected verdict for every mode is in the design notes
//
//   good      only the configured repository may be named; the revision cannot start with "-"
//   anyrepo   any repository path is accepted (revision still validated)
//   inject    only the configured repository, but the revision is handed to git unchecked ("--output=<file>" works)
//   both      neither restriction
//   lateinject  like inject, but git is started without being awaited and the reply is "queued": the file appears after the call returned
//
// Tools: git_status{repo_path} and git_diff{repo_path, target}, both annotated read-only. With --with-branch-type <described|bare> there is a
// third, git_branch{repo_path, branch_type}: branch_type is a required free-text string, the way a server that never declared an enum has it;
// any value but local, remote or all is refused. `described`: the description names the three choices ('local', 'remote', 'all'), so the
// harness can fill it. `bare`: the description does not, so the harness's control call for this tool fails (a read tool that cannot be judged).
import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const GIT_MODES = ["good", "anyrepo", "inject", "both", "lateinject"] as const;
type Mode = (typeof GIT_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

function usage(msg: string): never {
  process.stderr.write(`toy git server: ${msg}\nusage: git.js --mode <${GIT_MODES.join("|")}> --repo <dir> [--trace <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, repo: { type: "string" }, trace: { type: "string" }, "with-branch-type": { type: "string" } }, strict: true });
if (values["with-branch-type"] !== undefined && !["described", "bare"].includes(values["with-branch-type"])) usage("--with-branch-type must be described or bare");
const mode = values.mode as Mode;
if (!GIT_MODES.includes(mode)) usage(`--mode must be one of ${GIT_MODES.join(", ")}`);
if (!values.repo) usage("--repo is required");
const allowedRepo = resolve(values.repo);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const within = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

const restrictRepo = mode === "good" || mode === "inject" || mode === "lateinject";
const validateRevision = mode === "good" || mode === "anyrepo";

async function repoFor(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Error("repo_path must be a non-empty string");
  if (!restrictRepo) return input;
  // The allowed repository may not exist yet when the harness only lists tools; it does when a call arrives.
  const real = await realpath(resolve(input)).catch(() => resolve(input));
  const allowedReal = await realpath(allowedRepo).catch(() => allowedRepo);
  if (!within(real, allowedReal)) throw new Error(`Access denied: ${input} is not the configured repository`);
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

const server = new Server({ name: `sealmark-toy-git-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
const annotations = { readOnlyHint: true, openWorldHint: false };
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
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
    ...(values["with-branch-type"]
      ? [
          {
            name: "git_branch",
            description: "List the branches of a git repository.",
            inputSchema: {
              type: "object" as const,
              properties: { repo_path: { type: "string", description: "Path to the git repository" }, branch_type: { type: "string", description: values["with-branch-type"] === "bare" ? "Which branches" : "Which branches: 'local', 'remote', or 'all'" } },
              required: ["repo_path", "branch_type"],
            },
            annotations,
          },
        ]
      : []),
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    const repo = await repoFor(args.repo_path);
    if (req.params.name === "git_status") return await git(repo, ["status", "--short"]);
    if (req.params.name === "git_diff") {
      const target = args.target;
      if (typeof target !== "string" || !target) return fail("target must be a non-empty string");
      if (validateRevision && !/^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/.test(target)) return fail(`Invalid revision: ${target}`);
      // Unchecked modes pass the value straight through, without "--" and without a shell: git itself reads "--output=<file>".
      if (mode === "lateinject") {
        void git(repo, ["diff", target]);
        return ok("queued");
      }
      return await git(repo, ["diff", target]);
    }
    if (req.params.name === "git_branch" && values["with-branch-type"]) {
      const kind = args.branch_type;
      if (kind !== "local" && kind !== "remote" && kind !== "all") return fail(`Invalid branch_type: ${String(kind)} (use local, remote or all)`);
      return await git(repo, ["branch", "--list", ...(kind === "remote" ? ["-r"] : kind === "all" ? ["-a"] : [])]);
    }
    return fail(`unknown tool ${req.params.name}`);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
