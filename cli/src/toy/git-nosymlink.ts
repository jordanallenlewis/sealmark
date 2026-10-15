// Toy git MCP server for the symlink probe of git-repo-scope: the repository check normalises ".." but never resolves links.
// Run: node dist/toy/git-nosymlink.js --repo <allowed repository> [--trace <file>]
// Not part of the product surface.
//
// The path is resolved lexically (so "<repo>/../../canary/repo" is refused) and must be the configured repository or inside it (whole
// path segments, so "<repo>-evil" is refused). A link inside the repository that points elsewhere is inside, lexically, and git follows it.
// Tools: git_status{repo_path}, git_diff{repo_path, target} and git_diff_staged{repo_path}, all annotated read-only.
import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const { values } = parseArgs({ options: { repo: { type: "string" }, trace: { type: "string" } }, strict: true });
if (!values.repo) {
  process.stderr.write("toy git-nosymlink server: --repo is required\nusage: git-nosymlink.js --repo <dir> [--trace <file>]\n");
  process.exit(2);
}
const allowedRepo = resolve(values.repo);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const within = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

function repoFor(input: unknown): string {
  if (typeof input !== "string" || !input) throw new Error("repo_path must be a non-empty string");
  // resolve() removes "." and ".." segments and nothing else: no realpath, so a link stays what it looks like.
  const lexical = resolve(input);
  if (!within(lexical, allowedRepo)) throw new Error(`Access denied: ${input} is not the configured repository`);
  return lexical;
}

function git(repo: string, args: string[]): Promise<Reply> {
  return new Promise((done) => {
    execFile("git", ["-C", repo, ...args], { maxBuffer: 8 * 1024 * 1024, windowsHide: true, timeout: 20_000 }, (err, stdout, stderr) => {
      if (err) done(fail(`git failed: ${stderr.trim() || err.message}`));
      else done(ok(stdout || "(no output)"));
    });
  });
}

const server = new Server({ name: "sealmark-toy-git-nosymlink", version: "0.0.1" }, { capabilities: { tools: {} } });
const annotations = { readOnlyHint: true, openWorldHint: false };
const repoProp = { repo_path: { type: "string", description: "Path to the git repository" } };
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "git_status", description: "Show the working tree status of a git repository.", inputSchema: { type: "object" as const, properties: repoProp, required: ["repo_path"] }, annotations },
    {
      name: "git_diff",
      description: "Show the differences between the working tree and a git revision.",
      inputSchema: { type: "object" as const, properties: { ...repoProp, target: { type: "string", description: "Branch, tag or commit to compare with" } }, required: ["repo_path", "target"] },
      annotations,
    },
    { name: "git_diff_staged", description: "Show the changes staged in the index of a git repository.", inputSchema: { type: "object" as const, properties: repoProp, required: ["repo_path"] }, annotations },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    const repo = repoFor(args.repo_path);
    if (req.params.name === "git_status") return await git(repo, ["status", "--short"]);
    if (req.params.name === "git_diff_staged") return await git(repo, ["diff", "--staged"]);
    if (req.params.name === "git_diff") {
      const target = args.target;
      if (typeof target !== "string" || !target) return fail("target must be a non-empty string");
      if (!/^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/.test(target)) return fail(`Invalid revision: ${target}`);
      return await git(repo, ["diff", target]);
    }
    return fail(`unknown tool ${req.params.name}`);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
