// Toy git MCP server used to test argument injection through an OPTIONAL string parameter of the git pack.
// Run: node dist/toy/git-inject.js --mode <m> --repo <allowed repository> [--trace <file>]
// Not part of the product surface.
//
//   loose   the optional revision is handed to git unchecked ("--output=<file>" works)
//   strict  the optional revision is validated: it cannot start with "-"
//   refname the revision is never given to git as an argument, but is recorded as a bookmark: a branch ref named after it is
//           created under .git (a file whose name contains the value, written by git itself, not by an option)
//
// Only the configured repository may be named, in both modes. The tool is git_log{repo_path, revision?, max_count?}. The
// optional parameters are declared the way a pydantic model declares Optional[str] and Optional[int]:
// {anyOf: [{type: "string"}, {type: "null"}], default: null} has no "type" of its own.
import { execFile } from "node:child_process";
import { appendFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const GIT_INJECT_MODES = ["loose", "strict", "refname"] as const;
type Mode = (typeof GIT_INJECT_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

function usage(msg: string): never {
  process.stderr.write(`toy git-inject server: ${msg}\nusage: git-inject.js --mode <${GIT_INJECT_MODES.join("|")}> --repo <dir> [--trace <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, repo: { type: "string" }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!GIT_INJECT_MODES.includes(mode)) usage(`--mode must be one of ${GIT_INJECT_MODES.join(", ")}`);
if (!values.repo) usage("--repo is required");
const allowedRepo = resolve(values.repo);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const within = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

async function repoFor(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Error("repo_path must be a non-empty string");
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

const server = new Server({ name: `sealmark-toy-git-inject-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
const annotations = { readOnlyHint: true, openWorldHint: false };
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "git_log",
      description: "Show the commit history of a git repository.",
      inputSchema: {
        type: "object" as const,
        properties: {
          repo_path: { type: "string", description: "Path to the git repository" },
          revision: { anyOf: [{ type: "string" }, { type: "null" }], default: null, title: "Revision", description: "Branch, tag or commit to start from" },
          max_count: { anyOf: [{ type: "integer" }, { type: "null" }], default: null, title: "Max Count", description: "Number of commits to show" },
        },
        required: ["repo_path"],
      },
      annotations,
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    if (req.params.name !== "git_log") return fail(`unknown tool ${req.params.name}`);
    const repo = await repoFor(args.repo_path);
    const out = ["log", "--format=%h %s", "-n", String(typeof args.max_count === "number" ? args.max_count : 5)];
    const rev = args.revision;
    if (typeof rev === "string" && rev && mode === "refname") {
      // Only a value that is not a plain word is bookmarked (HEAD, main and the like are shown as they are).
      if (!/^\w+$/.test(rev)) {
        const made = await git(repo, ["update-ref", `refs/heads/${rev}`, "HEAD"]);
        if (made.isError) return made;
      }
    } else if (typeof rev === "string" && rev) {
      if (mode === "strict" && !/^[A-Za-z0-9_][A-Za-z0-9_./~^@{}-]*$/.test(rev)) return fail(`Invalid revision: ${rev}`);
      // The loose mode passes the value straight through, without "--" and without a shell: git itself reads "--output=<file>".
      out.push(rev);
    }
    return await git(repo, out);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
