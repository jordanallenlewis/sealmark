// Toy file-system MCP server with a move (or copy) tool that checks where the file is going but not where it comes from.
// Run: node dist/toy/fs-movesrc.js --root <dir> [--op move|copy] [--check dest|both] [--trace <file>]
// Not part of the product surface.
//
//   --check dest   (default) the destination is held inside the root; the source is trusted. Expected: fs-write-escape fails
//                  through a move-src-* probe. With --op move the secret leaves its directory; with --op copy it appears in the root.
//   --check both   the source is held inside the root too (the near-miss). Expected: fs-write-escape passes.
import { appendFileSync } from "node:fs";
import { copyFile, lstat, readlink, realpath, rename } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
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
class Refused extends Error {}

const { values } = parseArgs({ options: { root: { type: "string" }, op: { type: "string" }, check: { type: "string" }, trace: { type: "string" } }, strict: true });
const op = values.op ?? "move";
const check = values.check ?? "dest";
if (!values.root || !["move", "copy"].includes(op) || !["dest", "both"].includes(check)) {
  process.stderr.write("toy fs-movesrc server: --root is required, --op must be move or copy, --check must be dest or both\nusage: fs-movesrc.js --root <dir> [--op move|copy] [--check dest|both] [--trace <file>]\n");
  process.exit(2);
}
const root = resolve(values.root);
let realRoot = root;

const within = (child: string, parent: string) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

async function realOrParent(p: string, depth = 0): Promise<string> {
  try {
    return await realpath(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    // A link that points nowhere has no real path: follow it by hand, or a write through it lands wherever it points.
    try {
      if ((await lstat(p)).isSymbolicLink() && depth < 16) return await realOrParent(resolve(dirname(p), await readlink(p)), depth + 1);
    } catch {
      /* not a link: a file that is about to be created */
    }
    const parent = dirname(p);
    if (parent === p) throw e;
    return join(await realOrParent(parent, depth), basename(p));
  }
}

/** Resolves a path against the root (absolute and relative both work) and holds it inside the root. */
async function inside(input: unknown, what: string): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused(`${what} must be a non-empty string`);
  const real = await realOrParent(resolve(root, input));
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${what} ${input} is outside the allowed directory`);
  return real;
}

const tool = op === "move" ? "move_file" : "copy_file";
const toolList = [
  {
    name: tool,
    description: op === "move" ? "Move or rename a file." : "Copy a file.",
    inputSchema: { type: "object", properties: { source: { type: "string", description: "File to take" }, destination: { type: "string", description: "Where it goes" } }, required: ["source", "destination"] },
    annotations: { readOnlyHint: false, destructiveHint: op === "move", idempotentHint: false, openWorldHint: false },
  },
];

const server = new Server({ name: `sealmark-toy-fs-movesrc-${op}-${check}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    if (req.params.name !== tool) return fail(`unknown tool ${req.params.name}`);
    const dest = await inside(args.destination, "destination");
    // The bug under test: the source is only resolved, never held inside the root.
    const src = check === "both" ? await inside(args.source, "source") : resolve(root, String(args.source ?? ""));
    if (op === "move") await rename(src, dest);
    else await copyFile(src, dest);
    return ok(`${op === "move" ? "Moved" : "Copied"} ${String(args.source)} to ${String(args.destination)}`);
  } catch (e) {
    if (e instanceof Refused) return fail(e.message);
    const code = (e as NodeJS.ErrnoException).code;
    return fail(code ? `${code}: ${(e as Error).message}` : String((e as Error).message ?? e));
  }
});

try {
  realRoot = await realpath(root);
} catch {
  /* the root may not exist yet when the harness only lists tools */
}
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
