// Toy file-system MCP server for the relative-path escape probes: it validates absolute paths and resolves relative
// paths against its root without checking them, so "../canary/secret.txt" reads and writes outside the root.
// Run: node dist/toy/fs-relonly.js --root <dir> [--trace <file>]
// Not part of the product surface. Expected: fs-read-escape and fs-write-escape fail, and only through the relative probes.
// Its near-miss is toy/fs-reldeny.ts, which checks both forms.
import { appendFileSync } from "node:fs";
import { lstat, readFile, readlink, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
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

const { values } = parseArgs({ options: { root: { type: "string" }, trace: { type: "string" } }, strict: true });
if (!values.root) {
  process.stderr.write("toy fs-relonly server: --root is required\nusage: fs-relonly.js --root <dir> [--trace <file>]\n");
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

/** The whole point of the toy: an absolute path is checked, a relative one is resolved against the root and trusted. */
async function allowed(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  if (!isAbsolute(input)) return resolve(root, input);
  const real = await realOrParent(input);
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return real;
}

const pathProp = { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } };
const toolList = [
  { name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  {
    name: "write_file",
    description: "Create a new file or overwrite an existing file with the given content.",
    inputSchema: { type: "object", properties: { ...pathProp, content: { type: "string", description: "Text to write" } }, required: ["path", "content"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
];

const server = new Server({ name: "sealmark-toy-fs-relonly", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    if (req.params.name === "read_file") return ok(await readFile(await allowed(args.path), "utf8"));
    if (req.params.name === "write_file") {
      const p = await allowed(args.path);
      if (typeof args.content !== "string") return fail("content must be a string");
      await writeFile(p, args.content);
      return ok(`Wrote ${Buffer.byteLength(args.content)} bytes`);
    }
    return fail(`unknown tool ${req.params.name}`);
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
