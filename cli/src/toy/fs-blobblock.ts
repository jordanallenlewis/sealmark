// Toy file-system MCP server whose only tool, read_media, returns the file as an embedded RESOURCE block with a base64 blob
// (never as text), so a client that prints blocks as "[resource <uri>]" cannot see the bytes.
// Run: node dist/toy/fs-blobblock.js --mode <leaky|safe> --root <dir> [--trace <file>]
// Not part of the product surface. Expected verdicts:
//   leaky   resolves the path against the root and never checks that the result stays inside it, so a path that leaves the root
//           returns the file outside it, inside a resource blob.   fs-read-escape fail (the harness decodes the blob)
//   safe    the same tool with the path held inside the root (the near-miss).   fs-read-escape pass, and the tool is probed
import { appendFileSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const BLOBBLOCK_MODES = ["leaky", "safe"] as const;
type Mode = (typeof BLOBBLOCK_MODES)[number];

const READ_CAP = 8 * 1024 * 1024;

interface Reply {
  [x: string]: unknown;
  content: ({ type: "text"; text: string } | { type: "resource"; resource: { uri: string; mimeType: string; blob: string } })[];
  isError?: boolean;
}
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
class Refused extends Error {}

const { values } = parseArgs({ options: { mode: { type: "string" }, root: { type: "string" }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!BLOBBLOCK_MODES.includes(mode) || !values.root) {
  process.stderr.write(`toy fs-blobblock server: --mode must be one of ${BLOBBLOCK_MODES.join(", ")} and --root is required\nusage: fs-blobblock.js --mode <${BLOBBLOCK_MODES.join("|")}> --root <dir> [--trace <file>]\n`);
  process.exit(2);
}
const root = resolve(values.root);
let realRoot = root;

const within = (child: string, parent: string) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

async function realOrParent(p: string): Promise<string> {
  try {
    return await realpath(p);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    const parent = dirname(p);
    if (parent === p) throw e;
    return join(await realOrParent(parent), basename(p));
  }
}

async function validated(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  const real = await realOrParent(resolve(root, input));
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return real;
}

const server = new Server({ name: `sealmark-toy-fs-blobblock-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "read_media",
      description: "Read a file and return it as an embedded resource.",
      inputSchema: { type: "object", properties: { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } }, required: ["path"] },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    if (req.params.name !== "read_media") return fail(`unknown tool ${req.params.name}`);
    // The bug under test is the missing check in mode leaky: the path is only resolved against the root.
    const p = mode === "safe" ? await validated(args.path) : resolve(root, String(args.path ?? ""));
    const st = await stat(p);
    if (st.size > READ_CAP) throw new Refused(`File too large: ${st.size} bytes exceeds the ${READ_CAP} byte limit`);
    const blob = (await readFile(p)).toString("base64");
    return { content: [{ type: "resource", resource: { uri: `file://${p}`, mimeType: "application/octet-stream", blob } }] };
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
