// Toy file-system MCP server whose read tool returns file bytes encoded, not as plain text.
// Run: node dist/toy/fs-blob.js --mode <m> --root <dir> [--trace <file>]
// Not part of the product surface.
//
//   b64-leaky   read_media returns {"mimeType":..., "data":"<base64>"} in a text block and does not validate the path.
//               Expected: fs-read-escape fails (the harness decodes the base64 before looking for the canary).
//   b64-safe    the same tool with the path held inside the root (the near-miss). Expected: pass.
//   blob-leaky  read_media returns a resource block with a base64 blob and does not validate the path; read_text is a
//               validated plain-text reader next to it. mcp.ts renders a blob as a placeholder, so the harness cannot read the data:
//               read_media's control cannot pass and it is listed as not covered. Expected: fs-read-escape is a part, never a pass.
import { appendFileSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const BLOB_MODES = ["b64-leaky", "b64-safe", "blob-leaky"] as const;
type Mode = (typeof BLOB_MODES)[number];

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
if (!BLOB_MODES.includes(mode) || !values.root) {
  process.stderr.write(`toy fs-blob server: --mode must be one of ${BLOB_MODES.join(", ")} and --root is required\nusage: fs-blob.js --mode <${BLOB_MODES.join("|")}> --root <dir> [--trace <file>]\n`);
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

async function readBytes(p: string): Promise<Buffer> {
  const st = await stat(p);
  if (st.size > READ_CAP) throw new Refused(`File too large: ${st.size} bytes exceeds the ${READ_CAP} byte limit`);
  return readFile(p);
}

const pathProp = { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } };
const reader = { readOnlyHint: true, openWorldHint: false };
const toolList = [
  { name: "read_media", description: "Read a file and return its bytes, base64 encoded.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: reader },
  ...(mode === "blob-leaky" ? [{ name: "read_text", description: "Read the complete contents of a file as text.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: reader }] : []),
];

const server = new Server({ name: `sealmark-toy-fs-blob-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    if (req.params.name === "read_text") return { content: [{ type: "text", text: (await readBytes(await validated(args.path))).toString("utf8") }] };
    if (req.params.name !== "read_media") return fail(`unknown tool ${req.params.name}`);
    // The bug under test is the missing check in the leaky modes: the path is only resolved against the root.
    const p = mode === "b64-safe" ? await validated(args.path) : resolve(root, String(args.path ?? ""));
    const data = (await readBytes(p)).toString("base64");
    if (mode === "blob-leaky") return { content: [{ type: "resource", resource: { uri: `file://${p}`, mimeType: "application/octet-stream", blob: data } }] };
    return { content: [{ type: "text", text: JSON.stringify({ mimeType: "application/octet-stream", data }) }] };
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
