// Toy file-system MCP server (read_file and write_file) that stops answering escape-shaped paths. It answers every call for a path
// inside the root (the control calls, the large-file read, a link that stays inside) and validates paths properly, so it can
// never leak. What differs is what it does with a path that goes out of the root (one that has "..", "canary" or "root-evil" in it).
// Run: node dist/toy/fs-stallafter.js --mode <stall|first-hang> --root <dir> [--trace <file>]
// Not part of the product surface. Expected verdicts (run with --fail-under none; the pack is provisional):
//   stall       never answers an escape-shaped path: no escape probe is ever answered
//               fs-read-escape inconclusive, fs-write-escape inconclusive (a pass would claim probes that were never answered)
//   first-hang  hangs on the FIRST escape-shaped call of each tool only and refuses the rest like a safe server (the near-miss)
//               fs-read-escape pass, fs-write-escape pass (both say how many variants were answered and that one timed out)
import { appendFileSync } from "node:fs";
import { lstat, mkdir, readFile, readlink, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const STALLAFTER_MODES = ["stall", "first-hang"] as const;
type Mode = (typeof STALLAFTER_MODES)[number];

const READ_CAP = 8 * 1024 * 1024;

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
class Refused extends Error {}

const { values } = parseArgs({ options: { mode: { type: "string" }, root: { type: "string" }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!STALLAFTER_MODES.includes(mode) || !values.root) {
  process.stderr.write(`toy fs-stallafter server: --mode must be one of ${STALLAFTER_MODES.join(", ")} and --root is required\nusage: fs-stallafter.js --mode <${STALLAFTER_MODES.join("|")}> --root <dir> [--trace <file>]\n`);
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

async function validated(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  const real = await realOrParent(resolve(root, input));
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return real;
}

/** A path that goes out of the root, by the spellings the harness uses. */
const escapeShaped = (input: unknown): boolean => typeof input === "string" && /\.\.|%2e|canary|root-evil/i.test(input);

const hung = new Set<string>();
/** Never replies. The harness gives up after its probe timeout. */
const stallForever = (): Promise<never> => new Promise(() => {});

const pathProp = { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } };
const toolList = [
  { name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  {
    name: "write_file",
    description: "Create or overwrite a file with the given content.",
    inputSchema: { type: "object", properties: { ...pathProp, content: { type: "string", description: "Text to write" } }, required: ["path", "content"] },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  },
];

const server = new Server({ name: `sealmark-toy-fs-stallafter-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req.params.name;
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: name, args })}\n`);
  if (escapeShaped(args.path) && (mode === "stall" || !hung.has(name))) {
    hung.add(name);
    return stallForever();
  }
  try {
    if (name === "read_file") {
      const p = await validated(args.path);
      const body = await readFile(p);
      if (body.length > READ_CAP) throw new Refused(`File too large: ${body.length} bytes exceeds the ${READ_CAP} byte limit`);
      return ok(body.toString("utf8"));
    }
    if (name === "write_file") {
      if (typeof args.content !== "string") throw new Refused("content must be a string");
      const p = await validated(args.path);
      await mkdir(dirname(p), { recursive: true });
      await writeFile(p, args.content);
      return ok(`Wrote ${Buffer.byteLength(args.content)} bytes`);
    }
    return fail(`unknown tool ${name}`);
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
