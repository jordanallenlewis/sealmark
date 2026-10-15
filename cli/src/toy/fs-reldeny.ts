// Toy file-system MCP server that validates every path form, the near-miss of toy/fs-relonly.ts: a relative path is
// resolved against the root and then checked the same way an absolute one is.
// Run: node dist/toy/fs-reldeny.js --root <dir> [--abs-only] [--links follow|refuse|enoent] [--trace <file>]
// Not part of the product surface. Expected: every fs check passes.
//
//   --abs-only          a relative path is refused outright ("path must be absolute"), so only absolute probes make sense
//   --links follow      (default) links are resolved before the root check, so a link that leaves the root is refused and one
//                       that stays inside is followed
//   --links refuse      any path that goes through a symbolic link is refused with a clear message, inside the root or not
//   --links enoent      any path that goes through a symbolic link answers "ENOENT" (an unrelated-looking error)
import { appendFileSync, lstatSync } from "node:fs";
import { lstat, readFile, readdir, readlink, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
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

const { values } = parseArgs({ options: { root: { type: "string" }, trace: { type: "string" }, "abs-only": { type: "boolean" }, links: { type: "string" } }, strict: true });
const linkMode = values.links ?? "follow";
if (!values.root || !["follow", "refuse", "enoent"].includes(linkMode)) {
  process.stderr.write("toy fs-reldeny server: --root is required and --links must be follow, refuse or enoent\nusage: fs-reldeny.js --root <dir> [--abs-only] [--links follow|refuse|enoent] [--trace <file>]\n");
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

/** True when a component of the path below the root is a symbolic link (or a junction). */
function throughLink(full: string): boolean {
  const rel = relative(root, full);
  if (rel.startsWith("..") || isAbsolute(rel)) return false;
  let cur = root;
  for (const part of rel.split(sep).filter(Boolean)) {
    cur = join(cur, part);
    try {
      if (lstatSync(cur).isSymbolicLink()) return true;
    } catch {
      return false;
    }
  }
  return false;
}

async function allowed(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  if (values["abs-only"] && !isAbsolute(input)) throw new Refused("Invalid path: path must be absolute");
  const full = resolve(root, input);
  if (linkMode === "refuse" && throughLink(full)) throw new Refused("Access denied: symbolic links are not followed");
  if (linkMode === "enoent" && throughLink(full)) throw Object.assign(new Error(`ENOENT: no such file or directory, open '${input}'`), { code: "ENOENT" });
  const real = await realOrParent(full);
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return real;
}

const pathProp = { path: { type: "string", description: values["abs-only"] ? "Absolute path inside the allowed directory" : "Absolute path, or a path relative to the allowed directory" } };
const toolList = [
  { name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  {
    name: "write_file",
    description: "Create a new file or overwrite an existing file with the given content.",
    inputSchema: { type: "object", properties: { ...pathProp, content: { type: "string", description: "Text to write" } }, required: ["path", "content"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
  { name: "list_dir", description: "List the entries of a directory.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
];

const server = new Server({ name: "sealmark-toy-fs-reldeny", version: "0.0.1" }, { capabilities: { tools: {} } });
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
    if (req.params.name === "list_dir") {
      const entries = await readdir(await allowed(args.path), { withFileTypes: true });
      return ok(entries.map((e) => `${e.isDirectory() ? "[DIR]" : "[FILE]"} ${e.name}`).join("\n"));
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
