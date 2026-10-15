// Toy file-system MCP server whose content reader is broken while its listing tool works. Used to test what the fs pack says when a
// read tool's control call fails but a list tool's passes (the size cap must not claim that no tool returns file contents), and that
// no real sandbox path survives in a reason line built from the failing tool's error text.
// Run: node dist/toy/fs-ctlfail.js --root <dir> [--trace <file>] [--no-read]
// Not part of the product surface.
//
//   read_file   always fails with an ENOENT message that embeds the path it was given (a long absolute path, so a truncated copy of it is easy to spot)
//   list_dir    realpath, separator-bounded prefix check: refuses everything outside the root
import { appendFileSync } from "node:fs";
import { lstat, readdir, readlink, realpath } from "node:fs/promises";
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

const { values } = parseArgs({ options: { root: { type: "string" }, trace: { type: "string" }, "no-read": { type: "boolean" } }, strict: true });
if (!values.root) {
  process.stderr.write("toy fs-ctlfail server: --root is required\nusage: fs-ctlfail.js --root <dir> [--trace <file>]\n");
  process.exit(2);
}
const rootArg = resolve(values.root);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const within = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};

let realRoot = rootArg;

async function realOrParent(p: string, depth = 0): Promise<string> {
  try {
    return await realpath(p);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR") throw e;
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

const pathProp = { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } };
const reader = { readOnlyHint: true, openWorldHint: false };
const toolList = [
  // --no-read leaves only the listing tool: the near miss, where "no tool returns file contents" is true.
  ...(values["no-read"] ? [] : [{ name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object" as const, properties: pathProp, required: ["path"] }, annotations: reader }]),
  { name: "list_dir", description: "List the entries of a directory.", inputSchema: { type: "object" as const, properties: pathProp, required: ["path"] }, annotations: reader },
];

const server = new Server({ name: "sealmark-toy-fs-ctlfail", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  const input = typeof args.path === "string" ? args.path : "";
  try {
    // The resolved path, as a real server's error shows it: a long absolute path that a shortened copy of the message cuts through the middle of.
    if (req.params.name === "read_file") return fail(`ENOENT: no such file or directory, open '${resolve(rootArg, input)}'`);
    if (req.params.name === "list_dir") {
      if (!input) return fail("path must be a non-empty string");
      const real = await realOrParent(resolve(rootArg, input));
      if (!within(real, realRoot)) return fail(`Access denied: ${input} is outside the allowed directory`);
      const entries = await readdir(real, { withFileTypes: true });
      return ok(entries.map((e) => `${e.isDirectory() ? "[DIR]" : "[FILE]"} ${e.name}`).join("\n"));
    }
    return fail(`unknown tool ${req.params.name}`);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return fail(code ? `${code}: ${(e as Error).message}` : String((e as Error).message ?? e));
  }
});

try {
  realRoot = await realpath(rootArg);
} catch {
  /* the root may not exist yet when the harness only lists tools */
}
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
