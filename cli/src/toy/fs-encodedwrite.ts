// Toy file-system MCP server for the encoded-write probes of fs-write-escape. Each mode checks a write path in one known way.
// Run: node dist/toy/fs-encodedwrite.js --mode <m> --root <dir> [--trace <file>]
// Not part of the product surface.
//
//   safe      realpath of the target (or of its nearest existing ancestor), then a separator-bounded prefix check. Nothing in the path is decoded.
//   urldec    a lexical check on the string as given (resolved, then inside the root), after which the path is percent-decoded and used:
//             "<root>/%2e%2e/canary/x" passes the check and lands in the canary directory
//   fileurl   a "file://" prefix is stripped and the rest is used unchecked; every other path gets the lexical check
//   dotslash  a hand-written segment walk that counts ".." against the depth but forgets the pair when it follows a "." segment:
//             "<root>/./../canary/x" passes the check and the operating system then resolves it out of the root
//
// Tools: write_file{path, content} and copy_file{source, destination} (the destination follows the mode; the source always gets the safe
// check), and read_file{path} (always the safe check). All annotated.
import { appendFileSync } from "node:fs";
import { copyFile, lstat, readFile, readlink, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const FS_ENCODEDWRITE_MODES = ["safe", "urldec", "fileurl", "dotslash"] as const;
type Mode = (typeof FS_ENCODEDWRITE_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

class Refused extends Error {}

function usage(msg: string): never {
  process.stderr.write(`toy fs-encodedwrite server: ${msg}\nusage: fs-encodedwrite.js --mode <${FS_ENCODEDWRITE_MODES.join("|")}> --root <dir> [--trace <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, root: { type: "string" }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!FS_ENCODEDWRITE_MODES.includes(mode)) usage(`--mode must be one of ${FS_ENCODEDWRITE_MODES.join(", ")}`);
if (!values.root) usage("--root is required");
const rootArg = resolve(values.root);

const WIN = process.platform === "win32";
const fold = (s: string) => (WIN ? s.toLowerCase() : s);
const within = (child: string, parent: string) => {
  const c = fold(child);
  const p = fold(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
};
const deny = (input: string) => new Refused(`Access denied: ${input} is outside the allowed directory`);

let realRoot = rootArg;

/** realpath of the path itself, or of its nearest existing ancestor plus the missing tail (a file about to be created). */
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

/** The one correct check: resolve links, then require the real path to be the root or inside it, on a separator boundary. */
async function safePath(input: string): Promise<string> {
  const real = await realOrParent(resolve(rootArg, input));
  if (!within(real, realRoot)) throw deny(input);
  return real;
}

/** The segment walk of `dotslash`: ".." lowers the depth, except right after a "." segment, where the pair is taken for a no-op. */
function walkAllows(input: string): boolean {
  const abs = isAbsolute(input) ? input : rootArg + sep + input;
  if (!fold(abs).startsWith(fold(rootArg + sep))) return false;
  const segments = abs.slice(rootArg.length).split(/[\\/]+/).filter((s) => s !== "");
  let depth = 0;
  let prev = "";
  for (const seg of segments) {
    if (seg === "..") {
      if (prev !== ".") depth--;
      if (depth < 0) return false;
    } else if (seg !== ".") depth++;
    prev = seg;
  }
  return true;
}

/** The path the write may use for `input`, or a Refused. */
async function writablePath(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  switch (mode) {
    case "urldec": {
      // The check sees the encoded string, where "%2e%2e" is an ordinary directory name; the decoded path is what is written.
      if (!within(resolve(rootArg, input), rootArg)) throw deny(input);
      return resolve(rootArg, decodeURIComponent(input));
    }
    case "fileurl": {
      if (/^file:\/\//i.test(input)) return input.replace(/^file:\/\//i, "");
      if (!within(resolve(rootArg, input), rootArg)) throw deny(input);
      return resolve(rootArg, input);
    }
    case "dotslash": {
      if (!walkAllows(input)) throw deny(input);
      return resolve(rootArg, input);
    }
    default:
      return safePath(input);
  }
}

async function handle(name: string, args: Record<string, unknown>): Promise<Reply> {
  switch (name) {
    case "write_file": {
      const p = await writablePath(args.path);
      if (typeof args.content !== "string") return fail("content must be a string");
      await writeFile(p, args.content);
      return ok(`Wrote ${Buffer.byteLength(args.content)} bytes`);
    }
    case "copy_file": {
      const dest = await writablePath(args.destination);
      await copyFile(await safePath(String(args.source ?? "")), dest);
      return ok(`Copied ${String(args.source)} to ${String(args.destination)}`);
    }
    case "read_file": {
      if (typeof args.path !== "string" || !args.path) return fail("path must be a non-empty string");
      return ok(await readFile(await safePath(args.path), "utf8"));
    }
    default:
      return fail(`unknown tool ${name}`);
  }
}

const pathProp = { path: { type: "string", description: "Absolute path, or a path relative to the allowed directory" } };
const toolList = [
  { name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object" as const, properties: pathProp, required: ["path"] }, annotations: { readOnlyHint: true, openWorldHint: false } },
  {
    name: "write_file",
    description: "Create a new file or overwrite an existing file with the given content.",
    inputSchema: { type: "object" as const, properties: { ...pathProp, content: { type: "string", description: "Text to write" } }, required: ["path", "content"] },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "copy_file",
    description: "Copy a file.",
    inputSchema: { type: "object" as const, properties: { source: { type: "string", description: "File to take" }, destination: { type: "string", description: "Where it goes" } }, required: ["source", "destination"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
];

const server = new Server({ name: `sealmark-toy-fs-encodedwrite-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    return await handle(req.params.name, args);
  } catch (e) {
    if (e instanceof Refused) return fail(e.message);
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
