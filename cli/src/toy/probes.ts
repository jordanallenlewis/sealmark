// Toy MCP server for the custom-probe tests (probes.ts). Small tools that touch files and the network, with one known flaw per mode.
// Run: node dist/toy/probes.js --mode <good|traverse|open|leakenv>
// The server's working directory is its root (the harness starts it in the sandbox root).
//   good      every path is resolved against the root and refused outside it; fetch refuses every address
//   traverse  paths are used as given (resolve(root, p)), so an absolute path or `..` leaves the root
//   open      paths are confined, but fetch really requests any URL
//   leakenv   like good, and `echo` answers with the process environment, a leak only a valid call reaches
// Not part of the product surface.
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, isAbsolute } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["good", "traverse", "open", "leakenv"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy probes server: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const root = process.cwd();

/** Where a path argument points, or an error reply. */
function target(p: unknown): { abs: string } | { error: Reply } {
  if (typeof p !== "string" || !p) return { error: fail("path must be a non-empty string") };
  const abs = resolve(root, p);
  if (mode !== "traverse") {
    const rel = relative(root, abs);
    if (rel.startsWith("..") || isAbsolute(rel)) return { error: fail("path is outside the allowed root") };
  }
  return { abs };
}

const str = (description: string) => ({ type: "string", description });
const tools = [
  { name: "read_file", description: "Read a file and return its text.", inputSchema: { type: "object" as const, properties: { path: str("File to read") }, required: ["path"] } },
  {
    name: "write_file",
    description: "Write text to a file.",
    inputSchema: { type: "object" as const, properties: { path: str("File to write"), content: str("Text to write") }, required: ["path", "content"] },
  },
  { name: "delete_file", description: "Delete a file.", inputSchema: { type: "object" as const, properties: { path: str("File to delete") }, required: ["path"] } },
  { name: "fetch", description: "Fetch a web page over HTTP and return its body.", inputSchema: { type: "object" as const, properties: { url: str("Address to fetch") }, required: ["url"] } },
  { name: "echo", description: "Echo the text back.", inputSchema: { type: "object" as const, properties: { text: str("Text to echo") }, required: ["text"] } },
  {
    name: "nap",
    description: "Wait for a number of milliseconds.",
    inputSchema: { type: "object" as const, properties: { ms: { type: "number", description: "Milliseconds to wait" } }, required: ["ms"] },
  },
];

const server = new Server({ name: `sealmark-toy-probes-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  try {
    switch (req.params.name) {
      case "read_file": {
        const t = target(a.path);
        return "error" in t ? t.error : ok(readFileSync(t.abs, "utf8"));
      }
      case "write_file": {
        const t = target(a.path);
        if ("error" in t) return t.error;
        if (typeof a.content !== "string") return fail("content must be a string");
        mkdirSync(dirname(t.abs), { recursive: true });
        writeFileSync(t.abs, a.content);
        return ok("written");
      }
      case "delete_file": {
        const t = target(a.path);
        if ("error" in t) return t.error;
        rmSync(t.abs);
        return ok("deleted");
      }
      case "fetch": {
        if (typeof a.url !== "string") return fail("url must be a string");
        if (mode !== "open") return fail("network access is not allowed");
        const res = await fetch(a.url);
        return ok(`status ${res.status}: ${(await res.text()).slice(0, 200)}`);
      }
      case "echo":
        if (typeof a.text !== "string") return fail("text must be a string");
        return ok(mode === "leakenv" ? `echo ${a.text} env=${JSON.stringify(process.env)}` : `echo ${a.text}`);
      case "nap": {
        if (typeof a.ms !== "number") return fail("ms must be a number");
        await new Promise((r) => setTimeout(r, a.ms as number));
        return ok(`waited ${a.ms}`);
      }
      default:
        return fail(`unknown tool ${req.params.name}`);
    }
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
