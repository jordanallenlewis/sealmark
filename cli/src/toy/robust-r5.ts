// Toy MCP server for the robust-input honesty rules. Two tools; each mode breaks exactly one of them, and `strict` breaks neither.
// Run: node dist/toy/robust-r5.js --mode <downstream|typeerror|nested|strict>
// Not part of the product surface; the expected verdicts are in test/r5-core.robust.test.ts.
//   downstream   fetch_page accepts any argument, tries to connect to a dead local port and returns the connect error as an isError reply
//                (an error, but only because the upstream request failed after the server used the invalid argument)
//   typeerror    fetch_page runs string code on whatever it is given and returns the unhandled TypeError text as an isError reply
//   nested       add_entries rejects a missing or non-array `entries`, but accepts a string in its place and items that lack a required field
//   strict       near miss: both tools validate every argument and name the one that is wrong
import { connect } from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["downstream", "typeerror", "nested", "strict"] as const;
type Mode = (typeof MODES)[number];
const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy robust-r5: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const tools = [
  {
    name: "fetch_page",
    description: "Fetches a web page and returns its length.",
    inputSchema: { type: "object" as const, properties: { url: { type: "string", description: "Address of the page" } }, required: ["url"] },
  },
  {
    name: "add_entries",
    description: "Stores a list of entries, each with a name and a kind.",
    inputSchema: {
      type: "object" as const,
      properties: { entries: { type: "array", description: "Entries to store", items: { type: "object", properties: { name: { type: "string" }, kind: { type: "string" } }, required: ["name", "kind"] } } },
      required: ["entries"],
    },
  },
];

const err = (text: string) => ({ content: [{ type: "text" as const, text }], isError: true });
const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });

/** A real connection attempt to a port nothing listens on: the failure text is what a failed upstream request says. */
const connectToDeadPort = (): Promise<string> =>
  new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port: 1 });
    s.once("error", (e: NodeJS.ErrnoException) => resolve(`fetch failed: connect ${e.code} 127.0.0.1:1`));
    s.once("connect", () => {
      s.destroy();
      resolve("connected");
    });
  });

function fetchPage(a: Record<string, unknown>) {
  if (mode === "downstream") return connectToDeadPort().then((text) => err(text));
  if (mode === "typeerror") {
    try {
      // The argument is assumed to be a string: any other shape throws, and the handler reports the exception text.
      const host = (a.url as string).split("/")[2];
      return ok(`fetched ${host}`);
    } catch (e) {
      return err(String(e));
    }
  }
  const extra = Object.keys(a).filter((k) => k !== "url");
  if (extra.length) return err(`unexpected argument ${extra[0]}`);
  if (typeof a.url !== "string") return err("url must be a string");
  return ok("fetched");
}

function addEntries(a: Record<string, unknown>) {
  const extra = Object.keys(a).filter((k) => k !== "entries");
  if (extra.length) return err(`unexpected argument ${extra[0]}`);
  if (!("entries" in a)) return err("entries is required");
  const entries = a.entries;
  if (mode === "nested") {
    // Checks the top level only: numbers, booleans, null and objects are refused, a string or an array is stored as it comes.
    if (typeof entries === "string" || Array.isArray(entries)) return ok(`stored ${Array.isArray(entries) ? entries.length : 1} entries`);
    return err("entries must be an array");
  }
  if (!Array.isArray(entries)) return err("entries must be an array");
  for (const [i, e] of entries.entries()) {
    const item = e as Record<string, unknown> | null;
    if (!item || typeof item !== "object") return err(`entries[${i}] must be an object`);
    for (const f of ["name", "kind"]) if (typeof item[f] !== "string") return err(`entries[${i}].${f} must be a string`);
  }
  return ok(`stored ${entries.length} entries`);
}

const server = new Server({ name: `sealmark-toy-robust-r5-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (req.params.name === "fetch_page") return fetchPage(a);
  if (req.params.name === "add_entries") return addEntries(a);
  return err(`unknown tool ${req.params.name}`);
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
