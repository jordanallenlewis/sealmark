// Toy stdio MCP server for the round 6 core advisory `instructions-hygiene`. Two clean tools; only the
// `instructions` string from initialize differs between modes.
// Run: node dist/toy/poison-r6.js --mode <clean|unknown-tool|deny-hit|none>
// Not part of the product surface. Expected instructions-hygiene verdicts (the deny pattern is `you are a helpful assistant`):
//   clean         "Use `list_tables` first; `query` accepts a single SELECT."                         pass
//   unknown-tool  the same, plus "export the result with `export_csv`" (no such tool)                  fail (clause 1)
//   deny-hit      "You are a helpful assistant for ACME Corp. Use `list_tables` first."                fail (clause 2, with the deny pattern)
//   none          no instructions at all                                                                n/a
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const POISON_R6_MODES = ["clean", "unknown-tool", "deny-hit", "none"] as const;
type Mode = (typeof POISON_R6_MODES)[number];

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!POISON_R6_MODES.includes(mode)) {
  process.stderr.write(`toy poison-r6: --mode must be one of ${POISON_R6_MODES.join(", ")}\n`);
  process.exit(2);
}

const instructions: string | undefined = {
  clean: "Use `list_tables` first; `query` accepts a single SELECT.",
  "unknown-tool": "Use `list_tables` first; `query` accepts a single SELECT. Export the result with `export_csv` when it is long.",
  "deny-hit": "You are a helpful assistant for ACME Corp. Use `list_tables` first; `query` accepts a single SELECT.",
  none: undefined,
}[mode];

const tools = [
  { name: "list_tables", description: "Lists the tables the server may serve.", inputSchema: { type: "object" as const, properties: {} } },
  { name: "query", description: "Runs one read-only SELECT statement.", inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "A single SELECT statement" } }, required: ["sql"] } },
];

const server = new Server({ name: `sealmark-toy-poison-r6-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} }, ...(instructions ? { instructions } : {}) });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "list_tables") return { content: [{ type: "text" as const, text: "sales.public.orders" }] };
  return { content: [{ type: "text" as const, text: "0 rows" }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
