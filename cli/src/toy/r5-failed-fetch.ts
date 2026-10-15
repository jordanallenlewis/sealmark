// Toy MCP server for the coverage-counting tests.
// Run: node dist/toy/r5-failed-fetch.js --mode <failed|plain-error|ok>
//   failed       search(query) answers "Error searching <q>: TypeError: fetch failed" WITHOUT isError: the upstream request failed and the tool
//                said so in plain text, which a client cannot tell from success. It must not count as a call that exercised the tool.
//   plain-error  search(query) answers with isError and "not found": an ordinary rejection (counts as nothing either)
//   ok           search(query) answers "Found 3 results for <q>": the near-miss, which must still count
// echo(text) answers "echo: <text>" in every mode.
// Not part of the product surface; the expected behaviour is in test/r5-harness.coverage.test.ts.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["failed", "plain-error", "ok"] as const;
const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as (typeof MODES)[number];
if (!MODES.includes(mode)) {
  process.stderr.write(`toy r5-failed-fetch: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const str = (description: string) => ({ type: "string", description });
const tools = [
  { name: "search", description: "Search the index for a phrase and list what was found.", inputSchema: { type: "object" as const, properties: { query: str("Phrase to search for") }, required: ["query"] } },
  { name: "echo", description: "Echo the text back.", inputSchema: { type: "object" as const, properties: { text: str("Text to echo") }, required: ["text"] } },
];

const server = new Server({ name: `sealmark-toy-r5-failed-fetch-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (req.params.name === "echo") return { content: [{ type: "text", text: `echo: ${String(a.text ?? "")}` }] };
  const q = String(a.query ?? "");
  if (mode === "failed") return { content: [{ type: "text", text: `Error searching "${q}": TypeError: fetch failed` }] };
  if (mode === "plain-error") return { content: [{ type: "text", text: `no entry named ${q}: not found` }], isError: true };
  return { content: [{ type: "text", text: `Found 3 results for ${q}` }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
