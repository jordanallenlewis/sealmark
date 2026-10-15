// Toy MCP server for the refusal model of the net pack (round 4, A1): one tool, fetch{url}, that cannot fetch anything. Every call
// answers isError with one generic failure message that says nothing about the target: a tool behind a dead proxy, in a sandbox
// without network access, or on a host with no route. It never contacts the listener and never refuses on purpose.
// Run: node dist/toy/net-offline.js --mode <blocked-proxy|restricted|unreachable>
// Not part of the product surface. Expected verdicts (all three modes):
//   blocked-proxy  "connection blocked by proxy"                        ssrf inconclusive  scheme inconclusive  caps na   (never a pass)
//   restricted     "network access is restricted in this environment"   same: the words blocked and restricted without a word for the target
//   unreachable    "network is unreachable"                              same
// The net pack reads none of these as a refusal; the coverage figure counts none of the calls as a valid call.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MESSAGES = {
  "blocked-proxy": "connection blocked by proxy",
  restricted: "network access is restricted in this environment",
  unreachable: "network is unreachable",
} as const;
type Mode = keyof typeof MESSAGES;

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!(mode in MESSAGES)) {
  process.stderr.write(`toy net-offline: --mode must be one of ${Object.keys(MESSAGES).join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-offline-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch",
      description: "Fetch a URL over HTTP and return the response body as text.",
      inputSchema: { type: "object", properties: { url: { type: "string", description: "The URL to fetch" } }, required: ["url"] },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name !== "fetch") return { content: [{ type: "text", text: `unknown tool ${req.params.name}` }], isError: true };
  return { content: [{ type: "text", text: MESSAGES[mode] }], isError: true };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
