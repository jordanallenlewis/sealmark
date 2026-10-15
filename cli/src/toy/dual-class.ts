// Toy MCP server whose one tool looks like two kinds of tool at once.
// Run: node dist/toy/dual-class.js
// `download` takes a `url` and a `path`: the classifier makes it a path tool (primary) and keeps url as a secondary class. A run with no
// pack that consumes the secondary class must say so in "Not covered" instead of leaving the gap to be found in the JSON.
// Not part of the product surface; the expected text is in test/r4-harness.report-fields.test.ts.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const tools = [
  {
    name: "download",
    description: "Download a file from a URL and save it at a path.",
    inputSchema: { type: "object" as const, properties: { url: { type: "string" }, path: { type: "string" } }, required: ["url", "path"] },
  },
];

const server = new Server({ name: "sealmark-toy-dual-class", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: "saved" }] }));

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
