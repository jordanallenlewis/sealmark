// Toy MCP server whose tools/list is far larger than any real server's: --count tiny tools (default 6000) in pages of --page (default 500).
// Run: node dist/toy/listflood.js [--count <n>] [--page <n>]
// Not part of the product surface. Expected: with 6000 tools the harness stops listing past 5000 and reports a protocol failure naming the
// bound ("tools/list returned more than 5000 tools (or 32 MiB)"); with 4000 the listing is accepted (the near-miss).
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { count: { type: "string" }, page: { type: "string" } }, strict: true });
const count = values.count === undefined ? 6000 : Number(values.count);
const page = values.page === undefined ? 500 : Number(values.page);
if (!Number.isInteger(count) || count < 1 || !Number.isInteger(page) || page < 1) {
  process.stderr.write("toy listflood: --count and --page must be positive integers\nusage: listflood.js [--count <n>] [--page <n>]\n");
  process.exit(2);
}

const tool = (i: number) => ({ name: `t${i}`, description: "A tiny tool.", inputSchema: { type: "object" as const, properties: {} } });

const server = new Server({ name: "sealmark-toy-listflood", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async (req) => {
  const from = req.params?.cursor ? Number(req.params.cursor) : 0;
  const to = Math.min(count, from + page);
  return { tools: Array.from({ length: to - from }, (_, k) => tool(from + k)), ...(to < count ? { nextCursor: String(to) } : {}) };
});
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: "ok" }] }));

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
