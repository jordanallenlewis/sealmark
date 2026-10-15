// Toy MCP server for the robust-input valid-call count. One tool, `status`, takes no arguments and declares readOnlyHint: true.
// Run: node dist/toy/noarg-error.js --mode <error|ok>
// Not part of the product surface; the expected coverage is in test/r3-core-exec.noarg.test.ts.
//   error  `status` always answers isError, so the harness's no-argument call exercised nothing
//   ok     `status` answers normally, so the same call is a valid call
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode;
if (mode !== "error" && mode !== "ok") {
  process.stderr.write("toy noarg-error server: --mode must be error or ok\n");
  process.exit(2);
}

const tools = [
  {
    name: "status",
    description: "Reports whether the service is up.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true },
  },
];

const server = new Server({ name: `sealmark-toy-noarg-error-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async () =>
  mode === "error" ? { content: [{ type: "text", text: "service unavailable" }], isError: true } : { content: [{ type: "text", text: "up" }] },
);

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
