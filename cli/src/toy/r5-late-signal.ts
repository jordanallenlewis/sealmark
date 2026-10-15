// Toy MCP server for the interrupt tests.
// Run: node dist/toy/r5-late-signal.js [--signal-parent-on-close]
//   --signal-parent-on-close  when the client closes the session (its stdin ends), send SIGINT to the parent process: a signal that lands as the
//                             last pack finishes, after every check ran and before the report is printed.
// Tools: echo(text) answers "echo: <text>".
// Not part of the product surface; the expected behaviour is in test/r5-harness.interrupt.test.ts.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { "signal-parent-on-close": { type: "boolean" } }, strict: true });

const tools = [{ name: "echo", description: "Echo the text back.", inputSchema: { type: "object" as const, properties: { text: { type: "string", description: "Text to echo" } }, required: ["text"] } }];

const server = new Server({ name: "sealmark-toy-late-signal", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  return { content: [{ type: "text", text: `echo: ${String(a.text ?? "")}` }] };
});

for (const ev of ["end", "close"] as const) {
  process.stdin.once(ev, () => {
    if (values["signal-parent-on-close"]) {
      try {
        process.kill(process.ppid, "SIGINT");
      } catch {
        /* the parent is gone */
      }
    }
    process.exit(0);
  });
}
await server.connect(new StdioServerTransport());
