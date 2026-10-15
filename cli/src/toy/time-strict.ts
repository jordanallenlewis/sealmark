// Toy MCP server for the harness's coverage rule. One tool, `get_time`, takes a `timezone` string.
// Run: node dist/toy/time-strict.js --mode <strict|lenient>
//   strict   accepts an IANA-style zone name (UTC, Europe/Berlin) and answers every other value with a validation error
//            ("invalid timezone ...: expected ..."), so a config that tells the harness this is a URL tool gets nothing but
//            validation errors back: no call reached the tool's behaviour
//   lenient  accepts any string and answers normally: the near-miss, whose calls DO exercise the tool even when it is treated as a URL tool
// Not part of the product surface; the expected coverage is in test/r4-harness.coverage.test.ts.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode;
if (mode !== "strict" && mode !== "lenient") {
  process.stderr.write("toy time-strict server: --mode must be strict or lenient\n");
  process.exit(2);
}

const tools = [
  {
    name: "get_time",
    description: "Reports the current time in a time zone.",
    inputSchema: { type: "object" as const, properties: { timezone: { type: "string", description: "A time zone name such as Europe/Berlin." } }, required: ["timezone"] },
    annotations: { readOnlyHint: true },
  },
];

const ZONE = /^[A-Za-z_]+(\/[A-Za-z_]+)*$/;
const server = new Server({ name: `sealmark-toy-time-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tz = String((req.params.arguments as Record<string, unknown> | undefined)?.timezone ?? "");
  if (mode === "strict" && !ZONE.test(tz)) return { content: [{ type: "text", text: `invalid timezone: expected an IANA zone name such as Europe/Berlin` }], isError: true };
  return { content: [{ type: "text", text: `time in ${tz.slice(0, 40)}: 12:00` }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
