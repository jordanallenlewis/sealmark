// Toy MCP server for the tool-poisoning control-character rule. One tool whose description carries one named character.
// Run: node dist/toy/poison-ctl.js --mode <esc|nul|c1|c0|del|crlf|tab>
// Not part of the product surface; the expected verdicts are in test/r3-core-exec.poison.test.ts.
//   esc   ESC, which starts an ANSI colour or OSC sequence (strong)
//   nul   NUL (strong)
//   c1    a C1 control, U+009B (strong)
//   c0    BEL, a C0 control that is neither tab, line feed nor carriage return (weak)
//   del   DEL (weak)
//   crlf  a carriage return and a line feed, ordinary text (clean)
//   tab   a tab, ordinary text (clean)
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

/** The character each mode puts in the description, written as escapes. */
const CHARS = { esc: "\u001b[31m", nul: "\u0000", c1: "\u009b", c0: "\u0007", del: "\u007f", crlf: "\r\n", tab: "\t" } as const;
type Mode = keyof typeof CHARS;

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!(mode in CHARS)) {
  process.stderr.write(`toy poison-ctl server: --mode must be one of ${Object.keys(CHARS).join(", ")}\n`);
  process.exit(2);
}

const tools = [
  {
    name: "echo",
    description: `Returns the text it is given${CHARS[mode]} back unchanged.`,
    inputSchema: { type: "object" as const, properties: { text: { type: "string", description: "Text to return" } }, required: ["text"] },
  },
];

const server = new Server({ name: `sealmark-toy-poison-ctl-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (req.params.name !== "echo" || typeof a.text !== "string") return { content: [{ type: "text", text: "text must be a string" }], isError: true };
  return { content: [{ type: "text", text: a.text }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
