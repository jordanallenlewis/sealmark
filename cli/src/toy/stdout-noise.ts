// Toy MCP server that logs, and one that answers with a result that is not valid MCP. One tool.
// Run: node dist/toy/stdout-noise.js --mode <stdout|stderr|json|invalid>
// Not part of the product surface; the expected verdicts are in test/r5-core.stdout.test.ts.
//   stdout   a banner at start and a line per call go to stdout, which is the JSON-RPC channel (protocol: part)
//   stderr   the same lines go to stderr, where logs belong (near miss: protocol passes)
//   json     a line of valid JSON that is not a JSON-RPC message goes to stdout (protocol: part)
//   invalid  nothing is logged, but every tools/call reply has `content` as a string instead of an array: not valid MCP (protocol: part).
//            The SDK server refuses to send such a reply, so this mode speaks the protocol by hand.
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode;
if (mode !== "stdout" && mode !== "stderr" && mode !== "json" && mode !== "invalid") {
  process.stderr.write("toy stdout-noise: --mode must be stdout, stderr, json or invalid\n");
  process.exit(2);
}

const tools = [{ name: "echo", description: "Returns the text it is given, unchanged.", inputSchema: { type: "object" as const, properties: { text: { type: "string", description: "Text to return" } }, required: ["text"] } }];
const info = { name: `sealmark-toy-stdout-noise-${mode}`, version: "0.0.1" };

if (mode === "invalid") {
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    const m = JSON.parse(line) as { id?: number; method?: string; params?: { protocolVersion?: string } };
    if (m.id === undefined) return; // a notification
    const send = (result: unknown): void => void process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: m.id, result })}\n`);
    if (m.method === "initialize") send({ protocolVersion: m.params?.protocolVersion, capabilities: { tools: {} }, serverInfo: info });
    else if (m.method === "tools/list") send({ tools });
    else if (m.method === "tools/call") send({ content: "text must be a string", isError: true });
    else process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } })}\n`);
  });
  rl.on("close", () => process.exit(0));
} else {
  const log = (line: string): void => {
    const text = mode === "json" ? `${JSON.stringify({ level: "info", msg: line })}\n` : `${line}\n`;
    (mode === "stderr" ? process.stderr : process.stdout).write(text);
  };
  log("noisy-server 1.0 starting up");
  const server = new Server(info, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const a = (req.params.arguments ?? {}) as Record<string, unknown>;
    log(`handling call to ${req.params.name}`);
    if (req.params.name !== "echo" || typeof a.text !== "string") return { content: [{ type: "text", text: "text must be a string" }], isError: true };
    return { content: [{ type: "text", text: a.text }] };
  });
  for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
  await server.connect(new StdioServerTransport());
}
