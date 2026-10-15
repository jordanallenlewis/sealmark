// Toy MCP server that cannot start without a connection string, for the harness.
// Run: node dist/toy/dsn-required.js --dsn <dsn> [--pid-file <file>] [--signal-parent-on-start <n>] [--version <v>]
//   --dsn                      required and non-empty: an empty value (a {dsn} placeholder that expanded to nothing) exits 2 before the handshake
//   --pid-file                 appends this process's pid on every start, so a test can count starts from a file outside the sandbox
//   --signal-parent-on-start n  when this is the n-th start recorded in the pid file, sends SIGINT to its parent 100 ms after it answers
//                              the handshake, and never answers a tool call: a signal that lands while a pack is certainly waiting on this server
//   --version                  the version this server announces (default 0.0.1)
// Tools: run_sql(sql) answers "ok" and never touches a database; echo(text) answers "echo: <text>".
// Not part of the product surface; the expected behaviour is in test/r4-harness.*.test.ts.
import { appendFileSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({
  options: { dsn: { type: "string" }, "pid-file": { type: "string" }, "signal-parent-on-start": { type: "string" }, version: { type: "string" } },
  strict: true,
});

if (!values.dsn) {
  process.stderr.write("toy dsn-required: --dsn is empty, so there is nothing to connect to\n");
  process.exit(2);
}

let startNumber = 1;
if (values["pid-file"]) {
  // Append first, then find our own line: two servers that start together get two different numbers.
  appendFileSync(values["pid-file"], `${process.pid}\n`);
  startNumber = readFileSync(values["pid-file"], "utf8").split("\n").filter(Boolean).indexOf(String(process.pid)) + 1;
}

const tools = [
  { name: "run_sql", description: "Run a read-only SQL query.", inputSchema: { type: "object" as const, properties: { sql: { type: "string" } }, required: ["sql"] } },
  { name: "echo", description: "Repeat a note back.", inputSchema: { type: "object" as const, properties: { text: { type: "string" } }, required: ["text"] } },
];

// The start that signals its parent never answers a tool call, so the pack that called it is certainly still working when the signal lands.
const interrupter = values["signal-parent-on-start"] !== undefined && Number(values["signal-parent-on-start"]) === startNumber;
const server = new Server({ name: "sealmark-toy-dsn-required", version: values.version ?? "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (interrupter) await new Promise(() => {});
  if (req.params.name === "run_sql") return { content: [{ type: "text", text: "ok" }] };
  return { content: [{ type: "text", text: `echo: ${String(a.text ?? "")}` }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());

if (interrupter) {
  setTimeout(() => process.kill(process.ppid, "SIGINT"), 100);
}
