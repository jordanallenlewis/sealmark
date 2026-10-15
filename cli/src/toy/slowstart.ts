// Toy MCP server that is slow to start, or never starts, used to test cleanup when a server does not answer `initialize`.
// Run: node dist/toy/slowstart.js --mode <m> [--delay-ms <n>] [--pid-file <file>]
// Not part of the product surface. Every mode appends its own process id (one line) to --pid-file so a test can check
// afterwards that nothing is left running.
//
//   slow      waits --delay-ms (default 30000), then behaves as a normal one-tool server
//   never     starts, reads stdin and never answers; closing stdin does not stop it (a server stuck in its own startup)
//   stubborn  never, and also ignores SIGTERM, so only SIGKILL stops it
//   wrapper   never, and starts a `never` child first (what an npx or uvx launcher does): the whole tree must go
import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const SLOWSTART_MODES = ["slow", "never", "stubborn", "wrapper"] as const;
type Mode = (typeof SLOWSTART_MODES)[number];

function usage(msg: string): never {
  process.stderr.write(`toy slowstart server: ${msg}\nusage: slowstart.js --mode <${SLOWSTART_MODES.join("|")}> [--delay-ms <n>] [--pid-file <file>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, "delay-ms": { type: "string" }, "pid-file": { type: "string" } }, strict: true });
const mode = values.mode as Mode | undefined;
if (!mode || !(SLOWSTART_MODES as readonly string[]).includes(mode)) usage(`--mode must be one of ${SLOWSTART_MODES.join(", ")}`);
const delayMs = values["delay-ms"] === undefined ? 30_000 : Number(values["delay-ms"]);
if (!Number.isFinite(delayMs) || delayMs < 0) usage("--delay-ms must be a non-negative number");
const pidFile = values["pid-file"];
if (pidFile) appendFileSync(pidFile, `${process.pid}\n`);

/** Alive for ever, answers nothing, and does not notice stdin closing. */
function neverAnswer(): void {
  process.stdin.on("data", () => {});
  process.stdin.on("end", () => {});
  setInterval(() => {}, 1000);
}

if (mode === "slow") {
  await new Promise<void>((r) => setTimeout(r, delayMs));
  const server = new Server({ name: "sealmark-toy-slowstart", version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "echo", description: "Return the given text unchanged.", inputSchema: { type: "object", properties: { text: { type: "string", description: "Text to return" } }, required: ["text"] } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const text = (req.params.arguments as { text?: unknown } | undefined)?.text;
    return typeof text === "string" ? { content: [{ type: "text", text }] } : { content: [{ type: "text", text: "text must be a string" }], isError: true };
  });
  await server.connect(new StdioServerTransport());
} else {
  if (mode === "stubborn") process.on("SIGTERM", () => {});
  if (mode === "wrapper") {
    const args = [fileURLToPath(import.meta.url), "--mode", "never", ...(pidFile ? ["--pid-file", pidFile] : [])];
    // Same process group and no stdio, like a launcher's child: it outlives the wrapper unless something reaps the tree.
    spawn(process.execPath, args, { stdio: "ignore" }).unref();
  }
  neverAnswer();
}
