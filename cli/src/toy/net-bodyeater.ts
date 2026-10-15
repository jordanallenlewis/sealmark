// Toy MCP server for net-caps: one tool, fetch{url}, that fetches anything (loopback included, so net-caps can measure it) and
// differs only in what it does with the response BODY.
// Run: node dist/toy/net-bodyeater.js --mode <eat|cap>
// Not part of the product surface. Expected verdicts:
//   eat   reads the whole body (64 MiB from the listener) and then returns only its first KiB: the reply is tiny, but the server
//         consumed everything                                          ssrf fail  scheme pass  caps: size part (by bytes consumed)
//   cap   stops reading after 1 MiB and hangs up (a genuine read cap)   ssrf fail  scheme pass  caps: size pass
// Both give up on a response that never ends after 5 s, so the time half of net-caps passes and only the size half differs.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["eat", "cap"] as const;
type Mode = (typeof MODES)[number];

const READ_CAP = 1024 * 1024;
const REPLY_CHARS = 1000;

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

async function fetchTool(mode: Mode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`unsupported scheme ${u.protocol} (only http and https)`);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  const reader = res.body?.getReader();
  let head = "";
  let read = 0;
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    if (head.length < REPLY_CHARS) head += Buffer.from(value).toString("utf8").slice(0, REPLY_CHARS - head.length);
    read += value.length;
    if (mode === "cap" && read >= READ_CAP) {
      await reader.cancel().catch(() => {});
      return ok(`HTTP ${res.status}\n${head}\n[stopped reading at ${READ_CAP} bytes]`);
    }
  }
  return ok(`HTTP ${res.status}\n${head}\n[body truncated to ${REPLY_CHARS} characters]`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-bodyeater: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-bodyeater-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch",
      description: "Fetch a URL over HTTP and return the start of the response body as text.",
      inputSchema: { type: "object", properties: { url: { type: "string", description: "The URL to fetch" } }, required: ["url"] },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name !== "fetch") return fail(`unknown tool ${req.params.name}`);
  try {
    return await fetchTool(mode, (req.params.arguments ?? {}).url);
  } catch (e) {
    return fail(`fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
