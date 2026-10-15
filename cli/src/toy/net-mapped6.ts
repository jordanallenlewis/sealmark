// Toy MCP server for the IPv4-mapped IPv6 spelling (round 4, A2): one tool, fetch{url}, that parses the URL with the WHATWG parser
// (which turns 127.1, 0x7f000001 and 2130706433 into 127.0.0.1) and then denies four literals: 127.0.0.1, localhost, [::1] and 0.0.0.0.
// It never looks at http://[::ffff:127.0.0.1]:PORT/, which its HTTP client connects to the same IPv4 loopback address.
// Run: node dist/toy/net-mapped6.js --mode <denylist|strict>
// Not part of the product surface. Expected verdicts:
//   denylist  fetches the IPv4-mapped spelling   ssrf FAIL (the probe ipv4-mapped reached the listener: "1 of N probes")   scheme pass
//   strict    also rejects every IPv4-mapped IPv6 host, so nothing reaches the listener   ssrf pass   scheme pass
// The near miss (strict) is the same tool with one more rule.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["denylist", "strict"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const DENIED = new Set(["127.0.0.1", "localhost", "[::1]", "0.0.0.0"]);

async function fetchTool(mode: Mode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
  if (DENIED.has(u.hostname.toLowerCase())) return fail(`blocked: ${u.hostname} is a loopback address (not allowed)`);
  if (mode === "strict" && /^\[::ffff:/i.test(u.hostname)) return fail(`blocked: ${u.hostname} is an IPv4-mapped loopback address (not allowed)`);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-mapped6: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-mapped6-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch",
      description: "Fetch a URL over HTTP and return the response body as text.",
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
