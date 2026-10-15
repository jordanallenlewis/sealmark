// Toy MCP server for per-tool probe tokens in the net pack (round 5, G1): two URL tools. `fetch_page` fetches whatever it is given (no
// loopback guard); `lookup_page` never contacts anything and answers every call with a generic fetch failure.
// Run: node dist/toy/net-multitool.js
// Not part of the product surface. Expected: net-loopback-ssrf FAILS on fetch_page (the listener saw it), and lookup_page gets no
// net.ssrf-hit evidence line and no coverage credit: its calls are not valid calls (a failed fetch exercised nothing). Before round 5
// the pack made one token per corpus entry and gave every tool the same one, so the second tool inherited the first tool's listener hits.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const tools = ["fetch_page", "lookup_page"].map((name) => ({
  name,
  description: "Fetch a URL over HTTP and return the response body as text.",
  inputSchema: { type: "object", properties: { url: { type: "string", description: "The URL to fetch" } }, required: ["url"] },
}));

const server = new Server({ name: "sealmark-toy-net-multitool", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const url = (req.params.arguments ?? {}).url;
  if (typeof url !== "string" || !url) return fail("url must be a non-empty string");
  if (req.params.name === "lookup_page") return fail("fetch failed: ENETUNREACH");
  if (req.params.name !== "fetch_page") return fail(`unknown tool ${req.params.name}`);
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`unsupported scheme ${u.protocol}`);
    const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
    return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
  } catch (e) {
    return fail(`fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
