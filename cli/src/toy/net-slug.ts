// Toy MCP server for the data: probe of net-scheme-allowlist (round 5, G1): one tool, fetch_page{url}, that slugifies its argument into a
// search slug and reports what it searched for. The probe token therefore appears inside a percent-encoded run of the reply, which is
// an echo, not a decoded data: URL. Run: node dist/toy/net-slug.js --mode <slug|decode>
// Not part of the product surface. Expected verdicts:
//   slug    refuses loopback and file:, ftp:, gopher:, dict: with a scheme sentence; for data: answers "searched for <percent-encoded path of the URL>"
//           ssrf pass  scheme pass (the echo inside the URL is not a decode: never net.scheme-data)
//   decode  the same, but data: URLs are decoded and their content is returned in plain text        scheme part (net.scheme-data)
// The pair makes the rule testable from both sides: the same token is in the reply, and only the position differs.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["slug", "decode"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

function searchTool(mode: Mode, urlArg: unknown): Reply {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  if (u.protocol === "data:") {
    if (mode === "decode") return ok(decodeURIComponent(u.pathname.replace(/^[^,]*,/, "")));
    // The path of the data: URL, percent-encoded into a slug: the token sits inside "text%2Fplain%2Csm-<hex>", an echo, not content.
    return ok(`searched for ${encodeURIComponent(u.pathname)} (page 1)`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail("only http and https URLs are supported");
  return fail("only public hosts may be fetched");
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-slug: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-slug-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch_page",
      description: "Fetch a URL over HTTP and return the page text.",
      inputSchema: { type: "object", properties: { url: { type: "string", description: "The URL to fetch" } }, required: ["url"] },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name !== "fetch_page") return fail(`unknown tool ${req.params.name}`);
  return searchTool(mode, (req.params.arguments ?? {}).url);
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
