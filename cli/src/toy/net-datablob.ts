// Toy MCP server for net-scheme-allowlist: one tool, fetch{url}, that refuses loopback and every non-web scheme except data:, and
// answers a data: URL with a NON-TEXT content block, so the token the harness put in the URL can only be seen by reading the block.
// Run: node dist/toy/net-datablob.js --mode <resource|image|echo|strict>
// Not part of the product surface. Expected verdicts (net-loopback-ssrf passes in every mode):
//   resource  the decoded content as an embedded resource with a base64 blob   scheme part: "decoded the data: URL and returned its content as a resource block"
//   image     the decoded content as an image block (a toy does not care that it is not a picture)   scheme part: "... as an image block"
//   echo      a resource blob that holds the raw data: URL text, NOT decoded (the near-miss): the token the harness is looking for is
//             not in it once the URL itself is set aside   scheme inconclusive (no positive evidence, never a false "decoded")
//   strict    data: refused like every other scheme   scheme pass
import net from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["resource", "image", "echo", "strict"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: ({ type: "text"; text: string } | { type: "resource"; resource: { uri: string; mimeType: string; blob: string } } | { type: "image"; data: string; mimeType: string })[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

/** True for the addresses a server-side fetch must not reach (WHATWG parsing has already normalised 127.1, 0x7f000001 and 2130706433). */
function notPublic(hostRaw: string): boolean {
  const host = hostRaw.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (net.isIPv6(host)) return host === "::1" || host === "::" || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || /^::ffff:/.test(host);
  if (!net.isIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

async function fetchTool(mode: Mode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  if (u.protocol === "data:" && mode !== "strict") {
    const decoded = decodeURIComponent(u.pathname.replace(/^[^,]*,/, ""));
    if (mode === "echo") return { content: [{ type: "resource", resource: { uri: "echo://data-url", mimeType: "text/plain", blob: Buffer.from(urlArg).toString("base64") } }] };
    if (mode === "image") return { content: [{ type: "image", data: Buffer.from(decoded).toString("base64"), mimeType: "image/png" }] };
    return { content: [{ type: "resource", resource: { uri: "decoded://data-url", mimeType: "text/plain", blob: Buffer.from(decoded).toString("base64") } }] };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
  if (notPublic(u.hostname)) return fail(`blocked: ${u.hostname} is a loopback or internal address (not allowed)`);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-datablob: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-datablob-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fetch",
      description: "Fetch a URL over HTTP and return the response body.",
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
