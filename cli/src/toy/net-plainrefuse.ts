// Toy MCP server for the refusal vocabulary of net-loopback-ssrf: one tool, fetch{url}, that guards its fetches by resolved
// address and says so in plain words, never using the words loopback, private, internal, blocked, forbidden, denied or restricted.
// Run: node dist/toy/net-plainrefuse.js --mode <refuse|rpc|cannot|nxdomain|hostguard>
// Not part of the product surface. Expected verdicts:
//   refuse   "refused to fetch <host>: it resolves to 127.0.0.1, which is not a public address" (isError); only http(s) is supported
//            ssrf pass  scheme pass                                      A
//   rpc      the same guard, answered as a JSON-RPC invalid-params error that only names the address ("address 127.0.0.1 is not accepted")
//            ssrf pass  scheme pass
//   hostguard refuses every URL whose host is not public, whatever its scheme, and cannot say anything about URLs without a host
//            (file:, data:, javascript: fail with "invalid URL"): its ftp/gopher/dict refusals are the host guard's, not a scheme
//            allowlist's, and the scheme check says so    ssrf pass  scheme inconclusive
//   cannot   every fetch fails with "connect ENETUNREACH <address>:80": a tool that cannot fetch, not one that refuses
//            ssrf inconclusive  scheme inconclusive  (never a pass)
//   nxdomain every fetch fails with "the host name resolves to no address (ENOTFOUND)": the word "resolves" alone is not a refusal
//            ssrf inconclusive  scheme inconclusive  (never a pass)
import net from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["refuse", "rpc", "cannot", "nxdomain", "hostguard"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

/** The address a host name stands for, for the spellings the harness sends (WHATWG parsing has already normalised 127.1, 0x7f000001 and 2130706433). */
function addressOf(hostRaw: string): string | undefined {
  const host = hostRaw.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return "127.0.0.1";
  return net.isIP(host) ? host : undefined;
}

/** Not routable on the public internet. */
function notPublic(ip: string): boolean {
  if (net.isIPv6(ip)) return ip === "::1" || ip === "::" || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip) || /^::ffff:/.test(ip);
  const [a, b] = ip.split(".").map(Number) as [number, number];
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
  const ip = addressOf(u.hostname);
  if (mode === "cannot") return fail(`fetch failed: connect ENETUNREACH ${ip ?? u.hostname}:80 - network is unreachable`);
  if (mode === "nxdomain") return fail("fetch failed: the host name resolves to no address (ENOTFOUND)");
  if (mode === "hostguard") {
    if (!ip) return fail("invalid URL");
    if (notPublic(ip)) return fail(`refused to fetch ${u.hostname}: it resolves to ${ip}, which is not a public address`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail("only http and https URLs are supported");
  if (ip && notPublic(ip)) {
    if (mode === "rpc") throw new McpError(ErrorCode.InvalidParams, `address ${ip} is not accepted`);
    return fail(`refused to fetch ${u.hostname}: it resolves to ${ip}, which is not a public address`);
  }
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-plainrefuse: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-plainrefuse-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
    if (e instanceof McpError) throw e;
    return fail(`fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
