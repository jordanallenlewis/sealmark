// Toy MCP server for the refusal model of the net pack (round 4, A1): one tool, fetch{url}, that refuses every loopback spelling
// on purpose, in a wording the old vocabulary did not recognise. It never contacts the listener. Only http(s) is accepted.
// Run: node dist/toy/net-reserved.js --mode <reserved|unsafe|nonroutable|notroutable|isError-32602|rpc-32602>
// Not part of the product surface. Expected verdicts (every mode): ssrf pass (the listener saw nothing), scheme pass.
//   reserved       isError "Request rejected: target is a reserved address"
//   unsafe         isError "Unsafe destination"
//   nonroutable    isError "URL points to a non-routable network"
//   notroutable    isError "The requested host is not routable"
//   isError-32602  isError "Bad request for <address>": a validation error that names the address, with no JSON-RPC error (the Python SDK's form)
//   rpc-32602      a JSON-RPC invalid-params error (-32602) that names the address
import net from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["reserved", "unsafe", "nonroutable", "notroutable", "isError-32602", "rpc-32602"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

/** True for the addresses a server-side fetch must not reach (WHATWG parsing has already normalised 127.1, 0x7f000001 and 2130706433). */
function internal(hostRaw: string): boolean {
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
    return fail("could not parse the URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail("only http and https URLs are supported");
  if (internal(u.hostname)) {
    switch (mode) {
      case "reserved":
        return fail("Request rejected: target is a reserved address");
      case "unsafe":
        return fail("Unsafe destination");
      case "nonroutable":
        return fail("URL points to a non-routable network");
      case "notroutable":
        return fail("The requested host is not routable");
      case "isError-32602":
        return fail(`Bad request for ${u.hostname}`);
      case "rpc-32602":
        throw new McpError(ErrorCode.InvalidParams, `Invalid params: ${u.hostname} is not an accepted address`);
    }
  }
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-reserved: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-reserved-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
