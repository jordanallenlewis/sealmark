// Toy MCP server for the refusal model of net-loopback-ssrf (round 5, G1): one tool, fetch{url}, that never contacts the listener. The
// defect modes fetch nothing and say something that sounds like a refusal; the near misses are guards that really refuse an internal
// address in plain words. Run: node dist/toy/net-refusal.js --mode <mode>
// Not part of the product surface. Expected verdicts:
//   transport-refused  "Failed to fetch <url>: the sandbox refused to connect" for every URL      ssrf inconclusive  scheme inconclusive
//   class-failure      "Failed to connect to loopback interface: ECONNREFUSED" for every URL      ssrf inconclusive  scheme inconclusive
//   echo-host          "Request for <parsed host> failed: access restricted" for every URL        ssrf inconclusive  scheme inconclusive
//   refuse-all         "refused: <url> is a loopback address and is not allowed" for every URL,
//                      data: included (one sentence for everything)                               ssrf inconclusive (twin: same text)  scheme inconclusive
//   refuse-all-host    "request to this host was rejected" for every URL                          ssrf inconclusive (twin: same text)  scheme inconclusive
//   refuse-all-rule    "only allowed domains may be fetched" for every URL                        ssrf inconclusive (twin: same text)
//   refuse-all-echo    "refused: <parsed host> is not allowed" for every URL (the host echoed)    ssrf inconclusive (twin: same text once the host is removed)
//   refuse-all-class   "refused: private address ranges are not allowed" for every URL           ssrf inconclusive (twin: same text)
// Near misses (a guard that checks the address; a hostless URL gets a different reply). Every one must pass the loopback check:
//   guard-public       loopback: "Only public hosts may be fetched."; other schemes: "unsupported scheme"                    ssrf pass  scheme pass
//   guard-rule-failure loopback: "Failed to fetch <url>: <host> resolves to a non-public address"; other schemes: "only http and https are supported"   ssrf pass  scheme pass
//   guard-cannot-access loopback: "This tool cannot access <host>."; a URL with no host: "URL must have a host"             ssrf pass  scheme inconclusive
//                      (the host guard fires first for ftp:, gopher: and dict:, which says nothing about the scheme)
//   guard-validation   loopback: "Request to a private address failed validation"; other schemes: "invalid URL scheme"       ssrf pass  scheme pass
// The text of the near misses is the vocabulary of the refusal model; the point of the pairs is that the same words, said by a tool
// that says them for every URL, are not evidence, and said by a tool that says something else for a hostless URL, are.
import net from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const NET_REFUSAL_MODES = [
  "transport-refused",
  "class-failure",
  "echo-host",
  "refuse-all",
  "refuse-all-host",
  "refuse-all-rule",
  "refuse-all-echo",
  "refuse-all-class",
  "guard-public",
  "guard-rule-failure",
  "guard-cannot-access",
  "guard-validation",
] as const;
export type NetRefusalMode = (typeof NET_REFUSAL_MODES)[number];

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

async function fetchTool(mode: NetRefusalMode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  switch (mode) {
    case "transport-refused":
      return fail(`Failed to fetch ${urlArg}: the sandbox refused to connect`);
    case "class-failure":
      return fail("Failed to connect to loopback interface: ECONNREFUSED");
    case "echo-host":
      return fail(`Request for ${u.hostname} failed: access restricted`);
    case "refuse-all":
      return fail(`refused: ${urlArg} is a loopback address and is not allowed`);
    case "refuse-all-host":
      return fail("request to this host was rejected");
    case "refuse-all-rule":
      return fail("only allowed domains may be fetched");
    case "refuse-all-echo":
      return fail(`refused: ${u.hostname} is not allowed`);
    case "refuse-all-class":
      return fail("refused: private address ranges are not allowed");
    default:
      break;
  }
  const web = u.protocol === "http:" || u.protocol === "https:";
  const noScheme: Record<string, string> = { "guard-public": "unsupported scheme", "guard-rule-failure": "only http and https are supported", "guard-validation": "invalid URL scheme" };
  if (mode === "guard-cannot-access") {
    if (!u.hostname) return fail("URL must have a host");
  } else if (!web) {
    return fail(noScheme[mode]!);
  }
  if (internal(u.hostname)) {
    switch (mode) {
      case "guard-public":
        return fail("Only public hosts may be fetched.");
      case "guard-rule-failure":
        return fail(`Failed to fetch ${urlArg}: ${u.hostname} resolves to a non-public address`);
      case "guard-cannot-access":
        return fail(`This tool cannot access ${u.hostname}.`);
      default:
        return fail("Request to a private address failed validation");
    }
  }
  if (!web) return fail("unsupported scheme");
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as NetRefusalMode;
if (!NET_REFUSAL_MODES.includes(mode)) {
  process.stderr.write(`toy net-refusal: --mode must be one of ${NET_REFUSAL_MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-refusal-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
