// Toy MCP server for the net pack: one tool, fetch{url}, that misbehaves in one known way per mode.
// Run: node dist/toy/net.js --mode <good|open|schemes|slow|silent> [--root <path>]
// Not part of the product surface. Expected verdicts:
//   good     loopback/private refused by resolved address, http(s) only, 1 MiB cap, 5 s timeout   ssrf pass  scheme pass  caps na       A
//   open     nothing checked, any scheme, 1 MiB cap but no timeout                                 ssrf fail  scheme fail  caps part     F
//   schemes  loopback refused, but file: is read                                                   ssrf pass  scheme fail  caps na       D
//   slow     loopback allowed, http(s) only, no cap and no timeout                                 ssrf fail  scheme pass  caps fail     F
//   silent   fetches nothing and refuses nothing (replies "ok"): ssrf is inconclusive until net.control_url is set
//   dead     every fetch fails with isError "fetch failed: ENETUNREACH" (no network): ssrf and scheme are inconclusive, never a pass
//   deadrpc  every fetch fails with a JSON-RPC error ("network is down"): same as dead
//   textfail every fetch returns the plain text "Error: could not fetch <url>: network is down" without isError: same as dead, and
//            the echoed data: URL is not a decode (scheme is never "part")
//   jsquirk  good, except javascript: URLs get a generic "Invalid URL" error (recorded, never scored): ssrf pass, scheme pass
//   decode   refuses loopback and non-web schemes except that data: URLs are decoded and their content returned: scheme part
// Modes for net-redirect (advisory, never scored; the design notes 4.1):
//   hop       refuses the hostnames localhost and ::1 ("blocked: localhost is not allowed"), accepts every other spelling and follows
//             redirects without looking at the target: ssrf fail, scheme pass                         redirect fail (hop to a refused spelling)
//   noredir   loopback allowed, http(s) only, redirects are reported and never followed, no caps: ssrf fail   redirect pass
//   anyscheme like open, but follows redirects by hand: http(s) with fetch, file: with readFile, gopher:/dict:/ftp: with raw TCP,
//             up to 5 hops                                                                            redirect fail (file read and raw TCP)
import { readFile } from "node:fs/promises";
import dns from "node:dns/promises";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

export const NET_TOY_MODES = ["good", "open", "schemes", "slow", "silent", "dead", "deadrpc", "textfail", "decode", "jsquirk", "hop", "noredir", "anyscheme"] as const;
export type NetToyMode = (typeof NET_TOY_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const CAP_BYTES = 1024 * 1024;

/** True for every address a server-side fetch must never reach: loopback, private, link-local, unspecified, CGNAT, multicast. */
export function isInternalAddress(ipRaw: string): boolean {
  const ip = ipRaw.replace(/^\[|\]$/g, "").toLowerCase();
  const kind = net.isIP(ip);
  if (kind === 4) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  if (kind === 6) {
    if (ip === "::" || ip === "::1") return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
    if (mapped) return isInternalAddress(mapped[1]!);
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(ip);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1]!, 16);
      const lo = parseInt(mappedHex[2]!, 16);
      return isInternalAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip) || /^ff/.test(ip);
  }
  return false;
}

/** Resolves the host the way the request would and refuses when any answer is internal. WHATWG parsing has already normalised 127.1, 0x7f000001 and 2130706433. */
async function assertPublicHost(u: URL): Promise<string | undefined> {
  const host = u.hostname.replace(/^\[|\]$/g, "");
  // "localhost" is loopback by definition: no lookup, so a slow or failing resolver cannot turn this refusal into a generic error.
  if (host === "localhost" || host.endsWith(".localhost")) return `blocked: ${host} is a loopback name (not allowed)`;
  if (net.isIP(host)) return isInternalAddress(host) ? `blocked: ${host} is a loopback, private or internal address (not allowed)` : undefined;
  try {
    const answers = await dns.lookup(host, { all: true });
    const bad = answers.find((a) => isInternalAddress(a.address));
    return bad ? `blocked: ${host} resolves to ${bad.address}, an internal address (not allowed)` : undefined;
  } catch (e) {
    return `could not resolve ${host}: ${(e as Error).message}`;
  }
}

async function readBody(res: Response, cap: number | undefined): Promise<string> {
  if (cap === undefined) return res.text();
  const reader = res.body?.getReader();
  if (!reader) return "";
  const parts: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const room = cap - total;
    if (value.length > room) {
      parts.push(Buffer.from(value.subarray(0, room)));
      total += room;
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    parts.push(Buffer.from(value));
    total += value.length;
  }
  return Buffer.concat(parts).toString("utf8") + (truncated ? `\n[truncated at ${cap} bytes]` : "");
}

/** Raw TCP for the schemes a real fetch tool should never speak (ftp, gopher, dict): connect, send the path, read a little. */
function rawTcp(u: URL): Promise<string> {
  const defaults: Record<string, number> = { "ftp:": 21, "gopher:": 70, "dict:": 2628 };
  const port = Number(u.port || defaults[u.protocol] || 80);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    let got = "";
    const finish = () => {
      s.destroy();
      resolve(got || `connected to ${host}:${port}`);
    };
    s.setTimeout(1500, finish);
    s.once("error", reject);
    s.once("connect", () => s.write(`${decodeURIComponent(u.pathname.replace(/^\/_?/, ""))}\r\n`));
    s.on("data", (d) => {
      got += d.toString("latin1").slice(0, 1000);
      finish();
    });
  });
}

/** Follows a redirect chain by hand, the way a tool that "supports every scheme" might: the Location of each 3xx is fetched as given. */
async function fetchByHand(u: URL): Promise<Reply> {
  let cur = u;
  for (let hop = 0; hop <= 5; hop++) {
    if (cur.protocol === "file:") return ok(await readFile(fileURLToPath(cur), "utf8"));
    if (cur.protocol === "ftp:" || cur.protocol === "gopher:" || cur.protocol === "dict:") return ok(await rawTcp(cur));
    if (cur.protocol !== "http:" && cur.protocol !== "https:") return fail(`unsupported scheme ${cur.protocol}`);
    const res = await fetch(cur, { redirect: "manual" });
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel().catch(() => {});
      cur = new URL(location, cur);
      continue;
    }
    return ok(`HTTP ${res.status}\n${await readBody(res, CAP_BYTES)}`);
  }
  return fail("too many redirects");
}

function usage(msg: string): never {
  process.stderr.write(`toy net server: ${msg}\nusage: net.js --mode <${NET_TOY_MODES.join("|")}> [--root <path>]\n`);
  process.exit(2);
}

async function fetchTool(mode: NetToyMode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  const web = u.protocol === "http:" || u.protocol === "https:";
  if (mode === "silent") return ok("ok");
  if (mode === "dead") return fail("fetch failed: ENETUNREACH");
  if (mode === "textfail") return ok(`Error: could not fetch ${urlArg}: network is down`);
  if (mode === "jsquirk" && u.protocol === "javascript:") return fail(`Invalid URL: ${urlArg}`);
  if (mode === "decode" && u.protocol === "data:") return ok(decodeURIComponent(u.pathname.replace(/^[^,]*,/, "")));

  if (mode === "open") {
    if (u.protocol === "file:") return ok(await readFile(fileURLToPath(u), "utf8"));
    if (u.protocol === "ftp:" || u.protocol === "gopher:" || u.protocol === "dict:") return ok(await rawTcp(u));
    if (!web && u.protocol !== "data:") return fail(`unsupported scheme ${u.protocol}`);
    const res = await fetch(u, { redirect: "follow" });
    return ok(`HTTP ${res.status}\n${await readBody(res, CAP_BYTES)}`);
  }

  if (mode === "slow") {
    if (!web) return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
    // Loopback is allowed, nothing is capped and nothing times out.
    const res = await fetch(u, { redirect: "follow" });
    return ok(`HTTP ${res.status}\n${await readBody(res, undefined)}`);
  }

  if (mode === "anyscheme") return fetchByHand(u);

  if (mode === "hop") {
    if (!web) return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
    // Only these two spellings are looked at, and only on the URL the caller gave: the Location of a redirect is followed unchecked.
    if (u.hostname === "localhost" || u.hostname === "[::1]") return fail("blocked: localhost is not allowed");
    const res = await fetch(u, { redirect: "follow" });
    return ok(`HTTP ${res.status}\n${await readBody(res, CAP_BYTES)}`);
  }

  if (mode === "noredir") {
    if (!web) return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
    // Loopback is allowed, a redirect is reported and never followed, nothing is capped.
    const res = await fetch(u, { redirect: "manual" });
    return ok(`HTTP ${res.status}\n${await readBody(res, undefined)}`);
  }

  // good, schemes and decode: internal addresses are refused by resolved address.
  if (u.protocol === "file:" && mode === "schemes") return ok(await readFile(fileURLToPath(u), "utf8"));
  if (!web) return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
  const refusal = await assertPublicHost(u);
  if (refusal) return fail(refusal);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${await readBody(res, CAP_BYTES)}`);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, root: { type: "string" } }, strict: true });
const mode = values.mode as NetToyMode;
if (!NET_TOY_MODES.includes(mode)) usage(`--mode must be one of ${NET_TOY_MODES.join(", ")}`);

const server = new Server({ name: `sealmark-toy-net-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
  if (mode === "deadrpc") throw new McpError(ErrorCode.InternalError, "network is down");
  try {
    return await fetchTool(mode, (req.params.arguments ?? {}).url);
  } catch (e) {
    return fail(`fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
