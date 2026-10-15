// Toy MCP server for a tool's secondary url class (round 4, B1): fetch_file{path, url}, where `path` names where the downloaded file
// is meant to go and `url` (declared format "uri") is what to download. Both readings reach high confidence; a path tool wins by
// specificity and url is the secondary class, which the net pack now consumes. The tool writes nothing in any mode.
// Run: node dist/toy/net-ambig.js --mode <open|guarded|nearmiss>
// Not part of the product surface. Expected:
//   open      fetches whatever URL it is given (loopback too)       classified path/high, secondary url; net graded: ssrf FAIL
//   guarded   refuses loopback and internal addresses and non-web schemes with an explicit reason    net graded: ssrf pass, scheme pass
//   nearmiss  save_report{path, title}: the second parameter is not a URL                                classified path, no secondary; net n/a
import net from "node:net";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["open", "guarded", "nearmiss"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
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

async function fetchFile(mode: Mode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let u: URL;
  try {
    u = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  if (mode === "guarded") {
    if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
    if (notPublic(u.hostname)) return fail(`blocked: ${u.hostname} is a loopback or internal address (not allowed)`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`unsupported scheme ${u.protocol}`);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)} (not saved)`);
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-ambig: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-ambig-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools:
    mode === "nearmiss"
      ? [
          {
            name: "save_report",
            description: "Saves a report file to a path.",
            inputSchema: {
              type: "object",
              properties: { path: { type: "string", description: "Where to save the file" }, title: { type: "string", description: "The title of the report" } },
              required: ["path", "title"],
            },
          },
        ]
      : [
          {
            name: "fetch_file",
            description: "Downloads a file from a URL and saves it to a path.",
            inputSchema: {
              type: "object",
              properties: { path: { type: "string", description: "Where to save the file" }, url: { type: "string", format: "uri", description: "The file to download" } },
              required: ["path", "url"],
            },
          },
        ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (mode === "nearmiss") return ok("saved nothing");
  if (req.params.name !== "fetch_file") return fail(`unknown tool ${req.params.name}`);
  try {
    return await fetchFile(mode, (req.params.arguments ?? {}).url);
  } catch (e) {
    return fail(`fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
