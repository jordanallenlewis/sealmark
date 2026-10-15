// Toy MCP server for net-redirect (round 4, A3): one tool, fetch{url}, that follows redirects by hand, up to 5 hops. It fetches the
// loopback spelling 127.0.0.1 and refuses the names localhost and [::1] (with an explicit reason), and only http(s) is accepted.
// Run: node dist/toy/net-revalidate.js --mode <revalidate|initial-only>
// Not part of the product surface. Expected verdicts (ssrf fails in both modes: the tool fetches 127.0.0.1, which is what lets net-redirect observe it):
//   revalidate    checks the host of the first URL and of every redirect target: a same-origin 302 is followed, a 302 to localhost is
//                 refused like the direct request was                                                       net-redirect PASS
//   initial-only  checks the host of the first URL only and follows the Location of a redirect unchecked    net-redirect FAIL (hop to a refused spelling)
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["revalidate", "initial-only"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

/** The refusal of a URL, or undefined. Only these names are refused; 127.0.0.1 and every spelling the parser turns into it are fetched. */
function refusal(u: URL): string | undefined {
  if (u.protocol !== "http:" && u.protocol !== "https:") return `blocked: scheme ${u.protocol} is not allowed (only http and https)`;
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host === "[::1]") return `blocked: ${host} is a loopback name (not allowed)`;
  return undefined;
}

async function fetchTool(mode: Mode, urlArg: unknown): Promise<Reply> {
  if (typeof urlArg !== "string" || !urlArg) return fail("url must be a non-empty string");
  let cur: URL;
  try {
    cur = new URL(urlArg);
  } catch {
    return fail(`invalid URL: ${urlArg}`);
  }
  for (let hop = 0; hop <= 5; hop++) {
    // revalidate looks at every URL it is about to fetch; initial-only looks at the first one.
    const why = mode === "revalidate" || hop === 0 ? refusal(cur) : cur.protocol === "http:" || cur.protocol === "https:" ? undefined : refusal(cur);
    if (why) return fail(why);
    const res = await fetch(cur, { redirect: "manual", signal: AbortSignal.timeout(5000) });
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel().catch(() => {});
      cur = new URL(location, cur);
      continue;
    }
    return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
  }
  return fail("too many redirects");
}

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy net-revalidate: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

const server = new Server({ name: `sealmark-toy-net-revalidate-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
