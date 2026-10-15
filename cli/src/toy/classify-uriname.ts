// Toy MCP server for the classifier's ranking: one tool, load_file_resource{name, data}, where `name` is only a label, `data` is
// the address to load (declared format "uri") and "file" is in the tool name. A generic `name` plus a "file" hint reaches
// medium as a path; the format "uri" parameter reaches medium as a url. The url reading rests on stronger evidence, so the
// tool classifies url (primary) with path as secondary, and the net pack runs against it.
// Run: node dist/toy/classify-uriname.js
// Not part of the product surface. Expected: classification url/medium, secondary [path]; net ssrf pass, scheme pass (it refuses
// internal addresses and non-web schemes).
import net from "node:net";
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

/** True for the addresses a server-side fetch must not reach (WHATWG parsing has already normalised 127.1, 0x7f000001 and 2130706433). */
function notPublic(hostRaw: string): boolean {
  const host = hostRaw.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (net.isIPv6(host)) return host === "::1" || host === "::" || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || /^::ffff:/.test(host);
  if (!net.isIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

async function load(dataArg: unknown): Promise<Reply> {
  if (typeof dataArg !== "string" || !dataArg) return fail("data must be a non-empty string");
  let u: URL;
  try {
    u = new URL(dataArg);
  } catch {
    return fail(`invalid URL: ${dataArg}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return fail(`blocked: scheme ${u.protocol} is not allowed (only http and https)`);
  if (notPublic(u.hostname)) return fail(`blocked: ${u.hostname} is a loopback or internal address (not allowed)`);
  const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(5000) });
  return ok(`HTTP ${res.status}\n${(await res.text()).slice(0, 1000)}`);
}

const server = new Server({ name: "sealmark-toy-classify-uriname", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "load_file_resource",
      description: "Loads a remote file resource and returns its text.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string", description: "A label for the result" },
          data: { type: "string", format: "uri", description: "Where the resource lives" },
        },
        required: ["name", "data"],
      },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name !== "load_file_resource") return fail(`unknown tool ${req.params.name}`);
  try {
    return await load((req.params.arguments ?? {}).data);
  } catch (e) {
    return fail(`load failed: ${e instanceof Error ? e.message : String(e)}`);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
