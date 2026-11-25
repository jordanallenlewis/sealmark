// Toy stdio MCP server for the round 9 core advisories `resources-read` and `prompts-get`. One clean tool; the resources and prompts
// differ between modes.
// Run: node dist/toy/extras-r9.js --mode <clean|lax|broken|crash|listfail|none>
// Not part of the product surface. Expected verdicts (resources-read, prompts-get):
//   clean     both listed resources read; unknown URI -32002; prompts fetch; missing argument and unknown name -32602     pass, pass
//   lax       the same, but an unknown URI, an unknown prompt and a missing argument are answered as a success              part, part
//   broken    every resources/read and prompts/get answers an error                                                         fail, fail
//   crash     the process exits on the first resources/read or prompts/get                                                  fail, inconclusive (closed before prompts)
//   listfail  resources/list and prompts/list answer an error although both are advertised                                fail, fail
//   none      neither resources nor prompts are advertised                                                                  n/a, n/a
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

export const EXTRAS_R9_MODES = ["clean", "lax", "broken", "crash", "listfail", "none"] as const;
type Mode = (typeof EXTRAS_R9_MODES)[number];

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!EXTRAS_R9_MODES.includes(mode)) {
  process.stderr.write(`toy extras-r9: --mode must be one of ${EXTRAS_R9_MODES.join(", ")}\n`);
  process.exit(2);
}

const RESOURCES = [
  { uri: "memo://notes/today", name: "today", description: "Today's notes.", mimeType: "text/plain" },
  { uri: "memo://notes/readme", name: "readme", description: "How the notes are kept.", mimeType: "text/plain" },
];
const PROMPTS = [
  { name: "summarize", description: "Summarize today's notes." },
  { name: "review", description: "Review a piece of code.", arguments: [{ name: "code", description: "The code to review", required: true }] },
];
const RESOURCE_NOT_FOUND = -32002;

const advertise = mode !== "none";
const server = new Server(
  { name: `sealmark-toy-extras-r9-${mode}`, version: "0.0.1" },
  { capabilities: { tools: {}, ...(advertise ? { resources: {}, prompts: {} } : {}) } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "echo", description: "Returns the text it is given.", inputSchema: { type: "object" as const, properties: { text: { type: "string", description: "Text to return" } } } }],
}));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text" as const, text: "ok" }] }));

if (advertise) {
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    if (mode === "listfail") throw new McpError(ErrorCode.InternalError, "resource index unavailable");
    return { resources: RESOURCES };
  });
  server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
    if (mode === "crash") process.exit(1);
    if (mode === "broken") throw new McpError(ErrorCode.InternalError, "storage offline");
    const hit = RESOURCES.find((r) => r.uri === req.params.uri);
    if (hit) return { contents: [{ uri: hit.uri, mimeType: "text/plain", text: `contents of ${hit.name}` }] };
    if (mode === "lax") return { contents: [] };
    throw new McpError(RESOURCE_NOT_FOUND, `Resource not found: ${req.params.uri}`);
  });
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    if (mode === "listfail") throw new McpError(ErrorCode.InternalError, "prompt index unavailable");
    return { prompts: PROMPTS };
  });
  server.setRequestHandler(GetPromptRequestSchema, async (req) => {
    if (mode === "crash") process.exit(1);
    if (mode === "broken") throw new McpError(ErrorCode.InternalError, "templates offline");
    const p = PROMPTS.find((x) => x.name === req.params.name);
    const lax = mode === "lax";
    if (!p && !lax) throw new McpError(ErrorCode.InvalidParams, `Unknown prompt: ${req.params.name}`);
    const code = req.params.arguments?.code;
    if (p?.name === "review" && code === undefined && !lax) throw new McpError(ErrorCode.InvalidParams, "Missing required argument: code");
    return { messages: [{ role: "user" as const, content: { type: "text" as const, text: p?.name === "review" ? `Review this code: ${code ?? ""}` : "Summarize the notes." } }] };
  });
}

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
