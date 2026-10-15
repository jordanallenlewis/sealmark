// Toy MCP server for the orchestrator tests (run.ts): a server that never answers, and one whose tool rejects its input.
// Run: node dist/toy/hang.js --mode <hang|iserror>
//   hang     starts, reads stdin and never answers: `initialize` gets no reply, so the harness's connect timeout is the only way out.
//            It ignores the end of stdin, so only a signal or a kill stops it. A marker (any extra argument) is ignored; tests put a
//            unique one on the command line to find the process again.
//   iserror  an ordinary server with two text tools. `lookup` answers only the key "known" and rejects every other key with
//            isError (the arguments fit the schema, the call is refused); `note` always succeeds. Both reject a wrong type.
// Not part of the product surface.
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["hang", "iserror"] as const;
type Mode = (typeof MODES)[number];

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: false, allowPositionals: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) {
  process.stderr.write(`toy hang server: --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}

if (mode === "hang") {
  // Read and drop everything; keep the event loop alive without answering.
  process.stdin.resume();
  setInterval(() => {}, 1 << 30);
} else {
  interface Reply {
    [x: string]: unknown;
    content: { type: "text"; text: string }[];
    isError?: boolean;
  }
  const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
  const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

  const str = (description: string) => ({ type: "string", description });
  const tools = [
    { name: "lookup", description: "Look up a record by its key and return it.", inputSchema: { type: "object" as const, properties: { key: str("Key of the record") }, required: ["key"] } },
    { name: "note", description: "Store a short note and acknowledge it.", inputSchema: { type: "object" as const, properties: { text: str("Text of the note") }, required: ["text"] } },
  ];

  const server = new Server({ name: "sealmark-toy-hang-iserror", version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const a = (req.params.arguments ?? {}) as Record<string, unknown>;
    switch (req.params.name) {
      case "lookup":
        if (typeof a.key !== "string") return fail("key must be a string");
        return a.key === "known" ? ok("record: known") : fail(`no record for key ${JSON.stringify(a.key)}`);
      case "note":
        if (typeof a.text !== "string") return fail("text must be a string");
        return ok(`noted: ${a.text}`);
      default:
        return fail(`unknown tool ${req.params.name}`);
    }
  });
  for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
  await server.connect(new StdioServerTransport());
}
