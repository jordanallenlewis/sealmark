// Toy SQLite MCP server, the near miss for sqlite-exthole.ts: the same read tool and the same write tool with the same statement
// allowlist, but extension loading is switched off. It must still PASS sqlite-extension-load (and the other sqlite checks that do not
// concern this toy are not asserted).
// Run: node dist/toy/sqlite-extdeny.js --db <path> [--mode <deny|mute>]
// Not part of the product surface; the expected verdicts are asserted in src/test/r4-sql.extension.test.ts.
//
// deny  `write_query` takes INSERT, UPDATE and DELETE only, so the SELECT-form probe is answered "SELECT queries are not allowed for
//       write_query" (which says nothing about loading); the INSERT form reaches the engine, which answers "not authorized" because
//       loading is off. The harness must read that as a denial and pass.
// mute  every statement that names load_extension is refused with a generic "this statement is not allowed" and nothing else, on both
//       tools, so no form the harness sends gets an answer about extension loading: the verdict must be inconclusive, never a pass.
//
// The database is opened on the first query, not at startup, so a discovery session that runs before the fixture exists still works.
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const MODES = ["deny", "mute"] as const;
type Mode = (typeof MODES)[number];
const { values } = parseArgs({ options: { db: { type: "string" }, mode: { type: "string" } }, strict: true });
const mode = (values.mode ?? "deny") as Mode;
function usage(msg: string): never {
  process.stderr.write(`sqlite-extdeny toy: ${msg}\nusage: sqlite-extdeny.js --db <path> [--mode <${MODES.join("|")}>]\n`);
  process.exit(2);
}
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
if (!values.db) usage("--db is required");
const dbPath = values.db;

let db: DatabaseSync | undefined;
function connect(): DatabaseSync {
  // Extension loading is not enabled on this connection: the engine's own load_extension() answers "not authorized".
  return (db ??= new DatabaseSync(dbPath));
}

const WRITE = /^\s*(insert|update|delete)\b/i;

function execute(tool: string, sql: string): string {
  if (mode === "mute" && /load_extension/i.test(sql)) throw new Error("this statement is not allowed");
  if (tool === "read_query" && !/^\s*select\b/i.test(sql)) throw new Error("only SELECT queries are allowed");
  if (tool === "write_query" && !WRITE.test(sql)) throw new Error("SELECT queries are not allowed for write_query");
  const stmt = connect().prepare(sql);
  return JSON.stringify(tool === "write_query" ? { changes: Number(stmt.run().changes) } : stmt.all(), (_k, v) => (typeof v === "bigint" ? v.toString() : v));
}

const sqlTool = (name: string, description: string) => ({
  name,
  description,
  inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "SQL text to run" } }, required: ["sql"] },
});

const tools = [sqlTool("read_query", "Execute SELECT queries to read data from the SQLite database"), sqlTool("write_query", "Execute INSERT, UPDATE, or DELETE queries on the SQLite database")];

const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

const server = new Server({ name: `sealmark-toy-sqlite-extdeny-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (!tools.some((t) => t.name === req.params.name)) return fail(`unknown tool ${req.params.name}`);
  if (typeof args.sql !== "string") return fail("sql must be a string");
  try {
    return ok(execute(req.params.name, args.sql));
  } catch (e) {
    return fail(message(e));
  }
});

// Exit when the client goes away.
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
