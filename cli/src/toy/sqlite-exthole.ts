// Toy SQLite MCP server whose connection has extension loading switched on, behind a read tool and a write tool that each filter by
// statement type. Used to test that sqlite-extension-load is decided from what the engine says about loading, not from the fact that
// a probe was refused.
// Run: node dist/toy/sqlite-exthole.js --db <path>
// Not part of the product surface; the expected verdicts are asserted in src/test/r4-sql.extension.test.ts.
//
// `read_query` takes SELECT only. `write_query` takes INSERT, UPDATE and DELETE only: the plain `SELECT load_extension(...)` probe is
// answered "SELECT queries are not allowed for write_query", which says nothing about extension loading. Both tools run on one
// read-write connection with loading enabled, so an INSERT or UPDATE that calls load_extension reaches the loader and fails with the
// loader's own error (a library that does not exist). The near miss is sqlite-extdeny.ts, which is identical with loading disabled.
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

const { values } = parseArgs({ options: { db: { type: "string" } }, strict: true });
if (!values.db) {
  process.stderr.write("sqlite-exthole toy: --db is required\nusage: sqlite-exthole.js --db <path>\n");
  process.exit(2);
}
const dbPath = values.db;

let db: DatabaseSync | undefined;
function connect(): DatabaseSync {
  if (db) return db;
  // A build with extension loading switched on. node:sqlite exposes only the loadExtension() method, never the SQL function, so the
  // function is registered here in front of the method: load_extension('<path>') in a statement reaches the real loader.
  const c = new DatabaseSync(dbPath, { allowExtension: true });
  c.enableLoadExtension(true);
  c.function("load_extension", (p: unknown) => {
    c.loadExtension(String(p));
    return null;
  });
  db = c;
  return c;
}

const WRITE = /^\s*(insert|update|delete)\b/i;

function execute(tool: string, sql: string): string {
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

const server = new Server({ name: "sealmark-toy-sqlite-exthole", version: "0.0.1" }, { capabilities: { tools: {} } });
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
