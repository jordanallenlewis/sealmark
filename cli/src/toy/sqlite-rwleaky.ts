// Toy SQLite MCP server whose write tool shows no rows but whose read tool shares its connection: an ATTACH through `write_query`
// stays attached, so `read_query` can read the attached file. Used to test that sqlite-file-read follows a writer's ATTACH through the
// controlled reader on the same session.
// Run: node dist/toy/sqlite-rwleaky.js --db <path> [--mode <leak|guarded>]
// Not part of the product surface; the expected verdicts are asserted in src/test/r4-sql.fileread.test.ts. The near miss (a fresh
// connection per call, so nothing survives into the next call) is `sqlite-rwsplit.js --mode blind`.
//
// `read_query` takes SELECT and WITH only (so it refuses ATTACH, VACUUM and everything else itself). `write_query` takes anything but a
// SELECT, and answers every statement with a bare row count, never with rows. Both run on one read-write connection.
//
// leak     as above: the attached database is visible to read_query, which reads it
// guarded  as above, and both tools refuse any statement that names a table of an attached database ("<alias>.secret"), while
//          still listing the databases: the ATTACH persists, but nothing will read what it attached, not even to copy it into the
//          fixture (a near miss: must pass)
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

const MODES = ["leak", "guarded"] as const;
type Mode = (typeof MODES)[number];
const { values } = parseArgs({ options: { db: { type: "string" }, mode: { type: "string" } }, strict: true });
const mode = (values.mode ?? "leak") as Mode;
function usage(msg: string): never {
  process.stderr.write(`sqlite-rwleaky toy: ${msg}\nusage: sqlite-rwleaky.js --db <path> [--mode <${MODES.join("|")}>]\n`);
  process.exit(2);
}
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
if (!values.db) usage("--db is required");
const dbPath = values.db;

let db: DatabaseSync | undefined;

function execute(tool: string, sql: string): string {
  if (tool === "read_query" && !/^\s*(select|with)\b/i.test(sql)) throw new Error("only SELECT and WITH queries are allowed");
  // Both tools: a writer that took "CREATE TABLE ... AS SELECT v FROM <alias>.secret" would copy the attached file into the fixture (round 5).
  if (mode === "guarded" && /\b\w+\.secret\b/i.test(sql)) throw new Error("reading from an attached database is not allowed");
  if (tool === "write_query" && /^\s*select\b/i.test(sql)) throw new Error("SELECT queries are not allowed for write_query");
  const stmt = (db ??= new DatabaseSync(dbPath)).prepare(sql);
  if (tool === "write_query") return `OK: ${Number(stmt.run().changes)} row(s) affected`;
  return JSON.stringify(stmt.all(), (_k, v) => (typeof v === "bigint" ? v.toString() : v));
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

const server = new Server({ name: `sealmark-toy-sqlite-rwleaky-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
