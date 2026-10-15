// Toy SQLite MCP server with a read/write split, used to test that a declared writer tool is probed for the file checks.
// Run: node dist/toy/sqlite-rwsplit.js --mode <m> --db <path>
// Not part of the product surface; the expected verdicts for every mode are asserted in src/test/sql-pack.writer.test.ts.
//
// Both modes expose `read_query` (SELECT only; it refuses everything else, so ATTACH and VACUUM never get through it) and
// `write_query` on one read-write connection. The only difference is what `write_query` does with statements that reach
// outside the database file it was given.
//
// escape   write_query runs any statement: VACUUM INTO and ATTACH reach any path, so it writes and reads arbitrary files
// refuse   write_query runs any statement except VACUUM, ATTACH, DETACH and load_extension, which it refuses by name
// blind    write_query runs INSERT, UPDATE, DELETE, ATTACH (of a file that already exists) and SELECT, refuses the rest, and
//          answers every accepted statement with a bare row count, never with rows: a write tool that cannot show what an
//          ATTACHed file holds, and that cannot create a file. It opens a connection per call, so an ATTACH never survives
//          into the next call (read_query cannot see it either): the near miss for the follow-through-the-reader check
// plain    as refuse, and every failure comes back as plain text starting "Database error: " with no error flag (the way some
//          SQLite wrappers report an engine error). Also rejects stacked statements and refuses recursive and CROSS JOIN reads
//
// The database is opened on the first query, not at startup, so a discovery session that runs before the fixture exists still works.
import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";

const MODES = ["escape", "refuse", "blind", "plain"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const { values } = parseArgs({ options: { mode: { type: "string" }, db: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
function usage(msg: string): never {
  process.stderr.write(`sqlite-rwsplit toy: ${msg}\nusage: sqlite-rwsplit.js --mode <${MODES.join("|")}> --db <path>\n`);
  process.exit(2);
}
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
if (!values.db) usage("--db is required");
const dbPath = values.db;

let db: DatabaseSync | undefined;

const REFUSED_BY_NAME = /^\s*(vacuum|attach|detach)\b|load_extension/i;
const BLIND_ALLOWED = /^\s*(insert|update|delete|attach|select)\b/i;

/** Run one statement the way `tool` would in this mode. Throws on refusal or engine error. */
function execute(tool: string, sql: string): string {
  if (tool === "read_query" && !/^\s*select\b/i.test(sql)) throw new Error("only SELECT queries are allowed");
  if (tool === "write_query" && (mode === "refuse" || mode === "plain") && REFUSED_BY_NAME.test(sql)) {
    // A refusal by name says what it refused: the extension loader is named, so the harness can tell a denial of loading from a generic "no".
    throw new Error(/load_extension/i.test(sql) ? "load_extension is not allowed" : "this statement is not allowed");
  }
  if (mode === "plain" && /;\s*\S/.test(sql)) throw new Error("You can only execute one statement at a time.");
  if (mode === "plain" && /\brecursive\b|\bcross join\b/i.test(sql)) throw new Error("this statement is too expensive to run");
  if (tool === "write_query" && mode === "blind" && !BLIND_ALLOWED.test(sql)) throw new Error("only INSERT, UPDATE, DELETE, ATTACH and SELECT statements are allowed");
  if (tool === "write_query" && mode === "blind") {
    // Only a database file that already exists can be attached: a new file is never created.
    const target = /^\s*attach\s+(?:database\s+)?'((?:[^']|'')*)'/i.exec(sql)?.[1]?.replace(/''/g, "'");
    if (target !== undefined && !existsSync(target)) throw new Error("unable to open database file");
  }
  // blind: a connection per call, so nothing a statement sets up (an ATTACH) survives into the next call, on either tool.
  // The other modes share one connection, which is what lets an ATTACH through write_query be read back.
  const conn = mode === "blind" ? new DatabaseSync(dbPath) : (db ??= new DatabaseSync(dbPath));
  try {
    const stmt = conn.prepare(sql);
    if (tool === "write_query" && mode === "blind") {
      const info = stmt.run();
      return `OK: ${info.changes} row(s) affected`;
    }
    return JSON.stringify(stmt.all(), (_k, v) => (typeof v === "bigint" ? v.toString() : v));
  } finally {
    if (conn !== db) conn.close();
  }
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

const server = new Server({ name: `sealmark-toy-sqlite-rwsplit-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (!tools.some((t) => t.name === req.params.name)) return fail(`unknown tool ${req.params.name}`);
  if (typeof args.sql !== "string") return fail("sql must be a string");
  try {
    return ok(execute(req.params.name, args.sql));
  } catch (e) {
    return mode === "plain" ? ok(`Database error: ${message(e)}`) : fail(message(e));
  }
});

// Exit when the client goes away.
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
