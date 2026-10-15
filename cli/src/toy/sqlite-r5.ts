// Toy SQLite MCP servers for the round 5 sqlite pack items. Synthetic; one known behaviour per mode.
// Run: node dist/toy/sqlite-r5.js --mode <m> --db <path>
// Not part of the product surface; the expected verdicts for every mode are asserted in src/test/r5-sql.*.test.ts.
// No mode needs setAuthorizer, so every one of them runs on Node 22.13 and newer.
//
// Every statement runs on a connection opened for that call (a "fresh connection per call"), so nothing a call sets up, an ATTACH
// included, survives into the next call.
//
// fresh-stacked   stacked statements run and the rows of the last one come back: "ATTACH '<other file>' AS a; SELECT v FROM a.secret" in one call
//                 shows the other file's content. The two-call form (ATTACH, then SELECT) shows nothing, because of the fresh connection
// fresh-blind     as fresh-stacked, but every call answers a bare "OK" and never rows, so only the file the statements left behind shows it
// fresh-single    near miss for both: one statement per call (a second statement is refused with "only one statement per call"); SELECT and
//                 ATTACH of an existing file are accepted, everything else is refused. Nothing it accepts can reach another file
// ddl-stacked     create_table accepts text that starts with CREATE TABLE and runs ALL of it (stacked statements), answering "OK";
//                 read_query is a clean SELECT-only reader. The DDL tool is the way out: VACUUM INTO and ATTACH behind a CREATE TABLE
// ddl-strict      near miss: the same two tools, but create_table refuses a second statement ("only a single CREATE TABLE statement is allowed")
// other-engine    answers like another embedded engine: sqlite_version() is "Catalog Error: Scalar Function with name sqlite_version does not exist!";
//                 every other statement runs on a read-only SQLite connection
// plaincap        a read-only reader that answers the big-table probe with the plain text "Result set too large: more than 1000 rows. Add a LIMIT
//                 clause." and no error flag (zero rows)
// uncontrolled    a clean read_query reader, plus run_script, which refuses every statement it is given (no control form can work)
//
// The database is opened on the first query, not at startup, so a discovery session that runs before the fixture exists still works.
import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { parseArgs } from "node:util";

const MODES = ["fresh-stacked", "fresh-blind", "fresh-single", "ddl-stacked", "ddl-strict", "other-engine", "plaincap", "uncontrolled"] as const;
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
  process.stderr.write(`sqlite-r5 toy: ${msg}\nusage: sqlite-r5.js --mode <${MODES.join("|")}> --db <path>\n`);
  process.exit(2);
}
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
if (!values.db) usage("--db is required");
const dbPath = values.db;

const json = (rows: unknown[]) => JSON.stringify(rows, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
/** More than one statement: a semicolon followed by anything but whitespace. */
const STACKED = /;\s*\S/;
const statementsOf = (sql: string) => sql.split(";").map((s) => s.trim()).filter(Boolean);

/** Run every statement on one connection; the rows of the last one are the answer. */
function runAll(conn: DatabaseSync, sql: string): unknown[] {
  let rows: unknown[] = [];
  for (const s of statementsOf(sql)) rows = conn.prepare(s).all();
  return rows;
}

function execute(tool: string, sql: string): string {
  switch (mode) {
    case "fresh-stacked":
    case "fresh-blind": {
      const conn = new DatabaseSync(dbPath);
      try {
        const rows = runAll(conn, sql);
        return mode === "fresh-blind" ? "OK" : json(rows);
      } finally {
        conn.close();
      }
    }
    case "fresh-single": {
      if (STACKED.test(sql)) throw new Error("only one statement per call is allowed");
      if (!/^\s*(select|attach)\b/i.test(sql)) throw new Error("only SELECT statements are allowed");
      // An ATTACH of a file that does not exist would create it, so it is refused; one that exists is accepted and is gone with the connection.
      const target = /^\s*attach\s+(?:database\s+)?'((?:[^']|'')*)'/i.exec(sql)?.[1]?.replace(/''/g, "'");
      if (target !== undefined && !existsSync(target)) throw new Error("unable to open database file");
      const conn = new DatabaseSync(dbPath);
      try {
        return json(conn.prepare(sql).all());
      } finally {
        conn.close();
      }
    }
    case "ddl-stacked":
    case "ddl-strict": {
      if (tool === "read_query") {
        if (!/^\s*select\b/i.test(sql) || STACKED.test(sql)) throw new Error("only a single SELECT statement is allowed");
        const conn = new DatabaseSync(dbPath, { readOnly: true });
        try {
          return json(conn.prepare(sql).all());
        } finally {
          conn.close();
        }
      }
      // create_table: the first statement must be CREATE TABLE. ddl-stacked then runs everything it was given.
      if (!/^\s*create\s+table\b/i.test(sql)) throw new Error("only CREATE TABLE statements are allowed");
      if (mode === "ddl-strict" && STACKED.test(sql)) throw new Error("only a single CREATE TABLE statement is allowed");
      const conn = new DatabaseSync(dbPath);
      try {
        runAll(conn, sql);
        return "OK";
      } finally {
        conn.close();
      }
    }
    case "other-engine": {
      if (/sqlite_version/i.test(sql)) throw new Error("Catalog Error: Scalar Function with name sqlite_version does not exist!");
      const conn = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return json(conn.prepare(sql).all());
      } finally {
        conn.close();
      }
    }
    case "plaincap":
    case "uncontrolled": {
      if (tool === "run_script") throw new Error("this tool is disabled");
      if (!/^\s*select\b/i.test(sql) || STACKED.test(sql)) throw new Error("only a single SELECT statement is allowed");
      if (mode === "plaincap" && /\bbig_table\b/i.test(sql)) return "Result set too large: more than 1000 rows. Add a LIMIT clause.";
      const conn = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return json(conn.prepare(sql).all());
      } finally {
        conn.close();
      }
    }
  }
}

const sqlTool = (name: string, description: string) => ({
  name,
  description,
  inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "SQL text to run" } }, required: ["sql"] },
});

const READ = sqlTool("read_query", "Execute SELECT queries to read data from the SQLite database");
const tools =
  mode === "ddl-stacked" || mode === "ddl-strict"
    ? [READ, sqlTool("create_table", "Create a table in the SQLite database by running a CREATE TABLE statement")]
    : mode === "uncontrolled"
      ? [READ, sqlTool("run_script", "Run a SQL script against the SQLite database")]
      : mode === "fresh-single" || mode === "plaincap"
        ? [sqlTool("query", "Run a read-only SQL query against the SQLite database and return the rows as JSON.")]
        : mode === "fresh-blind"
          ? [sqlTool("query", "Run any SQL statement against the SQLite database. Answers OK when it ran.")]
          : [sqlTool("query", "Run any SQL statement against the SQLite database and return the rows as JSON.")];

const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

const server = new Server({ name: `sealmark-toy-sqlite-r5-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
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
