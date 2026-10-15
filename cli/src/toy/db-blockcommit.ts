// Toy MCP server for the db pack's transaction-terminator cases. Synthetic; one known flaw.
// Run: node dist/toy/db-blockcommit.js --dsn <dsn> [--timeout <sec=10>]
//
// A reader that runs whatever it is given inside a READ ONLY transaction and, to stop a caller from ending that transaction early,
// refuses text that contains the word COMMIT. It does not know that ROLLBACK, END and ABORT end a transaction too, so
// "ROLLBACK; INSERT ...", "END; INSERT ..." and "ABORT; INSERT ..." run the write in a new, writable transaction.
// Everything else is stopped by the read-only transaction: the stacked forms and the obfuscation case fail with the database's own error.
//
// Tools: query(sql). Same patterns as toy/db-policy.ts (which this file deliberately does not import: that file runs a server at load time).
// Not part of the product surface; the expected verdicts are in test/r5-sql.terminators.test.ts.
import { parseArgs } from "node:util";
import pg from "pg";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const { values } = parseArgs({ options: { dsn: { type: "string" }, timeout: { type: "string" } }, strict: true });
const timeoutSec = values.timeout === undefined ? 10 : Number(values.timeout);
if (!values.dsn || !(timeoutSec > 0)) {
  process.stderr.write("toy db-blockcommit: --dsn is required and --timeout must be a positive number of seconds\nusage: db-blockcommit.js --dsn <dsn> [--timeout <sec>]\n");
  process.exit(2);
}
const dsn = values.dsn;

/** One long-lived connection, reopened if the database side kills it (the harness terminates backends between probes). */
let conn: pg.Client | undefined;
async function client(): Promise<pg.Client> {
  if (conn) return conn;
  const c = new pg.Client({ connectionString: dsn, statement_timeout: Math.round(timeoutSec * 1000) });
  c.on("error", () => {
    if (conn === c) conn = undefined;
  });
  await c.connect();
  conn = c;
  return c;
}

/** The flaw: the one terminator this server knows about. */
const BLOCKED = /\bcommit\b/i;

async function query(sql: string): Promise<Reply> {
  if (BLOCKED.test(sql)) return fail("COMMIT is not allowed: this server is read-only");
  let c: pg.Client;
  try {
    c = await client();
  } catch (e) {
    return fail(message(e));
  }
  try {
    // Simple protocol, so several statements in one call all run: the text sits between BEGIN READ ONLY and the closing ROLLBACK.
    const res = (await c.query(`BEGIN READ ONLY;\n${sql}\n;`)) as unknown as pg.QueryResult | pg.QueryResult[];
    const last = Array.isArray(res) ? res[res.length - 1] : res;
    return ok(JSON.stringify(last.rows.slice(0, 1001)));
  } catch (e) {
    return fail(message(e));
  } finally {
    // Ends whatever is still open (an aborted transaction included); a "no transaction in progress" warning is not an error.
    await c.query("ROLLBACK").catch(() => {});
  }
}

const tools = [
  {
    name: "query",
    description: "Run a read-only SQL query against the database and return the rows as JSON.",
    inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "SQL text to run" } }, required: ["sql"] },
  },
];
const server = new Server({ name: "sealmark-toy-db-blockcommit", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  try {
    if (req.params.name !== "query") return fail(`unknown tool ${req.params.name}`);
    const sql = (req.params.arguments ?? {}).sql;
    return typeof sql === "string" ? await query(sql) : fail("sql must be a string");
  } catch (e) {
    if (e instanceof McpError) throw e;
    return fail(message(e));
  }
});

// Exit when the client goes away so no pg connection keeps the process alive.
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
