// Toy MCP servers for the db pack's required-parameter fillers and server-evidence classification. Synthetic.
// Run: node dist/toy/db-extraparam.js --mode <m> --dsn <dsn> [--timeout <sec=10>]
//
// Every mode is a safe reader (a READ ONLY transaction that is always rolled back, one statement per call). They differ in what the SQL tool
// also requires:
//   enum    run_query(sql, database, format): `database` is an enum (main, archive) and `format` a free string; both required. The harness fills
//           them (the first enum value, a token), so the tool is detected and graded
//   name    run_query(sql, database): `database` is a required string that must name the one database this server has ("warehouse"). The
//           harness's token is refused ("unknown database"), so the tool is listed with the sql_tools args remedy; with
//           args: {database: "warehouse"} it is graded
//   export  run_sql(query) and export_results(query): the second tool says it runs the query and exports the results in a chosen format, which
//           the classifier places because a sibling already takes the same argument
//
// Same patterns as toy/db-policy.ts (which this file deliberately does not import: that file runs a server at load time).
// Not part of the product surface; the expected behaviour is in test/r5-sql.extraparam.test.ts.
import { parseArgs } from "node:util";
import pg from "pg";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["enum", "name", "export"] as const;
type Mode = (typeof MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function usage(msg: string): never {
  process.stderr.write(`toy db-extraparam: ${msg}\nusage: db-extraparam.js --mode <${MODES.join("|")}> --dsn <dsn> [--timeout <sec>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, dsn: { type: "string" }, timeout: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
const timeoutSec = values.timeout === undefined ? 10 : Number(values.timeout);
if (!(timeoutSec > 0)) usage("--timeout must be a positive number of seconds");
if (!values.dsn) usage("--dsn is required");
const dsn = values.dsn;

/** One long-lived connection, reopened if the database side kills it (the harness terminates backends between probes). */
let conn: pg.Client | undefined;
async function client(): Promise<pg.Client> {
  if (conn) return conn;
  const c = new pg.Client({ connectionString: dsn });
  c.on("error", () => {
    if (conn === c) conn = undefined;
  });
  await c.connect();
  conn = c;
  return c;
}

/** The safe path (as toy/server.ts): read statements only, one at a time, inside a READ ONLY transaction that is always rolled back. */
async function safeQuery(sql: string): Promise<Reply> {
  if (!/^\s*(select|with|explain)\b/i.test(sql)) return fail("only read statements (select, with, explain) are allowed");
  const body = sql.trim().replace(/;\s*$/, "");
  if (body.includes(";")) return fail("multiple statements are not allowed");
  let c: pg.Client;
  try {
    c = await client();
  } catch (e) {
    return fail(message(e));
  }
  try {
    await c.query("BEGIN READ ONLY");
    await c.query(`SET LOCAL statement_timeout = ${Math.round(timeoutSec * 1000)}`);
    const wrap = !/^\s*explain\b/i.test(body);
    const r = await c.query(wrap ? `SELECT * FROM (\n${body}\n) sm_q LIMIT 1001` : body);
    return ok(JSON.stringify(r.rows));
  } catch (e) {
    return fail(message(e));
  } finally {
    await c.query("ROLLBACK").catch(() => {});
  }
}

const sqlTool = (props: Record<string, Record<string, unknown>>, name: string, description: string) => ({
  name,
  description,
  inputSchema: { type: "object" as const, properties: props, required: Object.keys(props) },
});

const tools =
  mode === "enum"
    ? [
        sqlTool(
          { sql: { type: "string", description: "SQL text to run" }, database: { type: "string", enum: ["main", "archive"], description: "Which database to query" }, format: { type: "string", description: "Output format label" } },
          "run_query",
          "Run a read-only SQL query against the database and return the rows as JSON.",
        ),
      ]
    : mode === "name"
      ? [sqlTool({ sql: { type: "string", description: "SQL text to run" }, database: { type: "string", description: "Name of the database to query" } }, "run_query", "Run a read-only SQL query against the database and return the rows as JSON.")]
      : [
          sqlTool({ query: { type: "string", description: "SQL text to run" } }, "run_sql", "Run a read-only SQL query against the database and return the rows as JSON."),
          sqlTool({ query: { type: "string", description: "The query to run; its results are exported" } }, "export_results", "Runs the query and exports the results in the chosen format."),
        ];

async function handle(name: string, args: Record<string, unknown>): Promise<Reply> {
  const sql = mode === "export" ? args.query : args.sql;
  if (typeof sql !== "string") return fail("the SQL argument must be a string");
  if (mode === "enum") {
    if (args.database !== "main" && args.database !== "archive") return fail('invalid database: expected "main" or "archive"');
    if (typeof args.format !== "string" || !args.format) return fail("format is required");
  }
  if (mode === "name" && args.database !== "warehouse") return fail(`unknown database "${String(args.database)}": no such database on this server`);
  return safeQuery(sql);
}

const server = new Server({ name: `sealmark-toy-db-extraparam-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  try {
    if (!tools.some((t) => t.name === req.params.name)) return fail(`unknown tool ${req.params.name}`);
    return await handle(req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>);
  } catch (e) {
    if (e instanceof McpError) throw e;
    return fail(message(e));
  }
});

// Exit when the client goes away so no pg connection keeps the process alive.
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
