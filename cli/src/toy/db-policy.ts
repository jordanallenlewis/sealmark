// Policy toy MCP servers for the db pack. Each mode has one known, synthetic flaw.
// Run: node dist/toy/db-policy.js --mode <m> --dsn <dsn> [--timeout <sec=10>]
//   sticky     the first --dsn it sees is written to $HOME/.sm-toy-dsn and preferred on every later start, so the second
//              and third instance connect as the first one's role (db-privilege fails; rls and pii fail with it)
//   pooled     a fresh connection per call, so a PREPARE does not survive into the next call; a per-statement allowlist
//              (first keyword) lets PREPARE and EXECUTE through, so both in ONE call run the prepared write
//   selectlist no read-only transaction; blocks any text with a write keyword and any function call in the select list,
//              so a volatile function called from the FROM clause runs
//   explainok  the safe read-only-transaction path for everything except text that starts with EXPLAIN, which is passed
//              through untouched, so EXPLAIN ANALYZE of a write runs
// Same patterns as toy/db-extra.ts (which this file deliberately does not import: that file runs a server at load time).
// Not part of the product surface; the expected verdicts are in test/r3-sql-pack.*.test.ts.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import pg from "pg";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, McpError } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["sticky", "pooled", "selectlist", "explainok"] as const;
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
  process.stderr.write(`toy db-policy: ${msg}\nusage: db-policy.js --mode <${MODES.join("|")}> --dsn <dsn> [--timeout <sec>]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, dsn: { type: "string" }, timeout: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!MODES.includes(mode)) usage(`--mode must be one of ${MODES.join(", ")}`);
const timeoutSec = values.timeout === undefined ? 10 : Number(values.timeout);
if (!(timeoutSec > 0)) usage("--timeout must be a positive number of seconds");
if (!values.dsn) usage(`mode ${mode} needs --dsn`);

/** The sticky flaw: the first connection string ever seen wins, and later starts read it back from a file in HOME. */
function stickyDsn(first: string): string {
  const file = join(process.env.HOME ?? homedir(), ".sm-toy-dsn");
  try {
    if (existsSync(file)) return readFileSync(file, "utf8").trim() || first;
    writeFileSync(file, first, { flag: "wx" });
  } catch {
    // an unreadable or unwritable HOME: behave as if the file were not there
  }
  return first;
}
const dsn = mode === "sticky" ? stickyDsn(values.dsn) : values.dsn;

// ---- database access ----

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

/** At most 1,001 rows reach the caller, whatever the statement returned. */
function render(res: pg.QueryResult | pg.QueryResult[]): Reply {
  const last = Array.isArray(res) ? res[res.length - 1] : res;
  return ok(JSON.stringify(last.rows.slice(0, 1001)));
}

/** Text goes to the database over the simple protocol, so several statements in one call all run. */
async function run(c: pg.Client, sql: string): Promise<Reply> {
  try {
    return render((await c.query(sql)) as unknown as pg.QueryResult | pg.QueryResult[]);
  } catch (e) {
    return fail(message(e));
  }
}

/** The safe path (as toy/server.ts): read statements only, inside a READ ONLY transaction that is always rolled back. */
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
    return render(await c.query(wrap ? `SELECT * FROM (\n${body}\n) sm_q LIMIT 1001` : body));
  } catch (e) {
    return fail(message(e));
  } finally {
    await c.query("ROLLBACK").catch(() => {});
  }
}

// ---- policies ----

const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
const firstKeyword = (stmt: string) => /^\s*([a-z]+)/i.exec(stripComments(stmt))?.[1]?.toLowerCase() ?? "";
/** Any of these anywhere in the text. `into` is here for SELECT INTO. */
const WRITE_WORD = /\b(insert|update|delete|truncate|create|drop|alter|grant|revoke|copy|into|do|call|commit|rollback|begin|vacuum)\b/i;
/** A function call in the select list: nothing between SELECT and the first call may be a FROM. */
const SELECT_LIST_CALL = /^\s*select\s+(?:(?!\bfrom\b)[^(])*\w+\s*\(/i;
/** pooled: functions known to change state or stall. */
const DENIED_FN = /\b(set_config|sm_mutate|pg_sleep)\s*\(/i;

/** pooled: a per-statement allowlist on the first keyword. Reads are also scanned for write words; PREPARE and EXECUTE are not
 * (they only name a prepared statement), which is the flaw: both in one call on one connection run the write. */
function pooledAllows(text: string): string | undefined {
  for (const stmt of text.split(";")) {
    if (!stmt.trim()) continue;
    const kw = firstKeyword(stmt);
    if (!["select", "with", "explain", "prepare", "execute"].includes(kw)) return `statement type "${kw || "?"}" is not allowed`;
    if (kw !== "prepare" && kw !== "execute" && (WRITE_WORD.test(stripComments(stmt)) || DENIED_FN.test(stmt))) return "statement refused by the write filter";
  }
  return undefined;
}

async function handle(args: Record<string, unknown>): Promise<Reply> {
  const sql = args.sql;
  if (typeof sql !== "string") return fail("sql must be a string");
  switch (mode) {
    case "sticky":
      return safeQuery(sql);
    case "explainok":
      if (/^\s*explain\b/i.test(sql)) {
        try {
          return await run(await client(), sql);
        } catch (e) {
          return fail(message(e));
        }
      }
      return safeQuery(sql);
    case "selectlist": {
      if (WRITE_WORD.test(sql)) return fail("write statements are not allowed");
      if (SELECT_LIST_CALL.test(sql)) return fail("function calls in the select list are not allowed");
      try {
        return await run(await client(), sql);
      } catch (e) {
        return fail(message(e));
      }
    }
    case "pooled": {
      const why = pooledAllows(sql);
      if (why) return fail(why);
      // A new connection for every call: nothing a statement sets up survives into the next call.
      const c = new pg.Client({ connectionString: dsn, statement_timeout: Math.round(timeoutSec * 1000) });
      c.on("error", () => {});
      try {
        await c.connect();
        return await run(c, sql);
      } catch (e) {
        return fail(message(e));
      } finally {
        await c.end().catch(() => {});
      }
    }
  }
}

const tools = [
  {
    name: "query",
    description: "Run a read-only SQL query against the database and return the rows as JSON.",
    inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "SQL text to run" } }, required: ["sql"] },
  },
];
const server = new Server({ name: `sealmark-toy-policy-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  try {
    if (req.params.name !== "query") return fail(`unknown tool ${req.params.name}`);
    return await handle((req.params.arguments ?? {}) as Record<string, unknown>);
  } catch (e) {
    if (e instanceof McpError) throw e;
    return fail(message(e));
  }
});

// Exit when the client goes away so no pg connection keeps the process alive.
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
