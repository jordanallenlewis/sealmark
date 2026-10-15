// Toy SQLite MCP servers used to test the sqlite pack. Each mode enforces (or fails to enforce) a different set of controls.
// Run: node dist/toy/sqlite.js --mode <m> --db <path> [--timeout <sec=3>]
// Not part of the product surface; the expected grade for every mode is in the design notes
//
// good     read-only connection + an authorizer that denies ATTACH (which also covers VACUUM INTO), DETACH, PRAGMA writes and
//          the load_extension function; 1,000-row cap; every query runs in a child process that is killed at --timeout
// ro       read-only connection and nothing else (the "mode=ro" pattern); cap and timeout present
// filter   read-write; accepts only text starting with select|with|pragma|explain; extension loading enabled; no cap, no timeout
// open     read-write, any text (stacked statements run), extension loading enabled; no cap, no timeout
// writers  read_query (SELECT prefix check) and write_query (anything) on one read-write connection; no cap, no timeout
// planner  returns EXPLAIN QUERY PLAN for whatever it is given, so the control read cannot succeed
//
// The good mode needs setAuthorizer (Node 24.10 or newer); the test skips it with a reason on older Node.
// The database is opened on the first query, not at startup, so a discovery session that runs before the fixture exists still works.
//
// A child process rather than a worker thread on purpose: worker.terminate() cannot interrupt a thread that is inside
// sqlite3_step, and the stalled thread blocks the main thread at the next garbage collection. Killing a process always works.
import { fork, type ChildProcess } from "node:child_process";
import { constants, DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const SQLITE_TOY_MODES = ["good", "ro", "filter", "open", "writers", "planner"] as const;
type Mode = (typeof SQLITE_TOY_MODES)[number];

const ROW_CAP = 1000;

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const { values } = parseArgs({
  options: { mode: { type: "string" }, db: { type: "string" }, timeout: { type: "string" }, engine: { type: "boolean" } },
  strict: true,
});
const mode = values.mode as Mode;
function usage(msg: string): never {
  process.stderr.write(`sqlite toy: ${msg}\nusage: sqlite.js --mode <${SQLITE_TOY_MODES.join("|")}> --db <path> [--timeout <sec>]\n`);
  process.exit(2);
}
if (!SQLITE_TOY_MODES.includes(mode)) usage(`--mode must be one of ${SQLITE_TOY_MODES.join(", ")}`);
if (!values.db) usage("--db is required");
const dbPath = values.db;
const timeoutSec = values.timeout === undefined ? 3 : Number(values.timeout);
if (!(timeoutSec > 0)) usage("--timeout must be a positive number of seconds");

// ---------------------------------------------------------------------------------------------------------
// The engine: one connection, configured per mode
// ---------------------------------------------------------------------------------------------------------

/** Pragmas the `good` mode lets through: introspection (with a table argument) and plain reads. A pragma that sets a value is a write. */
const ARG_PRAGMAS = new Set(["table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list"]);
const PLAIN_PRAGMAS = new Set(["table_list", "user_version", "journal_mode"]);

function connect(m: Mode, path: string): DatabaseSync {
  if (m === "good" || m === "ro") {
    const db = new DatabaseSync(path, { readOnly: true });
    if (m === "good") {
      db.setAuthorizer((code, a1, a2) => {
        if (code === constants.SQLITE_ATTACH || code === constants.SQLITE_DETACH) return constants.SQLITE_DENY;
        if (code === constants.SQLITE_FUNCTION && a2 === "load_extension") return constants.SQLITE_DENY;
        if (code === constants.SQLITE_PRAGMA) {
          const name = String(a1);
          return ARG_PRAGMAS.has(name) || (PLAIN_PRAGMAS.has(name) && a2 === null) ? constants.SQLITE_OK : constants.SQLITE_DENY;
        }
        return constants.SQLITE_OK;
      });
    }
    return db;
  }
  if (m === "filter" || m === "open") {
    // A build with extension loading switched on. node:sqlite only exposes the loadExtension() method, never the SQL function,
    // so the function is registered here in front of the method: a load_extension('<path>') call reaches the real loader.
    const db = new DatabaseSync(path, { allowExtension: true });
    db.enableLoadExtension(true);
    db.function("load_extension", (p: unknown) => {
      db.loadExtension(String(p));
      return null;
    });
    return db;
  }
  return new DatabaseSync(path);
}

const FILTER = /^\s*(select|with|pragma|explain)\b/i;

/** Run one statement on `db` the way `m` would. Throws on refusal or engine error. */
function execute(db: DatabaseSync, m: Mode, sql: string, tool: string): string {
  if (m === "filter" && !FILTER.test(sql)) throw new Error("only read statements (select, with, pragma, explain) are allowed");
  if (m === "writers" && tool === "read_query" && !/^\s*select\b/i.test(sql)) throw new Error("only SELECT queries are allowed");
  if (m === "open" && /;\s*\S/.test(sql)) {
    // "anything": stacked statements go to exec(), which runs them all.
    db.exec(sql);
    return "OK";
  }
  const stmt = db.prepare(m === "planner" ? `EXPLAIN QUERY PLAN ${sql}` : sql);
  const capped = m === "good" || m === "ro";
  let rows: unknown[] = [];
  let truncated = false;
  if (capped) {
    for (const row of stmt.iterate()) {
      if (rows.length >= ROW_CAP) {
        truncated = true;
        break;
      }
      rows.push(row);
    }
  } else {
    rows = stmt.all();
  }
  const body = JSON.stringify(rows, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
  return truncated ? `${body}\n-- truncated at ${ROW_CAP} rows` : body;
}

// ---------------------------------------------------------------------------------------------------------
// Child process (modes good and ro): the connection lives here so the parent can kill it at the timeout
// ---------------------------------------------------------------------------------------------------------

if (values.engine) {
  let db: DatabaseSync | undefined;
  process.on("disconnect", () => process.exit(0));
  process.on("message", (msg: { id: number; sql: string; tool: string }) => {
    let out: { id: number; ok: boolean; text: string };
    try {
      db ??= connect(mode, dbPath);
      out = { id: msg.id, ok: true, text: execute(db, mode, msg.sql, msg.tool) };
    } catch (e) {
      out = { id: msg.id, ok: false, text: message(e) };
    }
    process.send?.(out);
  });
  // Stay alive and wait for messages.
  setInterval(() => {}, 1 << 30);
} else {
  await serve();
}

async function serve(): Promise<void> {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

  let local: DatabaseSync | undefined;
  let child: ChildProcess | undefined;
  let nextId = 1;
  const waiting = new Map<number, (r: { ok: boolean; text: string }) => void>();

  const startChild = (): ChildProcess => {
    if (child) return child;
    const c = fork(fileURLToPath(import.meta.url), ["--engine", "--mode", mode, "--db", dbPath], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
    c.on("message", (m: { id: number; ok: boolean; text: string }) => {
      waiting.get(m.id)?.(m);
      waiting.delete(m.id);
    });
    c.on("exit", () => {
      if (child === c) child = undefined;
      for (const [id, done] of waiting) {
        waiting.delete(id);
        done({ ok: false, text: "the query engine process exited" });
      }
    });
    child = c;
    return c;
  };

  async function viaChild(sql: string, tool: string): Promise<Reply> {
    const c = startChild();
    const id = nextId++;
    const result = await new Promise<{ ok: boolean; text: string }>((resolve) => {
      const timer = setTimeout(() => {
        waiting.delete(id);
        // Killing the process is the only way to stop a statement that is inside the engine.
        if (child === c) child = undefined;
        c.kill("SIGKILL");
        resolve({ ok: false, text: `query timed out after ${timeoutSec}s and was cancelled` });
      }, timeoutSec * 1000);
      waiting.set(id, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      c.send({ id, sql, tool });
    });
    return result.ok ? ok(result.text) : fail(result.text);
  }

  function inProcess(sql: string, tool: string): Reply {
    try {
      local ??= connect(mode, dbPath);
      return ok(execute(local, mode, sql, tool));
    } catch (e) {
      return fail(message(e));
    }
  }

  const sqlTool = (name: string, description: string) => ({
    name,
    description,
    inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "SQL text to run" } }, required: ["sql"] },
  });

  const tools =
    mode === "writers"
      ? [sqlTool("read_query", "Execute SELECT queries to read data from the SQLite database"), sqlTool("write_query", "Execute INSERT, UPDATE, or DELETE queries on the SQLite database")]
      : mode === "good" || mode === "ro"
        ? [sqlTool("query", "Run a read-only SQL query against the SQLite database and return the rows as JSON.")]
        : [sqlTool("query", "Run any SQL statement against the SQLite database and return the rows as JSON.")];

  const server = new Server({ name: `sealmark-toy-sqlite-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    if (!tools.some((t) => t.name === req.params.name)) return fail(`unknown tool ${req.params.name}`);
    if (typeof args.sql !== "string") return fail("sql must be a string");
    return mode === "good" || mode === "ro" ? viaChild(args.sql, req.params.name) : inProcess(args.sql, req.params.name);
  });

  // Exit when the client goes away, taking the engine process with it.
  const bye = () => {
    child?.kill("SIGKILL");
    process.exit(0);
  };
  for (const ev of ["end", "close"] as const) process.stdin.once(ev, bye);
  process.on("exit", () => child?.kill("SIGKILL"));
  await server.connect(new StdioServerTransport());
}
