import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { ToolInfo } from "../mcp.js";
import { describe as describeCore } from "../packs/core.js";
import { FALLBACK_SLOW_SQL, MUTATION_CORPUS, describe as describeDb, runDb } from "../packs/db.js";
import {
  PG_ERROR,
  PLAN_MARKER,
  REFUSAL,
  approvalParamOf,
  callSql,
  coverageNotes,
  discoverSqlTools,
  enforcer,
  enrichSqlTools,
  isLoopbackHostname,
  listenerReachable,
  refused,
  refusedInTextOnly,
  roleOf,
} from "../packs/shared.js";
import type { CheckResult } from "../types.js";

// Pure tests: no database and no server process, so they run under SEALMARK_SKIP_DB too.

describe("listenerReachable", () => {
  it("a stdio server (no url) shares this machine's loopback", () => {
    assert.deepEqual(listenerReachable({}), { ok: true });
    assert.deepEqual(listenerReachable(undefined), { ok: true });
    assert.deepEqual(listenerReachable({ url: null }), { ok: true });
  });
  it("an HTTP server is reachable only when its URL names this machine", () => {
    for (const u of ["http://127.0.0.1:3000/mcp", "http://localhost/mcp", "https://[::1]:8443/mcp", "http://app.localhost/mcp"]) assert.deepEqual(listenerReachable({ url: u }), { ok: true }, u);
    for (const u of ["https://mcp.example.net/mcp", "http://10.0.0.5:3000/mcp", "http://169.254.169.254/", "http://192.168.1.2/mcp"]) {
      const r = listenerReachable({ url: u });
      assert.equal(r.ok, false, u);
    }
    assert.deepEqual(listenerReachable({ url: "https://mcp.example.net/mcp" }), { ok: false, host: "mcp.example.net" });
    const bad = listenerReachable({ url: "https://user:hunter2@not a url" });
    assert.equal(bad.ok, false);
    assert.ok(!bad.ok && !bad.host.includes("hunter2"), "an unparseable URL is never echoed (it can carry credentials)");
    // ${VAR} references are filled in before parsing, as they are when the session opens.
    assert.deepEqual(listenerReachable({ url: "http://localhost:${PORT}/mcp" }, { PORT: "3000" }), { ok: true });
    assert.deepEqual(listenerReachable({ url: "https://${HOST_NAME}/mcp" }, { HOST_NAME: "mcp.example.net" }), { ok: false, host: "mcp.example.net" });
    assert.equal(listenerReachable({ url: "http://localhost:${PORT}/mcp" }, {}).ok, true, "an unset variable becomes empty: the host is still localhost");
    assert.equal(isLoopbackHostname("127.0.0.2"), true);
    assert.equal(isLoopbackHostname("localhost.evil.example"), false);
  });
});

const tool = (name: string, description: string, properties: Record<string, Record<string, unknown>>, required: string[] = Object.keys(properties)): ToolInfo => ({
  name,
  description,
  inputSchema: { type: "object", properties, required },
});
const str = (d = "") => ({ type: "string", description: d });

describe("SQL tool discovery (addendum 1.1 table)", () => {
  it("a string param named sql, sql_query, sqlquery or query_sql is SQL on its own", () => {
    for (const arg of ["sql", "sql_query", "sqlquery", "query_sql"]) {
      const { tools } = discoverSqlTools([tool("t", "does a thing", { [arg]: str() })]);
      assert.deepEqual(tools.map((t) => [t.tool, t.arg, t.shape]), [["t", arg, "string"]], arg);
    }
  });

  it("query, statement and q need a SQL hint in the tool name, its description or the parameter's own description", () => {
    const none = discoverSqlTools([tool("lookup", "Looks things up", { query: str("what to look for") })]);
    assert.equal(none.tools.length, 0);
    assert.match(none.skipped[0].reason, /not clearly SQL/);
    assert.doesNotMatch(none.skipped[0].reason, /sql_tools/, "a tool that does not talk like a database is not told to list itself under sql_tools");
    const dbish = discoverSqlTools([tool("lookup", "Looks up records in the data warehouse", { query: str("what to look for") })]);
    assert.equal(dbish.tools.length, 0);
    assert.match(dbish.skipped[0].reason, /not clearly SQL.*list it under sql_tools to include it/);
    const inParam = discoverSqlTools([tool("lookup", "Looks things up", { query: str("The SQL to execute") })]);
    assert.equal(inParam.tools[0]?.arg, "query");
    const inDesc = discoverSqlTools([tool("lookup", "Reads from the postgres cluster", { statement: str() })]);
    assert.equal(inDesc.tools[0]?.arg, "statement");
    const q = discoverSqlTools([tool("lookup", "Runs against the sqlite file", { q: str() })]);
    assert.equal(q.tools[0]?.arg, "q");
    const search = discoverSqlTools([tool("web_search", "Search the web", { query: str("search terms") })]);
    assert.equal(search.tools.length, 0);
  });

  it("underscores in a tool name do not hide the hint (run_sql has no word boundary for a plain \\bsql\\b)", () => {
    const { tools } = discoverSqlTools([tool("run_sql", "Run", { query: str() })]);
    assert.equal(tools[0]?.arg, "query");
  });

  it("a read/write/run/execute _query or _sql tool name makes its only string param SQL", () => {
    assert.equal(discoverSqlTools([tool("read_query", "Go", { text: str() })]).tools[0]?.arg, "text");
    assert.equal(discoverSqlTools([tool("execute_sql", "Go", { text: str() })]).tools[0]?.arg, "text");
    assert.equal(discoverSqlTools([tool("run_query", "Go", { text: str(), other: str() })]).tools.length, 0);
    assert.equal(discoverSqlTools([tool("search_query", "Go", { text: str() })]).tools.length, 0);
  });

  it("an array of strings named queries, statements, sqls or sql is SQL with shape array", () => {
    for (const arg of ["queries", "statements", "sqls", "sql"]) {
      const { tools } = discoverSqlTools([tool("batch", "Go", { [arg]: { type: "array", items: { type: "string" } } })]);
      assert.deepEqual(tools.map((t) => [t.arg, t.shape]), [[arg, "array"]], arg);
    }
    assert.equal(discoverSqlTools([tool("batch", "Go", { queries: { type: "array", items: { type: "number" } } })]).tools.length, 0);
  });

  it("a shell command tool is never SQL", () => {
    assert.equal(discoverSqlTools([tool("run_shell", "Run a shell command", { command: str() })]).tools.length, 0);
  });

  it("roles come from the name and description: writers, readers, unknown", () => {
    assert.equal(roleOf(tool("write_query", "Execute INSERT, UPDATE, or DELETE queries", {})), "writer");
    assert.equal(roleOf(tool("read_query", "Execute SELECT queries", {})), "reader");
    assert.equal(roleOf(tool("create_table", "Create a table", {})), "writer");
    assert.equal(roleOf(tool("query", "Run a read-only SQL query", {})), "reader");
    // A tool that says both is not called a writer: the controls decide.
    assert.equal(roleOf(tool("query", "Execute SELECT or INSERT statements", {})), "reader");
    assert.equal(roleOf(tool("query", "Run any SQL statement", {})), "unknown");
  });

  it("a boolean confirm-style param is the approval param, and a required one does not make the tool unprobeable", () => {
    const t = tool("write_query", "Execute INSERT, UPDATE, or DELETE queries", { sql: str(), confirm: { type: "boolean" } });
    assert.equal(approvalParamOf(t), "confirm");
    const { tools, skipped } = discoverSqlTools([t]);
    assert.deepEqual(skipped, []);
    assert.deepEqual(tools[0], { tool: "write_query", arg: "sql", role: "writer", shape: "string", approvalParam: "confirm" });
    for (const name of ["approve", "approved", "dry_run", "force", "allow_write", "allow_writes"]) assert.equal(approvalParamOf(tool("t", "x", { sql: str(), [name]: { type: "boolean" } })), name);
    assert.equal(approvalParamOf(tool("t", "x", { sql: str(), confirm: str() })), undefined, "only a boolean counts");
  });

  it("other required arguments the harness can fill (a string, an enum) keep the tool; one it cannot fill skips it, with the reason (round 5)", () => {
    const filled = discoverSqlTools([tool("q", "Run SQL", { sql: str(), database: str() })]);
    assert.equal(filled.tools.length, 1);
    assert.deepEqual(filled.skipped, []);
    const { tools, skipped } = discoverSqlTools([tool("q", "Run SQL", { sql: str(), options: { type: "object" } })]);
    assert.equal(tools.length, 0);
    assert.match(skipped[0].reason, /also requires options/);
  });

  it("explicit sql_tools win; missing role, shape and approvalParam are filled from the schema", () => {
    const defs = [tool("run_queries", "Run read-only SQL queries", { queries: { type: "array", items: { type: "string" } } }), tool("w", "Execute INSERT queries", { sql: str(), approve: { type: "boolean" } })];
    const { tools, skipped } = discoverSqlTools(defs, [{ tool: "run_queries", arg: "queries" }, { tool: "w", arg: "sql" }, { tool: "gone", arg: "sql" }]);
    assert.deepEqual(skipped, []);
    assert.deepEqual(tools[0], { tool: "run_queries", arg: "queries", role: "reader", shape: "array" });
    assert.deepEqual(tools[1], { tool: "w", arg: "sql", role: "writer", shape: "string", approvalParam: "approve" });
    assert.deepEqual(tools[2], { tool: "gone", arg: "sql" }, "a tool the server does not declare is returned unchanged");
    // An explicit entry that sets a role keeps it.
    assert.equal(enrichSqlTools([{ tool: "w", arg: "sql", role: "reader" }], defs)[0].role, "reader");
  });

  it("callSql sends [sql] for array tools and a false approval flag only when the tool requires one", async () => {
    const sent: unknown[] = [];
    const session = {
      tools: [tool("a", "x", { queries: { type: "array", items: { type: "string" } } }), tool("w", "x", { sql: str(), confirm: { type: "boolean" } }, ["sql", "confirm"]), tool("o", "x", { sql: str(), confirm: { type: "boolean" } }, ["sql"])],
      call: async (name: string, args: Record<string, unknown>) => {
        sent.push([name, args]);
        return { isError: false, text: "", elapsedMs: 0, timedOut: false, closed: false };
      },
    };
    const s = session as unknown as Parameters<typeof callSql>[0];
    await callSql(s, { tool: "a", arg: "queries", shape: "array" }, "SELECT 1");
    await callSql(s, { tool: "w", arg: "sql", approvalParam: "confirm" }, "SELECT 1");
    await callSql(s, { tool: "o", arg: "sql", approvalParam: "confirm" }, "SELECT 1");
    assert.deepEqual(sent, [["a", { queries: ["SELECT 1"] }], ["w", { sql: "SELECT 1", confirm: false }], ["o", { sql: "SELECT 1" }]]);
  });
});

describe("refusal detection (addendum 1.3)", () => {
  it("plain-text refusals at the start of the response count", () => {
    for (const t of [
      "Error: only SELECT is allowed",
      "[ERROR] bad query",
      "ERR - nope",
      "Refused: writes are disabled",
      "Rejected by policy",
      "Only SELECT statements are allowed",
      "Invalid argument: sql",
      "Validation failed",
      "Cannot run DDL",
      "can't run that",
      "Unable to execute",
      "Not allowed",
      "Not permitted for this role",
      "  \n Blocked by the filter",
    ]) {
      assert.ok(REFUSAL.test(t), t);
      assert.ok(refusedInTextOnly({ isError: false, text: t }), t);
    }
  });

  it("a data row that merely contains the word error never counts", () => {
    for (const t of ['[{"note":"error budget"}]', "1\tsome error handling guide\tx", "ok: 0 errors", "Errors: 0", "No error occurred", "42 rows returned"]) {
      assert.equal(REFUSAL.test(t), false, t);
      assert.equal(refused({ isError: false, text: t }), false, t);
    }
  });

  it("only the first 300 characters are looked at", () => {
    assert.equal(refused({ isError: false, text: `${"x".repeat(300)} Error: late` }), false);
    assert.equal(refused({ isError: false, text: `${"x".repeat(10)} Error: late` }), false, "anchored: the refusal has to start the response");
  });

  it("isError and a JSON-RPC error are refusals whatever they say", () => {
    assert.equal(refused({ isError: true, text: "fine" }), true);
    assert.equal(refused({ isError: false, text: "", rpcError: "MCP error -32602" }), true);
    assert.equal(refusedInTextOnly({ isError: true, text: "Error: x" }), false, "isError is visible to clients, so it is not a text-only refusal");
  });

  it("PG_ERROR names errors the database raised, PLAN_MARKER names an EXPLAIN plan", () => {
    for (const t of ["ERROR: permission denied for table customers", "permission denied for view v", "new row violates row-level security policy", "SQLSTATE 42501", "code 42501", "Error: permission denied for table customers"]) assert.ok(PG_ERROR.test(t), t);
    assert.equal(PG_ERROR.test("Error: only read statements are allowed"), false);
    assert.equal(PG_ERROR.test("[]"), false);
    for (const t of ["QUERY PLAN\n------", "Seq Scan on customers", "Index Scan using x", "Result  (cost=0.00..0.02 rows=1 width=36)"]) assert.ok(PLAN_MARKER.test(t), t);
    assert.equal(PLAN_MARKER.test("sm-ctl-1\t100\tsm_admin"), false);
  });

  it("enforcer: a database error or silent filtering is database-enforced, a server refusal is server-enforced", () => {
    assert.equal(enforcer({ isError: true, text: "permission denied for table customers" }), "database");
    assert.equal(enforcer({ isError: false, text: "Error: permission denied for table customers" }), "database");
    assert.equal(enforcer({ isError: false, text: "[]" }), "database");
    assert.equal(enforcer({ isError: false, text: "Error: this table is not available" }), "server");
    assert.equal(enforcer({ isError: true, text: "table is hidden" }), "server");
  });
});

describe("coverage notes and check docs", () => {
  const check = (pack: string, notCovered: { tool: string; reason: string }[]): CheckResult => ({
    id: "x",
    pack: pack as CheckResult["pack"],
    label: "x",
    critical: false,
    scope: "server",
    verdict: "pass",
    summary: "",
    evidence: [],
    coverage: { probed: [], notCovered },
  });

  it("RunResult lines name tools no control could reach and leave out declared writers the write checks did exercise", () => {
    const notes = coverageNotes(
      [check("db", [{ tool: "create_table", reason: "neither control succeeded" }, { tool: "write_query", reason: "declared writer tool: read probes do not apply" }]), check("db", [{ tool: "create_table", reason: "neither control succeeded" }]), check("core", [{ tool: "ping", reason: "needs probes: to be called" }])],
      "db",
    );
    assert.deepEqual(notes, ['tool "create_table" was not covered by the db pack: neither control succeeded']);
    assert.deepEqual(coverageNotes([check("core", [{ tool: "ping", reason: "needs probes: to be called" }])], "core"), ['tool "ping" was not covered by the core pack: needs probes: to be called']);
  });

  it("describe(): every core and db check id is documented once, cap-timeout is retired and recorded under replaces", () => {
    const core = describeCore();
    const db = describeDb();
    assert.deepEqual(core.map((d) => d.id), ["protocol", "tool-poisoning", "robust-input", "secret-echo", "refusal-quality", "instructions-hygiene"]);
    assert.deepEqual(db.map((d) => d.id), ["read-only", "write-gate", "rls", "mutating-sql", "pii", "pii-masked", "db-rowcap", "db-timeout", "audit", "db-privilege"]);
    const ids = [...core, ...db].map((d) => d.id);
    assert.equal(new Set(ids).size, ids.length);
    assert.ok(!ids.includes("cap-timeout"));
    for (const id of ["db-rowcap", "db-timeout"]) assert.deepEqual(db.find((d) => d.id === id)?.replaces, ["cap-timeout"]);
    assert.equal(db.find((d) => d.id === "db-rowcap")?.thresholds.row_cap.default, 10000);
    assert.equal(db.find((d) => d.id === "db-timeout")?.thresholds.expected_sec.configKey, "checks.db-timeout.expected_sec");
    assert.equal(db.find((d) => d.id === "pii-masked")?.since, "0.2-draft");
    assert.equal(db.find((d) => d.id === "write-gate")?.advisory, true);
    for (const d of [...core, ...db]) {
      assert.match(d.scope, /^(server|database|environment)/, d.id);
      assert.ok(d.verifiedBy.length > 0, d.id);
      assert.ok(d.falsePositive.length > 0 && d.falseNegative.length > 0, d.id);
      assert.ok(d.configKeys.length > 0, d.id);
    }
  });

  it("the published mutation corpus labels the side-effect function case and groups it as indirect-fn", () => {
    const fn = MUTATION_CORPUS.find((c) => c.kind === "indirect-fn");
    assert.equal(fn?.id, "function with side effects (defeats any prefix filter by construction)");
    assert.equal(fn?.core, false, "weight unchanged: it is a non-core case");
    assert.equal(MUTATION_CORPUS.filter((c) => c.core).length, 7);
    assert.equal(MUTATION_CORPUS.length, 19);
    const doc = describeDb().find((d) => d.id === "mutating-sql")!;
    assert.equal(doc.probes.length, 19);
    assert.ok(doc.probes.some((p) => p.kind === "indirect-fn"));
    assert.equal(describeDb().find((d) => d.id === "db-timeout")?.probes.some((p) => p.text === FALLBACK_SLOW_SQL), true);
  });
});

describe("db pack options", () => {
  it("checks.db-timeout.slow_sql must be a SELECT: anything else is refused before a database is touched", async () => {
    const never = async () => {
      throw new Error("should not be reached");
    };
    for (const slowSql of ["DELETE FROM probe_t", "  insert into x values (1)", "DROP TABLE big_table"]) {
      await assert.rejects(runDb({ target: {} as never, sqlTools: [], open: never, timeoutSec: 1, log() {}, slowSql }), /must be a SELECT/, slowSql);
    }
  });
});
