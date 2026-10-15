// Round 5, package sql, items sql-6 and sql-7: other required parameters of a SQL tool, sql_tools[].args, and classification by server evidence.
//   toy/db-extraparam --mode enum    run_query(sql, database enum, format string), all required   -> detected, filled, graded
//   toy/db-extraparam --mode name    run_query(sql, database) where the token is not a database   -> listed with the sql_tools args remedy; graded with args
//   toy/db-extraparam --mode export  run_sql(query) beside export_results(query)                   -> both detected (the sibling rule)
import assert from "node:assert/strict";
import { after, before, describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { TemplateCtx } from "../config.js";
import { type EmbeddedHandle } from "../embedded.js";
import { McpSession, type ToolInfo } from "../mcp.js";
import { runDb } from "../packs/db.js";
import { callSql, discoverSqlTools, otherParams, sqlArgsFor } from "../packs/shared.js";
import { ROLES, provision, roleDsn, type PgTarget, type Role } from "../seed.js";
import type { CheckResult, SqlTool } from "../types.js";
import { freePort, quiet, startAllEmbedded } from "./helpers.js";

const TOY = fileURLToPath(new URL("../toy/db-extraparam.js", import.meta.url));
const TIMEOUT_SEC = 3;

const tool = (name: string, description: string, properties: Record<string, Record<string, unknown>>, required: string[] = Object.keys(properties)): ToolInfo => ({
  name,
  description,
  inputSchema: { type: "object", properties, required },
});
const str = (d = "") => ({ type: "string", description: d });

describe("other required parameters: what the harness fills, and what it cannot", () => {
  it("fills an enum with its first value, a string with a token, a number with its minimum or 1, a boolean with false; a default or a const wins", () => {
    const def = tool("q", "Run SQL", {
      sql: str(),
      db: { type: "string", enum: ["main", "archive"] },
      fmt: str(),
      limit: { type: "integer" },
      min: { type: "number", minimum: 5 },
      flag: { type: "boolean" },
      mode: { type: "string", default: "fast" },
      kind: { type: "string", const: "sql" },
    });
    const o = otherParams(def, "sql", undefined);
    assert.deepEqual(o.values, { db: "main", fmt: "sm-fill", limit: 1, min: 5, flag: false, mode: "fast", kind: "sql" });
    assert.deepEqual(o.placeholders, ["db", "fmt", "limit", "min", "flag"], "a default and a const are the server's own values, not placeholders");
    assert.deepEqual(o.unfillable, []);
  });

  it("an entry's args override every filler, and a required array or object cannot be filled", () => {
    const def = tool("q", "Run SQL", { sql: str(), db: { type: "string", enum: ["main"] }, ids: { type: "array", items: { type: "string" } } });
    const o = otherParams(def, "sql", undefined, { db: "archive" });
    assert.deepEqual(o.values, { db: "archive" });
    assert.deepEqual(o.placeholders, []);
    assert.deepEqual(o.unfillable, ["ids"]);
  });

  it("discovery keeps a tool whose other required parameters are fillable, and skips one that has an unfillable one, with the remedy", () => {
    const ok = discoverSqlTools([tool("run_query", "Run SQL", { sql: str(), database: str(), format: { type: "string", enum: ["json", "csv"] } })]);
    assert.deepEqual(ok.tools.map((t) => [t.tool, t.arg]), [["run_query", "sql"]]);
    assert.deepEqual(ok.skipped, []);
    const no = discoverSqlTools([tool("run_query", "Run SQL", { sql: str(), tables: { type: "array", items: { type: "string" } } })]);
    assert.equal(no.tools.length, 0);
    assert.match(no.skipped[0].reason, /^also requires tables, which the harness cannot fill in/);
    assert.match(no.skipped[0].reason, /set sql_tools: \[\{tool: "run_query", arg: "sql", args: \{\.\.\.\}\}\]/);
  });

  it("callSql sends the fillers, an entry's args win, the approval flag is false, and the evidence shows what was sent", async () => {
    const sent: [string, Record<string, unknown>][] = [];
    const defs = [tool("run_query", "x", { sql: str(), database: str(), format: { type: "string", enum: ["json"] }, confirm: { type: "boolean" } })];
    const session = {
      tools: defs,
      call: async (name: string, args: Record<string, unknown>) => {
        sent.push([name, args]);
        return { isError: false, text: "", elapsedMs: 0, timedOut: false, closed: false };
      },
    } as unknown as Parameters<typeof callSql>[0];
    const plain: SqlTool = { tool: "run_query", arg: "sql", approvalParam: "confirm" };
    await callSql(session, plain, "SELECT 1");
    assert.deepEqual(sent[0], ["run_query", { sql: "SELECT 1", database: "sm-fill", format: "json", confirm: false }]);
    assert.deepEqual(sqlArgsFor(plain, "SELECT 1"), { sql: "SELECT 1", database: "sm-fill", format: "json" }, "the evidence carries the filled arguments, not the approval flag");
    const given = { tool: "run_query", arg: "sql", approvalParam: "confirm", args: { database: "warehouse", confirm: true, sql: "DROP TABLE x", extra: 7 } } as SqlTool;
    await callSql(session, given, "SELECT 2");
    assert.deepEqual(sent[1], ["run_query", { sql: "SELECT 2", database: "warehouse", format: "json", extra: 7, confirm: false }], "args override the filler; neither the SQL argument nor the approval flag can be set through them");
  });
});

describe("classification by server evidence (a pure rule over ToolInfo)", () => {
  it("a lookup tool whose prose says 'select libraries' is not SQL: the verbs count only in the tool name and the argument's own description", () => {
    const lookup = tool("find_package", "Search the catalog. Use this to select libraries by name.", { query: str("what to look for") });
    const r = discoverSqlTools([lookup]);
    assert.equal(r.tools.length, 0);
    assert.match(r.skipped[0].reason, /not clearly SQL/);
    // The verbs still count where they say what the argument is.
    assert.equal(discoverSqlTools([tool("lookup", "Looks things up", { query: str("A SELECT statement") })]).tools[0]?.arg, "query");
    assert.equal(discoverSqlTools([tool("select_rows", "Looks things up", { query: str() })]).tools[0]?.arg, "query");
    // And the database words count anywhere.
    assert.equal(discoverSqlTools([tool("lookup", "Reads from the sqlite file", { query: str() })]).tools[0]?.arg, "query");
  });

  it("a query tool that exports results is SQL when a sibling tool took the same argument name; alone, it is not", () => {
    const sibling = tool("run_sql", "Run a read-only SQL query against the database", { query: str("SQL text") });
    const exporter = tool("export_results", "Runs the query and exports the results in the chosen format.", { query: str("The query to run; its results are exported") });
    const both = discoverSqlTools([sibling, exporter]);
    assert.deepEqual(both.tools.map((t) => [t.tool, t.arg, t.role]), [["run_sql", "query", "reader"], ["export_results", "query", "unknown"]]);
    assert.deepEqual(both.skipped, []);
    const alone = discoverSqlTools([exporter]);
    assert.equal(alone.tools.length, 0);
    assert.match(alone.skipped[0].reason, /not clearly SQL/);
  });

  it("the sibling rule needs the same argument name and a description that talks about results, rows, an export or a format", () => {
    const sibling = tool("run_sql", "Run a read-only SQL query against the database", { query: str("SQL text") });
    const otherName = tool("export_results", "Runs the query and exports the results.", { statement: str("what to run") });
    assert.equal(discoverSqlTools([sibling, otherName]).tools.length, 1, "a different argument name is not the same server evidence");
    const silent = tool("web_find", "Find pages on the web.", { query: str("search terms") });
    assert.equal(discoverSqlTools([sibling, silent]).tools.length, 1, "nothing about results, rows, an export or a format: still not SQL");
    const rows = tool("fetch_rows", "Returns matching rows.", { query: str("filter") });
    assert.equal(discoverSqlTools([sibling, rows]).tools.length, 2);
  });
});

async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

async function viaRunDb(target: PgTarget, mode: string, explicit?: SqlTool[]): Promise<{ checks: CheckResult[]; found: SqlTool[] }> {
  await provision(target);
  const spec = { command: process.execPath, args: [TOY, "--mode", mode, "--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)], env: {} };
  const tctx = (role: Role): TemplateCtx => ({ vars: { dsn: roleDsn(target, role) }, dsns: Object.fromEntries(ROLES.map((r) => [r, roleDsn(target, r)])) });
  const open = (role: Role) => McpSession.open(spec, tctx(role), {});
  const probe = await open("admin");
  const found = discoverSqlTools(probe.tools, explicit).tools;
  await probe.close();
  return { checks: await runDb({ target, sqlTools: found, open, timeoutSec: TIMEOUT_SEC, log: quiet }), found };
}

const handles: EmbeddedHandle[] = [];
const runs: Record<string, { checks: CheckResult[]; found: SqlTool[] }> = {};
let skipReason: string | undefined;

describe("db pack against toy/db-extraparam (embedded Postgres)", { timeout: 600_000 }, () => {
  before(async () => {
    if (process.env.SEALMARK_SKIP_DB === "1") {
      skipReason = "SEALMARK_SKIP_DB=1";
      return;
    }
    const ports = await distinctPorts(2);
    await startAllEmbedded(handles, ports);
    const [a, b] = handles.map((h) => h.target);
    await Promise.all([
      (async () => {
        runs.enum = await viaRunDb(a, "enum");
        runs.name = await viaRunDb(a, "name");
        runs.nameArgs = await viaRunDb(a, "name", [{ tool: "run_query", arg: "sql", args: { database: "warehouse" } } as SqlTool]);
      })(),
      (async () => {
        runs.export = await viaRunDb(b, "export");
      })(),
    ]);
  }, { timeout: 420_000 });

  after(async () => {
    for (const h of handles) await h.stop();
  });

  const skip = (t: TestContext) => {
    if (skipReason) t.skip(skipReason);
    return Boolean(skipReason);
  };
  const check = (mode: string, id: string) => runs[mode].checks.find((c) => c.id === id)!;

  it("enum: a required enum and a required string are filled, so the tool is detected and graded as a read-only reader", (t) => {
    if (skip(t)) return;
    assert.deepEqual(runs.enum.found.map((s) => s.tool), ["run_query"]);
    for (const id of ["read-only", "mutating-sql", "rls", "pii"]) assert.equal(check("enum", id).verdict, "pass", `${id}: ${check("enum", id).summary}`);
    const ro = check("enum", "read-only");
    const e = ro.evidence.find((x) => x.code === "db.control.reader");
    assert.equal((e?.args as { database?: string }).database, "main", "the evidence shows the filled arguments");
    assert.equal((e?.args as { format?: string }).format, "sm-fill");
    assert.deepEqual(ro.coverage?.notCovered, []);
  });

  it("name: the token is not a database, so the tool is listed with the remedy and the summary quotes the server's reply, not the connection string", (t) => {
    if (skip(t)) return;
    const m = check("name", "mutating-sql");
    assert.equal(m.verdict, "inconclusive");
    assert.match(m.summary, /unknown database "sm-fill": no such database on this server/);
    assert.match(m.summary, /filled in as a placeholder/);
    assert.match(m.summary, /set sql_tools: \[\{tool: "run_query", arg: "sql", args: \{database: <value>\}\}\]/);
    assert.doesNotMatch(m.summary, /connection string/);
    assert.ok(m.coverage?.notCovered.some((n) => n.tool === "run_query" && /database="sm-fill" filled in as a placeholder/.test(n.reason)), JSON.stringify(m.coverage));
  });

  it("name with sql_tools args: the same tool is graded", (t) => {
    if (skip(t)) return;
    for (const id of ["read-only", "mutating-sql", "rls", "pii"]) assert.equal(check("nameArgs", id).verdict, "pass", `${id}: ${check("nameArgs", id).summary}`);
    const e = check("nameArgs", "read-only").evidence.find((x) => x.code === "db.control.reader");
    assert.equal((e?.args as { database?: string }).database, "warehouse");
    assert.deepEqual(check("nameArgs", "read-only").coverage?.notCovered, []);
  });

  it("export: the tool that exports results is detected beside run_sql and both are graded", (t) => {
    if (skip(t)) return;
    assert.deepEqual(runs.export.found.map((s) => s.tool).sort(), ["export_results", "run_sql"]);
    assert.deepEqual(check("export", "mutating-sql").coverage?.probed.sort(), ["export_results", "run_sql"]);
    assert.equal(check("export", "mutating-sql").verdict, "pass");
  });
});
