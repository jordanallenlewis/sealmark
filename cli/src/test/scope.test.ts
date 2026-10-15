import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { loadEffectiveConfig, type LoadOptions } from "../config/index.js";
import type { ToolInfo } from "../mcp.js";
import { discoverSqlTools } from "../packs/shared.js";

// What the grade is a grade OF must not be settable from a file without the run saying so: a setting that hides a tool, or
// switches an engine pack off, either cannot do that or makes the run CUSTOM.

const tool = (name: string, description: string, properties: Record<string, Record<string, unknown>>, required: string[] = Object.keys(properties)): ToolInfo => ({
  name,
  description,
  inputSchema: { type: "object", properties, required },
});
const str = (d = "") => ({ type: "string", description: d });

const READER = tool("read_query", "Run a read-only SQL query against the database", { sql: str() });
const WRITER = tool("write_query", "Execute INSERT, UPDATE and DELETE statements against the database", { sql: str() });
const ODD = tool("lookup", "Looks things up", { stmt: str("what to run") });

describe("an explicit sql_tools list adds and corrects; it never hides a detected tool", () => {
  it("a detected writer the list leaves out is still probed", () => {
    const { tools } = discoverSqlTools([READER, WRITER], [{ tool: "read_query", arg: "sql" }]);
    assert.deepEqual(tools.map((t) => t.tool).sort(), ["read_query", "write_query"]);
    assert.equal(tools.find((t) => t.tool === "write_query")?.role, "writer");
  });

  it("without a list nothing changes, and with an empty list auto-detection still runs", () => {
    assert.deepEqual(discoverSqlTools([READER, WRITER]).tools.map((t) => t.tool).sort(), ["read_query", "write_query"]);
    assert.deepEqual(discoverSqlTools([READER, WRITER], []).tools.map((t) => t.tool).sort(), ["read_query", "write_query"]);
  });

  it("a tool auto-detection cannot place is added by the list, with the argument the list names", () => {
    const { tools, skipped } = discoverSqlTools([READER, ODD], [{ tool: "lookup", arg: "stmt" }]);
    assert.deepEqual(tools.map((t) => [t.tool, t.arg]).sort(), [["lookup", "stmt"], ["read_query", "sql"]]);
    assert.equal(skipped.some((s) => s.tool === "lookup"), false, "a tool the list names is no longer reported as skipped");
  });

  it("a detected writer cannot be relabelled a reader; a reader can be marked a writer", () => {
    const relabelled = discoverSqlTools([READER, WRITER], [{ tool: "write_query", arg: "sql", role: "reader" }]).tools;
    assert.equal(relabelled.find((t) => t.tool === "write_query")?.role, "writer");
    const marked = discoverSqlTools([READER, WRITER], [{ tool: "read_query", arg: "sql", role: "writer" }]).tools;
    assert.equal(marked.find((t) => t.tool === "read_query")?.role, "writer");
  });

  it("the classification of the unlisted tool is unchanged by the list", () => {
    const withList = classifyTools({ tools: [READER, WRITER], sqlTools: [{ tool: "read_query", arg: "sql" }] }).classification;
    const without = classifyTools({ tools: [READER, WRITER] }).classification;
    assert.equal(withList.find((c) => c.tool === "write_query")?.class, without.find((c) => c.tool === "write_query")?.class);
    assert.equal(withList.find((c) => c.tool === "write_query")?.class, "sql");
  });
});

describe("sqlite.engine is not a way to a standard run without the sqlite pack", () => {
  let root: string;
  let n = 0;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sealmark-scope-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));
  const load = (extra: string, o: Partial<LoadOptions> = {}) => {
    const dir = join(root, `p${n++}`);
    mkdirSync(dir);
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n${extra}`);
    return loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, ...o });
  };

  it("forcing an engine makes the run CUSTOM and names the setting; auto-detection stays STANDARD", () => {
    const auto = load("");
    assert.equal(auto.integrity.standard, true);
    for (const engine of ["duckdb", "sqlite"]) {
      const forced = load(`sqlite:\n  engine: ${engine}\n`);
      assert.equal(forced.integrity.standard, false, engine);
      const d = forced.integrity.standardDiff.find((x) => x.path === "sqlite.engine");
      assert.ok(d, "the diff names sqlite.engine");
      assert.equal(d.effective, engine);
      assert.equal(d.standard, null);
    }
  });

  it("the standard hash is unchanged (the setting is reported as a difference, not a locked leaf)", () => {
    assert.equal(load("sqlite:\n  engine: duckdb\n").integrity.hash, load("").integrity.hash);
  });

  it("listing sql_tools keeps the run STANDARD: it can no longer hide anything", () => {
    const c = load("sql_tools:\n  - { tool: query, arg: sql }\n");
    assert.equal(c.integrity.standard, true);
  });
});
