import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { pack } from "../packs/sql-guard.js";
import { REFERENCE_CORPUS, STATEMENT_CORPUS, covered, effectiveLimit, forwardedSql, namesFor, render } from "../packs/sql-guard-corpus.js";

// Round 6, P5: the published corpus is pinned, and the two pure readers of the wire.

describe("sql-guard corpus", () => {
  it("pins the statement ids in the published order", () => {
    assert.deepEqual(
      STATEMENT_CORPUS.map((e) => e.id),
      ["insert", "update", "delete", "merge", "create", "drop", "alter", "truncate", "grant", "vacuum", "analyze", "set-session", "copy", "stacked", "cte-dml", "explain-analyze-write", "obfuscated", "terminator", "unparseable", "unbalanced", "comment-hidden"],
    );
    assert.deepEqual(STATEMENT_CORPUS.filter((e) => e.nearMiss).map((e) => e.id), ["comment-hidden"]);
  });

  it("pins the reference ids", () => {
    assert.deepEqual(
      REFERENCE_CORPUS.map((e) => e.id),
      ["from", "join", "comma-join", "subquery-from", "subquery-where", "scalar-subquery", "exists", "cte", "union", "quoted", "cased", "alias-hidden"],
    );
  });

  it("pins the text of the statements that name the corpus's best-known attacks", () => {
    const text = (id: string) => STATEMENT_CORPUS.find((e) => e.id === id)!.sql;
    assert.equal(text("stacked"), "SELECT 'sm-{token}'; DROP TABLE sm_{token}");
    assert.equal(text("obfuscated"), "/*x*/ iNsErT INTO {table} (sm_{token}) VALUES ('sm-{token}')");
    assert.equal(text("unbalanced"), "SELECT 1 AS sm_{token}, 'sm-{token}");
    assert.match(text("cte-dml"), /^WITH d AS \(DELETE FROM \{table\}/);
    assert.match(text("terminator"), /^COMMIT; INSERT/);
  });

  it("every entry carries both token spellings, as an identifier and as a literal", () => {
    for (const e of [...STATEMENT_CORPUS, ...REFERENCE_CORPUS]) {
      assert.ok(e.sql.includes("sm-{token}"), `${e.id} has the literal spelling`);
      assert.ok(e.sql.includes("sm_{token}") || e.sql.includes("{o"), `${e.id} has the identifier spelling (references get it from the out-of-scope name)`);
    }
    for (const e of STATEMENT_CORPUS) assert.ok(e.sql.includes("sm_{token}"), `${e.id} has the identifier spelling`);
  });

  it("a rendered entry holds both spellings of its token and no unfilled placeholder", () => {
    const n = namesFor(["sales.public."], ".", "abc12345");
    for (const e of [...STATEMENT_CORPUS, ...REFERENCE_CORPUS]) {
      const sql = render(e.sql, "abc12345", n).toLowerCase();
      assert.ok(sql.includes("sm-abc12345") && sql.includes("sm_abc12345"), e.id);
      assert.ok(!sql.includes("{"), `${e.id} has no unfilled placeholder`);
    }
  });

  it("names: the out-of-scope name is covered by no allow entry, for exact, prefix and mixed lists", () => {
    for (const allow of [["sales.public.orders"], ["sales.public."], ["sales.public.", "sales.public.orders"], ["sales.public.orders", "sales.public.customers"], ["orders"]]) {
      const n = namesFor(allow, ".", "t0k");
      assert.ok(n.outOfScope.endsWith("outside_sm_t0k"), allow.join());
      assert.ok(!covered(n.outOfScope, allow, "."), `${n.outOfScope} must be out of scope for ${allow.join()}`);
    }
    assert.equal(namesFor(["sales.public.orders"], ".", "t").outOfScope, "sales.public.outside_sm_t");
    assert.equal(namesFor(["sales.public."], ".", "t").outOfScope, "sales.outside_sm_t");
    assert.equal(namesFor(["orders"], ".", "t").outOfScope, "outside_sm_t");
    assert.equal(namesFor(["sales/public/orders"], "/", "t").outOfScope, "sales/public/outside_sm_t");
  });

  it("names: table is the first exact entry, else a made-up name under the prefix, else a bare one", () => {
    assert.equal(namesFor(["sales.public.", "sales.public.orders"], ".", "t").table, "sales.public.orders");
    assert.equal(namesFor([], ".", "t").table, "sm_t");
    assert.equal(namesFor(["sales.public."], ".", "t").table, "sales.public.sm_t");
    assert.equal(namesFor(["sales.public."], ".", "t").inScope, "sales.public.sm_ctl_t");
  });

  it("reference forms: quoted quotes every segment, cased upper-cases, alias reuses the in-scope name's last segment", () => {
    const n = namesFor(["sales.public.orders"], ".", "t");
    const sql = (id: string) => render(REFERENCE_CORPUS.find((e) => e.id === id)!.sql, "t", n);
    assert.match(sql("quoted"), /"sales"\."public"\."outside_sm_t"/);
    assert.match(sql("cased"), /SALES\.PUBLIC\.OUTSIDE_SM_T/);
    assert.match(sql("alias-hidden"), /FROM sales\.public\.outside_sm_t AS orders /);
  });
});

describe("effectiveLimit", () => {
  const cases: [string, string, number | null][] = [
    ["LIMIT", "SELECT * FROM t LIMIT 500", 500],
    ["lower case", "select * from t limit 5", 5],
    ["MySQL offset, count", "SELECT * FROM t LIMIT 10, 20", 20],
    ["FETCH FIRST", "SELECT * FROM t FETCH FIRST 1000 ROWS ONLY", 1000],
    ["FETCH NEXT", "SELECT * FROM t OFFSET 0 ROWS FETCH NEXT 7 ROW ONLY", 7],
    ["TOP", "SELECT TOP 250 * FROM t", 250],
    ["no limit", "SELECT * FROM t", null],
    ["wrapper takes the outer limit", "SELECT * FROM (SELECT * FROM t LIMIT 1000000) AS sm LIMIT 1000", 1000],
    ["outer larger than the inner is still the outer", "SELECT * FROM (SELECT * FROM t LIMIT 5) AS sm LIMIT 1000000", 1000000],
    ["only inner limits: the shallowest level that has one", "SELECT * FROM (SELECT * FROM (SELECT 1 LIMIT 90) a LIMIT 80) AS sm", 80],
    ["several at the outer level: the smallest", "SELECT * FROM t LIMIT 100 OFFSET 0 FETCH FIRST 50 ROWS ONLY", 50],
    ["a number in a string literal is not a limit", "SELECT 'limit 5' AS x FROM t", null],
    ["a number in a comment is not a limit", "SELECT * FROM t /* LIMIT 5 */ -- LIMIT 6\n", null],
    ["an escaped quote in a literal", "SELECT 'it''s limit 3' FROM t LIMIT 40", 40],
  ];
  for (const [name, sql, want] of cases) it(name, () => assert.equal(effectiveLimit(sql), want));
});

describe("forwardedSql", () => {
  const req = (body: string, path = "/sql", query = "") => ({ path, query, body });
  it("takes the string values of a JSON body that hold the needle, without the JSON escaping", () => {
    const sql = `SELECT * FROM t WHERE x = 'sm-ab' LIMIT 5`;
    assert.equal(forwardedSql(req(JSON.stringify({ sql, submitter: "mcp:a" })), "sm-ab"), sql);
  });
  it("walks nested values and arrays", () => {
    assert.equal(forwardedSql(req(JSON.stringify({ q: { stmts: ["SELECT 1", "SELECT 'sm_ab'"] } })), "sm_ab"), "SELECT 'sm_ab'");
  });
  it("falls back to the raw text, URL-decoded, for a non-JSON body or a GET", () => {
    assert.match(forwardedSql(req("", "/sql", "?q=SELECT%20sm_ab%20LIMIT%209"), "sm_ab"), /SELECT sm_ab LIMIT 9/);
    assert.match(forwardedSql(req("SELECT sm_ab FETCH FIRST 3 ROWS ONLY"), "sm_ab"), /FETCH FIRST 3/);
  });
});

describe("sql-guard describe()", () => {
  it("documents three checks; statements and references are critical, rowcap is not; every corpus id is listed", () => {
    const docs = pack.describe();
    assert.deepEqual(docs.map((d) => [d.id, d.critical, d.advisory]), [["sql-guard-statements", true, false], ["sql-guard-references", true, false], ["sql-guard-rowcap", false, false]]);
    const ids = (id: string) => docs.find((d) => d.id === id)!.probes.map((p) => p.id);
    for (const e of STATEMENT_CORPUS) assert.ok(ids("sql-guard-statements").includes(e.id), e.id);
    for (const e of REFERENCE_CORPUS) assert.ok(ids("sql-guard-references").includes(e.id), e.id);
    assert.deepEqual(ids("sql-guard-rowcap"), ["control", "huge-limit"]);
    assert.equal(docs.find((d) => d.id === "sql-guard-rowcap")!.thresholds.row_cap!.default, 10000);
  });
});
