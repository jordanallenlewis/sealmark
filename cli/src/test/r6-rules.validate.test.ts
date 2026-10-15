// Round 6, package rules-agent: the new clauses of `probes:` as the validator sees them.
// Pure: nothing is called. Probes are built by hand and given to validateProbes, so these tests do not depend on the config layer.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { ConfigError } from "../config.js";
import type { ProbeSpec } from "../config/model.js";
import type { ToolInfo } from "../mcp.js";
import { countClauses, planContext, validateProbes, type PlanInput, type RuleProbeSpec } from "../probes.js";

const T = (name: string, description: string, props: Record<string, { type: string }>, required: string[]): ToolInfo => ({ name, description, inputSchema: { type: "object", properties: props, required } });
const TOOLS: ToolInfo[] = [
  T("list_tables", "List the tables the server may serve.", {}, []),
  T("describe_table", "Describe one table that is allowed by the server's scope.", { table: { type: "string" } }, ["table"]),
  T("count_rows", "Count the rows of one allowed table.", { table: { type: "string" } }, ["table"]),
  T("query", "Run a SQL query against the database", { sql: { type: "string" } }, ["sql"]),
  T("search_notes", "Search the notes for a text.", { q: { type: "string" } }, ["q"]),
];
const CLASSIFICATION = classifyTools({ tools: TOOLS, sqlTools: [{ tool: "query", arg: "sql" }] }).classification;
const base: PlanInput = { tools: TOOLS, classification: CLASSIFICATION };
const WITH_STUB: PlanInput = { ...base, upstream: { kind: "http", mintsTokens: true }, transport: "http" };

const plan = (specs: unknown[], input: PlanInput = base) => validateProbes(specs as ProbeSpec[], input);
const problemsOf = (specs: unknown[], input: PlanInput = base): string[] => {
  try {
    plan(specs, input);
  } catch (e) {
    assert.ok(e instanceof ConfigError, String(e));
    return e.message.split("\n");
  }
  return [];
};
const CHECK = { id: "custom-agg", label: "aggregate only", scope: "server", critical: true };

describe("r6 rules: matrix and cases", () => {
  it("expands a matrix into the cross product, ids id[k=v], sharing the check", () => {
    const p = plan([{ id: "agg", check: CHECK, tool: "count_rows", args: { table: "{matrix.table}" }, matrix: { table: ["sales.public.orders", "sales.public.customers"] }, expect: { is_error: false } }]);
    assert.deepEqual(p.probes.map((x) => x.id), ["agg[table=sales.public.orders]", "agg[table=sales.public.customers]"]);
    assert.deepEqual(p.probes.map((x) => x.spec.args), [{ table: "sales.public.orders" }, { table: "sales.public.customers" }]);
    assert.ok(p.probes.every((x) => x.check?.id === "custom-agg"));
    assert.equal(p.checks.length, 1, "one check, however many cells");
    assert.ok(p.probes.every((x) => x.spec.matrix === undefined && x.spec.cases === undefined), "the planned spec is concrete");
  });

  it("takes two keys in declared order (first key outermost) and keeps a scalar's type when the whole string is the reference", () => {
    const tools = [...TOOLS, T("page", "Page through rows.", { table: { type: "string" }, limit: { type: "number" } }, ["table", "limit"])];
    const input = { tools, classification: classifyTools({ tools }).classification };
    const p = plan([{ id: "pg", tool: "page", args: { table: "{matrix.table}", limit: "{matrix.limit}" }, matrix: { table: ["a", "b"], limit: [1, 2] } }], input);
    assert.deepEqual(p.probes.map((x) => x.id), ["pg[table=a,limit=1]", "pg[table=a,limit=2]", "pg[table=b,limit=1]", "pg[table=b,limit=2]"]);
    assert.deepEqual(p.probes[1]!.spec.args, { table: "a", limit: 2 });
    assert.equal(typeof p.probes[1]!.spec.args!.limit, "number");
  });

  it("substitutes a reference inside a longer string", () => {
    const p = plan([{ tool: "search_notes", id: "s", args: { q: "{matrix.q}-{token}" }, matrix: { q: ["x"] } }]);
    assert.equal(p.probes[0]!.spec.args!.q, "x-{token}", "{token} is left for the run to fill");
  });

  it("merges each case over the probe: its args over the probe's, its expect clauses over the probe's expect", () => {
    const p = plan([
      {
        id: "scope",
        check: CHECK,
        tool: "describe_table",
        args: { table: "x" },
        expect: { is_error: true },
        cases: [{ args: { table: "sales" }, expect: { upstream: { requests: "none" } } }, { id: "inside", args: { table: "sales.public.orders" }, expect: { is_error: false } }],
      },
    ], WITH_STUB);
    assert.deepEqual(p.probes.map((x) => x.id), ["scope#1", "inside"]);
    assert.deepEqual(p.probes[0]!.spec.expect, { is_error: true, upstream: { requests: "none" } });
    assert.deepEqual(p.probes[1]!.spec.expect, { is_error: false }, "a case's own clause replaces the probe's");
    assert.deepEqual(p.probes.map((x) => x.spec.args), [{ table: "sales" }, { table: "sales.public.orders" }]);
  });

  it("refuses matrix and cases together, an unreferenced key, an unknown reference, a key that is not an argument, and a huge product", () => {
    const m = (extra: object) => problemsOf([{ id: "m", tool: "count_rows", args: { table: "{matrix.table}" }, expect: { is_error: false }, ...extra }]).join("\n");
    assert.match(m({ matrix: { table: ["a"] }, cases: [{ args: {} }] }), /"matrix" and "cases" cannot be used together/);
    assert.match(m({ matrix: { table: ["a"], other: ["b"] } }), /matrix\.other is not an argument of "count_rows".*matrix\.other is never used: reference it as \{matrix\.other\}/s);
    assert.match(m({ args: { table: "{matrix.nope}" }, matrix: { table: ["a"] } }), /args use \{matrix\.nope\} but matrix has no "nope" key/);
    assert.match(m({ matrix: { table: [] } }), /matrix\.table must be a non-empty list/);
    assert.match(m({}), /args use \{matrix\.<name>\} but the probe has no matrix/);
    assert.match(m({ matrix: { table: Array.from({ length: 101 }, (_, i) => `t${i}`) } }), /matrix expands to 101 probes; the limit is 100/);
  });

  it("needs an expect on the probe or on every case, and an expect per expansion for a check", () => {
    const msg = problemsOf([{ id: "c", check: CHECK, tool: "describe_table", cases: [{ args: { table: "a" }, expect: { is_error: true } }, { args: { table: "b" } }] }]).join("\n");
    assert.match(msg, /cases\[1\] has no expect, and neither has the probe/);
    // every case brings its own: fine
    assert.equal(plan([{ id: "c", check: CHECK, tool: "describe_table", cases: [{ args: { table: "a" }, expect: { is_error: true } }, { args: { table: "b" }, expect: { is_error: false } }] }]).probes.length, 2);
    // a check whose probe-level expect is empty and whose case has no clause could never fail
    assert.match(problemsOf([{ id: "c", check: CHECK, tool: "describe_table", expect: {}, cases: [{ args: { table: "a" }, expect: {} }] }]).join("\n"), /needs an "expect" with at least one clause/);
  });

  it("refuses a duplicate expanded id", () => {
    const msg = problemsOf([{ id: "c", tool: "describe_table", expect: { is_error: true }, cases: [{ id: "same", args: { table: "a" } }, { id: "same", args: { table: "b" } }] }]).join("\n");
    assert.match(msg, /duplicate probe id "same"/);
  });

  it("validates each expansion on its own arguments (a literal SQL string in one case is refused for that case)", () => {
    const msg = problemsOf([{ id: "q", tool: "query", args: {}, cases: [{ id: "bad", args: { sql: "DROP TABLE x" }, expect: { is_error: true } }] }]).join("\n");
    assert.match(msg, /probes\[0\] \(bad\): .*SQL cannot be sent from probes/);
  });
});

describe("r6 rules: SQL, placeholders and the stub", () => {
  const sql = { tool: "query", args: { sql: "SELECT * FROM sales.public.orders WHERE 'sm-{token}' = 'sm-{token}'" } };

  it("accepts SQL on a SQL tool only when an upstream stub is declared (the refusal text is unchanged otherwise)", () => {
    assert.match(problemsOf([sql]).join("\n"), /SQL cannot be sent from probes \(the db and sqlite packs own SQL against databases the harness seeds\)/);
    assert.deepEqual(problemsOf([sql], WITH_STUB), []);
    assert.equal(plan([sql], WITH_STUB).probes[0]!.tool.name, "query");
  });

  it("refuses {bearer}, {bearer:a}, {upstream} and {upstream_token} in args, each saying what to write instead", () => {
    const msg = problemsOf([
      { tool: "search_notes", args: { q: "{bearer}" } },
      { tool: "search_notes", args: { q: "x {bearer:b}" } },
      { tool: "search_notes", args: { q: "{upstream}/sql" } },
      { tool: "search_notes", args: { q: "{upstream_token}" } },
    ], WITH_STUB).join("\n");
    assert.match(msg, /\{bearer\} cannot be used in a probe's arguments: the identity is chosen with `identity: a \| b \| none`/);
    assert.equal((msg.match(/\{bearer\} cannot be used/g) ?? []).length, 2);
    assert.match(msg, /\{upstream\} cannot be used in a probe's arguments: the stub is the server's backend, not a probe target/);
    assert.match(msg, /\{upstream_token\} exists only inside the reply of `upstream\.reply`/);
  });

  it("refuses upstream.reply and expect.upstream without a stub, naming the key to add", () => {
    const msg = problemsOf([
      { id: "a", tool: "count_rows", args: { table: "t" }, upstream: { reply: { json: {} } } },
      { id: "b", tool: "count_rows", args: { table: "t" }, expect: { upstream: { requests: "any" } } },
    ]).join("\n");
    assert.match(msg, /upstream\.reply needs the upstream stub: set upstream\.kind: http \(or pass --upstream\)/);
    assert.match(msg, /expect\.upstream needs the upstream stub: set upstream\.kind: http/);
  });

  it("refuses identity on a stdio server, accepts it on HTTP and when the transport is unknown", () => {
    const probe = { id: "i", tool: "count_rows", args: { table: "t" }, identity: "b" };
    assert.match(problemsOf([probe], { ...base, transport: "stdio" }).join("\n"), /identity needs an HTTP server whose headers use \{bearer\}/);
    assert.deepEqual(problemsOf([probe], { ...base, transport: "http" }), []);
    assert.deepEqual(problemsOf([probe]), [], "unknown transport is not refused (the config layer says)");
    assert.match(problemsOf([{ ...probe, identity: "c" }]).join("\n"), /"identity" must be "a", "b" or "none"/);
  });

  it("checks the shape of upstream.reply: one of body/json/bytes, status range, delay, bytes", () => {
    const reply = (r: object) => problemsOf([{ id: "r", tool: "count_rows", args: { table: "t" }, upstream: { reply: r } }], WITH_STUB).join("\n");
    assert.equal(reply({ status: 200, json: { rows: [{ id: 1, note: "{upstream_token}" }] } }), "");
    assert.equal(reply({ bytes: 1000, body: "{\"rows\":[\"{upstream_token}\"]}" }), "", "a bytes reply may carry a body prefix");
    assert.match(reply({ status: 200 }), /needs exactly one of body, json or bytes.*it has none/);
    assert.match(reply({ body: "x", json: {} }), /it has body and json/);
    assert.match(reply({ body: "x", status: 99 }), /status must be an integer from 100 to 599/);
    assert.match(reply({ body: "x", delay_ms: -1 }), /delay_ms must be an integer of 0 or more/);
    assert.match(reply({ bytes: 0 }), /bytes must be a positive integer/);
    assert.match(reply({ body: "x", extra: 1 }), /unknown key "extra"/);
  });

  it("checks the shape of every expect.upstream, expect.log and expect.response clause", () => {
    const exp = (e: object) => problemsOf([{ id: "e", tool: "count_rows", args: { table: "t" }, expect: e }], WITH_STUB).join("\n");
    assert.equal(exp({ upstream: { requests: "any", none_matching: "DROP", all_matching: "submitter=", header: { authorization: { matches: "^Bearer " } }, token_echoed: false }, log: { not_matches: "Bearer" }, response: { max_bytes: 10 } }), "");
    assert.match(exp({ upstream: { requests: "some" } }), /expect\.upstream\.requests must be "none" or "any"/);
    assert.match(exp({ upstream: { none_matching: "(" } }), /expect\.upstream\.none_matching is not a valid regular expression/);
    assert.match(exp({ upstream: { header: { authorization: {} } } }), /header\.authorization must be a mapping with equals and\/or matches/);
    assert.match(exp({ upstream: { token_echoed: "no" } }), /token_echoed must be true or false/);
    assert.match(exp({ log: { matches: "[" } }), /expect\.log\.matches is not a valid regular expression/);
    assert.match(exp({ response: { max_bytes: 0 } }), /expect\.response\.max_bytes must be a positive integer/);
    assert.match(exp({ upstream: { requestz: "any" } }), /unknown key "requestz"; did you mean "requests"\?/);
  });

  it("token_echoed needs a reply that mints {upstream_token}: refused only when the stub is known not to", () => {
    const noMint: PlanInput = { ...WITH_STUB, upstream: { kind: "http", mintsTokens: false } };
    const probe = { id: "t", tool: "count_rows", args: { table: "t" }, expect: { upstream: { token_echoed: false } } };
    assert.match(problemsOf([probe], noMint).join("\n"), /token_echoed needs a reply that carries \{upstream_token\}/);
    assert.deepEqual(problemsOf([{ ...probe, upstream: { reply: { json: { rows: [{ note: "{upstream_token}" }] } } } }], noMint), [], "this probe's own reply mints");
    assert.deepEqual(problemsOf([probe], WITH_STUB), [], "the configured stub mints");
    assert.deepEqual(problemsOf([probe], { ...WITH_STUB, upstream: { kind: "http" } }), [], "unknown is not refused");
  });

  it("countClauses counts every kind of assertion", () => {
    assert.equal(countClauses(undefined), 0);
    assert.equal(countClauses({}), 0);
    assert.equal(countClauses({ is_error: true, text: { matches: "a", not_matches: "b" }, files: { unchanged: ["x"], created: [] }, listener: "none", duration_ms: { max: 5 } }), 6);
    assert.equal(countClauses({ upstream: { requests: "any", token_echoed: false }, log: { matches: "x" }, response: { max_bytes: 3 } }), 4);
  });

  it("planContext reads the stub and the transport from the effective configuration", () => {
    assert.deepEqual(planContext({ server: { url: "http://x" }, value: {} }), { transport: "http" });
    assert.deepEqual(planContext({ server: {}, value: { upstream: { kind: "http", responses: [{ reply: { body: "{upstream_token}" } }] } } }), { transport: "stdio", upstream: { kind: "http", mintsTokens: true } });
    assert.deepEqual(planContext({ server: { url: "u" }, value: { upstream: { kind: "http", default_reply: { json: {} } } } }).upstream, { kind: "http", mintsTokens: false });
    assert.deepEqual(planContext(undefined, {}), { upstream: { kind: "http", mintsTokens: false } }, "a running stub counts as declared");
  });

  it("the plain probes of before are validated as before (no new key needed)", () => {
    const spec: RuleProbeSpec = { tool: "search_notes", args: { q: "sm-{token}" } };
    assert.equal(plan([spec]).probes[0]!.id, "search_notes#1");
    assert.match(problemsOf([{ tool: "search_notes", args: { q: "x" }, bogus: 1 }]).join("\n"), /unknown key "bogus"/);
  });
});
