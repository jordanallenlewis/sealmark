import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import {
  CHECKS,
  CANDIDATE_CHECKS,
  ConfigError,
  PACK_IDS,
  SCHEMA,
  STANDARD_PACKS,
  buildJsonSchema,
  expand,
  extractLocked,
  loadEffectiveConfig,
  placeholdersUsed,
  renderShow,
  standardHash,
  type EffectiveConfig,
  type LoadOptions,
} from "../config/index.js";
import { LOCKED_LEAVES } from "../config/schema.js";

/** Round 6, package P2 (config-report): every new key validates, every error text of the design (section 5.1) appears verbatim, and the standard hash does not move. */

const PINNED = readFileSync(fileURLToPath(new URL("../../src/test/fixtures/config/standard.hash.txt", import.meta.url)), "utf8").trim();

let root: string;
let counter = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-r6cfg-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

const SERVER = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js, --backend, '{upstream}']\n  url: http://127.0.0.1:8080/mcp\n";
const STDIO = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";

function proj(text: string): string {
  const dir = join(root, `p${counter++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), text);
  return dir;
}
const load = (text: string, o: Partial<LoadOptions> = {}): EffectiveConfig => loadEffectiveConfig({ cwd: proj(text), isolated: true, env: {}, ...o });
function failure(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `expected a ConfigError, got ${String(e)}`);
    return e.message;
  }
  assert.fail("expected a ConfigError");
}
const bad = (text: string, o: Partial<LoadOptions> = {}): string => failure(() => load(text, o));

describe("the pinned standard hash does not move", () => {
  it("equals the pinned file with the schema as it is", () => {
    assert.equal(standardHash(), PINNED);
  });

  it("is the same with every new key set: a STANDARD run stays STANDARD", () => {
    const cfg = load(
      `${SERVER}upstream:\n  kind: http\n  default_reply: { status: 200, json: { rows: [] } }\n  responses:\n    - { id: count, match: { path: "^/sql$" }, reply: { json: { n: 3 } } }\n  credential_header: X-Auth\n  max_body_kib: 64\n` +
        `identities: { a: token-aaaa, b: token-bbbb }\nscope:\n  tools: [{ tool: describe_table, param: table }]\n  allow: ["sales.public."]\n  deny: [hr.private.salaries]\n  separator: "."\n  case: sensitive\n` +
        `checks:\n  sql-guard-rowcap: { row_cap: 1000 }\n  sql-guard-statements: { control_sql: "SELECT 1" }\n  upstream-slow: { expected_sec: 3 }\n  refusal-quality: { patterns: [instead] }\n  instructions-hygiene: { deny: ["ACME"] }\n` +
        `probes:\n  - { tool: list_tables, args: {} }\n`,
    );
    assert.equal(cfg.integrity.standard, true, JSON.stringify(cfg.integrity.standardDiff));
    assert.equal(cfg.integrity.hash, PINNED);
  });

  it("adds no locked leaf: every new leaf is unlocked and the locked set is what main had", () => {
    const newPrefix = /^(upstream|identities|scope)\.|^checks\.(refusal-quality|instructions-hygiene|scope-escape|sql-guard-[a-z]+|upstream-[a-z-]+|log-secret)\./;
    assert.deepEqual(LOCKED_LEAVES.filter((l) => newPrefix.test(l.path)).map((l) => l.path), []);
    const locked = Object.keys(extractLocked(load(STDIO).value)).filter((k) => k !== "packs");
    assert.equal(locked.length, LOCKED_LEAVES.length);
    assert.equal(LOCKED_LEAVES.length, 136, "the number of locked leaves on main; a new locked leaf moves the hash");
  });

  it("a candidate check's enabled/severity are SCHEMA leaves that are unlocked and have no corpus leaves", () => {
    const ids = ["refusal-quality", "instructions-hygiene", "scope-escape", "sql-guard-statements", "sql-guard-references", "sql-guard-rowcap", "upstream-credential", "upstream-credential-echo", "log-secret", "upstream-error-leak", "upstream-slow"];
    for (const id of ids) {
      assert.ok(CHECKS.find((c) => c.id === id)?.candidate, `${id} is a candidate check`);
      assert.ok(CANDIDATE_CHECKS.includes(id as never), `${id} is in CANDIDATE_CHECKS`);
      for (const k of ["enabled", "severity"]) assert.ok(SCHEMA.some((l) => l.path === `checks.${id}.${k}` && !l.standardLocked), `${id}.${k}`);
      assert.ok(!SCHEMA.some((l) => l.path.startsWith(`checks.${id}.corpus`)), `${id} has no corpus leaves`);
    }
  });
});

describe("candidate packs are valid pack names; the standard pack list is untouched", () => {
  it("scope, sql-guard and upstream are accepted by --pack and packs:, and unknown names still say what is valid", () => {
    assert.ok(["scope", "sql-guard", "upstream"].every((p) => (PACK_IDS as readonly string[]).includes(p)));
    const cfg = load(`${STDIO}packs: [core, scope, sql-guard, upstream]\n`);
    assert.deepEqual(cfg.packs, ["core", "scope", "sql-guard", "upstream"]);
    assert.match(bad(STDIO, { flags: { pack: ["scop"] } }), /unknown pack "scop" \(use core, db, sqlite, fs, net, git, exec, http, effects, custom, scope, sql-guard, upstream\); did you mean "scope"\?/);
  });

  it("STANDARD_PACKS names none of them", () => {
    assert.ok(!STANDARD_PACKS.some((p) => ["scope", "sql-guard", "upstream"].includes(p)));
  });
});

describe("candidate settings are CUSTOM when a candidate check is disabled or re-scored, and only then", () => {
  it("checks.scope-escape.severity: critical is CUSTOM and the diff names it", () => {
    const cfg = load(`${STDIO}checks:\n  scope-escape: { severity: critical }\n`);
    assert.equal(cfg.integrity.standard, false);
    assert.deepEqual(cfg.integrity.standardDiff.map((d) => d.path), ["checks.scope-escape.severity"]);
    assert.equal(cfg.integrity.hash, PINNED, "a candidate setting is not a locked leaf: the diff makes the run CUSTOM, the hash covers the locked leaves only");
  });

  it("enabled: false on a candidate check is CUSTOM", () => {
    const cfg = load(`${STDIO}checks:\n  upstream-credential: { enabled: false }\n`);
    assert.deepEqual(cfg.integrity.standardDiff.map((d) => d.path), ["checks.upstream-credential.enabled"]);
  });

  it("a candidate check's threshold (row_cap, expected_sec, patterns) does not make the run CUSTOM", () => {
    const cfg = load(`${STDIO}checks:\n  sql-guard-rowcap: { row_cap: 50 }\n  upstream-slow: { expected_sec: 1.5 }\n  refusal-quality: { patterns: [nope] }\n`);
    assert.equal(cfg.integrity.standard, true);
  });

  it("a probe with check is CUSTOM (as before); a probe without is not, also with identity/matrix/cases/expect.upstream", () => {
    const valid = load(
      `${SERVER}upstream: { kind: http }\nprobes:\n  - { tool: describe_table, identity: b, matrix: { table: [a.b, c.d] }, args: { table: "{matrix.table}" }, upstream: { reply: { json: { rows: [] } } }, expect: { upstream: { requests: any } } }\n`,
    );
    assert.equal(valid.integrity.standard, true);
    const custom = load(`${SERVER}upstream: { kind: http }\nprobes:\n  - { id: p1, check: { id: custom-x, label: x, scope: server }, tool: t, expect: { is_error: false } }\n`);
    assert.equal(custom.integrity.standard, false);
    assert.deepEqual((custom.integrity.locked.custom_checks as string[]), ["custom-x"]);
  });
});

describe("upstream.* keys", () => {
  it("defaults: no stub, a 200 empty-JSON default reply, authorization, 1024 KiB", () => {
    const u = load(STDIO).upstream!;
    assert.deepEqual(u, { kind: null, responses: [], default_reply: { status: 200, json: {} }, credential_header: "authorization", max_body_kib: 1024 });
  });

  it("kind accepts http only", () => {
    assert.match(bad(`${SERVER}upstream: { kind: tcp }\n`), /upstream\.kind: expected one of http, got string "tcp"/);
  });

  it("a reply needs exactly one of body, json or bytes (bytes may carry body as its prefix)", () => {
    const msg = "reply needs exactly one of body, json or bytes";
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  default_reply: { status: 200 }\n`), new RegExp(msg));
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  default_reply: { body: x, json: {} }\n`), new RegExp(msg));
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  responses: [{ reply: { json: {}, bytes: 10 } }]\n`), new RegExp(msg));
    assert.equal(load(`${SERVER}upstream:\n  kind: http\n  default_reply: { bytes: 2048, body: "{\\"rows\\":[" }\n`).upstream!.default_reply.bytes, 2048);
  });

  it("status is 100-599, delay_ms is an integer of at least 0, regexes are validated, ids and match keys are checked", () => {
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  default_reply: { status: 99, json: {} }\n`), /must be between 100 and 599, got 99/);
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  default_reply: { json: {}, delay_ms: -1 }\n`), /delay_ms: must be at least 0, got -1/);
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  responses: [{ match: { path: "(" }, reply: { json: {} } }]\n`), /not a valid regular expression/);
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  responses: [{ match: { pth: x }, reply: { json: {} } }]\n`), /unknown key "pth" under upstream\.responses\[0\]\.match; did you mean "path"\?/);
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  responses: [{ match: { path: x } }]\n`), /missing required key "reply"/);
  });

  it("max_body_kib is at least 1", () => {
    assert.match(bad(`${SERVER}upstream:\n  kind: http\n  max_body_kib: 0\n`), /must be at least 1, got 0/);
  });

  it("kind set but the server never uses {upstream}: refused, naming the key", () => {
    assert.match(bad(`schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n  url: http://127.0.0.1:8080/mcp\nupstream: { kind: http }\n`), /upstream\.kind is set but server\.command\/args\/env\/url\/headers never use \{upstream\}: the server would not talk to the stub/);
    assert.match(bad(`${STDIO}upstream: { kind: http }\n`), /upstream\.kind is set but server\.command\/args\/env\/url\/headers never use \{upstream\}/);
  });

  it("{upstream} in env, headers, url or a staged file counts as use", () => {
    for (const where of ["env: { BACKEND: '{upstream}' }", "headers: { X-Backend: '{upstream}' }", "files: [{ path: '{sandbox}/c.json', content: '{upstream}' }]"]) {
      const cfg = load(`schema_version: 1\nserver:\n  command: node\n  url: http://127.0.0.1:8080/mcp\n  ${where}\nupstream: { kind: http }\n`);
      assert.equal(cfg.upstream!.kind, "http");
    }
    assert.equal(load(`schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n  env: { BACKEND: '{upstream}' }\nupstream: { kind: http }\n`).upstream!.kind, "http", "a stdio server may use the stub");
  });

  it("a url-only server cannot be pointed at the stub", () => {
    assert.match(bad(`schema_version: 1\nserver:\n  url: http://127.0.0.1:8080/mcp\n  headers: { X-B: '{upstream}' }\nupstream: { kind: http }\n`), /the upstream stub needs a server Sealmark starts \(server\.command \+ server\.url, or a stdio command\)/);
  });

  it("--upstream and SEALMARK_UPSTREAM__KIND set it", () => {
    assert.equal(load(SERVER, { flags: { upstream: true } }).upstream!.kind, "http");
    assert.equal(load(SERVER, { env: { SEALMARK_UPSTREAM__KIND: "http" } }).upstream!.kind, "http");
    assert.equal(load(`${SERVER}upstream: { kind: http }\n`, { env: { SEALMARK_UPSTREAM__KIND: "null" } }).upstream!.kind, null);
  });
});

describe("identities.*", () => {
  it("are null by default and read from the environment through ${VAR}", () => {
    assert.deepEqual(load(STDIO).identities, { a: null, b: null });
    const cfg = load(`${STDIO}identities: { a: "\${TOKEN_A}", b: "\${TOKEN_B:-fallback-b}" }\n`, { env: { TOKEN_A: "tok-a-1234" } });
    assert.deepEqual(cfg.identities, { a: "tok-a-1234", b: "fallback-b" });
  });

  it("an unset ${VAR} is an error that names the variable and the key", () => {
    assert.match(bad(`${STDIO}identities: { a: "\${TOKEN_A}" }\n`), /\$\{TOKEN_A\} is not set \(used in identities\.a\)/);
  });

  it("a and b must differ (also after the environment is read)", () => {
    const msg = /identities\.a and identities\.b must differ, or passthrough cannot be told from a shared credential/;
    assert.match(bad(`${STDIO}identities: { a: same-token, b: same-token }\n`), msg);
    assert.match(bad(`${STDIO}identities: { a: "\${X}", b: same }\n`, { env: { X: "same" } }), msg);
  });

  it("--identity-a and --identity-b set them; an empty value says so", () => {
    const cfg = load(STDIO, { flags: { "identity-a": "aaaa-1111", "identity-b": "bbbb-2222" } });
    assert.deepEqual(cfg.identities, { a: "aaaa-1111", b: "bbbb-2222" });
    assert.match(bad(STDIO, { flags: { "identity-a": " " } }), /--identity-a: expected a token, got an empty string/);
  });

  it("config show prints <redacted>, never the value, with and without origins and as JSON", () => {
    const cfg = load(`${STDIO}identities: { a: secret-token-a, b: secret-token-b }\n`);
    for (const out of [renderShow(cfg), renderShow(cfg, { origins: true }), renderShow(cfg, { json: true })]) {
      assert.ok(!out.includes("secret-token"), out);
      assert.match(out, /a: <redacted>|"a": "<redacted>"/);
    }
  });
});

describe("scope.*", () => {
  it("defaults: nothing declared, separator '.', insensitive", () => {
    assert.deepEqual(load(STDIO).scope, { tools: [], allow: [], deny: [], separator: ".", case: "insensitive" });
  });

  it("tools without an allow list is refused with the text of the design", () => {
    assert.match(bad(`${STDIO}scope:\n  tools: [{ tool: describe_table, param: table }]\n`), /scope\.allow is empty: list at least one identifier the server may serve \(an entry ending in "\." is a prefix\)/);
  });

  it("tool and param are required, the separator is one character, case is an enum", () => {
    assert.match(bad(`${STDIO}scope: { tools: [{ tool: t }], allow: [x] }\n`), /missing required key "param"/);
    assert.match(bad(`${STDIO}scope: { separator: "::" }\n`), /separator must be exactly one character/);
    assert.match(bad(`${STDIO}scope: { case: upper }\n`), /scope\.case: expected one of sensitive, insensitive, got string "upper"/);
  });

  it("flags: --scope-tool tool=param (repeatable), --scope-allow, --scope-deny", () => {
    const cfg = load(STDIO, { flags: { "scope-tool": ["describe_table=table", "count_rows=table"], "scope-allow": ["sales.public."], "scope-deny": ["hr.private.salaries", "hr."] } });
    assert.deepEqual(cfg.scope, { tools: [{ tool: "describe_table", param: "table" }, { tool: "count_rows", param: "table" }], allow: ["sales.public."], deny: ["hr.private.salaries", "hr."], separator: ".", case: "insensitive" });
    assert.match(bad(STDIO, { flags: { "scope-tool": ["describe_table"] } }), /--scope-tool: expected tool=param \(for example describe_table=table\), got "describe_table"/);
  });

  it("environment: SEALMARK_SCOPE__ALLOW as a JSON list and SEALMARK_SCOPE__TOOLS as JSON", () => {
    const cfg = load(STDIO, { env: { SEALMARK_SCOPE__ALLOW: '["sales.public."]', SEALMARK_SCOPE__TOOLS: '[{"tool":"describe_table","param":"table"}]' } });
    assert.deepEqual(cfg.scope!.allow, ["sales.public."]);
    assert.deepEqual(cfg.scope!.tools, [{ tool: "describe_table", param: "table" }]);
  });
});

describe("candidate check settings", () => {
  it("row_cap, control_sql, expected_sec, patterns and deny validate", () => {
    assert.match(bad(`${STDIO}checks:\n  sql-guard-rowcap: { row_cap: 0 }\n`), /must be at least 1, got 0/);
    assert.match(bad(`${STDIO}checks:\n  sql-guard-statements: { control_sql: "DELETE FROM t" }\n`), /control_sql must start with SELECT or WITH/);
    assert.equal(load(`${STDIO}checks:\n  sql-guard-statements: { control_sql: "with x as (select 1) select * from x" }\n`).checks["sql-guard-statements"].control_sql, "with x as (select 1) select * from x");
    assert.match(bad(`${STDIO}checks:\n  upstream-slow: { expected_sec: 0 }\n`), /must be greater than 0, got 0/);
    assert.match(bad(`${STDIO}checks:\n  refusal-quality: { patterns: ["("] }\n`), /not a valid regular expression/);
    assert.match(bad(`${STDIO}checks:\n  instructions-hygiene: { deny: ["("] }\n`), /not a valid regular expression/);
  });

  it("the refusal-quality default list is the one in the design; a configured list replaces it", () => {
    assert.deepEqual(load(STDIO).checks["refusal-quality"].patterns, ["instead", "use (the )?[a-z_]+ tool", "available", "allowed", "try", "list_[a-z]+", "contact", "will not (help|succeed)", "permanent", "not retry"]);
    assert.deepEqual(load(`${STDIO}checks:\n  refusal-quality: { patterns: [only] }\n`).checks["refusal-quality"].patterns, ["only"]);
  });

  it("instructions-hygiene.deny appends across layers (mergeable)", () => {
    const dir = proj(`${STDIO}checks:\n  instructions-hygiene: { deny: [a] }\n`);
    writeFileSync(join(dir, "sealmark.local.yaml"), "checks:\n  instructions-hygiene: { deny: [b] }\n");
    assert.deepEqual(loadEffectiveConfig({ cwd: dir, isolated: true, env: {} }).checks["instructions-hygiene"].deny, ["a", "b"]);
  });
});

describe("probes: the round 6 clauses (shape; the semantic checks are the rules package's)", () => {
  const P = (probe: string, extra = SERVER + "upstream: { kind: http }\n") => `${extra}probes:\n  - ${probe}\n`;

  it("accepts every clause of the design", () => {
    const cfg = load(
      `${SERVER}upstream: { kind: http, responses: [{ reply: { json: { rows: ["{upstream_token}"] } } }] }\nprobes:\n` +
        `  - id: agg\n    check: { id: custom-agg, label: aggregate only, scope: server, critical: true }\n    tool: count_rows\n    identity: a\n    upstream: { reply: { status: 200, json: { rows: [{ id: 1, note: "{upstream_token}" }] } } }\n    matrix: { table: ["sales.public.orders", "sales.public.customers"] }\n    args: { table: "{matrix.table}" }\n    expect: { is_error: false, upstream: { requests: any, token_echoed: false } }\n` +
        `  - id: scope-cases\n    check: { id: custom-scope, label: refuses, scope: server }\n    tool: describe_table\n    cases:\n      - { args: { table: sales }, expect: { is_error: true, upstream: { requests: none } } }\n      - { id: allowed, args: { table: "sales.public.orders" }, expect: { is_error: false, upstream: { all_matching: "submitter=", none_matching: "DROP", header: { authorization: { matches: "^Bearer " } } } } }\n` +
        `  - id: big\n    check: { id: custom-cap, label: capped, scope: server }\n    tool: query\n    args: { sql: "SELECT 1" }\n    upstream: { reply: { bytes: 20971520, body: "{" } }\n    expect: { response: { max_bytes: 1048576 }, log: { not_matches: "Bearer", matches: "ok" } }\n`,
    );
    assert.equal(cfg.probes.length, 3);
    assert.equal(cfg.probes[0].identity, "a");
    assert.deepEqual(cfg.probes[0].matrix, { table: ["sales.public.orders", "sales.public.customers"] });
    assert.equal(cfg.probes[1].cases!.length, 2);
    assert.equal(cfg.probes[2].expect!.response!.max_bytes, 1048576);
  });

  it("identity is a, b or none", () => {
    assert.match(bad(P("{ tool: t, identity: c }")), /expected one of a, b, none, got string "c"/);
  });

  it("matrix and cases are exclusive; every matrix key must be referenced and every reference must exist", () => {
    assert.match(bad(P("{ tool: t, matrix: { x: [1] }, cases: [{ expect: { is_error: true } }], args: { x: '{matrix.x}' } }")), /"matrix" and "cases" are exclusive/);
    assert.match(bad(P("{ tool: t, matrix: { x: [1], y: [2] }, args: { x: '{matrix.x}' } }")), /matrix key "y" is not referenced by any args value; use \{matrix\.y\} in args/);
    assert.match(bad(P("{ tool: t, matrix: { x: [1] }, args: { x: '{matrix.x}', y: '{matrix.z}' } }")), /args uses \{matrix\.z\} but matrix has no key "z"/);
    assert.match(bad(P("{ tool: t, args: { x: '{matrix.x}' } }")), /args uses \{matrix\.<name>\} but the probe has no "matrix"/);
    assert.match(bad(P("{ tool: t, matrix: { x: [] }, args: { x: '{matrix.x}' } }")), /needs at least 1 item/);
  });

  it("cases need the probe's expect or one of their own", () => {
    assert.match(bad(P("{ tool: t, cases: [{ args: { a: 1 } }] }")), /a case needs an "expect"/);
    assert.equal(load(P("{ tool: t, expect: { is_error: true }, cases: [{ args: { a: 1 } }] }")).probes.length, 1);
  });

  it("upstream.reply follows the reply rule, and expect clauses are typed", () => {
    assert.match(bad(P("{ tool: t, upstream: { reply: { status: 200 } } }")), /reply needs exactly one of body, json or bytes/);
    assert.match(bad(P("{ tool: t, expect: { upstream: { requests: some } } }")), /expected one of none, any, got string "some"/);
    assert.match(bad(P("{ tool: t, expect: { upstream: { all_matching: '(' } } }")), /not a valid regular expression/);
    assert.match(bad(P("{ tool: t, expect: { log: { matches: '(' } } }")), /not a valid regular expression/);
    assert.match(bad(P("{ tool: t, expect: { response: { max_bytes: 0 } } }")), /must be at least 1, got 0/);
    assert.match(bad(P("{ tool: t, expect: { upstream: { token_echoed: yes } } }")), /expected true or false/);
  });

  it("upstream.reply and expect.upstream need upstream.kind; the error names the key to add", () => {
    assert.match(bad(P("{ tool: t, upstream: { reply: { json: {} } } }", STDIO)), /upstream\.reply needs upstream\.kind; set upstream\.kind: http \(or pass --upstream\)/);
    assert.match(bad(P("{ tool: t, expect: { upstream: { requests: any } } }", STDIO)), /expect\.upstream needs upstream\.kind; set upstream\.kind: http/);
    assert.match(bad(P("{ tool: t, cases: [{ expect: { upstream: { requests: none } } }] }", STDIO)), /expect\.upstream needs upstream\.kind/);
  });

  it("identity on a stdio server is refused with the text of the design", () => {
    assert.match(bad(P("{ tool: t, identity: b }", STDIO)), /identity needs an HTTP server whose headers use \{bearer\}/);
    assert.equal(load(P("{ tool: t, identity: b }", `${SERVER}`)).probes[0].identity, "b");
  });

  it("token_echoed needs {upstream_token} in the probe's reply or in upstream.responses", () => {
    const msg = /expect\.upstream\.token_echoed needs an upstream\.reply with \{upstream_token\}/;
    assert.match(bad(P("{ tool: t, expect: { upstream: { token_echoed: false } } }")), msg);
    assert.match(bad(P("{ tool: t, upstream: { reply: { json: { a: 1 } } }, expect: { upstream: { token_echoed: true } } }")), msg);
    assert.equal(load(P("{ tool: t, upstream: { reply: { json: { a: '{upstream_token}' } } }, expect: { upstream: { token_echoed: true } } }")).probes.length, 1);
    assert.equal(load(P("{ tool: t, expect: { upstream: { token_echoed: false } } }", `${SERVER}upstream: { kind: http, default_reply: { body: "{upstream_token}" } }\n`)).probes.length, 1);
  });
});

describe("placeholders {upstream}, {bearer}, {bearer:a}, {bearer:b}", () => {
  it("are recognised in a server spec and expand from the harness variables", () => {
    const used = placeholdersUsed({ command: "node", args: ["--backend", "{upstream}"], headers: { Authorization: "Bearer {bearer}", "X-B": "{bearer:b}" } });
    assert.deepEqual([...used].sort(), ["bearer", "bearer:b", "upstream"]);
    const vars = { upstream: "http://127.0.0.1:5555", "bearer:a": "tok-a", "bearer:b": "tok-b" };
    assert.equal(expand("Bearer {bearer}", { vars, dsns: {} }), "Bearer tok-a", "{bearer} is {bearer:a}");
    assert.equal(expand("{bearer:a}/{bearer:b} {upstream}/sql", { vars, dsns: {} }), "tok-a/tok-b http://127.0.0.1:5555/sql");
  });

  it("a placeholder the caller did not supply stays as written, so a missing stub is visible", () => {
    assert.equal(expand("{upstream} {bearer:b}", { vars: {}, dsns: {} }), "{upstream} {bearer:b}");
  });

  it("are not reported as unknown placeholders, and {bearer} under Authorization is not a literal secret", () => {
    const cfg = load(`${SERVER}  headers: { Authorization: "Bearer {bearer}" }\nupstream: { kind: http }\n`);
    assert.ok(!cfg.warnings.some((w) => /unknown placeholder/.test(w)), cfg.warnings.join("\n"));
    assert.match(renderShow(cfg), /Authorization: Bearer \{bearer\}/);
  });

  it("a misspelling is still caught, with a suggestion", () => {
    const cfg = load(`${SERVER}  env: { X: "{upstram}" }\nupstream: { kind: http }\n`);
    assert.ok(cfg.warnings.some((w) => /unknown placeholder \{upstram\}.*did you mean \{upstream\}\?/.test(w)), cfg.warnings.join("\n"));
  });
});

describe("the JSON Schema carries every new key", () => {
  const schema = buildJsonSchema() as { properties: Record<string, { properties?: Record<string, { properties?: Record<string, unknown> }> }> };
  it("upstream, identities and scope sections, the candidate check sections and the probe clauses", () => {
    assert.deepEqual(Object.keys(schema.properties.upstream.properties!).sort(), ["credential_header", "default_reply", "kind", "max_body_kib", "responses"]);
    assert.deepEqual(Object.keys(schema.properties.identities.properties!).sort(), ["a", "b"]);
    assert.deepEqual(Object.keys(schema.properties.scope.properties!).sort(), ["allow", "case", "deny", "separator", "tools"]);
    for (const id of ["scope-escape", "sql-guard-statements", "sql-guard-references", "sql-guard-rowcap", "upstream-credential", "upstream-credential-echo", "log-secret", "upstream-error-leak", "upstream-slow", "refusal-quality", "instructions-hygiene"]) {
      assert.ok(schema.properties.checks.properties![id], id);
    }
    const text = JSON.stringify(schema);
    for (const k of ["token_echoed", "none_matching", "all_matching", "max_bytes", "matrix", "cases", "identity"]) assert.ok(text.includes(`"${k}"`), k);
  });

  it("identities are flagged secret in the schema extension", () => {
    const a = schema.properties.identities.properties!.a as unknown as { "x-sealmark": { secret: boolean } };
    assert.equal(a["x-sealmark"].secret, true);
  });

  it("the standard profile file lists no new key (it holds the locked leaves)", () => {
    const std = parse(readFileSync(fileURLToPath(new URL("../../src/config/profiles/standard.yaml", import.meta.url)), "utf8")) as Record<string, unknown>;
    for (const k of ["upstream", "identities", "scope"]) assert.ok(!(k in std), k);
  });
});

describe("--replay of a report whose run included candidate packs", () => {
  it("restores the locked settings and accepts scope, sql-guard and upstream in the recorded pack list", () => {
    const first = load(`${SERVER}upstream: { kind: http }\npacks: [core, db, sqlite, fs, net, git, http, effects, scope, sql-guard, upstream]\n`);
    assert.equal(first.integrity.standard, true);
    const replayed = load(STDIO, { replay: { hash: first.integrity.hash, locked: first.integrity.locked, methodology: first.integrity.methodology } });
    assert.equal(replayed.integrity.hash, PINNED);
    assert.ok(replayed.packs.includes("scope") && replayed.packs.includes("upstream"));
  });

  it("a forged locked block that names a candidate setting is still refused", () => {
    const first = load(STDIO);
    const locked = { ...first.integrity.locked, "scope.allow": ["x"] };
    assert.match(bad(STDIO, { replay: { hash: first.integrity.hash, locked, methodology: first.integrity.methodology } }), /config\.locked carries setting\(s\) a report may not set: scope\.allow/);
  });
});
