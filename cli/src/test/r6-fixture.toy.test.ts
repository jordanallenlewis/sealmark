// The scoped toy alone: each mode's rule exercised over HTTP against a small backend recorder
// written in this file. No harness, no stub observer; the SDK client is the caller.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { networkInterfaces } from "node:os";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SCOPED_TOY_MODES, SCOPED_TOY_ROW_CAP, startScopedToy, type ScopedToy, type ScopedToyMode } from "../toy/scoped-http.js";

// ---- a tiny backend: records what it receives, answers what it is told to ----
interface Seen {
  path: string;
  authorization: string | undefined;
  submitter: string | undefined;
  sql: string;
  params: unknown;
  raw: string;
}
interface Reply {
  status?: number;
  body?: string;
  bytes?: number;
  delayMs?: number;
}
class Backend {
  seen: Seen[] = [];
  reply: Reply = {};
  private timers = new Set<NodeJS.Timeout>();
  private server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let j: { sql?: string; submitter?: string; params?: unknown } = {};
      try {
        j = JSON.parse(raw);
      } catch {
        /* keep empty */
      }
      this.seen.push({ path: req.url ?? "", authorization: req.headers.authorization, submitter: j.submitter, sql: j.sql ?? "", params: j.params, raw });
      const send = () => {
        const r = this.reply;
        const body = r.bytes ? (r.body ?? "").padEnd(r.bytes, " ") : (r.body ?? JSON.stringify({ rows: [], count: 0 }));
        res.writeHead(r.status ?? 200, { "content-type": "application/json" });
        res.end(body);
      };
      if (this.reply.delayMs) {
        const t = setTimeout(send, this.reply.delayMs);
        this.timers.add(t);
      } else send();
    });
  });
  url = "";
  async start() {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", () => r()));
    this.url = `http://127.0.0.1:${(this.server.address() as net.AddressInfo).port}`;
  }
  reset() {
    this.seen = [];
    this.reply = {};
  }
  async stop() {
    for (const t of this.timers) clearTimeout(t);
    await new Promise<void>((r) => {
      this.server.close(() => r());
      this.server.closeAllConnections();
    });
  }
}

const backend = new Backend();
const toys: ScopedToy[] = [];
const clients: Client[] = [];
before(async () => {
  await backend.start();
});
after(async () => {
  await Promise.all(clients.map((c) => c.close().catch(() => {})));
  await Promise.all(toys.map((t) => t.close()));
  await backend.stop();
});

async function start(mode: ScopedToyMode, over: Partial<Parameters<typeof startScopedToy>[1]> = {}): Promise<ScopedToy> {
  const t = await startScopedToy(mode, { backend: backend.url, ...over });
  toys.push(t);
  return t;
}
async function connect(toy: ScopedToy, bearer: string | null = "sm-bearer-a-000000000000"): Promise<Client> {
  const c = new Client({ name: "r6-fixture-test", version: "0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(toy.url), bearer ? { requestInit: { headers: { Authorization: `Bearer ${bearer}` } } } : {}));
  clients.push(c);
  return c;
}
interface Out {
  text: string;
  isError: boolean;
}
async function call(c: Client, name: string, args: Record<string, unknown>, timeout = 20_000): Promise<Out> {
  const r = (await c.callTool({ name, arguments: args }, undefined, { timeout })) as { content: Array<{ type: string; text?: string }>; isError?: boolean };
  return { text: r.content.map((x) => x.text ?? "").join(""), isError: Boolean(r.isError) };
}

// ---- the battery: the same calls against every mode; a mode must differ from `good` only on the items its one rule touches ----
type Item = { id: string; tool: string; args: Record<string, unknown> };
const D = (id: string, table: string): Item => ({ id, tool: "describe_table", args: { table } });
const Q = (id: string, sql: string): Item => ({ id, tool: "query", args: { sql } });
const O = "hr.private.salaries"; // out of scope
const BATTERY: Item[] = [
  D("s-ctrl", "sales.public.orders"),
  D("s-upper", "SALES.PUBLIC.ORDERS"),
  D("s-sibling", "sales.public.orders_smt1"),
  D("s-prefix-abuse", "sales.publicx.t_smt1"),
  D("s-container", "sales.public"),
  D("s-bare", "sales"),
  D("s-partial", "sales.public.ord"),
  D("s-partial-seg", "sales.pub"),
  D("s-encoded", "sales%2Epublic%2Eoutside_smt1"),
  D("s-deny", O),
  D("s-traversal", "sales.public.orders.._smt1"),
  D("s-quoted", '"sales"."public"."outside_smt1"'),
  { id: "c-ctrl", tool: "count_rows", args: { table: "sales.public.orders" } },
  { id: "c-out", tool: "count_rows", args: { table: O } },
  { id: "n-ctrl", tool: "search_notes", args: { q: "sm-t1" } },
  { id: "l-ctrl", tool: "list_tables", args: {} },
  Q("q-ctrl", "SELECT * FROM sales.public.orders WHERE 'sm-t1' = 'sm-t1'"),
  Q("q-noref", "SELECT 1 AS sm_t1"),
  Q("q-from", `SELECT * FROM ${O}`),
  Q("q-join", `SELECT * FROM sales.public.orders a JOIN ${O} b ON a.id = b.id`),
  Q("q-comma", `SELECT * FROM sales.public.orders a, ${O} b`),
  Q("q-subq-from", `SELECT * FROM (SELECT * FROM ${O}) x`),
  Q("q-subq-where", `SELECT * FROM sales.public.orders WHERE id IN (SELECT id FROM ${O})`),
  Q("q-scalar", `SELECT (SELECT count(*) FROM ${O}) AS n`),
  Q("q-exists", `SELECT 1 WHERE EXISTS (SELECT 1 FROM ${O})`),
  Q("q-cte", `WITH c AS (SELECT * FROM ${O}) SELECT * FROM c`),
  Q("q-cte-ok", "WITH c AS (SELECT * FROM sales.public.orders) SELECT * FROM c"),
  Q("q-union", `SELECT id FROM sales.public.orders UNION SELECT id FROM ${O}`),
  Q("q-quoted", 'SELECT * FROM "hr"."private"."salaries"'),
  Q("q-cased", "SELECT * FROM HR.Private.Salaries"),
  Q("q-alias", `SELECT * FROM ${O} AS a`),
  Q("q-insert", "INSERT INTO sales.public.orders VALUES (1)"),
  Q("q-update", "UPDATE sales.public.orders SET id = 2"),
  Q("q-delete", "DELETE FROM sales.public.orders"),
  Q("q-drop", "DROP TABLE sales.public.orders"),
  Q("q-stacked", "SELECT 1; DROP TABLE sm_t1"),
  Q("q-cte-dml", "WITH d AS (DELETE FROM sales.public.orders WHERE x = 'sm-t1') SELECT * FROM d"),
  Q("q-obfuscated", "/*x*/ iNsErT INTO sm_t1 VALUES (1)"),
  Q("q-terminator", "COMMIT; INSERT INTO sm_t1 VALUES (1)"),
  Q("q-set-session", "SET statement_timeout = 0; SELECT 1"),
  Q("q-explain", "EXPLAIN ANALYZE DELETE FROM sales.public.orders"),
  Q("q-unparseable", "SELEC T 1 sm_t1"),
  Q("q-unbalanced", "SELECT 'sm-t1"),
  Q("q-comment", "SELECT 1 -- ; DROP TABLE sm_t1"),
  Q("q-biglimit", "SELECT * FROM sales.public.orders LIMIT 1000000"),
  Q("q-smalllimit", "SELECT * FROM sales.public.orders LIMIT 10"),
];

/** The observable behaviour of one call: refused or not, and the statement the backend received (the backend's whole request for the call). */
async function signature(c: Client, item: Item): Promise<string> {
  backend.reset();
  const out = await call(c, item.tool, item.args);
  const fwd = backend.seen.map((s) => s.sql.replace(/\s+/g, " ")).join(" || ") || "-";
  return `${out.isError ? "err" : "ok"} | ${fwd}`;
}
async function behaviour(mode: ScopedToyMode): Promise<Record<string, string>> {
  const toy = await start(mode);
  const c = await connect(toy);
  const out: Record<string, string> = {};
  for (const item of BATTERY) out[item.id] = await signature(c, item);
  return out;
}

const WRAP = (q: string) => `ok | SELECT * FROM (${q}) AS sm LIMIT 1000`;
const diffIds = (good: Record<string, string>, other: Record<string, string>) => Object.keys(good).filter((k) => good[k] !== other[k]).sort();
const ids = (...xs: string[]) => [...xs].sort();

describe("scoped toy: good", { timeout: 120_000 }, () => {
  let good: Record<string, string>;
  before(async () => {
    good = await behaviour("good");
  });

  it("serves in-scope tables and forwards them with a row cap", () => {
    assert.equal(good["s-ctrl"], "ok | SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'sales.public.orders'");
    assert.equal(good["s-upper"], "ok | SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'SALES.PUBLIC.ORDERS'");
    assert.equal(good["s-sibling"].startsWith("ok |"), true, "a new name under the allowed prefix is in scope: the backend decides if it exists");
    assert.equal(good["q-ctrl"], WRAP("SELECT * FROM sales.public.orders WHERE 'sm-t1' = 'sm-t1'"));
    assert.equal(good["q-noref"], WRAP("SELECT 1 AS sm_t1"));
    assert.equal(good["q-cte-ok"], WRAP("WITH c AS (SELECT * FROM sales.public.orders) SELECT * FROM c"));
    assert.equal(good["c-ctrl"], "ok | SELECT count(*) FROM sales.public.orders");
    assert.equal(good["l-ctrl"], "ok | -");
  });

  it("refuses every out-of-scope identifier and nothing reaches the backend", () => {
    for (const id of ["s-prefix-abuse", "s-container", "s-bare", "s-partial", "s-partial-seg", "s-encoded", "s-deny", "s-traversal", "s-quoted", "c-out"]) assert.equal(good[id], "err | -", id);
  });

  it("refuses every table reference form: from, join, comma join, subquery, cte, union, quoted, cased, alias", () => {
    for (const id of ["q-from", "q-join", "q-comma", "q-subq-from", "q-subq-where", "q-scalar", "q-exists", "q-cte", "q-union", "q-quoted", "q-cased", "q-alias"]) assert.equal(good[id], "err | -", id);
  });

  it("refuses DML, DDL, session, stacked, obfuscated, unparseable and unbalanced statements (fail closed)", () => {
    for (const id of ["q-insert", "q-update", "q-delete", "q-drop", "q-stacked", "q-cte-dml", "q-obfuscated", "q-terminator", "q-set-session", "q-explain", "q-unparseable", "q-unbalanced"]) assert.equal(good[id], "err | -", id);
  });

  it("strips a comment before forwarding (the comment never reaches the backend)", () => {
    assert.equal(good["q-comment"], WRAP("SELECT 1"));
  });

  it("caps rows: wraps and lowers a larger client LIMIT, keeps a smaller one", () => {
    assert.equal(good["q-biglimit"], WRAP("SELECT * FROM sales.public.orders LIMIT 1000"));
    assert.equal(good["q-smalllimit"], WRAP("SELECT * FROM sales.public.orders LIMIT 10"));
    assert.equal(SCOPED_TOY_ROW_CAP, 1000);
  });

  it("refusals route: they name the available tables, the list tool and that retrying will not help", async () => {
    const c = await connect(await start("good"));
    for (const [tool, args] of [["describe_table", { table: O }], ["count_rows", { table: O }], ["query", { sql: `SELECT * FROM ${O}` }], ["query", { sql: "DROP TABLE x" }]] as const) {
      const r = await call(c, tool, args);
      assert.equal(r.isError, true);
      assert.match(r.text, /Available tables: sales\.public\.orders, sales\.public\.customers, sales\.public\.events/);
      assert.match(r.text, /`list_tables`/);
      assert.match(r.text, /will not help/);
      assert.doesNotMatch(r.text, /salaries.*salaries\b.*Available tables: .*salaries/);
    }
    const r = await call(c, "describe_table", { table: O });
    assert.match(r.text, /`hr\.private\.salaries` is not available through this server\./);
    assert.doesNotMatch(r.text.split("Available tables:")[1]!, /salaries/);
  });

  it("list_tables names only in-scope tables; instructions name only real tools", async () => {
    const c = await connect(await start("good"));
    const r = await call(c, "list_tables", {});
    assert.equal(r.text, "Tables you can read: sales.public.orders, sales.public.customers, sales.public.events");
    assert.equal(c.getInstructions(), "Use `list_tables` first; `query` accepts a single SELECT.");
    const names = (await c.listTools()).tools.map((t) => t.name);
    assert.deepEqual(names, ["list_tables", "describe_table", "query", "count_rows", "search_notes"]);
  });

  it("--allow with an exact entry narrows the scope (a sibling is then out of scope)", async () => {
    const c = await connect(await start("good", { allow: ["sales.public.orders"] }));
    backend.reset();
    assert.equal((await call(c, "describe_table", { table: "sales.public.orders" })).isError, false);
    assert.equal((await call(c, "describe_table", { table: "sales.public.customers" })).isError, true);
    assert.equal((await call(c, "describe_table", { table: "sales.public.ordersx" })).isError, true);
    assert.equal(backend.seen.length, 1);
  });

  it("the byte cap: a 2 MiB backend reply is not relayed; a small one is", async () => {
    const c = await connect(await start("good"));
    backend.reset();
    backend.reply = { body: '{"rows":["x"]}', bytes: 2 * 1024 * 1024 };
    const big = await call(c, "query", { sql: "SELECT * FROM sales.public.orders" });
    assert.equal(big.isError, true);
    assert.ok(Buffer.byteLength(big.text) < 1024 * 1024);
    backend.reply = { body: '{"rows":["x"]}' };
    assert.equal((await call(c, "query", { sql: "SELECT * FROM sales.public.orders" })).text, '{"rows":["x"]}');
  });

  it("count_rows returns only the count, never the rows", async () => {
    const c = await connect(await start("good"));
    backend.reset();
    backend.reply = { body: JSON.stringify({ rows: [{ id: 1, note: "sm-row-aaaa" }], count: 1 }) };
    const r = await call(c, "count_rows", { table: "sales.public.orders" });
    assert.equal(r.text, '{"count":1}');
    backend.reply = { body: JSON.stringify({ rows: [{ count: 3 }] }) };
    assert.equal((await call(c, "count_rows", { table: "sales.public.orders" })).text, '{"count":3}');
  });

  it("search_notes sends the text as a parameter, not inside the SQL", async () => {
    const c = await connect(await start("good"));
    backend.reset();
    await call(c, "search_notes", { q: "x'; DROP TABLE y; --" });
    assert.equal(backend.seen.length, 1);
    assert.doesNotMatch(backend.seen[0]!.sql, /DROP/);
    assert.deepEqual(backend.seen[0]!.params, ["x'; DROP TABLE y; --"]);
  });

  it("passes the caller's own credential through unchanged, tags the submitter, and keeps no state between callers", async () => {
    const toy = await start("good");
    backend.reset();
    const a = await connect(toy, "sm-bearer-a-aaaaaaaaaaaa");
    const b = await connect(toy, "sm-bearer-b-bbbbbbbbbbbb");
    await call(a, "describe_table", { table: "sales.public.orders" });
    await call(b, "describe_table", { table: "sales.public.orders" });
    await call(a, "search_notes", { q: "z" });
    assert.deepEqual(backend.seen.map((s) => s.authorization), ["Bearer sm-bearer-a-aaaaaaaaaaaa", "Bearer sm-bearer-b-bbbbbbbbbbbb", "Bearer sm-bearer-a-aaaaaaaaaaaa"]);
    assert.ok(backend.seen.every((s) => /^mcp:[0-9a-f]{8}$/.test(s.submitter ?? "")));
    assert.notEqual(backend.seen[0]!.submitter, backend.seen[1]!.submitter);
    assert.ok(backend.seen.every((s) => !s.raw.includes("sm-bearer")), "the token is a header, never part of the body");
  });

  it("maps a backend error to a fixed message and shows nothing from its reply", async () => {
    const c = await connect(await start("good"));
    backend.reset();
    backend.reply = { status: 500, body: '{"error":"sm-upstream-err-1234","received":{"authorization":"Bearer sm-bearer-a-000000000000"}}' };
    const r = await call(c, "query", { sql: "SELECT 1" });
    assert.equal(r.isError, true);
    assert.equal(r.text, "The backend could not run the query (status 500); nothing from its reply is shown. Try again later.");
  });

  it("times out on a backend that does not answer", async () => {
    const c = await connect(await start("good", { backendTimeoutMs: 300 }));
    backend.reset();
    backend.reply = { delayMs: 2000 };
    const t0 = Date.now();
    const r = await call(c, "query", { sql: "SELECT 1" });
    assert.equal(r.isError, true);
    assert.match(r.text, /timeout/);
    assert.ok(Date.now() - t0 < 1500);
  });

  it("requires a bearer, validates Host and Origin, and rejects an unknown session", async () => {
    const toy = await start("good");
    const post = (headers: Record<string, string>, body: unknown = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "x", version: "0" } } }) =>
      fetch(toy.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });
    assert.equal((await post({})).status, 401);
    assert.equal((await post({ authorization: "Bearer sm-x" })).status, 200);
    assert.equal((await post({ authorization: "Bearer sm-x", origin: "http://evil.example" })).status, 403);
    assert.equal((await post({ authorization: "Bearer sm-x", "mcp-session-id": "nope" })).status, 404);
    const hostile = await new Promise<number>((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: toy.port, path: "/mcp", method: "POST", headers: { host: "evil.example", authorization: "Bearer sm-x", "content-type": "application/json" } }, (res) => resolve(res.statusCode ?? 0));
      req.on("error", reject);
      req.end("{}");
    });
    assert.equal(hostile, 403);
  });
});

// Each mode: the set of battery items whose behaviour differs from `good`. Every entry is one rule's footprint.
const DIFF: Partial<Record<ScopedToyMode, string[]>> = {
  "scope-first-ref": ["q-comma", "q-join", "q-subq-where", "q-union"],
  "scope-prefix-loose": ["s-prefix-abuse"],
  "scope-container": ["s-container"],
  "scope-partial": ["s-partial", "s-partial-seg"],
  "scope-encoded": ["s-encoded"],
  "guard-fail-open": ["q-unbalanced", "q-unparseable"],
  "guard-first-keyword": ["q-cte-dml", "q-stacked", "q-terminator"],
  // one rule (an allow-list of statements replaced by a deny-list of exact-case verbs), two symptoms
  "guard-comment-strip": ["q-obfuscated", "q-unparseable"],
  "rowcap-passthrough": ["q-biglimit"],
  "comment-ok": ["q-comment"],
  "strict-case": ["s-upper"],
};
/** Modes whose rule is not visible in the battery's (refused or not, forwarded SQL) signature: it must equal good's on every item. Their rule is asserted below. */
const IDENTICAL: ScopedToyMode[] = ["bytecap-missing", "agg-raw-rows", "cred-static", "cred-swap", "cred-logged", "cred-echoed", "err-leak", "no-timeout", "deadend", "prompt-leftover", "origin-open", "anon-upstream-no-auth"];

describe("scoped toy: every mode differs from good in exactly its one rule", { timeout: 300_000 }, () => {
  let good: Record<string, string>;
  const got: Partial<Record<ScopedToyMode, Record<string, string>>> = {};
  before(async () => {
    good = await behaviour("good");
    for (const m of [...(Object.keys(DIFF) as ScopedToyMode[]), "rowcap-missing", "limit-subquery", ...IDENTICAL] as ScopedToyMode[]) got[m] = await behaviour(m);
  });

  it("scope-first-ref: only the first SQL reference is checked, so later references of every form reach the backend", () => {
    // q-from, q-subq-from, q-scalar, q-exists, q-cte and q-alias keep their out-of-scope table as the FIRST reference and stay refused.
    assert.deepEqual(diffIds(good, got["scope-first-ref"]!), ids(...DIFF["scope-first-ref"]!));
    for (const id of ["q-join", "q-comma", "q-subq-where", "q-union"]) assert.match(got["scope-first-ref"]![id]!, /^ok \|/, id);
    assert.equal(got["scope-first-ref"]!["q-from"], "err | -");
    for (const id of ["s-prefix-abuse", "s-container", "s-partial", "q-insert", "q-unparseable"]) assert.equal(got["scope-first-ref"]![id], good[id], id);
  });
  it("scope-prefix-loose: sales.publicx.t passes the prefix; the bare container is still refused", () => {
    assert.deepEqual(diffIds(good, got["scope-prefix-loose"]!), DIFF["scope-prefix-loose"]);
    assert.match(got["scope-prefix-loose"]!["s-prefix-abuse"]!, /^ok \|.*sales\.publicx\.t_smt1/);
  });
  it("scope-container: sales.public is accepted, sales is still refused", () => {
    assert.deepEqual(diffIds(good, got["scope-container"]!), DIFF["scope-container"]);
    assert.equal(got["scope-container"]!["s-bare"], "err | -");
  });
  it("scope-partial: sales.public.ord is resolved to a table", () => {
    assert.deepEqual(diffIds(good, got["scope-partial"]!), DIFF["scope-partial"]);
    assert.match(got["scope-partial"]!["s-partial"]!, /sales\.public\.orders/);
  });
  it("scope-encoded: %2E counts as a separator in the match and the raw text goes to the backend", () => {
    assert.deepEqual(diffIds(good, got["scope-encoded"]!), DIFF["scope-encoded"]);
    assert.match(got["scope-encoded"]!["s-encoded"]!, /sales%2Epublic%2Eoutside_smt1/);
  });
  it("guard-fail-open: only unparseable and unbalanced SQL is forwarded; classified writes are still refused", () => {
    assert.deepEqual(diffIds(good, got["guard-fail-open"]!), ids(...DIFF["guard-fail-open"]!));
    assert.match(got["guard-fail-open"]!["q-unparseable"]!, /SELEC T 1 sm_t1/);
    assert.match(got["guard-fail-open"]!["q-unbalanced"]!, /'sm-t1/);
    assert.equal(got["guard-fail-open"]!["q-insert"], "err | -");
  });
  it("guard-first-keyword: stacked, cte-dml and terminator statements get through; the scope layer is untouched", () => {
    assert.deepEqual(diffIds(good, got["guard-first-keyword"]!), ids(...DIFF["guard-first-keyword"]!));
    assert.equal(got["guard-first-keyword"]!["q-join"], "err | -");
    assert.equal(got["guard-first-keyword"]!["q-insert"], "err | -");
    assert.equal(got["guard-first-keyword"]!["q-unparseable"], "err | -");
  });
  it("guard-comment-strip: a mixed-case INSERT gets through; the upper-case one does not", () => {
    assert.deepEqual(diffIds(good, got["guard-comment-strip"]!), ids(...DIFF["guard-comment-strip"]!));
    assert.match(got["guard-comment-strip"]!["q-obfuscated"]!, /iNsErT INTO sm_t1/);
    assert.equal(got["guard-comment-strip"]!["q-insert"], "err | -");
    assert.equal(got["guard-comment-strip"]!["q-drop"], "err | -");
  });
  it("rowcap-missing: nothing is wrapped (a control and a huge LIMIT both go out as written)", () => {
    const d = diffIds(good, got["rowcap-missing"]!);
    assert.ok(d.includes("q-ctrl") && d.includes("q-biglimit"));
    assert.equal(got["rowcap-missing"]!["q-ctrl"], "ok | SELECT * FROM sales.public.orders WHERE 'sm-t1' = 'sm-t1'");
    assert.equal(got["rowcap-missing"]!["q-biglimit"], "ok | SELECT * FROM sales.public.orders LIMIT 1000000");
    for (const id of d) assert.match(id, /^q-(ctrl|noref|cte-ok|comment|biglimit|smalllimit)$/);
    for (const id of ["s-ctrl", "q-insert", "q-from"]) assert.equal(got["rowcap-missing"]![id], good[id], id);
  });
  it("rowcap-passthrough: wraps, but a client LIMIT above the cap becomes the outer one", () => {
    assert.deepEqual(diffIds(good, got["rowcap-passthrough"]!), DIFF["rowcap-passthrough"]);
    assert.equal(got["rowcap-passthrough"]!["q-biglimit"], "ok | SELECT * FROM (SELECT * FROM sales.public.orders LIMIT 1000000) AS sm LIMIT 1000000");
    assert.equal(got["rowcap-passthrough"]!["q-ctrl"], good["q-ctrl"]);
  });
  it("limit-subquery (near miss): the cap is an outer FETCH FIRST 1000 ROWS ONLY, refusals unchanged", () => {
    const g = got["limit-subquery"]!;
    assert.equal(g["q-ctrl"], "ok | SELECT * FROM (SELECT * FROM sales.public.orders WHERE 'sm-t1' = 'sm-t1') AS sm FETCH FIRST 1000 ROWS ONLY");
    assert.doesNotMatch(g["q-ctrl"]!, /LIMIT/);
    assert.match(g["q-biglimit"]!, /LIMIT 1000\) AS sm FETCH FIRST 1000 ROWS ONLY$/);
    for (const id of Object.keys(good).filter((k) => !k.startsWith("q-") || good[k]!.startsWith("err"))) assert.equal(g[id], good[id], id);
  });
  it("comment-ok (near miss): the comment is forwarded as a comment; nothing else changes", () => {
    assert.deepEqual(diffIds(good, got["comment-ok"]!), DIFF["comment-ok"]);
    assert.match(got["comment-ok"]!["q-comment"]!, /^ok \| SELECT \* FROM \( SELECT 1 -- ; DROP TABLE sm_t1 \) AS sm LIMIT 1000$/);
  });
  it("every mode whose rule is not a statement or identifier rule behaves like good on the whole battery", () => {
    for (const m of IDENTICAL) assert.deepEqual(diffIds(good, got[m]!), [], m);
  });
  it("strict-case (near miss): the upper-case spelling is refused, the lower-case one still served", () => {
    assert.deepEqual(diffIds(good, got["strict-case"]!), DIFF["strict-case"]);
    assert.equal(got["strict-case"]!["s-ctrl"], good["s-ctrl"]);
    assert.equal(got["strict-case"]!["s-upper"], "err | -");
  });
});

describe("scoped toy: credential, size, error and instruction modes", { timeout: 120_000 }, () => {
  const A = "sm-bearer-a-aaaaaaaaaaaa";
  const B = "sm-bearer-b-bbbbbbbbbbbb";
  async function authsSeen(mode: ScopedToyMode): Promise<Array<string | undefined>> {
    const toy = await start(mode);
    backend.reset();
    const a = await connect(toy, A);
    const b = await connect(toy, B);
    await call(a, "search_notes", { q: "1" });
    await call(b, "search_notes", { q: "2" });
    await call(a, "search_notes", { q: "3" });
    return backend.seen.map((s) => s.authorization);
  }

  it("cred-static sends TOY_STATIC_TOKEN; no other mode reads it", async () => {
    const prev = process.env.TOY_STATIC_TOKEN;
    process.env.TOY_STATIC_TOKEN = "sm-static-zzzz";
    try {
      assert.deepEqual(await authsSeen("cred-static"), ["Bearer sm-static-zzzz", "Bearer sm-static-zzzz", "Bearer sm-static-zzzz"]);
      for (const m of ["good", "cred-swap", "anon-upstream-no-auth", "err-leak"] as const) assert.ok((await authsSeen(m)).every((x) => x !== undefined && !x.includes("sm-static-zzzz")), m);
    } finally {
      if (prev === undefined) delete process.env.TOY_STATIC_TOKEN;
      else process.env.TOY_STATIC_TOKEN = prev;
    }
  });
  it("TOY_STATIC_TOKEN is referenced once in the source, in the cred-static branch", () => {
    const src = readFileSync(fileURLToPath(new URL("../../src/toy/scoped-http.ts", import.meta.url)), "utf8");
    const uses = src.split("\n").filter((l) => l.includes("process.env"));
    assert.equal(uses.length, 1);
    assert.match(uses[0]!, /cred-static/);
  });
  it("cred-swap: the first caller's credential is used for every later call, other callers' included", async () => {
    assert.deepEqual(await authsSeen("cred-swap"), [`Bearer ${A}`, `Bearer ${A}`, `Bearer ${A}`]);
    assert.deepEqual(await authsSeen("good"), [`Bearer ${A}`, `Bearer ${B}`, `Bearer ${A}`]);
  });
  it("cred-logged: the Authorization header reaches stderr; good prints nothing", async () => {
    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as { write: unknown }).write = (s: string | Uint8Array) => (lines.push(String(s)), true);
    try {
      await authsSeen("good");
      assert.equal(lines.filter((l) => l.includes(A)).length, 0);
      await authsSeen("cred-logged");
      assert.ok(lines.some((l) => l.includes(A)));
      assert.ok(lines.some((l) => l.includes(B)));
    } finally {
      (process.stderr as { write: unknown }).write = orig;
    }
  });
  it("cred-echoed: every reply carries the caller's credential; good's never does", async () => {
    for (const [mode, expectEcho] of [["good", false], ["cred-echoed", true]] as const) {
      const c = await connect(await start(mode), A);
      for (const [tool, args] of [["list_tables", {}], ["describe_table", { table: "sales.public.orders" }], ["describe_table", { table: O }], ["query", { sql: "DROP TABLE x" }]] as const) {
        const r = await call(c, tool, args);
        assert.equal(r.text.includes(A), expectEcho, `${mode} ${tool}`);
      }
    }
  });
  it("err-leak: the backend's error body (canary and echoed credential) is relayed raw; good relays nothing", async () => {
    const body = `{"error":"sm-upstream-err-9999","received":{"authorization":"Bearer ${A}"}}`;
    for (const [mode, leaks] of [["good", false], ["err-leak", true]] as const) {
      const c = await connect(await start(mode), A);
      backend.reset();
      backend.reply = { status: 500, body };
      const r = await call(c, "query", { sql: "SELECT 1" });
      assert.equal(r.isError, true);
      assert.equal(r.text.includes("sm-upstream-err-9999"), leaks, mode);
      assert.equal(r.text.includes(A), leaks, mode);
    }
  });
  it("no-timeout: waits on a silent backend until the server closes; good gives up after its timeout", async () => {
    const hung = await start("no-timeout", { backendTimeoutMs: 200 });
    const c = await connect(hung);
    backend.reset();
    backend.reply = { delayMs: 60_000 };
    const pending = call(c, "query", { sql: "SELECT 1" }, 3000);
    const winner = await Promise.race([pending.then(() => "answered"), new Promise((r) => setTimeout(() => r("still waiting"), 900))]);
    assert.equal(winner, "still waiting");
    await hung.close();
    const r = await pending.catch(() => ({ isError: true, text: "closed" }));
    assert.equal(r.isError, true);

    const g = await connect(await start("good", { backendTimeoutMs: 200 }));
    const t0 = Date.now();
    assert.match((await call(g, "query", { sql: "SELECT 1" })).text, /timeout/);
    assert.ok(Date.now() - t0 < 1500);
  });
  it("bytecap-missing: a 2 MiB backend reply is relayed whole; good refuses it", async () => {
    backend.reset();
    backend.reply = { body: '{"rows":["x"]}', bytes: 2 * 1024 * 1024 };
    const c = await connect(await start("bytecap-missing"));
    const r = await call(c, "query", { sql: "SELECT * FROM sales.public.orders" });
    assert.equal(r.isError, false);
    assert.ok(Buffer.byteLength(r.text) >= 2 * 1024 * 1024);
  });
  it("agg-raw-rows: count_rows returns the rows; good returns only the count", async () => {
    const reply = JSON.stringify({ rows: [{ id: 1, note: "sm-row-abcd1234" }], count: 1 });
    for (const [mode, rows] of [["good", false], ["agg-raw-rows", true]] as const) {
      const c = await connect(await start(mode));
      backend.reset();
      backend.reply = { body: reply };
      const r = await call(c, "count_rows", { table: "sales.public.orders" });
      assert.equal(r.text.includes("sm-row-abcd1234"), rows, mode);
    }
  });
  it("deadend: every refusal is the single word forbidden; good's refusals route", async () => {
    const c = await connect(await start("deadend"));
    for (const [tool, args] of [["describe_table", { table: O }], ["count_rows", { table: O }], ["query", { sql: `SELECT * FROM ${O}` }], ["query", { sql: "DROP TABLE x" }]] as const) assert.deepEqual(await call(c, tool, args), { text: "forbidden", isError: true });
    assert.equal((await call(c, "describe_table", { table: "sales.public.orders" })).isError, false);
  });
  it("prompt-leftover: the instructions name a tool that does not exist and keep a leftover prompt", async () => {
    const c = await connect(await start("prompt-leftover"));
    const text = c.getInstructions() ?? "";
    assert.match(text, /export_csv/);
    assert.match(text, /You are a helpful assistant for ACME Corp/);
    const names = (await c.listTools()).tools.map((t) => t.name);
    assert.ok(!names.includes("export_csv"));
    assert.ok(text.startsWith("Use `list_tables` first; `query` accepts a single SELECT."));
  });
  it("origin-open: a foreign Host and Origin are accepted; good refuses them", async () => {
    const send = (toy: ScopedToy, headers: Record<string, string>) =>
      new Promise<number>((resolve, reject) => {
        const req = http.request({ host: "127.0.0.1", port: toy.port, path: "/mcp", method: "POST", headers: { authorization: "Bearer sm-x", "content-type": "application/json", accept: "application/json, text/event-stream", ...headers } }, (res) => (res.resume(), resolve(res.statusCode ?? 0)));
        req.on("error", reject);
        req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "x", version: "0" } } }));
      });
    const hostile = { host: "evil.example", origin: "http://evil.example" };
    assert.equal(await send(await start("good"), hostile), 403);
    assert.equal(await send(await start("origin-open"), hostile), 200);
  });
  it("refuse-all (near miss): every call is an error and nothing reaches the backend", async () => {
    const c = await connect(await start("refuse-all"));
    backend.reset();
    for (const item of BATTERY) assert.equal((await call(c, item.tool, item.args)).isError, true, item.id);
    assert.equal(backend.seen.length, 0);
  });
  it("anon-upstream-no-auth (near miss): an anonymous call is served and reaches the backend with no credential header", async () => {
    const toy = await start("anon-upstream-no-auth");
    backend.reset();
    const anon = await connect(toy, null);
    assert.equal((await call(anon, "search_notes", { q: "x" })).isError, false);
    assert.equal(backend.seen.length, 1);
    assert.equal(backend.seen[0]!.authorization, undefined);
    assert.equal(backend.seen[0]!.submitter, "mcp:anonymous");
    // with a token it still passes the caller's own
    const named = await connect(toy, A);
    await call(named, "search_notes", { q: "y" });
    assert.equal(backend.seen[1]!.authorization, `Bearer ${A}`);
    // good turns an anonymous caller away at the door
    const good = await start("good");
    await assert.rejects(connect(good, null));
  });
});

describe("scoped toy: process properties", () => {
  it("lists every mode of the design: 21 broken and 5 near misses plus good", () => {
    assert.equal(SCOPED_TOY_MODES.length, 1 + 21 + 5);
  });
  it("binds 127.0.0.1 only", async () => {
    const toy = await start("good");
    assert.equal(toy.host, "127.0.0.1");
    assert.match(toy.url, /^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
    const external = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal);
    if (external) {
      const err = await new Promise<NodeJS.ErrnoException | null>((resolve) => {
        const s = net.connect({ host: external.address, port: toy.port });
        s.once("connect", () => (s.destroy(), resolve(null)));
        s.once("error", (e) => resolve(e as NodeJS.ErrnoException));
      });
      assert.equal(err?.code, "ECONNREFUSED", "a non-loopback address must not reach the toy");
    }
    const src = readFileSync(fileURLToPath(new URL("../../src/toy/scoped-http.ts", import.meta.url)), "utf8");
    assert.doesNotMatch(src, /0\.0\.0\.0|"::"/);
    assert.match(src, /listen\(opts\.port \?\? 0, "127\.0\.0\.1"/);
  });
  it("--backend is honoured: the toy talks to the backend it was given and no other", async () => {
    const other = new Backend();
    await other.start();
    try {
      const toy = await startScopedToy("good", { backend: `${other.url}/` });
      toys.push(toy);
      backend.reset();
      const c = await connect(toy);
      await call(c, "describe_table", { table: "sales.public.orders" });
      assert.equal(other.seen.length, 1);
      assert.equal(other.seen[0]!.path, "/sql");
      assert.equal(backend.seen.length, 0);
    } finally {
      await other.stop();
    }
  });
  it("the command line needs --backend and a known --mode", async () => {
    const { spawnSync } = await import("node:child_process");
    const file = fileURLToPath(new URL("../toy/scoped-http.js", import.meta.url));
    const noBackend = spawnSync(process.execPath, [file, "--mode", "good"], { encoding: "utf8" });
    assert.equal(noBackend.status, 2);
    assert.match(noBackend.stderr, /--backend/);
    const badMode = spawnSync(process.execPath, [file, "--mode", "nope", "--backend", "http://127.0.0.1:1"], { encoding: "utf8" });
    assert.equal(badMode.status, 2);
    assert.match(badMode.stderr, /--mode must be one of/);
  });
});
