// Synthetic toy: a scoped, read-only data server over Streamable HTTP, for round 6.
// Written from scratch on the pattern of toy/http.ts (node:http + the MCP SDK transport). Loopback only; prints `listening <url>`.
// Run: node dist/toy/scoped-http.js --mode <mode> --port <n> --backend <url> [--allow <entry>]... [--deny <entry>]...
//   --allow / --deny take identifiers; an entry ending in "." is a prefix (default allow `sales.public.`, default deny `hr.private.salaries`).
//   TOY_STATIC_TOKEN is read by mode `cred-static` only.
// Not part of the product surface. The server answers tool calls by talking to a backend (POST <backend>/sql) with the caller's own bearer token.
//
//   good   identifier scope (allow/deny, case-insensitive), a fail-closed SELECT-only SQL guard whose table references are all checked
//          (FROM, JOIN, comma join, subquery, CTE, UNION, quoted, any case), a row cap by LIMIT wrapping, a 1 MiB reply cap, an aggregate-only
//          count_rows, per-caller bearer passthrough with no fallback credential, Host/Origin/bearer/session validation, routing refusals.
//   every other mode breaks exactly one rule of `good` (or is a near miss that must still pass); see MODE_NOTES below.
import { createHash, randomUUID } from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export const SCOPED_TOY_MODES = [
  "good",
  // broken
  "scope-first-ref", "scope-prefix-loose", "scope-container", "scope-partial", "scope-encoded",
  "guard-fail-open", "guard-first-keyword", "guard-comment-strip",
  "rowcap-missing", "rowcap-passthrough", "bytecap-missing", "agg-raw-rows",
  "cred-static", "cred-swap", "cred-logged", "cred-echoed", "err-leak", "no-timeout",
  "deadend", "prompt-leftover", "origin-open",
  // near misses (each must still pass the check it neighbours)
  "strict-case", "limit-subquery", "comment-ok", "refuse-all", "anon-upstream-no-auth",
] as const;
export type ScopedToyMode = (typeof SCOPED_TOY_MODES)[number];

/** What each mode changes relative to `good`. Kept next to the list so a reader sees the one rule per mode. */
export const MODE_NOTES: Record<ScopedToyMode, string> = {
  good: "reference behaviour",
  "scope-first-ref": "SQL: only the first table reference is checked against the scope",
  "scope-prefix-loose": "prefix compared without its separator (sales.publicx.t passes)",
  "scope-container": "a bare container (sales.public) is accepted",
  "scope-partial": "a partial name (sales.public.ord, sales.pub) is resolved by prefix to a table",
  "scope-encoded": "the scope matcher decodes %2E to a separator; the raw text goes to the backend",
  "guard-fail-open": "SQL that cannot be parsed or classified is forwarded instead of refused",
  "guard-first-keyword": "the statement guard looks at the first keyword only (select, with or a transaction word); table references are still scoped",
  "guard-comment-strip": "the statement allow-list is a deny-list on exact-case verbs (iNsErT passes; so does SQL that is not classified)",
  "rowcap-missing": "the statement is forwarded without a row cap",
  "rowcap-passthrough": "wraps, but the outer LIMIT is the client's own larger one",
  "bytecap-missing": "relays the whole backend reply however large",
  "agg-raw-rows": "count_rows returns the backend's rows, not just the count",
  "cred-static": "uses TOY_STATIC_TOKEN as the backend credential instead of the caller's",
  "cred-swap": "caches the first caller's credential and uses it for every later call",
  "cred-logged": "logs the Authorization header to stderr",
  "cred-echoed": "every reply carries the caller's credential",
  "err-leak": "relays the backend's error body raw",
  "no-timeout": "waits for the backend forever",
  deadend: "every refusal says only \"forbidden\"",
  "prompt-leftover": "instructions name a tool that does not exist and keep a leftover prompt",
  "origin-open": "no Host or Origin validation",
  "strict-case": "near miss: the scope compare is case-sensitive (upper-case spelling refused)",
  "limit-subquery": "near miss: caps rows with an outer FETCH FIRST instead of LIMIT",
  "comment-ok": "near miss: forwards comments as written (they are comments, not statements)",
  "refuse-all": "near miss: refuses every tool call",
  "anon-upstream-no-auth": "near miss: no bearer is required; an anonymous call reaches the backend with no credential header",
};

export const SCOPED_TOY_ROW_CAP = 1000;
export const SCOPED_TOY_BYTE_CAP = 1024 * 1024;
export const SCOPED_TOY_BACKEND_TIMEOUT_MS = 3000;
export const SCOPED_TOY_DEFAULT_ALLOW = ["sales.public."];
export const SCOPED_TOY_DEFAULT_DENY = ["hr.private.salaries"];
/** Tables the catalog knows (containers such as `sales.public` are not tables). */
export const SCOPED_TOY_TABLES = ["sales.public.orders", "sales.public.customers", "sales.public.events", "hr.private.salaries"];

export interface ScopedToy {
  mode: ScopedToyMode;
  port: number;
  host: "127.0.0.1";
  /** The MCP endpoint, for example http://127.0.0.1:41234/mcp. */
  url: string;
  close(): Promise<void>;
}
export interface ScopedToyOptions {
  port?: number;
  /** Base URL of the backend, e.g. http://127.0.0.1:5555 (the harness's {upstream}). */
  backend: string;
  allow?: string[];
  deny?: string[];
  /** Tests only; default 3000. */
  backendTimeoutMs?: number;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// SQL: a small tokenizer and a reference extractor. It is the toy's guard, not a general parser; anything it cannot read is refused.
// ---------------------------------------------------------------------------------------------------------------------------------

type Tok = { t: "word" | "qident" | "string" | "num" | "punct"; v: string };
class SqlError extends Error {}

/** Splits `src` into tokens and returns a copy with comments replaced by a space (newlines kept). Throws SqlError on an unterminated quote or comment. */
function tokenize(src: string): { tokens: Tok[]; clean: string } {
  const tokens: Tok[] = [];
  let clean = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === "-" && src[i + 1] === "-") {
      while (i < src.length && src[i] !== "\n") i++;
      clean += " ";
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) throw new SqlError("unterminated comment");
      i = end + 2;
      clean += " ";
      continue;
    }
    if (c === "'" || c === '"') {
      let j = i + 1;
      let v = "";
      for (;;) {
        if (j >= src.length) throw new SqlError("unterminated quote");
        if (src[j] === c) {
          if (src[j + 1] === c) {
            v += c;
            j += 2;
            continue;
          }
          break;
        }
        v += src[j++];
      }
      tokens.push({ t: c === "'" ? "string" : "qident", v });
      clean += src.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    const word = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(src.slice(i, i + 200));
    if (word) {
      tokens.push({ t: "word", v: word[0] });
      clean += word[0];
      i += word[0].length;
      continue;
    }
    const num = /^\d+(\.\d+)?/.exec(src.slice(i, i + 50));
    if (num) {
      tokens.push({ t: "num", v: num[0] });
      clean += num[0];
      i += num[0].length;
      continue;
    }
    if (!/\s/.test(c)) tokens.push({ t: "punct", v: c });
    clean += c;
    i++;
  }
  let depth = 0;
  for (const k of tokens) {
    if (k.t !== "punct") continue;
    if (k.v === "(") depth++;
    if (k.v === ")" && --depth < 0) throw new SqlError("unbalanced parentheses");
  }
  if (depth !== 0) throw new SqlError("unbalanced parentheses");
  return { tokens, clean };
}

/** Statements the guard refuses by their first keyword (everything but select and with is refused; this list only names the known ones). */
const DENY_FIRST = new Set(["insert", "update", "delete", "merge", "create", "drop", "alter", "truncate", "grant", "revoke", "vacuum", "analyze", "analyse", "set", "copy", "commit", "begin", "rollback", "start", "end", "savepoint", "release", "call", "do", "execute", "explain", "prepare", "deallocate", "lock", "load", "refresh", "reindex", "cluster", "pragma", "attach", "detach", "reset", "listen", "notify", "show", "comment"]);
/** Words that write or escape wherever they appear in a statement. */
const DENY_ANYWHERE = new Set(["insert", "update", "delete", "merge", "create", "drop", "alter", "truncate", "grant", "revoke", "copy", "call", "execute", "into"]);
const TRANSACTION_WORDS = new Set(["begin", "commit", "rollback", "end", "start"]);
/** A word that ends a FROM list, so a later comma is not a comma join. */
const FROM_END = new Set(["where", "group", "order", "having", "limit", "offset", "fetch", "union", "intersect", "except", "window", "qualify", "returning", "for"]);
const RESERVED_AS_TABLE = new Set(["select", "where", "on", "using", "group", "order", "having", "limit", "union", "values"]);

/** Table references of a token list: each is the list of its name parts. Returns an error string when a reference cannot be read. */
function tableRefs(tokens: Tok[]): { refs: string[][]; ctes: Set<string> } | string {
  const ctes = new Set<string>();
  const isName = (k: Tok | undefined) => k !== undefined && (k.t === "word" || k.t === "qident");
  for (let i = 0; i + 2 < tokens.length; i++) {
    const prev = tokens[i - 1];
    if (isName(tokens[i]) && tokens[i + 1]!.t === "word" && tokens[i + 1]!.v.toLowerCase() === "as" && tokens[i + 2]!.v === "(" && prev && ((prev.t === "word" && ["with", "recursive"].includes(prev.v.toLowerCase())) || prev.v === ",")) ctes.add(tokens[i]!.v.toLowerCase());
  }
  const refs: string[][] = [];
  const inFrom: boolean[] = [false];
  let expect = false;
  for (let i = 0; i < tokens.length; i++) {
    const k = tokens[i]!;
    const lower = k.t === "word" ? k.v.toLowerCase() : "";
    if (expect) {
      if (k.v === "(" && k.t === "punct") {
        expect = false;
        inFrom.push(false);
        continue;
      }
      if (lower === "lateral") continue;
      if (!isName(k) || (k.t === "word" && RESERVED_AS_TABLE.has(lower))) return `cannot read a table name near "${k.v}"`;
      const parts = [k.v];
      while (tokens[i + 1]?.v === "." && tokens[i + 1]!.t === "punct" && isName(tokens[i + 2])) {
        parts.push(tokens[i + 2]!.v);
        i += 2;
      }
      if (tokens[i + 1]?.v === "(" && tokens[i + 1]!.t === "punct") return "functions in FROM are not accepted";
      refs.push(parts);
      expect = false;
      continue;
    }
    if (k.t === "punct") {
      if (k.v === "(") inFrom.push(false);
      else if (k.v === ")") inFrom.pop();
      else if (k.v === "," && inFrom[inFrom.length - 1]) expect = true;
      continue;
    }
    if (lower === "from") {
      inFrom[inFrom.length - 1] = true;
      expect = true;
    } else if (lower === "join") expect = true;
    else if (FROM_END.has(lower)) inFrom[inFrom.length - 1] = false;
  }
  return { refs, ctes };
}

// ---------------------------------------------------------------------------------------------------------------------------------

function readBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function jsonError(res: http.ServerResponse, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }));
}

interface ToolOut {
  text: string;
  isError?: boolean;
}

const TOOLS = [
  { name: "list_tables", description: "List the tables this server can read.", inputSchema: { type: "object", properties: {} } },
  { name: "describe_table", description: "Describe the columns of one allowed table. Only tables listed by list_tables are permitted.", inputSchema: { type: "object", properties: { table: { type: "string", description: "Table identifier, for example sales.public.orders" } }, required: ["table"] } },
  { name: "query", description: "Run one read-only SELECT statement over the allowed tables. At most 1000 rows are returned.", inputSchema: { type: "object", properties: { sql: { type: "string", description: "A single SELECT statement" } }, required: ["sql"] } },
  { name: "count_rows", description: "Count the rows of one allowed table. Returns only the number.", inputSchema: { type: "object", properties: { table: { type: "string", description: "Table identifier" } }, required: ["table"] } },
  { name: "search_notes", description: "Search the free-text notes of events. The text is sent as a parameter, never as SQL.", inputSchema: { type: "object", properties: { q: { type: "string", description: "Text to look for" } }, required: ["q"] } },
];

export async function startScopedToy(mode: ScopedToyMode, opts: ScopedToyOptions): Promise<ScopedToy> {
  if (!SCOPED_TOY_MODES.includes(mode)) throw new Error(`scoped toy: unknown mode ${mode}`);
  const backend = opts.backend.replace(/\/+$/, "");
  const timeoutMs = opts.backendTimeoutMs ?? SCOPED_TOY_BACKEND_TIMEOUT_MS;
  const strict = mode === "strict-case";
  const fold = (s: string) => (strict ? s : s.toLowerCase());
  const allow = (opts.allow ?? SCOPED_TOY_DEFAULT_ALLOW).map(fold);
  const deny = (opts.deny ?? SCOPED_TOY_DEFAULT_DENY).map(fold);
  const closing = new AbortController();
  let cachedAuth: string | undefined; // cred-swap
  let port = 0;

  // ---- scope ----
  const catalogUnder = (entry: string) => SCOPED_TOY_TABLES.map(fold).filter((t) => t.startsWith(entry)).map((t) => t.slice(entry.length));
  /** The identifier to forward when `raw` is in scope, or undefined. */
  const resolve = (raw: string): string | undefined => {
    let id = fold(raw);
    if (mode === "scope-encoded") id = id.replace(/%2e/gi, ".");
    for (const d of deny) if (d.endsWith(".") ? id.startsWith(d) : id === d) return undefined;
    // scope-partial, the same rule one level up: a name cut inside a segment (`sales.pub`) is completed to the first in-scope table it starts.
    if (mode === "scope-partial" && /^[a-z0-9_.]+$/i.test(id) && !id.endsWith(".")) {
      const table = SCOPED_TOY_TABLES.map(fold).find((t) => t.length > id.length && t.startsWith(id) && t[id.length] !== ".");
      if (table !== undefined && allow.some((e) => (e.endsWith(".") ? table.startsWith(e) : table === e))) return table;
    }
    for (const entry of allow) {
      if (!entry.endsWith(".")) {
        if (id === entry) return raw;
        continue;
      }
      if (mode === "scope-container" && id === entry.slice(0, -1)) return raw;
      // scope-prefix-loose: the prefix is compared without its separator, so `sales.publicx.t` passes as `sales.public` + `x.t`.
      if (mode === "scope-prefix-loose" && !id.startsWith(entry) && id.startsWith(entry.slice(0, -1)) && /^[a-z0-9_]+\.[a-z0-9_]+$/i.test(id.slice(entry.length - 1))) return raw;
      if (!id.startsWith(entry)) continue;
      const rest = id.slice(entry.length);
      if (!/^[a-z0-9_]+$/i.test(rest)) continue;
      const partialOf = catalogUnder(entry).find((t) => t.startsWith(rest) && t !== rest);
      if (partialOf !== undefined) {
        if (mode === "scope-partial") return `${raw.slice(0, entry.length)}${partialOf}`;
        continue;
      }
      return raw;
    }
    return undefined;
  };
  const available = () => SCOPED_TOY_TABLES.filter((t) => resolve(t) !== undefined);
  const refusal = (what: string): ToolOut => {
    if (mode === "deadend") return { text: "forbidden", isError: true };
    return { text: `${what} Available tables: ${available().join(", ")} (call \`list_tables\`). Retrying with the same input will not help.`, isError: true };
  };

  // ---- the guard: returns the statement to forward, or a refusal ----
  const guard = (sql: string): { forward: string } | { refused: string } => {
    let parsed: { tokens: Tok[]; clean: string };
    try {
      parsed = tokenize(sql);
    } catch {
      return mode === "guard-fail-open" ? { forward: sql } : { refused: "That statement could not be parsed." };
    }
    const { tokens } = parsed;
    const body = [...tokens];
    if (body.length && body[body.length - 1]!.v === ";" && body[body.length - 1]!.t === "punct") body.pop();
    const first = body[0]?.t === "word" ? body[0].v : undefined;
    const lowerFirst = first?.toLowerCase();
    const clean = parsed.clean.trim().replace(/;\s*$/, "");
    const forward = mode === "comment-ok" ? sql.trim().replace(/;\s*$/, "") : clean;

    if (mode === "guard-first-keyword") {
      // Only the first keyword is looked at: no other keyword and no statement count. (Table references are still checked below: that layer is the scope's.)
      const ok = lowerFirst !== undefined && (lowerFirst === "select" || lowerFirst === "with" || TRANSACTION_WORDS.has(lowerFirst));
      if (!ok) return { refused: "Only a single read-only SELECT is accepted." };
    } else if (mode === "guard-comment-strip") {
      // The statement allow-list is replaced by a deny-list over exact-case verbs, so iNsErT is not recognised (and an unclassifiable statement is not
      // refused): one rule, two symptoms. INTO is not a statement verb, so a deny-list of verbs would not name it. Table references are checked below.
      const sloppy = (w: string) => w === w.toLowerCase() || w === w.toUpperCase();
      const hit = body.find((k, idx) => k.t === "word" && sloppy(k.v) && ((DENY_ANYWHERE.has(k.v.toLowerCase()) && k.v.toLowerCase() !== "into") || (idx === 0 && DENY_FIRST.has(k.v.toLowerCase()))));
      if (hit) return { refused: "Only a single read-only SELECT is accepted." };
    } else {
      if (mode === "guard-fail-open" && (lowerFirst === undefined || (lowerFirst !== "select" && lowerFirst !== "with" && !DENY_FIRST.has(lowerFirst)))) return { forward: sql };
      if (body.some((k) => k.t === "punct" && k.v === ";")) return { refused: "Only one statement per call is accepted." };
      if (lowerFirst !== "select" && lowerFirst !== "with") return { refused: "Only a single read-only SELECT is accepted." };
      const bad = body.find((k) => k.t === "word" && (DENY_ANYWHERE.has(k.v.toLowerCase()) || /^pg_/i.test(k.v)));
      if (bad) return { refused: `\`${bad.v}\` is not accepted: this server is read-only.` };
    }
    const found = tableRefs(body);
    if (typeof found === "string") return mode === "guard-fail-open" ? { forward } : { refused: `That statement could not be checked (${found}).` };
    const checked = mode === "scope-first-ref" ? found.refs.slice(0, 1) : found.refs;
    for (const parts of checked) {
      const name = parts.join(".");
      if (parts.length === 1 && found.ctes.has(parts[0]!.toLowerCase())) continue;
      if (parts.some((p) => p.includes(".")) || resolve(name) === undefined) return { refused: `\`${name}\` is not available through this server.` };
    }
    return { forward };
  };

  const capSql = (sql: string): string => {
    const limit = /\blimit\s+(\d+)(\s+offset\s+\d+)?\s*$/i.exec(sql);
    const clientN = limit ? Number(limit[1]) : undefined;
    const lowered = limit && clientN! > SCOPED_TOY_ROW_CAP ? sql.replace(limit[0], `LIMIT ${SCOPED_TOY_ROW_CAP}${limit[2] ?? ""}`) : sql;
    switch (mode) {
      case "rowcap-missing":
        return sql;
      case "rowcap-passthrough":
        return `SELECT * FROM (${sql}) AS sm LIMIT ${clientN !== undefined && clientN > SCOPED_TOY_ROW_CAP ? clientN : SCOPED_TOY_ROW_CAP}`;
      case "limit-subquery":
        return `SELECT * FROM (${lowered}) AS sm FETCH FIRST ${SCOPED_TOY_ROW_CAP} ROWS ONLY`;
      case "comment-ok": // identical to good unless a line comment is present, which then needs its own line
        return /--/.test(sql) ? `SELECT * FROM (\n${lowered}\n) AS sm LIMIT ${SCOPED_TOY_ROW_CAP}` : `SELECT * FROM (${lowered}) AS sm LIMIT ${SCOPED_TOY_ROW_CAP}`;
      default:
        return `SELECT * FROM (${lowered}) AS sm LIMIT ${SCOPED_TOY_ROW_CAP}`;
    }
  };

  // ---- the backend ----
  const credentialFor = (auth: string | undefined): string | undefined => {
    if (mode === "cred-static") return `Bearer ${process.env.TOY_STATIC_TOKEN ?? "sm-toy-static-token"}`;
    if (mode === "cred-swap") return (cachedAuth ??= auth);
    return auth;
  };
  type Backend = { ok: true; text: string; json: unknown } | { ok: false; out: ToolOut };
  const callBackend = async (payload: Record<string, unknown>, auth: string | undefined): Promise<Backend> => {
    const cred = credentialFor(auth);
    const submitter = `mcp:${auth ? createHash("sha256").update(auth).digest("hex").slice(0, 8) : "anonymous"}`;
    const signals = [closing.signal];
    if (mode !== "no-timeout") signals.push(AbortSignal.timeout(timeoutMs));
    try {
      const res = await fetch(`${backend}/sql`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(cred ? { authorization: cred } : {}) },
        body: JSON.stringify({ ...payload, submitter }),
        signal: AbortSignal.any(signals),
      });
      const limit = mode === "bytecap-missing" ? undefined : SCOPED_TOY_BYTE_CAP;
      const chunks: Buffer[] = [];
      let n = 0;
      let truncated = false;
      const reader = res.body?.getReader();
      for (;;) {
        const r = await reader?.read();
        if (!r || r.done) break;
        n += r.value.length;
        if (limit !== undefined && n > limit) {
          truncated = true;
          await reader!.cancel().catch(() => {});
          break;
        }
        chunks.push(Buffer.from(r.value));
      }
      const text = Buffer.concat(chunks).toString("utf8");
      if (!res.ok) return { ok: false, out: { text: `The backend could not run the query (status ${res.status}); ${mode === "err-leak" ? `its reply: ${text}` : "nothing from its reply is shown. Try again later."}`, isError: true } };
      if (truncated) return { ok: false, out: { text: "The backend reply is larger than the 1 MiB limit and was not returned. Try a WHERE clause or a smaller LIMIT.", isError: true } };
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
      return { ok: true, text, json };
    } catch (e) {
      if (closing.signal.aborted) return { ok: false, out: { text: "The server is shutting down.", isError: true } };
      if (e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError")) return { ok: false, out: { text: `The backend did not answer within ${Math.round(timeoutMs / 1000)} s (timeout); nothing was run. Try again later.`, isError: true } };
      return { ok: false, out: { text: "The backend could not be reached. Try again later.", isError: true } };
    }
  };

  // ---- the tools ----
  const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
  const callTool = async (name: string, args: Record<string, unknown>, auth: string | undefined): Promise<ToolOut> => {
    if (mode === "refuse-all") return { text: "Refused: this server is not accepting calls.", isError: true };
    switch (name) {
      case "list_tables":
        return { text: `Tables you can read: ${available().join(", ")}` };
      case "describe_table": {
        const table = str(args.table);
        if (table === undefined) return { text: "table must be a string. Try again with a string.", isError: true };
        const id = resolve(table);
        if (id === undefined) return refusal(`\`${table}\` is not available through this server.`);
        const r = await callBackend({ sql: `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '${id.replace(/'/g, "''")}'` }, auth);
        return r.ok ? { text: r.text } : r.out;
      }
      case "query": {
        const sql = str(args.sql);
        if (sql === undefined) return { text: "sql must be a string. Try again with a string.", isError: true };
        const g = guard(sql);
        if ("refused" in g) return refusal(g.refused);
        const r = await callBackend({ sql: capSql(g.forward) }, auth);
        return r.ok ? { text: r.text } : r.out;
      }
      case "count_rows": {
        const table = str(args.table);
        if (table === undefined) return { text: "table must be a string. Try again with a string.", isError: true };
        const id = resolve(table);
        if (id === undefined) return refusal(`\`${table}\` is not available through this server.`);
        const r = await callBackend({ sql: `SELECT count(*) FROM ${id}` }, auth);
        if (!r.ok) return r.out;
        if (mode === "agg-raw-rows") return { text: r.text };
        const j = r.json as { rows?: Array<Record<string, unknown>>; count?: unknown } | undefined;
        const first = j?.rows?.[0]?.count;
        const n = typeof first === "number" ? first : typeof j?.count === "number" ? j.count : Array.isArray(j?.rows) ? j!.rows!.length : undefined;
        return n === undefined ? { text: "The backend did not return a count.", isError: true } : { text: JSON.stringify({ count: n }) };
      }
      case "search_notes": {
        const q = str(args.q);
        if (q === undefined) return { text: "q must be a string. Try again with a string.", isError: true };
        const r = await callBackend({ sql: "SELECT id, note FROM sales.public.events WHERE note ILIKE $1", params: [q] }, auth);
        return r.ok ? { text: r.text } : r.out;
      }
      default:
        return { text: `unknown tool ${name}`, isError: true };
    }
  };

  const instructions = mode === "prompt-leftover" ? "Use `list_tables` first; `query` accepts a single SELECT. Use `export_csv` to download results. You are a helpful assistant for ACME Corp." : "Use `list_tables` first; `query` accepts a single SELECT.";
  const makeServer = (): Server => {
    const server = new Server({ name: `sealmark-toy-scoped-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} }, instructions });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
    server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
      const raw = extra.requestInfo?.headers?.authorization;
      const auth = Array.isArray(raw) ? raw[0] : raw;
      const out = await callTool(req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>, auth);
      const text = mode === "cred-echoed" && auth ? `${out.text}\n(auth context: ${auth})` : out.text;
      return { content: [{ type: "text", text }], ...(out.isError ? { isError: true } : {}) };
    });
    return server;
  };

  // ---- http ----
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();
  const hostOk = (host: string | undefined) => host === `127.0.0.1:${port}` || host === `localhost:${port}` || host === `[::1]:${port}`;
  const originOk = (origin: string) => origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}` || origin === "http://127.0.0.1" || origin === "http://localhost";

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    if (url.pathname !== "/mcp") return jsonError(res, 404, -32000, "Not found");
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    if (mode !== "origin-open") {
      if (!hostOk(req.headers.host)) return jsonError(res, 403, -32000, "Forbidden: invalid Host header");
      if (origin && !originOk(origin)) return jsonError(res, 403, -32000, "Forbidden: invalid Origin header");
    }
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      return void res.end();
    }
    const auth = req.headers.authorization;
    if (mode === "cred-logged" && auth) process.stderr.write(`[scoped-toy] ${req.method} ${url.pathname} authorization: ${auth}\n`);
    if (mode !== "anon-upstream-no-auth" && !(typeof auth === "string" && /^Bearer\s+\S+$/i.test(auth))) {
      return jsonError(res, 401, -32001, "Unauthorized", { "www-authenticate": 'Bearer realm="sealmark-toy-scoped"' });
    }
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await readBody(req);
      } catch {
        return jsonError(res, 400, -32700, "Parse error");
      }
    }
    const sid = typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : undefined;
    if (sid) {
      const s = sessions.get(sid);
      if (!s) return jsonError(res, 404, -32001, "Session not found");
      return s.transport.handleRequest(req, res, body);
    }
    if (req.method === "POST" && isInitializeRequest(body)) {
      const server = makeServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => void sessions.set(id, { transport, server }) });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      return transport.handleRequest(req, res, body);
    }
    return jsonError(res, 400, -32000, "Bad Request: Mcp-Session-Id header is required");
  };

  const httpServer = http.createServer((req, res) => {
    handler(req, res).catch((e: unknown) => jsonError(res, 500, -32603, e instanceof Error ? e.message : "internal error"));
  });
  await new Promise<void>((resolveListen, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.port ?? 0, "127.0.0.1", () => resolveListen());
  });
  port = (httpServer.address() as { port: number }).port;

  return {
    mode,
    port,
    host: "127.0.0.1",
    url: `http://127.0.0.1:${port}/mcp`,
    async close() {
      closing.abort();
      for (const { transport, server } of sessions.values()) {
        await transport.close().catch(() => {});
        await server.close().catch(() => {});
      }
      sessions.clear();
      await new Promise<void>((resolveClose) => {
        httpServer.close(() => resolveClose());
        httpServer.closeAllConnections();
      });
    },
  };
}

// Command line entry: only when this file is the program, not when a test imports it.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { mode: { type: "string" }, port: { type: "string" }, backend: { type: "string" }, allow: { type: "string", multiple: true }, deny: { type: "string", multiple: true }, "backend-timeout-ms": { type: "string" } }, strict: true });
  const mode = values.mode as ScopedToyMode;
  if (!SCOPED_TOY_MODES.includes(mode)) {
    process.stderr.write(`scoped toy: --mode must be one of ${SCOPED_TOY_MODES.join(", ")}\n`);
    process.exit(2);
  }
  if (!values.backend) {
    process.stderr.write("scoped toy: --backend <url> is required\n");
    process.exit(2);
  }
  const list = (v: string[] | undefined) => (v ? v.flatMap((s) => s.split(",")).map((s) => s.trim()).filter(Boolean) : undefined);
  const toy = await startScopedToy(mode, { port: values.port ? Number(values.port) : 0, backend: values.backend, allow: list(values.allow), deny: list(values.deny), backendTimeoutMs: values["backend-timeout-ms"] ? Number(values["backend-timeout-ms"]) : undefined });
  process.stdout.write(`listening ${toy.url}\n`);
  const stop = () => void toy.close().finally(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
