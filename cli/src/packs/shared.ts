// Helpers shared by the core and db packs.
// Type-only imports from mcp.ts on purpose: mcp.ts re-exports discoverSqlTools from this file, so a runtime import
// back would be a cycle.
import { expandEnvRefs } from "../config/placeholders.js";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import type { CheckResult, SqlTool, ToolAnnotations } from "../types.js";

// ---------------------------------------------------------------------------------------------------------
// Refusal detection (addendum 1.3)
// ---------------------------------------------------------------------------------------------------------

/**
 * How a server words a refusal in plain text. Anchored to the start of the response on purpose: a data row that
 * contains the word "error" somewhere in the middle never counts.
 */
export const REFUSAL =
  /^\s*(?:\[?(?:error|err)\]?\s*[:\-]|\[(?:error|err)\]|error\b|refused|rejected|denied|blocked|forbidden|disallowed|not (?:allowed|permitted|supported)|only [^.\n]{0,60}(?:allowed|permitted|supported)|invalid\b|validation\b|unsafe\b|cannot\b|can't\b|unable to\b)/i;

/** The first 300 characters, which is where a refusal states itself. */
export const head = (text: string): string => text.slice(0, 300);

/**
 * True when the server declined the call: `isError`, a JSON-RPC error, or a plain-text refusal that never set
 * `isError` (which a client cannot tell from success). Callers must test `closed`/`timedOut` first: a call that never
 * got an answer also reads as an error here.
 */
export function refused(r: Pick<CallResult, "isError" | "rpcError" | "text">): boolean {
  return Boolean(r.isError) || r.rpcError !== undefined || REFUSAL.test(head(r.text ?? ""));
}

/** A refusal in plain text only: no `isError`, no JSON-RPC error. This is the case clients cannot see. */
export function refusedInTextOnly(r: Pick<CallResult, "isError" | "rpcError" | "text">): boolean {
  return !r.isError && r.rpcError === undefined && REFUSAL.test(head(r.text ?? ""));
}

const PG_PHRASES = /permission denied for (?:table|view|column|relation|schema)|SQLSTATE|\b42501\b|violates row-level security/i;
/** psql's own prefix. Case-sensitive on purpose: the addendum's `/im` would take a server's own plain-text "Error: ..." for the database's. */
const PG_PREFIX = /^ERROR:\s/m;
/** An error the database itself raised (as opposed to a refusal the server made up). */
export const PG_ERROR = { test: (s: string): boolean => PG_PHRASES.test(s) || PG_PREFIX.test(s) };

/** What EXPLAIN prints. A control that gets a plan back did not get rows. */
export const PLAN_MARKER = /QUERY PLAN|Seq Scan|Index Scan|cost=\d/;

/** Who enforced a control in one response (addendum 1.5). `leaked` is for the caller to decide: this only classifies the refusal. */
export function enforcer(r: Pick<CallResult, "isError" | "rpcError" | "text">): "server" | "database" {
  const text = `${r.text ?? ""}\n${r.rpcError ?? ""}`;
  if (PG_ERROR.test(text)) return "database";
  if (refused(r)) return "server";
  return "database";
}

// ---------------------------------------------------------------------------------------------------------
// Where the server runs relative to the harness's loopback listener
// ---------------------------------------------------------------------------------------------------------

export function isLoopbackHostname(hostRaw: string): boolean {
  const h = hostRaw.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/**
 * Can the server under test connect to the harness's loopback listener (and read its sandbox paths)? A stdio server is
 * started by the harness on this machine, so yes. An HTTP server is already running: only when its URL names this
 * machine. For a server on another host, 127.0.0.1:<port> is that host's own loopback, where nothing listens, so
 * every refusal-by-failure would be read as a pass.
 */
export function listenerReachable(server: { url?: string | null } | undefined, env: Record<string, string | undefined> = {}): { ok: true } | { ok: false; host: string } {
  if (!server?.url) return { ok: true };
  let host = "";
  try {
    // `${PORT}` and friends are filled in when the session opens, so they are filled in here too.
    host = new URL(expandEnvRefs(server.url, env)).hostname;
  } catch {
    // Never echo the URL: it can carry credentials.
    return { ok: false, host: "a host that could not be determined (server.url does not parse)" };
  }
  return isLoopbackHostname(host) ? { ok: true } : { ok: false, host };
}

// ---------------------------------------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------------------------------------

/** One line of response text for an evidence outcome (addendum item 23: 400 characters). */
export const brief = (s: string, n = 400): string => s.replace(/\s+/g, " ").slice(0, n);
/** The response text kept for JSON output, 4 KiB at most. */
export const excerpt = (s: string): string | undefined => (s ? s.slice(0, 4096) : undefined);

/**
 * `RunResult.notCovered` lines for the tools a pack could not exercise at all. "Declared writer tool" notes are left
 * out: those tools were exercised (by the write checks); only the read probes skip them.
 */
export function coverageNotes(checks: readonly CheckResult[], pack: string): string[] {
  const out = new Set<string>();
  for (const c of checks) {
    if (c.pack !== pack) continue;
    for (const n of c.coverage?.notCovered ?? []) {
      if (/^declared writer tool/.test(n.reason)) continue;
      out.add(`tool "${n.tool}" was not covered by the ${pack} pack: ${n.reason}`);
    }
  }
  return [...out];
}

// ---------------------------------------------------------------------------------------------------------
// SQL tool discovery (addendum 1.1)
// ---------------------------------------------------------------------------------------------------------

type Prop = { type?: string | string[]; description?: string; items?: { type?: string | string[] }; [k: string]: unknown };

const STRONG_NAMES = ["sql", "sql_query", "sqlquery", "query_sql"];
const GENERIC_NAMES = ["query", "statement", "q"];
const ARRAY_NAMES = ["queries", "statements", "sqls", "sql"];
/** Words that say "database" wherever they appear in the tool name, its description or the parameter's description. */
const SQL_HINT = /\bsql\b|database|postgres|sqlite|duckdb|mysql|\btable|\bschema\b|\bdb\b/i;
/**
 * SQL verbs. Only the tool name and the parameter's own description are tested for these: in a tool's prose ("select libraries by name") they are
 * ordinary English, and a lookup tool whose description says so would otherwise be taken for a SQL tool.
 */
const SQL_VERBS = /\b(select|insert|update|delete)\b/i;
/** What a query tool says about its output when it takes a statement: results, rows, an export or a format. */
const OUTPUT_TALK = /\b(results?|rows?|export(?:s|ed)?|format(?:s|ted)?)\b/i;
/** Looser than SQL_HINT: a tool that talks about records, rows or a warehouse may be a database tool the rules could not place. */
const DB_FLAVOUR = /\b(records?|rows?|columns?|relational|warehouse|lakehouse|datasets?|data ?(?:store|source|base)s?|analytics)\b/i;
const TOOL_NAME_RULE = /(^|_)(read|write|run|execute|exec)_?(query|sql)$/i;
const WRITER = /\b(insert|update|delete|write|create|alter|drop|modify|mutat|execute (?:ddl|dml))/i;
const NOT_WRITER = /\bread[- ]?only\b|\bselect\b/i;
const READER = /\b(select|read[- ]?only|read)\b/i;
const APPROVAL = /^(confirm|approve|approved|dry_run|force|allow_writes?)$/i;

const typesOf = (p: Prop | undefined): string[] => [p?.type].flat().filter((t): t is string => typeof t === "string");
const isString = (p: Prop | undefined) => typesOf(p).includes("string");
const isStringArray = (p: Prop | undefined) => typesOf(p).includes("array") && [p?.items?.type].flat().includes("string");
/** Underscores, dots and dashes hide word boundaries from \b; "run_sql" has none. */
const words = (s: string) => s.replace(/[_.-]+/g, " ");

export function annotationsOf(t: ToolInfo): ToolAnnotations | undefined {
  return (t as { annotations?: ToolAnnotations }).annotations;
}

/**
 * The tool can only be run as a task (`execution.taskSupport: "required"` in tools/list). The harness makes plain
 * `tools/call` requests, which such a server answers with -32600 before it looks at the arguments, so nothing the harness
 * sends tells it anything about the tool's input handling.
 */
export function requiresTask(t: ToolInfo): boolean {
  return (t as { execution?: { taskSupport?: unknown } }).execution?.taskSupport === "required";
}

/** Why a task-only tool is listed under Not covered. */
export const TASK_ONLY_REASON = "requires task-based execution, which the harness does not use";

/** Declared role of a SQL tool from its name and description. A claim, not a fact: the controls decide what a tool can do. */
export function roleOf(t: ToolInfo): "reader" | "writer" | "unknown" {
  const text = `${words(t.name)} ${t.description ?? ""}`;
  if (WRITER.test(text) && !NOT_WRITER.test(text)) return "writer";
  if (READER.test(text)) return "reader";
  return "unknown";
}

/** A boolean parameter that asks the caller to approve a change. */
export function approvalParamOf(t: ToolInfo): string | undefined {
  const props = t.inputSchema?.properties ?? {};
  return Object.keys(props).find((k) => APPROVAL.test(k) && typesOf(props[k] as Prop).includes("boolean"));
}

interface Found {
  arg: string;
  shape: "string" | "array";
}

function sqlParam(t: ToolInfo): { found: Found } | { skip: string; generic?: string } | undefined {
  const props = (t.inputSchema?.properties ?? {}) as Record<string, Prop>;
  const lower = (k: string) => k.toLowerCase();
  const strings = Object.keys(props).filter((k) => isString(props[k]));
  const strong = strings.find((k) => STRONG_NAMES.includes(lower(k)));
  if (strong) return { found: { arg: strong, shape: "string" } };
  const array = Object.keys(props).find((k) => ARRAY_NAMES.includes(lower(k)) && isStringArray(props[k]));
  if (array) return { found: { arg: array, shape: "array" } };
  const generic = strings.find((k) => GENERIC_NAMES.includes(lower(k)));
  if (generic) {
    const own = `${words(t.name)} ${props[generic]?.description ?? ""}`;
    const hint = `${own} ${t.description ?? ""}`;
    if (SQL_HINT.test(hint) || SQL_VERBS.test(own)) return { found: { arg: generic, shape: "string" } };
  }
  if (TOOL_NAME_RULE.test(t.name) && strings.length === 1) return { found: { arg: strings[0], shape: "string" } };
  if (generic) {
    // Telling a text search or a knowledge-graph lookup to declare itself SQL is noise: the advice only goes to tools that talk like a database.
    const advice = DB_FLAVOUR.test(`${words(t.name)} ${t.description ?? ""}`) ? "; list it under sql_tools to include it" : "";
    return { skip: `argument "${generic}" is not clearly SQL (nothing in the tool name, its description or the argument's description mentions sql, a database or a table)${advice}`, generic };
  }
  return undefined;
}

/**
 * Find tools that take SQL. Explicit config wins for the tools it lists (missing role, shape and approvalParam are
 * filled in from the tool's schema), but an explicit list only ever ADDS or CORRECTS: a tool that auto-detection finds is
 * still probed when the list leaves it out (hiding a writer would otherwise keep a run STANDARD; drop a tool from a run
 * with the locked `tools.exclude`), and a detected writer cannot be relabelled a reader. Anything not clearly SQL is
 * skipped and reported, never probed.
 */
export function discoverSqlTools(tools: ToolInfo[], explicit?: SqlTool[]): { tools: SqlTool[]; skipped: { tool: string; reason: string }[] } {
  const auto = detectSqlTools(tools);
  if (!explicit?.length) return auto;
  const listed = new Set(explicit.map((e) => e.tool));
  const enriched = enrichSqlTools(explicit, tools).map((e) => (auto.tools.find((a) => a.tool === e.tool)?.role === "writer" && e.role !== "writer" ? { ...e, role: "writer" as const } : e));
  return { tools: [...enriched, ...auto.tools.filter((a) => !listed.has(a.tool))], skipped: auto.skipped.filter((s) => !listed.has(s.tool)) };
}

/**
 * Other required parameters (sql_tools[].args is the typed way to set one).
 * A tool is probed when every one of them has a value: the entry's own `args`, a `default`, a `const`, the first `enum`
 * value, a token for a string, the minimum (or 1) for a number, `false` for a boolean. Values chosen by the harness are placeholders: when the
 * control read fails with one, the tool is listed with the remedy, because a placeholder the server does not accept looks like a broken connection.
 */
export function explicitArgs(st: Pick<SqlTool, "tool" | "args">): Record<string, unknown> {
  const a = st.args;
  return a !== null && typeof a === "object" && !Array.isArray(a) ? (a as Record<string, unknown>) : {};
}

export interface OtherParams {
  /** Every required parameter other than the SQL argument and the approval flag that has a value. */
  values: Record<string, unknown>;
  /** The ones the harness chose itself (not from `args`, a default or a const). */
  placeholders: string[];
  /** Required parameters of a type the harness cannot fill (an array, an object). */
  unfillable: string[];
}

export function otherParams(def: ToolInfo, arg: string, approvalParam: string | undefined, given: Record<string, unknown> = {}): OtherParams {
  const props = (def.inputSchema?.properties ?? {}) as Record<string, Prop>;
  const out: OtherParams = { values: {}, placeholders: [], unfillable: [] };
  for (const p of def.inputSchema?.required ?? []) {
    if (p === arg || p === approvalParam) continue;
    const s = props[p];
    if (p in given) out.values[p] = given[p];
    else if (s?.default !== undefined) out.values[p] = s.default;
    else if (s?.const !== undefined) out.values[p] = s.const;
    else {
      const types = typesOf(s);
      let v: unknown;
      if (Array.isArray(s?.enum) && s.enum.length) v = s.enum[0];
      else if (types.includes("string")) v = "sm-fill";
      else if (types.includes("integer") || types.includes("number")) v = typeof s?.minimum === "number" ? s.minimum : typeof s?.exclusiveMinimum === "number" ? s.exclusiveMinimum + 1 : 1;
      else if (types.includes("boolean")) v = false;
      else {
        out.unfillable.push(p);
        continue;
      }
      out.values[p] = v;
      out.placeholders.push(p);
    }
  }
  return out;
}

/** The remedy a listed tool is told: which parameters were filled with a placeholder, and the sql_tools entry that sets them. */
export function placeholderRemedy(st: SqlTool, def: ToolInfo | undefined, reply: string): string | undefined {
  if (!def) return undefined;
  const o = otherParams(def, st.arg, st.approvalParam, explicitArgs(st));
  if (!o.placeholders.length) return undefined;
  const filled = o.placeholders.map((p) => `${p}=${JSON.stringify(o.values[p])}`).join(", ");
  return `the control read failed with ${filled} filled in as a placeholder (${reply}); set sql_tools: [{tool: "${st.tool}", arg: "${st.arg}", args: {${o.placeholders.map((p) => `${p}: <value>`).join(", ")}}}]`;
}

function detectSqlTools(tools: ToolInfo[]): { tools: SqlTool[]; skipped: { tool: string; reason: string }[] } {
  const skipped: { tool: string; reason: string }[] = [];
  const found: SqlTool[] = [];
  /** Tools whose generic argument ("query", "statement") the rules did not place; the sibling rule below may. */
  const unplaced: { t: ToolInfo; generic: string }[] = [];
  const accept = (t: ToolInfo, hit: Found): void => {
    const approvalParam = approvalParamOf(t);
    const o = otherParams(t, hit.arg, approvalParam);
    if (o.unfillable.length) {
      skipped.push({
        tool: t.name,
        reason: `also requires ${o.unfillable.join(", ")}, which the harness cannot fill in (it fills enums, strings, numbers and booleans), so it is not probed; set sql_tools: [{tool: "${t.name}", arg: "${hit.arg}", args: {...}}] to give it a value`,
      });
      return;
    }
    found.push({ tool: t.name, arg: hit.arg, role: roleOf(t), shape: hit.shape, ...(approvalParam ? { approvalParam } : {}) });
  };
  for (const t of tools) {
    const hit = sqlParam(t);
    if (!hit) continue;
    if ("skip" in hit) {
      skipped.push({ tool: t.name, reason: hit.skip });
      if (hit.generic) unplaced.push({ t, generic: hit.generic });
      continue;
    }
    accept(t, hit.found);
  }
  // Server evidence: a tool with a query or statement argument whose description talks about results, rows, an export or a format is a query tool
  // when another tool of the same server was found to be SQL with the same argument name.
  for (const { t, generic } of unplaced) {
    const props = (t.inputSchema?.properties ?? {}) as Record<string, Prop>;
    const sibling = found.find((f) => f.arg.toLowerCase() === generic.toLowerCase());
    if (!sibling || !OUTPUT_TALK.test(`${t.description ?? ""} ${props[generic]?.description ?? ""}`)) continue;
    const i = skipped.findIndex((s) => s.tool === t.name);
    if (i >= 0) skipped.splice(i, 1);
    accept(t, { arg: generic, shape: "string" });
  }
  return { tools: found, skipped };
}

/** Fill `role`, `shape` and `approvalParam` where the entry does not set them. Entries the server does not declare are returned unchanged. */
export function enrichSqlTools(sqlTools: SqlTool[], tools: ToolInfo[]): SqlTool[] {
  return sqlTools.map((st) => {
    const def = tools.find((t) => t.name === st.tool);
    if (!def) return st;
    const prop = (def.inputSchema?.properties ?? {})[st.arg] as Prop | undefined;
    const approvalParam = st.approvalParam ?? approvalParamOf(def);
    return {
      ...st,
      role: st.role ?? roleOf(def),
      shape: st.shape ?? (isStringArray(prop) && !isString(prop) ? "array" : "string"),
      ...(approvalParam ? { approvalParam } : {}),
    };
  });
}

/**
 * Call a SQL tool with one statement. Array tools get `[sql]`. A required approval parameter is sent as `false`: the
 * harness never approves anything on a server's behalf, so a write through a gated tool must be refused.
 */
export function callSql(session: McpSession, st: SqlTool, sql: string, timeoutMs?: number): Promise<CallResult> {
  const def = session.tools.find((t) => t.name === st.tool);
  const args: Record<string, unknown> = { [st.arg]: st.shape === "array" ? [sql] : sql };
  // The other required parameters: the entry's `args`, else a default, an enum value or a placeholder; `args` also sets optional ones.
  const given = explicitArgs(st);
  const other: Record<string, unknown> = { ...(def ? otherParams(def, st.arg, st.approvalParam, given).values : {}) };
  for (const [k, v] of Object.entries(given)) if (k !== st.arg && k !== st.approvalParam) other[k] = v;
  Object.assign(args, other);
  if (Object.keys(other).length) sentExtras.set(st, other);
  if (st.approvalParam && (def?.inputSchema?.required ?? []).includes(st.approvalParam)) args[st.approvalParam] = false;
  return session.call(st.tool, args, timeoutMs);
}

/** What `callSql` sent besides the SQL argument and the approval flag, per entry, so the evidence shows it. */
const sentExtras = new WeakMap<object, Record<string, unknown>>();

/** The arguments `callSql` sends, for evidence (the SQL argument, then any other argument it filled in or was given). */
export function sqlArgsFor(st: SqlTool, sql: string): Record<string, unknown> {
  return { [st.arg]: st.shape === "array" ? [sql] : sql, ...(sentExtras.get(st) ?? {}) };
}

// ---- round 6 gate reasons: one text each, shared by run, doctor and the packs ----
export const NO_UPSTREAM_STUB = "no upstream stub: set `upstream.kind: http` (flag --upstream) and use `{upstream}` in the server config";
export const NO_VALID_CALL = "no valid call: add a `probes:` entry without `check` for one tool, or run `sealmark init --probes`";
export const NO_SCOPE_TOOL = "no `scope.tools` entry names a tool the server declares";
export const NO_SQL_TOOL = "no tool takes a SQL string";
