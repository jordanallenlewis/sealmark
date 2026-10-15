import { randomBytes } from "node:crypto";
import type { CheckConfig } from "../config/model.js";
import { CHECKS } from "../config/schema.js";
import type { CallResult, McpSession } from "../mcp.js";
import { BIG_ROWS, MASKED_EMAIL, RAW_EMAIL, ROLES, StateReader, TENANT1_MARK, TENANT2_MARK, resetProbeState, terminateBackends, type PgTarget, type Role, type RoleFacts } from "../seed.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, SqlTool, Verdict } from "../types.js";
import { applyCheckConfig } from "./core.js";
import { PLAN_MARKER, brief, callSql, enforcer, enrichSqlTools, excerpt, placeholderRemedy, refused, sqlArgsFor } from "./shared.js";

export interface DbCtx {
  target: PgTarget;
  sqlTools: SqlTool[];
  open: (role: Role) => Promise<McpSession>;
  /** Statement timeout the server is expected to enforce, in seconds (`--timeout-probe`). `expectedSec` overrides it for db-timeout. */
  timeoutSec: number;
  log: (s: string) => void;
  /** checks.db-rowcap.row_cap. Default 10 000. */
  rowCap?: number;
  /** checks.db-timeout.expected_sec. Default: `timeoutSec`. */
  expectedSec?: number;
  /** checks.db-timeout.slow_sql: replaces the pg_sleep probe. Must be a SELECT. */
  slowSql?: string;
  /** `checks.<id>.enabled` and `.severity` from the configuration. Absent means every check runs with its built-in severity. */
  checks?: Record<string, CheckConfig>;
  /** Receives what the db-privilege observation recorded, whether or not the check is registered (tests judge it with `privilegeCheck`). */
  recordPrivilege?: (input: PrivilegeInput) => void;
}

const DEFAULT_ROW_CAP = 10_000;
const CALL_MS = 30_000;
/** A statement that "ended" faster than this was refused or never ran; it was not cancelled by a timeout. */
const MIN_CANCEL_MS = 1000;
/** Wording a server uses when it refuses an oversized result on purpose. Plain "limit" is not enough: SQL errors quote it. */
const LIMIT_MSG = /too many (rows|results)|too (large|big)|exceeds?\b.{0,40}\b(rows?|limit|max)|\b(row|result)s? (limit|cap)|max(imum)? (of )?[\d,]+ rows|limited to/i;
/** CPU-bound and never completes in the window; used when a server refuses pg_sleep outright. */
export const FALLBACK_SLOW_SQL = "SELECT count(*) FROM big_table a CROSS JOIN big_table b WHERE a.id + b.id = -1";
const WRITER_NOTE = "declared writer tool: read probes do not apply";

/**
 * One rule for every probe: a call that timed out or lost its connection is no evidence at all (a dead server
 * "blocks" everything). A JSON-RPC error is different: the server answered, so it is a legitimate refusal.
 */
const noAnswer = (r: CallResult) => r.closed || r.timedOut;
const STOPPED = "the server stopped answering during the write probes";
const noAnswerText = (r: CallResult) => brief(r.rpcError || (r.timedOut ? "timed out" : "no answer"));
const said = (r: Pick<CallResult, "text" | "rpcError">) => r.text || r.rpcError || "empty response";

/** pass if every tool is clean, part if some are, fail if none are. */
function aggregate(perTool: boolean[]): Verdict {
  const ok = perTool.filter(Boolean).length;
  return ok === perTool.length ? "pass" : ok === 0 ? "fail" : "part";
}

/**
 * Put the first item that `pick` accepts at the front. The terminal summary quotes `evidence[0]`, so that line should be the probe that
 * decided the verdict, not a control read or an earlier probe that did not. The rest keep their order.
 */
function leadWith(evidence: Evidence[], pick: (e: Evidence) => boolean): Evidence[] {
  const i = evidence.findIndex(pick);
  return i <= 0 ? evidence : [evidence[i], ...evidence.slice(0, i), ...evidence.slice(i + 1)];
}

interface Meta {
  id: string;
  label: string;
  critical: boolean;
  scope: string;
  advisory?: boolean;
}

function done(meta: Meta, verdict: Verdict, summary: string, evidence: Evidence[], extra: { coverage?: CheckCoverage; enforcedBy?: CheckResult["enforcedBy"] } = {}): CheckResult {
  return { ...meta, pack: "db", verdict, summary, evidence, ...(extra.coverage ? { coverage: extra.coverage } : {}), ...(extra.enforcedBy ? { enforcedBy: extra.enforcedBy } : {}) };
}

interface EvOpts {
  st?: SqlTool;
  role?: string;
  r?: Pick<CallResult, "text" | "rpcError">;
  sql?: string;
  code?: string;
  enforcedBy?: Evidence["enforcedBy"];
}

function ev(probe: string, outcome: string, verifiedBy: Evidence["verifiedBy"], o: EvOpts = {}): Evidence {
  const ex = o.r ? excerpt(said(o.r) === "empty response" ? "" : said(o.r)) : undefined;
  return {
    probe,
    outcome,
    verifiedBy,
    ...(o.role ? { role: o.role } : {}),
    ...(o.st ? { tool: o.st.tool } : {}),
    ...(o.st && o.sql !== undefined ? { args: sqlArgsFor(o.st, o.sql) } : {}),
    ...(o.enforcedBy ? { enforcedBy: o.enforcedBy } : {}),
    ...(o.code ? { code: o.code } : {}),
    ...(ex ? { excerpt: ex } : {}),
  };
}

const META = {
  readonly: { id: "read-only", label: "Read-only by default", critical: false, scope: "server (tested as a role that can write, so the DB cannot be the reason a write fails)" },
  write: { id: "write-gate", label: "Write approval gate", critical: false, advisory: true, scope: "server" },
  rls: { id: "rls", label: "Row-level security respected", critical: true, scope: "database policy, tested through the server: does the server defeat it?" },
  multi: { id: "mutating-sql", label: "Mutating SQL blocked", critical: true, scope: "server (tested as a role that can write)" },
  pii: { id: "pii", label: "Personal data masking respected", critical: true, scope: "database grants, tested through the server: does the server defeat them?" },
  piiMasked: { id: "pii-masked", label: "Masked data reachable", critical: false, scope: "server (does it let a masked view through, or does it deny everything?)" },
  rowcap: { id: "db-rowcap", label: "Row cap", critical: false, scope: "server" },
  timeout: { id: "db-timeout", label: "Statement timeout", critical: false, scope: "server" },
  audit: { id: "audit", label: "Every call logged", critical: false, advisory: true, scope: "server" },
  privilege: {
    id: "db-privilege",
    label: "Connects as the database role it was given",
    critical: false,
    advisory: true,
    scope: "server (does each instance connect as exactly the role in its {dsn}, with that role's attributes?)",
  },
} satisfies Record<string, Meta>;

/** Emission order. */
const ORDER = ["read-only", "write-gate", "rls", "mutating-sql", "pii", "pii-masked", "db-rowcap", "db-timeout", "audit", "db-privilege"];

/**
 * db-privilege is a candidate: the methodology package registers it in config/schema.ts (CHECKS). Until it is there the
 * configuration cannot address it (`checks.db-privilege.severity` would be rejected), so the pack neither emits nor documents it.
 */
const privilegeRegistered = (): boolean => CHECKS.some((c) => c.id === META.privilege.id);

/** `privilege`, when given, is the finding the controls already produced (the wrong-role case); otherwise a registered check is `na`. */
function allInconclusive(reason: string, coverage?: CheckCoverage, privilege?: CheckResult): CheckResult[] {
  const rest = Object.values(META).filter((m: Meta) => m.id !== META.privilege.id);
  const out = rest.map((m: Meta) => done(m, m.advisory ? "na" : "inconclusive", reason, [], coverage ? { coverage } : {}));
  if (privilege) out.push(privilege);
  else if (privilegeRegistered()) out.push(done(META.privilege, "na", reason, [], coverage ? { coverage } : {}));
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// The published mutation corpus (docs/methodology.md). Verification closures are bound to a StateReader at run time.
// ---------------------------------------------------------------------------------------------------------

interface CorpusCase {
  id: string;
  kind: string;
  /** Core cases defeat a plain prefix filter or a read-only transaction: executing one fails the check. */
  core: boolean;
  steps: string[];
}

export const MUTATION_CORPUS: CorpusCase[] = [
  { id: "stacked statements (DROP)", kind: "stacked", core: true, steps: ["SELECT 1; DROP TABLE audit_probe"] },
  { id: "stacked statements (INSERT)", kind: "stacked", core: true, steps: ["SELECT 1; INSERT INTO probe_t (id, v) VALUES (9002, 'stacked')"] },
  // One entry per transaction-terminator keyword Postgres accepts (COMMIT, ROLLBACK, END, ABORT): a read-only transaction ends at any of them,
  // and a filter that names one word lets the other three through. COMMIT WORK and COMMIT TRANSACTION share the keyword a filter would
  // match, so they add nothing; `... AND CHAIN` starts a new transaction with the same read-only characteristic, so it is not an escape.
  { id: "COMMIT then write (read-only transaction escape)", kind: "txn-escape", core: true, steps: ["COMMIT; INSERT INTO probe_t (id, v) VALUES (9005, 'commit-escape')"] },
  { id: "ROLLBACK then write (read-only transaction escape)", kind: "txn-escape", core: true, steps: ["ROLLBACK; INSERT INTO probe_t (id, v) VALUES (9014, 'rollback-escape')"] },
  { id: "END then write (read-only transaction escape)", kind: "txn-escape", core: true, steps: ["END; INSERT INTO probe_t (id, v) VALUES (9015, 'end-escape')"] },
  { id: "ABORT then write (read-only transaction escape)", kind: "txn-escape", core: true, steps: ["ABORT; INSERT INTO probe_t (id, v) VALUES (9016, 'abort-escape')"] },
  { id: "case and comment obfuscation (INSERT)", kind: "obfuscation", core: true, steps: ["/*x*/ iNsErT INTO probe_t VALUES (9008,'obf')"] },
  { id: "data-modifying CTE (DELETE)", kind: "cte", core: false, steps: ["WITH d AS (DELETE FROM probe_t WHERE id = 9003 RETURNING id) SELECT count(*) FROM d"] },
  { id: "data-modifying CTE (INSERT)", kind: "cte", core: false, steps: ["WITH i AS (INSERT INTO probe_t (id, v) VALUES (9004, 'cte') RETURNING id) SELECT * FROM i"] },
  { id: "function with side effects (defeats any prefix filter by construction)", kind: "indirect-fn", core: false, steps: ["SELECT sm_mutate()"] },
  { id: "anonymous DO block", kind: "anonymous-block", core: false, steps: ["DO $$ BEGIN INSERT INTO probe_t VALUES (9007,'do'); END $$"] },
  { id: "TRUNCATE", kind: "ddl", core: false, steps: ["TRUNCATE probe_t"] },
  { id: "DDL (CREATE TABLE)", kind: "ddl", core: false, steps: ["CREATE TABLE sm_ddl_probe (x int)"] },
  { id: "DDL via SELECT INTO", kind: "ddl", core: false, steps: ["SELECT 1 INTO sm_ddl_probe"] },
  { id: "PREPARE then EXECUTE", kind: "prepared", core: false, steps: ["PREPARE p AS INSERT INTO probe_t VALUES (9011,'prep')", "EXECUTE p"] },
  { id: "session state (disable read-only, then write)", kind: "session-state", core: false, steps: ["SELECT set_config('default_transaction_read_only', 'off', false)", "INSERT INTO probe_t (id, v) VALUES (9006, 'session')"] },
  // Added in 0.3-draft. Each is a form the cases above miss: a server that opens a connection per call (the two-call PREPARE never
  // finds its statement), one that only filters the select list for function calls, one that lets EXPLAIN through untouched.
  { id: "PREPARE and EXECUTE in one call", kind: "prepared", core: false, steps: ["PREPARE p2 AS INSERT INTO probe_t VALUES (9012,'prep1'); EXECUTE p2"] },
  { id: "function with side effects in FROM", kind: "indirect-fn", core: false, steps: ["SELECT * FROM sm_mutate()"] },
  { id: "EXPLAIN ANALYZE runs the statement", kind: "explain", core: false, steps: ["EXPLAIN ANALYZE INSERT INTO probe_t (id, v) VALUES (9013, 'explain')"] },
];

const TWO_CALL_PREPARE = "PREPARE then EXECUTE";
const ONE_CALL_PREPARE = "PREPARE and EXECUTE in one call";
/** The error of an EXECUTE that reached a connection which never saw the PREPARE, and nothing else. */
const POOL_ROTATED = /^[^"]{0,60}?prepared statement "p" does not exist\W*$/i;

function mutationChecks(state: StateReader): Record<string, { setup?: () => Promise<void>; executed: () => Promise<boolean> }> {
  return {
    "stacked statements (DROP)": { executed: async () => !(await state.tableExists("audit_probe")) },
    "stacked statements (INSERT)": { executed: () => state.probeRow(9002) },
    "COMMIT then write (read-only transaction escape)": { executed: () => state.probeRow(9005) },
    "ROLLBACK then write (read-only transaction escape)": { executed: () => state.probeRow(9014) },
    "END then write (read-only transaction escape)": { executed: () => state.probeRow(9015) },
    "ABORT then write (read-only transaction escape)": { executed: () => state.probeRow(9016) },
    "case and comment obfuscation (INSERT)": { executed: () => state.probeRow(9008) },
    "data-modifying CTE (DELETE)": { setup: () => state.seed(9003, "cte-delete"), executed: async () => !(await state.probeRow(9003)) },
    "data-modifying CTE (INSERT)": { executed: () => state.probeRow(9004) },
    "function with side effects (defeats any prefix filter by construction)": { executed: () => state.probeValue("fn") },
    "anonymous DO block": { executed: () => state.probeRow(9007) },
    TRUNCATE: { setup: () => state.seed(9009, "truncate-me"), executed: async () => !(await state.probeRow(9009)) },
    "DDL (CREATE TABLE)": { executed: () => state.tableExists("sm_ddl_probe") },
    "DDL via SELECT INTO": { executed: () => state.tableExists("sm_ddl_probe") },
    "PREPARE then EXECUTE": { executed: () => state.probeRow(9011) },
    "session state (disable read-only, then write)": { executed: () => state.probeRow(9006) },
    "PREPARE and EXECUTE in one call": { executed: () => state.probeRow(9012) },
    "function with side effects in FROM": { executed: () => state.probeValue("fn") },
    "EXPLAIN ANALYZE runs the statement": { executed: () => state.probeRow(9013) },
  };
}

// ---------------------------------------------------------------------------------------------------------
// db-privilege (advisory candidate): does each instance connect as exactly the role it was given?
// ---------------------------------------------------------------------------------------------------------

/** What the harness recorded for one server instance. `privilegeCheck` judges it; it never touches a database or a server. */
export interface PrivilegeObservation {
  /** The role this instance was started as (its {dsn}). */
  role: Role;
  /** `usename` of every backend that appeared while the instance started and answered one read, harness connections excluded. */
  backends: string[];
  /** The `SELECT current_user AS u, '<token>' AS t` sent through a SQL tool. Absent when no SQL tool was available. */
  read?: { st: SqlTool; sql: string; token: string; r: Pick<CallResult, "text" | "rpcError"> };
}

export interface PrivilegeInput {
  instances: PrivilegeObservation[];
  /** Attributes of every role that was named: the three harness roles and every backend `usename` seen. */
  facts: Record<string, RoleFacts>;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const wordIn = (text: string, name: string) => new RegExp(`(?<![\\w$])${escapeRe(name)}(?![\\w$])`).test(text);
const roleName = (r: Role) => `sm_${r}`;
const count = (names: string[]) => [...new Set(names)].map((n) => `${n} (${names.filter((x) => x === n).length})`).join(", ");

/** The role names a `current_user` answer carries: only a response that echoes the token counts, and only names the harness knows. */
function currentUserIn(o: PrivilegeObservation, known: string[]): string[] | undefined {
  if (!o.read || !o.read.r.text.includes(o.read.token)) return undefined;
  const names = known.filter((n) => wordIn(o.read!.r.text, n));
  return names.length ? names : undefined;
}

/**
 * Judges a recording. pass: every instance's new backends and current_user name its own role and no role seen is a
 * superuser, BYPASSRLS or the owner of an RLS table. fail: an instance connected as another role, or a role seen has one of
 * those attributes. inconclusive: an instance left neither a new backend nor a readable current_user (a pooler, no reader tool).
 */
export function privilegeCheck(input: PrivilegeInput): CheckResult {
  if (!input.instances.length) return done(META.privilege, "na", "not observed: no server instance was started as a database role", []);
  const known = [...new Set([...ROLES.map(roleName), ...Object.keys(input.facts), ...input.instances.flatMap((i) => i.backends)])];
  const evidence: Evidence[] = [];
  const wrong: string[] = [];
  const blind: string[] = [];
  const seen: string[] = [];
  for (const o of input.instances) {
    const user = currentUserIn(o, known);
    const names = [...new Set([...o.backends, ...(user ?? [])])];
    for (const n of names) if (!seen.includes(n)) seen.push(n);
    const off = names.filter((n) => n !== roleName(o.role));
    if (off.length) wrong.push(`as ${o.role}, connected as ${off.join(", ")}`);
    else if (!names.length) blind.push(o.role);
    evidence.push(
      ev(
        `backends that appeared while the ${o.role} instance started and answered a read`,
        o.backends.length ? `as ${o.role}, the new backends were ${count(o.backends)}` : `as ${o.role}, no new backend appeared (a connection pool outside the database, or a connection opened before the harness looked)`,
        "db-state",
        { role: o.role, code: "db.privilege.backends" },
      ),
    );
    const outcome = user
      ? `as ${o.role}, current_user was ${user.join(", ")}`
      : o.read
        ? `as ${o.role}, the answer did not name a database role the harness knows (${brief(said(o.read.r))})`
        : `as ${o.role}, no SQL tool was available to ask the database`;
    evidence.push(ev(o.read ? o.read.sql : "SELECT current_user", outcome, "response", { ...(o.read ? { st: o.read.st, r: o.read.r, sql: o.read.sql } : {}), role: o.role, code: "db.privilege.current-user" }));
  }
  const excess: string[] = [];
  for (const n of seen) {
    const f = input.facts[n];
    const flags = f ? [f.superuser && "a superuser", f.bypassRls && "BYPASSRLS", f.ownsRlsTable && "the owner of an RLS table"].filter((x): x is string => Boolean(x)) : [];
    if (flags.length) excess.push(`${n} is ${flags.join(" and ")}`);
    evidence.push(
      ev(
        `pg_roles and pg_tables for ${n}`,
        f ? `${n}: superuser ${f.superuser ? "yes" : "no"}, BYPASSRLS ${f.bypassRls ? "yes" : "no"}, owns customers or orders ${f.ownsRlsTable ? "yes" : "no"}` : `${n}: not found in pg_roles`,
        "db-state",
        { code: "db.privilege.role-attributes" },
      ),
    );
  }
  if (wrong.length || excess.length) {
    const parts = [wrong.length ? `an instance did not use the role it was given: ${wrong.join("; ")}` : "", excess.length ? `a role the server used is too privileged: ${excess.join("; ")}` : ""].filter(Boolean);
    return done(META.privilege, "fail", `${parts.join(". ")} (advisory: the harness supplies least-privilege credentials, so the server should have used them)`, evidence);
  }
  if (blind.length) {
    return done(META.privilege, "inconclusive", `could not tell which role the ${blind.join(" and ")} instance connected as: no new database backend appeared and no readable current_user came back (a connection pool in front of the database, or no SQL tool that can read)`, evidence);
  }
  return done(
    META.privilege,
    "pass",
    `every instance connected as exactly the role it was given (${input.instances.map((i) => roleName(i.role)).join(", ")}); none is a superuser, has BYPASSRLS or owns an RLS table`,
    evidence,
  );
}

// ---------------------------------------------------------------------------------------------------------

/** When a control read failed with a parameter the harness filled in itself, the summary quotes the server's reply and the remedy, not the connection string. */
function placeholderHint(uncovered: { tool: string; reason: string }[]): string | undefined {
  const u = uncovered.find((x) => /filled in as a placeholder/.test(x.reason));
  return u ? `no SQL tool could run a basic read as the admin role: ${u.tool}: ${u.reason}` : undefined;
}

/** A tool controlled only through CREATE TABLE is "ddl": it takes neither a SELECT nor an INSERT, so one core corpus case runs on it (DDL_STACKED). */
type Kind = "reader" | "writer" | "gated" | "ddl";
const DDL_CONTROL_TABLE = "sm_ctl_probe";
const DDL_STACKED_TABLE = "sm_ddl_stacked";
const DDL_STACKED_ID = 9020;
const DDL_CASE_ID = "DDL then write in one call (DDL-only tool)";
const DDL_STACKED_SQL = `CREATE TABLE ${DDL_STACKED_TABLE} (x int); INSERT INTO probe_t (id, v) VALUES (${DDL_STACKED_ID}, 'ddl-stacked')`;
interface Controlled {
  st: SqlTool;
  kind: Kind;
}

export async function runDb(ctx: DbCtx): Promise<CheckResult[]> {
  return applyDbChecksConfig(await runDbChecks(ctx), ctx.checks);
}

/**
 * Applies checks.<id>.enabled and .severity to every db check. A disabled check is reported n/a whatever the probes produced
 * (or whether they ran). With the shipped defaults the list comes back untouched.
 */
export function applyDbChecksConfig(out: CheckResult[], checks: Record<string, CheckConfig> | undefined): CheckResult[] {
  const metas: Meta[] = Object.values(META).filter((m) => m.id !== META.privilege.id || privilegeRegistered());
  if (!checks || !metas.some((m) => checks[m.id]?.enabled === false || checks[m.id]?.severity)) return out;
  return metas.flatMap((m) => {
    const have = out.find((c) => c.id === m.id) ?? (checks[m.id]?.enabled === false ? done(m, "na", "disabled by config", []) : undefined);
    return have ? [applyCheckConfig(have, checks[m.id])] : [];
  });
}

async function runDbChecks(ctx: DbCtx): Promise<CheckResult[]> {
  const off = (m: Meta) => ctx.checks?.[m.id]?.enabled === false;
  const rowCap = ctx.rowCap ?? DEFAULT_ROW_CAP;
  const expectedSec = ctx.expectedSec ?? ctx.timeoutSec;
  if (ctx.slowSql !== undefined && !/^\s*select\b/i.test(ctx.slowSql)) throw new Error("checks.db-timeout.slow_sql must be a SELECT statement");
  const out: CheckResult[] = [];
  const state = new StateReader(ctx.target);
  await state.connect();
  const sessions: McpSession[] = [];
  const open = async (role: Role) => {
    const s = await ctx.open(role);
    sessions.push(s);
    return s;
  };
  let calls = 0;
  const call = (s: McpSession, st: SqlTool, sql: string, ms = CALL_MS) => {
    calls++;
    return callSql(s, st, sql, ms);
  };
  // Resetting may have to kill connections a server left holding locks. The server's own connection is then dead
  // and every later probe errors, which reads as "blocked". Say so on every check produced afterwards.
  const caveats: Evidence[] = [];
  const reset = async () => {
    if (await resetProbeState(ctx.target, [state.pid])) {
      const msg = "the harness had to terminate database connections a server left holding locks; results after this point may be unreliable because the server's own connection was killed";
      ctx.log(`warning: ${msg}`);
      if (!caveats.length) caveats.push({ probe: "reset probe state", outcome: msg, verifiedBy: "db-state" });
    }
  };
  const push = (c: CheckResult) => out.push(caveats.length ? { ...c, evidence: [...c.evidence, ...caveats] } : c);
  try {
    await reset();
    let admin: McpSession, support: McpSession, analyst: McpSession;
    let adminStopped = false; // the write probes killed or hung the admin session
    let adminDown = false; // ...and it could not be started again
    // The instances are opened one at a time so the new database backends can be told apart (db-privilege).
    const wantPrivilege = (privilegeRegistered() && !off(META.privilege)) || Boolean(ctx.recordPrivilege);
    const backends = async (): Promise<{ pid: number; usename: string }[]> => (wantPrivilege ? state.backends().catch(() => []) : []);
    let baseline = await backends();
    try {
      admin = await open("admin");
    } catch (e) {
      return allInconclusive(`could not start the server as a database role: ${(e as Error).message}`);
    }
    // Later checks still need the admin session; start it again if the write probes took it down.
    const reviveAdmin = async () => {
      if (!adminStopped) return;
      adminStopped = false;
      try {
        admin = await open("admin");
      } catch {
        adminDown = true;
      }
    };

    // The pipeline may hand over tools without roles; the server's own tool list says what each one claims to be.
    const candidates = enrichSqlTools(ctx.sqlTools, admin.tools);

    // ---- controls (addendum 1.1) ----
    // Every tool must be able to run a basic read as the admin role (a token-bearing SELECT, so that an EXPLAIN plan
    // that happens to contain "rows=100" can never pass), or later results mean nothing. The same read names the
    // database role: a server that ignores the {dsn} it was given (a hard-coded or cached connection) would otherwise
    // be credited with blocking writes that the database refused on its own. A tool that cannot read gets a write
    // control (declared writer or unknown role): an INSERT that the harness then finds in the database.
    const controlled: Controlled[] = [];
    const uncovered: { tool: string; reason: string }[] = [];
    const controlNotes: Evidence[] = [];
    let wrongRole = false;
    for (const st of candidates) {
      const token = `sm-ctl-${randomBytes(4).toString("hex")}`;
      const readSql = `SELECT '${token}' AS t, (SELECT count(*) FROM customers) AS n, current_user AS u`;
      const probe = `control read via ${st.tool} as admin`;
      const r = await call(admin, st, readSql);
      let readFail: string;
      let stayed = false; // the tool answered as the wrong role: a write control would prove nothing either
      if (noAnswer(r)) readFail = `no answer (${noAnswerText(r)})`;
      else if (PLAN_MARKER.test(r.text)) readFail = `returned a plan, not rows: ${brief(r.text)}`;
      else if (r.text.includes(token) && /\bsm_admin\b/.test(r.text)) {
        controlled.push({ st, kind: "reader" });
        controlNotes.push(ev(probe, "passed: the response carried the token and the role sm_admin", "response", { st, role: "admin", r, sql: readSql, code: "db.control.reader" }));
        continue;
      } else if (r.text.includes(token)) {
        wrongRole = true;
        stayed = true;
        readFail = `the server did not connect as the requested role sm_admin (answered: ${brief(r.text)})`;
      } else readFail = brief(said(r));
      controlNotes.push(ev(probe, stayed ? readFail : `failed: ${readFail}`, "response", { st, role: "admin", r, sql: readSql, code: stayed ? "db.control.wrong-role" : "db.control.reader-failed" }));
      // A parameter the harness filled in itself (an enum value, a token) may be what the server refused; the remedy says what to set.
      const remedy = stayed ? undefined : placeholderRemedy(st, admin.tools.find((x) => x.name === st.tool), brief(said(r)));
      if (stayed || st.role === "reader") {
        uncovered.push({ tool: st.tool, reason: stayed ? readFail : (remedy ?? `the read control failed: ${readFail}`) });
        continue;
      }
      // Write control.
      await reset();
      const wtoken = `sm-ctl-${randomBytes(4).toString("hex")}`;
      const writeSql = `INSERT INTO probe_t (id, v) VALUES (9000, '${wtoken}')`;
      const wr = await call(admin, st, writeSql);
      const applied = !noAnswer(wr) && (await state.probeValue(wtoken));
      await reset();
      const wprobe = `control write via ${st.tool} as admin`;
      if (applied) {
        controlled.push({ st, kind: "writer" });
        controlNotes.push(ev(wprobe, "passed: the row appeared in the database", "db-state", { st, role: "admin", r: wr, sql: writeSql, code: "db.control.writer" }));
      } else if (!noAnswer(wr) && st.approvalParam && refused(wr)) {
        controlled.push({ st, kind: "gated" });
        controlNotes.push(ev(wprobe, `refused without approval (${st.approvalParam} omitted): ${brief(said(wr))}. The harness never sets an approval parameter, so a write through this tool with approval is not exercised`, "response", { st, role: "admin", r: wr, sql: writeSql, code: "db.control.gated" }));
      } else {
        controlNotes.push(ev(wprobe, `failed: no row appeared in the database (${noAnswer(wr) ? noAnswerText(wr) : brief(said(wr))})`, "db-state", { st, role: "admin", r: wr, sql: writeSql, code: "db.control.writer-failed" }));
        // A DDL-only tool (a create_table style tool) takes neither a SELECT nor an INSERT. CREATE TABLE is the third control: the table must be in the database.
        let ddlMade = false;
        let ddlSaid = "not tried";
        if (!noAnswer(wr)) {
          const ddlSql = `CREATE TABLE ${DDL_CONTROL_TABLE} (x int)`;
          const dr = await call(admin, st, ddlSql);
          ddlMade = !noAnswer(dr) && (await state.tableExists(DDL_CONTROL_TABLE));
          ddlSaid = noAnswer(dr) ? noAnswerText(dr) : brief(said(dr));
          await reset();
          controlNotes.push(
            ev(
              `control CREATE TABLE via ${st.tool} as admin`,
              ddlMade ? "passed: the table appeared in the database; DDL-only tool, controlled through CREATE TABLE" : `failed: no table appeared in the database (${ddlSaid})`,
              "db-state",
              { st, role: "admin", r: dr, sql: ddlSql, code: ddlMade ? "db.control.ddl" : "db.control.ddl-failed" },
            ),
          );
          if (noAnswer(dr)) adminStopped = true;
        } else adminStopped = true;
        if (ddlMade) controlled.push({ st, kind: "ddl" });
        else {
          const why = `neither control succeeded (read: ${readFail}; write: ${noAnswer(wr) ? noAnswerText(wr) : brief(said(wr))}); no control form worked (CREATE TABLE: ${ddlSaid})`;
          uncovered.push({ tool: st.tool, reason: remedy ? `${why}; ${remedy}` : why });
        }
        await reviveAdmin();
      }
    }
    for (const u of uncovered) ctx.log(`warning: SQL tool "${u.tool}" was not covered: ${u.reason}`);

    // ---- db-privilege: which role did each instance really connect as? ----
    // One benign read per instance (not counted in validCalls: it is not a probe of any other check), then the backends that
    // appeared since the instance was started. The wrong-role finding is made here, before the early return below.
    const instances: PrivilegeObservation[] = [];
    const observe = async (role: Role, session: McpSession, before: { pid: number }[]): Promise<void> => {
      if (!wantPrivilege) return;
      const st = controlled.find((c) => c.kind === "reader")?.st ?? candidates.find((s) => s.role !== "writer") ?? candidates[0];
      let read: PrivilegeObservation["read"];
      if (st) {
        const token = `sm-who-${randomBytes(4).toString("hex")}`;
        const sql = `SELECT current_user AS u, '${token}' AS t`;
        const r = await callSql(session, st, sql, CALL_MS);
        read = { st, sql, token, r: { text: r.text, ...(r.rpcError !== undefined ? { rpcError: r.rpcError } : {}) } };
      }
      const known = new Set(before.map((b) => b.pid));
      instances.push({ role, backends: (await backends()).filter((b) => !known.has(b.pid)).map((b) => b.usename), ...(read ? { read } : {}) });
    };
    await observe("admin", admin, baseline);
    try {
      baseline = await backends();
      support = await open("support");
      await observe("support", support, baseline);
      baseline = await backends();
      analyst = await open("analyst");
      await observe("analyst", analyst, baseline);
    } catch (e) {
      return allInconclusive(`could not start the server as a database role: ${(e as Error).message}`);
    }
    let privilege: CheckResult | undefined;
    if (wantPrivilege) {
      const names = [...new Set([...ROLES.map(roleName), ...instances.flatMap((i) => i.backends)])];
      const input: PrivilegeInput = { instances, facts: await state.roleFacts(names).catch(() => ({})) };
      ctx.recordPrivilege?.(input);
      if (privilegeRegistered()) privilege = privilegeCheck(input);
    }

    if (!controlled.length) {
      const first = controlNotes[0]?.outcome ?? "unknown";
      return allInconclusive(
        wrongRole
          ? `the server did not connect as the requested database role (${first}). Check that the {dsn} placeholder reaches the connection the server actually uses.`
          : placeholderHint(uncovered) ??
              `no SQL tool could run a basic read as the admin role (${first}). Check how the server takes its connection string, or whether the tool needs other arguments (sql_tools: [{tool, arg, args: {<param>: <value>}}]).`,
        { probed: [], notCovered: uncovered, validCalls: calls },
        privilege,
      );
    }
    if (privilege) push(privilege);
    const probeTools = controlled.map((c) => c.st);
    const readers = controlled.filter((c) => c.kind === "reader").map((c) => c.st);
    const writerTools = controlled.filter((c) => c.kind !== "reader").map((c) => c.st);
    // The best controlled reader (not a declared writer) is the control tool for rls and pii.
    const controlTool = readers.find((s) => s.role !== "writer") ?? readers[0];
    const writerNotes = writerTools.map((s) => ({ tool: s.tool, reason: WRITER_NOTE }));
    const cover = (probed: SqlTool[], since: number, extra: { tool: string; reason: string }[] = []): CheckCoverage => ({
      probed: probed.map((s) => s.tool),
      notCovered: [...uncovered, ...extra],
      validCalls: calls - since,
    });
    const isWriter = (s: SqlTool) => s.role === "writer" || controlled.some((c) => c.st.tool === s.tool && c.kind !== "reader");
    const nameList = (l: SqlTool[]) => l.map((s) => s.tool).join(", ");
    const probedPhrase = (l: SqlTool[]) => `the ${l.length} probed SQL tool${l.length === 1 ? "" : "s"} (${nameList(l)})`;
    const ddlTools = controlled.filter((c) => c.kind === "ddl").map((c) => c.st);

    // The write gate is computed after the mutation corpus. Per tool: whether a corpus case ran through it, and whether a core case did.
    let writeGate: CheckResult | undefined;
    const holdWrite = (c: CheckResult) => {
      writeGate = c;
    };
    const mutRan = new Map<string, { core: boolean; ids: string[] }>();
    const noteRan = (tool: string, id: string, core: boolean) => {
      const m = mutRan.get(tool) ?? { core: false, ids: [] };
      m.core ||= core;
      if (!m.ids.includes(id)) m.ids.push(id);
      mutRan.set(tool, m);
    };
    const flushWriteGate = () => {
      let w = writeGate;
      writeGate = undefined;
      if (!w) return;
      const ran = [...mutRan.entries()];
      const ungated = ran.filter(([tool, m]) => m.core && !candidates.find((s) => s.tool === tool)?.approvalParam).map(([tool]) => tool);
      if (w.verdict !== "fail" && ungated.length) {
        w = done(
          META.write,
          "fail",
          `writes executed with no confirmation step: a core mutating-sql case ran through ${ungated.join(", ")}, which has no approval parameter (advisory: MCP clients may add their own approval)`,
          [ev("mutating-sql core cases as the admin role", `executed through ${ungated.join(", ")} without any approval step; see the mutating-sql check for the per-case evidence`, "db-state", { role: "admin", code: "db.wg.no-gate" })],
          { ...(w.coverage ? { coverage: w.coverage } : {}) },
        );
      } else if (w.verdict === "na" && ran.length) {
        w = done(META.write, "na", `plain writes were blocked (see mutating-sql: a corpus case executed through ${ran.map(([tool]) => tool).join(", ")})`, [], { ...(w.coverage ? { coverage: w.coverage } : {}) });
      }
      push(w);
    };

    /** The one core case a DDL-controlled tool gets: CREATE TABLE, then an INSERT in the same call, judged by the database (a stacked-statement bypass behind a CREATE TABLE filter). */
    const ddlCases = async (): Promise<{ evidence: Evidence[]; executed: boolean; stopped: boolean; probes: number; blocked: number }> => {
      const evidence: Evidence[] = [];
      let executed = false;
      let stopped = false;
      let probes = 0;
      let blocked = 0;
      for (const st of ddlTools) {
        await reset();
        const r = await call(admin, st, DDL_STACKED_SQL);
        const gone = noAnswer(r) || (r.rpcError !== undefined && !(await admin.alive()));
        const ran = await state.probeRow(DDL_STACKED_ID);
        if (ran) {
          executed = true;
          noteRan(st.tool, DDL_CASE_ID, true);
        } else if (gone) {
          stopped = true;
          evidence.push(ev(DDL_STACKED_SQL, `no evidence: ${STOPPED} (${noAnswerText(r)}); the remaining cases were not run`, "response", { st, role: "admin", code: "db.mut.no-answer" }));
          break;
        }
        probes++;
        if (!ran) blocked++;
        evidence.push(
          ev(DDL_STACKED_SQL, ran ? `EXECUTED: ${DDL_CASE_ID}; the database changed` : `blocked or ineffective: ${DDL_CASE_ID} (${brief(said(r))})`, "db-state", {
            st,
            role: "admin",
            r,
            sql: DDL_STACKED_SQL,
            code: ran ? "db.mut.executed.ddl" : "db.mut.blocked.ddl",
          }),
        );
      }
      await reset();
      return { evidence, executed, stopped, probes, blocked };
    };

    // ---- read-only by default (plain single-statement writes), on every controlled tool ----
    // (the write-gate probes share these writes, so the block is skipped only when both checks are off)
    if (!off(META.readonly) || !off(META.write)) {
      const c0 = calls;
      const evidence: Evidence[] = [...controlNotes];
      const clean: SqlTool[] = [];
      const dirty: SqlTool[] = [];
      let anyExecuted = false;
      let stopped = false;
      for (const st of probeTools) {
        await reset();
        await state.seed(9010, "to-delete");
        const writes: { label: string; sql: string; applied: () => Promise<boolean> }[] = [
          { label: "INSERT", sql: "INSERT INTO probe_t (id, v) VALUES (9001, 'sm-insert')", applied: () => state.probeRow(9001) },
          { label: "UPDATE", sql: "UPDATE tenants SET name = 'sm-updated' WHERE id = 1", applied: async () => (await state.tenantName(1)) === "sm-updated" },
          { label: "DELETE", sql: "DELETE FROM probe_t WHERE id = 9010", applied: async () => !(await state.probeRow(9010)) },
        ];
        let blocked = true;
        for (const w of writes) {
          const r = await call(admin, st, w.sql);
          const applied = await w.applied();
          if (applied) {
            blocked = false;
            anyExecuted = true;
          } else if (noAnswer(r) || (r.rpcError !== undefined && !(await admin.alive()))) {
            stopped = true;
            evidence.push(ev(w.sql, `no evidence: ${STOPPED} (${noAnswerText(r)})`, "response", { st, role: "admin", sql: w.sql, code: "db.ro.no-answer" }));
            break;
          }
          evidence.push(
            ev(w.sql, applied ? "executed: the row changed in the database" : `not applied (${brief(said(r))})`, "db-state", { st, role: "admin", r, sql: w.sql, code: applied ? "db.ro.executed" : "db.ro.blocked" }),
          );
        }
        if (stopped) {
          if (!blocked) dirty.push(st); // a write that ran before the server went quiet still counts
          break;
        }
        (blocked ? clean : dirty).push(st);
      }
      if (stopped) adminStopped = true;
      const coverage = cover(probeTools, c0);
      if (stopped && !anyExecuted) {
        push(done(META.readonly, "inconclusive", `${STOPPED}, so no write was observed either way`, evidence, { coverage }));
        push(done(META.write, "na", `not measured: ${STOPPED}`, [], { coverage }));
      } else {
        const v = aggregate([...clean.map(() => true), ...dirty.map(() => false)]);
        const executedNames = dirty.map((s) => `${s.tool}${isWriter(s) ? " (declared writer tool; exclude it under tools.exclude if writes are intended)" : ""}`).join(", ");
        push(
          done(
            META.readonly,
            v,
            v === "pass"
              ? `plain writes blocked on ${probedPhrase(probeTools)}`
              : `writes executed through ${executedNames}${clean.length ? ` and blocked on ${nameList(clean)}` : ""}`,
            // The control reads come first in `evidence`; lead with the probe that matches the verdict instead (an executed write, or the first blocked one).
            leadWith(evidence, (e) => e.code === (v === "pass" ? "db.ro.blocked" : "db.ro.executed")),
            { coverage },
          ),
        );

        // ---- write approval gate (advisory) ----
        const declared = candidates.filter((s) => s.role === "writer");
        const unreached = declared.filter((s) => !controlled.some((c) => c.st.tool === s.tool));
        const writersSeen = probeTools.filter(isWriter);
        const gatedNames = controlled.filter((c) => c.kind === "gated").map((c) => c.st);
        // Uncontrolled tools are already in `uncovered`, with the reason their controls failed.
        const wcov = cover(probeTools, c0);
        // Held until the mutation corpus has run: a corpus case that executed says more about the gate than the three plain writes do.
        if (anyExecuted) {
          holdWrite(
            done(META.write, "fail", `writes executed with no confirmation step through ${nameList(dirty)} (advisory: MCP clients may add their own approval)`, [
              ev("plain INSERT, UPDATE and DELETE as the admin role", "applied without any approval step; see the read-only check for the per-statement evidence", "db-state", { role: "admin", code: "db.wg.no-gate" }),
            ], { coverage: wcov }),
          );
        } else if (writersSeen.length && !unreached.length && writersSeen.every((s) => s.approvalParam && gatedNames.some((g) => g.tool === s.tool))) {
          holdWrite(
            done(
              META.write,
              "pass",
              `every writer tool (${nameList(writersSeen)}) has an approval parameter (${writersSeen.map((s) => s.approvalParam).join(", ")}) and refused the write when the harness omitted it; the harness never approves, so writes with approval are not tested`,
              writersSeen.map((s) => ev(`plain write through ${s.tool} without ${s.approvalParam}`, "refused", "response", { st: s, role: "admin", code: "db.wg.gated" })),
              { coverage: wcov },
            ),
          );
        } else if (unreached.length) {
          holdWrite(done(META.write, "na", `not covered: writer tool(s) ${nameList(unreached)} declared but no control succeeded`, [], { coverage: wcov }));
        } else if (writersSeen.length) {
          holdWrite(done(META.write, "na", `writer tool(s) ${nameList(writersSeen)} blocked every plain write and declare no approval parameter, so no approval flow was tested`, [], { coverage: wcov }));
        } else {
          holdWrite(done(META.write, "na", "no write concept: no writer tool declared and every reader blocked writes", [], { coverage: wcov }));
        }
      }
    }

    await reviveAdmin();

    // Without a controlled reader there is nothing to run the read probes on.
    if (!readers.length || !controlTool) {
      const why = `no reader tool passed the control read (controlled: ${nameList(probeTools)}), so the read probes had nothing to run on`;
      for (const m of [META.rls, META.multi, META.pii, META.piiMasked, META.rowcap, META.timeout]) {
        if (m.id === META.multi.id && ddlTools.length && !off(META.multi)) {
          // Only DDL-controlled tools: the one case that applies to them can still run, and it can fail the check; the rest of the corpus could not be run.
          const c0 = calls;
          const d = await ddlCases();
          if (d.stopped) adminStopped = true;
          const v: Verdict = d.executed ? "fail" : "inconclusive";
          push(
            done(
              META.multi,
              v,
              d.executed
                ? `EXECUTED: ${DDL_CASE_ID}; the other forms could not be run (${why})`
                : `${why}; the stacked write was blocked on the DDL-only tool(s) ${nameList(ddlTools)}, but the rest of the corpus could not be run`,
              d.evidence,
              { coverage: cover(ddlTools, c0, writerNotes) },
            ),
          );
          continue;
        }
        push(done(m, "inconclusive", why, [], { coverage: cover([], calls, writerNotes) }));
      }
      flushWriteGate();
      push(done(META.audit, "na", "not measured: servers do not write audit rows by themselves", []));
      out.sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
      return out;
    }

    // ---- row-level security ----
    if (!off(META.rls)) {
      const c0 = calls;
      const evidence: Evidence[] = [];
      const adminSees = await call(admin, controlTool, "SELECT note FROM customers WHERE tenant_id = 2 LIMIT 3");
      const supportSees = await call(support, controlTool, "SELECT note FROM customers WHERE tenant_id = 1 LIMIT 3");
      if (!adminSees.text.includes(TENANT2_MARK) || !supportSees.text.includes(TENANT1_MARK)) {
        push(done(META.rls, "inconclusive", "control reads failed: admin could not see tenant 2 or support could not see tenant 1, so a leak could not be told from a broken connection", [
          ev("control: admin reads tenant 2, support reads tenant 1", `admin: ${brief(said(adminSees))}; support: ${brief(said(supportSees))}`, "response", { st: controlTool, code: "db.rls.control-failed" }),
        ], { coverage: cover(readers, c0, writerNotes) }));
      } else {
        const probes = ["SELECT id, tenant_id, note FROM customers WHERE tenant_id = 2", "SELECT id, tenant_id, note FROM orders WHERE tenant_id = 2", "SELECT * FROM orders"];
        const perTool: boolean[] = [];
        const who: Evidence["enforcedBy"][] = [];
        for (const st of readers) {
          let clean = true;
          for (const q of probes) {
            const r = await call(support, st, q);
            const leaked = r.text.includes(TENANT2_MARK);
            if (leaked) clean = false;
            const by = leaked ? "unknown" : enforcer(r);
            if (!leaked) who.push(by);
            evidence.push(
              ev(q, leaked ? "returned tenant 2 rows to the support role" : `no tenant 2 rows (${brief(said(r))})`, "response", { st, role: "support", r, sql: q, enforcedBy: by, code: leaked ? "db.rls.leak" : `db.rls.${by}` }),
            );
          }
          perTool.push(clean);
        }
        const v = aggregate(perTool);
        const by: CheckResult["enforcedBy"] = who.includes("server") ? "server" : who.length ? "database" : "unknown";
        const how =
          by === "server"
            ? "server-enforced: the server refused or filtered some probes itself, so the database policy was only partly exercised"
            : "DB-enforced: the server passed the policy through and added no filtering of its own";
        push(
          done(
            META.rls,
            v,
            v === "pass"
              ? `${how} (support role saw only its own tenant on every tool)`
              : v === "part"
                ? "tenant 2 rows leaked through some tools but not others"
                : "support role read tenant 2 rows on every tool (does the server connect as the table owner or an admin role?)",
            evidence,
            { coverage: cover(readers, c0, writerNotes), enforcedBy: v === "pass" ? by : by === "server" ? "server" : "unknown" },
          ),
        );
      }
    }

    // ---- mutating SQL blocked ----
    if (!off(META.multi)) {
      const c0 = calls;
      const evidence: Evidence[] = [];
      let coreExecuted = false;
      const executedIds: string[] = [];
      let probes = 0;
      let blockedProbes = 0;
      let stopped = false;
      /** Per tool: the cases that ran. And the two-call PREPARE/EXECUTE answers that may only mean a pool handed EXECUTE to another connection. */
      const ranOn = new Map<string, Set<string>>();
      const poolSuspects: { tool: string; e: Evidence; said: string }[] = [];
      const verify = mutationChecks(state);
      outer: for (const st of readers) {
        for (const c of MUTATION_CORPUS) {
          const v = verify[c.id];
          await reset();
          await v.setup?.();
          let last = "";
          let lastR: CallResult | undefined;
          let gone: CallResult | undefined;
          for (const step of c.steps) {
            const r = await call(admin, st, step);
            last = brief(said(r));
            lastR = r;
            if (noAnswer(r) || (r.rpcError !== undefined && !(await admin.alive()))) {
              gone = r;
              break;
            }
          }
          const ran = await v.executed();
          const probe = c.steps.join("  →  ");
          if (ran) {
            if (c.core) coreExecuted = true;
            if (!executedIds.includes(c.id)) executedIds.push(c.id);
            ranOn.set(st.tool, (ranOn.get(st.tool) ?? new Set()).add(c.id));
            noteRan(st.tool, c.id, c.core);
          } else if (gone) {
            stopped = true;
            evidence.push(ev(probe, `no evidence: ${STOPPED} (${noAnswerText(gone)}); the remaining cases were not run`, "response", { st, role: "admin", code: "db.mut.no-answer" }));
            break outer;
          }
          probes++;
          if (!ran) blockedProbes++;
          const e = ev(probe, ran ? `EXECUTED: ${c.id}; the database changed` : `blocked or ineffective: ${c.id} (${last})`, "db-state", {
            st,
            role: "admin",
            ...(lastR ? { r: lastR } : {}),
            sql: c.steps[c.steps.length - 1],
            code: ran ? `db.mut.executed.${c.kind}` : `db.mut.blocked.${c.kind}`,
          });
          evidence.push(e);
          if (!ran && c.id === TWO_CALL_PREPARE && POOL_ROTATED.test(last)) poolSuspects.push({ tool: st.tool, e, said: last });
        }
      }
      if (!stopped && ddlTools.length) {
        const d = await ddlCases();
        evidence.push(...d.evidence);
        probes += d.probes;
        blockedProbes += d.blocked;
        if (d.executed) {
          coreExecuted = true;
          executedIds.push(DDL_CASE_ID);
        }
        if (d.stopped) stopped = true;
      }
      // The two-call PREPARE/EXECUTE ends in 'prepared statement "p" does not exist' when a connection pool handed the EXECUTE to another
      // connection. That is not a block. It is said so only when the single-call form executed on the same tool (so the statement itself is
      // not what stopped it); otherwise it stays what it was, a refusal.
      let poolRotated = 0;
      for (const { tool, e, said: text } of poolSuspects) {
        if (!ranOn.get(tool)?.has(ONE_CALL_PREPARE)) continue;
        e.outcome = `not executed: the pool handed EXECUTE to another connection (not a block): ${TWO_CALL_PREPARE} (${text})`;
        e.code = "db.mut.pool-rotated";
        blockedProbes--;
        poolRotated++;
      }
      if (stopped) adminStopped = true;
      await reset();
      const any = executedIds.length > 0;
      const v: Verdict = coreExecuted ? "fail" : stopped ? "inconclusive" : any ? "part" : "pass";
      push(
        done(
          META.multi,
          v,
          v === "inconclusive"
            ? `${STOPPED}, so the mutation corpus could not be completed`
            : v === "pass"
              ? `all ${MUTATION_CORPUS.length} mutation forms blocked on ${probedPhrase(readers)}${ddlTools.length ? `; the stacked write was blocked on the DDL-only tool${ddlTools.length === 1 ? "" : "s"} ${nameList(ddlTools)}` : ""}`
              : `EXECUTED: ${executedIds.join(", ")}; ${blockedProbes} of ${probes} blocked${poolRotated ? `, ${poolRotated} not executed because of connection pooling` : ""}`,
          evidence,
          { coverage: cover([...readers, ...ddlTools], c0, writerNotes) },
        ),
      );
    }
    flushWriteGate();

    await reviveAdmin();

    // ---- personal data masking: denied, masked or leaked, per tool ----
    if (!off(META.pii)) {
      const c0 = calls;
      const evidence: Evidence[] = [];
      const ctl = await call(analyst, controlTool, "SELECT id, name FROM customers LIMIT 3");
      if (!/Customer \d/.test(ctl.text)) {
        push(done(META.pii, "inconclusive", "control read failed: the analyst role could not read non-sensitive columns through the server", [
          ev("control: analyst reads customers.name", brief(said(ctl)), "response", { st: controlTool, role: "analyst", r: ctl, code: "db.pii.control-failed" }),
        ], { coverage: cover(readers, c0, writerNotes) }));
      } else {
        const probes = ["SELECT email FROM customers", "SELECT * FROM customers", "SELECT id, name, email FROM customers WHERE tenant_id = 1 LIMIT 5"];
        const perTool: boolean[] = [];
        const outcomes: string[] = [];
        const who: Evidence["enforcedBy"][] = [];
        for (const st of readers) {
          let clean = true;
          let seen: "denied" | "masked" | "leaked" = "denied";
          for (const q of probes) {
            const r = await call(analyst, st, q);
            const leaked = RAW_EMAIL.test(r.text);
            const masked = !leaked && MASKED_EMAIL.test(r.text);
            if (leaked) {
              clean = false;
              seen = "leaked";
            } else if (masked && seen === "denied") seen = "masked";
            const by = leaked ? "unknown" : enforcer(r);
            if (!leaked) who.push(by);
            evidence.push(
              ev(q, leaked ? "returned unmasked email addresses to the analyst role" : `no raw emails (${brief(said(r))})`, "response", {
                st,
                role: "analyst",
                r,
                sql: q,
                enforcedBy: by,
                code: leaked ? "db.pii.leaked" : masked ? "db.pii.masked" : "db.pii.denied",
              }),
            );
          }
          perTool.push(clean);
          outcomes.push(`${st.tool}=${seen}`);
        }
        const v = aggregate(perTool);
        const by: CheckResult["enforcedBy"] = who.includes("server") ? "server" : who.length ? "database" : "unknown";
        const how =
          by === "server"
            ? "server-enforced: the server refused or filtered some probes itself, so the database grants were only partly exercised"
            : "DB-enforced: the server passed the grants through and added no filtering of its own";
        const cov = cover(readers, c0, writerNotes);
        cov.outcome = outcomes.length === 1 ? outcomes[0].split("=")[1] : outcomes.join("; ");
        push(
          done(
            META.pii,
            v,
            v === "pass"
              ? `${how} (analyst role never received raw emails on any tool)`
              : v === "part"
                ? "raw emails leaked through some tools but not others"
                : "analyst role received raw emails on every tool (does the server connect as a more privileged role?)",
            leadWith(evidence, (e) => v !== "pass" && e.code === "db.pii.leaked"),
            { coverage: cov, enforcedBy: v === "pass" ? by : by === "server" ? "server" : "unknown" },
          ),
        );
      }
    }

    // ---- masked data reachable (a server that denies everything is not masking) ----
    if (!off(META.piiMasked)) {
      const c0 = calls;
      const evidence: Evidence[] = [];
      const statuses: Verdict[] = [];
      for (const st of readers) {
        const q = "SELECT id, email FROM customers_masked LIMIT 3";
        const r = await call(analyst, st, q);
        const leaked = RAW_EMAIL.test(r.text);
        const masked = !leaked && MASKED_EMAIL.test(r.text);
        const s: Verdict = noAnswer(r) ? "inconclusive" : leaked ? "fail" : masked ? "pass" : "inconclusive";
        statuses.push(s);
        evidence.push(
          ev(
            q,
            s === "pass" ? "masked emails came back" : s === "fail" ? "raw emails came back from the masked view" : noAnswer(r) ? `no answer (${noAnswerText(r)})` : `no masked rows: ${refused(r) ? "refused" : "empty"} (${brief(said(r))})`,
            "response",
            { st, role: "analyst", r, sql: q, code: `db.pii-masked.${s}` },
          ),
        );
      }
      const scored = statuses.filter((s) => s === "pass" || s === "fail");
      const v: Verdict = scored.length ? aggregate(scored.map((s) => s === "pass")) : "inconclusive";
      push(
        done(
          META.piiMasked,
          v,
          v === "pass"
            ? "the masked view was readable and returned only masked emails"
            : v === "part"
              ? "the masked view was readable through some tools but returned raw emails or nothing through others"
              : v === "fail"
                ? "the masked view returned raw emails"
                : "the masked view could not be read through any tool (refused or empty), so masking could not be told from denying everything",
          evidence,
          { coverage: cover(readers, c0, writerNotes) },
        ),
      );
    }

    // ---- row cap and statement timeout ----
    // (one loop serves both: it is skipped when both are off, and the slow statement only runs while db-timeout is on)
    cap: if (!off(META.rowcap) || !off(META.timeout)) {
      if (adminDown) {
        const why = "the admin session could not be restarted after the server stopped answering during the write probes";
        push(done(META.rowcap, "inconclusive", why, []));
        push(done(META.timeout, "inconclusive", why, []));
        break cap;
      }
      const capEvidence: Evidence[] = [];
      const timeoutEvidence: Evidence[] = [];
      const capOk: boolean[] = [];
      const timeoutOk: boolean[] = [];
      /** Per measured tool: the probe whose answer decided it (the CPU-bound join when pg_sleep was refused, not the refused pg_sleep). */
      const timeoutDecided: { ok: boolean; ev: Evidence; sql: string; state: string; tool: string }[] = [];
      const capC0 = calls;
      let timeoutCalls = 0;
      const waitMs = (expectedSec + 8) * 1000;
      const slowSql = ctx.slowSql ?? `SELECT pg_sleep(${expectedSec + 20})`;
      const slowLabel = ctx.slowSql ? `${ctx.slowSql} with a ${expectedSec}s expectation` : `SELECT pg_sleep(${expectedSec + 20}) with a ${expectedSec}s expectation`;
      const notMeasured: string[] = [];
      const capUnmeasured: string[] = [];
      /** The most rows any tool returned for the big-table read: what a "no cap" summary says, not the table's size. */
      let maxRows = 0;
      for (const st of readers) {
        const probe = `SELECT id, payload FROM big_table (${BIG_ROWS.toLocaleString()} rows exist)`;
        const sql = "SELECT id, payload FROM big_table ORDER BY id";
        const r = await call(admin, st, sql, 120_000);
        // Distinct rows: a server may repeat the result as text and as structured content.
        const rows = new Set(r.text.match(/row-\d+-end/g) ?? []).size;
        maxRows = Math.max(maxRows, rows);
        let ok: boolean | undefined;
        let outcome: string;
        if (noAnswer(r)) {
          ok = false;
          outcome = `response too large or connection dropped, so a cap could not be confirmed (${noAnswerText(r)})`;
        } else if (rows > rowCap) {
          ok = false;
          outcome = `${rows.toLocaleString()} row(s) came back (cap threshold ${rowCap.toLocaleString()})`;
        } else if (rows > 0) {
          ok = true;
          outcome = `${rows.toLocaleString()} row(s) came back, under the ${rowCap.toLocaleString()} threshold`;
        } else if (LIMIT_MSG.test(r.text || r.rpcError || "")) {
          // A thrown error reaches the client as a JSON-RPC error; plain text can say the same. Either is the server's own answer.
          ok = true;
          outcome = `refused as too large: ${brief(said(r))}`;
        } else if (refused(r)) {
          // The server declined the probe for some other reason. That is not "no cap" and not a cap either.
          ok = undefined;
          outcome = `the server refused the probe without a recognizable limit message, so a cap could not be measured (${brief(said(r))})`;
        } else {
          ok = false;
          outcome = `no rows and no recognizable limit message, so a cap cannot be confirmed (${brief(r.text || "empty")})`;
        }
        if (ok === undefined) capUnmeasured.push(st.tool);
        else capOk.push(ok);
        capEvidence.push(ev(probe, outcome, "response", { st, role: "admin", r, sql, code: ok === undefined ? "db.rowcap.not-measured" : ok ? "db.rowcap.ok" : "db.rowcap.exceeded" }));

        if (off(META.timeout)) continue;
        // ---- statement timeout on a fresh session ----
        const t0 = calls;
        let fresh: McpSession;
        try {
          fresh = await open("admin");
        } catch (e) {
          timeoutOk.push(false);
          timeoutEvidence.push(ev(slowLabel, `could not start a fresh server session: ${(e as Error).message}`, "response", { st, role: "admin", code: "db.timeout.no-session" }));
          continue;
        }
        type Judged = { state: "cancelled" | "running" | "dropped" | "returned" | "refused-fast"; text: string };
        const judge = (slow: CallResult): Judged => {
          const secs = (slow.elapsedMs / 1000).toFixed(1);
          // Elapsed time first: a plain-text "Error: canceling statement due to statement timeout" also reads as a refusal.
          if (slow.closed) return { state: "dropped", text: `the server connection dropped after ${secs}s` };
          if (slow.timedOut || slow.elapsedMs >= waitMs) return { state: "running", text: `no statement timeout within ${(waitMs / 1000).toFixed(0)} s (expected ${expectedSec} s plus an 8 s margin); a server that cancels later than that is not seen: set --timeout-probe to its value` };
          if (slow.elapsedMs >= MIN_CANCEL_MS) return { state: "cancelled", text: `statement ended after ${secs}s` };
          if (refused(slow)) return { state: "refused-fast", text: `refused before execution after ${secs}s (${brief(said(slow))})` };
          return { state: "returned", text: `returned after ${secs}s with no error, so the statement did not run as written` };
        };
        const slow = await call(fresh, st, slowSql, waitMs);
        let j = judge(slow);
        let decider = ev(slowLabel, j.text, "response", { st, role: "admin", r: slow, sql: slowSql, code: `db.timeout.${j.state}` });
        let decidedSql = slowSql;
        timeoutEvidence.push(decider);
        let measured: boolean | undefined = j.state === "cancelled";
        if (j.state === "refused-fast") {
          const second = await call(fresh, st, FALLBACK_SLOW_SQL, waitMs);
          j = judge(second);
          decider = ev(`${FALLBACK_SLOW_SQL} (fallback: the server refused ${ctx.slowSql ? "the slow statement" : "pg_sleep"})`, j.text, "response", { st, role: "admin", r: second, sql: FALLBACK_SLOW_SQL, code: `db.timeout.fallback.${j.state}` });
          decidedSql = FALLBACK_SLOW_SQL;
          timeoutEvidence.push(decider);
          if (j.state === "refused-fast") {
            measured = undefined;
            notMeasured.push(st.tool);
            timeoutEvidence.push(ev("db-timeout", "not measured (the server refuses both pg_sleep and a long join)", "response", { st, role: "admin", code: "db.timeout.not-measured" }));
          } else measured = j.state === "cancelled";
        }
        if (measured !== undefined) {
          timeoutOk.push(measured);
          timeoutDecided.push({ ok: measured, ev: decider, sql: decidedSql, state: j.state, tool: st.tool });
        }
        timeoutCalls += calls - t0;
        await fresh.close();
      }
      await terminateBackends(ctx.target, [state.pid]);

      const capCov = cover(readers, capC0, writerNotes);
      capCov.validCalls = readers.length;
      const timeoutCov = cover(readers, calls, writerNotes);
      timeoutCov.validCalls = timeoutCalls;
      for (const t of notMeasured) timeoutCov.notCovered.push({ tool: t, reason: "db-timeout not measured: the server refuses both pg_sleep and a long join" });
      for (const t of capUnmeasured) capCov.notCovered.push({ tool: t, reason: "db-rowcap not measured: the server refused the probe without a recognizable limit message" });

      if (!capOk.length) {
        push(done(META.rowcap, "inconclusive", `the server refused the probe on every tool without a recognizable limit message (${nameList(readers)}), so a cap could not be measured`, capEvidence, { coverage: capCov }));
      } else {
        const v = aggregate(capOk);
        push(
          done(
            META.rowcap,
            v,
            v === "pass" ? `no response exceeded ${rowCap.toLocaleString()} rows on any tool` : v === "part" ? "a row cap held on some tools but not others" : maxRows > 0 ? `no row cap: ${maxRows.toLocaleString()} of ${BIG_ROWS.toLocaleString()} rows could be read through every tool` : "no row cap confirmed: no rows and no limit message came back on any tool",
            capEvidence,
            { coverage: capCov },
          ),
        );
      }
      if (!timeoutOk.length) {
        push(done(META.timeout, "na", "not measured (the server refuses both pg_sleep and a long join)", timeoutEvidence, { coverage: timeoutCov }));
      } else {
        const v = aggregate(timeoutOk);
        // The first probe that decided the verdict: a failing one unless every measured tool was cancelled. Its evidence leads the list and is named in the summary.
        const deciding = timeoutDecided.find((d) => d.ok === (v === "pass")) ?? timeoutDecided[0];
        const by = `${brief(deciding.sql, 80)} on ${deciding.tool}`;
        const waitSec = expectedSec + 8;
        push(
          done(
            META.timeout,
            v,
            v === "pass"
              ? `a runaway statement was cancelled on all ${timeoutOk.length} measured tool(s) within ${waitSec}s`
              : v === "part"
                ? `a runaway statement was cancelled on some tools but not others (not cancelled: ${by})`
                : deciding.state === "running"
                  ? `no statement timeout within ${waitSec}s (expected ${expectedSec}s): ${by}`
                  : `no statement timeout (expected ${expectedSec}s): ${deciding.ev.outcome}: ${by}`,
            leadWith(timeoutEvidence, (e) => e === deciding.ev),
            { coverage: timeoutCov },
          ),
        );
      }
    }

    push(done(META.audit, "na", "not measured: servers do not write audit rows by themselves", []));
    out.sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
    return out;
  } finally {
    for (const s of sessions) await s.close();
    await state.end();
  }
}

// ---------------------------------------------------------------------------------------------------------
// Check documentation
// ---------------------------------------------------------------------------------------------------------

const DB_SINCE = "0.1-draft";
const NEW_SINCE = "0.2-draft";

const baseDoc = (m: Meta, d: Pick<CheckDoc, "verifiedBy" | "falsePositive" | "falseNegative"> & Partial<CheckDoc>): CheckDoc => ({
  id: m.id,
  pack: "db",
  label: m.label,
  critical: m.critical,
  advisory: Boolean(m.advisory),
  scope: m.scope,
  probes: [],
  thresholds: {},
  configKeys: [`checks.${m.id}.enabled`, `checks.${m.id}.severity`],
  since: DB_SINCE,
  status: "shipped",
  ...d,
});

/** db-privilege's documentation. `describe()` lists it once config/schema.ts registers the id (the methodology package does that). */
export const PRIVILEGE_DOC: CheckDoc = baseDoc(META.privilege, {
  verifiedBy: ["db-state", "response"],
  probes: [
    { id: "backends", text: "SELECT usename FROM pg_stat_activity WHERE datname = 'sealmark_seed' AND pid <> ALL(<harness pids>), before and after each instance starts and answers one read", core: true, kind: "privilege" },
    { id: "current-user", text: "SELECT current_user AS u, '<token>' AS t", core: true, kind: "privilege" },
    { id: "role-attributes", text: "pg_roles.rolsuper and rolbypassrls, and pg_tables.tableowner for customers and orders, for every role seen", core: true, kind: "privilege" },
  ],
  falsePositive:
    "The harness supplies every credential, so 'superuser or table owner' is fixed by construction; the check asks whether the server used the credentials it was given. A server that opens an extra connection as another role (a metadata or admin pool) fails even if it never runs a query with it. Advisory: not scored.",
  falseNegative:
    "A connection pool outside the database hides the backends, and a server with no SQL tool that can read leaves nothing to ask: both are inconclusive, never a pass. A server that connects as the right role at start and switches later (SET ROLE) is not seen.",
  since: "0.3-draft",
});

export function describe(): CheckDoc[] {
  return [
    baseDoc(META.readonly, {
      verifiedBy: ["db-state", "response"],
      probes: [
        { id: "insert", text: "INSERT INTO probe_t (id, v) VALUES (9001, 'sm-insert')", core: true, kind: "write" },
        { id: "update", text: "UPDATE tenants SET name = 'sm-updated' WHERE id = 1", core: true, kind: "write" },
        { id: "delete", text: "DELETE FROM probe_t WHERE id = 9010", core: true, kind: "write" },
      ],
      falsePositive: "A server that blocks plain writes only because it crashed or hung is reported inconclusive, not as read-only. A declared writer tool that is meant to write is reported by name; exclude it under tools.exclude if writes are intended.",
      falseNegative: "Only single-statement INSERT, UPDATE and DELETE on the seed tables are tried; a server that allows other write forms is caught by mutating-sql, not here. A tool whose SELECT and INSERT controls both fail gets CREATE TABLE as a third control (the table must appear in the database) and, in mutating-sql, one core case: CREATE TABLE, then an INSERT in the same call. Tools that fail every control are listed as not covered. A required parameter other than the SQL argument is filled with the entry's sql_tools args, else a default, the first enum value or a placeholder; when the control read fails with a placeholder, the tool is listed with the sql_tools entry that sets it.",
      configKeys: ["tools.exclude", "sql_tools"],
    }),
    baseDoc(META.write, {
      verifiedBy: ["db-state", "response"],
      falsePositive: "MCP clients may add their own approval step in front of any tool, which this check cannot see. It is advisory and not scored. It is computed after the mutating-sql corpus: a core case that executed through a tool with no approval parameter fails it, and any other case that executed is named in its n/a text.",
      falseNegative: "The harness never sets an approval parameter to true, so it does not prove an approved write works. A server whose writer tool could not be controlled is reported as not covered.",
    }),
    baseDoc(META.rls, {
      verifiedBy: ["response"],
      probes: [
        { id: "customers-t2", text: "SELECT id, tenant_id, note FROM customers WHERE tenant_id = 2", core: true, kind: "rls" },
        { id: "orders-t2", text: "SELECT id, tenant_id, note FROM orders WHERE tenant_id = 2", core: true, kind: "rls" },
        { id: "orders-all", text: "SELECT * FROM orders", core: true, kind: "rls" },
      ],
      falsePositive: "A server that connects as the table owner or a BYPASSRLS role defeats the policy, which is the failure this check is for. The control reads must succeed first, otherwise the check is inconclusive.",
      falseNegative: "Only the seed schema's row-level policy is tested. DB-enforced means the database did the filtering and the server added none of its own; it does not mean the server would handle other policies.",
      configKeys: ["checks.rls.enabled", "checks.rls.severity", "tools.exclude"],
    }),
    baseDoc(META.multi, {
      verifiedBy: ["db-state", "response"],
      probes: MUTATION_CORPUS.map((c) => ({ id: c.id, text: c.steps.join("  ->  "), core: c.core, kind: c.kind })),
      falsePositive: "Only a change the harness finds in the database counts as executed. There is one transaction-escape case per terminator keyword Postgres accepts (COMMIT, ROLLBACK, END, ABORT); COMMIT WORK and COMMIT TRANSACTION share the keyword a filter would match, and ... AND CHAIN starts a new transaction with the same read-only characteristic, so neither is an escape and neither is a case. The side-effect function cases (in the select list and in FROM) defeat any prefix filter by construction, so they are not core cases and only cost half a point; so do the single-call PREPARE and EXECUTE and the EXPLAIN ANALYZE of a write.",
      falseNegative: "The corpus is finite and published. A server that blocks every listed form can still be bypassed by one that is not listed.",
      configKeys: ["checks.mutating-sql.enabled", "checks.mutating-sql.severity", "checks.mutating-sql.corpus.add", "checks.mutating-sql.corpus.remove"],
    }),
    baseDoc(META.pii, {
      verifiedBy: ["response"],
      probes: [
        { id: "email", text: "SELECT email FROM customers", core: true, kind: "pii" },
        { id: "star", text: "SELECT * FROM customers", core: true, kind: "pii" },
        { id: "mixed", text: "SELECT id, name, email FROM customers WHERE tenant_id = 1 LIMIT 5", core: true, kind: "pii" },
      ],
      falsePositive: "A server that connects as a more privileged role than the analyst role leaks by design of its configuration. A server that denies the column outright passes (outcome denied); whether it can show masked data is pii-masked's question.",
      falseNegative: "Only the seed schema's email column is tried. The per-tool outcome (denied, masked or leaked) is recorded in coverage.outcome.",
      configKeys: ["checks.pii.enabled", "checks.pii.severity", "tools.exclude"],
    }),
    baseDoc(META.piiMasked, {
      verifiedBy: ["response"],
      probes: [{ id: "masked-view", text: "SELECT id, email FROM customers_masked LIMIT 3", core: false, kind: "pii" }],
      falsePositive: "A server that refuses or returns nothing is inconclusive, not failed: a server that denies everything is not masking.",
      falseNegative: "Passing means a masked view could be read; it does not prove the server masks data on its own.",
      since: NEW_SINCE,
    }),
    baseDoc(META.rowcap, {
      verifiedBy: ["response"],
      probes: [{ id: "big-table", text: "SELECT id, payload FROM big_table ORDER BY id", core: false, kind: "rowcap" }],
      thresholds: { row_cap: { default: DEFAULT_ROW_CAP, configKey: "checks.db-rowcap.row_cap", standardLocked: true } },
      falsePositive: "A response the harness cannot receive at all (the connection drops) is counted as no confirmed cap. A server that refuses the probe without a recognizable limit message is not measured, not failed.",
      falseNegative: "A cap is judged on one query against a 200 000-row table.",
      configKeys: ["checks.db-rowcap.row_cap", "checks.db-rowcap.enabled", "checks.db-rowcap.severity"],
      since: NEW_SINCE,
      replaces: ["cap-timeout"],
    }),
    baseDoc(META.timeout, {
      verifiedBy: ["response"],
      probes: [
        { id: "pg-sleep", text: "SELECT pg_sleep(<expected_sec + 20>)", core: false, kind: "timeout" },
        { id: "cross-join", text: FALLBACK_SLOW_SQL, core: false, kind: "timeout" },
      ],
      thresholds: { expected_sec: { default: 10, configKey: "checks.db-timeout.expected_sec", standardLocked: true } },
      falsePositive: "A statement that ends in under one second was refused or never ran, not cancelled: it is reported as refused before execution and the CPU-bound fallback is tried. If both are refused the check is not measured, never failed.",
      falseNegative: "The harness waits expected_sec + 8 seconds, so a timeout longer than that is reported as no timeout.",
      configKeys: ["checks.db-timeout.expected_sec", "checks.db-timeout.slow_sql", "timeout_probe_sec", "checks.db-timeout.enabled", "checks.db-timeout.severity"],
      since: NEW_SINCE,
      replaces: ["cap-timeout"],
    }),
    baseDoc(META.audit, {
      verifiedBy: ["response"],
      falsePositive: "Not measured in methodology 0.2: servers do not write audit rows by themselves, so there is nothing to compare against.",
      falseNegative: "Always n/a today.",
      status: "planned",
    }),
    ...(privilegeRegistered() ? [PRIVILEGE_DOC] : []),
  ];
}

