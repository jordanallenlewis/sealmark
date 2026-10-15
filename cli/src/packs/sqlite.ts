// The `sqlite` pack: does a SQL tool on an embedded database stay inside the one
// database file it was given?
//
// Every target is harness-owned: the fixture database in the sandbox root, a canary database and canary files in the sandbox
// canary directory, and paths that do not exist. Nothing here is aimed at a tool the classifier did not call SQL, and the
// harness decides every verdict by reading the database file and the sandbox directories itself, never by the server's word
// (the one exception is `sqlite-extension-load`, which is decided from the error text and says so).
//
// Engines: SQLite is graded through `node:sqlite`. DuckDB is planned: it needs the optional dependency @duckdb/node-api,
// which this build does not ship, so a config with {duckdb_path} is reported as not applicable with that reason.
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fillArgs } from "../classify.js";
import { placeholdersUsed } from "../config.js";
import { SessionError, type CallResult, type McpSession, type ToolInfo } from "../mcp.js";
import { diffFor, type FsSnapshot } from "../observers/fs.js";
import {
  SQLITE_BIG_ROWS,
  columnExists,
  journalModeOf,
  createCanaryDb,
  createSqliteFixture,
  probeRowExists,
  readState,
  removeDbFiles,
  sqlPath,
  sqliteUnavailable,
  tableExists,
  tableHasValue,
  tenantName,
  userVersionOf,
  type DbState,
} from "../sqlite-fixtures.js";
import { head, refused, roleOf } from "./shared.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, Pack, PackCtx, Sandbox, ToolClassification, Verdict } from "../types.js";

// ---------------------------------------------------------------------------------------------------------
// Check metadata
// ---------------------------------------------------------------------------------------------------------

interface Meta {
  id: string;
  label: string;
  critical: boolean;
  scope: string;
  advisory?: boolean;
}

const SCOPE = "server (tested through its SQL tool against a seeded SQLite file; the engine itself is not what is graded; SQLite only in this release, DuckDB is planned)";

const META = {
  readonly: { id: "sqlite-read-only", label: "SQLite: read-only by default", critical: false, scope: SCOPE },
  mutating: { id: "sqlite-mutating-sql", label: "SQLite: mutating SQL blocked", critical: true, scope: SCOPE },
  fileRead: { id: "sqlite-file-read", label: "SQLite: no reading of other files", critical: true, scope: `${SCOPE}; the database file the server was given is the only file it should read` },
  fileWrite: { id: "sqlite-file-write", label: "SQLite: no writing of other files", critical: true, scope: `${SCOPE}; the database file the server was given is the only file it should write` },
  ext: { id: "sqlite-extension-load", label: "SQLite: no loading of extensions", critical: true, scope: `${SCOPE}; decided from the error text, not from observed code execution` },
  rowcap: { id: "sqlite-rowcap", label: "SQLite: row cap", critical: false, scope: "server (SQLite only in this release; DuckDB is planned)" },
  timeout: { id: "sqlite-timeout", label: "SQLite: query timeout", critical: false, scope: "server (SQLite only in this release; DuckDB is planned)" },
} satisfies Record<string, Meta>;

const ALL_META: Meta[] = Object.values(META);

const DUCKDB_PLANNED =
  "DuckDB grading is planned and not shipped in this build (it needs the optional dependency @duckdb/node-api); SQLite servers are graded through {sqlite_path}";
const NO_PLACEHOLDER =
  "no {sqlite_path} placeholder in the server config, so the harness cannot give the server a database to grade (SQLite servers only: if the server runs on SQLite, add {sqlite_path} to its args; a DuckDB server is not graded in this release, see {duckdb_path} under Not covered)";

// ---------------------------------------------------------------------------------------------------------
// Text rules
// ---------------------------------------------------------------------------------------------------------

const textOf = (r: CallResult) => r.text || r.rpcError || "";
const noAnswer = (r: CallResult) => r.closed || r.timedOut;
const brief = (s: string, n = 140) => s.replace(/\s+/g, " ").trim().slice(0, n);
const excerpt = (s: string) => s.slice(0, 4096);

/**
 * A response that is a query plan, not rows. Case-sensitive on purpose (SQLite prints its plan nodes in capitals), so a row that says
 * "search results" is not a plan. The control read returns only a token and a count, so nothing else can match.
 */
const PLAN = /QUERY PLAN|\bopcode\b|\bOpenRead\b|\b(?:SCAN|SEARCH) (?:TABLE )?[A-Za-z_]\w*/;
/** Wording a server uses when it refuses an oversized result on purpose. Plain "limit" is not enough: SQL errors quote it. */
const LIMIT_MSG = /too many (rows|results)|too (large|big)|exceeds?\b.{0,40}\b(rows?|limit|max)|\b(row|result)s? (limit|cap)|max(imum)? (of )?[\d,]+ rows|limited to|truncated/i;

/** Extension-load outcomes. Attempted-load wording is what the loader says once it really tried to open a library. */
const LOAD_ATTEMPTED =
  /cannot open shared object|specified module could not be found|specified procedure could not be found|not a valid win32 application|\bdlopen\b|undefined symbol|image not found|\bIO Error\b/i;
/**
 * What the engine says when loading is switched off or the function is not there: phrases that are about loading by themselves.
 * A refusal that is only a generic "not allowed" ("SELECT queries are not allowed for write_query") is NOT a denial, because the
 * connection behind it may have loading enabled. The bare words count only within 40 characters of "extension" or "load".
 */
const LOAD_DENIED =
  /not authorized|not allowed to load|load_extension (?:is )?(?:disabled|not (?:allowed|enabled|permitted))|no such function: load_extension|extension loading (?:is )?(?:disabled|not (?:allowed|enabled))/i;
const LOAD_WORD = "not allowed|not permitted|disabled|prohibited|forbidden|unsupported|not supported";
const LOAD_DENIED_NEAR = new RegExp(`(?:extension|\\bload\\w*)[^]{0,40}\\b(?:${LOAD_WORD})\\b|\\b(?:${LOAD_WORD})\\b[^]{0,40}(?:extension|\\bload\\w*)`, "i");

/**
 * A refusal or an engine error: the shared rule, plus the prefix some SQLite wrappers put on an engine error in plain text with no
 * `isError` ("Database error: ...", "sqlite3.OperationalError: ...", "SQLite error: ..."). Local to this pack on purpose, so no
 * other pack's refusal detection changes. Anchored to the start of the response like the shared rule: a data row that quotes the words is not one.
 */
const ENGINE_ERROR = /^\s*(?:database error\b|sqlite3?[._ ](?:\w+\.)?\w*(?:error|exception)\b|sqlite_\w+\b)/i;
export function sqliteRefused(r: Pick<CallResult, "isError" | "rpcError" | "text">): boolean {
  return refused(r) || ENGINE_ERROR.test(head(r.text ?? ""));
}

/** The control read passes only when the response carries this run's token and the row count, and is neither a refusal nor a query plan. */
export function controlReadPasses(r: CallResult, token: string): boolean {
  const text = textOf(r);
  return !refused(r) && text.includes(token) && /\b100\b/.test(text) && !PLAN.test(text);
}

/**
 * What `SELECT sqlite_version()` says about the engine behind a tool. Positive evidence only: a reply carrying a 3.x.y version confirms SQLite
 * (`sqlite`); an answer that is not one, or an error in another engine's words, is `other` and the sqlite corpus does not apply; a plain refusal
 * (functions not allowed, a statement filter) says nothing about the engine and is `unconfirmed`, so the pack proceeds with a note.
 */
export type Fingerprint = { engine: "sqlite"; version: string } | { engine: "other"; reply: string; names?: string } | { engine: "unconfirmed"; reply: string };
/** Error classes and phrases of another embedded engine; `no such function: sqlite_version` is what an engine without that function says. */
const OTHER_ENGINE = /\b(?:Catalog|Binder|Parser|Conversion|Invalid Input|Not implemented) Error\b|\bDuckDB\b|no such function:?\s*sqlite_version|Scalar Function with name sqlite_version|function sqlite_version\w* does not exist/i;
export const FINGERPRINT_SQL = "SELECT sqlite_version() AS sm_v";
export function fingerprintOf(r: Pick<CallResult, "isError" | "rpcError" | "text">): Fingerprint {
  const text = (r.text || r.rpcError || "").trim();
  const reply = brief(text || "empty response", 160);
  const version = /(?<![\w.])3\.\d+\.\d+(?![\w.])/.exec(text)?.[0];
  if (version && !sqliteRefused(r)) return { engine: "sqlite", version };
  if (OTHER_ENGINE.test(text)) return { engine: "other", reply, ...(/duckdb/i.test(text) ? { names: "DuckDB" } : {}) };
  if (sqliteRefused(r)) return { engine: "unconfirmed", reply };
  // Answered, but not with a SQLite version: the reply is another engine's (or a stub's), so the SQLite corpus has nothing to say about it.
  return { engine: "other", reply };
}

export type ExtOutcome = "attempted" | "denied" | "unknown";
/**
 * Decided from the engine's own words, never from the fact that the call failed: a refusal that says nothing about loading is `unknown`,
 * and the caller then tries a form the tool accepts (extensionForms).
 */
export function classifyExtensionLoad(r: CallResult): ExtOutcome {
  const t = textOf(r);
  if (LOAD_ATTEMPTED.test(t)) return "attempted";
  if (LOAD_DENIED.test(t) || LOAD_DENIED_NEAR.test(t)) return "denied";
  return "unknown";
}

/**
 * The statements the extension probe sends to one tool, in order. The SELECT form goes first; the others are tried only when that
 * answer was a refusal that said nothing about loading, and they are the forms the tool's role accepts: a writer takes an INSERT and an
 * UPDATE, a reader a SELECT with a WHERE.
 */
export function extensionForms(role: "reader" | "writer", canary: string): { label: string; sql: string }[] {
  const lib = `${canary}/sm-ext`;
  const select = { label: "SELECT form", sql: `SELECT load_extension('${lib}')` };
  return role === "writer"
    ? [select, { label: "INSERT form", sql: `INSERT INTO probe_t (id, v) VALUES (9100, load_extension('${lib}'))` }, { label: "UPDATE form", sql: `UPDATE probe_t SET v = load_extension('${lib}') WHERE id = 9010` }]
    : [select, { label: "WHERE form", sql: `SELECT 1 WHERE load_extension('${lib}') IS NULL` }];
}

// ---------------------------------------------------------------------------------------------------------
// Tools: what the classifier called SQL, and their declared role
// ---------------------------------------------------------------------------------------------------------

type Role = "reader" | "writer" | "unknown";

interface SqlTool {
  name: string;
  arg: string;
  shape: "string" | "array";
  role: Role;
  info: ToolInfo;
  cls: ToolClassification;
}

interface Controlled extends SqlTool {
  /** How the control passed: a read (reader) or a harness-verified INSERT (writer). A declared writer is always `writer`. */
  kind: "reader" | "writer";
  /** Controlled only through `CREATE TABLE sm_ctl_<t> (x)` (verified in the fixture): the file probes run behind a DDL prefix, nothing else does. */
  ddl?: boolean;
  /** The control read passed, so this tool shows rows: a canary token that it read would have been visible. False for a tool controlled only by a write. */
  readOk: boolean;
}

function declaredRole(info: ToolInfo, explicit?: Role): Role {
  return explicit && explicit !== "unknown" ? explicit : roleOf(info);
}

function sqlToolsOf(ctx: PackCtx): SqlTool[] {
  const out: SqlTool[] = [];
  for (const cls of ctx.classification ?? []) {
    if (cls.class !== "sql" || cls.confidence === "low" || cls.excluded || !cls.params.sql) continue;
    const info = ctx.tools.find((t) => t.name === cls.tool);
    if (!info) continue;
    const given = ctx.sqlTools?.find((s) => s.tool === cls.tool);
    const prop = info.inputSchema?.properties?.[cls.params.sql] as { type?: string | string[]; items?: unknown } | undefined;
    const isArray = [prop?.type].flat().includes("array");
    out.push({ name: cls.tool, arg: cls.params.sql, shape: given?.shape ?? (isArray ? "array" : "string"), role: declaredRole(info, given?.role), info, cls });
  }
  return out;
}

type Engine = "sqlite" | "duckdb" | undefined;

function engineOf(ctx: PackCtx): Engine {
  const keys = placeholdersUsed(ctx.config.server);
  const forced = ctx.config.sqlite?.engine ?? undefined;
  if (forced === "duckdb") return "duckdb";
  if (keys.has("duckdb_path") && forced !== "sqlite") return "duckdb";
  if (keys.has("sqlite_path")) return "sqlite";
  if (forced === "sqlite" && (keys.has("dir") || keys.has("sandbox"))) return "sqlite";
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------

function setting(ctx: PackCtx, id: string) {
  return ctx.config.checks?.[id];
}

/** `checks.<id>.severity` overrides how a check counts; `enabled: false` removes it (reported n/a). */
function metaFor(ctx: PackCtx, m: Meta): Meta {
  const sev = setting(ctx, m.id)?.severity;
  if (!sev) return m;
  return { ...m, critical: sev === "critical", advisory: sev === "advisory" ? true : undefined };
}

const isOff = (ctx: PackCtx, m: Meta) => setting(ctx, m.id)?.enabled === false;

function done(ctx: PackCtx, m: Meta, verdict: Verdict, summary: string, evidence: Evidence[], coverage?: CheckCoverage): CheckResult {
  return { ...metaFor(ctx, m), pack: "sqlite", verdict, summary, evidence, ...(coverage ? { coverage } : {}) };
}

function aggregate(perTool: boolean[]): "pass" | "part" | "fail" {
  const ok = perTool.filter(Boolean).length;
  return ok === perTool.length ? "pass" : ok === 0 ? "fail" : "part";
}

const rand = (n = 4) => randomBytes(n).toString("hex");

// ---------------------------------------------------------------------------------------------------------
// The rig: one server session at a time, a pristine fixture behind it, and observers around every call
// ---------------------------------------------------------------------------------------------------------

/** The server stopped answering (crashed, hung or closed). Later cases cannot be judged. */
class Stopped extends Error {}

interface Observed {
  fs: FsSnapshot;
  db: DbState;
}

interface Probed {
  r: CallResult;
  /** The harness saw the database change (file hash or logical content). */
  changed: boolean;
  /** The state could not be read before or after, so "unchanged" is not established. */
  unreadable: boolean;
  canaryAdded: string[];
  canaryChanged: string[];
  canaryRemoved: string[];
  /** `-wal`, `-shm` and `-journal` files present next to the database after the call (a note, never a write; reading a write-ahead-log database can itself create them). */
  sidecars: string[];
  before: DbState;
  after: DbState;
}

const argsFor = (t: SqlTool, sql: string, token: string): Record<string, unknown> =>
  fillArgs(t.info, t.cls, { sql: t.shape === "array" ? [sql] : sql }, token) ?? { [t.arg]: t.shape === "array" ? [sql] : sql };

export class Rig {
  session: McpSession | undefined;
  dirty = false;
  validCalls = 0;
  readonly probed = new Set<string>();
  /** Files the probes created under the canary directory, removed at the end of the run. */
  readonly created = new Set<string>();
  /** Journal or write-ahead-log files seen next to the fixture. */
  readonly sidecars = new Set<string>();

  constructor(
    readonly ctx: PackCtx,
    readonly sb: Sandbox,
    readonly fixture: string,
    readonly pristine: string,
  ) {}

  /** The sandbox is gone or going (an interrupt made the harness remove it): nothing may be recreated inside it. */
  get gone(): boolean {
    return !existsSync(this.sb.dir) || this.ctx.interrupted?.() === true;
  }

  /** Put the pristine fixture back. A file a dying server still holds (Windows) is retried for a few seconds. Does nothing once the sandbox is gone. */
  async restore(): Promise<void> {
    if (this.gone) return;
    let last: unknown;
    for (let i = 0; i < 10; i++) {
      try {
        removeDbFiles(this.fixture);
        mkdirSync(dirname(this.fixture), { recursive: true });
        copyFileSync(this.pristine, this.fixture);
        return;
      } catch (e) {
        last = e;
        await new Promise((r) => setTimeout(r, 300));
      }
    }
    throw last;
  }

  async stop(): Promise<void> {
    const s = this.session;
    this.session = undefined;
    if (s) await s.close();
  }

  /** Close the server, put the pristine fixture back, start the server again and run one harmless read so connect-time work (journal mode, pragmas) is not charged to the first probe. */
  async fresh(tool: SqlTool): Promise<void> {
    await this.stop();
    if (this.gone) throw new Stopped("the run was interrupted");
    await this.restore();
    this.session = await this.ctx.open();
    this.dirty = false;
    const warm = await this.session.call(tool.name, argsFor(tool, "SELECT 1", "sm-warm"), 30_000);
    this.validCalls++;
    this.probed.add(tool.name);
    if (noAnswer(warm)) throw new Stopped(`the server stopped answering at startup (${brief(textOf(warm))})`);
  }

  async ensure(tool: SqlTool): Promise<McpSession> {
    if (!this.session || this.session.closed || this.dirty) await this.fresh(tool);
    return this.session!;
  }

  private async observe(): Promise<Observed> {
    return { fs: await this.sb.fs.snapshot(["root", "canary"]), db: await readState(this.fixture) };
  }

  /** One call with the fixture and the sandbox directories observed before and after. */
  /** `cont` continues a multi-step case on the session the earlier step left, even when that step changed the database on purpose. */
  async probe(tool: SqlTool, sql: string, ms = 30_000, cont = false): Promise<Probed> {
    const s = cont && this.session ? this.session : await this.ensure(tool);
    const before = await this.observe();
    const r = await s.call(tool.name, argsFor(tool, sql, "sm-probe"), ms);
    this.validCalls++;
    this.probed.add(tool.name);
    const after = await this.observe();
    const diff = this.sb.fs.diff(before.fs, after.fs);
    const canary = diffFor(diff, "canary");
    for (const k of canary.added) this.created.add(this.sb.fs.resolve(k));
    const unreadable = !before.db.ok || !after.db.ok;
    const changed = before.db.ok && after.db.ok && (before.db.file !== after.db.file || before.db.logical !== after.db.logical);
    if (changed) this.dirty = true;
    const fixtureName = this.fixture.split(/[\\/]/).pop() ?? "";
    const sidecars = Object.keys(after.fs).filter((k) => k.startsWith("root/") && /-(wal|shm|journal)$/.test(k) && k.slice(5).startsWith(fixtureName));
    sidecars.forEach((k) => this.sidecars.add(k));
    return { r, changed, unreadable, canaryAdded: canary.added, canaryChanged: canary.changed, canaryRemoved: canary.removed, sidecars, before: before.db, after: after.db };
  }
}

const stateNote = (p: Probed) =>
  p.unreadable ? "the database could not be read to confirm (state unknown)" : p.changed ? "the database changed" : `database unchanged (sha256 ${p.after.file?.slice(0, 12)}…)`;

// ---------------------------------------------------------------------------------------------------------
// The pack
// ---------------------------------------------------------------------------------------------------------

const BIG_SELECT = "SELECT id, payload FROM big_table ORDER BY id";
/** Never finishes in the wait window: a recursive series 10^10 long. */
const RUNAWAY = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1e10) SELECT count(*) FROM c";
/** CPU-bound fallback when the server refuses the recursive form: 4 * 10^10 pairs, none of which match. */
const RUNAWAY_JOIN = "SELECT count(*) FROM big_table a CROSS JOIN big_table b WHERE a.id + b.id = -1";

interface Case {
  id: string;
  core: boolean;
  steps: string[];
  /** The harness's own reader for this case; the generic "the database changed" signal also counts. */
  executed: (fixture: string) => Promise<boolean | undefined> | boolean | undefined;
  /** Shown when the call came back without a refusal and changed nothing. */
  quiet?: string;
}

const probeRow = (id: number): Case["executed"] => (fx) => probeRowExists(fx, id);

function builtinCases(): Case[] {
  return [
    { id: "stacked-insert", core: true, steps: ["SELECT 1; INSERT INTO probe_t (id, v) VALUES (9002, 'stacked')"], executed: probeRow(9002), quiet: "accepted without a refusal, but only the first statement ran" },
    { id: "comment-obfuscation", core: true, steps: ["/*x*/ iNsErT INTO probe_t (id, v) VALUES (9003, 'obf')"], executed: probeRow(9003) },
    { id: "cte-insert", core: true, steps: ["WITH x AS (SELECT 1) INSERT INTO probe_t SELECT 9004, 'cte' FROM x"], executed: probeRow(9004) },
    { id: "replace-into", core: false, steps: ["REPLACE INTO probe_t (id, v) VALUES (9005, 'replace')"], executed: probeRow(9005) },
    { id: "upsert", core: false, steps: ["INSERT INTO probe_t (id, v) VALUES (9006, 'upsert') ON CONFLICT (id) DO UPDATE SET v = 'x'"], executed: probeRow(9006) },
    { id: "create-table", core: false, steps: ["CREATE TABLE sm_ddl (x int)"], executed: (fx) => tableExists(fx, "sm_ddl") },
    { id: "alter-table", core: false, steps: ["ALTER TABLE probe_t ADD COLUMN sm int"], executed: (fx) => columnExists(fx, "probe_t", "sm") },
    { id: "drop-table", core: false, steps: ["DROP TABLE audit_probe"], executed: async (fx) => (await tableExists(fx, "audit_probe")) === false },
    { id: "pragma-user-version", core: false, steps: ["PRAGMA user_version = 7"], executed: (fx) => userVersionOf(fx) === 7 },
    { id: "pragma-journal-mode", core: false, steps: ["PRAGMA journal_mode = wal"], executed: async (fx) => (await journalModeOf(fx)) === "wal" },
  ];
}

/** `corpus.add` entries (`executed: probe_row:<id>` or `table_exists:<name>`) become cases; `corpus.remove` drops by id or exact step text. */
function corpusFor(ctx: PackCtx): Case[] {
  const conf = setting(ctx, META.mutating.id)?.corpus;
  const cases = builtinCases();
  const remove = new Set(conf?.remove ?? []);
  const kept = cases.filter((c) => !remove.has(c.id) && !c.steps.some((s) => remove.has(s)));
  for (const raw of conf?.add ?? []) {
    const a = raw as { id: string; core?: boolean; steps: string[]; executed: string };
    const [kind, arg] = a.executed.split(":");
    kept.push({
      id: a.id,
      core: Boolean(a.core),
      steps: a.steps,
      executed: kind === "probe_row" ? probeRow(Number(arg)) : (fx) => tableExists(fx, arg),
    });
  }
  return kept;
}

export const pack: Pack = {
  id: "sqlite",
  describe,
  applies(ctx) {
    // Cheap checks first: loading node:sqlite prints Node's ExperimentalWarning, so it happens only for a config this pack can run.
    if (!ctx.config?.server) return { ok: false, reason: "no server configuration" };
    if (ctx.config.server.url && !ctx.config.server.command) return { ok: false, reason: "the server is already running (HTTP), so the harness cannot start it with the {sqlite_path} fixture" };
    if (!ctx.sandbox || ctx.sandboxEnabled === false) return { ok: false, reason: "the sandbox is off, so the fixture and canary directories prove nothing" };
    const engine = engineOf(ctx);
    if (engine === "duckdb") return { ok: false, reason: DUCKDB_PLANNED };
    if (!engine) return { ok: false, reason: NO_PLACEHOLDER };
    if (!sqlToolsOf(ctx).length) return { ok: false, reason: "no tool takes a SQL string" };
    const why = sqliteUnavailable();
    // node:sqlite missing or switched off is a property of the harness's Node, not of the server: inconclusive, not n/a.
    if (why) return { ok: false, reason: why, kind: "harness" };
    return { ok: true };
  },
  run: runSqlite,
};
export default pack;

function inconclusiveAll(ctx: PackCtx, reason: string): CheckResult[] {
  return ALL_META.map((m) => (isOff(ctx, m) ? disabled(ctx, m) : done(ctx, m, "inconclusive", reason, [])));
}

function disabled(ctx: PackCtx, m: Meta): CheckResult {
  return done(ctx, m, "na", "disabled by config", []);
}

async function runSqlite(ctx: PackCtx): Promise<CheckResult[]> {
  const sb = ctx.sandbox!;
  const tools = sqlToolsOf(ctx);
  const fixture = join(sb.root, "fixture.sqlite");
  const pristineDir = join(sb.dir, "sqlite-pristine");
  const pristine = join(pristineDir, "fixture.sqlite");
  const dbToken = `sm-fscanary-${rand(8)}`;
  const canaryDb = join(sb.canary, "secret.db");
  const CAN = sqlPath(sb.canary);
  const shown = (s: string) => s.split(CAN).join("{canary}");

  mkdirSync(pristineDir, { recursive: true });
  createSqliteFixture(pristine);
  createCanaryDb(canaryDb, dbToken);
  const rig = new Rig(ctx, sb, fixture, pristine);
  const log = (s: string) => ctx.log(`sqlite: ${s}`);

  /** `sent` is the SQL of each call, in order. `args` carries exactly that (one entry per call); a note about the probe goes in `more.probe` or the outcome, never in `args`. */
  const ev = (t: SqlTool, sent: string | string[], outcome: string, verifiedBy: Evidence["verifiedBy"], more: Partial<Evidence> = {}): Evidence => {
    const calls = [sent].flat().map((sql) => ({ [t.arg]: t.shape === "array" ? [shown(sql)] : shown(sql) }));
    return {
      probe: [sent].flat().map(shown).join("  →  "),
      outcome,
      verifiedBy,
      tool: t.name,
      args: calls.length === 1 ? calls[0] : calls,
      ...more,
    };
  };

  try {
    await rig.restore();

    // ---- controls: a tool that cannot run a basic read (or a verified INSERT) proves nothing when it blocks things ----
    const controlled: Controlled[] = [];
    const notCovered: { tool: string; reason: string }[] = [];
    const controlNotes: Evidence[] = [];
    for (const t of tools) {
      const tok = `sm-ctl-${rand(6)}`;
      const sql = `SELECT '${tok}' AS t, count(*) AS n FROM customers`;
      try {
        const p = await rig.probe(t, sql);
        const text = textOf(p.r);
        const readOk = controlReadPasses(p.r, tok);
        if (readOk) {
          controlled.push({ ...t, kind: t.role === "writer" ? "writer" : "reader", readOk: true });
          controlNotes.push(ev(t, sql, `control read passed${t.role === "writer" ? " (declared writer tool: the file probes run on it; the mutation, row-cap and timeout probes do not)" : ""}`, "response"));
          continue;
        }
        const why = PLAN.test(text) && !text.includes(tok) ? "returned a plan, not rows" : `control read failed: ${brief(text || "empty response")}`;
        controlNotes.push(ev(t, sql, why, "response"));
        if (t.role === "reader") {
          notCovered.push({ tool: t.name, reason: why });
          continue;
        }
        const ins = `INSERT INTO probe_t (id, v) VALUES (9000, '${tok}')`;
        const w = await rig.probe(t, ins);
        const landed = (await probeRowExists(fixture, 9000)) === true;
        controlNotes.push(ev(t, ins, landed ? "control write landed (verified in the database file)" : `control write did not land (${brief(textOf(w.r))})`, "db-state"));
        if (landed) {
          controlled.push({ ...t, kind: "writer", readOk: false });
          continue;
        }
        // A DDL-only tool (a create_table style tool) takes neither a SELECT nor an INSERT. CREATE TABLE is the third control: the table must be in the fixture file.
        const ctlTable = `sm_ctl_${rand(3)}`;
        const ddl = `CREATE TABLE ${ctlTable} (x)`;
        const d = await rig.probe(t, ddl);
        const made = (await tableExists(fixture, ctlTable)) === true;
        controlNotes.push(
          ev(t, ddl, made ? "control CREATE TABLE landed (verified in the database file): DDL-only tool, controlled through CREATE TABLE" : `no control form worked: no table appeared in the database file (${brief(textOf(d.r))})`, "db-state"),
        );
        if (made) controlled.push({ ...t, kind: "writer", readOk: false, ddl: true });
        else notCovered.push({ tool: t.name, reason: `neither a control read nor a control write nor a control CREATE TABLE worked (${why})` });
      } catch (e) {
        if (e instanceof Stopped) {
          notCovered.push({ tool: t.name, reason: e.message });
          continue;
        }
        throw e;
      }
    }
    await rig.stop();
    if (!controlled.length) {
      return inconclusiveAll(ctx, `no SQL tool could run a basic read as a control (${controlNotes[0]?.outcome ?? "no SQL tool"}); check how the server takes its database path ({sqlite_path})`).map((c) => ({ ...c, evidence: controlNotes }));
    }

    // ---- engine fingerprint: the corpus is SQLite's, so the engine is confirmed by a function only SQLite answers ----
    // {sqlite_path} says what the harness gave the server, not what answers behind it. Asked once, through the first tool that answered a read.
    let engineNote: Evidence | undefined;
    const askTool = controlled.find((c) => c.readOk);
    if (!askTool) {
      engineNote = { probe: FINGERPRINT_SQL, outcome: "engine not confirmed: no tool answered a basic read, so sqlite_version() could not be asked", verifiedBy: "response", code: "sqlite.engine.unconfirmed" };
    } else {
      try {
        const p = await rig.probe(askTool, FINGERPRINT_SQL);
        if (noAnswer(p.r)) throw new Stopped(`the server stopped answering (${brief(textOf(p.r))})`);
        const fp = fingerprintOf(p.r);
        if (fp.engine === "other") {
          const reason = `the server's engine did not answer like SQLite (sqlite_version(): ${fp.reply}); the sqlite corpus does not apply${fp.names ? ` (the error names ${fp.names})` : ""}`;
          const fpEv = ev(askTool, FINGERPRINT_SQL, `not SQLite: ${fp.reply}`, "response", { code: "sqlite.engine.other", excerpt: excerpt(textOf(p.r)) });
          return inconclusiveAll(ctx, reason).map((c) => (c.verdict === "inconclusive" ? { ...c, evidence: [fpEv] } : c));
        }
        controlNotes.push(ev(askTool, FINGERPRINT_SQL, fp.engine === "sqlite" ? `engine confirmed: sqlite_version() answered ${fp.version}` : `engine not confirmed: ${fp.reply}`, "response", { code: `sqlite.engine.${fp.engine === "sqlite" ? "confirmed" : "unconfirmed"}` }));
        if (fp.engine === "unconfirmed") {
          engineNote = { ...controlNotes[controlNotes.length - 1], outcome: `engine not confirmed: sqlite_version() was refused, so the engine was taken to be SQLite as {sqlite_path} says (${fp.reply})` };
        }
      } catch (e) {
        if (!(e instanceof Stopped)) throw e;
        engineNote = { probe: FINGERPRINT_SQL, outcome: `engine not confirmed: ${e.message}`, verifiedBy: "response", code: "sqlite.engine.unconfirmed" };
      } finally {
        await rig.stop();
      }
    }
    const uncontrolled = notCovered.map((n) => n.tool);
    /** A SQL tool no control form could drive proves nothing when it refuses a probe: the file checks cannot pass over it (the line git-repo-scope draws). */
    const uncontrolledPart = (v: Verdict, summary: string): { v: Verdict; summary: string } =>
      v === "pass" && uncontrolled.length ? { v: "part", summary: `${summary}; ${uncontrolled.join(", ")} could not be controlled (no control read, INSERT or CREATE TABLE worked), so the check cannot say ${uncontrolled.length === 1 ? "it refuses" : "they refuse"}` } : { v, summary };
    const readers = controlled.filter((t) => t.kind === "reader");
    const writers = controlled.filter((t) => t.kind === "writer");
    // A declared writer is probed for the file checks (VACUUM INTO, ATTACH and load_extension are verified by the file observer and the
    // canary token and need no read control). Only the checks whose probes are mutation or read-volume probes leave it out.
    const WRITER_EXCLUDED: Record<string, string> = {
      [META.mutating.id]: "the mutation corpus does not apply (a writer is expected to run mutating SQL)",
      [META.rowcap.id]: "the row-cap probe does not apply (it is a large read)",
      [META.timeout.id]: "the timeout probe does not apply (it is a long read)",
    };
    const cov = (m: Meta, tools: SqlTool[], extra: { tool: string; reason: string }[] = []): CheckCoverage => ({
      probed: tools.map((t) => t.name),
      notCovered: [...notCovered, ...(WRITER_EXCLUDED[m.id] ? writers.map((t) => ({ tool: t.name, reason: `declared writer tool: ${WRITER_EXCLUDED[m.id]}` })) : []), ...extra],
      validCalls: rig.validCalls,
    });
    const noReaders = (m: Meta): CheckResult =>
      done(ctx, m, "inconclusive", `not covered: only declared writer tool(s) (${writers.map((t) => t.name).join(", ")}) could be controlled, and for a declared writer ${WRITER_EXCLUDED[m.id]}`, [], cov(m, []));

    const out: CheckResult[] = [];
    const run = async (m: Meta, fn: () => Promise<CheckResult>) => {
      if (isOff(ctx, m)) return out.push(disabled(ctx, m));
      try {
        const c = await fn();
        out.push(engineNote ? { ...c, evidence: [...c.evidence, engineNote] } : c);
      } catch (e) {
        if (e instanceof Stopped) out.push(done(ctx, m, "inconclusive", `${e.message}, so this check could not be completed`, [], cov(m, [])));
        else if (e instanceof SessionError) out.push(done(ctx, m, "inconclusive", `could not start the server again: ${(e as Error).message}`, [], cov(m, [])));
        else throw e;
      } finally {
        await rig.stop();
      }
    };

    // ---- sqlite-read-only: plain writes on every controlled tool ----
    await run(META.readonly, async () => {
      const evidence: Evidence[] = [];
      const per: { tool: SqlTool; clean: boolean; kind: string }[] = [];
      const writes: { label: string; sql: string; applied: () => boolean | undefined | Promise<boolean | undefined> }[] = [
        { label: "INSERT", sql: "INSERT INTO probe_t (id, v) VALUES (9001, 'sm-insert')", applied: () => probeRowExists(fixture, 9001) },
        { label: "UPDATE", sql: "UPDATE tenants SET name = 'sm-updated' WHERE id = 1", applied: async () => (await tenantName(fixture, 1)) === "sm-updated" },
        { label: "DELETE", sql: "DELETE FROM probe_t WHERE id = 9010", applied: async () => ((await probeRowExists(fixture, 9010)) === false ? true : undefined) },
      ];
      let stopped = false;
      let anyExecuted = false;
      let unreadable = 0;
      outer: for (const t of controlled) {
        let blocked = true;
        for (const w of writes) {
          const p = await rig.probe(t, w.sql);
          const applied = (await w.applied()) === true || p.changed;
          if (p.unreadable && !applied) unreadable++;
          if (applied) {
            blocked = false;
            anyExecuted = true;
          } else if (noAnswer(p.r)) {
            stopped = true;
            evidence.push(ev(t, w.sql, `no evidence: the server stopped answering during the write probes (${brief(textOf(p.r))})`, "response"));
            per.push({ tool: t, clean: blocked, kind: t.kind });
            break outer;
          }
          evidence.push(ev(t, w.sql, applied ? `executed: ${stateNote(p)}` : `not applied (${brief(textOf(p.r) || "empty response")}); ${stateNote(p)}`, "db-state", { code: applied ? "sqlite.write.executed" : "sqlite.write.blocked" }));
        }
        per.push({ tool: t, clean: blocked, kind: t.kind });
      }
      const coverage = cov(META.readonly, controlled, [{ tool: "(engine)", reason: "engine has no roles or grants; row filtering and masking are not graded" }]);
      if (stopped && !anyExecuted) return done(ctx, META.readonly, "inconclusive", "the server stopped answering during the write probes, so no write was observed either way", evidence, coverage);
      const v = aggregate(per.map((x) => x.clean));
      if (v === "pass" && unreadable) return done(ctx, META.readonly, "inconclusive", `the database file could not be read after ${unreadable} probe(s), so "unchanged" is not established`, evidence, coverage);
      const names = (xs: typeof per) => xs.map((x) => `${x.tool.name}${x.kind === "writer" ? " (declared writer tool; exclude it under tools.exclude if writes are intended)" : ""}`).join(", ");
      const summary =
        v === "pass"
          ? `plain writes blocked on all ${per.length} SQL tool(s)`
          : v === "part"
            ? `writes executed through ${names(per.filter((x) => !x.clean))} and blocked on ${names(per.filter((x) => x.clean))}`
            : `writes executed on every SQL tool (${names(per)})`;
      return done(ctx, META.readonly, v, summary, evidence, coverage);
    });

    // ---- sqlite-mutating-sql ----
    await run(META.mutating, async () => {
      if (!readers.length) return noReaders(META.mutating);
      const cases = corpusFor(ctx);
      const evidence: Evidence[] = [];
      let coreExecuted = false;
      let anyExecuted = false;
      let stopped = false;
      let unreadable = 0;
      const executedIds: string[] = [];
      /** Cases the server accepted without a refusal that changed nothing (a stacked statement of which only the first ran): not blocked, not executed. */
      const ineffectiveIds = new Set<string>();
      outer: for (const t of readers) {
        for (const c of cases) {
          await rig.ensure(t);
          let last: Probed | undefined;
          let gone: CallResult | undefined;
          let changedAny = false;
          for (const [i, step] of c.steps.entries()) {
            last = await rig.probe(t, step, 30_000, i > 0);
            changedAny ||= last.changed;
            if (last.unreadable) unreadable++;
            if (noAnswer(last.r)) {
              gone = last.r;
              break;
            }
          }
          const specific = (await c.executed(fixture)) === true;
          const ran = specific || changedAny;
          const text = textOf(last!.r);
          if (ran) {
            anyExecuted = true;
            if (c.core) coreExecuted = true;
            executedIds.push(c.id);
          } else if (gone) {
            stopped = true;
            evidence.push(ev(t, c.steps, `no evidence: the server stopped answering (${brief(textOf(gone))}); the remaining cases were not run`, "response"));
            break outer;
          }
          const quiet = !ran && !sqliteRefused(last!.r) && c.quiet ? ` (${c.quiet})` : "";
          if (quiet) ineffectiveIds.add(c.id);
          evidence.push(
            ev(t, c.steps, ran ? `EXECUTED: ${c.id}; ${stateNote(last!)}` : `blocked or ineffective: ${c.id} (${brief(text || "empty response")})${quiet}; ${stateNote(last!)}`, "db-state", {
              code: ran ? "sqlite.mutation.executed" : "sqlite.mutation.blocked",
            }),
          );
        }
      }
      if (rig.sidecars.size) evidence.push({ probe: "files next to the fixture", outcome: `${[...rig.sidecars].join(", ")} appeared next to the database (journal or write-ahead-log files; noted, not counted as a write)`, verifiedBy: "fs-observer", code: "sqlite.sidecar" });
      const coverage = cov(META.mutating, readers);
      const v: Verdict = coreExecuted ? "fail" : stopped ? "inconclusive" : anyExecuted ? "part" : unreadable ? "inconclusive" : "pass";
      const summary =
        v === "inconclusive"
          ? stopped
            ? "the server stopped answering during the mutation corpus, so it could not be completed"
            : `the database file could not be read after ${unreadable} probe(s), so "unchanged" is not established`
          : v === "pass"
            ? `all ${cases.length} mutation forms blocked on ${readers.length} tool(s)`
            : (() => {
                const ran = new Set(executedIds);
                const ineffective = [...ineffectiveIds].filter((id) => !ran.has(id)).length;
                const blocked = cases.length - ran.size - ineffective;
                return `EXECUTED: ${[...ran].join(", ")}; ${blocked} of ${cases.length} blocked${ineffective ? `, ${ineffective} ineffective (accepted, only the first statement ran)` : ""}`;
              })();
      return done(ctx, META.mutating, v, summary, evidence, coverage);
    });

    // ---- sqlite-file-read: ATTACH an existing database outside the fixture and read it ----
    // Every controlled tool is probed, a declared writer included: the verdict comes from the canary token, not from a read control.
    await run(META.fileRead, async () => {
      const evidence: Evidence[] = [];
      type Seen = "clean" | "leaked" | "unshown";
      /** `through`: the controlled reader that was asked, on the same session, about what the tool's ATTACH left behind. */
      const per: { tool: Controlled; seen: Seen; through?: string }[] = [];
      const unshown: { tool: string; reason: string }[] = [];
      // A tool that shows no rows cannot show the canary itself. When a controlled reader exists, it is asked on the same session.
      const reader = readers[0];

      /** One more way in, tried through one tool. `table` is a table the form tries to create in the fixture: the harness reads it from the file. */
      interface ReadForm {
        label: string;
        steps: string[];
        table?: string;
      }
      /** Forms the two-call ATTACH then SELECT misses: one call (a fresh connection per call hides the two-call form), and a copy of the other file into the fixture. */
      const extraReadForms = (stamp: string): ReadForm[] => {
        const url = `'${CAN}/secret.db'`;
        return [
          { label: "ATTACH and SELECT in one call", steps: [`ATTACH ${url} AS sm_a_${stamp}; SELECT v FROM sm_a_${stamp}.secret`] },
          { label: "ATTACH and copy into the fixture in one call", steps: [`ATTACH ${url} AS sm_b_${stamp}; CREATE TABLE sm_rd_${stamp}b AS SELECT v FROM sm_b_${stamp}.secret`], table: `sm_rd_${stamp}b` },
          { label: "ATTACH, then copy into the fixture, in two calls", steps: [`ATTACH ${url} AS sm_c_${stamp}`, `CREATE TABLE sm_rd_${stamp}c AS SELECT v FROM sm_c_${stamp}.secret`], table: `sm_rd_${stamp}c` },
        ];
      };
      /** DDL-only tools take a CREATE TABLE first and (a server that runs stacked statements) whatever follows it. */
      const ddlReadForms = (stamp: string): ReadForm[] => [
        {
          label: "CREATE TABLE, then ATTACH and copy into the fixture, in one call",
          steps: [`CREATE TABLE sm_p_${stamp} (x); ATTACH '${CAN}/secret.db' AS sm_a_${stamp}; CREATE TABLE sm_rd_${stamp} AS SELECT v FROM sm_a_${stamp}.secret`],
          table: `sm_rd_${stamp}`,
        },
      ];
      /** Runs the forms in order and stops at the first that shows the token (in a response, or in the fixture file the harness reads itself). */
      const tryForms = async (t: Controlled, forms: ReadForm[]): Promise<{ leaked: boolean; evidence: Evidence[] }> => {
        const found: Evidence[] = [];
        for (const f of forms) {
          let said = "";
          let leaked = false;
          let viaFile = false;
          let state = "";
          for (const [i, step] of f.steps.entries()) {
            const p = await rig.probe(t, step, 30_000, i > 0);
            if (noAnswer(p.r)) throw new Stopped("the server stopped answering during the file-read probes");
            said = textOf(p.r);
            state = stateNote(p);
            if (said.includes(dbToken)) leaked = true;
            // Read the fixture before the next probe: a copy changes the fixture, and the next probe puts the pristine one back.
            if (f.table && !leaked && (await tableHasValue(fixture, f.table, dbToken)) === true) {
              leaked = true;
              viaFile = true;
            }
          }
          found.push(
            ev(
              t,
              f.steps,
              leaked
                ? viaFile
                  ? `the canary token from a database outside the fixture was copied into the fixture database (table ${f.table}, read by the harness from the file): ${f.label}`
                  : `returned the canary token from a database outside the fixture: ${f.label}`
                : `no canary token in the response${f.table ? " or in the fixture file" : ""}: ${f.label} (${brief(said || "empty")})${f.table ? `; ${state}` : ""}`,
              f.table ? "db-state" : "response",
              { code: leaked ? "sqlite.file-read.canary-leaked" : "sqlite.file-read.blocked", ...(leaked && !viaFile ? { excerpt: excerpt(said) } : {}) },
            ),
          );
          if (leaked) return { leaked: true, evidence: found };
        }
        return { leaked: false, evidence: found };
      };

      for (const t of controlled) {
        if (t.ddl) {
          const r = await tryForms(t, ddlReadForms(rand(3)));
          per.push({ tool: t, seen: r.leaked ? "leaked" : "clean" });
          evidence.push(...r.evidence);
          continue;
        }
        await rig.ensure(t);
        const alias = `sm_s_${rand(3)}`;
        const attach = `ATTACH '${CAN}/secret.db' AS ${alias}`;
        const read = `SELECT v FROM ${alias}.secret`;
        const list = "SELECT name FROM pragma_database_list";
        const a = await rig.probe(t, attach);
        const b = await rig.probe(t, read, 30_000, true);
        if (noAnswer(b.r) || noAnswer(a.r)) throw new Stopped("the server stopped answering during the file-read probes");
        let leaked = textOf(a.r).includes(dbToken) || textOf(b.r).includes(dbToken);
        let seen: Seen = leaked ? "leaked" : !t.readOk && !sqliteRefused(a.r) ? "unshown" : "clean";
        let chain: string | undefined;
        let said = `ATTACH: ${brief(textOf(a.r) || "empty")}; read: ${brief(textOf(b.r) || "empty")}`;
        let leakText = textOf(b.r) || textOf(a.r);
        let through: string | undefined;
        let note = "";
        if (seen === "unshown" && reader && reader.name !== t.name) {
          // The ATTACH was accepted and shows nothing. Whether it left the database attached for the reader on the same session decides.
          through = reader.name;
          const c = await rig.probe(reader, read, 30_000, true);
          const d = await rig.probe(reader, list, 30_000, true);
          if (noAnswer(c.r) || noAnswer(d.r)) throw new Stopped("the server stopped answering during the file-read probes");
          chain = `${attach}  →  ${read}  →  ${read} (through ${reader.name})  →  ${list} (through ${reader.name})`;
          said = `ATTACH through ${t.name}: ${brief(textOf(a.r) || "empty")}; read through ${reader.name}: ${brief(textOf(c.r) || "empty")}; database list through ${reader.name}: ${brief(textOf(d.r) || "empty")}`;
          const visible = textOf(d.r).includes(alias);
          const listShown = !sqliteRefused(d.r) && textOf(d.r).trim() !== "";
          if (textOf(c.r).includes(dbToken)) {
            leaked = true;
            seen = "leaked";
            leakText = textOf(c.r);
          } else if (visible && sqliteRefused(c.r)) {
            seen = "clean";
            note = `the ATTACH persisted (the alias is in the reader's database list) but ${reader.name} refused to read it`;
          } else if (!visible && (listShown || /no such table|unknown database|no such database/i.test(textOf(c.r)))) {
            seen = "clean";
            note = "the ATTACH did not persist for the reader: the server uses a fresh connection per call";
          }
          // Otherwise (the reader neither showed the token nor said the alias is missing or refused) it stays unshown.
        }
        const outcome = leaked
          ? through
            ? `returned the canary token from a database outside the fixture (attached through ${t.name}, read through ${through}; the server shares the attached database between its tools)`
            : "returned the canary token from a database outside the fixture (the server attached and read a file it was not given)"
          : seen === "unshown"
            ? `the ATTACH of a database outside the fixture was accepted, but this tool returns no rows, so no canary token could have shown (${said})`
            : note
              ? `no canary token: ${note} (${said})`
              : `no canary token (${said})`;
        evidence.push(
          ev(t, [attach, read], outcome, "response", {
            ...(chain ? { probe: shown(chain) } : {}),
            code: leaked ? "sqlite.file-read.canary-leaked" : seen === "unshown" ? "sqlite.file-read.unshown" : "sqlite.file-read.blocked",
            ...(leaked ? { excerpt: excerpt(leakText) } : {}),
          }),
        );
        // The forms the two-call probe misses, until one shows the token. A leak already found is decisive, so nothing more is sent through this tool.
        let finalSeen: Seen = seen;
        let finalThrough = through;
        if (!leaked) {
          const more = await tryForms(t, extraReadForms(rand(3)));
          evidence.push(...more.evidence);
          if (more.leaked) {
            finalSeen = "leaked";
            finalThrough = undefined;
          }
        }
        per.push({ tool: t, seen: finalSeen, through: finalThrough });
        if (finalSeen === "unshown") {
          unshown.push({
            tool: t.name,
            reason: reader
              ? `declared writer tool accepted an ATTACH of a database outside the fixture and returns no rows, and ${reader.name} on the same session neither showed it nor said it was missing, so a read can be neither confirmed nor ruled out`
              : "declared writer tool accepted an ATTACH of a database outside the fixture but returns no rows, and no controlled reader exists to ask, so a read can be neither confirmed nor ruled out",
          });
        }
      }
      const names = (pick: (s: Seen) => boolean) => per.filter((x) => pick(x.seen)).map((x) => x.tool.name).join(", ");
      const direct = per.filter((x) => x.seen === "leaked" && !x.through);
      const viaReader = per.filter((x) => x.seen === "leaked" && x.through);
      const cleanedByReader = per.filter((x) => x.seen === "clean" && x.through);
      const coverage = cov(META.fileRead, controlled, [...unshown, { tool: "(engine)", reason: "SQLite reads other files only through ATTACH; DuckDB file-reading functions are planned" }]);
      // One tool that reads another file is a breach however many others are clean, so any leak fails the check.
      const v0: Verdict = per.some((x) => x.seen === "leaked") ? "fail" : unshown.length ? "inconclusive" : "pass";
      const summary0 =
        v0 === "pass"
          ? `no canary database was readable through ${per.length} tool(s)${cleanedByReader.length ? `; ${cleanedByReader.map((x) => x.tool.name).join(", ")} accepted an ATTACH, but the reader on the same session could not read what it attached (see the evidence)` : ""}`
          : v0 === "inconclusive"
            ? `no canary database was read through ${names((s) => s === "clean") || "any tool"}, but ${names((s) => s === "unshown")} accepted an ATTACH of a database outside the fixture and returns no rows${readers.length ? ", and a controlled reader on the same session did not settle it" : ", and no controlled reader exists to ask"}, so a read cannot be ruled out`
            : [
                ...(direct.length ? [per.every((x) => x.seen === "leaked" && !x.through) ? "a database outside the fixture was attached and read through every tool" : `a database outside the fixture was attached and read through ${direct.map((x) => x.tool.name).join(", ")}; not through ${per.filter((x) => !direct.includes(x)).map((x) => x.tool.name).join(", ")}`] : []),
                ...viaReader.map((x) => `a database outside the fixture was attached through ${x.tool.name} and read through ${x.through} (the attached database is shared between the tools)`),
              ].join("; ");
      const { v, summary } = uncontrolledPart(v0, summary0);
      return done(ctx, META.fileRead, v, summary, evidence, coverage);
    });

    // ---- sqlite-file-write: VACUUM INTO and ATTACH of a new file, observed in the canary directory ----
    // Every controlled tool is probed, a declared writer included: the file observer decides, so no read control is needed.
    await run(META.fileWrite, async () => {
      const evidence: Evidence[] = [];
      const per: { tool: Controlled; clean: boolean }[] = [];
      for (const t of controlled) {
        await rig.ensure(t);
        const stamp = rand(3);
        // A DDL-only tool takes a CREATE TABLE first, so its probes sit behind one (and a server that runs stacked statements runs the rest).
        const ddl = t.ddl ? `CREATE TABLE sm_p_${stamp} (x); ` : "";
        const cases: { id: string; steps: string[] }[] = t.ddl
          ? [
              { id: "CREATE TABLE, then VACUUM INTO", steps: [`${ddl}VACUUM INTO '${CAN}/vac-${stamp}.db'`] },
              { id: "CREATE TABLE, then ATTACH new file", steps: [`${ddl}ATTACH '${CAN}/att-${stamp}.db' AS sm_a; CREATE TABLE sm_a.t (x)`] },
            ]
          : [
              { id: "VACUUM INTO", steps: [`VACUUM INTO '${CAN}/vac-${stamp}.db'`] },
              { id: "ATTACH new file", steps: [`ATTACH '${CAN}/att-${stamp}.db' AS sm_a`, "CREATE TABLE sm_a.t (x)"] },
              { id: "ATTACH new file, one call", steps: [`ATTACH '${CAN}/att1-${stamp}.db' AS sm_b; CREATE TABLE sm_b.t (x)`] },
            ];
        let clean = true;
        for (const c of cases) {
          const added = new Set<string>();
          const changed = new Set<string>();
          let last: Probed | undefined;
          for (const [i, step] of c.steps.entries()) {
            last = await rig.probe(t, step, 30_000, i > 0);
            last.canaryAdded.forEach((k) => added.add(k));
            [...last.canaryChanged, ...last.canaryRemoved].forEach((k) => changed.add(k));
            if (noAnswer(last.r)) throw new Stopped("the server stopped answering during the file-write probes");
          }
          const wrote = added.size > 0 || changed.size > 0;
          if (wrote) clean = false;
          evidence.push(
            ev(t, c.steps, wrote ? `wrote outside the fixture: ${[...added].map((k) => `${k} (new)`).concat([...changed].filter((k) => !added.has(k)).map((k) => `${k} (changed)`)).join(", ")}` : `no file appeared in the canary directory (${brief(textOf(last!.r) || "empty")})`, "fs-observer", {
              code: wrote ? "sqlite.file-write.created" : "sqlite.file-write.blocked",
            }),
          );
        }
        per.push({ tool: t, clean });
      }
      // One tool that writes another file is a breach however many others are clean, so any write fails the check.
      const dirty = per.filter((x) => !x.clean).map((x) => x.tool.name);
      const v0: Verdict = dirty.length ? "fail" : "pass";
      const summary0 =
        v0 === "pass"
          ? `nothing was written outside the fixture through ${per.length} tool(s)`
          : dirty.length === per.length
            ? "files were written to the canary directory through every tool"
            : `files were written to the canary directory through ${dirty.join(", ")}; not through ${per.filter((x) => x.clean).map((x) => x.tool.name).join(", ")}`;
      const { v, summary } = uncontrolledPart(v0, summary0);
      return done(ctx, META.fileWrite, v, summary, evidence, cov(META.fileWrite, controlled));
    });

    // ---- sqlite-extension-load: decided from the error text ----
    // Every controlled tool is probed, a declared writer included.
    await run(META.ext, async () => {
      const evidence: Evidence[] = [];
      const per: ExtOutcome[] = [];
      /** Tools that refused every form without a word about extension loading. */
      const mute: string[] = [];
      // A DDL-only tool takes neither a SELECT nor an INSERT, so none of the forms below can reach it: it is left out and listed.
      const ddlOnly = controlled.filter((c) => c.ddl);
      for (const t of controlled.filter((c) => !c.ddl)) {
        await rig.ensure(t);
        // The SELECT form first. A refusal that says nothing about loading (a writer that does not take SELECT, a reader that wants a different
        // shape) decides nothing, so the forms the tool's role accepts are tried too. The text decides, never the fact that a call failed.
        const forms = extensionForms(t.kind, CAN);
        const sent: string[] = [];
        let o: ExtOutcome = "unknown";
        let last: Probed | undefined;
        let via = "";
        for (const [i, f] of forms.entries()) {
          last = await rig.probe(t, f.sql);
          if (noAnswer(last.r)) throw new Stopped("the server stopped answering during the extension probe");
          sent.push(f.sql);
          o = classifyExtensionLoad(last.r);
          if (i > 0) via = f.label;
          if (o !== "unknown" || !sqliteRefused(last.r)) break;
        }
        const said = brief(textOf(last!.r) || "empty");
        const silent = o === "unknown" && sqliteRefused(last!.r);
        if (silent) mute.push(t.name);
        const how = via ? ` (through the ${via}, after the SELECT form was refused without a word about extensions)` : "";
        evidence.push(
          ev(
            t,
            sent,
            o === "attempted"
              ? `the engine tried to load a library${how}: ${said}`
              : o === "denied"
                ? `loading was refused${how}: ${said}`
                : silent
                  ? `the server refused the probe forms without saying anything about extension loading (${sent.length} form(s) tried): ${said}`
                  : `unrecognised answer, so this cannot be decided: ${said}`,
            "response",
            { code: `sqlite.extension.${o}`, excerpt: excerpt(textOf(last!.r)) },
          ),
        );
        per.push(o);
      }
      const attempted = per.map((o) => o !== "attempted");
      const coverage = cov(META.ext, controlled.filter((c) => !c.ddl), [
        ...ddlOnly.map((t) => ({ tool: t.name, reason: "DDL-only tool: the extension probe forms are a SELECT or an INSERT, which it does not take" })),
        { tool: "(engine)", reason: "a real extension is never shipped: only whether the load is attempted is observed, never what a loaded library would do" },
      ]);
      if (!per.length) return done(ctx, META.ext, "inconclusive", `not covered: only DDL-only tool(s) (${ddlOnly.map((t) => t.name).join(", ")}) could be controlled, and the extension probe forms are a SELECT or an INSERT, which they do not take`, evidence, coverage);
      const silentWhy = `the server refused the probe forms without saying anything about extension loading (${mute.join(", ")})`;
      if (per.every((o) => o === "unknown")) return done(ctx, META.ext, "inconclusive", mute.length === per.length ? silentWhy : "the answer was not recognisable as either a refusal or an attempted load", evidence, coverage);
      if (per.some((o) => o === "attempted")) {
        const v = aggregate(attempted);
        return done(ctx, META.ext, v, v === "part" ? "extension loading was attempted through some tools but not others" : "extension loading was attempted: the engine tried to open a library from a path the harness chose", evidence, coverage);
      }
      if (per.some((o) => o === "unknown")) return done(ctx, META.ext, "inconclusive", mute.length ? silentWhy : "some answers were not recognisable as either a refusal or an attempted load", evidence, coverage);
      return done(ctx, META.ext, "pass", `extension loading was refused on ${per.length} tool(s)`, evidence, coverage);
    });

    // ---- sqlite-rowcap ----
    await run(META.rowcap, async () => {
      if (!readers.length) return noReaders(META.rowcap);
      const cap = setting(ctx, META.rowcap.id)?.row_cap ?? 10_000;
      const evidence: Evidence[] = [];
      const per: boolean[] = [];
      const skipped: { tool: string; reason: string }[] = [];
      for (const t of readers) {
        const s = await rig.ensure(t);
        const note = `${BIG_SELECT} (${SQLITE_BIG_ROWS.toLocaleString()} rows exist)`;
        const r = await s.call(t.name, argsFor(t, BIG_SELECT, "sm-probe"), 120_000);
        rig.validCalls++;
        const text = textOf(r);
        const rows = new Set(r.text.match(/row-\d+-end/g) ?? []).size;
        let ok: boolean | undefined;
        let outcome: string;
        if (noAnswer(r)) {
          ok = false;
          outcome = `response too large or connection dropped, so a cap could not be confirmed (${brief(r.rpcError || (r.timedOut ? "timed out" : "no answer"))})`;
        } else if (rows > cap) {
          ok = false;
          outcome = `${rows.toLocaleString()} row(s) came back (cap threshold ${cap.toLocaleString()})`;
        } else if (rows > 0) {
          ok = true;
          outcome = `${rows.toLocaleString()} row(s) came back, under the ${cap.toLocaleString()} threshold`;
        } else if (LIMIT_MSG.test(text)) {
          // Zero rows and a limit message is the server's own cap, whether it flagged the reply as an error or sent plain text.
          ok = true;
          outcome = `${sqliteRefused(r) ? "refused" : "answered with no rows"} as too large: ${brief(text)}`;
        } else if (sqliteRefused(r)) {
          ok = undefined;
          outcome = `the server refused the query with no recognizable limit message, so a cap cannot be measured (${brief(text)})`;
          skipped.push({ tool: t.name, reason: "the server refused the row-cap query" });
        } else {
          // Zero rows and nothing recognisable: a server that caps by replying in words the harness does not know looks the same as one that
          // returned nothing. That is not evidence of "no cap".
          ok = undefined;
          outcome = `no rows and no recognizable limit message, so a cap can be neither confirmed nor ruled out (${brief(text || "empty")})`;
          skipped.push({ tool: t.name, reason: "no rows and no recognisable limit message" });
        }
        if (ok !== undefined) per.push(ok);
        evidence.push(ev(t, BIG_SELECT, outcome, "response", { probe: note, code: ok === undefined ? "sqlite.rowcap.not-measured" : ok ? "sqlite.rowcap.capped" : "sqlite.rowcap.uncapped" }));
        if (noAnswer(r)) await rig.stop();
      }
      const coverage = cov(META.rowcap, readers, skipped);
      if (!per.length) return done(ctx, META.rowcap, "inconclusive", "a cap could not be measured on any tool: the server refused the row-cap query, or answered with no rows and no recognisable limit message", evidence, coverage);
      const v = aggregate(per);
      return done(ctx, META.rowcap, v, v === "pass" ? `no response carried more than ${cap.toLocaleString()} rows` : v === "part" ? "a cap held on some tools but not others" : "no row cap was in effect (see the evidence for what came back)", evidence, coverage);
    });

    // ---- sqlite-timeout ----
    await run(META.timeout, async () => {
      if (!readers.length) return noReaders(META.timeout);
      const expected = setting(ctx, META.timeout.id)?.expected_sec ?? ctx.timeoutProbeSec;
      const waitMs = (expected + 8) * 1000;
      const evidence: Evidence[] = [];
      const per: boolean[] = [];
      const skipped: { tool: string; reason: string }[] = [];
      type Outcome = { clean: boolean; text: string } | "refused";
      const judge = (r: CallResult): Outcome => {
        const secs = (r.elapsedMs / 1000).toFixed(1);
        if (r.closed) return { clean: false, text: `the server connection dropped after ${secs}s` };
        if (r.timedOut || r.elapsedMs >= waitMs) return { clean: false, text: `no query timeout within ${(waitMs / 1000).toFixed(0)} s (expected ${expected} s plus an 8 s margin); a server that cancels later than that is not seen: set --timeout-probe to its value` };
        if (r.elapsedMs >= 1000) return { clean: true, text: `query ended after ${secs}s (${brief(textOf(r), 80)})` };
        if (sqliteRefused(r)) return "refused";
        return { clean: false, text: `returned after ${secs}s with no error, so the query did not run as written` };
      };
      for (const t of readers) {
        try {
          await rig.fresh(t);
          let r = await rig.session!.call(t.name, argsFor(t, RUNAWAY, "sm-probe"), waitMs);
          rig.validCalls++;
          let sql = RUNAWAY;
          let j = judge(r);
          if (j === "refused") {
            evidence.push(ev(t, RUNAWAY, `refused before execution after ${(r.elapsedMs / 1000).toFixed(1)}s (${brief(textOf(r))}); trying a CPU-bound join instead`, "response"));
            await rig.fresh(t);
            r = await rig.session!.call(t.name, argsFor(t, RUNAWAY_JOIN, "sm-probe"), waitMs);
            rig.validCalls++;
            sql = RUNAWAY_JOIN;
            j = judge(r);
          }
          if (j === "refused") {
            skipped.push({ tool: t.name, reason: "not measured (the server refuses both the recursive series and a long join)" });
            evidence.push(ev(t, RUNAWAY_JOIN, `not measured: the server refuses both a long recursive series and a long join (${brief(textOf(r))})`, "response"));
          } else {
            per.push(j.clean);
            evidence.push(ev(t, sql, j.text, "response", { probe: `${sql} (${expected}s expectation)`, code: j.clean ? "sqlite.timeout.cancelled" : "sqlite.timeout.none" }));
          }
        } catch (e) {
          if (!(e instanceof Stopped)) throw e;
          per.push(false);
          evidence.push(ev(t, RUNAWAY, `could not run the timeout probe: ${e.message}`, "response"));
        } finally {
          await rig.stop();
        }
      }
      const coverage = cov(META.timeout, readers, skipped);
      if (!per.length) return done(ctx, META.timeout, "na", "not measured: the server refuses both the recursive series and a long join", evidence, coverage);
      const v = aggregate(per);
      return done(ctx, META.timeout, v, v === "pass" ? "a runaway query was cancelled on every tool" : v === "part" ? "a runaway query was cancelled on some tools but not others" : "a runaway query was not cancelled", evidence, coverage);
    });

    return out;
  } finally {
    await rig.stop().catch(() => {});
    // Leave the pristine fixture in place (later packs start the server with it) and take our files out of the canary directory.
    // After an interrupt the harness has already removed the sandbox (or is doing it), so there is nothing to put back and nothing may be recreated.
    if (!rig.gone) {
      try {
        await rig.restore();
      } catch {
        /* a locked file is reported by the sandbox teardown */
      }
      for (const p of [...rig.created, canaryDb, ...["-wal", "-shm", "-journal"].map((s) => canaryDb + s)]) rmSync(p, { force: true, maxRetries: 3, retryDelay: 200 });
      rmSync(pristineDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
    }
    log("done");
  }
}

// ---------------------------------------------------------------------------------------------------------
// describe(): the published corpus and thresholds
// ---------------------------------------------------------------------------------------------------------

const SINCE = "0.2-draft";

function describe(): CheckDoc[] {
  const base = {
    pack: "sqlite" as const,
    advisory: false,
    since: SINCE,
    status: "shipped" as const,
  };
  const duck = (id: string, text: string) => ({ id, text: `${text} (DuckDB; planned, not run in this release)`, kind: "duckdb-planned" });
  const mut = builtinCases().map((c) => ({ id: c.id, text: c.steps.join("  →  "), core: c.core, kind: c.core ? "core" : "indirect" }));
  const falseNegativeCommon = "Only the statement forms in the published corpus are tried; a server that blocks those and allows another form still passes. The engine's own configuration (compile options, authorizer) is not inspected.";
  return [
    {
      ...base,
      id: META.readonly.id,
      label: META.readonly.label,
      critical: false,
      scope: META.readonly.scope,
      verifiedBy: ["db-state", "response"],
      probes: [
        { id: "insert", text: "INSERT INTO probe_t (id, v) VALUES (9001, 'sm-insert')" },
        { id: "update", text: "UPDATE tenants SET name = 'sm-updated' WHERE id = 1" },
        { id: "delete", text: "DELETE FROM probe_t WHERE id = 9010" },
        { id: "engine-fingerprint", text: `${FINGERPRINT_SQL}  (once, before every sqlite check, through the first tool that answered a read: a 3.x.y answer confirms SQLite, another engine's answer makes every sqlite check inconclusive)` },
        { id: "ddl-control", text: "CREATE TABLE sm_ctl_<t> (x)  (the third control, for a tool whose SELECT and INSERT controls both failed; the table must appear in the fixture file)" },
      ],
      thresholds: {},
      falsePositive: "A tool declared as a writer is expected to write. The check reports it by name and says to exclude it under tools.exclude when writes are intended; it is still counted.",
      falseNegative: "Only three plain statements are tried on one table each. Roles and grants do not exist in SQLite, so row-level security and masking are not graded here.",
      configKeys: ["checks.sqlite-read-only.enabled", "checks.sqlite-read-only.severity", "tools.exclude"],
    },
    {
      ...base,
      id: META.mutating.id,
      label: META.mutating.label,
      critical: true,
      scope: META.mutating.scope,
      verifiedBy: ["db-state"],
      probes: mut,
      thresholds: {},
      falsePositive: "A server that deliberately offers a second tool for writes is judged on the read tool only; a write-capable tool declared as a writer is listed under not covered. PRAGMA writable_schema = 1 is excluded because it changes nothing without a following write.",
      falseNegative: falseNegativeCommon,
      configKeys: ["checks.sqlite-mutating-sql.enabled", "checks.sqlite-mutating-sql.severity", "checks.sqlite-mutating-sql.corpus.add", "checks.sqlite-mutating-sql.corpus.remove"],
    },
    {
      ...base,
      id: META.fileRead.id,
      label: META.fileRead.label,
      critical: true,
      scope: META.fileRead.scope,
      verifiedBy: ["response", "db-state"],
      probes: [
        { id: "attach-read", text: "ATTACH '{canary}/secret.db' AS s  →  SELECT v FROM s.secret" },
        { id: "attach-read-one-call", text: "ATTACH '{canary}/secret.db' AS s; SELECT v FROM s.secret  (one call: a fresh connection per call hides the two-call form)" },
        { id: "attach-copy-one-call", text: "ATTACH '{canary}/secret.db' AS s; CREATE TABLE sm_rd_<t> AS SELECT v FROM s.secret  (one call; sm_rd_<t> is read from the fixture file by the harness)" },
        { id: "attach-copy-two-calls", text: "ATTACH '{canary}/secret.db' AS s  →  CREATE TABLE sm_rd_<t> AS SELECT v FROM s.secret  (two calls; sm_rd_<t> is read from the fixture file by the harness)" },
        { id: "ddl-prefixed-copy", text: "CREATE TABLE sm_p_<t> (x); ATTACH '{canary}/secret.db' AS s; CREATE TABLE sm_rd_<t> AS SELECT v FROM s.secret  (a DDL-only tool, controlled through CREATE TABLE sm_ctl_<t> (x))" },
        duck("read-text", "SELECT content FROM read_text('{canary}/secret.txt')"),
        duck("read-csv", "SELECT * FROM read_csv('{canary}/secret.csv')"),
      ],
      thresholds: {},
      falsePositive:
        "None known for a tool that shows rows: the canary database is created by the harness and was never given to the server, so reading it means the server followed a path it chose. A declared writer tool is probed too. One that accepts the ATTACH but never returns rows is followed through the controlled reader on the same session, which is asked to read the attached database and to list its databases: the canary token through the reader is a fail (both tools are named); an alias the reader does not see (a fresh connection per call), or one it sees but refuses to read, is clean, with the reason in the evidence; with no controlled reader to ask, or a reader whose answer settles neither, the check is inconclusive, never a pass. The single-call and copy-into-the-fixture forms need no reader: the harness reads sm_rd_<t> from the fixture file, so a tool that returns no rows is still judged. A tool whose SELECT and INSERT controls both fail gets CREATE TABLE sm_ctl_<t> (x) as a third control, verified in the fixture, and is then probed behind a CREATE TABLE prefix. A SQL tool that answers none of the three controls is listed under not covered and the check is part at best, never a pass: a tool that could not be driven proves nothing when it refuses a probe. The check also needs the engine to be SQLite: after the first control read, SELECT sqlite_version() must answer 3.x.y; another engine's answer makes every sqlite check inconclusive, and a tool that refuses functions altogether proceeds with an 'engine not confirmed' note. A read through any one tool fails the check.",
      falseNegative: "A read-only connection does not stop ATTACH of an existing file (observed), so mode=ro alone fails this check. Only ATTACH forms are tried: a server that blocks them and reads files another way (extensions, DuckDB functions) is not caught.",
      configKeys: ["checks.sqlite-file-read.enabled", "checks.sqlite-file-read.severity", "checks.sqlite-file-read.corpus.add", "checks.sqlite-file-read.corpus.remove"],
    },
    {
      ...base,
      id: META.fileWrite.id,
      label: META.fileWrite.label,
      critical: true,
      scope: META.fileWrite.scope,
      verifiedBy: ["fs-observer"],
      probes: [
        { id: "vacuum-into", text: "VACUUM INTO '{canary}/vac-<t>.db'" },
        { id: "attach-new", text: "ATTACH '{canary}/att-<t>.db' AS a  →  CREATE TABLE a.t (x)" },
        { id: "attach-new-one-call", text: "ATTACH '{canary}/att1-<t>.db' AS a; CREATE TABLE a.t (x)  (one call)" },
        { id: "ddl-prefixed-vacuum", text: "CREATE TABLE sm_p_<t> (x); VACUUM INTO '{canary}/vac-<t>.db'  (a DDL-only tool, controlled through CREATE TABLE sm_ctl_<t> (x))" },
        { id: "ddl-prefixed-attach-new", text: "CREATE TABLE sm_p_<t> (x); ATTACH '{canary}/att-<t>.db' AS a; CREATE TABLE a.t (x)  (a DDL-only tool)" },
        duck("copy-to", "COPY (SELECT 1) TO '{canary}/c-<t>.csv'"),
        duck("export-database", "EXPORT DATABASE '{canary}/exp-<t>'"),
      ],
      thresholds: {},
      falsePositive:
        "A new or changed file in the canary directory is a write outside the database the server was given, so no false positive is known. -wal, -shm and -journal files next to the fixture are noted, never counted. A declared writer tool is probed like any other, because VACUUM INTO and ATTACH need no read control and the file observer decides; a tool whose SELECT and INSERT controls both fail is controlled through CREATE TABLE sm_ctl_<t> (x) (verified in the fixture) and probed behind a CREATE TABLE prefix. A SQL tool that failed every control (neither a control read nor a control write nor a control CREATE TABLE worked) is listed under not covered and the check is part at best, never a pass. A write through any one tool fails the check, however many other tools are clean.",
      falseNegative: "VACUUM INTO writes under a read-only connection (observed). Attaching a new file under a read-only connection failed in the engine used here, so that probe is an attempt, not an expectation.",
      configKeys: ["checks.sqlite-file-write.enabled", "checks.sqlite-file-write.severity", "checks.sqlite-file-write.corpus.add", "checks.sqlite-file-write.corpus.remove"],
    },
    {
      ...base,
      id: META.ext.id,
      label: META.ext.label,
      critical: true,
      scope: META.ext.scope,
      verifiedBy: ["response"],
      probes: [
        { id: "load-extension", text: "SELECT load_extension('{canary}/sm-ext')" },
        { id: "load-extension-writer-insert", text: "INSERT INTO probe_t (id, v) VALUES (9100, load_extension('{canary}/sm-ext'))  (a declared writer whose answer to the SELECT form said nothing about loading)" },
        { id: "load-extension-writer-update", text: "UPDATE probe_t SET v = load_extension('{canary}/sm-ext') WHERE id = 9010  (as above, when the INSERT form was also refused without a word about loading)" },
        { id: "load-extension-reader-where", text: "SELECT 1 WHERE load_extension('{canary}/sm-ext') IS NULL  (a reader whose answer to the SELECT form said nothing about loading)" },
        duck("load", "LOAD '{canary}/sm.duckdb_extension'"),
        duck("install", "INSTALL sm_nonexistent"),
      ],
      thresholds: {},
      falsePositive:
        "The verdict is read from the engine's own words, never from the fact that the call failed. A generic refusal (\"SELECT queries are not allowed\") is not a denial of loading, because the connection behind it may have loading enabled: the tool is then sent a form its role accepts (an INSERT or UPDATE for a writer, a SELECT with a WHERE for a reader). Only wording about loading counts as a denial (not authorized, load_extension disabled, no such function: load_extension, or not allowed, disabled, forbidden or unsupported next to the word extension or load). Wording the harness does not recognise, including a refusal of every form that never mentions loading, is reported as inconclusive, never as a pass. A server that returns a custom message for a real attempt could still be misread as refused only if that message also matches one of the denial phrases. A declared writer tool is probed like any other.",
      falseNegative: "A real extension is never shipped, so a successful load is not tested: the check observes whether the engine tried to open a library at a path the harness chose.",
      configKeys: ["checks.sqlite-extension-load.enabled", "checks.sqlite-extension-load.severity", "checks.sqlite-extension-load.corpus.add", "checks.sqlite-extension-load.corpus.remove"],
    },
    {
      ...base,
      id: META.rowcap.id,
      label: META.rowcap.label,
      critical: false,
      scope: META.rowcap.scope,
      verifiedBy: ["response"],
      probes: [{ id: "big-select", text: BIG_SELECT }],
      thresholds: { row_cap: { default: 10_000, configKey: "checks.sqlite-rowcap.row_cap", standardLocked: true } },
      falsePositive: "A server that returns a very large result by design is judged against the same published threshold as every other server.",
      falseNegative: "Rows are counted by the fixture's own row marker in the text; a server that returns a different shape for the same rows (a file reference, for example) is not measured. A reply with no rows and a limit message is a cap, whether or not the server flagged it as an error; a reply with no rows and no recognisable message is inconclusive, never a fail.",
      configKeys: ["checks.sqlite-rowcap.enabled", "checks.sqlite-rowcap.severity", "checks.sqlite-rowcap.row_cap"],
    },
    {
      ...base,
      id: META.timeout.id,
      label: META.timeout.label,
      critical: false,
      scope: META.timeout.scope,
      verifiedBy: ["response"],
      probes: [
        { id: "recursive-series", text: RUNAWAY },
        { id: "cross-join", text: `${RUNAWAY_JOIN} (used when the server refuses the recursive series)` },
      ],
      thresholds: { expected_sec: { default: 10, configKey: "checks.sqlite-timeout.expected_sec", standardLocked: true } },
      falsePositive: "A server that refuses both runaway forms is reported as not measured (n/a), never as a pass or a fail.",
      falseNegative: "The harness waits expected_sec + 8 seconds, so a timeout longer than that is reported as no timeout; set --timeout-probe to the server's own value. SQLite has no sleep function, so the probe is a CPU-bound query. A server that cancels only certain query shapes could pass.",
      configKeys: ["checks.sqlite-timeout.enabled", "checks.sqlite-timeout.severity", "checks.sqlite-timeout.expected_sec", "timeout_probe_sec"],
    },
  ];
}
