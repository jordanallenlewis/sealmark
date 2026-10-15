// The `sql-guard` pack: does a server that fronts a SQL backend keep its statement allowlist,
// its scope and its row cap, judged by what the harness-owned upstream stub received?
//
// There is no SQL parser here. Every statement carries a fresh token as an identifier (`sm_<tok>`) and as a literal
// (`'sm-<tok>'`); the verdict is "did that token reach the stub", the same model as the listener's `/t/<token>`. A server that
// refuses never forwards, so a refusal is a pass whatever its wording; a statement that arrives at the stub was let through.
//
// This is a candidate pack (design 5.4): scored inside its own pack, left off the badge, outside STANDARD_PACKS.
import { randomBytes } from "node:crypto";
import type { CallResult, McpSession } from "../mcp.js";
import type { ScopeSettings } from "../config/model.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, Pack, PackApplies, PackCtx, PackId, SqlTool, UpstreamMark, UpstreamRequest, UpstreamStub, Verdict } from "../types.js";
import {
  CONTROL_DEFAULT,
  CONTROL_SCOPED,
  DEFAULT_ROW_CAP,
  HUGE_LIMIT,
  REFERENCE_CORPUS,
  STATEMENT_CORPUS,
  effectiveLimit,
  forwardedSql,
  namesFor,
  render,
  type CorpusEntry,
  type Names,
} from "./sql-guard-corpus.js";
import { NO_SQL_TOOL, NO_UPSTREAM_STUB, callSql, discoverSqlTools, enrichSqlTools, head, refused, sqlArgsFor } from "./shared.js";

const PACK: PackId = "sql-guard";
const UPSTREAM: Evidence["verifiedBy"] = "upstream";
const SINCE = "0.3-draft";

const scopeOf = (ctx: PackCtx): Partial<Pick<ScopeSettings, "allow" | "separator">> => ctx.config.scope ?? {};

/** How long the harness waits after the last probe for a forwarder that answers before it forwards. Test hook. */
export const SETTLE_MS = { value: 150 };

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

const SCOPE = "server (judged by what reached the harness's upstream stub, not by the server's reply; no SQL is parsed)";

const META = {
  statements: { id: "sql-guard-statements", label: "SQL guard: only read statements reach the backend", critical: true, scope: SCOPE },
  references: { id: "sql-guard-references", label: "SQL guard: out-of-scope references blocked in every position", critical: true, scope: SCOPE },
  rowcap: { id: "sql-guard-rowcap", label: "SQL guard: row cap applied before the backend", critical: false, scope: `${SCOPE}; read from the forwarded text, a heuristic` },
} satisfies Record<string, Meta>;

const ALL_META: Meta[] = Object.values(META);

const NO_STUB = NO_UPSTREAM_STUB;
const NO_SQL = NO_SQL_TOOL;
const NO_ALLOW = "no scope.allow: list the identifiers the server may serve (set scope.allow, an entry ending in \".\" is a prefix) so there is an out-of-scope name to reach for";
const RATE_NOTE = "the cap may be applied to the reply instead: write a probe with `upstream.reply` rows and `expect.upstream.token_echoed` to test it";

const setting = (ctx: PackCtx, id: string) => ctx.config.checks?.[id];
/** `checks.<id>.severity` overrides how a check counts; `enabled: false` removes it (reported n/a). */
function metaFor(ctx: PackCtx, m: Meta): Meta {
  const sev = setting(ctx, m.id)?.severity;
  if (!sev) return m;
  return { ...m, critical: sev === "critical", advisory: sev === "advisory" ? true : undefined };
}
const isOff = (ctx: PackCtx, m: Meta) => setting(ctx, m.id)?.enabled === false;

function done(ctx: PackCtx, m: Meta, verdict: Verdict, summary: string, evidence: Evidence[], coverage?: CheckCoverage): CheckResult {
  return { ...metaFor(ctx, m), pack: PACK, verdict, summary, evidence, ...(coverage ? { coverage } : {}) };
}

// ---------------------------------------------------------------------------------------------------------
// Which tools, and what the harness sends
// ---------------------------------------------------------------------------------------------------------

/** SQL tools: the shared discovery (detection plus `sql_tools`), plus any tool the classifier called SQL above low confidence. */
function sqlToolsFor(ctx: PackCtx): { tools: SqlTool[]; writers: string[] } {
  const found = new Map<string, SqlTool>();
  for (const st of discoverSqlTools(ctx.tools ?? [], ctx.sqlTools).tools) found.set(st.tool, st);
  // Excluded tools, and tools `tools.overrides` gives a class other than sql (the override wins over name-based detection).
  const excluded = new Set((ctx.classification ?? []).filter((c) => c.excluded || (c.source === "override" && c.class !== "sql")).map((c) => c.tool));
  for (const cls of ctx.classification ?? []) {
    if (cls.class !== "sql" || cls.confidence === "low" || cls.excluded || !cls.params.sql || found.has(cls.tool)) continue;
    const given = ctx.sqlTools?.find((s) => s.tool === cls.tool);
    found.set(cls.tool, { tool: cls.tool, arg: cls.params.sql, ...(given?.args ? { args: given.args } : {}) });
  }
  const all = enrichSqlTools([...found.values()].filter((s) => !excluded.has(s.tool)), ctx.tools ?? []);
  return { tools: all.filter((s) => s.role !== "writer"), writers: all.filter((s) => s.role === "writer").map((s) => s.tool) };
}

const tokenOf = () => randomBytes(4).toString("hex");
const noAnswer = (r: CallResult) => r.closed || r.timedOut;
const brief = (s: string, n = 140) => s.replace(/\s+/g, " ").trim().slice(0, n);

/** A reply that says the arguments were wrong: the server did not run the statement, so the call exercised nothing. */
function validationError(r: CallResult, st: SqlTool): boolean {
  if (r.rpcError !== undefined && /-32602|invalid params/i.test(r.rpcError)) return true;
  return r.isError && new RegExp(`${st.arg}|param|argument`, "i").test(r.text) && /invalid|expected|required|missing/i.test(r.text);
}

// ---------------------------------------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------------------------------------

interface Probe {
  family: "control" | "statement" | "reference" | "rowcap";
  id: string;
  nearMiss: boolean;
  sql: string;
  token: string;
  args: Record<string, unknown>;
  /** undefined: not sent (the session had already gone away). */
  reply?: CallResult;
  reached: UpstreamRequest[];
}

interface ToolRun {
  st: SqlTool;
  control?: Probe;
  probes: Probe[];
  /** Why the tool could not be judged (control did not reach, session lost). */
  why?: string;
}

const needles = (token: string): string[] => [`sm-${token}`, `sm_${token}`];
function reachedBy(up: UpstreamStub, token: string, since: UpstreamMark): UpstreamRequest[] {
  const seen = new Map<number, UpstreamRequest>();
  for (const n of needles(token)) for (const r of up.find(n, since)) seen.set(r.id, r);
  return [...seen.values()];
}

function controlTemplate(ctx: PackCtx, exactAllow: string | undefined): string {
  const given = setting(ctx, META.statements.id)?.control_sql;
  if (typeof given === "string" && given.trim()) return given;
  return exactAllow !== undefined ? CONTROL_SCOPED : CONTROL_DEFAULT;
}

async function send(session: McpSession, st: SqlTool, timeoutMs: number, family: Probe["family"], entry: { id: string; nearMiss?: boolean }, sql: string, token: string): Promise<Probe> {
  const reply = await callSql(session, st, sql, timeoutMs);
  return { family, id: entry.id, nearMiss: entry.nearMiss === true, sql, token, args: sqlArgsFor(st, sql), reply, reached: [] };
}

async function runTool(ctx: PackCtx, up: UpstreamStub, session: McpSession, st: SqlTool): Promise<ToolRun> {
  const scope = scopeOf(ctx);
  const sep = scope.separator || ".";
  const allow = scope.allow ?? [];
  const exact = allow.find((a) => !a.endsWith(sep));
  const timeoutMs = ctx.timeoutProbeSec * 1000;
  const run: ToolRun = { st, probes: [] };
  const names = (token: string): Names => namesFor(allow, sep, token);

  // 1. The control: a plain read must get through, or nothing below means anything.
  const ctlToken = tokenOf();
  const tpl = controlTemplate(ctx, exact);
  const ctlSql = render(tpl, ctlToken, names(ctlToken));
  const mark = up.mark();
  const control = await send(session, st, timeoutMs, "control", { id: "control" }, ctlSql, ctlToken);
  run.control = control;
  const arrived = noAnswer(control.reply!) ? reachedBy(up, ctlToken, mark) : await waitForToken(up, ctlToken, Math.min(2000, timeoutMs), mark);
  control.reached = arrived;
  if (!arrived.length) {
    const r = control.reply!;
    run.why = noAnswer(r)
      ? `the control statement got no answer (${r.timedOut ? "timed out" : "the server closed the connection"})`
      : `the control statement never reached the upstream (${refused(r) ? "refused" : "answered without forwarding"}: ${brief(r.text || r.rpcError || "empty reply", 100)})`;
    return run;
  }

  // 2. The corpora, then one settle, then judge by token. Each probe has its own token so a hit maps back to it.
  const probes: Probe[] = [];
  let lost = false;
  const mine = async (family: Probe["family"], entry: { id: string; nearMiss?: boolean }, sql: (token: string, n: Names) => string): Promise<void> => {
    if (lost || ctx.interrupted?.()) return;
    const token = tokenOf();
    const p = await send(session, st, timeoutMs, family, entry, sql(token, names(token)), token);
    if (p.reply!.closed) lost = true;
    probes.push(p);
  };
  for (const e of STATEMENT_CORPUS) await mine("statement", e, (t, n) => render(e.sql, t, n));
  if (allow.length) for (const e of REFERENCE_CORPUS) await mine("reference", e, (t, n) => render(e.sql, t, n));
  // The row-cap probe: the control statement with a huge client LIMIT appended (skipped when the control already carries a limit of its own).
  if (effectiveLimit(ctlSql) === null) {
    await mine("rowcap", { id: "huge-limit" }, (t, n) => `${render(tpl, t, n).replace(/[\s;]+$/, "")} LIMIT ${HUGE_LIMIT}`);
  }
  if (SETTLE_MS.value > 0) await new Promise((r) => setTimeout(r, SETTLE_MS.value));
  const since = mark;
  for (const p of probes) p.reached = reachedBy(up, p.token, since);
  run.probes = probes;
  if (lost) run.why = "the server closed the connection part-way, so later probes were not sent";
  return run;
}

async function waitForToken(up: UpstreamStub, token: string, timeoutMs: number, since: UpstreamMark): Promise<UpstreamRequest[]> {
  for (const n of needles(token)) {
    const hit = await up.waitFor(n, timeoutMs, since);
    if (hit.length) return hit;
  }
  return reachedBy(up, token, since);
}

// ---------------------------------------------------------------------------------------------------------
// Evidence and verdicts
// ---------------------------------------------------------------------------------------------------------

const label = (p: Probe) => `${p.family} ${p.id}`;

function evidenceFor(st: SqlTool, p: Probe): Evidence {
  const base = { probe: `${label(p)}: ${p.sql}`, verifiedBy: UPSTREAM, tool: st.tool, args: p.args };
  const r = p.reply;
  if (!r) return { ...base, outcome: "not sent: the server had stopped answering", code: "sql-guard.unjudged" };
  if (p.reached.length) {
    const q = p.reached[0]!;
    const text = forwardedSql(q, `sm_${p.token}`);
    const allowed = p.nearMiss ? "reached the upstream (allowed: it is valid SQL, not a leak)" : p.family === "control" ? "reached the upstream" : "reached the upstream: the guard let it through";
    return { ...base, outcome: `${allowed} as ${q.method} ${q.path}`, excerpt: text.slice(0, 4096), code: p.family === "control" ? "sql-guard.control" : p.nearMiss ? "sql-guard.near-miss" : "sql-guard.reached" };
  }
  if (noAnswer(r)) return { ...base, outcome: r.timedOut ? "no answer before the probe timeout; nothing reached the upstream" : "the server closed the connection; nothing reached the upstream", code: "sql-guard.unjudged" };
  if (refused(r)) return { ...base, outcome: `refused: ${brief(head(r.text || r.rpcError || ""), 120)}`, excerpt: (r.text || r.rpcError || "").slice(0, 4096), code: "sql-guard.refused" };
  return { ...base, outcome: `answered without forwarding anything to the upstream: ${brief(r.text, 120)}`, excerpt: r.text.slice(0, 4096), code: "sql-guard.not-forwarded" };
}

const unjudged = (p: Probe): boolean => p.reached.length === 0 && (p.reply === undefined || noAnswer(p.reply));
const leaked = (p: Probe): boolean => p.reached.length > 0 && !p.nearMiss;

/** Valid calls: the control (it got through) plus each probe the server processed (not a validation error, not unanswered). */
function coverageOf(runs: ToolRun[], family: Probe["family"][]): CheckCoverage {
  const controlled = runs.filter((r) => !r.why || r.probes.length);
  let valid = 0;
  const notCovered: CheckCoverage["notCovered"] = [];
  for (const r of runs) {
    if (!r.control?.reached.length) {
      notCovered.push({ tool: r.st.tool, reason: r.why ?? "the control did not reach the upstream" });
      continue;
    }
    valid += 1;
    for (const p of r.probes) if (family.includes(p.family) && p.reply && !noAnswer(p.reply) && !validationError(p.reply, r.st)) valid += 1;
  }
  return { probed: controlled.filter((r) => r.control?.reached.length).map((r) => r.st.tool), notCovered, validCalls: valid };
}

function noControl(ctx: PackCtx, m: Meta, runs: ToolRun[]): CheckResult {
  const why = runs.map((r) => `${r.st.tool}: ${r.why ?? "control did not reach the upstream"}`).join("; ");
  return done(ctx, m, "inconclusive", `no control statement reached the upstream, so nothing can be judged (${why}). If the server refuses every call, check scope.allow, sql_tools[].args and the credentials it needs`, runs.flatMap((r) => (r.control ? [evidenceFor(r.st, r.control)] : [])), coverageOf(runs, []));
}

function corpusCheck(ctx: PackCtx, m: Meta, runs: ToolRun[], family: "statement" | "reference", noun: string): CheckResult {
  if (!runs.some((r) => r.control?.reached.length)) return noControl(ctx, m, runs);
  const judgedRuns = runs.filter((r) => r.control?.reached.length);
  const probes = judgedRuns.flatMap((r) => r.probes.filter((p) => p.family === family).map((p) => ({ r, p })));
  const leaks = probes.filter(({ p }) => leaked(p));
  const unj = probes.filter(({ p }) => unjudged(p));
  const evidence: Evidence[] = [
    ...judgedRuns.map((r) => evidenceFor(r.st, r.control!)),
    ...leaks.map(({ r, p }) => evidenceFor(r.st, p)),
    ...probes.filter(({ p }) => !leaked(p)).map(({ r, p }) => evidenceFor(r.st, p)),
  ];
  const coverage = coverageOf(runs, [family]);
  const total = probes.length;
  const note = [unj.length ? `${unj.length} unjudged (no answer)` : "", runs.some((r) => r.why && r.control?.reached.length) ? runs.find((r) => r.why && r.control?.reached.length)!.why : ""].filter(Boolean).join("; ");
  if (leaks.length) {
    const ids = [...new Set(leaks.map(({ p }) => p.id))];
    return done(ctx, m, "fail", `${leaks.length} of ${total} ${noun} reached the upstream: ${ids.join(", ")}${note ? ` (${note})` : ""}`, evidence, coverage);
  }
  if (total - unj.length === 0) return done(ctx, m, "inconclusive", `every ${noun.replace(/s$/, "")} probe went unanswered, so the guard could not be judged${note ? ` (${note})` : ""}`, evidence, coverage);
  return done(ctx, m, "pass", `${total - unj.length} ${noun} sent, none reached the upstream; the control did${note ? ` (${note})` : ""}`, evidence, coverage);
}

function rowcapCheck(ctx: PackCtx, m: Meta, runs: ToolRun[]): CheckResult {
  if (!runs.some((r) => r.control?.reached.length)) return noControl(ctx, m, runs);
  const cap = Number(setting(ctx, m.id)?.row_cap ?? DEFAULT_ROW_CAP);
  const evidence: Evidence[] = [];
  const verdicts: ("pass" | "part" | "fail")[] = [];
  const lines: string[] = [];
  for (const r of runs.filter((x) => x.control?.reached.length)) {
    const ctl = r.control!;
    const huge = r.probes.find((p) => p.family === "rowcap");
    const eCtl = effectiveLimit(forwardedSql(ctl.reached[0]!, `sm_${ctl.token}`));
    const eHuge = huge?.reached.length ? effectiveLimit(forwardedSql(huge.reached[0]!, `sm_${huge.token}`)) : undefined;
    let v: "pass" | "part" | "fail";
    let what: string;
    if (typeof eHuge === "number") {
      v = eHuge <= cap ? "pass" : "fail";
      what = eHuge <= cap ? `a client LIMIT ${HUGE_LIMIT} reached the upstream as ${eHuge} (cap ${cap})` : `a client LIMIT ${HUGE_LIMIT} was forwarded as ${eHuge}, above the cap of ${cap}`;
    } else if (typeof eCtl === "number") {
      v = eCtl <= cap ? "pass" : "fail";
      what = `the control carried a limit of ${eCtl} at the wire (cap ${cap})${huge && !huge.reached.length ? "; the huge-limit probe was not forwarded" : ""}`;
    } else {
      v = "part";
      what = `no LIMIT, FETCH FIRST or TOP at the wire; ${RATE_NOTE}`;
    }
    verdicts.push(v);
    lines.push(`${r.st.tool}: ${what}`);
    evidence.push({ ...evidenceFor(r.st, ctl), outcome: `${evidenceFor(r.st, ctl).outcome}; limit at the wire: ${eCtl ?? "none"}` });
    if (huge) evidence.push({ ...evidenceFor(r.st, huge), code: "sql-guard.rowcap", outcome: huge.reached.length ? `forwarded with limit ${eHuge ?? "none"}` : evidenceFor(r.st, huge).outcome });
  }
  const verdict: Verdict = verdicts.includes("fail") ? "fail" : verdicts.includes("part") ? "part" : "pass";
  return done(ctx, m, verdict, lines.join("; "), evidence, coverageOf(runs, ["rowcap"]));
}

// ---------------------------------------------------------------------------------------------------------
// The pack
// ---------------------------------------------------------------------------------------------------------

function applies(ctx: PackCtx): PackApplies {
  if (!sqlToolsFor(ctx).tools.length) return { ok: false, reason: NO_SQL };
  if (!ctx.upstream) return { ok: false, reason: NO_STUB };
  return { ok: true };
}

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const up = ctx.upstream;
  const { tools, writers } = sqlToolsFor(ctx);
  const off = (m: Meta) => isOff(ctx, m);
  const disabled = (m: Meta) => done(ctx, m, "na", "disabled by config", []);
  if (!up) return ALL_META.map((m) => (off(m) ? disabled(m) : done(ctx, m, "inconclusive", NO_STUB, [])));
  if (!tools.length) return ALL_META.map((m) => (off(m) ? disabled(m) : done(ctx, m, "na", writers.length ? `${NO_SQL} that is not declared as a writer (${writers.join(", ")})` : NO_SQL, [])));
  const hasAllow = (scopeOf(ctx).allow ?? []).length > 0;

  const runs: ToolRun[] = [];
  let session: McpSession | undefined;
  try {
    session = await ctx.open();
    for (const st of tools) {
      if (ctx.interrupted?.()) break;
      runs.push(await runTool(ctx, up, session, st));
    }
  } catch (e) {
    const why = `could not run the probes: ${brief(e instanceof Error ? e.message : String(e), 160)}`;
    return ALL_META.map((m) => (off(m) ? disabled(m) : done(ctx, m, "inconclusive", why, [])));
  } finally {
    await session?.close().catch(() => undefined);
  }

  const writerNote = writers.length ? `; not probed (declared as writers): ${writers.join(", ")}` : "";
  const withNote = (r: CheckResult): CheckResult => (writerNote && r.verdict !== "na" ? { ...r, summary: `${r.summary}${writerNote}` } : r);
  return [
    off(META.statements) ? disabled(META.statements) : withNote(corpusCheck(ctx, META.statements, runs, "statement", "corpus statements")),
    off(META.references) ? disabled(META.references) : hasAllow ? withNote(corpusCheck(ctx, META.references, runs, "reference", "out-of-scope references")) : done(ctx, META.references, "na", NO_ALLOW, []),
    off(META.rowcap) ? disabled(META.rowcap) : withNote(rowcapCheck(ctx, META.rowcap, runs)),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// describe
// ---------------------------------------------------------------------------------------------------------

const FAMILIES: Record<string, string> = {
  insert: "writes", update: "writes", delete: "writes", merge: "writes", create: "DDL", drop: "DDL", alter: "DDL", truncate: "DDL", grant: "privileges",
  vacuum: "maintenance", analyze: "maintenance", "set-session": "session state", copy: "file access", stacked: "multiple statements",
  "cte-dml": "DML hidden in a CTE", "explain-analyze-write": "EXPLAIN ANALYZE of a write", obfuscated: "mixed case and a leading comment",
  terminator: "transaction words then a write", unparseable: "unparseable input", unbalanced: "unbalanced quote", "comment-hidden": "near miss: hostile text inside a comment is allowed to reach",
};

function describe(): CheckDoc[] {
  const base = { pack: PACK, advisory: false, since: SINCE, status: "shipped" as const, verifiedBy: [UPSTREAM] };
  const entries = (list: readonly CorpusEntry[], kind: string) => list.map((e) => ({ id: e.id, text: e.sql, kind: e.nearMiss ? "near-miss" : kind }));
  return [
    {
      ...base,
      id: META.statements.id,
      label: META.statements.label,
      critical: true,
      scope: META.statements.scope,
      probes: [
        { id: "control", text: `${CONTROL_SCOPED}  (with no exact scope.allow entry: ${CONTROL_DEFAULT}; override with checks.sql-guard-statements.control_sql); it must reach the upstream, else the check is inconclusive`, core: true, kind: "control" },
        ...STATEMENT_CORPUS.map((e) => ({ id: e.id, text: `${e.sql}  (${FAMILIES[e.id] ?? "statement"}${e.nearMiss ? "" : "; must not reach the upstream"})`, kind: e.nearMiss ? "near-miss" : "statement" })),
      ],
      thresholds: {},
      falsePositive: "A server that deliberately offers a write tool is not probed through it (a tool declared as a writer is listed as not covered). The comment-hidden near miss is allowed to reach and never counts.",
      falseNegative: "Only the statement forms in the published corpus are tried; a guard that blocks those and passes another form still passes. A server that answers from a cache, or never forwards, shows nothing at the stub.",
      configKeys: ["checks.sql-guard-statements.enabled", "checks.sql-guard-statements.severity", "checks.sql-guard-statements.control_sql", "sql_tools", "upstream.kind"],
    },
    {
      ...base,
      id: META.references.id,
      label: META.references.label,
      critical: true,
      scope: META.references.scope,
      probes: entries(REFERENCE_CORPUS, "reference").map((e) => ({ ...e, text: `${e.text}  ({a} an in-scope name, {o} <container of scope.allow[0]>.outside_sm_<token>; must not reach the upstream)` })),
      thresholds: {},
      falsePositive: "None known: an out-of-scope name that reaches the upstream was let through whatever the server intended.",
      falseNegative: "Only the reference positions in the published corpus are tried, against one out-of-scope name per probe. Not applicable (n/a) without scope.allow.",
      configKeys: ["checks.sql-guard-references.enabled", "checks.sql-guard-references.severity", "scope.allow", "scope.separator", "sql_tools", "upstream.kind"],
    },
    {
      ...base,
      id: META.rowcap.id,
      label: META.rowcap.label,
      critical: false,
      scope: META.rowcap.scope,
      probes: [
        { id: "control", text: "the control statement of sql-guard-statements; the limit written in what the upstream received (LIMIT n, FETCH FIRST n ROWS ONLY, TOP n; the outermost level, the smallest value) must be at most the cap", core: true, kind: "control" },
        { id: "huge-limit", text: `<control statement> LIMIT ${HUGE_LIMIT}  (forwarded as written is a fail)`, kind: "statement" },
      ],
      thresholds: { row_cap: { default: DEFAULT_ROW_CAP, configKey: "checks.sql-guard-rowcap.row_cap", standardLocked: false } },
      falsePositive: "A server that caps the reply instead of the query (rows dropped after the backend answered) shows no limit at the wire and reads as part, not fail; the evidence says how to test that with a probe.",
      falseNegative: "The limit is read with a regex over the forwarded text; a dialect that spells it another way reads as no cap.",
      configKeys: ["checks.sql-guard-rowcap.enabled", "checks.sql-guard-rowcap.severity", "checks.sql-guard-rowcap.row_cap", "upstream.kind"],
    },
  ];
}

export const pack: Pack = { id: PACK, describe, applies, run };
export default pack;

// Exported for the tests of this package.
export { sqlToolsFor, validationError };
