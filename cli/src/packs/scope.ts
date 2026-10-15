import { randomBytes } from "node:crypto";
import { fillArgs } from "../classify.js";
import { rejectedBeforeRunning, type CallResult, type ToolInfo } from "../mcp.js";
import type { ScopeSettings } from "../config/model.js";
import type { CheckDoc, CheckResult, Evidence, Pack, PackApplies, PackCtx, PackId, ToolClassification, VerifiedBy } from "../types.js";
import { Sessions, Tally, metaFor, oneLine, result, type Meta } from "./fs.js";
import { excerpt, explicitArgs, refused } from "./shared.js";

/**
 * The `scope` pack, a candidate pack: it runs when `scope.tools` is declared and is scored inside its own pack,
 * off the badge. One critical check, `scope-escape`: a tool that takes an identifier (a table, a dataset, a path inside a catalog) must refuse
 * every identifier outside `scope.allow`, whatever the spelling. With an upstream stub the verdict is "did the identifier reach the backend";
 * without one it rests on the reply alone.
 */

const SINCE = "0.3-draft";
const PACK: PackId = "scope";
const PROBE_MS_FLOOR = 5000;
/** How long to wait for a request the server forwards just after it replied. */
const SETTLE_MS = 40;

// ---------------------------------------------------------------------------------------------------------
// Declared scope (`EffectiveConfig.scope`, with the defaults applied for a configuration built by hand)
// ---------------------------------------------------------------------------------------------------------

/** `scope:` (config/model.ts): an entry of `allow` or `deny` that ends with `separator` is a prefix (`sales.public.`), any other is exact; deny wins. */
export type { ScopeSettings };

export function readScope(config: { scope?: Partial<ScopeSettings> } | undefined): ScopeSettings {
  const raw: Partial<ScopeSettings> = config?.scope ?? {};
  const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : []);
  return {
    tools: Array.isArray(raw.tools) ? raw.tools.filter((t) => t && typeof t.tool === "string" && typeof t.param === "string") : [],
    allow: strs(raw.allow),
    deny: strs(raw.deny),
    separator: typeof raw.separator === "string" && raw.separator.length ? raw.separator : ".",
    case: raw.case === "sensitive" ? "sensitive" : "insensitive",
  };
}

// ---------------------------------------------------------------------------------------------------------
// The reference rule and the corpus (pure)
// ---------------------------------------------------------------------------------------------------------

const isPrefix = (entry: string, sep: string): boolean => entry.endsWith(sep);
const fold = (s: string, mode: ScopeSettings["case"]): string => (mode === "insensitive" ? s.toLowerCase() : s);

/**
 * The harness's own reading of "in scope", used only to prove that every generated escape is outside it (the server decides for itself).
 * A plain name (no quotes, whitespace, `..`, percent signs or a path separator other than the declared one) that matches an allow entry
 * (exact, or by prefix when the entry ends in the separator) and no deny entry. Anything with a quote, an encoding or a traversal in it is out of
 * scope by form: a server that resolves it to an allowed name is doing the very normalisation the corpus probes.
 */
export function inScope(identifier: string, s: Pick<ScopeSettings, "allow" | "deny" | "separator" | "case">, mode: ScopeSettings["case"] = s.case): boolean {
  if (/["'`\s%]|\.\./.test(identifier)) return false;
  if (s.separator !== "/" && identifier.includes("/")) return false;
  if (s.separator !== "\\" && identifier.includes("\\")) return false;
  const id = fold(identifier, mode);
  const hit = (entry: string): boolean => {
    const e = fold(entry, mode);
    return isPrefix(entry, s.separator) ? id.startsWith(e) : id === e;
  };
  if (s.deny.some(hit)) return false;
  return s.allow.some(hit);
}

export interface ScopeProbe {
  /** Family id (`sibling`, `container`, ...); a second identifier of the same family is `container#2`. */
  id: string;
  family: string;
  identifier: string;
  /** The text a stub request carries when the identifier reached the backend: the fresh token when there is one, else the identifier. */
  needle: string;
}

export const SCOPE_FAMILIES: { id: string; text: string }[] = [
  { id: "sibling", text: "<exact allow entry>_sm<tok>, a name next to an allowed one (sales.public.orders_sm<tok>)" },
  { id: "container", text: "the bare containers of an allowed name (sales.public, then sales)" },
  { id: "partial", text: "an allowed name cut short (sales.public.ord)" },
  { id: "prefix-abuse", text: "a prefix compared without its separator (sales.publicx.t_sm<tok>); for an exact entry the entry plus x (sales.public.ordersx)" },
  { id: "case", text: "the sibling in upper case (out of scope under either case rule)" },
  { id: "quoted", text: 'quoted segments ("sales"."public"."outside_sm<tok>")' },
  { id: "separator-encoded", text: "the separator percent-encoded or replaced (sales%2Epublic%2Eoutside_sm<tok>, sales/public/outside_sm<tok>)" },
  { id: "traversal", text: "dot-dot spellings (sales.public.orders.._sm<tok>, sales.public.orders/../outside_sm<tok>)" },
  { id: "deny", text: "every scope.deny entry as written" },
  { id: "case-control", text: "control, case: insensitive only: the upper-case spelling of an allowed name (SALES.PUBLIC.ORDERS) is expected to be accepted; a refusal is noted, never a fail" },
];

const randomToken = (): string => randomBytes(3).toString("hex");

const segments = (s: string, sep: string): string[] => s.split(sep).filter((x) => x.length);

/**
 * The out-of-scope identifiers for one tool: one probe per family per allow form, each on a fresh identifier (`mkTok` is called once per probe) so
 * a stub observation maps back to its probe. Every identifier is checked against `inScope` under both case rules and dropped when it
 * is in scope (a prefix entry makes `<prefix>x` an allowed name, so such a form is not an escape for that entry).
 */
export function scopeCorpus(s: Pick<ScopeSettings, "allow" | "deny" | "separator" | "case">, mkTok: () => string = randomToken): ScopeProbe[] {
  const sep = s.separator;
  const exact = s.allow.find((e) => !isPrefix(e, sep));
  const prefix = s.allow.find((e) => isPrefix(e, sep));
  const out: ScopeProbe[] = [];
  const counts = new Map<string, number>();
  const add = (family: string, identifier: string, tok?: string): boolean => {
    for (const mode of ["sensitive", "insensitive"] as const) if (inScope(identifier, { ...s, case: mode }, mode)) return false;
    if (out.some((p) => p.identifier === identifier)) return false;
    const n = (counts.get(family) ?? 0) + 1;
    counts.set(family, n);
    out.push({ id: n === 1 ? family : `${family}#${n}`, family, identifier, needle: tok ? `sm${tok}` : identifier });
    return true;
  };
  // The container a probe is aimed at: the parent of the exact entry, or the prefix without its trailing separator.
  const bare = prefix !== undefined ? prefix.slice(0, prefix.length - sep.length) : exact !== undefined ? exact.split(sep).slice(0, -1).join(sep) : "";
  const parentSegs = segments(bare, sep);
  const base = exact ?? (prefix !== undefined ? `${prefix}sm_base` : undefined);

  if (exact !== undefined) {
    const t = mkTok();
    add("sibling", `${exact}_sm${t}`, t);
  }
  // Containers: each proper ancestor of the allowed name, nearest first.
  const ancestors: string[] = [];
  const start = prefix !== undefined && exact === undefined ? segments(bare, sep) : segments(exact ?? "", sep).slice(0, -1);
  for (let n = start.length; n >= 1; n--) ancestors.push(start.slice(0, n).join(sep));
  for (const a of ancestors) add("container", a);
  if (exact !== undefined) {
    const parts = segments(exact, sep);
    const last = parts[parts.length - 1] ?? "";
    if (last.length >= 2) add("partial", [...parts.slice(0, -1), last.slice(0, Math.max(1, Math.floor(last.length / 2)))].join(sep));
  } else if (prefix !== undefined) {
    const last = parentSegs[parentSegs.length - 1] ?? "";
    if (last.length >= 2) add("partial", [...parentSegs.slice(0, -1), last.slice(0, Math.max(1, Math.floor(last.length / 2)))].join(sep));
  }
  if (exact !== undefined) add("prefix-abuse", `${exact}x`);
  if (prefix !== undefined) {
    const t = mkTok();
    add("prefix-abuse", `${prefix.slice(0, prefix.length - sep.length)}x${sep}t_sm${t}`, t);
  }
  {
    // The sibling in upper case; when a prefix entry makes that sibling an allowed name, the prefix-abuse form in upper case.
    const t = mkTok();
    const forms = [exact !== undefined ? `${exact}_sm${t}` : undefined, prefix !== undefined ? `${prefix.slice(0, prefix.length - sep.length)}x${sep}t_sm${t}` : undefined];
    for (const f of forms) if (f !== undefined && add("case", f.toUpperCase(), t)) break;
  }
  if (base !== undefined) {
    const t = mkTok();
    add("quoted", `"${[...parentSegs, `outside_sm${t}`].join(`"${sep}"`)}"`, t);
    const t2 = mkTok();
    const encoded = `%${sep.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`;
    add("separator-encoded", [...parentSegs, `outside_sm${t2}`].join(encoded), t2);
    const t3 = mkTok();
    const alt = sep === "/" ? "\\" : "/";
    add("separator-encoded", [...parentSegs, `outside_sm${t3}`].join(alt), t3);
    const t4 = mkTok();
    add("traversal", `${base}.._sm${t4}`, t4);
    const t5 = mkTok();
    add("traversal", `${base}/../outside_sm${t5}`, t5);
  }
  for (const d of s.deny) add("deny", d);
  return out;
}

/** Identifiers that must be accepted before an escape probe means anything: up to three exact allow entries, else one name under the first prefix. */
export function controlIdentifiers(s: Pick<ScopeSettings, "allow" | "separator">, mkTok: () => string = randomToken): { identifier: string; needle: string }[] {
  const exact = s.allow.filter((e) => !isPrefix(e, s.separator)).slice(0, 3);
  if (exact.length) return exact.map((e) => ({ identifier: e, needle: e }));
  const prefix = s.allow.find((e) => isPrefix(e, s.separator));
  if (!prefix) return [];
  const t = mkTok();
  return [{ identifier: `${prefix}sm_control_${t}`, needle: `sm_control_${t}` }];
}

/** The upper-case spelling of the first exact entry, when it differs; a server declared case-insensitive is expected to accept it. */
export function caseControl(s: Pick<ScopeSettings, "allow" | "separator" | "case">): string | undefined {
  if (s.case !== "insensitive") return undefined;
  const e = s.allow.find((x) => !isPrefix(x, s.separator));
  return e !== undefined && e.toUpperCase() !== e ? e.toUpperCase() : undefined;
}

// ---------------------------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------------------------

export const SCOPE_META: Record<string, Meta> = {
  "scope-escape": { id: "scope-escape", label: "Identifiers outside the declared scope are refused", critical: true, scope: "server (does it refuse every identifier outside scope.allow, in every spelling?)" },
};

const CONFIG_KEYS = ["scope.tools", "scope.allow", "scope.deny", "scope.separator", "scope.case", "checks.scope-escape.enabled", "checks.scope-escape.severity"];

export function describe(): CheckDoc[] {
  const m = SCOPE_META["scope-escape"];
  return [
    {
      id: m.id,
      pack: PACK,
      label: m.label,
      critical: m.critical,
      advisory: false,
      scope: m.scope,
      verifiedBy: ["upstream", "response"],
      probes: [
        { id: "control", text: "a call naming an exact scope.allow entry (up to three; else <prefix>sm_control_<tok> under the first prefix) must be processed and, with an upstream stub, reach it; otherwise the check is inconclusive", kind: "control" },
        ...SCOPE_FAMILIES.map((f) => ({ id: f.id, text: f.text, kind: f.id === "case-control" ? "control" : "escape" })),
      ],
      thresholds: {},
      falsePositive: "A server that serves an identifier from its own cache answers it without reaching the backend: that is a part (scope.served-locally), not a fail. A server declared case-insensitive that refuses the upper-case spelling is noted, never failed.",
      falseNegative: "Without an upstream stub the verdict rests on the reply alone. A scope rule that depends on something other than the identifier (the caller, the time) is not exercised. Only the forms in the corpus are sent; a name that hides in an encoding outside it passes.",
      configKeys: CONFIG_KEYS,
      since: SINCE,
      status: "shipped",
    },
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Which tools the pack addresses
// ---------------------------------------------------------------------------------------------------------

interface Target {
  tool: ToolInfo;
  param: string;
  base: Record<string, unknown>;
}

function declared(ctx: PackCtx, s: ScopeSettings): ToolInfo[] {
  return s.tools.map((t) => ctx.tools.find((x) => x.name === t.tool)).filter((t): t is ToolInfo => t !== undefined);
}

function applies(ctx: PackCtx): PackApplies {
  const s = readScope(ctx.config);
  if (!s.tools.length) return { ok: false, reason: "no scope.tools entry: declare the tool and parameter that take an identifier (scope.tools: [{tool, param}]) and scope.allow" };
  if (!declared(ctx, s).length) return { ok: false, reason: "no scope.tools entry names a tool the server declares" };
  if (!s.allow.length) return { ok: false, reason: 'scope.allow is empty: list at least one identifier the server may serve (an entry ending in "." is a prefix)' };
  return { ok: true };
}

const stringParams = (t: ToolInfo): string[] =>
  Object.entries(t.inputSchema?.properties ?? {})
    .filter(([, p]) => {
      const sch = p as { type?: unknown; anyOf?: { type?: unknown }[] };
      const types = [sch.type, ...(sch.anyOf ?? []).map((a) => a.type)].flat();
      return types.includes("string");
    })
    .map(([k]) => k);

/** The arguments for one tool: its other required parameters filled by the classifier's rule, plus `sql_tools[].args` for a SQL tool. */
function targetFor(ctx: PackCtx, entry: { tool: string; param: string }, tool: ToolInfo): Target | { skip: string } {
  const strings = stringParams(tool);
  if (!strings.includes(entry.param)) return { skip: `scope.tools: tool "${tool.name}" has no string parameter named "${entry.param}"${strings.length ? ` (its string parameters: ${strings.join(", ")})` : ""}` };
  const given = (() => {
    const st = ctx.sqlTools?.find((x) => x.tool === tool.name);
    return st ? explicitArgs(st) : {};
  })();
  const c: ToolClassification = ctx.classification.find((x) => x.tool === tool.name) ?? { tool: tool.name, class: "text", confidence: "explicit", params: {}, unfillable: [], reasons: [] };
  const open = c.unfillable.filter((p) => p !== entry.param && !(p in given));
  if (open.length) return { skip: `required parameters (${open.join(", ")}) cannot be filled by the harness${ctx.sqlTools?.some((x) => x.tool === tool.name) ? "; set sql_tools[].args" : ""}` };
  const filled = fillArgs(tool, { ...c, unfillable: [] }, {}, "sm-fill") ?? {};
  const base: Record<string, unknown> = { ...filled, ...given };
  const missing = (tool.inputSchema?.required ?? []).filter((p) => p !== entry.param && base[p] === undefined);
  if (missing.length) return { skip: `required parameters (${missing.join(", ")}) cannot be filled by the harness` };
  return { tool, param: entry.param, base };
}

// ---------------------------------------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------------------------------------

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

type Outcome = "leaked" | "refused" | "served-locally" | "unjudged";

async function scopeEscape(ctx: PackCtx): Promise<CheckResult> {
  const m = metaFor(ctx, SCOPE_META["scope-escape"]);
  if (m.disabled) return result(m, PACK, "na", "", []);
  const s = readScope(ctx.config);
  const stub = ctx.upstream;
  const by: VerifiedBy = stub ? "upstream" : "response";
  const ms = Math.max(PROBE_MS_FLOOR, ctx.config.timeouts?.probe_ms ?? 10_000);
  const keeper = new Sessions(ctx);
  const tally = new Tally();
  const evidence: Evidence[] = [];
  const leaks: string[] = [];
  const local: string[] = [];
  const notes: string[] = [];
  let controlled = 0;
  let judged = 0;
  let sent = 0;

  const ask = async (t: Target, identifier: string, needle: string): Promise<{ r: CallResult; args: Record<string, unknown>; reached: boolean }> => {
    const args = { ...t.base, [t.param]: identifier };
    const mark = stub?.mark();
    const r = await keeper.call(t.tool.name, args, ms);
    let reached = stub ? stub.find(needle, mark).length > 0 : false;
    if (stub && !reached && !r.closed && !r.timedOut) {
      await sleep(SETTLE_MS);
      reached = stub.find(needle, mark).length > 0;
    }
    return { r, args, reached };
  };
  const said = (r: CallResult): string => oneLine(r.text || r.rpcError || (r.timedOut ? "no reply before the timeout" : "no reply"), 100);

  try {
    for (const entry of s.tools) {
      const tool = ctx.tools.find((x) => x.name === entry.tool);
      if (!tool) {
        tally.skip(entry.tool, "the server declares no such tool");
        continue;
      }
      const t = targetFor(ctx, entry, tool);
      if ("skip" in t) {
        tally.skip(tool.name, t.skip);
        continue;
      }
      // The control: an allowed identifier must get through, or a refusal of its neighbours proves nothing.
      let ok = false;
      for (const c of controlIdentifiers(s)) {
        const { r, args, reached } = await ask(t, c.identifier, c.needle);
        const processed = !r.closed && !r.timedOut && !rejectedBeforeRunning(r, args);
        ok = processed && (stub ? reached : !refused(r));
        tally.note(tool.name, ok);
        evidence.push({
          probe: `control: ${tool.name}(${t.param} = ${c.identifier})`,
          outcome: ok ? (stub ? "processed and reached the upstream, so a refusal of an out-of-scope name means something" : "answered, so a refusal of an out-of-scope name means something") : `the allowed identifier did not get through: ${said(r)}${stub && processed && !reached ? " (nothing reached the upstream)" : ""}`,
          verifiedBy: by,
          tool: tool.name,
          args,
          ...(ok ? {} : { excerpt: excerpt(r.text || r.rpcError || "") }),
          code: ok ? "scope.control" : "scope.control-failed",
        });
        if (ok) break;
      }
      if (!ok) {
        tally.skip(tool.name, `no control call succeeded, so a refusal of its out-of-scope names proves nothing: the scope.allow entries may be misspelled, or the server rejects the other parameters the harness filled in`);
        continue;
      }
      controlled++;

      const upper = caseControl(s);
      if (upper) {
        const { r, args, reached } = await ask(t, upper, upper);
        const accepted = !r.closed && !r.timedOut && (stub ? reached : !refused(r));
        if (!accepted && !r.closed && !r.timedOut) notes.push(`${tool.name}: declared case-insensitive but the upper-case spelling was refused`);
        evidence.push({
          probe: `case-control: ${tool.name}(${t.param} = ${upper})`,
          outcome: accepted ? "the upper-case spelling of an allowed name was accepted (scope.case: insensitive)" : `declared case-insensitive but the upper-case spelling was refused: ${said(r)}. Noted, never a fail (set scope.case: sensitive if the server is meant to compare case)`,
          verifiedBy: by,
          tool: tool.name,
          args,
          code: accepted ? "scope.case-control" : "scope.case-refused",
        });
      }

      for (const p of scopeCorpus(s)) {
        const { r, args, reached } = await ask(t, p.identifier, p.needle);
        sent++;
        let outcome: Outcome;
        if (r.closed || r.timedOut) outcome = "unjudged";
        else if (stub) outcome = reached ? "leaked" : refused(r) ? "refused" : "served-locally";
        else outcome = refused(r) ? "refused" : "leaked";
        // The coverage rule: the tool was controlled and the reply was not a validation error.
        tally.note(tool.name, outcome !== "unjudged" && !rejectedBeforeRunning(r, args));
        if (outcome !== "unjudged") judged++;
        const label = `${tool.name}.${t.param} ${p.id}`;
        if (outcome === "leaked") leaks.push(`${tool.name} ${p.id}`);
        else if (outcome === "served-locally") local.push(`${tool.name} ${p.id}`);
        const words: Record<Outcome, string> = {
          leaked: stub ? "reached the upstream" : "answered as if the name were allowed (no upstream stub: judged on the reply)",
          refused: `refused: ${said(r)}`,
          "served-locally": `answered without reaching the upstream (served from the server itself?): ${said(r)}`,
          unjudged: `no judgeable reply: ${said(r)}`,
        };
        evidence.push({
          probe: `${label}: ${p.identifier}`,
          outcome: words[outcome],
          verifiedBy: by,
          tool: tool.name,
          args,
          excerpt: excerpt(r.text || r.rpcError || ""),
          code: outcome === "leaked" ? "scope.leaked" : outcome === "refused" ? "scope.refused" : outcome === "served-locally" ? "scope.served-locally" : "scope.unjudged",
        });
      }
    }
  } catch (e) {
    return result(m, PACK, "inconclusive", `the check stopped: ${(e as Error).message}`, evidence, tally.coverage());
  }

  const coverage = tally.coverage();
  const mode = stub ? "" : " (no upstream stub: judged on responses)";
  const tail = notes.length ? `; ${notes.join("; ")}` : "";
  if (leaks.length) return result(m, PACK, "fail", `${leaks.length} out-of-scope identifier(s) got through: ${leaks.slice(0, 6).join(", ")}${leaks.length > 6 ? ", ..." : ""}${mode}${tail}`, evidence, coverage);
  if (!controlled) return result(m, PACK, "inconclusive", "no control call succeeded, so a refusal could not be told from a tool that does not work: check scope.allow (the entries may be misspelled) and scope.tools", evidence, coverage);
  if (!judged) return result(m, PACK, "inconclusive", `no out-of-scope probe got a judgeable reply (${sent} sent)`, evidence, coverage);
  if (local.length) return result(m, PACK, "part", `nothing out of scope reached the upstream, but ${local.length} probe(s) were answered without it (served from the server itself?): ${local.slice(0, 6).join(", ")}${tail}`, evidence, coverage);
  return result(m, PACK, "pass", `${judged} out-of-scope identifier(s) were refused${stub ? " and none reached the upstream" : ""}${mode}${tail}`, evidence, coverage);
}

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  return [await scopeEscape(ctx)];
}

export const pack: Pack = { id: PACK, describe, applies, run };
export default pack;
