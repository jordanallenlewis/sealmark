import type { RunResult, ToolAnnotations, ToolSurface } from "../types.js";

/**
 * Tool-surface drift between two runs of the same server (a baseline and a later run): what an agent that approved the
 * first surface would want to review. It is a relation between two reports, never a grade.
 */

export type DriftKind =
  | "tool-added"
  | "tool-removed"
  | "description-changed"
  | "required-added"
  | "param-removed"
  | "param-type-changed"
  | "param-added"
  | "annotation-changed"
  | "schema-changed"
  | "server-version-changed";

/** `breaking` and `notable` entries fail a run that asks for `--fail-on drift`; `info` is only printed. */
export type DriftSeverity = "breaking" | "notable" | "info";

export interface DriftEntry {
  server: string;
  kind: DriftKind;
  severity: DriftSeverity;
  tool?: string;
  param?: string;
  from?: string;
  to?: string;
  text: string;
}

const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;
const MAX_LISTED = 10;
/** Tool and parameter names are server-controlled; a line never carries more than this much of one. */
const MAX_NAME = 120;
const NO_SURFACE = " (baseline has no tool surface: names and annotations only)";
const SEVERITY_ORDER: Record<DriftSeverity, number> = { breaking: 0, notable: 1, info: 2 };

const shown = (name: string) => (name.length > MAX_NAME ? `${name.slice(0, MAX_NAME - 3)}...` : name);
const listed = (names: string[]) => {
  const some = names.slice(0, MAX_LISTED).map(shown);
  return names.length > MAX_LISTED ? `${some.join(", ")} and ${names.length - MAX_LISTED} more` : some.join(", ");
};
const short = (hash: unknown) => String(hash).slice(0, 8);
const hintChanges = (a: ToolAnnotations | undefined, b: ToolAnnotations | undefined): string[] =>
  HINTS.flatMap((h) => (a?.[h] === b?.[h] ? [] : [`${h} ${a?.[h] ?? "unset"} -> ${b?.[h] ?? "unset"}`]));

/** Entries that fail a run asked to fail on drift: breaking and notable ones. */
export function driftFails(entries: DriftEntry[]): DriftEntry[] {
  return entries.filter((e) => e.severity === "breaking" || e.severity === "notable");
}

/** The surface list of a report, or undefined when there is none to compare. Entries without a name (a hand-edited file) are left out. */
function surfaceOf(r: RunResult): ToolSurface[] | undefined {
  const s = r.server.surface;
  if (!Array.isArray(s)) return undefined;
  const list = s.filter((t) => t && typeof t === "object" && typeof t.name === "string");
  // Tools listed but no surface entries: the report predates the capture, so compare names instead of calling every tool gone.
  return list.length === 0 && Array.isArray(r.server.tools) && r.server.tools.length > 0 ? undefined : list;
}

/**
 * Drift in what the server offers between the baseline run and this one: tools added or removed, a changed description (hash and
 * length only, never the text), a required parameter added, a parameter removed or retyped, annotation hints that changed. Never a
 * regression: a new tool is not a failed check, so the exit code moves only under `--fail-on drift`. A baseline without a tool
 * surface (a report written before 0.2.1) is compared by tool names and annotations only, and says so.
 */
export function surfaceDrift(base: RunResult, run: RunResult): DriftEntry[] {
  const server = run.server.name;
  const before = surfaceOf(base);
  const now = surfaceOf(run);
  // The suffix says what could not be compared, so it appears only when this run has a surface and the baseline does not. Two reports
  // without one (hand-built or both pre-0.2.1) compare as they always did: names and annotations, in the order found, no suffix.
  const out = before && now ? compareSurfaces(server, before, now, namesOf(base, before), namesOf(run, now)) : namesOnly(server, base, run, now ? NO_SURFACE : "");
  // The two versions are comparable only when both reports measure them the same way (both resolved, or both older reports without the block).
  const was = Boolean(base.server.resolved) === Boolean(run.server.resolved) ? announcedVersion(base) : undefined;
  const is = announcedVersion(run);
  if (was !== undefined && is !== undefined && was !== is) {
    out.push({ server, kind: "server-version-changed", severity: "info", from: was, to: is, text: `server ${server}: version ${was} -> ${is}` });
  }
  // What to look at first, then by tool. The sort is stable, so one tool's entries keep the order they were found in.
  return !now ? out : out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.tool ?? "").localeCompare(b.tool ?? "", "en"));
}

/**
 * The version the server itself announced (`serverInfo.version`, as the run resolved it). `server.version` is the label from the
 * configuration when one was set, so a baseline that carried a label and a run that did not would differ without the server
 * having changed. A report that predates the resolved block (neither side has one) is compared by `server.version`, as it was.
 */
function announcedVersion(r: RunResult): string | undefined {
  const resolved = r.server.resolved;
  if (resolved) return typeof resolved.serverInfoVersion === "string" && resolved.serverInfoVersion !== "" ? resolved.serverInfoVersion : undefined;
  return typeof r.server.version === "string" ? r.server.version : undefined;
}

/** Tool names a report holds: the surface entries plus `server.tools`, so a tool the list names but the surface lacks (a hand-edited file) is still seen. */
function namesOf(r: RunResult, surface: ToolSurface[]): Set<string> {
  return new Set([...surface.map((t) => t.name), ...(Array.isArray(r.server.tools) ? r.server.tools.filter((t) => typeof t === "string") : [])]);
}

function compareSurfaces(server: string, before: ToolSurface[], now: ToolSurface[], hadNames: Set<string>, hasNames: Set<string>): DriftEntry[] {
  const out: DriftEntry[] = [];
  const was = new Map(before.map((t) => [t.name, t]));
  for (const name of hadNames) {
    if (!hasNames.has(name)) out.push({ server, kind: "tool-removed", severity: "breaking", tool: shown(name), text: `server ${server}: tool removed: ${shown(name)}` });
  }
  for (const name of hasNames) {
    if (!hadNames.has(name)) out.push({ server, kind: "tool-added", severity: "notable", tool: shown(name), text: `server ${server}: tool added: ${shown(name)}` });
  }
  for (const t of now) {
    const tool = shown(t.name);
    const a = was.get(t.name);
    if (!a) continue;
    const entry = (kind: DriftKind, severity: DriftSeverity, text: string, extra: Partial<DriftEntry> = {}): void => {
      out.push({ server, kind, severity, tool, text: `server ${server}, tool ${tool}: ${text}`, ...extra });
    };
    if (a.descriptionHash !== t.descriptionHash) {
      entry("description-changed", "notable", `description changed (sha ${short(a.descriptionHash)} -> ${short(t.descriptionHash)}, ${a.descriptionLength} -> ${t.descriptionLength} chars)`);
    }
    const oldParams: Record<string, string> = a.params && typeof a.params === "object" ? a.params : {};
    const newParams: Record<string, string> = t.params && typeof t.params === "object" ? t.params : {};
    const oldRequired = new Set(Array.isArray(a.required) ? a.required : []);
    const newRequired = Array.isArray(t.required) ? t.required : [];
    // What the parameter-level entries below find; a changed schema hash with none of them is reported as schema-changed.
    let derived = false;
    for (const p of newRequired) {
      if (oldRequired.has(p)) continue;
      derived = true;
      entry("required-added", "breaking", `required parameter added: ${shown(p)}`, { param: shown(p) });
    }
    for (const p of Object.keys(oldParams)) {
      if (p in newParams) continue;
      derived = true;
      entry("param-removed", "breaking", `parameter removed: ${shown(p)}`, { param: shown(p) });
    }
    for (const [p, type] of Object.entries(newParams)) {
      if (!(p in oldParams)) {
        // A new required parameter is already reported as required-added; only an optional one is info.
        if (newRequired.includes(p)) continue;
        derived = true;
        entry("param-added", "info", `optional parameter added: ${shown(p)}`, { param: shown(p) });
      } else if (oldParams[p] !== type && oldParams[p] !== "unknown") {
        // "unknown" in a baseline can be a parameter declared with anyOf, which older captures could not read: that is not a change of type.
        derived = true;
        entry("param-type-changed", "breaking", `parameter ${shown(p)} type ${oldParams[p]} -> ${type}`, { param: shown(p), from: oldParams[p], to: type });
      }
    }
    const changes = hintChanges(a.annotations, t.annotations);
    if (changes.length) entry("annotation-changed", "notable", `annotations changed ${changes.join(", ")}`);
    if (a.inputSchemaHash !== t.inputSchemaHash && !derived) entry("schema-changed", "notable", `input schema changed (sha ${short(a.inputSchemaHash)} -> ${short(t.inputSchemaHash)}; no parameter added, removed or retyped)`);
  }
  return out;
}

/** The baseline has no tool surface: compare tool names (`server.tools`) and annotations (`classification`), which is all a 0.2.0 report holds. */
function namesOnly(server: string, base: RunResult, run: RunResult, suffix: string): DriftEntry[] {
  const out: DriftEntry[] = [];
  const before = Array.isArray(base.server.tools) ? base.server.tools : [];
  const now = Array.isArray(run.server.tools) ? run.server.tools : [];
  const had = new Set(before);
  const has = new Set(now);
  const added = now.filter((t) => !had.has(t));
  const removed = before.filter((t) => !has.has(t));
  if (added.length) out.push({ server, kind: "tool-added", severity: "notable", text: `server ${server}: tools added: ${listed(added)}${suffix}` });
  if (removed.length) out.push({ server, kind: "tool-removed", severity: "breaking", text: `server ${server}: tools removed: ${listed(removed)}${suffix}` });
  const was = new Map((Array.isArray(base.classification) ? base.classification : []).map((c) => [c.tool, c.annotations]));
  for (const c of Array.isArray(run.classification) ? run.classification : []) {
    if (!was.has(c.tool)) continue;
    const changes = hintChanges(was.get(c.tool), c.annotations);
    if (changes.length) out.push({ server, kind: "annotation-changed", severity: "notable", tool: shown(c.tool), text: `server ${server}, tool ${shown(c.tool)}: annotations changed ${changes.join(", ")}${suffix}` });
  }
  return out;
}
