import { createHash } from "node:crypto";
import { originText } from "./layers.js";
import { METHODOLOGY, SCHEMA_VERSION, type ConfigIntegrity, type DiffEntry, type Origin, type PluginSpec, type ProbeSpec } from "./model.js";
import { isShipped, standardMerged, STANDARD_PROFILES } from "./profiles.js";
import { LOCKED_LEAVES, STANDARD_PACKS } from "./schema.js";
import { canonicalJson, deepClone, deepEqual, getIn, pointer } from "./util.js";

/**
 * Integrity model. Every grade-affecting leaf is `standardLocked`. A run is STANDARD only
 * when those leaves equal the shipped standard profile, no standard pack was dropped, and no plugin, custom
 * check or non-standard profile is in play. Adding a pack (exec, custom) or a probe without a check keeps
 * the run standard: adding coverage never weakens it.
 */

/**
 * Checks shipped advisory ahead of the standard (0.3-draft candidates). Their leaves are not locked, so adding one cannot change the
 * pinned standard hash; the rule in evaluateIntegrity makes turning one off or scoring it CUSTOM instead.
 */
export const CANDIDATE_CHECKS = [
  "db-privilege",
  // Round 6: the two core advisories and the checks of the candidate packs scope, sql-guard and upstream.
  "refusal-quality",
  "instructions-hygiene",
  "scope-escape",
  "sql-guard-statements",
  "sql-guard-references",
  "sql-guard-rowcap",
  "upstream-credential",
  "upstream-credential-echo",
  "log-secret",
  "upstream-error-leak",
  "upstream-slow",
] as const;

/** The only keys a replayed report may carry: every locked leaf, `packs`, and the custom-run record (`custom_checks`, `plugins`; see checkReplay). */
export function replayablePaths(): Set<string> {
  return new Set([...LOCKED_LEAVES.map((l) => l.path), "packs", ...CUSTOM_KEYS]);
}

/** Recorded in `config.locked` only for a run that declares custom checks or plugins, so a STANDARD run's locked block (and hash) is unchanged. */
const CUSTOM_KEYS = ["custom_checks", "plugins"] as const;

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x)) : []);

/**
 * Flat map of dotted schema path to value for every locked leaf, plus `packs` (the effective pack list, sorted). A run with custom
 * check probes or plugins also records `custom_checks` (sorted check ids) and `plugins` (sorted modules): they decide what was graded.
 */
export function extractLocked(value: Record<string, unknown>): Record<string, unknown> {
  const locked: Record<string, unknown> = {};
  for (const l of LOCKED_LEAVES) locked[l.path] = deepClone(getIn(value, l.path.split(".")));
  locked.packs = [...((value.packs as string[] | undefined) ?? [])].sort();
  const checks = ((value.probes as { check?: { id?: unknown } }[] | undefined) ?? []).flatMap((p) => (p?.check?.id !== undefined ? [String(p.check.id)] : [])).sort();
  const plugins = ((value.plugins as { module?: unknown }[] | undefined) ?? []).flatMap((p) => (p?.module !== undefined ? [String(p.module)] : [])).sort();
  if (checks.length) locked.custom_checks = checks;
  if (plugins.length) locked.plugins = plugins;
  return locked;
}

/**
 * Hash over the canonical JSON of the locked leaves, the methodology version and the standard packs that ran, plus (only when
 * there are any) the ids of custom checks and the plugin modules, so a CUSTOM run never shares a hash with a STANDARD one.
 * It does not depend on the server command, on extra packs, or on anything outside the grade.
 */
export function computeHash(locked: Record<string, unknown>, methodology: string = METHODOLOGY): string {
  const { packs, custom_checks, plugins, ...rest } = locked;
  const standardPacks = ((packs as string[] | undefined) ?? []).filter((p) => STANDARD_PACKS.includes(p)).sort();
  const checks = strings(custom_checks).sort();
  const modules = strings(plugins).sort();
  // Only when something custom is in play: with none, the digest input is exactly what it was, so the standard hash does not move.
  const custom = checks.length || modules.length ? { custom: { checks, plugins: modules } } : {};
  return `sha256:${createHash("sha256").update(canonicalJson({ methodology, locked: rest, packs: standardPacks, ...custom })).digest("hex")}`;
}

export interface IntegrityInput {
  value: Record<string, unknown>;
  origins: ReadonlyMap<string, Origin>;
  /** Selected profile name and the names along its chain (base first). */
  profile: string;
  chain: readonly string[];
  plugins: readonly PluginSpec[];
  probes: readonly ProbeSpec[];
}

const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x) => b.includes(x));

export function evaluateIntegrity(input: IntegrityInput): ConfigIntegrity {
  const { value, origins } = input;
  const locked = extractLocked(value);
  const std = extractLocked(standardMerged().value);
  const diff: DiffEntry[] = [];
  // A map-valued setting has an origin per entry (`/tools/overrides/<tool>`), not one of its own: take the first entry that was set somewhere.
  const originOf = (path: string) => {
    const ptr = pointer(path.split("."));
    const own = origins.get(ptr);
    if (own && own.layer !== "default") return originText(own);
    for (const [k, o] of origins) if (k.startsWith(`${ptr}/`) && o.layer !== "default") return originText(o);
    return originText(own);
  };

  for (const l of LOCKED_LEAVES) {
    if (!deepEqual(locked[l.path], std[l.path])) diff.push({ path: l.path, standard: std[l.path], effective: locked[l.path], origin: originOf(l.path) });
  }
  const packs = locked.packs as string[];
  if (!STANDARD_PACKS.every((p) => packs.includes(p))) {
    diff.push({ path: "packs", standard: [...STANDARD_PACKS].sort(), effective: packs, origin: originOf("packs") });
  }
  // Not a locked leaf (that would change the pinned standard hash), but it decides which engine pack runs: forcing duckdb
  // makes the sqlite pack not applicable while the run would still read as standard.
  const engine = getIn(value, ["sqlite", "engine"]);
  if (engine !== null && engine !== undefined) diff.push({ path: "sqlite.engine", standard: null, effective: engine, origin: originOf("sqlite.engine") });
  // Candidate checks (see CANDIDATE_CHECKS) are unlocked leaves for the same reason: a candidate that was switched off or scored is no longer the standard run.
  for (const id of CANDIDATE_CHECKS) {
    const enabled = getIn(value, ["checks", id, "enabled"]);
    const severity = getIn(value, ["checks", id, "severity"]);
    if (enabled !== true) diff.push({ path: `checks.${id}.enabled`, standard: true, effective: enabled, origin: originOf(`checks.${id}.enabled`) });
    if (severity !== null) diff.push({ path: `checks.${id}.severity`, standard: null, effective: severity, origin: originOf(`checks.${id}.severity`) });
  }
  if (input.plugins.length) diff.push({ path: "plugins", standard: [], effective: input.plugins.map((p) => p.module), origin: originOf("plugins") });
  const customChecks = input.probes.filter((p) => p.check);
  if (customChecks.length) diff.push({ path: "probes", standard: [], effective: customChecks.map((p) => p.check?.id), origin: originOf("probes") });
  // One entry, naming the outermost shipped profile that is not standard or ci (paranoid extends strict: one difference, not two).
  const nonStandard = [...input.chain].reverse().find((name) => isShipped(name) && !STANDARD_PROFILES.includes(name));
  if (nonStandard) diff.push({ path: "profile", standard: "standard", effective: nonStandard, origin: originOf("profile") });

  return {
    hash: computeHash(locked),
    profile: input.profile,
    standard: diff.length === 0,
    standardDiff: diff,
    methodology: METHODOLOGY,
    schemaVersion: (value.schema_version as number | undefined) ?? SCHEMA_VERSION,
    locked,
  };
}

/** The hash every standard run carries for this methodology version. */
export function standardHash(): string {
  return computeHash(extractLocked(standardMerged().value));
}

/**
 * What a replay cannot restore: a report from a CUSTOM run (custom checks or plugins) replays its locked settings only; the probes and
 * plugins themselves are the user's to declare. Returned as warnings, not an error.
 */
export function replayNotes(c: { locked?: unknown }): string[] {
  const l = (c.locked ?? {}) as Record<string, unknown>;
  // The names come from a report file: printable ASCII only, so a forged one cannot write control sequences to the terminal.
  const names = (v: unknown) => strings(v).map((x) => x.replace(/[^\x20-\x7e]/g, "?").slice(0, 80));
  const checks = names(l.custom_checks);
  const plugins = names(l.plugins);
  if (!checks.length && !plugins.length) return [];
  const what = [checks.length ? `custom checks (${checks.join(", ")})` : "", plugins.length ? `plugins (${plugins.join(", ")})` : ""].filter(Boolean).join(" and ");
  return [`the report was a CUSTOM run with ${what}; --replay restores the locked settings only, so declare the same ${[checks.length ? "probes:" : "", plugins.length ? "plugins:" : ""].filter(Boolean).join(" and ")} yourself`];
}

/** Checks a report's `config` block before a replay: methodology, and that `locked` really hashes to `hash`. Returns an error message, or undefined when sound. */
export function checkReplay(c: { hash?: unknown; locked?: unknown; methodology?: unknown }): string | undefined {
  if (typeof c.hash !== "string" || typeof c.locked !== "object" || c.locked === null || Array.isArray(c.locked)) return "report has no config.hash and config.locked; only reports from sealmark 0.2 or later can be replayed";
  if (c.methodology !== METHODOLOGY) return `report was graded with methodology ${String(c.methodology)}; this sealmark runs ${METHODOLOGY}`;
  const locked = c.locked as Record<string, unknown>;
  // A report is untrusted input: its hash proves nothing about who wrote it (anyone can compute it). Only grade-affecting
  // settings may travel in it, so it can never carry active, yes, plugins, server or db.pg. The sandbox.* and net.control_url
  // leaves are locked (so they are accepted here, every report carries them) but loadEffectiveConfig never applies them.
  const allowed = replayablePaths();
  // `custom_checks` and `plugins` are a record of what a CUSTOM run declared (names only, never applied); anything but a list of names is a forgery.
  const malformed = CUSTOM_KEYS.filter((k) => locked[k] !== undefined && !(Array.isArray(locked[k]) && (locked[k] as unknown[]).every((x) => typeof x === "string")));
  const unknown = [...Object.keys(locked).filter((k) => !allowed.has(k)), ...malformed];
  if (unknown.length) return `config.locked carries setting(s) a report may not set: ${unknown.slice(0, 5).join(", ")}; only the grade-affecting (locked) settings and packs are replayed`;
  if (computeHash(locked, METHODOLOGY) !== c.hash) return "config.locked does not match config.hash; the report was edited or comes from a different methodology";
  return undefined;
}
