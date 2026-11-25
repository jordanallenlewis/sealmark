import type { CheckConfig } from "../config/model.js";
import type { ToolInfo } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence } from "../types.js";
import { brief } from "./shared.js";

// Description lint (methodology 0.3-draft, round 8): two advisory candidate checks in core that read only what tools/list declares.
// No call is made and no LLM is asked: every clause is a fixed rule over the listing, so the same listing gives the same verdicts
// anywhere. Advisory: they are listed in every report and never move a letter (grade.ts skips advisory checks).

export const TOOL_DESCRIPTIONS_META = { id: "tool-descriptions", label: "Tool descriptions tell the tools apart", scope: "server (what it declares, not what it does)" };
export const PARAM_DESCRIPTIONS_META = { id: "param-descriptions", label: "Parameters say what they take", scope: "server (what it declares, not what it does)" };

/** A description shorter than this says nothing (the same floor `protocol` uses for "no useful description"). */
export const MIN_DESCRIPTION = 10;
/** Longer than this, a description costs context on every request that lists the tools. */
export const MAX_DESCRIPTION = 1024;
/** Evidence lines per check; the rest are counted in one closing line. */
export const MAX_FINDINGS = 25;
/** Names listed in one evidence line; the rest are counted. */
export const MAX_NAMES = 10;
/** param-descriptions: pass when at least this share of parameters is described and typed, part down to PART_SHARE, fail below. */
export const PASS_SHARE = 0.9;
export const PART_SHARE = 0.5;

/** Lower-case words of a name or a sentence in any script: camelCase and snake_case split, punctuation and symbols dropped. */
export const words = (s: string): string[] =>
  s.replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, "$1 $2").toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
const sameWords = (a: string, b: string): boolean => words(a).join(" ") === words(b).join(" ");
/** Two names a model cannot tell apart: equal once case and the separators _ - . and spaces are dropped. */
const nameKey = (s: string): string => s.toLowerCase().replace(/[-_.\s]+/g, "");
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const label = (s: string): string => brief(s, 80);
/** At most MAX_NAMES names, each cut to 80 characters, then a count, so one evidence line stays short whatever the listing holds. */
const nameList = (names: readonly string[]): string =>
  names.slice(0, MAX_NAMES).map(label).join(", ") + (names.length > MAX_NAMES ? ` and ${names.length - MAX_NAMES} more` : "");

type Done = (r: Pick<CheckResult, "verdict" | "summary" | "evidence">) => CheckResult;

function finisher(meta: { id: string; label: string; scope: string }, cfg: CheckConfig | undefined): Done {
  const base = { id: meta.id, pack: "core" as const, label: meta.label, critical: false, advisory: true as const, scope: meta.scope };
  return (r) => {
    if (cfg?.enabled === false) return { ...base, verdict: "na", summary: "disabled by config", evidence: [] };
    return { ...base, ...r };
  };
}

/** At most MAX_FINDINGS lines, then one line that counts the rest, so a server with hundreds of tools keeps a readable report. */
function capped(found: Evidence[], probe: string): Evidence[] {
  if (found.length <= MAX_FINDINGS) return found;
  return [...found.slice(0, MAX_FINDINGS), { probe, outcome: `${found.length - MAX_FINDINGS} more finding(s) not listed`, verifiedBy: "static", code: "descriptions.more" }];
}

/**
 * `tool-descriptions` (advisory candidate). Per tool: a description is missing or under MIN_DESCRIPTION characters; it only restates the
 * tool's name; it is longer than MAX_DESCRIPTION characters. Across tools: two tools share one description (same words), or two names
 * differ only by case or separators. fail when two tools cannot be told apart or no tool has a usable description (missing, short or restating); part for any other
 * finding; pass with none; n/a with no tools. Exact duplicate names are `protocol`'s (a schema error), not counted again here.
 */
export function toolDescriptions(tools: readonly ToolInfo[], cfg?: CheckConfig): CheckResult {
  const done = finisher(TOOL_DESCRIPTIONS_META, cfg);
  if (!tools.length) return done({ verdict: "na", summary: "the server declares no tools", evidence: [] });
  const probe = "tools/list: tool names and descriptions";
  const found: Evidence[] = [];
  let missing = 0;
  let restated = 0;
  let long = 0;
  // Distinct names per description: an exact duplicate name is protocol's schema error, not a second tool sharing the text.
  const byText = new Map<string, Set<string>>();
  for (const t of tools) {
    const name = String(t.name);
    const text = typeof t.description === "string" ? t.description.trim() : "";
    if (text.length < MIN_DESCRIPTION) {
      missing++;
      found.push({ probe, outcome: text ? `${label(name)}: the description is ${text.length} character(s), under ${MIN_DESCRIPTION}` : `${label(name)}: no description`, verifiedBy: "static", tool: name, code: "descriptions.missing" });
      continue;
    }
    if (sameWords(text, name)) {
      restated++;
      found.push({ probe, outcome: `${label(name)}: the description only restates the tool's name`, verifiedBy: "static", tool: name, code: "descriptions.restates-name" });
    }
    if (text.length > MAX_DESCRIPTION) {
      long++;
      found.push({ probe, outcome: `${label(name)}: the description is ${text.length} characters, over ${MAX_DESCRIPTION}`, verifiedBy: "static", tool: name, code: "descriptions.too-long" });
    }
    // A description with no letter or digit (only symbols or emoji) has no words to compare: it is not grouped with others.
    const key = words(text).join(" ");
    if (key) byText.set(key, (byText.get(key) ?? new Set()).add(name));
  }
  let shared = 0;
  for (const names of byText.values()) {
    if (names.size < 2) continue;
    shared++;
    found.push({ probe, outcome: `${names.size} tools share one description: ${nameList([...names])}`, verifiedBy: "static", code: "descriptions.duplicate" });
  }
  const byName = new Map<string, Set<string>>();
  for (const t of tools) {
    const name = String(t.name);
    byName.set(nameKey(name), (byName.get(nameKey(name)) ?? new Set()).add(name));
  }
  let collide = 0;
  for (const names of byName.values()) {
    if (names.size < 2) continue;
    collide++;
    found.push({ probe, outcome: `tool names differ only by case or separators: ${nameList([...names])}`, verifiedBy: "static", code: "descriptions.name-collision" });
  }
  if (!found.length) {
    return done({ verdict: "pass", summary: `${tools.length} tool description(s) read: each is present, says more than the tool's name, is at most ${MAX_DESCRIPTION} characters and differs from the others`, evidence: [{ probe, outcome: `${tools.length} tool(s) read`, verifiedBy: "static" }] });
  }
  const parts = [
    missing ? `${missing} of ${tools.length} tool(s) have no useful description` : "",
    restated ? `${restated} only restate the tool's name` : "",
    long ? `${long} are over ${MAX_DESCRIPTION} characters` : "",
    shared ? `${shared} description(s) shared by several tools` : "",
    collide ? `${collide} set(s) of names that differ only by case or separators` : "",
  ].filter(Boolean);
  // No usable description: every tool's is missing, too short, or only restates its name.
  const verdict = shared || collide || missing + restated === tools.length ? "fail" : "part";
  return done({ verdict, summary: parts.join(", "), evidence: capped(found, probe) });
}

/** Top-level keywords that can declare or allow a property outside `properties`. */
const OPEN_KEYS = ["allOf", "anyOf", "oneOf", "$ref", "$dynamicRef", "patternProperties", "if", "then", "else", "dependentSchemas", "unevaluatedProperties"];

/** A parameter schema states a type: `type`, a closed value set, a composition or a reference, or the shape of an object or array. */
function typed(s: Record<string, unknown>): boolean {
  const t = s.type;
  if (typeof t === "string" || (Array.isArray(t) && t.some((x) => typeof x === "string"))) return true;
  return ["enum", "const", "anyOf", "oneOf", "allOf", "$ref", "properties", "items"].some((k) => k in s);
}

/** A parameter documents itself: a closed value set (enum, const) or a lone boolean. */
function selfDescribing(s: Record<string, unknown>): boolean {
  if ((Array.isArray(s.enum) && s.enum.length > 0) || "const" in s) return true;
  return s.type === "boolean";
}

/** Described: a description or title that is not blank and says more than the parameter's name. */
function described(name: string, s: Record<string, unknown>): boolean {
  return [s.description, s.title].some((d) => typeof d === "string" && d.trim() !== "" && !sameWords(d, name));
}

/**
 * `param-descriptions` (advisory candidate). Every top-level parameter in each tool's inputSchema: it is described (a description or
 * title that says more than its name) unless it documents itself (enum, const, boolean), and it states a type. A name in `required`
 * that `properties` does not declare, in a closed schema, is a contract a client cannot meet. pass when at least PASS_SHARE of parameters are clean and no
 * required name is undeclared; part down to PART_SHARE; fail below it or with an undeclared required name; n/a when no tool takes a parameter.
 */
export function paramDescriptions(tools: readonly ToolInfo[], cfg?: CheckConfig): CheckResult {
  const done = finisher(PARAM_DESCRIPTIONS_META, cfg);
  const probe = "tools/list: input schema parameters";
  const found: Evidence[] = [];
  let total = 0;
  let clean = 0;
  let undeclared = 0;
  for (const t of tools) {
    const name = String(t.name);
    const schema: Record<string, unknown> = isObject(t.inputSchema) ? t.inputSchema : {};
    const props: Record<string, unknown> = isObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required.filter((r): r is string => typeof r === "string") : [];
    const bare: string[] = [];
    const untyped: string[] = [];
    for (const [p, raw] of Object.entries(props)) {
      total++;
      const s = isObject(raw) ? raw : {};
      const okText = selfDescribing(s) || described(p, s);
      const okType = typed(s);
      if (okText && okType) clean++;
      if (!okText) bare.push(p);
      if (!okType) untyped.push(p);
    }
    // Only a closed schema makes an undeclared required name a contract no client can meet: with additionalProperties not false, or a
    // composition or reference at the top level, the name may be declared or allowed elsewhere, so it is not counted.
    const closed = schema.additionalProperties === false && !OPEN_KEYS.some((k) => k in schema);
    const missing = closed ? [...new Set(required.filter((r) => !Object.hasOwn(props, r)))] : [];
    undeclared += missing.length;
    const n = Object.keys(props).length;
    if (bare.length) found.push({ probe, outcome: `${label(name)}: ${bare.length} of ${n} parameter(s) not described: ${nameList(bare)}`, verifiedBy: "static", tool: name, code: "params.undocumented" });
    if (untyped.length) found.push({ probe, outcome: `${label(name)}: ${untyped.length} of ${n} parameter(s) state no type: ${nameList(untyped)}`, verifiedBy: "static", tool: name, code: "params.untyped" });
    if (missing.length) found.push({ probe, outcome: `${label(name)}: required but not declared in properties: ${nameList(missing)}`, verifiedBy: "static", tool: name, code: "params.required-undeclared" });
  }
  if (!total && !undeclared) return done({ verdict: "na", summary: tools.length ? "no tool takes a parameter" : "the server declares no tools", evidence: [] });
  const share = total ? clean / total : 0;
  const verdict = undeclared || share < PART_SHARE ? "fail" : share < PASS_SHARE ? "part" : "pass";
  const head = `${clean} of ${total} parameter(s) are described and typed`;
  const summary = [head, undeclared ? `${undeclared} required name(s) not declared` : ""].filter(Boolean).join(", ");
  return done({ verdict, summary, evidence: found.length ? capped(found, probe) : [{ probe, outcome: `${total} parameter(s) in ${tools.length} tool(s) read`, verifiedBy: "static" }] });
}

/** The two checks for describe(); `common` carries pack, thresholds, since and status from core's list. */
export function describeDescriptions(common: Omit<CheckDoc, "id" | "label" | "critical" | "advisory" | "scope" | "verifiedBy" | "probes" | "falsePositive" | "falseNegative" | "configKeys">): CheckDoc[] {
  return [
    {
      ...common,
      id: TOOL_DESCRIPTIONS_META.id,
      label: TOOL_DESCRIPTIONS_META.label,
      critical: false,
      advisory: true,
      scope: TOOL_DESCRIPTIONS_META.scope,
      verifiedBy: ["static"],
      probes: [
        { id: "missing", text: `a tool's description is missing or under ${MIN_DESCRIPTION} characters`, core: false, kind: "static" },
        { id: "restates-name", text: "a tool's description has the same words as its name (get_weather: \"Get weather\")", core: false, kind: "static" },
        { id: "too-long", text: `a tool's description is over ${MAX_DESCRIPTION} characters (it costs context on every request that lists the tools)`, core: false, kind: "static" },
        { id: "duplicate", text: "two or more tools have a description with the same words", core: false, kind: "static" },
        { id: "name-collision", text: "two or more tool names are equal once case and the separators _ - . are dropped (get_user, getUser)", core: false, kind: "static" },
        { id: "verdict", text: "fail when two tools cannot be told apart (a shared description or colliding names) or no tool has a usable description (every one missing, under 10 characters or only restating the name); part for any other finding; pass with none; n/a with no tools", core: false, kind: "advisory" },
      ],
      falsePositive: "A short description can be enough for an obvious tool, and two tools can share a description on purpose (aliases); the check is advisory and never moves a letter.",
      falseNegative: "Only the words are read, never their meaning: a description that is present, distinct and wrong passes. Exact duplicate names are protocol's schema error and are not counted again here.",
      configKeys: [`checks.${TOOL_DESCRIPTIONS_META.id}.enabled`, `checks.${TOOL_DESCRIPTIONS_META.id}.severity`],
      since: "0.3-draft",
    },
    {
      ...common,
      id: PARAM_DESCRIPTIONS_META.id,
      label: PARAM_DESCRIPTIONS_META.label,
      critical: false,
      advisory: true,
      scope: PARAM_DESCRIPTIONS_META.scope,
      verifiedBy: ["static"],
      probes: [
        { id: "undocumented", text: "a top-level parameter has no description or title that says more than its name, and no enum, const or boolean type that documents it", core: false, kind: "static" },
        { id: "untyped", text: "a top-level parameter states no type (type, enum, const, anyOf, oneOf, allOf, $ref, properties or items)", core: false, kind: "static" },
        { id: "required-undeclared", text: "a name in the input schema's required list that its properties do not declare, in a closed schema (additionalProperties: false, and no allOf, anyOf, oneOf, $ref, patternProperties or conditional at the top level)", core: false, kind: "static" },
        { id: "verdict", text: `pass when ${PASS_SHARE * 100} % or more of the parameters are described and typed and no required name is undeclared; part at ${PART_SHARE * 100} %; fail below, or with an undeclared required name; n/a when no tool takes a parameter`, core: false, kind: "advisory" },
      ],
      falsePositive: "A well-named parameter (path, url) can be clear without a description; the check is advisory and never moves a letter.",
      falseNegative: "Only top-level parameters are read; nested object fields and array items are not. A description that is present and wrong passes.",
      configKeys: [`checks.${PARAM_DESCRIPTIONS_META.id}.enabled`, `checks.${PARAM_DESCRIPTIONS_META.id}.severity`],
      since: "0.3-draft",
    },
  ];
}
