import { ConfigError } from "./config.js";
import { discoverSqlTools, type ToolInfo } from "./mcp.js";
import type { Confidence, PackId, ParamRole, SqlTool, ToolAnnotations, ToolClass, ToolClassification, ToolOverride } from "./types.js";

/**
 * Capability classifier. It decides, per tool, what kind of argument the tool takes,
 * so that a pack only ever points a tool at a target the harness owns. It reads names, descriptions and input schemas;
 * it never calls anything. Tables below are the single source of truth for the heuristics.
 */

// ---- heuristic tables ----------------------------------------------------------------------------------

/** Parameter names are compared lower-cased with `_`, `-` and spaces removed, so `file_path`, `filePath` and `filepath` are one name. */
const key = (s: string) => s.toLowerCase().replace(/[_\-\s]/g, "");
const keys = (names: string[]) => new Set(names.map(key));

const STRONG: Record<"path" | "url" | "command" | "git", Set<string>> = {
  path: keys(["path", "paths", "file_path", "filepath", "filename", "file", "directory", "dir", "source", "destination", "dest", "target_path", "root"]),
  url: keys(["url", "uri", "href", "link", "endpoint", "website", "webpage"]),
  command: keys(["command", "cmd", "shell", "script", "program", "executable", "exe", "bash", "powershell", "run"]),
  git: keys(["repo_path", "repo", "repository", "repository_path", "git_dir"]),
};
/** Names that only count when the tool itself says what it is about. */
const GENERIC: Record<"path" | "url" | "command" | "git", Set<string>> = {
  path: keys(["target", "name", "location", "src"]),
  url: keys(["address", "site", "page"]),
  command: keys(["input", "code"]),
  git: keys(["path"]),
};
/** Array parameters that carry the arguments of a spawned program. */
const COMMAND_ARRAYS = keys(["args", "argv", "arguments"]);

/** Tested against the tool name and description after word splitting (`read_text_file` -> `read text file`). */
const HINT: Record<"sql" | "path" | "url" | "command" | "git", RegExp> = {
  sql: /\b(sql|database|postgres|table)\b/g,
  path: /\b(file|files|directory|directories|folder|path|read|write|list|move|copy|delete)\b/g,
  url: /\b(fetch|http|https|url|web|crawl|download|request|browse)\b/g,
  command: /\b(exec|execute|shell|command|terminal|run|spawn|process)\b/g,
  git: /\bgit\b/g,
};

const DEST_NAMES = keys(["destination", "dest", "target_path"]);

/**
 * The last word of a parameter name that holds a path: `outputPath`, `source_file`, `dir`. The match is by whole word (`words()` splits
 * camelCase and separators), so a one-word name that merely ends in the same letters (`xpath`, `profile`, `redir`) is not a path.
 */
const PATH_TAIL = new Set(["path", "file", "filepath", "filename", "dir", "directory"]);
/** A first word that makes such a name a destination (the thing a move, copy or save writes to). Source prefixes (source, src, from, input) need no entry: a path that is not a destination is the source. */
const DEST_PREFIX = new Set(["destination", "dest", "target", "to", "output", "new"]);
/** A name that belongs to the git class (`repo_path`, `git_dir`) is not read as a path as well. */
const GIT_WORDS = new Set(["git", "repo", "repository"]);

/** What a parameter name says about a path: undefined (nothing), "path" (a path or a source) or "dest" (a destination). */
function pathRole(name: string): "path" | "dest" | undefined {
  const k = key(name);
  if (STRONG.git.has(k)) return undefined;
  if (STRONG.path.has(k)) return DEST_NAMES.has(k) ? "dest" : "path";
  const parts = words(name).split(" ").filter(Boolean);
  if (parts.length < 2 || !PATH_TAIL.has(parts[parts.length - 1]!) || parts.some((w) => GIT_WORDS.has(w))) return undefined;
  return DEST_PREFIX.has(parts[0]!) ? "dest" : "path";
}
const CONTENT_NAMES = keys(["content", "contents", "text", "data", "body"]);
const GIT_SECONDARY: Partial<Record<ParamRole, Set<string>>> = {
  message: keys(["message", "msg"]),
  branch_name: keys(["branch_name", "branch", "base_branch"]),
  target: keys(["target"]),
  revision: keys(["revision", "rev", "ref", "commit"]),
};

/** Most specific first. */
const SPECIFICITY: ToolClass[] = ["command", "sql", "git", "path", "url", "text"];
const CONF_ORDER: Confidence[] = ["low", "medium", "high"];

// ---- schema helpers ------------------------------------------------------------------------------------

type Prop = { type?: string | string[]; format?: string; description?: string; enum?: unknown[]; const?: unknown; default?: unknown; items?: Prop; anyOf?: Prop[]; oneOf?: Prop[]; minimum?: number; [k: string]: unknown };
/**
 * `enumArray`: an array whose items are an enum (filled with its first value). `object` and `objectArray`: an object, or an array of
 * objects, that declares its properties and whose required properties are all scalars the harness can fill (one level; filled from them).
 */
type Kind = "string" | "stringArray" | "enumArray" | "enum" | "boolean" | "number" | "object" | "objectArray" | "other";

function typesOf(p: Prop | undefined): string[] {
  if (!p) return [];
  const own = [p.type].flat().filter((t): t is string => typeof t === "string");
  const nested = [...(p.anyOf ?? []), ...(p.oneOf ?? [])].flatMap(typesOf);
  return [...own, ...nested];
}

/** The scalar kinds a harness filler exists for: what a sub-property of an object parameter may be for the object to be fillable. */
const FILLABLE_SCALAR = new Set<Kind>(["string", "stringArray", "enumArray", "enum", "boolean", "number"]);

/**
 * The properties of an object schema the harness sets when it builds a value: the required ones, or, when the schema declares no
 * `required` at all, every property it can fill (an `{oldText, newText}` item is only meaningful with both).
 */
function fillNames(o: Prop | undefined): string[] {
  const props = (o?.properties ?? {}) as Record<string, Prop>;
  if (Array.isArray(o?.required)) return (o!.required as unknown[]).filter((r): r is string => typeof r === "string");
  return Object.keys(props).filter((k) => props[k]!.default !== undefined || FILLABLE_SCALAR.has(kindOf(props[k])));
}

/** An object schema the harness can build a value for: it declares its properties and every one it must set is a fillable scalar. */
function fillableObject(o: Prop | undefined): boolean {
  const props = o?.properties as Record<string, Prop> | undefined;
  if (!props || typeof props !== "object" || Array.isArray(props) || !Object.keys(props).length) return false;
  return fillNames(o).every((r) => props[r] !== undefined && (props[r]!.default !== undefined || FILLABLE_SCALAR.has(kindOf(props[r]))));
}

const itemsOf = (p: Prop): Prop | undefined => p.items ?? ((p.anyOf ?? []).concat(p.oneOf ?? [])).find((b) => b.type === "array")?.items;

function kindOf(p: Prop | undefined): Kind {
  if (!p) return "other";
  if (Array.isArray(p.enum) || p.const !== undefined) return "enum";
  const t = typesOf(p).filter((x) => x !== "null");
  if (t.includes("array")) {
    const it = itemsOf(p);
    if (!it) return "other";
    const itemTypes = typesOf(it);
    if (itemTypes.includes("object")) return fillableObject(it) ? "objectArray" : "other";
    if (Array.isArray(it.enum)) return it.enum.length ? "enumArray" : "other";
    return itemTypes.includes("string") ? "stringArray" : "other";
  }
  if (t.includes("object")) return fillableObject(p) ? "object" : "other";
  if (t.includes("string")) return "string";
  if (t.includes("boolean")) return "boolean";
  if (t.includes("integer") || t.includes("number")) return "number";
  return "other";
}

/**
 * `#/$defs/X` and `#/definitions/X` inside the tool's own input schema, followed up to eight times. Anything else (an external
 * URL, a pointer into `properties`) stays unresolved, so such a parameter is `other` and the tool stays unfillable. This is a
 * copy of the resolver in packs/git.ts: classify.ts is below the packs and must not import one.
 */
function deref(root: Record<string, unknown>, s: Prop | undefined): Prop | undefined {
  let cur = s;
  for (let i = 0; cur && typeof cur.$ref === "string" && i < 8; i++) {
    const m = /^#\/(\$defs|definitions)\/(.+)$/.exec(cur.$ref);
    cur = m ? ((root[m[1]!] ?? {}) as Record<string, Prop>)[decodeURIComponent(m[2]!)] : undefined;
  }
  return cur && typeof cur.$ref !== "string" ? cur : undefined;
}

/**
 * `p` with every `$ref` the tool's own schema can answer replaced by what it points at (the reference's sibling keywords, such
 * as a `default`, win), through `anyOf`/`oneOf` branches and array `items`. A pydantic `Literal` parameter arrives as
 * `{"$ref": "#/$defs/Mode"}`; classified as written it would be `other` and the tool would be unfillable. A reference that
 * cannot be resolved, or that is still nested after `depth` levels (a cycle), is left as written.
 */
function inline(root: Record<string, unknown>, p: Prop | undefined, depth = 0, budget = { left: 200 }): Prop | undefined {
  // The schema is server-controlled: a wide cycle of branches must not grow without bound, so a parameter gets a fixed number of visits.
  if (!p || typeof p !== "object" || depth > 8 || budget.left-- <= 0) return p;
  let out: Prop = p;
  if (typeof p.$ref === "string") {
    const target = deref(root, p);
    if (!target) return p;
    const { $ref: _ref, ...siblings } = p;
    out = { ...target, ...siblings };
  }
  const branch = (b: Prop) => inline(root, b, depth + 1, budget) ?? b;
  if (Array.isArray(out.anyOf)) out = { ...out, anyOf: out.anyOf.map(branch) };
  if (Array.isArray(out.oneOf)) out = { ...out, oneOf: out.oneOf.map(branch) };
  if (out.items && typeof out.items === "object" && !Array.isArray(out.items)) out = { ...out, items: branch(out.items) };
  // The properties of an object parameter (and of an array's items) are read one level down, so they are resolved the same way.
  const sub = out.properties as Record<string, Prop> | undefined;
  if (sub && typeof sub === "object" && !Array.isArray(sub)) out = { ...out, properties: Object.fromEntries(Object.entries(sub).map(([k, v]) => [k, branch(v)])) };
  return out;
}

/** words("readTextFile") === "read text file"; keeps matching independent of the server's naming style. */
const words = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-./:]+/g, " ").toLowerCase();

/** "git-style diff" describes a format, not a repository: the word git there is not evidence that the tool takes one. */
const GIT_FORMAT_PHRASE = /\bgit (?:style|like|flavou?red)\b/g;

function hintMatch(re: RegExp, tool: ToolInfo): { where: "name" | "description"; words: string[] } | undefined {
  const find = (text: string) => [...new Set([...(re === HINT.git ? text.replace(GIT_FORMAT_PHRASE, " ") : text).matchAll(new RegExp(re.source, "g"))].map((m) => m[1] ?? m[0]))];
  const inName = find(words(`${tool.name} ${tool.title ?? ""}`));
  if (inName.length) return { where: "name", words: inName };
  const inDesc = find(words(tool.description ?? ""));
  if (inDesc.length) return { where: "description", words: inDesc };
  return undefined;
}

const hintReason = (h: { where: string; words: string[] }) => `${h.where} matches /${h.words.join("|")}/`;

export function annotationsOf(tool: ToolInfo): ToolAnnotations | undefined {
  const a = (tool as { annotations?: Record<string, unknown> }).annotations;
  if (!a || typeof a !== "object") return undefined;
  const out: ToolAnnotations = {};
  for (const k of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const) if (typeof a[k] === "boolean") out[k] = a[k];
  return Object.keys(out).length ? out : undefined;
}

// ---- candidates ----------------------------------------------------------------------------------------

interface Cand {
  cls: ToolClass;
  conf: Confidence;
  /**
   * What the evidence rests on. `strong`: a parameter that names the class (path, url, command, repo) or has format "uri".
   * `generic`: a generic parameter name (name, target, input, ...) that only counts because the tool name or description
   * says what the tool is about. Used to rank candidates that both reach medium (see `rankCandidates`).
   */
  evidence: "strong" | "generic";
  params: Partial<Record<ParamRole, string>>;
  reasons: string[];
  style?: "shell" | "spawn";
}

const stepUp = (c: Confidence): Confidence => (c === "low" ? "medium" : "high");
const stepDown = (c: Confidence): Confidence => (c === "high" ? "medium" : "low");

interface ToolShape {
  tool: ToolInfo;
  props: Record<string, Prop>;
  kind: Record<string, Kind>;
  /** Parameter names in schema order. */
  names: string[];
  /**
   * Object and array-of-object parameters that carry a path one level down: `files` -> `files[].file_path`. The harness can aim a
   * path at a top-level parameter only, so such a parameter is never fillable (see unfillableOf).
   */
  nestedPath: Record<string, string>;
}

/** `files[].file_path` for a string sub-property of an object parameter (or of an array's items) that names a path, or undefined. */
function nestedPathOf(name: string, p: Prop): string | undefined {
  const isArray = typesOf(p).includes("array");
  const holder = isArray ? itemsOf(p) : p;
  const sub = holder && typeof holder === "object" ? (holder.properties as Record<string, Prop> | undefined) : undefined;
  if (!sub || typeof sub !== "object" || Array.isArray(sub) || (!isArray && !typesOf(p).includes("object"))) return undefined;
  const hit = Object.keys(sub).find((k) => kindOf(sub[k]) === "string" && pathRole(k) !== undefined);
  return hit ? `${name}${isArray ? "[]" : ""}.${hit}` : undefined;
}

function shapeOf(tool: ToolInfo): ToolShape {
  const root = (tool.inputSchema ?? {}) as Record<string, unknown>;
  const raw = (root.properties ?? {}) as Record<string, Prop>;
  const names = Object.keys(raw);
  // References inside the tool's own schema are followed once, here, so every later reader (kind, enum, default, format) sees the real schema.
  const props = Object.fromEntries(names.map((n) => [n, inline(root, raw[n]) as Prop])) as Record<string, Prop>;
  const nestedPath = Object.fromEntries(names.flatMap((n) => {
    const hit = nestedPathOf(n, props[n]!);
    return hit ? [[n, hit] as const] : [];
  }));
  return { tool, props, kind: Object.fromEntries(names.map((n) => [n, kindOf(props[n])])), names, nestedPath };
}

const isUri = (p: Prop | undefined) => p?.format === "uri" || p?.format === "uri-reference" || p?.format === "iri";

function secondaryParams(s: ToolShape, cls: ToolClass, taken: Set<string>): Partial<Record<ParamRole, string>> {
  const out: Partial<Record<ParamRole, string>> = {};
  const find = (set: Set<string>, kinds: Kind[]) => s.names.find((n) => !taken.has(n) && set.has(key(n)) && kinds.includes(s.kind[n]));
  if (cls === "path" || cls === "url" || cls === "git") {
    const c = find(CONTENT_NAMES, ["string"]);
    if (c) out.content = c;
  }
  if (cls === "git") {
    for (const [role, set] of Object.entries(GIT_SECONDARY) as [ParamRole, Set<string>][]) {
      const n = find(set, ["string"]);
      if (n) out[role] = n;
    }
    const files = s.names.find((n) => key(n) === "files" && s.kind[n] === "stringArray");
    if (files) out.files = files;
  }
  return out;
}

/** Evidence for one class from names and descriptions alone. Returns undefined when nothing matches at all. */
function candidate(s: ToolShape, cls: "path" | "url" | "command" | "git"): { cand?: Cand; weak?: string } {
  const hint = hintMatch(HINT[cls], s.tool);
  /** The hint that was used: the tool's, or for a generic parameter the one that qualified it. */
  let used: { where: string; words: string[] } | undefined = hint;
  /**
   * A generic parameter name counts only when the tool name or title says what the tool is about, or the parameter's own description
   * does. A word in the tool's description alone ("list the indexes") does not promote it. The git hint is the literal word "git",
   * not a common verb, so it keeps counting wherever it is written.
   */
  const genericHint = (param: string): { where: string; words: string[] } | undefined => {
    if (hint && (hint.where === "name" || cls === "git")) return hint;
    const own = [...new Set([...words(s.props[param]?.description ?? "").matchAll(new RegExp(HINT[cls].source, "g"))].map((m) => m[1] ?? m[0]))];
    return own.length ? { where: "parameter description", words: own } : undefined;
  };
  const strings = s.names.filter((n) => s.kind[n] === "string");
  const arrays = s.names.filter((n) => s.kind[n] === "stringArray");
  const reasons: string[] = [];
  const params: Partial<Record<ParamRole, string>> = {};
  let conf: Confidence | undefined;
  let weak: string | undefined;
  const taken = new Set<string>();

  if (cls === "path") {
    const strong = strings.filter((n) => pathRole(n) !== undefined);
    const arr = arrays.find((n) => key(n) === "paths");
    const generic = strings.filter((n) => GENERIC.path.has(key(n)));
    // A required parameter whose items carry the path (`files: [{file_path, ...}]`): the tool reads paths, but the harness cannot aim one
    // into it. The candidate exists so the report says so ("would be path (param files[].file_path), but required parameter files ...").
    const nested = s.names.find((n) => s.nestedPath[n] && ((s.tool.inputSchema?.required ?? []) as string[]).includes(n));
    if (!strong.length && !arr && nested) {
      reasons.push(`param "${s.nestedPath[nested]}"`);
      conf = "medium";
    } else if (strong.length || arr) {
      const sources = strong.filter((n) => pathRole(n) !== "dest");
      const dests = strong.filter((n) => pathRole(n) === "dest");
      const path = sources[0] ?? dests[0];
      const dest = sources.length ? (dests[0] ?? sources[1]) : dests[1];
      if (path) params.path = path;
      if (dest) params.dest = dest;
      if (arr) params.paths = arr;
      for (const n of [path, dest, arr]) if (n) taken.add(n);
      reasons.push(...[path, dest, arr].filter((n): n is string => Boolean(n)).map((n) => `param "${n}"`));
      conf = "medium";
    } else if (generic.length && (used = genericHint(generic[0]!))) {
      params.path = generic[0];
      taken.add(generic[0]);
      reasons.push(`generic param "${generic[0]}"`);
      conf = "medium";
    } else if (generic.length) weak = `argument "${generic[0]}" could be a path, but nothing in the tool name, its title or the parameter's own description says so`;
  } else if (cls === "url") {
    const strong = strings.filter((n) => STRONG.url.has(key(n)) || isUri(s.props[n]));
    const generic = strings.filter((n) => GENERIC.url.has(key(n)));
    if (strong.length) {
      params.url = strong[0];
      taken.add(strong[0]);
      reasons.push(`param "${strong[0]}"${isUri(s.props[strong[0]]) && !STRONG.url.has(key(strong[0])) ? ' (format "uri")' : ""}`);
      conf = "medium";
    } else if (generic.length && (used = genericHint(generic[0]!))) {
      params.url = generic[0];
      taken.add(generic[0]);
      reasons.push(`generic param "${generic[0]}"`);
      conf = "medium";
    } else if (generic.length) weak = `argument "${generic[0]}" could be a URL, but nothing in the tool name, its title or the parameter's own description says so`;
  } else if (cls === "command") {
    const strong = strings.filter((n) => STRONG.command.has(key(n)));
    const arr = arrays.find((n) => COMMAND_ARRAYS.has(key(n)));
    const generic = strings.filter((n) => GENERIC.command.has(key(n)));
    if (strong.length || arr) {
      if (strong.length) {
        params.command = strong[0];
        taken.add(strong[0]);
        reasons.push(`param "${strong[0]}"`);
      }
      if (arr) {
        params.args = arr;
        taken.add(arr);
        reasons.push(`param "${arr}" (argument list)`);
      }
      conf = "medium";
    } else if (generic.length && (used = genericHint(generic[0]!))) {
      params.command = generic[0];
      taken.add(generic[0]);
      reasons.push(`generic param "${generic[0]}"`);
      conf = "medium";
    } else if (generic.length) weak = `argument "${generic[0]}" could be a command, but nothing in the tool name, its title or the parameter's own description says so`;
  } else {
    const strong = strings.filter((n) => STRONG.git.has(key(n)));
    const generic = strings.filter((n) => GENERIC.git.has(key(n)));
    if (strong.length) {
      params.repo = strong[0];
      taken.add(strong[0]);
      reasons.push(`param "${strong[0]}"`);
      conf = "medium";
    } else if (generic.length && (used = genericHint(generic[0]!))) {
      params.repo = generic[0];
      taken.add(generic[0]);
      reasons.push(`generic param "${generic[0]}"`);
      conf = "medium";
    }
  }
  if (!conf) return { weak };
  if (used) {
    reasons.push(hintReason(used));
    if (!reasons[0].startsWith("generic")) conf = stepUp(conf);
  }
  Object.assign(params, secondaryParams(s, cls, taken));
  const style = cls === "command" ? (params.args ? "spawn" : "shell") : undefined;
  const evidence = reasons[0]!.startsWith("generic") ? "generic" : "strong";
  return { cand: { cls, conf, evidence, params, reasons, style } };
}

/**
 * Order the candidates that reached medium or better; the first is the primary class, the rest are reported as `secondary`.
 * Evidence strength decides first: a candidate resting on a parameter that names its class (or has format "uri") outranks one
 * that rests on a generic parameter plus a hint word, so a tool with a generic `name` and a "file" in its name does not hide a
 * `format: "uri"` parameter from the net pack. SPECIFICITY then breaks ties. Two things keep their old order:
 * - command and sql go first whatever the evidence: they are the classes with the most dangerous probes, and a tool that might
 *   be one is never demoted to a weaker reading;
 * - a generic candidate that claims a parameter some strong candidate also claims is a different reading of the same parameter,
 *   and the hint word is what chooses between the readings (`git_root{path}` is git, not path), so it is not demoted.
 */
function rankCandidates(cands: Cand[]): Cand[] {
  // The parameter that carries the class itself; content-like extras are not what makes a tool a path, url or git tool.
  const main = (c: Cand) => (c.cls === "path" ? c.params.path : c.cls === "url" ? c.params.url : c.cls === "git" ? c.params.repo : undefined);
  const sharesWithStrong = (c: Cand) => main(c) !== undefined && cands.some((o) => o !== c && o.evidence === "strong" && main(o) === main(c));
  const lane = (c: Cand) => (c.cls === "command" || c.cls === "sql" ? 0 : c.evidence === "strong" || sharesWithStrong(c) ? 1 : 2);
  return [...cands].sort((a, c) => lane(a) - lane(c) || SPECIFICITY.indexOf(a.cls) - SPECIFICITY.indexOf(c.cls));
}

// ---- unfillable parameters -----------------------------------------------------------------------------

/** Required parameters the harness has no safe value for (objects, arrays of non-strings, untyped without a default). */
function unfillableOf(s: ToolShape): string[] {
  const required = (s.tool.inputSchema?.required ?? []) as string[];
  return required.filter((n) => {
    const p = s.props[n];
    if (!p) return false;
    if (p.default !== undefined) return false;
    // A required parameter that carries the path one level down cannot be aimed at a path the harness owns, however fillable it is otherwise.
    return s.kind[n] === "other" || n in s.nestedPath;
  });
}

// ---- globs and overrides -------------------------------------------------------------------------------

export function globToRegExp(glob: string): RegExp {
  const body = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${body}$`);
}

const matchesAny = (name: string, globs: string[]) => globs.find((g) => globToRegExp(g).test(name));

export interface ClassifyInput {
  tools: ToolInfo[];
  /** Explicit `sql_tools` from the config: class sql, confidence explicit. */
  sqlTools?: SqlTool[];
  /** `tools.overrides`: class (and optionally parameter roles) forced by the user. Overrides always win and are printed. */
  overrides?: Record<string, ToolOverride>;
  /** `tools.include` (default `["*"]`) is evaluated before `tools.exclude`. */
  include?: string[];
  exclude?: string[];
}

export interface ClassifyOutput {
  classification: ToolClassification[];
  warnings: string[];
  /** Tools discoverSqlTools declined, with its reason (the db pack reports these as not covered). */
  sqlSkipped: { tool: string; reason: string }[];
}

function base(s: ToolShape): Pick<ToolClassification, "tool" | "annotations" | "unfillable"> {
  const annotations = annotationsOf(s.tool);
  return { tool: s.tool.name, unfillable: unfillableOf(s), ...(annotations ? { annotations } : {}) };
}

/** Classify every tool. Pure: no calls are made. Throws ConfigError for an override that contradicts the tool's schema. */
export function classifyTools(input: ClassifyInput): ClassifyOutput {
  const warnings: string[] = [];
  const include = input.include?.length ? input.include : ["*"];
  const exclude = input.exclude ?? [];
  const overrides = input.overrides ?? {};
  const names = new Set(input.tools.map((t) => t.name));
  for (const o of Object.keys(overrides)) if (!names.has(o)) warnings.push(`tools.overrides lists "${o}" but the server declares no such tool`);
  const sql = discoverSqlTools(input.tools, input.sqlTools);
  const sqlFound = new Map(sql.tools.map((t) => [t.tool, t]));
  const sqlSkipped = new Map(sql.skipped.map((t) => [t.tool, t.reason]));
  const explicitSql = new Set((input.sqlTools ?? []).map((t) => t.tool));

  const classification = input.tools.map((tool): ToolClassification => {
    const s = shapeOf(tool);
    const b = base(s);

    // 1. tools.include / tools.exclude
    const notIncluded = !matchesAny(tool.name, include);
    const excludedBy = matchesAny(tool.name, exclude);
    if (notIncluded || excludedBy) {
      return { ...b, class: "opaque", confidence: "explicit", params: {}, reasons: [notIncluded ? `not matched by tools.include (${include.join(", ")})` : `excluded by tools.exclude (${excludedBy})`], excluded: true, source: "override" };
    }

    // 2. tools.overrides
    const ov = overrides[tool.name];
    if (ov) {
      const params: Partial<Record<ParamRole, string>> = {};
      for (const [role, name] of Object.entries(ov.params ?? {}) as [ParamRole, string][]) {
        if (!s.props[name]) {
          throw new ConfigError(`tools.overrides.${tool.name}.params.${role}: the tool has no parameter "${name}" (its parameters: ${s.names.join(", ") || "none"}).`);
        }
        params[role] = name;
      }
      if (!ov.params && ov.class !== "opaque" && ov.class !== "text") {
        const found = ov.class === "sql" ? undefined : candidate(s, ov.class as "path" | "url" | "command" | "git").cand;
        if (found) Object.assign(params, found.params);
        else if (ov.class === "sql") {
          const arg = sqlFound.get(tool.name)?.arg;
          if (arg) params.sql = arg;
        }
      }
      return {
        ...b,
        class: ov.class,
        confidence: "explicit",
        params,
        reasons: ["override: tools.overrides"],
        source: "override",
        ...(ov.class === "command" ? { style: params.args ? ("spawn" as const) : ("shell" as const) } : {}),
      };
    }

    // 3. sql_tools from the config
    if (explicitSql.has(tool.name)) {
      const arg = sqlFound.get(tool.name)!.arg;
      return { ...b, class: "sql", confidence: "explicit", params: { sql: arg }, reasons: ['config: sql_tools lists this tool'], source: "sql_tools" };
    }

    // 4. heuristics
    const cands: Cand[] = [];
    const weak: string[] = [];
    for (const cls of ["command", "git", "path", "url"] as const) {
      const r = candidate(s, cls);
      if (r.cand) cands.push(r.cand);
      else if (r.weak) weak.push(r.weak);
    }
    let sqlRow: Cand | undefined;
    const sqlTool = sqlFound.get(tool.name);
    if (sqlTool) {
      const hint = hintMatch(HINT.sql, tool);
      const strong = ["sql", "sqlquery"].includes(key(sqlTool.arg));
      sqlRow = { cls: "sql", conf: strong && hint ? "high" : "medium", evidence: "strong", params: { sql: sqlTool.arg }, reasons: [`${strong ? "param" : "generic param"} "${sqlTool.arg}"`, ...(hint ? [hintReason(hint)] : [])] };
      cands.push(sqlRow);
    }
    const skipReason = sqlSkipped.get(tool.name);
    if (skipReason) {
      if (/also requires/.test(skipReason)) {
        // It is SQL, but the harness cannot fill the other required arguments: keep the class, drop to core only.
        const others = ((tool.inputSchema?.required ?? []) as string[]).filter((r) => r !== s.names.find((n) => ["sql", "sqlquery", "query", "statement"].includes(key(n))));
        return { ...b, class: "sql", confidence: "low", params: {}, unfillable: others, reasons: [skipReason] };
      }
      weak.push(skipReason);
    }

    const unfillable = b.unfillable;
    const strings = s.names.filter((n) => s.kind[n] === "string" || s.kind[n] === "stringArray");
    const matched = rankCandidates(cands.filter((c) => CONF_ORDER.indexOf(c.conf) >= 1));

    if (!matched.length) {
      if (!strings.length) {
        // Say which of the three it is: nothing to fill, only enums to choose from, or no string at all.
        const enumLike = (n: string) => s.kind[n] === "enum" || s.kind[n] === "enumArray";
        const why = s.names.length === 0 ? NO_PARAMETERS : s.names.some(enumLike) ? "no free-text parameter: every string parameter is an enum" : "the tool has no string parameters";
        return { ...b, class: "opaque", confidence: "low", params: {}, reasons: [why] };
      }
      const free = s.names.find((n) => s.kind[n] === "string");
      const said = free ? `free-text parameter "${free}": no path, URL, command, SQL or repository signal` : "string-array parameters only: none names a path, URL, command, SQL or repository";
      return { ...b, class: "text", confidence: "low", params: free ? { text: free } : {}, reasons: weak.length ? weak : [said] };
    }

    const primary = matched[0];
    if (unfillable.length) {
      return {
        ...b,
        class: "opaque",
        confidence: "low",
        params: {},
        reasons: [`would be ${primary.cls} (${primary.reasons.join(", ")}), but required parameter${unfillable.length > 1 ? "s" : ""} ${unfillable.map((u) => `"${u}"`).join(", ")} cannot be filled by the harness`],
        secondary: matched.map((c) => c.cls),
      };
    }
    let conf = primary.conf;
    const reasons = [...primary.reasons];
    if ((primary.cls === "path" || primary.cls === "git") && b.annotations?.destructiveHint === true) {
      conf = stepDown(conf);
      reasons.push("destructiveHint is true: confidence lowered one step");
    }
    const secondary = matched.slice(1).map((c) => c.cls);
    // The parameters the secondary readings found (the first reading wins per role), so a pack can use a class the tool only has on the side.
    const secondaryParams: Partial<Record<ToolClass, Partial<Record<ParamRole, string>>>> = {};
    for (const c of matched.slice(1)) if (!(c.cls in secondaryParams)) secondaryParams[c.cls] = { ...c.params };
    const row: ToolClassification = {
      ...b,
      class: primary.cls,
      confidence: conf,
      params: primary.params,
      reasons,
      ...(secondary.length ? { secondary } : {}),
      ...(Object.keys(secondaryParams).length ? { secondaryParams } : {}),
      ...(primary.style ? { style: primary.style } : {}),
      source: "heuristic",
    };
    // A path tool that also takes a URL is probed by the net pack through that parameter: the report says so (round 4, B1).
    if (secondaryUrlParam(row)) row.reasons = [...row.reasons, "secondary: url (probed by net)"];
    return row;
  });
  return { classification, warnings, sqlSkipped: sql.skipped };
}

// ---- gating --------------------------------------------------------------------------------------------

/**
 * The frozen gate: low confidence means core only; medium unlocks the packs whose
 * inputs the harness owns (fs, net, git, effects); high or explicit also unlocks exec, and exec only with --active.
 * A command tool is probed by no other pack. A git tool is not probed by fs (it has one class).
 */
export function packsFor(c: ToolClassification, o: { active: boolean; sandboxEnabled: boolean }): PackId[] {
  const own = primaryPacks(c, o);
  // A secondary url class is probed by the net pack like a primary one (it needs no sandbox).
  return secondaryUrlParam(c) !== undefined && !own.includes("net") ? [...own, "net"] : own;
}

/**
 * The parameter through which the net pack can probe a tool whose primary class is path or git and that also takes a URL, or
 * undefined. Only url is consumed from a secondary reading: a path or git secondary would aim write probes at a tool whose primary
 * slot then holds a harness token, which proves nothing. A command or SQL tool is never probed through a URL it happens to take.
 */
export function secondaryUrlParam(c: ToolClassification): string | undefined {
  if (c.excluded || c.confidence === "low" || (c.class !== "path" && c.class !== "git")) return undefined;
  if (!c.secondary?.includes("url")) return undefined;
  return c.secondaryParams?.url?.url;
}

function primaryPacks(c: ToolClassification, o: { active: boolean; sandboxEnabled: boolean }): PackId[] {
  if (c.excluded || c.confidence === "low") return [];
  const sandbox = o.sandboxEnabled;
  switch (c.class) {
    case "sql":
      return ["db", "sqlite"];
    case "path":
      return sandbox ? ["fs", "effects"] : [];
    case "git":
      return sandbox ? ["git", "effects"] : [];
    case "url":
      return sandbox ? ["net", "effects"] : ["net"];
    case "command":
      return (c.confidence === "high" || c.confidence === "explicit") && o.active && sandbox ? ["exec"] : [];
    default:
      return [];
  }
}

/** The reason a tool without parameters carries; coreOnlyHint reads it, because there is nothing to add under `tools:` for such a tool. */
const NO_PARAMETERS = "the tool takes no parameters";

/** Why a tool gets the hygiene checks only, or undefined when some pack probes it. */
export function coreOnlyReason(c: ToolClassification): string | undefined {
  if (c.class === "sql" && c.confidence !== "low") return undefined;
  if (c.excluded) return c.reasons[0];
  if (c.confidence === "low") return c.reasons.join("; ");
  if (c.class === "text" || c.class === "opaque") return c.reasons.join("; ");
  if (c.class === "command" && c.confidence === "medium") return `${c.class} tool at medium confidence (${c.reasons.join(", ")}); exec needs high confidence`;
  return undefined;
}

/**
 * What to do about a core-only tool. Excluded tools and low-confidence heuristic readings: put the tool under tools: (the hint that
 * has always been printed). An override already is that, and an unfillable tool is not helped by it: both are called by a probes: entry.
 */
export function coreOnlyHint(c: ToolClassification, counted: readonly string[] = []): string {
  // A tool that a counted `probes:` entry already called needs no advice to write one.
  const probe = counted.includes(c.tool) ? "" : "write a probes: entry to call it";
  if (c.source === "override" && !c.excluded) return `it is overridden to class ${c.class}, which no pack probes${probe ? `; ${probe}` : ""}`;
  if (c.unfillable.length) {
    // The classifier's own reason for an opaque tool already names the parameters; do not say it twice.
    const said = c.reasons.some((r) => /cannot be filled by the harness/.test(r));
    const own = said ? "" : `its required parameter${c.unfillable.length > 1 ? "s" : ""} ${c.unfillable.map((u) => `"${u}"`).join(", ")} cannot be filled by the harness`;
    return [own, probe].filter(Boolean).join("; ");
  }
  // Nothing to put under tools: for a tool that takes no parameters: no class would make a pack able to call it.
  if (c.reasons.includes(NO_PARAMETERS)) return "";
  return "add it under tools: to include it";
}

/** `why; hint`, or just `why` when there is no hint. */
const withHint = (why: string, hint: string): string => (hint ? `${why}; ${hint}` : why);

/**
 * Lines for RunResult.notCovered: every tool that only the core checks reached. `counted` names the tools a counted `probes:` entry
 * already called (the harness knows; default none): they are not told to write one.
 */
export function coreOnlyNotes(rows: ToolClassification[], counted: readonly string[] = [], max = 12): string[] {
  const lines = rows.flatMap((c) => {
    const why = coreOnlyReason(c);
    return why ? [`tool "${c.tool}" is covered by the core checks only: ${withHint(why, coreOnlyHint(c, counted))}`] : [];
  });
  if (lines.length <= max) return lines;
  return [...lines.slice(0, max), `${lines.length - max} more tool(s) are covered by the core checks only (see the classification)`];
}

// ---- report rows ---------------------------------------------------------------------------------------

function tags(a: ToolAnnotations | undefined): string {
  if (!a) return "";
  const t: string[] = [];
  if (a.readOnlyHint) t.push("readOnly");
  if (a.destructiveHint) t.push("destructive");
  if (a.idempotentHint) t.push("idempotent");
  if (a.openWorldHint === false) t.push("closedWorld");
  else if (a.openWorldHint) t.push("openWorld");
  return t.length ? `[${t.join(", ")}]` : "";
}

/**
 * The text `Classification:` block: one line per tool (`read_text_file  path  high  [readOnly]  ← param "path", name matches /read|file/`),
 * core-only tools say why, and the last line lists the packs that applied when the caller knows them.
 */
export function classificationBlock(rows: ToolClassification[], packsApplied?: PackId[], counted: readonly string[] = []): string[] {
  const out = ["Classification:"];
  if (!rows.length) out.push("  (the server declares no tools)");
  const w = (f: (c: ToolClassification) => string) => Math.max(0, ...rows.map((c) => f(c).length));
  const wt = w((c) => c.tool);
  const wc = w((c) => c.class);
  const wf = w((c) => c.confidence);
  const wa = w((c) => tags(c.annotations));
  for (const c of rows) {
    const why = coreOnlyReason(c);
    const tail = why ? `core only: ${withHint(why, coreOnlyHint(c, counted))}` : `← ${c.reasons.join(", ")}`;
    out.push(`  ${[c.tool.padEnd(wt), c.class.padEnd(wc), c.confidence.padEnd(wf), tags(c.annotations).padEnd(wa), tail].filter((x, i) => i !== 3 || wa > 0).join("  ")}`);
  }
  if (packsApplied) out.push(`  packs applied: ${packsApplied.length ? packsApplied.join(", ") : "none"}`);
  return out;
}

// ---- filling arguments ---------------------------------------------------------------------------------

/**
 * Build the arguments for a call from classified values (`{ path: "…/ok.txt" }`) plus harmless fillers for every other
 * required parameter: strings get `token`, string arrays `[token]`, enums their first value, booleans (also a boolean-or-string union) false, numbers their
 * default, minimum or 1. Returns undefined when the tool has an unfillable required parameter. Optional parameters are left unset.
 */
export function fillArgs(tool: ToolInfo, c: ToolClassification, values: Partial<Record<ParamRole, string | string[]>>, token: string): Record<string, unknown> | undefined {
  if (c.unfillable.length) return undefined;
  const s = shapeOf(tool);
  const args: Record<string, unknown> = {};
  for (const [role, v] of Object.entries(values) as [ParamRole, string | string[]][]) {
    const name = c.params[role];
    if (name === undefined || !s.props[name]) continue;
    args[name] = s.kind[name] === "stringArray" ? [v].flat() : Array.isArray(v) ? v[0] : v;
  }
  for (const n of (tool.inputSchema?.required ?? []) as string[]) {
    if (n in args) continue;
    const p = s.props[n];
    if (!p) continue;
    const v = fillOne(p, s.kind[n]!, token);
    if (v !== undefined) args[n] = v;
  }
  return args;
}

/** A harmless value for one parameter of the given kind, or undefined when the harness has none. Objects are built from their required properties. */
function fillOne(p: Prop, kind: Kind, token: string): unknown {
  if (p.default !== undefined) return p.default;
  // A boolean is a member of a boolean-or-string union and a harness token is not: some servers accept only true or false there.
  if (kind !== "enum" && typesOf(p).includes("boolean")) return false;
  switch (kind) {
    case "string":
      return token;
    case "stringArray":
      return [token];
    case "enum":
      return Array.isArray(p.enum) ? p.enum[0] : p.const;
    case "enumArray":
      return [itemsOf(p)?.enum?.[0]];
    case "boolean":
      return false;
    case "number":
      return typeof p.minimum === "number" ? p.minimum : 1;
    case "object":
      return fillObject(p, token);
    case "objectArray":
      return [fillObject(itemsOf(p), token)];
    default:
      return undefined;
  }
}

/** An object with every required property filled (optional ones are left out): the one-level object the classifier called fillable. */
function fillObject(o: Prop | undefined, token: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const props = (o?.properties ?? {}) as Record<string, Prop>;
  for (const r of fillNames(o)) {
    if (!props[r]) continue;
    const v = fillOne(props[r]!, kindOf(props[r]), token);
    if (v !== undefined) out[r] = v;
  }
  return out;
}
