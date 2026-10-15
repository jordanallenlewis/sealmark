import { dbPlaceholders } from "./placeholders.js";
import { describeValue, didYouMean, dotted, isPlainObject, type PathSeg } from "./util.js";

/** A problem found while validating a value. `path` points at the offending value (or at the key when `onKey`). */
export interface Problem {
  path: PathSeg[];
  message: string;
  onKey?: boolean;
}

/**
 * One small description of a value's shape. The validator, the env/flag text coercion and the JSON Schema
 * are all derived from it, so they cannot drift.
 */
export type Shape =
  | { k: "string"; coerce?: boolean; nonEmpty?: boolean; pattern?: RegExp; patternHint?: string }
  | { k: "int"; min?: number; max?: number }
  | { k: "num"; min?: number; max?: number; exclusiveMin?: boolean }
  | { k: "bool" }
  | { k: "enum"; values: readonly string[] }
  | { k: "array"; item: Shape; minItems?: number; scalar?: boolean }
  | { k: "object"; fields: Record<string, Shape>; required?: string[] }
  | { k: "map"; value: Shape }
  | { k: "any" }
  | { k: "scalar" }
  | { k: "custom"; base: Shape; check: (v: unknown, path: PathSeg[], out: Problem[]) => void };

const bad = (out: Problem[], path: PathSeg[], message: string, onKey = false) => out.push({ path, message, ...(onKey ? { onKey } : {}) });

function range(out: Problem[], path: PathSeg[], v: number, min?: number, max?: number, exclusiveMin?: boolean): boolean {
  if (min !== undefined && (exclusiveMin ? v <= min : v < min)) {
    bad(out, path, max !== undefined ? `must be between ${min} and ${max}, got ${v}` : exclusiveMin ? `must be greater than ${min}, got ${v}` : `must be at least ${min}, got ${v}`);
    return false;
  }
  if (max !== undefined && v > max) {
    bad(out, path, min !== undefined ? `must be between ${min} and ${max}, got ${v}` : `must be at most ${max}, got ${v}`);
    return false;
  }
  return true;
}

/** Validates `v` against `shape`, appending problems to `out`. Returns the value with scalar coercions applied (undefined when invalid). */
export function validateShape(shape: Shape, v: unknown, path: PathSeg[], out: Problem[]): unknown {
  switch (shape.k) {
    case "string": {
      let s: string;
      if (typeof v === "string") s = v;
      else if (shape.coerce && (typeof v === "number" || typeof v === "boolean")) s = String(v);
      else return void bad(out, path, `expected a string, got ${describeValue(v)}`);
      if (shape.nonEmpty && !s.trim()) return void bad(out, path, "must not be empty");
      if (shape.pattern && !shape.pattern.test(s)) return void bad(out, path, `${shape.patternHint ?? `must match ${shape.pattern}`}, got ${JSON.stringify(s)}`);
      return s;
    }
    case "int":
      if (typeof v !== "number" || !Number.isInteger(v)) return void bad(out, path, `expected an integer, got ${describeValue(v)}`);
      return range(out, path, v, shape.min, shape.max) ? v : undefined;
    case "num":
      if (typeof v !== "number" || !Number.isFinite(v)) return void bad(out, path, `expected a number, got ${describeValue(v)}`);
      return range(out, path, v, shape.min, shape.max, shape.exclusiveMin) ? v : undefined;
    case "bool":
      if (typeof v !== "boolean") return void bad(out, path, `expected true or false, got ${describeValue(v)}`);
      return v;
    case "enum": {
      if (typeof v === "string" && shape.values.includes(v)) return v;
      const hint = typeof v === "string" ? didYouMean(v, shape.values) : undefined;
      return void bad(out, path, `expected one of ${shape.values.join(", ")}, got ${describeValue(v)}${hint ? `; did you mean "${hint}"?` : ""}`);
    }
    case "array": {
      // `scalar` lets a one-item list be written as the bare value (`fail_on: regressions`); null stays an error, so a reset is not read as an item.
      if (shape.scalar && v !== undefined && v !== null && !Array.isArray(v)) v = [v];
      if (!Array.isArray(v)) return void bad(out, path, `expected a list, got ${describeValue(v)}`);
      if (shape.minItems !== undefined && v.length < shape.minItems) bad(out, path, `needs at least ${shape.minItems} item${shape.minItems === 1 ? "" : "s"}`);
      return v.map((item, i) => validateShape(shape.item, item, [...path, i], out));
    }
    case "object": {
      if (!isPlainObject(v)) return void bad(out, path, `expected a mapping, got ${describeValue(v)}`);
      const res: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(v)) {
        const field = shape.fields[key];
        if (!field) {
          const hint = didYouMean(key, Object.keys(shape.fields));
          bad(out, [...path, key], `unknown key "${key}"${path.length ? ` under ${dotted(path)}` : ""}${hint ? `; did you mean "${hint}"?` : ""}`, true);
          continue;
        }
        const r = validateShape(field, val, [...path, key], out);
        if (r !== undefined) res[key] = r;
      }
      for (const req of shape.required ?? []) if (!(req in v)) bad(out, path, `missing required key "${req}"`);
      return res;
    }
    case "map": {
      if (!isPlainObject(v)) return void bad(out, path, `expected a mapping, got ${describeValue(v)}`);
      const res: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(v)) {
        if (val === null) res[key] = null; // null deletes the key in a lower layer
        else {
          const r = validateShape(shape.value, val, [...path, key], out);
          if (r !== undefined) res[key] = r;
        }
      }
      return res;
    }
    case "any":
      return v;
    case "scalar":
      // A string, a number or a boolean as written: no coercion (a tool parameter must receive the type the user meant).
      if (typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v))) return v;
      return void bad(out, path, `expected a string, a number or true/false, got ${describeValue(v)}`);
    case "custom": {
      const n = out.length;
      const r = validateShape(shape.base, v, path, out);
      if (out.length === n) shape.check(r, path, out);
      return r;
    }
  }
}

/** JSON Schema (draft-07) for a shape. */
export function shapeToJsonSchema(shape: Shape): Record<string, unknown> {
  switch (shape.k) {
    case "string":
      return { type: shape.coerce ? ["string", "number", "boolean"] : "string", ...(shape.nonEmpty ? { minLength: 1 } : {}), ...(shape.pattern ? { pattern: shape.pattern.source } : {}) };
    case "int":
      return { type: "integer", ...(shape.min !== undefined ? { minimum: shape.min } : {}), ...(shape.max !== undefined ? { maximum: shape.max } : {}) };
    case "num":
      return { type: "number", ...(shape.min !== undefined ? (shape.exclusiveMin ? { exclusiveMinimum: shape.min } : { minimum: shape.min }) : {}), ...(shape.max !== undefined ? { maximum: shape.max } : {}) };
    case "bool":
      return { type: "boolean" };
    case "enum":
      return { enum: [...shape.values] };
    case "array": {
      const list = { type: "array", items: shapeToJsonSchema(shape.item), ...(shape.minItems ? { minItems: shape.minItems } : {}) };
      return shape.scalar ? { oneOf: [list, shapeToJsonSchema(shape.item)] } : list;
    }
    case "object":
      return {
        type: "object",
        properties: Object.fromEntries(Object.entries(shape.fields).map(([k, s]) => [k, shapeToJsonSchema(s)])),
        ...(shape.required?.length ? { required: shape.required } : {}),
        additionalProperties: false,
      };
    case "map":
      return { type: "object", additionalProperties: { oneOf: [shapeToJsonSchema(shape.value), { type: "null" }] } };
    case "any":
      return {};
    case "scalar":
      return { type: ["string", "number", "boolean"] };
    case "custom":
      return shapeToJsonSchema(shape.base);
  }
}

// ---- shared small shapes ----

export const str: Shape = { k: "string" };
export const strCoerced: Shape = { k: "string", coerce: true };
export const bool: Shape = { k: "bool" };
export const strings: Shape = { k: "array", item: str };

/** Parses a string into the closest type for a shape, so env and flag text goes through the same validator as YAML. Returns the text unchanged when it cannot be converted. */
export function coerceText(shape: Shape, text: string): unknown {
  const t = text.trim();
  switch (shape.k) {
    case "bool": {
      if (/^(true|1|yes|on)$/i.test(t)) return true;
      if (/^(false|0|no|off)$/i.test(t)) return false;
      return text;
    }
    case "int":
    case "num": {
      if (t === "") return text;
      const n = Number(t);
      return Number.isFinite(n) ? n : text;
    }
    case "array": {
      if (t.startsWith("[")) {
        try {
          const j: unknown = JSON.parse(t);
          if (Array.isArray(j)) return j;
        } catch {
          /* fall through to comma list */
        }
      }
      if (t === "") return [];
      return t.split(",").map((s) => coerceText(shape.item, s.trim()));
    }
    case "map":
    case "object":
    case "any": {
      try {
        const j: unknown = JSON.parse(t);
        return j;
      } catch {
        return text;
      }
    }
    case "custom":
      return coerceText(shape.base, text);
    default:
      return text;
  }
}

// ---- address rules for network corpus entries ----

/** inet_aton-style parse ("127.1", "0x7f000001", "2130706433"); undefined when not an IPv4 literal. */
function parseIpv4Loose(host: string): number | undefined {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return undefined;
  const nums = parts.map((p) => (/^(0x[0-9a-f]+|\d+)$/i.test(p) ? Number(p) : NaN));
  if (nums.some((n) => !Number.isFinite(n))) return undefined;
  const last = nums[nums.length - 1];
  const head = nums.slice(0, -1);
  if (head.some((n) => n > 255) || last >= 256 ** (4 - head.length)) return undefined;
  return head.reduce((acc, n, i) => acc + n * 256 ** (3 - i), 0) + last;
}

/** Hosts the harness may aim a network probe at: loopback in any spelling, `localhost`, or a placeholder the harness fills with its own listener. */
export function isHarnessHost(hostRaw: string): boolean {
  const host = hostRaw.replace(/^\[|\]$/g, "").toLowerCase();
  if (host.includes("{")) return true;
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1" || host === "0:0:0:0:0:0:0:1" || host === "::ffff:127.0.0.1") return true;
  const n = parseIpv4Loose(host);
  return n !== undefined && (n === 0 || Math.floor(n / 2 ** 24) === 127);
}

function checkNetEntry(v: unknown, path: PathSeg[], out: Problem[]): void {
  const s = String(v);
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)/i.exec(s);
  if (m && !isHarnessHost(m[1])) {
    bad(out, path, `host "${m[1]}" is not loopback; network corpus entries may only target the harness listener (link-local, private and public addresses are never contacted)`);
  }
}

const LITERAL_TARGET = /^([A-Za-z]:[\\/]|[\\/]{2}|\/|~|file:)/;

function checkLiteralTarget(v: unknown, path: PathSeg[], out: Problem[]): void {
  const s = String(v);
  if (LITERAL_TARGET.test(s) && !s.includes("{")) bad(out, path, `literal target ${JSON.stringify(s)}; corpus entries must use {sandbox}, {sandbox_home} or {canary} so every target is harness-owned`);
}

/** Shape of one `corpus.add` entry for a check. */
export function corpusAddShape(checkId: string): Shape {
  if (checkId === "mutating-sql" || checkId === "sqlite-mutating-sql") {
    return {
      k: "object",
      fields: {
        id: { k: "string", nonEmpty: true, pattern: /^[A-Za-z0-9._-]+$/, patternHint: "id may use letters, digits, . _ -" },
        core: bool,
        steps: { k: "array", item: { k: "string", nonEmpty: true }, minItems: 1 },
        executed: { k: "string", pattern: /^(probe_row:\d+|table_exists:[A-Za-z_][A-Za-z0-9_]*)$/, patternHint: "executed must be probe_row:<id> or table_exists:<name> (the harness's own state readers; a custom case can never require code)" },
      },
      required: ["id", "steps", "executed"],
    };
  }
  if (checkId.startsWith("net-")) return { k: "custom", base: { k: "string", nonEmpty: true }, check: checkNetEntry };
  if (/^(fs|git|exec)-/.test(checkId)) return { k: "custom", base: { k: "string", nonEmpty: true }, check: checkLiteralTarget };
  return { k: "string", nonEmpty: true };
}

// ---- structured leaves ----

/**
 * One `sql_tools` entry. `args` carries the values for the tool's other required parameters (a tool that also needs a `database` or a
 * `mode`); scalars only, and never the SQL argument itself, which the harness fills. Whether each key is a parameter of the tool is
 * known only once the server's tool list is read, so that check belongs to the run.
 */
export const SQL_TOOL_SHAPE: Shape = {
  k: "custom",
  base: {
    k: "object",
    fields: {
      tool: { k: "string", nonEmpty: true },
      arg: { k: "string", nonEmpty: true },
      role: { k: "enum", values: ["reader", "writer", "unknown"] },
      shape: { k: "enum", values: ["string", "array"] },
      args: { k: "map", value: { k: "scalar" } },
    },
    required: ["tool", "arg"],
  },
  check: (v, path, out) => {
    const e = v as { arg?: string; args?: Record<string, unknown> };
    if (e.args && e.arg !== undefined && Object.hasOwn(e.args, e.arg)) bad(out, [...path, "args", e.arg], `"${e.arg}" is the SQL argument the harness fills; args holds the tool's other parameters`);
  },
};

export const TOOL_CLASSES = ["sql", "path", "url", "command", "git", "text", "opaque"] as const;

export const TOOL_OVERRIDE_SHAPE: Shape = {
  k: "object",
  fields: { class: { k: "enum", values: TOOL_CLASSES }, params: { k: "map", value: str } },
  required: ["class"],
};

const STAGED_PATH = /^\{(sandbox|sandbox_home|dir)\}/;

function checkStagedPath(v: unknown, path: PathSeg[], out: Problem[]): void {
  if (!STAGED_PATH.test(String(v))) bad(out, path, "staged files are written only inside the sandbox; start the path with {sandbox} or {sandbox_home}");
}

function checkStagedContent(v: unknown, path: PathSeg[], out: Problem[]): void {
  if (dbPlaceholders().test(String(v))) {
    bad(out, path, "server.files cannot carry database placeholders: the server is started once per database role, and a file cannot change between roles; pass the connection string through args or env");
  }
}

/** One staged file: where it goes (inside the sandbox) and what it holds. A file cannot change between database roles, so database placeholders are refused. */
export const STAGED_FILES_SHAPE: Shape = {
  k: "array",
  item: {
    k: "object",
    fields: { path: { k: "custom", base: str, check: checkStagedPath }, content: { k: "custom", base: str, check: checkStagedContent } },
    required: ["path", "content"],
  },
};

export const PLUGIN_SHAPE: Shape = {
  k: "object",
  fields: { module: { k: "string", nonEmpty: true }, options: { k: "map", value: { k: "any" } } },
  required: ["module"],
};

const SANDBOX_REF = /^\{(sandbox|sandbox_home|canary|dir)\}/;

function checkRegex(v: unknown, path: PathSeg[], out: Problem[]): void {
  try {
    new RegExp(String(v));
  } catch (e) {
    bad(out, path, `not a valid regular expression: ${(e as Error).message}`);
  }
}

function checkSandboxPath(v: unknown, path: PathSeg[], out: Problem[]): void {
  if (!SANDBOX_REF.test(String(v))) bad(out, path, `custom probes observe only the sandbox; start with {sandbox}, {sandbox_home} or {canary}, got ${JSON.stringify(String(v))}`);
}

const sandboxPaths: Shape = { k: "array", item: { k: "custom", base: str, check: checkSandboxPath } };
const regex: Shape = { k: "custom", base: str, check: checkRegex };
/** A list of regular expressions (checks.refusal-quality.patterns, checks.instructions-hygiene.deny). */
export const regexList: Shape = { k: "array", item: regex };

/** A HTTP header name as a map key is checked where the map is read; here only the value shape. */
const scalars: Shape = { k: "array", item: { k: "scalar" }, minItems: 1 };

/**
 * A scripted reply of the upstream stub (round 6, `upstream.default_reply`, `upstream.responses[].reply`, `probes[].upstream.reply`).
 * Exactly one of `body`, `json` or `bytes`; a `bytes` reply may also carry `body` as the prefix it is padded after.
 */
export const UPSTREAM_REPLY_SHAPE: Shape = {
  k: "custom",
  base: {
    k: "object",
    fields: {
      status: { k: "int", min: 100, max: 599 },
      headers: { k: "map", value: strCoerced },
      body: str,
      json: { k: "any" },
      bytes: { k: "int", min: 1 },
      delay_ms: { k: "int", min: 0 },
    },
  },
  check: (v, path, out) => {
    const r = v as Record<string, unknown>;
    const has = (k: string) => Object.hasOwn(r, k);
    const ok = has("json") ? !has("body") && !has("bytes") : has("body") || has("bytes");
    if (!ok) bad(out, path, "reply needs exactly one of body, json or bytes (a bytes reply may also give body as its prefix)");
  },
};

/** One `upstream.responses` entry: which requests it answers (all given parts must hold; none means every request) and what it answers. */
export const UPSTREAM_RESPONSE_SHAPE: Shape = {
  k: "object",
  fields: {
    id: { k: "string", nonEmpty: true },
    match: {
      k: "object",
      fields: { method: { k: "string", nonEmpty: true }, path: regex, body: regex, header: { k: "map", value: regex } },
    },
    reply: UPSTREAM_REPLY_SHAPE,
  },
  required: ["reply"],
};

/** One `scope.tools` entry: a tool and the string parameter that carries the identifier the scope applies to. */
export const SCOPE_TOOL_SHAPE: Shape = {
  k: "object",
  fields: { tool: { k: "string", nonEmpty: true }, param: { k: "string", nonEmpty: true } },
  required: ["tool", "param"],
};

/** checks.sql-guard-statements.control_sql: a harmless read, so the control proves the statement path works before the corpus is judged. */
export const CONTROL_SQL_SHAPE: Shape = {
  k: "custom",
  base: { k: "string", nonEmpty: true },
  check: (v, path, out) => {
    if (!/^\s*(select|with)\b/i.test(String(v))) bad(out, path, `control_sql must start with SELECT or WITH, got ${JSON.stringify(String(v).slice(0, 40))}`);
  },
};

const matrixRefs = (text: string): string[] => [...text.matchAll(/\{matrix\.([A-Za-z0-9_-]+)\}/g)].map((m) => m[1]);

/** What a probe expects. Round 6 adds `upstream` (what the stub saw), `log` (what the server printed) and `response.max_bytes`. */
const EXPECT_SHAPE: Shape = {
  k: "object",
  fields: {
    is_error: bool,
    text: { k: "object", fields: { matches: regex, not_matches: regex } },
    files: { k: "object", fields: { unchanged: sandboxPaths, created: sandboxPaths, absent: sandboxPaths } },
    listener: { k: "enum", values: ["none", "hit", "any"] },
    duration_ms: { k: "object", fields: { max: { k: "int", min: 1 } } },
    upstream: {
      k: "object",
      fields: {
        requests: { k: "enum", values: ["none", "any"] },
        none_matching: regex,
        all_matching: regex,
        header: { k: "map", value: { k: "object", fields: { equals: str, matches: regex } } },
        token_echoed: bool,
      },
    },
    log: { k: "object", fields: { matches: regex, not_matches: regex } },
    response: { k: "object", fields: { max_bytes: { k: "int", min: 1 } } },
  },
};

export const PROBE_SHAPE: Shape = {
  k: "custom",
  base: {
    k: "object",
    fields: {
      id: { k: "string", nonEmpty: true },
      check: {
        k: "custom",
        base: {
          k: "object",
          fields: { id: { k: "string", nonEmpty: true }, label: { k: "string", nonEmpty: true }, critical: bool, scope: str },
          required: ["id", "label", "scope"],
        },
        check: (v, path, out) => {
          const scope = String((v as { scope?: string }).scope ?? "");
          if (!/^(server|database|environment)\b/.test(scope)) bad(out, [...path, "scope"], `scope must start with "server", "database" or "environment", got ${JSON.stringify(scope)}`);
        },
      },
      tool: { k: "string", nonEmpty: true },
      args: { k: "map", value: { k: "any" } },
      active: bool,
      timeout_ms: { k: "int", min: 1 },
      identity: { k: "enum", values: ["a", "b", "none"] },
      matrix: { k: "map", value: scalars },
      cases: {
        k: "array",
        item: { k: "object", fields: { id: { k: "string", nonEmpty: true }, args: { k: "map", value: { k: "any" } }, expect: EXPECT_SHAPE } },
        minItems: 1,
      },
      upstream: { k: "object", fields: { reply: UPSTREAM_REPLY_SHAPE }, required: ["reply"] },
      expect: EXPECT_SHAPE,
    },
    required: ["tool"],
  },
  check: (v, path, out) => {
    const p = v as { check?: unknown; id?: unknown; matrix?: Record<string, unknown>; cases?: { expect?: unknown }[]; args?: unknown; expect?: unknown };
    if (p.check !== undefined && p.id === undefined) bad(out, path, `a probe with "check" needs an "id" so its result can be matched`);
    if (p.matrix !== undefined && p.cases !== undefined) bad(out, [...path, "cases"], `"matrix" and "cases" are exclusive: use one to expand a probe`);
    if (p.cases !== undefined && p.expect === undefined) {
      p.cases.forEach((c, i) => {
        if (c && c.expect === undefined) bad(out, [...path, "cases", i], `a case needs an "expect" (or give the probe an "expect" that every case inherits)`);
      });
    }
    if (p.matrix !== undefined) {
      const text = JSON.stringify(p.args ?? {});
      const used = new Set(matrixRefs(text));
      for (const k of Object.keys(p.matrix)) {
        if (!used.has(k)) bad(out, [...path, "matrix", k], `matrix key "${k}" is not referenced by any args value; use {matrix.${k}} in args`, true);
      }
      for (const name of used) {
        if (!Object.hasOwn(p.matrix, name)) bad(out, [...path, "args"], `args uses {matrix.${name}} but matrix has no key "${name}"`);
      }
    } else if (p.args !== undefined && matrixRefs(JSON.stringify(p.args)).length) {
      bad(out, [...path, "args"], `args uses {matrix.<name>} but the probe has no "matrix"`);
    }
  },
};

export const PROBES_SHAPE: Shape = {
  k: "custom",
  base: { k: "array", item: PROBE_SHAPE },
  check: (v, path, out) => {
    const seen = new Set<string>();
    (v as { id?: string }[]).forEach((p, i) => {
      if (!p || p.id === undefined) return;
      if (seen.has(p.id)) bad(out, [...path, i, "id"], `duplicate probe id "${p.id}"`);
      seen.add(p.id);
    });
  },
};
