import { readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { LineCounter, isMap, isScalar, isSeq, parseDocument, type Document } from "yaml";
import { newLayer, type Layer } from "./layers.js";
import { SCHEMA_VERSION, type LayerKind } from "./model.js";
import { PROFILE_FORBIDDEN_TOP, TREE, type Leaf, type SchemaNode } from "./schema.js";
import { describeValue, didYouMean, dotted, isPlainObject, pointer, type PathSeg } from "./util.js";
import { validateShape, type Problem } from "./validators.js";

/** What a validation pass needs to know about where values come from. */
export interface VCtx {
  kind: LayerKind;
  /** Location prefix for a problem: `sealmark.yaml:12`, `env SEALMARK_X`, `--timeout-probe`. */
  where(path: readonly PathSeg[], onKey?: boolean): string;
  /** Files name the setting in each message; env and flags already name it in the prefix. */
  showPath: boolean;
  issues: string[];
  /** Line of a path in the source file, when there is one. */
  locate?: (path: readonly PathSeg[], onKey?: boolean) => number | undefined;
  lines: Map<string, number>;
  profileBody?: boolean;
}

export function report(problems: readonly Problem[], ctx: VCtx): void {
  for (const p of problems) {
    ctx.issues.push(`${ctx.where(p.path, p.onKey)}: ${ctx.showPath && !p.onKey ? `${dotted(p.path)}: ` : ""}${p.message}`);
  }
}

function note(ctx: VCtx, path: readonly PathSeg[], value: unknown): void {
  if (!ctx.locate) return;
  const line = ctx.locate(path);
  if (line !== undefined) ctx.lines.set(pointer(path), line);
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      const l = ctx.locate([...path, k], true);
      if (l !== undefined) ctx.lines.set(pointer([...path, k]), l);
    }
  }
}

/** Validates one leaf value. Used by files, env and flags alike, so a bad value reads the same everywhere. */
export function validateLeaf(leaf: Leaf, v: unknown, path: readonly PathSeg[], ctx: VCtx): unknown {
  if (leaf.flagOnly && ctx.kind !== "flag") {
    const flag = `--${leaf.path.replace(/_/g, "-")}`;
    ctx.issues.push(`${ctx.where(path, true)}: ${leaf.path} can only be set with ${flag} on the command line, never from files or environment`);
    return undefined;
  }
  const problems: Problem[] = [];
  const r = validateShape(leaf.shape, v, [...path], problems);
  if (problems.length) {
    report(problems, ctx);
    return undefined;
  }
  note(ctx, path, r);
  return r;
}

function validateNode(node: SchemaNode, v: unknown, path: PathSeg[], ctx: VCtx): unknown {
  if (v === null) return null; // delete / reset to default
  if (node.leaf) return validateLeaf(node.leaf, v, path, ctx);
  if (!isPlainObject(v)) {
    ctx.issues.push(`${ctx.where(path)}: ${dotted(path)}: expected a mapping, got ${describeValue(v)}`);
    return undefined;
  }
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v)) {
    const child = node.children.get(k) ?? node.wildcard;
    if (!child) {
      const hint = didYouMean(k, node.children.keys());
      ctx.issues.push(`${ctx.where([...path, k], true)}: unknown key "${k}"${path.length ? ` under ${dotted(path)}` : ""}${hint ? `; did you mean "${hint}"?` : ""}`);
      continue;
    }
    const r = validateNode(child, val, [...path, k], ctx);
    if (r !== undefined) out[k] = r;
  }
  return out;
}

export interface ProfileDef {
  name: string;
  extends?: string;
  description?: string;
  data: Record<string, unknown>;
  /** Layer holding the validated body, with the positions of the file that defined it. */
  layer: Layer;
}

export interface Validated {
  data: Record<string, unknown>;
  profiles: ProfileDef[];
  extends?: string;
  description?: string;
}

/**
 * Validates a whole document (or a profile body when `ctx.profileBody`). Collects every problem in `ctx.issues`.
 * `base` is the path of the document inside its file (a profile body lives at ["profiles", name]).
 */
export function validateRoot(raw: unknown, ctx: VCtx, base: PathSeg[] = [], layerFor?: (name: string) => Layer): Validated {
  const res: Validated = { data: {}, profiles: [] };
  if (!isPlainObject(raw)) {
    ctx.issues.push(`${ctx.where(base)}: ${base.length ? `${dotted(base)}: ` : ""}expected a mapping, got ${describeValue(raw)}`);
    return res;
  }
  const body: Record<string, unknown> = { ...raw };
  if (ctx.profileBody) {
    for (const key of ["extends", "description"] as const) {
      if (!(key in body)) continue;
      const val = body[key];
      delete body[key];
      if (val === null || val === undefined) continue;
      if (typeof val !== "string") ctx.issues.push(`${ctx.where([...base, key])}: ${dotted([...base, key])}: expected a string, got ${describeValue(val)}`);
      else res[key] = val;
    }
    for (const key of Object.keys(body)) {
      if (PROFILE_FORBIDDEN_TOP.has(key)) {
        ctx.issues.push(`${ctx.where([...base, key], true)}: "${key}" cannot be set inside a profile (a profile describes how to run, not one project)`);
        delete body[key];
      }
    }
  } else if ("profiles" in body) {
    const profiles = body.profiles;
    delete body.profiles;
    if (profiles !== null) {
      if (!isPlainObject(profiles)) ctx.issues.push(`${ctx.where(["profiles"])}: profiles: expected a mapping of name to profile, got ${describeValue(profiles)}`);
      else {
        for (const [name, pbody] of Object.entries(profiles)) {
          if (pbody === null) continue;
          const layer = layerFor ? layerFor(name) : newLayer("profile", `profile:${name}`);
          const inner: VCtx = { ...ctx, profileBody: true, lines: layer.lines };
          const v = validateRoot(pbody, inner, ["profiles", name]);
          layer.data = v.data;
          res.profiles.push({ name, extends: v.extends, description: v.description, data: v.data, layer });
        }
      }
    }
  }
  // Keep the root-level path for messages: validateNode builds paths from `base`.
  const cleaned = validateNode(TREE, body, [...base], ctx);
  res.data = isPlainObject(cleaned) ? cleaned : {};
  return res;
}

// ---- files ----

/** A path as shown in messages: relative to cwd when inside it, else as given. */
export function displayPath(path: string, cwd: string): string {
  const inside = (r: string) => Boolean(r) && !r.startsWith("..") && !isAbsolute(r);
  let rel = relative(cwd, path);
  if (!inside(rel)) {
    // macOS keeps temp folders behind a symlink (/var -> /private/var), so a path and the cwd can name the same place
    // differently. Compare real paths before giving up and printing the whole thing.
    try {
      const real = (p: string) => {
        try {
          return realpathSync(p);
        } catch {
          return join(realpathSync(dirname(p)), basename(p)); // a file that does not exist yet
        }
      };
      rel = relative(real(cwd), real(path));
    } catch {
      /* keep the absolute path */
    }
  }
  return inside(rel) ? rel.replace(/\\/g, "/") : path;
}

function lineOf(lc: LineCounter, node: unknown): number | undefined {
  const range = (node as { range?: [number, number, number] } | null | undefined)?.range;
  return range ? lc.linePos(range[0]).line : undefined;
}

/** Line of the value at `path` (or of its key), falling back to the deepest ancestor that exists. */
function locator(doc: Document, lc: LineCounter) {
  return (path: readonly PathSeg[], onKey = false): number | undefined => {
    let node: unknown = doc.contents;
    let best = lineOf(lc, node);
    for (let i = 0; i < path.length; i++) {
      const seg = path[i];
      if (isMap(node)) {
        const pair = node.items.find((p) => isScalar(p.key) && String(p.key.value) === String(seg));
        if (!pair) return best;
        if (onKey && i === path.length - 1) return lineOf(lc, pair.key) ?? best;
        node = pair.value;
      } else if (isSeq(node)) node = node.items[Number(seg)];
      else return best;
      best = lineOf(lc, node) ?? best;
    }
    return best;
  };
}

export interface LoadedFile {
  layer: Layer;
  profiles: ProfileDef[];
  warnings: string[];
  display: string;
  /** Profile bodies only: the `extends` and `description` header keys. */
  extends?: string;
  description?: string;
}

/**
 * Reads, parses and validates one config file. Returns undefined when `optional` and the file is absent.
 * Problems are appended to `issues`; the caller throws once everything has been collected.
 */
export function loadFile(path: string, kind: "user" | "project" | "local", o: { cwd: string; optional: boolean; issues: string[] }): LoadedFile | undefined {
  const display = displayPath(path, o.cwd);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (o.optional && (code === "ENOENT" || code === "ENOTDIR")) return undefined;
    o.issues.push(code === "ENOENT" || code === "ENOTDIR" ? `Cannot read ${display}. Run "sealmark init" to create one.` : `Cannot read ${display}: ${(e as Error).message}`);
    return undefined;
  }
  return parseConfigText(text.replace(/^﻿/, ""), display, kind, o.issues);
}

/** Same as loadFile for text already in memory (tests, migrations). */
export function parseConfigText(
  text: string,
  display: string,
  kind: "user" | "project" | "local" | "profile",
  issues: string[],
  o: { profileBody?: boolean; source?: string } = {},
): LoadedFile | undefined {
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, prettyErrors: false });
  const layer = newLayer(kind, o.source ?? display);
  const warnings: string[] = [];
  if (doc.errors.length) {
    for (const e of doc.errors) {
      const line = e.pos ? lc.linePos(e.pos[0]).line : undefined;
      issues.push(`${display}${line ? `:${line}` : ""}: ${e.message.split("\n")[0]}`);
    }
    return undefined;
  }
  const raw: unknown = doc.toJS();
  if (raw === null || raw === undefined) {
    if (kind === "project") issues.push(`${display} is empty.`);
    return { layer, profiles: [], warnings, display };
  }
  const locate = locator(doc, lc);
  const where = (path: readonly PathSeg[], onKey = false) => {
    const line = locate(path, onKey);
    return line !== undefined ? `${display}:${line}` : display;
  };
  const ctx: VCtx = { kind, where, showPath: true, issues, locate, lines: layer.lines, profileBody: o.profileBody };

  if (!o.profileBody && isPlainObject(raw) && raw.schema_version !== undefined && typeof raw.schema_version === "number" && Number.isInteger(raw.schema_version)) {
    const sv = raw.schema_version;
    if (sv > SCHEMA_VERSION) {
      issues.push(`${where(["schema_version"])}: schema_version ${sv} is newer than this sealmark understands (${SCHEMA_VERSION}); upgrade sealmark`);
      return undefined;
    }
    if (sv < SCHEMA_VERSION) {
      issues.push(`${where(["schema_version"])}: schema_version ${sv} is older than ${SCHEMA_VERSION}; run "sealmark config migrate ${display}" to upgrade the file`);
      return undefined;
    }
  } else if (!o.profileBody && kind === "project" && isPlainObject(raw) && raw.schema_version === undefined) {
    warnings.push(`${display}: no schema_version; reading it as ${SCHEMA_VERSION} (add "schema_version: ${SCHEMA_VERSION}" or run "sealmark config migrate")`);
  }

  const v = validateRoot(raw, ctx, [], (name) => newLayer("profile", `profile:${name}`));
  layer.data = v.data;
  for (const p of v.profiles) p.layer.lines.clear();
  return { layer, profiles: v.profiles, warnings, display, extends: v.extends, description: v.description };
}
