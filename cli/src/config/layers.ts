import { MERGEABLE_PATHS, SCHEMA, defaults, leafByPath } from "./schema.js";
import type { LayerKind, Origin } from "./model.js";
import { deepClone, isPlainObject, pointer, uniqueBy, type PathSeg } from "./util.js";

/** One validated source of configuration, ready to merge. */
export interface Layer {
  kind: LayerKind;
  /** Display name of the whole layer: a file path, `profile:quick`, `env`, `flags`. */
  source: string;
  data: Record<string, unknown>;
  /** Line numbers by JSON pointer (files only). Looked up by the leaf or its nearest ancestor. */
  lines: Map<string, number>;
  /** Per-leaf source text overriding `source` (env var and flag names), by JSON pointer. */
  sources: Map<string, string>;
}

export const newLayer = (kind: LayerKind, source: string, data: Record<string, unknown> = {}): Layer => ({ kind, source, data, lines: new Map(), sources: new Map() });

function originFor(layer: Layer, path: readonly PathSeg[]): Origin {
  const sources = layer.sources;
  let line: number | undefined;
  let src: string | undefined;
  for (let n = path.length; n > 0 && (line === undefined || src === undefined); n--) {
    const ptr = pointer(path.slice(0, n));
    if (src === undefined) src = sources.get(ptr);
    if (line === undefined) line = layer.lines.get(ptr);
  }
  return { layer: layer.kind, source: src ?? layer.source, ...(line !== undefined ? { line } : {}) };
}

function dropOrigins(origins: Map<string, Origin>, ptr: string): void {
  for (const k of [...origins.keys()]) if (k === ptr || k.startsWith(`${ptr}/`)) origins.delete(k);
}

function applyLayer(acc: Record<string, unknown>, origins: Map<string, Origin>, data: Record<string, unknown>, path: string[], layer: Layer): void {
  for (const [k, v] of Object.entries(data)) {
    const p = [...path, k];
    const leaf = v === null ? leafByPath(p.join(".")) : undefined;
    if (leaf?.nullable && leaf.default !== null) {
      // The exception: a nullable setting whose default is not null (output.exit_policy.fail_under, default A) keeps an explicit null,
      // because falling back to the default would make "off" impossible to ask for.
      acc[k] = null;
      origins.set(pointer(p), originFor(layer, p));
    } else if (v === null) {
      // null deletes the key: the value falls back to what lower layers (or the default) provide
      delete acc[k];
      dropOrigins(origins, pointer(p));
    } else if (isPlainObject(v)) {
      if (!isPlainObject(acc[k])) {
        acc[k] = {};
        dropOrigins(origins, pointer(p));
      }
      applyLayer(acc[k] as Record<string, unknown>, origins, v, p, layer);
    } else if (Array.isArray(v)) {
      const prev = acc[k];
      acc[k] = MERGEABLE_PATHS.has(p.join(".")) && Array.isArray(prev) ? uniqueBy([...prev, ...deepClone(v)]) : deepClone(v);
      origins.set(pointer(p), originFor(layer, p));
    } else {
      acc[k] = v;
      origins.set(pointer(p), originFor(layer, p));
    }
  }
}

function overlay(base: Record<string, unknown>, top: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(top)) out[k] = isPlainObject(v) && isPlainObject(out[k]) ? overlay(out[k] as Record<string, unknown>, v) : v;
  return out;
}

export interface Merged {
  value: Record<string, unknown>;
  origins: Map<string, Origin>;
}

/**
 * Merges layers lowest to highest, then puts the result over the built-in defaults.
 * Scalars replace; maps merge key-wise; lists replace except `mergeable` ones, which append and de-duplicate;
 * `null` deletes a key (so the value falls back to a lower layer or the default), except on a nullable setting with a non-null default, where null is a value of its own.
 */
export function mergeLayers(layers: readonly Layer[]): Merged {
  const acc: Record<string, unknown> = {};
  const origins = new Map<string, Origin>();
  for (const layer of layers) applyLayer(acc, origins, layer.data, [], layer);
  const value = overlay(defaults(), acc);
  const dflt: Origin = { layer: "default", source: "default" };
  for (const l of SCHEMA) {
    if (l.default === undefined || l.path.includes("*")) continue;
    const ptr = pointer(l.path.split("."));
    if (!origins.has(ptr)) origins.set(ptr, dflt);
  }
  return { value, origins };
}

/** Display text of an origin: `sealmark.yaml:17`, `profile:standard`, `env SEALMARK_X`, `flag --timeout-probe`, `default`. */
export function originText(o: Origin | undefined): string {
  if (!o) return "default";
  return o.line !== undefined ? `${o.source}:${o.line}` : o.source;
}
