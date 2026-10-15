import { stringify } from "yaml";
import { originText } from "./layers.js";
import type { EffectiveConfig, Origin } from "./model.js";
import { redactValue, stripUserinfo } from "./placeholders.js";
import { findLeaf } from "./schema.js";
import { deepClone, isPlainObject, pointer } from "./util.js";

/**
 * A copy of the merged config that is safe to print: secret-looking values under server.env / headers and
 * `secret` leaves become <redacted>, URL credentials are dropped, placeholders stay unexpanded.
 */
export function redactedValue(value: Record<string, unknown>): Record<string, unknown> {
  const out = deepClone(value);
  const spec = (s: unknown) => {
    if (!isPlainObject(s)) return;
    for (const key of ["env", "headers"] as const) {
      const m = s[key];
      if (isPlainObject(m)) for (const [k, v] of Object.entries(m)) if (typeof v === "string") m[k] = redactValue(k, v);
    }
    if (typeof s.url === "string") s.url = stripUserinfo(s.url);
  };
  spec(out.server);
  if (isPlainObject(out.servers)) for (const s of Object.values(out.servers)) spec(s);
  const walk = (node: unknown, path: string[]) => {
    if (!isPlainObject(node)) return;
    for (const [k, v] of Object.entries(node)) {
      const leaf = findLeaf([...path, k]);
      if (leaf?.secret && v !== null && v !== undefined) node[k] = "<redacted>";
      else walk(v, [...path, k]);
    }
  };
  walk(out, []);
  return out;
}

const plainKey = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
const key = (k: string) => (plainKey.test(k) ? k : JSON.stringify(k));

function scalar(v: unknown): string {
  if (typeof v === "string" && /[\n\r]/.test(v)) return JSON.stringify(v);
  return stringify(v, { lineWidth: 0 }).trimEnd();
}

/** An item of a one-line `[a, b]` list: a plain scalar is only valid there without flow indicators (`[`, `]`, `{`, `}`, `,`), so a regular expression such as `use (the )?[a-z_]+ tool` is quoted. */
function flowItem(v: unknown): string {
  const s = scalar(v);
  return typeof v === "string" && /[[\]{},]/.test(s) && !/^["']/.test(s) ? JSON.stringify(v) : s;
}

function emit(node: Record<string, unknown>, path: string[], indent: string, origins: Record<string, Origin>, withOrigins: boolean, out: string[]): void {
  for (const [k, v] of Object.entries(node)) {
    const p = [...path, k];
    const comment = withOrigins ? (o: Origin | undefined) => `   # ${originText(o)}` : () => "";
    const here = comment(origins[pointer(p)]);
    if (isPlainObject(v) && Object.keys(v).length) {
      out.push(`${indent}${key(k)}:`);
      emit(v, p, `${indent}  `, origins, withOrigins, out);
    } else if (isPlainObject(v)) out.push(`${indent}${key(k)}: {}${here}`);
    else if (Array.isArray(v)) {
      if (v.every((x) => x === null || typeof x !== "object")) out.push(`${indent}${key(k)}: [${v.map(flowItem).join(", ")}]${here}`);
      else {
        out.push(`${indent}${key(k)}:${here}`);
        for (const line of stringify(v, { lineWidth: 0 }).trimEnd().split("\n")) out.push(`${indent}  ${line}`);
      }
    } else out.push(`${indent}${key(k)}: ${scalar(v)}${here}`);
  }
}

const LISTED = 8;

/**
 * The first line of `config show`: whether this configuration would produce a STANDARD run (every grade-affecting setting equals
 * the published profile) or a CUSTOM one, and which settings make it custom. A YAML comment, so the output still loads.
 */
function integrityLine(cfg: EffectiveConfig): string {
  const { standard, hash, standardDiff } = cfg.integrity;
  if (standard) return `# STANDARD: every grade-affecting setting equals the published profile (hash ${hash})`;
  const paths = standardDiff.map((d) => d.path);
  const shown = paths.slice(0, LISTED).join(", ");
  const more = paths.length > LISTED ? ` and ${paths.length - LISTED} more` : "";
  return `# CUSTOM: ${paths.length} ${paths.length === 1 ? "setting differs" : "settings differ"} from the standard profile: ${shown}${more}`;
}

/**
 * `sealmark config show [--origins] [--json]`. Text is a STANDARD or CUSTOM comment, then YAML with a trailing comment per leaf naming where
 * the value came from; JSON is { value, origins, integrity } with one origin per JSON pointer and `integrity: { standard, hash, diff }`.
 * Secrets are redacted and placeholders are never expanded.
 */
export function renderShow(cfg: EffectiveConfig, o: { origins?: boolean; json?: boolean } = {}): string {
  const value = redactedValue(cfg.value);
  if (o.json) {
    const { standard, hash, standardDiff } = cfg.integrity;
    const diff = standardDiff.map((d) => ({ path: d.path, standard: d.standard, effective: d.effective }));
    return `${JSON.stringify({ value, origins: cfg.origins, integrity: { standard, hash, diff } }, null, 2)}\n`;
  }
  const lines: string[] = [integrityLine(cfg)];
  emit(value, [], "", cfg.origins, Boolean(o.origins), lines);
  return `${lines.join("\n")}\n`;
}
