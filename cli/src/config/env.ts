import { newLayer, type Layer } from "./layers.js";
import { TREE, type Leaf, type SchemaNode } from "./schema.js";
import { dotted, didYouMean, isPlainObject, pointer, setIn } from "./util.js";
import { validateLeaf, type VCtx } from "./loader.js";
import { coerceText } from "./validators.js";

export const ENV_PREFIX = "SEALMARK_";

/** SEALMARK_* variables that are not settings: the harness's own canaries (set for the server under test) and the user-file override. */
const RESERVED = new Set(["SEALMARK_CANARY", "SEALMARK_FAKE_API_KEY", "SEALMARK_USER_CONFIG"]);

/** `init` writes `${SEALMARK_INPUT_<ID>}` for a client's `${input:id}` prompt and says to set it in the environment: those are values, not settings. */
const INPUT_PREFIX = "SEALMARK_INPUT_";

const norm = (s: string) => s.toLowerCase().replace(/-/g, "_");
const envStyle = (path: readonly string[]) => `${ENV_PREFIX}${path.map((s) => s.toUpperCase().replace(/-/g, "_")).join("__")}`;

interface Resolved {
  path: string[];
  leaf: Leaf;
  /** Key inside a map-valued leaf (SEALMARK_SERVER__ENV__FOO). */
  mapKey?: string;
}

function resolve(rest: string): Resolved | string {
  const segs = rest.split("__").filter((s) => s !== "");
  if (!segs.length) return "names no setting";
  let node: SchemaNode = TREE;
  const path: string[] = [];
  for (let i = 0; i < segs.length; i++) {
    if (node.leaf) {
      if (node.leaf.shape.k !== "map") return `${dotted(path)} is a single setting and has no sub-setting "${segs[i].toLowerCase()}"`;
      return { path, leaf: node.leaf, mapKey: segs.slice(i).join("__") };
    }
    const hit = [...node.children].find(([key]) => norm(key) === norm(segs[i]));
    if (hit) {
      path.push(hit[0]);
      node = hit[1];
    } else if (node.wildcard) {
      path.push(segs[i].toLowerCase());
      node = node.wildcard;
    } else {
      const hint = didYouMean(segs[i], node.children.keys());
      return `unknown setting "${segs[i].toLowerCase()}"${path.length ? ` under ${dotted(path)}` : ""}${hint ? `; did you mean ${envStyle([...path, hint])}?` : ""}`;
    }
  }
  if (!node.leaf) return `${dotted(path)} is a section, not a setting; name one of its settings (${[...node.children.keys()].slice(0, 4).join(", ")}...)`;
  return { path, leaf: node.leaf };
}

/** Builds the environment layer from SEALMARK_* variables. Values are typed by the schema, so errors match YAML errors. */
export function envToLayer(env: Record<string, string | undefined>, issues: string[]): Layer {
  const layer = newLayer("env", "env");
  for (const [name, text] of Object.entries(env).sort(([a], [b]) => a.localeCompare(b))) {
    if (text === undefined || !name.toUpperCase().startsWith(ENV_PREFIX)) continue;
    const upper = name.toUpperCase();
    if (RESERVED.has(upper) || upper.startsWith(INPUT_PREFIX)) continue;
    const source = `env ${name}`;
    const r = resolve(upper.slice(ENV_PREFIX.length));
    if (typeof r === "string") {
      issues.push(`${source}: ${r}`);
      continue;
    }
    const ctx: VCtx = { kind: "env", where: () => source, showPath: false, issues, lines: layer.lines };
    const { leaf, path } = r;
    let value: unknown;
    if (r.mapKey !== undefined) value = { [r.mapKey]: text };
    else value = text.trim() === "null" || text.trim() === "~" ? null : coerceText(leaf.shape, text);
    const cleaned = value === null ? null : validateLeaf(leaf, value, path, ctx);
    if (cleaned === undefined) continue;
    if (isPlainObject(cleaned) && r.mapKey !== undefined) {
      const existing = path.reduce<unknown>((o, k) => (isPlainObject(o) ? o[k] : undefined), layer.data);
      setIn(layer.data, path, { ...(isPlainObject(existing) ? existing : {}), ...cleaned });
      layer.sources.set(pointer([...path, r.mapKey]), source);
    } else {
      setIn(layer.data, path, cleaned);
      layer.sources.set(pointer(path), source);
    }
  }
  return layer;
}
