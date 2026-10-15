import { createHash } from "node:crypto";
import { canonicalJson } from "./config/util.js";
import type { ToolInfo } from "./mcp.js";
import type { ToolAnnotations, ToolClassification, ToolSurface } from "./types.js";

/**
 * What a tool offers an agent, reduced to hashes and types so two runs can be compared without storing server-controlled text
 * (report/drift.ts). Deterministic: the same tools give the same bytes whatever the order of keys or of the tool list. Descriptions
 * are hashed and measured, never stored.
 */

const HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

/** A JSON type as one short string: "string", "string|null" for a type array, or undefined when the schema says none. */
function typeText(t: unknown): string | undefined {
  if (typeof t === "string") return t;
  if (Array.isArray(t) && t.length && t.every((x) => typeof x === "string")) return t.join("|");
  return undefined;
}

/**
 * A parameter's type: "string", "string|null", "array<string>", "array", "object", or "unknown" when it has none. A parameter
 * declared with `anyOf`, `oneOf` or `allOf` (what an optional field of a typed schema library becomes) is the union of its members'
 * types, so a change from `string|null` to `number|null` is a change drift can see. Nesting is followed to a fixed depth.
 */
function paramType(schema: unknown, depth = 0): string {
  if (!schema || typeof schema !== "object") return "unknown";
  const { type, items, anyOf, oneOf, allOf } = schema as { type?: unknown; items?: unknown; anyOf?: unknown; oneOf?: unknown; allOf?: unknown };
  const t = typeText(type);
  if (t === undefined) {
    if (depth >= 3) return "unknown";
    const members = [anyOf, oneOf, allOf].flatMap((m) => (Array.isArray(m) ? m : []));
    const union: string[] = [];
    for (const m of members) {
      const mt = paramType(m, depth + 1);
      if (mt === "unknown") return "unknown"; // one member without a type: the union is not known
      for (const part of mt.split("|")) if (!union.includes(part)) union.push(part);
    }
    return union.length ? union.join("|") : "unknown";
  }
  if (t !== "array") return t;
  const it = typeText(items && typeof items === "object" ? (items as { type?: unknown }).type : undefined);
  return it ? `array<${it}>` : "array";
}

function annotationsOf(c: ToolClassification | undefined): ToolAnnotations | undefined {
  if (!c?.annotations) return undefined;
  const out: ToolAnnotations = {};
  for (const h of HINTS) if (typeof c.annotations[h] === "boolean") out[h] = c.annotations[h];
  return Object.keys(out).length ? out : undefined;
}

export function captureSurface(tools: ToolInfo[], classification: ToolClassification[]): ToolSurface[] {
  const byTool = new Map(classification.map((c) => [c.tool, c]));
  return tools
    .map((t): ToolSurface => {
      const schema = t.inputSchema ?? {};
      const props = schema.properties && typeof schema.properties === "object" ? schema.properties : {};
      const description = typeof t.description === "string" ? t.description : "";
      const annotations = annotationsOf(byTool.get(t.name));
      return {
        name: t.name,
        ...(typeof t.title === "string" ? { title: t.title } : {}),
        descriptionHash: sha256(description),
        descriptionLength: description.length,
        inputSchemaHash: sha256(canonicalJson(schema)),
        required: (Array.isArray(schema.required) ? schema.required.filter((r): r is string => typeof r === "string") : []).sort(),
        params: Object.fromEntries(Object.keys(props).sort().map((k) => [k, paramType(props[k])])),
        ...(annotations ? { annotations } : {}),
      };
    })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
