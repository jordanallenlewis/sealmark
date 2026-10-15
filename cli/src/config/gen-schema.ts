import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { LOCKED_LEAVES, STANDARD_PACKS, buildJsonSchema } from "./schema.js";
import { METHODOLOGY } from "./model.js";

/**
 * Build step (npm run build): writes cli/schema/sealmark.schema.json from the schema table.
 * `--check` compares instead of writing and exits 1 on drift (used by the tests).
 * The shipped profile YAML files are copied to dist/ by the build script in package.json.
 */

export const SCHEMA_FILE = fileURLToPath(new URL("../../schema/sealmark.schema.json", import.meta.url));

export function schemaText(): string {
  return `${JSON.stringify(buildJsonSchema(), null, 2)}\n`;
}

/** Text of config/profiles/standard.yaml generated from the schema defaults. The shipped file must equal it (a test checks). */
export function standardProfileText(): string {
  const lines = [
    `# standard: the published methodology (${METHODOLOGY}). The only profile whose grade is "official".`,
    "# Every setting that affects a grade is listed here with its published value; this file is the appendix of the methodology.",
    "# Generated from cli/src/config/schema.ts (npm run gen:standard). Do not edit by hand.",
    "description: The published methodology. A run is STANDARD only when these values are used unchanged.",
    `packs: [${STANDARD_PACKS.join(", ")}]`,
  ];
  const tree: Record<string, unknown> = {};
  for (const l of LOCKED_LEAVES) {
    const segs = l.path.split(".");
    let cur = tree;
    for (const s of segs.slice(0, -1)) cur = (cur[s] ??= {}) as Record<string, unknown>;
    cur[segs[segs.length - 1]] = l.default;
  }
  const emit = (node: Record<string, unknown>, indent: string) => {
    for (const [k, v] of Object.entries(node)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length) {
        lines.push(`${indent}${k}:`);
        emit(v as Record<string, unknown>, `${indent}  `);
      } else lines.push(`${indent}${k}: ${Array.isArray(v) ? `[${v.map((x) => JSON.stringify(x)).join(", ")}]` : v !== null && typeof v === "object" ? "{}" : JSON.stringify(v)}`);
    }
  };
  emit(tree, "");
  return `${lines.join("\n")}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = schemaText();
  if (process.argv.includes("--check")) {
    let current = "";
    try {
      current = readFileSync(SCHEMA_FILE, "utf8");
    } catch {
      /* missing */
    }
    if (current !== text) {
      process.stderr.write("cli/schema/sealmark.schema.json is out of date; run npm run build\n");
      process.exit(1);
    }
  } else if (process.argv.includes("--standard")) {
    process.stdout.write(standardProfileText());
  } else {
    mkdirSync(fileURLToPath(new URL("../../schema/", import.meta.url)), { recursive: true });
    writeFileSync(SCHEMA_FILE, text);
    process.stdout.write(`wrote ${SCHEMA_FILE}\n`);
  }
}
