import { readFileSync, writeFileSync } from "node:fs";
import { isMap, parseDocument, type Document } from "yaml";
import { ConfigError, SCHEMA_VERSION } from "./model.js";

/**
 * Config file migrations. A rule rewrites a file from `from` to `from + 1` using recorded
 * rename/move steps, on the YAML document so comments and key order survive.
 *
 * Status: this is the scaffold plus the first rule. "Version 0" is the pre-1.0 layout of flat top-level keys
 * (`timeout_probe`, `fail_under`, `format`) and the 0.1 `cap-timeout` check id; no released version wrote it.
 * It exists so the mechanism, the diff output and the "refuse a newer file" path are exercised before the
 * first real breaking rename.
 */

export interface MigrationRule {
  from: number;
  to: number;
  describe: string;
  apply(doc: Document, notes: string[]): void;
}

type Path = string[];

/** Moves a node (keeping its comments) from one path to another; no-op when absent. */
function move(doc: Document, from: Path, to: Path, notes: string[]): void {
  if (!doc.hasIn(from)) return;
  const node = doc.getIn(from, true);
  doc.deleteIn(from);
  if (from.length > 1) pruneEmpty(doc, from.slice(0, -1));
  doc.setIn(to, node);
  notes.push(`moved ${from.join(".")} -> ${to.join(".")}`);
}

function pruneEmpty(doc: Document, path: Path): void {
  const node = doc.getIn(path, true);
  if (isMap(node) && node.items.length === 0) {
    doc.deleteIn(path);
    if (path.length > 1) pruneEmpty(doc, path.slice(0, -1));
  }
}

export const MIGRATIONS: MigrationRule[] = [
  {
    from: 0,
    to: 1,
    describe: "flat v0 keys move into their sections; cap-timeout splits into db-rowcap and db-timeout",
    apply(doc, notes) {
      move(doc, ["timeout_probe"], ["timeout_probe_sec"], notes);
      move(doc, ["fail_under"], ["output", "exit_policy", "fail_under"], notes);
      move(doc, ["format"], ["output", "format"], notes);
      move(doc, ["checks", "cap-timeout", "timeout_sec"], ["checks", "db-timeout", "expected_sec"], notes);
      move(doc, ["checks", "cap-timeout", "row_cap"], ["checks", "db-rowcap", "row_cap"], notes);
      for (const key of ["enabled", "severity"]) {
        if (!doc.hasIn(["checks", "cap-timeout", key])) continue;
        const value = doc.getIn(["checks", "cap-timeout", key]);
        doc.deleteIn(["checks", "cap-timeout", key]);
        doc.setIn(["checks", "db-rowcap", key], value);
        doc.setIn(["checks", "db-timeout", key], value);
        notes.push(`copied checks.cap-timeout.${key} to checks.db-rowcap.${key} and checks.db-timeout.${key}`);
      }
      pruneEmpty(doc, ["checks", "cap-timeout"]);
    },
  },
];

export interface MigrationResult {
  from: number;
  to: number;
  text: string;
  changed: boolean;
  notes: string[];
  /** Changed lines only: `-12: old` / `+12: new`. Empty when unchanged. */
  diff: string;
}

/** Changed lines between two texts, by longest common subsequence. */
export function lineDiff(a: string, b: string): string {
  const x = a.split(/\r?\n/);
  const y = b.split(/\r?\n/);
  const dp = Array.from({ length: x.length + 1 }, () => new Array<number>(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < x.length || j < y.length) {
    if (i < x.length && j < y.length && x[i] === y[j]) {
      i++;
      j++;
    } else if (j < y.length && (i === x.length || dp[i][j + 1] >= dp[i + 1][j])) out.push(`+${j++ + 1}: ${y[j - 1]}`);
    else out.push(`-${i++ + 1}: ${x[i - 1]}`);
  }
  return out.join("\n");
}

/** Migrates config text to the current layout. Refuses a file newer than this binary. */
export function migrateText(text: string, display = "config"): MigrationResult {
  const doc = parseDocument(text, { prettyErrors: false });
  if (doc.errors.length) throw new ConfigError(doc.errors.map((e) => `${display}: ${e.message.split("\n")[0]}`));
  if (!isMap(doc.contents)) throw new ConfigError(`${display}: expected a mapping at the top level`);
  const notes: string[] = [];
  const declared = doc.get("schema_version");
  let from = SCHEMA_VERSION;
  if (declared !== undefined) {
    if (typeof declared !== "number" || !Number.isInteger(declared) || declared < 0) throw new ConfigError(`${display}: schema_version must be a whole number, got ${JSON.stringify(declared)}`);
    from = declared;
  } else notes.push(`no schema_version found; reading as ${SCHEMA_VERSION}`);
  if (from > SCHEMA_VERSION) throw new ConfigError(`${display}: schema_version ${from} is newer than this sealmark understands (${SCHEMA_VERSION}); upgrade sealmark`);
  let v = from;
  while (v < SCHEMA_VERSION) {
    const rule = MIGRATIONS.find((m) => m.from === v);
    if (!rule) throw new ConfigError(`${display}: no migration from schema_version ${v}`);
    rule.apply(doc, notes);
    v = rule.to;
  }
  if (doc.get("schema_version") === undefined) doc.contents.items.unshift(doc.createPair("schema_version", SCHEMA_VERSION));
  else doc.set("schema_version", SCHEMA_VERSION);
  const out = doc.toString({ lineWidth: 0, flowCollectionPadding: false });
  const changed = out !== text;
  return { from, to: SCHEMA_VERSION, text: out, changed, notes, diff: changed ? lineDiff(text, out) : "" };
}

/** Migrates a file; rewrites it only when `write` is true. */
export function migrateFile(path: string, o: { write: boolean }): MigrationResult {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new ConfigError(`Cannot read ${path}.`);
  }
  const r = migrateText(text.replace(/^﻿/, ""), path);
  if (o.write && r.changed) writeFileSync(path, r.text);
  return r;
}
