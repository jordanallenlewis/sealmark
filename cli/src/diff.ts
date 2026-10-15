import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { UsageError, type CommandOutput } from "./commands.js";
import { compareBaseline, parseBaseline } from "./report/baseline.js";
import { driftFails } from "./report/drift.js";
import { inertLines } from "./report/sanitize.js";
import type { RunResult } from "./types.js";

export const DIFF_FORMAT = "sealmark.diff/1";

function load(path: string | undefined, what: string): RunResult[] {
  if (!path) throw new UsageError("diff needs two report files: sealmark diff before.json after.json");
  let text: string;
  try {
    text = readFileSync(resolve(path), "utf8");
  } catch (e) {
    throw new UsageError(`cannot read the ${what} report ${path} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`);
  }
  try {
    return parseBaseline(text, `the ${what} report ${path}`);
  } catch (e) {
    throw new UsageError((e as Error).message);
  }
}

/**
 * `sealmark diff before.json after.json`: compares two JSON reports without running anything. Prints what `--baseline` would
 * (regressions, improvements, notes, tool-surface drift) and exits 1 when something regressed or drifted (breaking or notable).
 */
export function diffCommand(before: string | undefined, after: string | undefined, o: { json: boolean }): CommandOutput {
  const d = compareBaseline(load(before, "before"), load(after, "after"));
  const code = d.regressions.length || driftFails(d.drift).length ? 1 : 0;
  if (o.json) {
    const body = { format: DIFF_FORMAT, regressions: d.regressions, improvements: d.improvements, notes: d.notes, drift: d.drift };
    return { code, stdout: `${JSON.stringify(body, null, 2)}\n` };
  }
  // Check and tool names come from the servers: every line is made inert before it reaches a terminal.
  const lines = [
    ...d.regressions.map((r) => `regression: ${r.text}`),
    ...d.improvements.map((i) => `improved: ${i}`),
    ...d.notes.map((n) => `note: ${n}`),
    ...d.drift.map((e) => `drift: ${e.text}`),
  ];
  return { code, stdout: lines.length ? `${inertLines(lines.join("\n"))}\n` : "no change\n" };
}
