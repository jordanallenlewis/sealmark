import { LETTERS } from "../grade.js";
import type { PackId, RunResult, Verdict } from "../types.js";
import { isFailed, type AnyRun } from "./common.js";
import { surfaceDrift, type DriftEntry } from "./drift.js";

/**
 * Baseline / ratchet (packs-design 6.7). A baseline is a JSON report written by an earlier run (`--write-baseline`, or
 * any `--format json` output). A regression is:
 *   - a check whose verdict rank dropped (pass > part > fail; na and inconclusive have no rank and are reported as notes),
 *   - a pack whose letter dropped,
 *   - a pack that was graded in the baseline and is not graded now (a gate must not go green because a pack silently stopped running).
 * New checks, new packs and improvements are never regressions.
 */

export interface Regression {
  server: string;
  pack: PackId;
  /** Present for a check regression. */
  check?: string;
  kind: "check" | "letter" | "pack-not-graded";
  from: string;
  to: string;
  advisory?: boolean;
  text: string;
}

export interface BaselineDiff {
  regressions: Regression[];
  improvements: string[];
  notes: string[];
  /** Tool-surface drift against the baseline, one entry per change (report/drift.ts). Never a regression: `--fail-on drift` decides whether it moves the exit code. */
  drift: DriftEntry[];
}

const RANK: Partial<Record<Verdict, number>> = { pass: 2, part: 1, fail: 0 };
const letterRank = (l: string) => LETTERS.indexOf(l as (typeof LETTERS)[number]);

/** Accepts a single RunResult or `{ runs: [...] }`. Throws an Error with a plain message for anything else. */
export function parseBaseline(text: string, label = "baseline"): RunResult[] {
  let data: unknown;
  try {
    data = JSON.parse(text.replace(/^﻿/, ""));
  } catch (e) {
    throw new Error(`${label} is not valid JSON (${(e as Error).message})`);
  }
  const list = data && typeof data === "object" && Array.isArray((data as { runs?: unknown }).runs) ? ((data as { runs: unknown[] }).runs) : [data];
  const runs = list.filter((r): r is RunResult => Boolean(r) && typeof r === "object" && "packs" in (r as object) && "checks" in (r as object));
  if (!runs.length) throw new Error(`${label} has no sealmark run in it (expected the JSON written by --format json or --write-baseline)`);
  return runs;
}

export function compareBaseline(baseline: RunResult[], current: AnyRun[]): BaselineDiff {
  const out: BaselineDiff = { regressions: [], improvements: [], notes: [], drift: [] };
  const cur = current.filter((r): r is RunResult => !isFailed(r));

  for (const run of cur) {
    // One server against one baseline run is compared even if the name changed.
    const base = baseline.find((b) => b.server.name === run.server.name) ?? (baseline.length === 1 && cur.length === 1 ? baseline[0] : undefined);
    if (!base) {
      out.notes.push(`server ${run.server.name}: not in the baseline, so nothing to compare`);
      continue;
    }
    if (base.server.name !== run.server.name) out.notes.push(`compared with the baseline run for "${base.server.name}"`);
    // Exactly one side CUSTOM is a different configuration even when the two hashes happen to agree.
    const oneCustom = base.config !== undefined && run.config !== undefined && base.config.standard !== run.config.standard;
    if (oneCustom && base.config?.hash === run.config?.hash) out.notes.push(`server ${run.server.name}: the baseline was graded under a different configuration (${base.config?.standard ? "STANDARD" : "CUSTOM"} vs ${run.config?.standard ? "STANDARD" : "CUSTOM"}); the comparison may not be like for like`);
    else if (base.config?.hash !== run.config?.hash) out.notes.push(`server ${run.server.name}: the baseline was graded under a different configuration (hash ${base.config?.hash?.slice(0, 15) ?? "none"} vs ${run.config?.hash?.slice(0, 15) ?? "none"}); the comparison may not be like for like`);
    const name = run.server.name;
    out.drift.push(...surfaceDrift(base, run));

    for (const [id, bp] of Object.entries(base.packs) as [PackId, NonNullable<RunResult["packs"][PackId]>][]) {
      const cp = run.packs[id];
      if (bp.status !== "graded" || !bp.grade) continue;
      if (!cp || cp.status !== "graded" || !cp.grade) {
        out.regressions.push({ server: name, pack: id, kind: "pack-not-graded", from: bp.grade.letter, to: cp ? `${cp.status}${cp.reason ? ` (${cp.reason})` : ""}` : "absent", text: `server ${name}, pack ${id}: was graded ${bp.grade.letter}, now ${cp ? cp.status : "absent"}${cp?.reason ? ` (${cp.reason})` : ""}` });
        continue;
      }
      if (letterRank(cp.grade.letter) < letterRank(bp.grade.letter)) {
        out.regressions.push({ server: name, pack: id, kind: "letter", from: bp.grade.letter, to: cp.grade.letter, text: `server ${name}, pack ${id}: grade dropped ${bp.grade.letter} -> ${cp.grade.letter}` });
      } else if (letterRank(cp.grade.letter) > letterRank(bp.grade.letter)) {
        out.improvements.push(`server ${name}, pack ${id}: grade rose ${bp.grade.letter} -> ${cp.grade.letter}`);
      }
    }

    for (const bc of base.checks) {
      const cc = run.checks.find((c) => c.pack === bc.pack && c.id === bc.id);
      if (!cc) {
        out.notes.push(`server ${name}, check ${bc.id}: in the baseline but not in this run`);
        continue;
      }
      const b = RANK[bc.verdict];
      const c = RANK[cc.verdict];
      if (b === undefined || c === undefined) {
        if (b !== undefined && c === undefined) out.notes.push(`server ${name}, check ${bc.id}: was ${bc.verdict}, now ${cc.verdict} (not ranked, so not a regression)`);
        continue;
      }
      if (c < b) {
        out.regressions.push({ server: name, pack: bc.pack, check: bc.id, kind: "check", from: bc.verdict, to: cc.verdict, advisory: Boolean(cc.advisory), text: `server ${name}, check ${bc.id}${cc.advisory ? " (advisory)" : ""}: ${bc.verdict} -> ${cc.verdict} (${cc.summary})` });
      } else if (c > b) out.improvements.push(`server ${name}, check ${bc.id}: ${bc.verdict} -> ${cc.verdict}`);
    }
  }
  return out;
}
