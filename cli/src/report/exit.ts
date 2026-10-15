import { meetsThreshold } from "../grade.js";
import type { Letter, RunResult } from "../types.js";
import type { Regression } from "./baseline.js";
import { driftFails, type DriftEntry } from "./drift.js";
import { isFailed, type AnyRun } from "./common.js";

/**
 * Exit codes (unchanged from 0.1): 0 ok, 1 a graded pack is below --fail-under (or regressed against a baseline),
 * 2 usage or config error, 3 no pack was graded, 4 harness or server failure.
 * With several servers the code is the worst (highest) of them.
 */

export interface ExitPolicy {
  failUnder?: Letter;
  /** How --fail-under treats an inconclusive pack. `pass` (the default) only warns, as 0.1 did. */
  treatInconclusiveAs: "pass" | "fail";
  /** Exit code used when a critical check failed (0 keeps 0.1 behavior). */
  criticalFail: number;
  /** `--fail-on any`: the --fail-under gate (and the inconclusive and critical rules around it) decides the exit code. false with `regressions` or `drift` alone. */
  failOnGate: boolean;
  /** `--fail-on any` or `regressions`: a regression against the baseline exits 1. */
  failOnRegressions: boolean;
  /** `--fail-on drift`: breaking or notable tool-surface drift against the baseline exits 1. */
  failOnDrift: boolean;
  regressions: Regression[];
  /** Tool-surface drift against the baseline (empty without one). */
  drift: DriftEntry[];
  /** True when a baseline was supplied. */
  baseline: boolean;
}

export interface ExitDecision {
  code: number;
  /** Lines for stderr, in order. */
  messages: string[];
  /** What the exit code means, in a few words ("a graded pack is below the gate (B)"). The cause of the worst code; "ok ..." for 0. */
  reason: string;
}

export function decideExit(runs: AnyRun[], p: ExitPolicy): ExitDecision {
  const messages: string[] = [];
  let code = 0;
  let reason = "";
  // The reason belongs to the worst code; a later cause of the same code does not replace the first.
  const raise = (c: number, why: string): void => {
    if (c > code) {
      code = c;
      reason = why;
    }
  };
  let noteGateOff = false;
  const multi = runs.length > 1;
  for (const run of runs) {
    if (isFailed(run)) {
      raise(4, "a server failed to run");
      continue;
    }
    const r: RunResult = run;
    const tag = multi ? `server ${r.server.name}: ` : "";
    const graded = Object.entries(r.packs).flatMap(([id, pk]) => (pk?.status === "graded" && pk.grade ? [{ id, grade: pk.grade }] : []));
    if (!graded.length) {
      messages.push(`${tag}no pack was graded; see the reasons in the report`);
      raise(3, "no pack was graded");
      continue;
    }
    const gated = Boolean(p.failUnder && p.failOnGate);
    // A requested pack that could not be judged is said so whatever the gate: with the gate off the warning is all there is.
    for (const [id, pk] of Object.entries(r.packs)) {
      if (pk?.status !== "inconclusive") continue;
      if (gated && p.treatInconclusiveAs === "fail") {
        messages.push(`${tag}pack ${id} was inconclusive (${pk.reason}); output.exit_policy.treat_inconclusive_as is fail`);
        raise(1, "an inconclusive pack counts as failing (output.exit_policy.treat_inconclusive_as)");
      } else if (gated) messages.push(`warning: ${tag}pack ${id} was inconclusive (${pk.reason}) and is not covered by --fail-under ${p.failUnder}`);
      else messages.push(`warning: ${tag}pack ${id} was inconclusive (${pk.reason})`);
    }
    if (!gated && p.treatInconclusiveAs === "fail" && !noteGateOff && Object.values(r.packs).some((pk) => pk?.status === "inconclusive")) {
      noteGateOff = true;
      messages.push(
        p.failUnder
          ? "note: output.exit_policy.treat_inconclusive_as is fail, but --fail-on does not include the gate (any), so it does not affect the exit code"
          : "note: output.exit_policy.treat_inconclusive_as is fail, but the gate is off (--fail-under none), so it does not affect the exit code",
      );
    }
    if (gated) {
      for (const g of graded.filter((x) => !meetsThreshold(x.grade.letter, p.failUnder!))) {
        messages.push(`${tag}pack ${g.id} graded ${g.grade.letter}, below --fail-under ${p.failUnder}`);
        raise(1, `a graded pack is below the gate (${p.failUnder})`);
      }
      // At the A gate an A is the claim "proven top mark": a provisional A* (a critical check was inconclusive) does not meet it.
      // Lower gates are unchanged: a provisional B still meets --fail-under B.
      if (p.failUnder === "A") {
        for (const g of graded.filter((x) => meetsThreshold(x.grade.letter, "A") && x.grade.provisional)) {
          messages.push(`${tag}pack ${g.id} graded A* (provisional: a critical check was inconclusive), which does not meet --fail-under A`);
          raise(1, "a provisional grade does not meet the A gate");
        }
      }
    }
    if (p.criticalFail > 0) {
      const capped = graded.filter((g) => g.grade.capped);
      if (capped.length) {
        messages.push(`${tag}critical fail in pack ${capped.map((g) => `${g.id} (${g.grade.criticalFails.join(", ")})`).join("; ")}; exit code ${p.criticalFail} (output.exit_policy.critical_fail)`);
        raise(p.criticalFail, `a critical check failed (output.exit_policy.critical_fail is ${p.criticalFail})`);
      }
    }
  }
  if (p.baseline) {
    for (const g of p.regressions) messages.push(`regression: ${g.text}`);
    if (p.failOnRegressions && p.regressions.length) raise(1, "the run regressed against the baseline");
    if (p.failOnDrift && driftFails(p.drift).length) raise(1, "the tool surface drifted against the baseline");
  }
  if (code === 0) {
    reason = !p.failOnGate
      ? p.failOnRegressions
        ? p.failOnDrift ? "no regression or tool-surface drift against the baseline" : "no regression against the baseline"
        : "no tool-surface drift against the baseline"
      : p.failUnder ? `every graded pack meets the gate (${p.failUnder})` : "the gate is off (--fail-under none); grades do not affect the exit code";
  }
  return { code, messages, reason };
}
