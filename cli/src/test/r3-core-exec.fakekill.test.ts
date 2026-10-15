import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { ConfigIntegrity, RunResult, SealmarkConfig } from "../types.js";
import { quiet } from "./helpers.js";

const FAKEKILL = fileURLToPath(new URL("../toy/exec-fakekill.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};

function run(mode: string): Promise<RunResult> {
  const config: SealmarkConfig = { name: `toy-exec-fakekill-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [FAKEKILL, "--mode", mode], env: {} } };
  const base = legacyEffectiveConfig({ config, packs: ["exec"], packsExplicit: false, timeoutProbeSec: 2 });
  return runHarness({
    config,
    effective: { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent } },
    packs: ["exec"],
    packsExplicit: false,
    active: true,
    timeoutProbeSec: 2,
    log: quiet,
  });
}

/** Command lines of every sm-sleep still alive whose script lives under this test's scratch directory. */
const sleepersLeft = (): string[] =>
  spawnSync("ps", ["-axo", "command"], { encoding: "utf8" })
    .stdout.split("\n")
    .filter((l) => /sm-sleep/.test(l) && l.includes(dir));

const cap = (r: RunResult) => r.checks.find((c) => c.id === "exec-timeout-cap")!;

// The toy signals a process group and the process table is read with ps: POSIX only.
describe("exec-timeout-cap: a limit message is confirmed by the process table", { timeout: 240_000, skip: process.platform === "win32" && "POSIX only (process groups, ps)" }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r3-fakekill-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(["fake", "honest"].map(async (m) => void (results[m] = await run(m))));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("fake: answers killed and leaves the program running -> fail with exec.time.left-running, and the harness stopped it", () => {
    const c = cap(results.fake);
    // The time half fails. The toy caps its output, so the output half passes and the check folds to part, the same as any other time-only failure.
    assert.equal(c.verdict, "part");
    assert.match(c.summary, /not stopped in time/);
    const ev = c.evidence.find((e) => e.code === "exec.time.left-running");
    assert.ok(ev, JSON.stringify(c.evidence));
    assert.equal(ev.verifiedBy, "process");
    assert.match(ev.outcome, /sm-sleep \(pid \d+\) was still running and was stopped by the harness/);
    assert.match(ev.excerpt ?? "", /killed: still running after 1 s/);
    assert.deepEqual(sleepersLeft(), []);
  });

  it("honest: kills the program and answers the same text -> pass, verified by the process table", () => {
    const c = cap(results.honest);
    assert.equal(c.verdict, "pass", JSON.stringify(c.evidence));
    const ev = c.evidence.find((e) => e.code === "exec.time.capped");
    assert.ok(ev, JSON.stringify(c.evidence));
    assert.equal(ev.verifiedBy, "process");
    assert.match(ev.outcome, /with a limit message and no sm-sleep from this sandbox remains in the process table/);
    assert.deepEqual(sleepersLeft(), []);
  });
});
