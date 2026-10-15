import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { ConfigError } from "../config.js";
import { EXEC_NEEDS_ACTIVE, describe as describeExec, pack as execPack } from "../packs/exec.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { ConfigIntegrity, EffectiveConfig, PackId, RunResult, SealmarkConfig } from "../types.js";
import { gradeOf, quiet, verdicts } from "./helpers.js";

const EXEC_TOY = fileURLToPath(new URL("../toy/exec.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

const execConfig = (mode: string, extra: string[] = []): SealmarkConfig => ({
  name: `toy-exec-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [EXEC_TOY, "--mode", mode, "--timeout", "6", ...extra], env: {} },
});

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};
const leftovers = () => readdirSync(parent).filter((n) => n.startsWith("sealmark-"));

function effective(config: SealmarkConfig, packs: PackId[], over: Partial<EffectiveConfig> = {}): EffectiveConfig {
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: false, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, ...over, sandbox: { ...base.sandbox, dir: parent } };
}

function runExec(mode: string, o: { extra?: string[]; active?: boolean; over?: Partial<EffectiveConfig>; packsExplicit?: boolean } = {}): Promise<RunResult> {
  const config = execConfig(mode, o.extra);
  return runHarness({
    config,
    effective: effective(config, ["exec"], o.over),
    packs: ["exec"],
    packsExplicit: o.packsExplicit ?? false,
    active: o.active ?? true,
    timeoutProbeSec: 2,
    log: quiet,
  });
}

const ids = (r: RunResult) => r.checks.filter((c) => c.pack === "exec").map((c) => c.id);
const check = (r: RunResult, id: string) => r.checks.find((c) => c.id === id)!;

describe("exec pack against toy servers", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-exec-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const jobs: Record<string, () => Promise<RunResult>> = {
      good: () => runExec("good"),
      shelly: () => runExec("shelly"),
      wander: () => runExec("wander"),
      shellOnly: () => runExec("good", { extra: ["--tools", "shell"] }),
      deny: () => runExec("deny"),
      inactive: () => runExec("good", { active: false }),
      disabled: () => runExec("good", { over: { checks: { "exec-cwd": { enabled: false, severity: null }, "exec-allowlist": { enabled: true, severity: "scored" } } } }),
    };
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (results[k] = await fn())));
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  it("good (no shell, allowlist, cwd in the root, timeout and output cap) is an A with every check passing", () => {
    const r = results.good;
    assert.deepEqual(verdicts(r, "exec"), { "exec-injection": "pass", "exec-cwd": "pass", "exec-timeout-cap": "pass", "exec-allowlist": "pass" });
    const g = gradeOf(r, "exec");
    assert.equal(g?.letter, "A");
    assert.equal(g?.pct, 100);
    assert.equal(g?.scored, 3);
    assert.equal(check(r, "exec-allowlist").advisory, true);
    assert.equal(check(r, "exec-injection").critical, true);
  });

  it("good: every injection variant reached the program as data, and the evidence says how that was seen", () => {
    const inj = check(results.good, "exec-injection");
    // Two tools (run and shell) take the same variants, but shell-style tools are not injection targets.
    assert.equal(inj.evidence.length, 6);
    assert.ok(
      inj.evidence.every((e) => e.code === "exec.injection.literal" && e.verifiedBy === "fs-observer"),
      JSON.stringify(inj.evidence.map((e) => e.code)),
    );
    assert.ok(inj.coverage?.notCovered.some((n) => n.tool === "shell" && /shell by design/.test(n.reason)));
    assert.ok((inj.coverage?.validCalls ?? 0) >= 6);
  });

  it("shelly (shell: true) fails the critical injection check and is capped at D (2 of 3 scored pass)", () => {
    const r = results.shelly;
    const v = verdicts(r, "exec");
    assert.equal(v["exec-injection"], "fail");
    assert.equal(v["exec-cwd"], "pass");
    assert.equal(v["exec-timeout-cap"], "pass");
    assert.equal(v["exec-allowlist"], "part");
    const g = gradeOf(r, "exec");
    assert.equal(g?.letter, "D");
    assert.equal(g?.raw, "C");
    assert.equal(g?.capped, true);
    assert.equal(g?.pct, 66.67);
    assert.deepEqual(g?.criticalFails, ["exec-injection"]);
  });

  it("shelly: a canary file written outside the root is the evidence, and the separators that fire depend on the platform", () => {
    const inj = check(results.shelly, "exec-injection");
    const fired = inj.evidence.filter((e) => e.code === "exec.injection.injected");
    // `&&`, `&` and `|` work in cmd.exe and in sh; `;`, `$()` and backticks only in sh.
    assert.ok(fired.length >= 3, `${fired.length} variants fired`);
    if (process.platform !== "win32") assert.equal(fired.length, 6);
    assert.ok(fired.every((e) => /executed-\d+\.txt appeared outside the root/.test(e.outcome)));
    assert.match(inj.summary, /passes its arguments through a shell/);
  });

  it("wander (cwd in the home directory, no timeout, no output cap) passes injection and fails the other two scored checks: F", () => {
    const r = results.wander;
    const v = verdicts(r, "exec");
    assert.equal(v["exec-injection"], "pass");
    assert.equal(v["exec-cwd"], "fail");
    assert.equal(v["exec-timeout-cap"], "fail");
    assert.equal(v["exec-allowlist"], "part");
    const g = gradeOf(r, "exec");
    assert.equal(g?.letter, "F");
    assert.equal(g?.pct, 33.33);
    const cap = check(r, "exec-timeout-cap");
    assert.ok(
      cap.evidence.some((e) => e.code === "exec.time.no-cap"),
      JSON.stringify(cap.evidence.map((e) => e.code)),
    );
    assert.ok(
      cap.evidence.some((e) => /^exec\.output\.(uncapped|dropped|timeout)$/.test(e.code ?? "")),
      JSON.stringify(cap.evidence.map((e) => e.code)),
    );
    assert.match(cap.summary, /not stopped in time/);
    assert.match(cap.summary, /output was not capped/);
  });

  it("wander: the program the server left running was found and stopped by the harness", () => {
    // Both tools (run and shell) were measured at once; each result names the programs the harness stopped.
    const sleeps = check(results.wander, "exec-timeout-cap").evidence.filter((e) => e.code === "exec.time.no-cap");
    assert.equal(sleeps.length, 2);
    for (const sleep of sleeps) assert.match(sleep.outcome, /sm-sleep was still running \(pid \d+(, \d+)*\) and was stopped by the harness/);
    assert.deepEqual(results.wander.sandbox?.leftoverProcesses, []);
  });

  it("on Windows a bare program name cannot be spawned without a shell, so the harness falls back to node plus the script and says so", { skip: process.platform !== "win32" }, () => {
    const inj = check(results.wander, "exec-injection");
    assert.ok(
      inj.evidence.every((e) => /started as node plus its script/.test(e.probe)),
      inj.evidence[0]?.probe,
    );
    // The server that resolves bare names (good) is driven with the bare name.
    assert.ok(check(results.good, "exec-injection").evidence.every((e) => !/started as node/.test(e.probe)));
  });

  it("a server whose only command tool is shell-style gets injection na with a reason, and is graded on the other checks", () => {
    const r = results.shellOnly;
    const inj = check(r, "exec-injection");
    assert.equal(inj.verdict, "na");
    assert.match(inj.summary, /one command line, which is a shell by design/);
    assert.deepEqual(
      r.classification?.filter((c) => c.class === "command").map((c) => [c.tool, c.style]),
      [["shell", "shell"]],
    );
    const v = verdicts(r, "exec");
    assert.equal(v["exec-cwd"], "pass");
    assert.equal(v["exec-timeout-cap"], "pass");
    assert.equal(gradeOf(r, "exec")?.letter, "A");
    assert.equal(gradeOf(r, "exec")?.scored, 2);
  });

  it("a tool that refuses every program leaves the pack inconclusive, never a pass or a fail", () => {
    const r = results.deny;
    assert.deepEqual(verdicts(r, "exec"), { "exec-injection": "inconclusive", "exec-cwd": "inconclusive", "exec-timeout-cap": "inconclusive", "exec-allowlist": "inconclusive" });
    assert.equal(r.packs.exec?.status, "inconclusive");
    assert.match(check(r, "exec-cwd").summary, /sm-echo could not be started through/);
    assert.ok(check(r, "exec-cwd").evidence.some((e) => e.code === "exec.control.failed"));
  });

  it("without --active the pack is not applicable, with the exact reason, and no program is started", () => {
    const r = results.inactive;
    assert.equal(r.packs.exec?.status, "na");
    assert.equal(r.packs.exec?.reason, "the exec pack runs only with --active");
    assert.equal(EXEC_NEEDS_ACTIVE, "the exec pack runs only with --active");
    assert.deepEqual(ids(r), []);
    assert.equal(r.sandbox?.active, false);
    assert.equal(r.options.active, false);
  });

  it("asking for the exec pack by name without --active is a configuration error (exit 2), not a silent skip", async () => {
    await assert.rejects(runExec("good", { active: false, packsExplicit: true }), (e: unknown) => e instanceof ConfigError && /needs --active on the command line/.test((e as Error).message));
  });

  it("the pack itself refuses without active, without a sandbox, and without a command tool, each with a reason", () => {
    assert.deepEqual(execPack.applies({ pack: "exec" } as never), { ok: false, reason: EXEC_NEEDS_ACTIVE });
    assert.deepEqual(execPack.applies({ pack: "exec", active: false } as never), { ok: false, reason: EXEC_NEEDS_ACTIVE });
    const noSandbox = execPack.applies({ pack: "exec", active: true, sandboxEnabled: false } as never);
    assert.equal(noSandbox.ok, false);
    assert.match((noSandbox as { reason: string }).reason, /--no-sandbox/);
    const noTool = execPack.applies({ pack: "exec", active: true, sandbox: {}, classification: [], tools: [] } as never);
    assert.equal(noTool.ok, false);
    assert.match((noTool as { reason: string }).reason, /classified as running a command/);
  });

  it("run() called directly without --active returns four na checks and starts nothing", async () => {
    const out = await execPack.run({ pack: "exec", active: false } as never);
    assert.deepEqual(
      out.map((c) => [c.id, c.verdict]),
      [
        ["exec-injection", "na"],
        ["exec-cwd", "na"],
        ["exec-timeout-cap", "na"],
        ["exec-allowlist", "na"],
      ],
    );
    assert.ok(out.every((c) => c.summary === EXEC_NEEDS_ACTIVE && c.pack === "exec"));
  });

  it("a check disabled in config is na with the reason and its origin; a severity override changes how it is scored", () => {
    const r = results.disabled;
    const cwd = check(r, "exec-cwd");
    assert.equal(cwd.verdict, "na");
    assert.match(cwd.summary, /^disabled by config/);
    const allow = check(r, "exec-allowlist");
    assert.equal(allow.advisory, undefined);
    assert.equal(allow.critical, false);
    assert.equal(gradeOf(r, "exec")?.scored, 3);
  });

  it("every check id a run emits is documented by describe(), once, with the scope rule and the safety wording", () => {
    const docs = describeExec();
    assert.deepEqual(
      docs.map((d) => d.id),
      ["exec-injection", "exec-cwd", "exec-timeout-cap", "exec-allowlist"],
    );
    for (const d of docs) {
      assert.match(d.scope, /^server/);
      assert.equal(d.pack, "exec");
      assert.ok(d.falsePositive && d.falseNegative && d.probes.length, d.id);
    }
    for (const r of Object.values(results))
      for (const id of ids(r))
        assert.ok(
          docs.some((d) => d.id === id),
          id,
        );
    // The published corpus names only the harness programs.
    for (const d of docs) for (const p of d.probes) assert.match(p.text, /sm-(echo|canary|sleep|spew)/, p.id);
    assert.equal(docs.find((d) => d.id === "exec-allowlist")?.advisory, true);
    assert.equal(docs.find((d) => d.id === "exec-injection")?.critical, true);
  });

  it("only harness programs were ever asked for: every exec probe names an sm-* program", () => {
    for (const r of Object.values(results)) {
      for (const c of r.checks.filter((x) => x.pack === "exec")) {
        for (const e of c.evidence) {
          if (e.code === "exec.control.failed" || e.code?.endsWith("unfillable")) continue;
          assert.match(e.probe, /sm-(echo|canary|sleep|spew)/, e.probe);
        }
      }
    }
  });

  it("every sandbox was removed and no program was left running", () => {
    for (const [k, r] of Object.entries(results)) {
      assert.equal(r.sandbox?.cleanedUp, true, k);
      assert.deepEqual(r.sandbox?.leftoverProcesses, [], k);
      if (r.sandbox?.dir) assert.equal(existsSync(r.sandbox.dir), false, k);
    }
    assert.deepEqual(leftovers(), []);
  });
});
