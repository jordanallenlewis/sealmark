import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { FORMATS, renderReport, type ReportFormat } from "../report.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { ConfigIntegrity, EffectiveConfig, PackId, RunResult, SealmarkConfig } from "../types.js";
import { quiet } from "./helpers.js";

/**
 * The README determinism claim, round 5: two REAL runs of the synthetic fs toy at `--verbosity verbose`, and two of the synthetic git
 * fixture at normal verbosity, rendered in every format with redaction on. The control-file names (`w-ctl-sm-<hex>-abs.txt`), the probe
 * files (`w-sm-<hex>-3.txt`), the control token (`sm-control-<hex>`), `pwned-<hex>` and commit ids may not survive, the human formats are
 * byte-identical between the two runs, and JSON differs only in startedAt, durationMs and sandbox.listenerPort.
 */

const FS_TOY = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
const GIT_TOY = fileURLToPath(new URL("../toy/git.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

let dir: string;
let parent: string;
const fsRuns: RunResult[] = [];
const gitRuns: RunResult[] = [];
const FS_MODES = ["good", "traverse"];
const GIT_MODES = ["good", "inject"];

async function run(toy: string, args: string[], packs: PackId[]): Promise<RunResult> {
  const config: SealmarkConfig = { name: "toy", version: "0.0.1", server: { command: process.execPath, args: [toy, ...args], env: {} } };
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: false, timeoutProbeSec: 2 });
  const effective: EffectiveConfig = { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent } };
  return runHarness({ config, effective, packs, packsExplicit: false, timeoutProbeSec: 2, log: quiet });
}

const runFs = (mode: string) => run(FS_TOY, ["--mode", mode, "--root", "{sandbox}"], ["core", "fs"]);
const runGit = (mode: string) => run(GIT_TOY, ["--mode", mode, "--repo", "{sandbox}/repo"], ["core", "git"]);

/** The one timing figure outside the report layer that may differ (see r4-report.determinism.test.ts). */
const cutoff = (s: string) => s.replace(/the listener sent (?:under )?[\d.]+ of 64 MiB/g, "the listener sent N of 64 MiB");

/** A JSON-ish document with the fields that may differ between two runs blanked. */
function stable(text: string): string {
  return text
    .replace(/"startedAt": "[^"]*"/g, '"startedAt": ""')
    .replace(/"startTimeUtc": "[^"]*"/g, '"startTimeUtc": ""')
    .replace(/"durationMs": [\d.]+/g, '"durationMs": 0')
    .replace(/"listenerPort": \d+/g, '"listenerPort": 0')
    .replace(/timestamp="[^"]*"/g, 'timestamp=""')
    .replace(/ time="[\d.]+"/g, ' time="0"');
}

/** Per-run shapes the harness generates: a token, a control token, a pwned file, a commit id. */
const RAW = [/sm-[a-z]*-?[0-9a-f]{8,}/, /pwned-[0-9a-f]{12}/, /(?<![0-9A-Za-z])[0-9a-f]{40}(?![0-9A-Za-z])/, /sealmark-[0-9a-f]{10}/, /dangling-[0-9a-f]{12}/];

function spellings(d: string): string[] {
  const parts = d.split("/").filter(Boolean);
  return [d, encodeURI(d), encodeURIComponent(d), d.replace(/\//g, "\\"), parts[parts.length - 1]!];
}

describe("two real runs of the fs toy (verbose) and the git fixture (normal), every format", { timeout: 420_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r5-det-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    for (const m of FS_MODES) fsRuns.push(...(await Promise.all([runFs(m), runFs(m)])));
    for (const m of GIT_MODES) gitRuns.push(...(await Promise.all([runGit(m), runGit(m)])));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const sets: { name: string; runs: () => RunResult[]; modes: string[]; verbosity: "verbose" | "normal" }[] = [
    { name: "fs toy, verbose", runs: () => fsRuns, modes: FS_MODES, verbosity: "verbose" },
    { name: "git fixture, normal", runs: () => gitRuns, modes: GIT_MODES, verbosity: "normal" },
  ];

  for (const set of sets) {
    const render = (f: ReportFormat, r: RunResult) => cutoff(renderReport(f, [r], { verbosity: set.verbosity }));

    it(`${set.name}: the two runs really differ in sandbox, port and tokens`, () => {
      const [a, b] = set.runs();
      assert.notEqual(a!.sandbox!.dir, b!.sandbox!.dir);
      assert.notEqual(JSON.stringify(a!.checks), JSON.stringify(b!.checks), "the evidence carries per-run tokens before redaction");
    });

    for (const f of FORMATS) {
      it(`${set.name}, ${f}: no real sandbox path, port, token or commit id`, () => {
        for (const r of set.runs()) {
          const out = render(f, r);
          for (const s of spellings(r.sandbox!.dir!)) assert.ok(!out.includes(s), `${f} carries ${s}`);
          for (const re of RAW) assert.equal(re.exec(out), null, `${f} carries ${re.exec(out)?.[0]}`);
        }
      });
    }

    for (const f of ["text", "markdown", "summary", "badge", "shields"] as const) {
      it(`${set.name}, ${f}: byte-identical between the two runs`, () => {
        const runs = set.runs();
        for (let i = 0; i < runs.length; i += 2) assert.equal(render(f, runs[i]!), render(f, runs[i + 1]!), set.modes[i / 2]);
      });
    }

    for (const f of ["json", "junit", "sarif"] as const) {
      it(`${set.name}, ${f}: identical but for startedAt, durationMs, sandbox.listenerPort and startTimeUtc`, () => {
        const runs = set.runs();
        for (let i = 0; i < runs.length; i += 2) assert.equal(stable(render(f, runs[i]!)), stable(render(f, runs[i + 1]!)), set.modes[i / 2]);
      });
    }
  }
});
