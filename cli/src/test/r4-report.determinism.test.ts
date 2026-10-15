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
 * Two REAL runs of a synthetic net toy server, rendered in every format with redaction on: no real sandbox path (in any
 * encoding), no real listener port (after any host spelling) and no per-run token is left, the human formats are
 * byte-identical, and the machine formats differ only in the fields that are allowed to (startedAt, durationMs,
 * sandbox.listenerPort, startTimeUtc).
 */

const NET_TOY = fileURLToPath(new URL("../toy/net.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

let dir: string;
let parent: string;
const runs: RunResult[] = [];
/** The toy modes that put the most per-run text in a report: loopback hits, file:// reads, any-scheme fetches and redirect hops. */
const MODES = ["open", "schemes", "anyscheme", "hop"];

async function runNet(mode: string): Promise<RunResult> {
  const config: SealmarkConfig = { name: "toy-net", version: "0.0.1", server: { command: process.execPath, args: [NET_TOY, "--mode", mode], env: {} } };
  const packs: PackId[] = ["core", "net"];
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: false, timeoutProbeSec: 2 });
  const effective: EffectiveConfig = { ...base, integrity: INTEGRITY, cwd: dir, sandbox: { ...base.sandbox, dir: parent } };
  return runHarness({ config, effective, packs, packsExplicit: false, timeoutProbeSec: 2, log: quiet });
}

/**
 * The one number that still differs between two runs outside the report layer: how many bytes the listener had sent when the
 * client cut the oversized reply off (a timing quantity; the redactor cannot and should not touch it). The net pack prints it as
 * `under N` with N a power of two from 8 (which makes two runs agree in practice, not by construction: under heavy load a run can
 * step to the next bound), so the test blanks the figure instead of asserting the bound.
 */
const cutoff = (s: string) => s.replace(/the listener sent (?:under )?[\d.]+ of 64 MiB/g, "the listener sent N of 64 MiB");
const render = (f: ReportFormat, r: RunResult) => cutoff(renderReport(f, [r], { verbosity: "verbose" }));

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

/** Every spelling of a directory a report could carry. */
function spellings(d: string): string[] {
  const parts = d.split("/").filter(Boolean);
  return [d, encodeURI(d), encodeURIComponent(d), encodeURIComponent(d).toLowerCase(), d.replace(/\//g, "\\"), d.replace(/\//g, "\\\\"), parts[parts.length - 1]!];
}

describe("two real runs of a net toy server, every format", { timeout: 420_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r4-det-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    // One mode at a time, the two runs of a mode side by side: the suite runs other files in parallel, so the load stays small.
    for (const m of MODES) runs.push(...(await Promise.all([runNet(m), runNet(m)])));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("the two runs really differ in sandbox, port and tokens", () => {
    const [a, b] = runs;
    assert.notEqual(a!.sandbox!.dir, b!.sandbox!.dir);
    assert.ok(a!.sandbox!.listenerPort && b!.sandbox!.listenerPort);
    assert.notEqual(a!.sandbox!.listenerPort, b!.sandbox!.listenerPort);
    assert.notEqual(JSON.stringify(a!.checks), JSON.stringify(b!.checks), "the evidence carries per-run tokens before redaction");
  });

  for (const f of FORMATS) {
    it(`${f}: no real sandbox path, port or token`, () => {
      for (const r of runs) {
        const out = render(f, r);
        for (const s of spellings(r.sandbox!.dir!)) assert.ok(!out.includes(s), `${f} carries ${s}`);
        const port = String(r.sandbox!.listenerPort);
        const m = new RegExp(`(?<![0-9])${port}(?![0-9])`).exec(stable(out));
        assert.equal(m, null, `${f} carries the listener port ${port}`);
        assert.ok(!/sm-[a-z]*-?[0-9a-f]{8,}/.test(out), `${f} carries a per-run token: ${/sm-[a-z]*-?[0-9a-f]{8,}/.exec(out)?.[0]}`);
      }
    });
  }

  for (const f of ["text", "markdown", "summary", "badge", "shields"] as const) {
    it(`${f}: byte-identical between the two runs`, () => {
      for (let i = 0; i < runs.length; i += 2) assert.equal(render(f, runs[i]!), render(f, runs[i + 1]!), MODES[i / 2]);
    });
  }

  for (const f of ["json", "junit", "sarif"] as const) {
    it(`${f}: identical but for startedAt, durationMs, sandbox.listenerPort and startTimeUtc`, () => {
      for (let i = 0; i < runs.length; i += 2) assert.equal(stable(render(f, runs[i]!)), stable(render(f, runs[i + 1]!)), MODES[i / 2]);
    });
  }
});
