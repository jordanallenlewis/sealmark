// Round 6 integration: two REAL runs of the scoped toy with the example config, in the good
// mode and in a mode whose replies carry the caller's token, rendered in every format with redaction on. The stub's port, the two minted
// bearers, the minted reply rows and the error canary may not survive; the human formats are byte-identical between the two runs, and JSON
// differs only in the four fields the determinism claim names: startedAt, durationMs, sandbox.listenerPort and upstream.url (plus the
// measured time of each valid call, probes.calls[].elapsedMs, a timing like durationMs).
// Also here: the seams the integration package pins (the three pack-id lists, the placeholder lists, doctor and run on the auto-added packs).
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { HARNESS_KEYS as CONFIG_HARNESS_KEYS } from "../config/placeholders.js";
import { PACK_IDS, loadEffectiveConfig, toSealmarkConfig, type EffectiveConfig } from "../config/index.js";
import { autoAddedPacks } from "../doctor.js";
import { REGISTRY, RUN_ORDER } from "../packs/index.js";
import { PROBE_HARNESS_KEYS } from "../probes.js";
import { FORMATS, renderReport, type ReportFormat } from "../report.js";
import { runHarness } from "../run.js";
import { BUILTIN_PACKS, CANDIDATE_PACKS, type PackId, type RunResult } from "../types.js";
import { freePort, quiet } from "./helpers.js";

const FIXTURE = fileURLToPath(new URL("../../src/test/fixtures/config/scoped-http.yaml", import.meta.url));
const TOY = fileURLToPath(new URL("../toy/scoped-http.js", import.meta.url));
const MODES = ["good", "cred-echoed"];

let dir: string;
const runs: RunResult[] = [];
const configs: EffectiveConfig[] = [];

/** Both runs of a mode use the same server port, so the server URL in the report is the same; everything else is per run. */
async function runMode(mode: string, port: number): Promise<RunResult> {
  const root = mkdtempSync(join(dir, `${mode}-`));
  const text = readFileSync(FIXTURE, "utf8").replaceAll("dist/toy/scoped-http.js", TOY).replaceAll("8080", String(port)).replace('"--mode", "good"', `"--mode", "${mode}"`);
  writeFileSync(join(root, "sealmark.yaml"), text);
  const cfg = loadEffectiveConfig({ cwd: root, isolated: true, env: {} });
  configs.push(cfg);
  return runHarness({ config: toSealmarkConfig(cfg), effective: cfg, packs: cfg.packs as PackId[], packsExplicit: cfg.packsExplicit, timeoutProbeSec: cfg.timeoutProbeSec, log: quiet });
}

/**
 * The fields the determinism claim lets differ, blanked. The listener port and the stub port appear only in those fields after redaction.
 * `probes.calls[].elapsedMs` is the measured time of each valid call: a timing, like durationMs, present only when probes: are declared.
 */
function stable(text: string): string {
  return text
    .replace(/"elapsedMs": \d+/g, '"elapsedMs": 0')
    .replace(/"startedAt": "[^"]*"/g, '"startedAt": ""')
    .replace(/"startTimeUtc": "[^"]*"/g, '"startTimeUtc": ""')
    .replace(/"durationMs": [\d.]+/g, '"durationMs": 0')
    .replace(/"listenerPort": \d+/g, '"listenerPort": 0')
    .replace(/"url": "http:\/\/127\.0\.0\.1:[^"]*"/g, '"url": ""')
    .replace(/timestamp="[^"]*"/g, 'timestamp=""')
    .replace(/ time="[\d.]+"/g, ' time="0"');
}

/** Per-run shapes the harness mints: tokens, bearers, reply rows, the error canary. */
const RAW = [/sm-bearer-[ab]-[0-9a-f]{12}/, /sm-row-[0-9a-f]{8}/, /sm-upstream-err-[0-9a-f]+/, /sm-[a-z]*-?[0-9a-f]{8,}/, /sealmark-[0-9a-f]{10}/];

describe("round 6: two real runs of the scoped toy, every format", { timeout: 600_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r6-det-"));
    for (const m of MODES) {
      const port = await freePort();
      runs.push(await runMode(m, port), await runMode(m, port));
    }
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const render = (f: ReportFormat, r: RunResult) => renderReport(f, [r], { verbosity: "verbose" });

  it("the two runs really differ in sandbox, stub port and bearers", () => {
    const [a, b] = runs;
    assert.notEqual(a!.sandbox!.dir, b!.sandbox!.dir);
    assert.notEqual(a!.upstream?.url, b!.upstream?.url);
    assert.equal(a!.upstream?.kind, "http");
    assert.deepEqual(a!.identities, { names: ["a", "b"], source: "minted" });
  });

  for (const f of FORMATS) {
    it(`${f}: no real sandbox path, stub port, bearer, reply row or canary`, () => {
      for (const r of runs) {
        const out = render(f, r);
        assert.ok(!out.includes(r.sandbox!.dir!), `${f} carries the sandbox`);
        const port = /:(\d+)$/.exec(r.upstream!.url)![1]!;
        assert.ok(!out.includes(`127.0.0.1:${port}`), `${f} carries the stub port ${port}`);
        for (const re of RAW) assert.equal(re.exec(out), null, `${f} carries ${re.exec(out)?.[0]}`);
      }
    });
  }

  for (const f of ["text", "markdown", "summary", "badge", "shields"] as const) {
    it(`${f}: byte-identical between the two runs`, () => {
      for (let i = 0; i < runs.length; i += 2) assert.equal(render(f, runs[i]!), render(f, runs[i + 1]!), MODES[i / 2]);
    });
  }

  for (const f of ["json", "junit", "sarif"] as const) {
    it(`${f}: identical but for startedAt, durationMs, sandbox.listenerPort and upstream.url`, () => {
      for (let i = 0; i < runs.length; i += 2) assert.equal(stable(render(f, runs[i]!)), stable(render(f, runs[i + 1]!)), MODES[i / 2]);
    });
  }

  it("doctor and run add the same candidate packs for the example config (seam S11)", () => {
    const cfg = configs[0]!;
    const auto = autoAddedPacks(cfg, { hasSqlTool: true });
    assert.deepEqual([...auto.packs].sort(), ["custom", "scope", "sql-guard", "upstream"]);
    assert.deepEqual([...runs[0]!.options.packsRequested].sort(), [...new Set([...(cfg.packs as PackId[]), ...auto.packs])].sort());
  });
});

describe("round 6: the lists that must agree", () => {
  it("BUILTIN_PACKS, PACK_IDS and the registry name the same packs, and RUN_ORDER holds each candidate pack (seam S5)", () => {
    assert.deepEqual([...PACK_IDS].sort(), [...BUILTIN_PACKS].sort());
    assert.deepEqual(REGISTRY.map((p) => p.id).sort(), [...BUILTIN_PACKS].sort());
    for (const id of CANDIDATE_PACKS) assert.ok(RUN_ORDER.includes(id), id);
  });

  it("the probe placeholders are the configuration's harness placeholders minus {token}, {upstream} and {bearer...} (seam S4)", () => {
    // A probe may not address the stub or choose a credential by placeholder: `identity:` chooses the caller.
    const withheld = new Set(["token", "upstream", "bearer", "bearer:a", "bearer:b"]);
    assert.deepEqual([...PROBE_HARNESS_KEYS].sort(), CONFIG_HARNESS_KEYS.filter((k) => !withheld.has(k)).sort());
  });
});
