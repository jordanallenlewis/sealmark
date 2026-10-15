// The custom pack runs when the user declares a check: the default pack list has no `custom`, and a check that never ran could not
// fail the gate. Doctor and run must also agree on whether it runs.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { runDoctor } from "../doctor.js";
import type { ProbeCall } from "../probes.js";
import { runHarness } from "../run.js";
import type { PackId, RunResult } from "../types.js";
import { CLI, hermeticEnv } from "./helpers.js";
import { spawnSync } from "node:child_process";

const HANG = fileURLToPath(new URL("../toy/hang.js", import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;

const CHECK = `check: { id: custom-note-acked, label: "A note is acknowledged", critical: false, scope: "server (note tool)" }`;
const PASSING = `  - { id: note-ack, ${CHECK}, tool: note, args: { text: hello }, expect: { text: { matches: "^noted" } } }\n`;
// The note tool succeeds, so an expectation that it fails cannot hold.
const FAILING = `  - { id: note-ack, ${CHECK}, tool: note, args: { text: hello }, expect: { is_error: true } }\n`;
const PLAIN = `  - { id: note-plain, tool: note, args: { text: hello } }\n`;

function write(name: string, probes: string, extra = ""): string {
  const file = join(dir, name);
  writeFileSync(file, `schema_version: 1\nname: ${name.replace(/\W/g, "-")}\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "iserror"]\nsandbox:\n  dir: ${q(parent)}\n${extra}probes:\n${probes}`);
  return file;
}

async function run(file: string, over: { packs?: PackId[]; flagPacks?: string[] } = {}): Promise<{ r: RunResult; log: string[] }> {
  const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file, ...(over.flagPacks ? { pack: over.flagPacks } : {}) }, env: {}, isolated: true });
  const log: string[] = [];
  const r = await runHarness({
    config: { name: eff.name, version: eff.version, server: eff.server },
    effective: eff,
    packs: over.packs ?? (eff.packs as PackId[]),
    packsExplicit: Boolean(over.packs) || eff.packsExplicit,
    timeoutProbeSec: 2,
    log: (s) => log.push(s),
  });
  return { r, log };
}

const NOTE = "note: probes with a check were declared, so the custom pack is included";

describe("harness-core: the custom pack runs when a check is declared", { timeout: 240_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-hc-custom-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  it("a check probe with the default pack list produces a graded custom pack, and says it added the pack", async () => {
    const { r, log } = await run(write("default-list.yaml", PASSING));
    assert.equal(r.packs.custom?.status, "graded", JSON.stringify(r.packs.custom));
    assert.equal(r.checks.find((c) => c.id === "custom-note-acked")?.verdict, "pass");
    assert.equal(r.probes?.custom.length, 1, "the probe's record is in the report");
    assert.ok(r.options.packsRequested.includes("custom"));
    assert.ok(log.includes(NOTE), log.join("\n"));
    // A check probe differs from the standard profile, so the run is CUSTOM and no standard grade is claimed.
    assert.equal(r.config?.standard, false);
    assert.equal(r.badge?.eligible, false);
  });

  it("a failing check reaches the grade: the pack fails instead of silently not running", async () => {
    const { r } = await run(write("failing.yaml", FAILING));
    const c = r.checks.find((x) => x.id === "custom-note-acked");
    assert.equal(c?.verdict, "fail");
    const p = r.packs.custom;
    assert.equal(p?.status, "graded");
    assert.notEqual(p?.status === "graded" ? p.grade?.letter : "A", "A");
  });

  it("a pack list nobody chose (the library's default origin) gets custom appended; `--pack custom` is not added twice", async () => {
    const file = write("explicit.yaml", PASSING);
    const only = await run(file, { packs: ["core"] });
    assert.equal(only.r.packs.custom?.status, "graded");
    assert.ok(only.log.includes(NOTE));
    const named = await run(file, { flagPacks: ["core", "custom"] });
    assert.equal(named.r.packs.custom?.status, "graded");
    assert.equal(named.r.options.packsRequested.filter((p) => p === "custom").length, 1);
    assert.ok(!named.log.includes(NOTE), "the user asked for the pack, so there is nothing to announce");
  });

  it("a pack list typed with --pack is respected: custom is not added, and the report says the probes were skipped (round 4, E7)", async () => {
    const { r } = await run(write("typed-list.yaml", PASSING), { flagPacks: ["core"] });
    assert.equal(r.packs.custom, undefined);
    assert.ok(r.warnings?.includes("probes with a check were declared but the pack list omits custom, so they were skipped (add custom to --pack or packs:)"), JSON.stringify(r.warnings));
  });

  it("near-miss: a probe without a check stays a coverage-only valid call and does not add the pack", async () => {
    const { r, log } = await run(write("plain.yaml", PLAIN));
    assert.equal(r.packs.custom, undefined);
    assert.ok(!r.options.packsRequested.includes("custom"));
    assert.ok(!log.includes(NOTE));
    assert.equal(r.probes?.calls.length, 1);
    assert.equal((r.probes?.calls[0] as ProbeCall | undefined)?.valid, true);
  });

  it("doctor and run agree: custom would run exactly when run runs it", async () => {
    for (const [name, probes, runsCustom] of [
      ["agree-check.yaml", PASSING, true],
      ["agree-plain.yaml", PLAIN, false],
    ] as const) {
      const file = write(name, probes);
      const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
      const d = await runDoctor({ cfg: eff, startupTimeoutMs: 20_000, handleSignals: false });
      const custom = d.servers[0]!.packs.find((p) => p.pack === "custom")!;
      assert.equal(custom.requested && custom.applies, runsCustom, `${name}: doctor says ${custom.requested ? "requested" : "not requested"}, ${custom.applies ? "applies" : "n/a"}: ${custom.reason}`);
      const { r } = await run(file);
      assert.equal(r.packs.custom !== undefined, runsCustom, `${name}: run`);
    }
  });

  it("exit codes: a failing check exits 1 on the default gate, a clean run exits 0", () => {
    // custom is named: a typed pack list is respected (round 4), so a check probe reaches the gate only when the list includes custom.
    const base = ["run", "--timeout-probe", "2", "--pack", "core", "--pack", "custom"];
    const code = (file: string) => spawnSync(process.execPath, [CLI, ...base, "--config", file], { cwd: dir, encoding: "utf8", timeout: 120_000, env: hermeticEnv() });
    const bad = code(write("exit-bad.yaml", FAILING));
    assert.equal(bad.status, 1, `${bad.stdout}\n${bad.stderr}`);
    assert.match(bad.stderr + bad.stdout, /custom-note-acked/);
    const good = code(write("exit-good.yaml", PASSING));
    assert.equal(good.status, 0, `${good.stdout}\n${good.stderr}`);
  });
});
