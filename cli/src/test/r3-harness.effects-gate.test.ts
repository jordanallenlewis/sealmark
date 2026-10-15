import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { loadEffectiveConfig } from "../config/index.js";
import { runDoctor } from "../doctor.js";
import { effectsGateReason } from "../packs/effects.js";
import { runHarness } from "../run.js";
import { TOY, quiet, toyConfig } from "./helpers.js";

// run, doctor and effects.applies() read one wording from effectsGateReason. The `nosql` toy has no path, repository or URL tool,
// so the first of the two classification reasons applies.
describe("r3-harness: one effects gate wording", { timeout: 120_000 }, () => {
  let root: string;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sm-r3-gate-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  const expected = effectsGateReason([], { active: false, sandboxEnabled: true })!;

  it("the helper has the two classification reasons and nothing else", () => {
    assert.match(expected, /harness-owned target/);
  });

  it("run reports the helper's text for the pack", async () => {
    const r = await runHarness({ config: toyConfig("nosql"), packs: ["core", "effects"], packsExplicit: false, timeoutProbeSec: 2, log: quiet });
    assert.equal(r.packs.effects?.reason, expected);
  });

  it("doctor reports the helper's text for the pack", async () => {
    const dir = join(root, "doc");
    mkdirSync(join(dir, "sb"), { recursive: true });
    writeFileSync(
      join(dir, "sealmark.yaml"),
      `schema_version: 1\nname: gate\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--mode", "nosql"])}\n  env: {}\nsandbox:\n  dir: ${JSON.stringify(join(dir, "sb"))}\n`,
    );
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    const r = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
    const p = r.servers[0].packs.find((x) => x.pack === "effects")!;
    assert.equal(p.applies, false);
    assert.equal(p.reason, expected);
  });
});
