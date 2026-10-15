import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { checkReplay, computeHash, loadEffectiveConfig, type EffectiveConfig, type LoadOptions } from "../config/index.js";

// A replayed report must not change where or how the server runs: sandbox.* and net.control_url are locked leaves (every
// genuine report carries them, so checkReplay accepts them) but loadEffectiveConfig never applies them.

let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-chreplay-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";
const load = (yaml: string, o: Partial<LoadOptions> = {}): EffectiveConfig => {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), yaml);
  return loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, ...o });
};
const asReport = (c: EffectiveConfig) => JSON.parse(JSON.stringify(c.integrity)) as EffectiveConfig["integrity"];
const forge = (extra: Record<string, unknown>) => {
  const rep = asReport(load(BASE));
  const locked = { ...rep.locked, ...extra };
  return { ...rep, locked, hash: computeHash(locked) };
};

describe("--replay does not apply sandbox.* or net.control_url", () => {
  it("a foreign report with keep_env, scrub_env, enabled and control_url changes none of them and a warning names each", () => {
    const evil = forge({
      "sandbox.keep_env": ["MY_CI_SECRET", "AWS_SECRET_ACCESS_KEY"],
      "sandbox.scrub_env": false,
      "sandbox.enabled": false,
      "net.control_url": "http://169.254.169.254/latest/meta-data/",
    });
    assert.equal(checkReplay(evil), undefined, "the hash is consistent, so only loadEffectiveConfig can refuse to apply them");
    const cfg = load(BASE, { replay: evil });
    assert.deepEqual(cfg.sandbox.keep_env, []);
    assert.equal(cfg.sandbox.scrub_env, true);
    assert.equal(cfg.sandbox.enabled, true);
    assert.equal(cfg.net.control_url, null);
    for (const p of ["sandbox.keep_env", "sandbox.scrub_env", "sandbox.enabled", "net.control_url"]) {
      assert.equal(cfg.warnings.filter((w) => w.startsWith(`--replay: ${p} is not replayed`)).length, 1, p);
    }
    assert.match(cfg.warnings.join("\n"), /sandbox\.keep_env is not replayed.*the local setting \[\] stays/);
    assert.equal(cfg.integrity.standard, true, "nothing was applied, so the report cannot make the run CUSTOM through these leaves");
  });

  it("a genuine report from a standard run replays with no warning", () => {
    const original = load(BASE);
    const cfg = load(BASE, { replay: asReport(original) });
    assert.deepEqual(cfg.warnings, []);
    assert.equal(cfg.integrity.hash, original.integrity.hash);
  });

  it("a replayed checks.* leaf still applies", () => {
    const original = load(`${BASE}checks:\n  fs-size-cap: { pass_mib: 8 }\n`);
    const cfg = load(BASE, { replay: asReport(original) });
    assert.equal(cfg.checks["fs-size-cap"].pass_mib, 8);
    assert.equal(cfg.integrity.hash, original.integrity.hash);
    assert.deepEqual(cfg.warnings, []);
  });
});
