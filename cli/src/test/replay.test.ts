import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ConfigError, checkReplay, computeHash, loadEffectiveConfig, type EffectiveConfig, type LoadOptions } from "../config/index.js";
import { cliKit } from "./helpers.js";

// A report is untrusted input. Its config.hash proves nothing about who wrote it (anyone can compute it), so --replay may
// only restore grade-affecting settings; it must never be a way to set --active, --yes, plugins or a database.

let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-replay-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";

function proj(yaml: string): string {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), yaml);
  return dir;
}
const load = (yaml: string, o: Partial<LoadOptions> = {}): EffectiveConfig => loadEffectiveConfig({ cwd: proj(yaml), isolated: true, env: {}, ...o });
function failure(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `expected a ConfigError, got ${String(e)}`);
    return e.message;
  }
  assert.fail("expected a ConfigError");
}

describe("--replay is not a config channel", () => {
  it("active, yes, plugins, server, db.pg, probes and sql_tools cannot ride in config.locked, even with a matching hash", () => {
    const rep = load(BASE).integrity;
    for (const [key, val] of [
      ["active", true],
      ["yes", true],
      ["plugins", [{ module: "../evil.mjs" }]],
      ["db.pg", "postgres://postgres:pw@victim:5432/postgres"],
      ["server.command", "evil"],
      ["probes", []],
      ["sql_tools", []],
    ] as const) {
      const locked = { ...rep.locked, [key]: val };
      const evil = { ...rep, locked, hash: computeHash(locked) };
      assert.equal(computeHash(evil.locked), evil.hash, "the forged hash is consistent");
      assert.match(checkReplay(evil) ?? "", /may not set/, key);
      assert.match(failure(() => load(BASE, { replay: evil })), /^--replay: config\.locked carries setting\(s\) a report may not set/, key);
    }
  });

  it("replayed values are validated like file values: a wrong type or an out-of-range number is refused", () => {
    const rep = load(BASE).integrity;
    for (const [key, val, re] of [
      ["timeout_probe_sec", "soon", /timeout_probe_sec/],
      ["timeout_probe_sec", -5, /timeout_probe_sec/],
      ["packs", ["core", "nonsense"], /packs/],
    ] as const) {
      const locked = { ...rep.locked, [key]: val };
      const evil = { ...rep, locked, hash: computeHash(locked) };
      assert.equal(checkReplay(evil), undefined, "the hash is consistent, so only validation can refuse it");
      assert.match(failure(() => load(BASE, { replay: evil })), re, `${key}=${String(val)}`);
    }
  });

  it("a genuine report still replays (through JSON, as the CLI reads it) and never turns on active or yes", () => {
    const original = load(`${BASE}timeout_probe_sec: 20\n`);
    const cfg = load(BASE, { replay: JSON.parse(JSON.stringify(original.integrity)) });
    assert.equal(cfg.active, false);
    assert.equal(cfg.yes, false);
    assert.equal(cfg.timeoutProbeSec, 20);
    assert.equal(cfg.integrity.hash, original.integrity.hash);
  });
});

describe("cli: sealmark run --replay with a forged report", { timeout: 120_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(root, "cli-"));
  });
  const kit = cliKit(() => dir);

  it("exits 2 and never loads the plugin module", () => {
    const marker = join(dir, "plugin-ran.txt");
    const plugin = join(dir, "evil.mjs");
    writeFileSync(plugin, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "ran");\nexport default {};\n`);
    const cfg = kit.toyConfig("sealmark.yaml", "good");
    const rep = load(BASE).integrity;
    const locked = { ...rep.locked, active: true, yes: true, plugins: [{ module: plugin }] };
    const report = join(dir, "evil-report.json");
    writeFileSync(report, JSON.stringify({ config: { ...rep, locked, hash: computeHash(locked) } }));
    const r = kit.sealmark(["run", "--config", cfg, "--pack", "core", "--timeout-probe", "2", "--replay", report]);
    assert.equal(r.code, 2, r.err + r.out);
    assert.match(r.err, /may not set/);
    assert.equal(rmMarker(marker), false, "the plugin module was never imported");
  });
});

function rmMarker(p: string): boolean {
  try {
    rmSync(p);
    return true;
  } catch {
    return false;
  }
}
