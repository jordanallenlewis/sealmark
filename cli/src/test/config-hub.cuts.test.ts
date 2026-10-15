import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { loadEffectiveConfig, standardHash, type EffectiveConfig } from "../config/index.js";
import { cliKit } from "./helpers.js";

// retries.connect, retries.call, concurrency.servers, concurrency.packs and output.interactive were documented as working and read by nothing.
// An existing file that sets them still loads; they warn and are dropped.

let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-chcuts-"));
});
after(() => rmSync(root, { recursive: true, force: true }));
const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";
const load = (yaml: string): EffectiveConfig => {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), yaml);
  return loadEffectiveConfig({ cwd: dir, isolated: true, env: {} });
};

describe("settings nothing reads", () => {
  it("a file with retries.connect loads with a 'no longer used' warning and no error", () => {
    const c = load(`${BASE}retries: { connect: 3 }\n`);
    assert.equal(c.warnings.filter((w) => /retries\.connect is no longer used and is ignored$/.test(w)).length, 1, c.warnings.join("\n"));
    assert.deepEqual(c.retries, { call: 0 });
  });

  it("concurrency and output.interactive warn the same way and leave no trace in the effective config", () => {
    const c = load(`${BASE}concurrency: { servers: 4, packs: 1 }\noutput: { interactive: false }\n`);
    for (const p of ["concurrency.servers", "concurrency.packs", "output.interactive"]) assert.ok(c.warnings.some((w) => w.endsWith(`${p} is no longer used and is ignored`)), p);
    assert.equal("concurrency" in c, false);
    assert.equal("interactive" in c.output, false);
    assert.equal("concurrency" in c.value, false);
  });

  it("the grade is untouched: the standard hash does not depend on the cut keys, retries.call included (0.3-draft: retired, unlocked)", () => {
    const plain = load(BASE);
    const cut = load(`${BASE}retries: { connect: 3, call: 2 }\nconcurrency: { servers: 2 }\noutput: { interactive: false }\n`);
    assert.equal(cut.integrity.hash, plain.integrity.hash);
    assert.equal(cut.integrity.hash, standardHash());
    assert.equal(cut.integrity.standard, true);
    assert.deepEqual(cut.retries, { call: 0 });
  });

  it("retries.call loads with a 'no longer used' warning, is ignored, and no longer makes a run CUSTOM", () => {
    const c = load(`${BASE}retries: { call: 2 }\n`);
    assert.equal(c.warnings.filter((w) => /retries\.call is no longer used and is ignored$/.test(w)).length, 1, c.warnings.join("\n"));
    assert.deepEqual(c.retries, { call: 0 });
    assert.equal(c.integrity.standard, true);
    assert.equal(c.integrity.hash, standardHash());
  });

  it("describe --json marks the five keys deprecated, with nothing to use instead", () => {
    const dir = mkdtempSync(join(root, "d"));
    const { sealmark } = cliKit(() => dir);
    const r = sealmark(["describe", "--json"]);
    assert.equal(r.code, 0, r.err);
    const keys = (JSON.parse(r.out) as { configKeys: { path: string; deprecated: boolean; standardLocked: boolean; replacedBy?: string[] }[] }).configKeys;
    for (const p of ["retries.connect", "retries.call", "concurrency.servers", "concurrency.packs", "output.interactive"]) {
      const k = keys.find((x) => x.path === p);
      assert.ok(k, p);
      assert.equal(k.deprecated, true, p);
      assert.deepEqual(k.replacedBy, [], p);
    }
    assert.equal(keys.find((x) => x.path === "retries.call")?.standardLocked, false);
  });

  it("server.start_timeout_sec documents its real default (60) and version, without becoming a real default", () => {
    const dir = mkdtempSync(join(root, "d"));
    const { sealmark } = cliKit(() => dir);
    const keys = (JSON.parse(sealmark(["describe", "--json"]).out) as { configKeys: { path: string; default: unknown; since: string }[] }).configKeys;
    for (const p of ["server.start_timeout_sec", "servers.*.start_timeout_sec"]) {
      const k = keys.find((x) => x.path === p)!;
      assert.equal(k.default, 60, p);
      assert.equal(k.since, "0.2-draft", p);
    }
    assert.equal("start_timeout_sec" in (load(BASE).server as unknown as Record<string, unknown>), false);
  });
});
