import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import type { RunResult } from "../types.js";
import { FAST, cliKit } from "./helpers.js";

const NOARG = fileURLToPath(new URL("../toy/noarg-error.js", import.meta.url));

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r3-noarg-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeConfig } = cliKit(() => dir);

const run = (mode: string): RunResult => {
  const cfg = writeConfig(`${mode}.yaml`, process.execPath, [NOARG, "--mode", mode]);
  const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json"]);
  return JSON.parse(r.out) as RunResult;
};
const robust = (r: RunResult) => r.checks.find((c) => c.id === "robust-input")!;

describe("robust-input: a refused no-argument call is not a valid call", { timeout: 120_000 }, () => {
  it("error: no valid call counted, coverage stays hygiene-only, and the tool is listed as not covered with the reason", () => {
    const r = run("error");
    assert.equal(r.coverage?.validCalls, 0);
    assert.equal(r.coverage?.toolsCalledValid, 0);
    assert.equal(r.coverage?.level, "hygiene-only");
    assert.deepEqual(robust(r).coverage?.probed, []);
    assert.deepEqual(robust(r).coverage?.notCovered, [{ tool: "status", reason: "its no-argument call returned an error, so no tool behaviour was exercised" }]);
  });

  it("ok: the same call answered normally is one valid call on one tool", () => {
    const r = run("ok");
    assert.equal(r.coverage?.validCalls, 1);
    assert.equal(r.coverage?.toolsCalledValid, 1);
    assert.deepEqual(robust(r).coverage?.probed, ["status"]);
    assert.deepEqual(robust(r).coverage?.notCovered, []);
  });
});
