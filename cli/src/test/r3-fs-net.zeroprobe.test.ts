import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { CheckResult, RunResult, SealmarkConfig } from "../types.js";
import { runPacks } from "./packctx.js";

// An escape check in which no probe was answered proves nothing: it is inconclusive, never a pass. "Sent" means the harness built
// the arguments, called the tool and the server answered (any reply). The near-miss, a server that hangs on one probe only, still passes.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};

const toy = (mode: string): SealmarkConfig => ({
  name: `toy-fs-stallafter-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-stallafter.js", import.meta.url)), "--mode", mode, "--root", "{sandbox}"], env: {} },
});

const check = (m: string, id: string): CheckResult => results[m].checks.find((c) => c.id === id)!;

describe("r3 fs-net: the zero-probe guard", { timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r3-zeroprobe-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(["stall", "first-hang"].map(async (m) => void (results[m] = await runPacks(toy(m), ["fs"], where()))));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a server that stops answering escape paths: both escape checks are inconclusive, with one evidence line per reason", () => {
    for (const id of ["fs-read-escape", "fs-write-escape"]) {
      const c = check("stall", id);
      assert.equal(c.verdict, "inconclusive", `${id}: ${c.summary}`);
      assert.match(c.summary, /^no escape probe was answered on (read_file|write_file): \d+ timed out, \d+ could not be built, \d+ removed by config/, id);
      assert.ok(c.evidence.some((e) => e.code === "fs.escape.timed-out" && /timed out/.test(e.outcome)), JSON.stringify(c.evidence.map((e) => e.code)));
      assert.ok(c.evidence.some((e) => e.code === "fs.control.read" || e.code === "fs.control.write"), "the controls did pass, so the tool was reachable");
    }
  });

  it("the pack is provisional and has no pass among its escape checks", () => {
    const g = results.stall.packs.fs?.grade;
    assert.ok(g, `an fs grade exists: ${JSON.stringify(results.stall.packs.fs)}`);
    assert.equal(g.provisional, true);
    for (const id of ["fs-read-escape", "fs-write-escape"]) assert.notEqual(check("stall", id).verdict, "pass", id);
  });

  it("near miss: only the first probe hangs, the rest are refused, so the checks pass and say how many were answered", () => {
    for (const id of ["fs-read-escape", "fs-write-escape"]) {
      const c = check("first-hang", id);
      assert.equal(c.verdict, "pass", `${id}: ${c.summary}`);
      assert.match(c.summary, /\((\d+) of (\d+) variants answered; 1 timed out\)/, id);
      const m = /\((\d+) of (\d+) variants answered/.exec(c.summary)!;
      assert.equal(Number(m[1]) + 1, Number(m[2]), "exactly one probe was not answered");
    }
  });
});
