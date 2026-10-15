import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { RunResult, SealmarkConfig } from "../types.js";
import { runPacks } from "./packctx.js";

// Round 4, C2 and C4: a content reader whose control call fails while a listing tool works. fs-size-cap must not say "no tool
// returns file contents", and no real sandbox path may survive in a reason line built from the failing tool's error text.

const TOY = fileURLToPath(new URL("../toy/fs-ctlfail.js", import.meta.url));

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};

const toy = (extra: string[]): SealmarkConfig => ({
  name: "toy-fs-ctlfail",
  version: "0.0.1",
  server: { command: process.execPath, args: [TOY, "--root", "{sandbox}", ...extra], env: {} },
});

const check = (name: string, id: string) => results[name].checks.find((c) => c.id === id)!;

describe("fs pack: a read tool whose control failed next to a list tool that works", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-ctlfail-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    results.broken = await runPacks(toy([]), ["fs"], where());
    results.listonly = await runPacks(toy(["--no-read"]), ["fs"], where());
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("fs-read-escape is a part: the listing was probed, the reader was not judged", () => {
    const c = check("broken", "fs-read-escape");
    assert.equal(c.verdict, "part", c.summary);
    assert.match(c.summary, /read_file/);
  });

  it("fs-size-cap is inconclusive and names the tool whose control failed (it is not n/a)", () => {
    const c = check("broken", "fs-size-cap");
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /the control call of read_file failed, so a large read was not attempted/);
    assert.doesNotMatch(c.summary, /no tool returns file contents/);
  });

  it("near miss: with no read tool at all the size cap stays n/a", () => {
    const c = check("listonly", "fs-size-cap");
    assert.equal(c.verdict, "na", c.summary);
    assert.match(c.summary, /no tool returns file contents/);
  });

  it("no real sandbox path survives in a summary, a coverage reason, the run's not-covered list or anywhere else in the JSON", () => {
    const r = results.broken;
    const reasons = r.checks.flatMap((c) => (c.coverage?.notCovered ?? []).map((n) => n.reason));
    const control = reasons.find((x) => /control call on \{sandbox\}\/ok\.txt failed/.test(x));
    assert.ok(control, `the failed control is listed as not covered: ${JSON.stringify(reasons)}`);
    assert.match(control, /ENOENT/);
    // The toy's message is "...open '<the resolved sandbox path>/ok.txt'", far longer than the 80 characters a reason keeps. Cutting first would leave the start
    // of a real path that no redaction matches, so the test looks for the start of the temp directory, not for the whole sandbox path.
    assert.match(control, /open '\{sandbox\}\/ok\.txt'\)$/, control);
    const roots = [tmpdir(), realpathSync(tmpdir())];
    const leaks = (s: string) => roots.some((t) => s.includes(t));
    for (const c of r.checks) {
      assert.ok(!leaks(c.summary), `${c.id}: ${c.summary}`);
      for (const x of (c.coverage?.notCovered ?? []).map((n) => n.reason)) assert.ok(!leaks(x), `${c.id}: ${x}`);
    }
    for (const x of r.notCovered) assert.ok(!leaks(x), x);
    assert.ok(!leaks(JSON.stringify(r.checks)), "nothing in any check carries the real sandbox directory");
    assert.ok(!JSON.stringify(r.checks).includes(parent));
  });
});
