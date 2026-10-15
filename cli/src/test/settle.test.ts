import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { SETTLE_MS, mergeDiffs, settleMsFor, settledDiff, type FsSnapshot } from "../observers/fs.js";
import { gitAvailable } from "../packs/git.js";
import type { FsDiff, RunResult } from "../types.js";
import { verdicts } from "./helpers.js";
import { runHarness } from "../run.js";
import { effectiveFor, fsConfig, gitConfig, runPacks } from "./packctx.js";
import { quiet } from "./helpers.js";

const empty = (over: Partial<FsDiff> = {}): FsDiff => ({ added: [], removed: [], changed: [], touched: [], any: false, ...over });

describe("settling after a reply (pure)", () => {
  it("settleMsFor is 300 ms at small probe timeouts and grows with timeout_probe_sec up to 1.5 s", () => {
    assert.equal(SETTLE_MS, 300);
    assert.equal(settleMsFor(2), 300);
    assert.equal(settleMsFor(6), 300);
    assert.equal(settleMsFor(10), 500);
    assert.equal(settleMsFor(60), 1500);
    assert.equal(settleMsFor(1000), 1500);
    assert.equal(settleMsFor(undefined), 500);
    assert.equal(settleMsFor(0), 500);
  });

  it("mergeDiffs unions what either diff saw, sorted and without duplicates", () => {
    const m = mergeDiffs(empty({ added: ["root/b", "root/a"], any: true }), empty({ added: ["root/a"], removed: ["root/c"], changed: ["root/d"], touched: ["root/e"], any: true }));
    assert.deepEqual(m, { added: ["root/a", "root/b"], removed: ["root/c"], changed: ["root/d"], touched: ["root/e"], any: true });
    assert.equal(mergeDiffs(empty(), empty()).any, false);
  });

  it("settledDiff sees a change that lands after the first diff, and skips the wait when the first diff already has the answer", async () => {
    let calls = 0;
    const fs = {
      diffSince: async () => (++calls === 1 ? empty() : empty({ added: ["root/late.txt"], any: true })),
    } as never;
    const t0 = Date.now();
    const d = await settledDiff(fs, {} as FsSnapshot, ["root"], 120);
    assert.deepEqual(d.added, ["root/late.txt"]);
    assert.ok(Date.now() - t0 >= 100, "waited for the settle window");

    calls = 0;
    const fast = { diffSince: async () => (++calls, empty({ added: ["root/now.txt"], any: true })) } as never;
    const t1 = Date.now();
    const d2 = await settledDiff(fast, {} as FsSnapshot, undefined, 5000, (x) => x.added.length > 0);
    assert.deepEqual(d2.added, ["root/now.txt"]);
    assert.equal(calls, 1);
    assert.ok(Date.now() - t1 < 1000, "no wait when done() is satisfied");
  });
});

describe("packs see a server that writes after it has replied", { timeout: 240_000 }, () => {
  let dir: string;
  let parent: string;
  const where = () => ({ dir, parent });
  const r: Record<string, RunResult> = {};

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-settle-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const jobs: Promise<void>[] = [
      runPacks(fsConfig("latelog"), ["fs", "effects"], where()).then((x) => void (r.latelog = x)),
      runPacks(fsConfig("latetraverse"), ["fs", "effects"], where()).then((x) => void (r.latetraverse = x)),
      runPacks(fsConfig("logger"), ["fs", "effects"], where()).then((x) => void (r.logger = x)),
    ];
    if (gitAvailable()) jobs.push(// A longer probe timeout gives a longer settle window (settleMsFor), so a slow git start on a busy machine is still inside it.
      runHarness({ config: gitConfig("lateinject"), effective: effectiveFor(gitConfig("lateinject"), ["git"], where(), { timeoutProbeSec: 20 }), packs: ["git"], packsExplicit: true, timeoutProbeSec: 20, log: quiet }).then((x) => void (r.lateinject = x)));
    await Promise.all(jobs);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("latelog: a read-only tool that appends to a log after replying fails annotation-honesty, like the one that appends before", () => {
    assert.equal(verdicts(r.logger, "effects")["annotation-honesty"], "fail");
    const v = verdicts(r.latelog, "effects");
    assert.equal(v["annotation-honesty"], "fail", JSON.stringify(r.latelog.checks.filter((c) => c.pack === "effects").map((c) => [c.id, c.verdict, c.summary])));
    const ann = r.latelog.checks.find((c) => c.id === "annotation-honesty")!;
    assert.ok(ann.evidence.some((e) => e.code === "effects.readonly-write" && e.tool === "read_file" && /\.log/.test(e.outcome)));
  });

  it("latetraverse: a write that escapes the root 120 ms after the reply still fails fs-write-escape (the control write is seen too)", () => {
    const v = verdicts(r.latetraverse, "fs");
    assert.equal(v["fs-write-escape"], "fail", JSON.stringify(r.latetraverse.checks.filter((c) => c.pack === "fs").map((c) => [c.id, c.verdict, c.summary])));
  });

  it("lateinject: git writing the --output file after the reply still fails git-arg-injection", { skip: gitAvailable() ? false : "git is not on PATH" }, () => {
    const v = verdicts(r.lateinject, "git");
    assert.equal(v["git-arg-injection"], "fail", JSON.stringify(r.lateinject.checks.filter((c) => c.pack === "git").map((c) => [c.id, c.verdict, c.summary])));
  });
});
