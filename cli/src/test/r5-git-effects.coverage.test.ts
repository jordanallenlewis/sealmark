import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { gitAvailable } from "../packs/git.js";
import type { RunResult } from "../types.js";
import { gitConfig, runPacks } from "./packctx.js";

// Round 5, git-8 (and git-9 wording): git coverage counts a control only when it answered and a probe only when its tool was controlled and the reply was
// not a validation error. The test asserts counts, not the call shape, so it holds before and after Tally.note takes an outcome.

const skip = gitAvailable() ? false : "git is not on PATH";
let dir: string;
let parent: string;
let bare: RunResult;
let good: RunResult;

describe("git pack (round 5): coverage counts only calls that exercised a controlled tool", { skip, timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-r5-cov-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const where = { dir, parent };
    const cfg = (mode: string, extra: string[]) => {
      const c = gitConfig(mode);
      c.server.args!.push(...extra);
      return c;
    };
    [bare, good] = await Promise.all([runPacks(cfg("good", ["--with-branch-type", "bare"]), ["git"], where), runPacks(gitConfig("good"), ["git"], where)]);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a read tool whose control failed is not in probed, is in notCovered, and none of its calls count", () => {
    const c = bare.checks.find((x) => x.id === "git-repo-scope")!;
    assert.deepEqual(c.coverage?.probed.sort(), ["git_diff", "git_status"], JSON.stringify(c.coverage));
    assert.ok(c.coverage?.notCovered.some((n) => n.tool === "git_branch" && /control call on \{sandbox\}\/repo did not answer/.test(n.reason)));
    // Two controls plus nine targets (five absolute, four relative) for each of the two controlled tools; git_branch's failed control counts for nothing.
    assert.equal(c.coverage?.validCalls, 2 + 2 * 9, JSON.stringify(c.coverage));
  });

  it("git-arg-injection: the failed control of the same tool is a not-covered line, and its probes do not count", () => {
    const c = bare.checks.find((x) => x.id === "git-arg-injection")!;
    assert.ok(!c.coverage?.probed.includes("git_branch"), JSON.stringify(c.coverage));
    assert.ok(c.coverage?.notCovered.some((n) => n.tool === "git_branch" && /control call on \{sandbox\}\/repo failed/.test(n.reason)), JSON.stringify(c.coverage?.notCovered));
  });

  it("a server whose every tool is controlled counts the controls and every probe", () => {
    const c = good.checks.find((x) => x.id === "git-repo-scope")!;
    assert.deepEqual(c.coverage?.probed.sort(), ["git_diff", "git_status"]);
    assert.equal(c.coverage?.validCalls, 2 + 2 * 9);
    assert.equal(c.verdict, "pass");
  });
});
