import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { gitAvailable } from "../packs/git.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { gradeOf } from "./helpers.js";
import { insideDir, readTrace, runPacks } from "./packctx.js";

// Round 5, git-1..git-4 and git-8: the controls the fixture can answer (an object, a file, a remote, a tag), relative targets, write-capable tools judged
// by observation of harness-owned repositories, and coverage that counts only calls that exercised a controlled tool. Each false pass has a toy that now
// fails and a near miss (strict) that still passes with every read and write tool judged.

const skip = gitAvailable() ? false : "git is not on PATH";
const toyPath = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));

const cfg = (name: string, script: string, args: string[]): SealmarkConfig => ({
  name: `toy-${name}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [toyPath(script), ...args, "--repo", "{sandbox}/repo"], env: {} },
});

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};
const scope = (name: string) => results[name].checks.find((c) => c.id === "git-repo-scope")!;
const inject = (name: string) => results[name].checks.find((c) => c.id === "git-arg-injection")!;
const READS = ["git_status", "git_diff_staged", "git_show", "git_blame", "git_remote", "git_tag"];
const WRITES = ["git_add", "git_commit", "git_worktree_add", "git_clone"];

describe("git pack (round 5): controls the fixture can answer, relative targets and write tools", { skip, timeout: 600_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-r5-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const modes = ["strict", "show-leaks", "relative-skip", "worktree-escape", "clone-canary", "empty-lists"];
    await Promise.all(
      modes.map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(cfg(`git-r5-${m}`, "git-r5", ["--mode", m, "--trace", traces[m]]), ["git"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("near miss: the strict server passes with every read and write tool judged, and keeps grade A", () => {
    const c = scope("strict");
    assert.equal(c.verdict, "pass", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code, e.outcome])]));
    for (const n of [...READS, ...WRITES]) assert.match(c.summary, new RegExp(`\\b${n}\\b`), `${n} is among the tools that refused`);
    assert.doesNotMatch(c.summary, /not judged/);
    for (const n of READS) assert.ok(c.evidence.some((e) => e.code === "git.control" && e.tool === n), `${n}: control answered`);
    for (const n of WRITES) assert.ok(c.evidence.some((e) => e.code === "git.write-control" && e.tool === n), `${n}: the write control changed the harness repository`);
    assert.equal(inject("strict").verdict, "pass", inject("strict").summary);
    assert.equal(gradeOf(results.strict, "git")?.letter, "A");
  });

  it("controls first: a show tool with an object parameter and a blame tool with a file parameter are judged because the fixture answers HEAD and tracked.txt", () => {
    const c = scope("strict");
    const show = c.evidence.find((e) => e.code === "git.control" && e.tool === "git_show");
    assert.ok(show);
    assert.equal((show.args as Record<string, unknown>).object, "HEAD");
    const blame = c.evidence.find((e) => e.code === "git.control" && e.tool === "git_blame");
    assert.ok(blame);
    assert.equal((blame.args as Record<string, unknown>).file_path, "tracked.txt");
    // The remote and tag listings answer because the fixture has a remote and a tag.
    assert.ok(c.evidence.some((e) => e.code === "git.control" && e.tool === "git_remote"));
    assert.ok(c.evidence.some((e) => e.code === "git.control" && e.tool === "git_tag"));
    assert.equal(c.evidence.filter((e) => e.code === "git.control-failed").length, 0);
  });

  it("show-leaks: a show tool with an object parameter that follows the planted link fails, over the absolute and the relative link", () => {
    const c = scope("show-leaks");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code])]));
    assert.match(c.summary, /git_show on symlink/);
    assert.match(c.summary, /git_show on rel-link/);
    assert.doesNotMatch(c.summary, /git_status|git_blame|git_remote|git_tag|git_add/, "the tools that resolve links are not blamed");
    assert.doesNotMatch(c.summary, /canary-repo|evil-repo|prefix-repo/, "its lexical check still refuses the other repositories");
  });

  it("relative-skip: a server that validates only absolute repository paths fails on the relative targets", () => {
    const c = scope("relative-skip");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code])]));
    assert.match(c.summary, /git_status on rel-canary/);
    assert.match(c.summary, /rel-evil/);
    assert.match(c.summary, /rel-prefix/);
    assert.match(c.summary, /rel-link/);
    assert.doesNotMatch(c.summary, /canary-repo|dotdot|evil-repo on|prefix-repo|symlink/, "its absolute-path check still refuses the absolute targets");
    const hit = c.evidence.find((e) => e.code === "git.repo-escape" && /rel-canary|\.\.\/canary\/repo/.test(e.probe));
    assert.ok(hit);
    assert.equal((hit.args as Record<string, unknown>).repo_path, "../canary/repo");
  });

  it("worktree-escape: a worktree tool that creates its destination anywhere fails, seen as a directory that appeared outside the root", () => {
    const c = scope("worktree-escape");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code])]));
    assert.match(c.summary, /git_worktree_add on dest-canary/);
    assert.match(c.summary, /git_worktree_add on dest-evil/);
    assert.doesNotMatch(c.summary, /git_add|git_commit|git_clone|git_status/);
    const hit = c.evidence.find((e) => e.code === "git.write-escape" && /dest-canary|\{canary\}\/wt-/.test(e.probe));
    assert.ok(hit);
    assert.equal(hit.verifiedBy, "fs-observer");
    assert.match(hit.outcome, /canary\/wt-/);
  });

  it("clone-canary: a clone tool that accepts a source outside the configured repository fails, seen as the canary repository's token appearing in the root", () => {
    const c = scope("clone-canary");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code])]));
    assert.match(c.summary, /git_clone on repo-canary/);
    assert.match(c.summary, /git_clone on clone-file-url/);
    assert.doesNotMatch(c.summary, /git_worktree_add|git_add on|git_commit/);
    const hit = c.evidence.find((e) => e.code === "git.write-escape" && /file:\/\//.test(e.probe));
    assert.ok(hit);
    assert.match(hit.outcome, /sm-canary-/);
  });

  it("empty-lists: a remote and a tag listing that answer with an empty list are 'answered but showed no repository content', not 'did not answer'; the check is a part and names them", () => {
    const c = scope("empty-lists");
    assert.equal(c.verdict, "part", JSON.stringify([c.summary, c.evidence.map((e) => [e.tool, e.code])]));
    assert.match(c.summary, /git_remote not judged: its control call answered but showed no repository content/);
    assert.match(c.summary, /git_tag not judged: its control call answered but showed no repository content/);
    assert.doesNotMatch(c.summary, /control call failed/);
    assert.match(c.summary, /git_status, git_diff_staged, git_show, git_blame, git_add, git_commit, git_worktree_add, git_clone refused the repositories outside/, "the tools that answered are judged");
    const e = c.evidence.find((x) => x.code === "git.control-failed" && x.tool === "git_remote");
    assert.ok(e);
    assert.match(e.outcome, /answered but showed nothing of the repository/);
    assert.ok(c.coverage?.notCovered.some((n) => n.tool === "git_remote" && /answered but showed no repository content, so not judged/.test(n.reason)));
    assert.ok(!c.coverage?.probed.includes("git_remote"), "a tool whose control was not judged is not counted as probed");
    assert.notEqual(gradeOf(results["empty-lists"], "git")?.letter, "A");
  });

  it("every path a probe sent is inside the sandbox directory, relative paths included (acceptance 9)", () => {
    for (const m of ["strict", "relative-skip"]) {
      const sandboxDir = results[m].sandbox!.dir!;
      const sent = readTrace(traces[m]).flatMap((t) => [t.args.repo_path, t.args.destination]).filter((p): p is string => typeof p === "string");
      assert.ok(sent.some((p) => p === "../canary/repo"), `${m}: the relative canary target was sent: ${JSON.stringify(sent.slice(0, 40))}`);
      assert.ok(sent.some((p) => p === "repo/linkout"), `${m}: the relative link target was sent`);
      for (const p of sent) assert.ok(insideDir(sandboxDir, p), `${m}: ${p}`);
    }
  });

  it("the scope check calls every read tool before the first write tool (the write controls change HEAD, the index and the tag the read controls rely on)", () => {
    const calls = readTrace(traces.strict).map((t) => t.tool);
    const firstWrite = calls.findIndex((n) => WRITES.includes(n));
    assert.ok(firstWrite > 0);
    assert.ok(calls.slice(0, firstWrite).every((n) => READS.includes(n)), "nothing but read tools before the first write tool");
    // The write half is one run of write tools (four controls and the probes), not interleaved with read calls.
    assert.ok(calls.slice(firstWrite, firstWrite + 12).every((n) => WRITES.includes(n)), JSON.stringify(calls.slice(firstWrite, firstWrite + 12)));
  });
});
