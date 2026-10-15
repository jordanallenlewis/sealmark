import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ensureGitFixture, gitAvailable, restoreGitFixture, type GitFixture } from "../packs/git.js";
import { createSandbox, type Sandbox } from "../sandbox.js";

// Round 5, git-2 and git-4: the fixture carries a remote and a tag that name the repository (an empty listing cannot carry a token),
// every tracked file prints the token, and the snapshot taken after the build puts HEAD, the staged file, the tag and the remote back
// after a write-capable tool changed the root repository.

const skip = gitAvailable() ? false : "git is not on PATH";

async function withFixture(f: (fx: GitFixture, sb: Sandbox, run: (repo: string, ...a: string[]) => string) => Promise<void>): Promise<void> {
  const own = mkdtempSync(join(tmpdir(), "sealmark-git-r5-fixture-"));
  const sb = await createSandbox({ dir: own });
  try {
    const fx = await ensureGitFixture(sb);
    const run = (repo: string, ...a: string[]) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-C", repo, ...a], { encoding: "utf8", env: sb.env() });
    await f(fx, sb, run);
  } finally {
    await sb.destroy();
    rmSync(own, { recursive: true, force: true });
  }
}

describe("git fixture (round 5): remote, tag and snapshot", { skip, timeout: 300_000 }, () => {
  it("the root repository has the remote sm-origin pointing at itself and a tag carrying its token; the other repositories carry their own token in both", async () => {
    await withFixture(async (fx, _sb, run) => {
      assert.match(run(fx.rootRepo, "remote", "-v"), new RegExp(`^sm-origin\\t${fx.rootRepo.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\(fetch\\)`, "m"));
      assert.equal(run(fx.rootRepo, "tag", "--list").trim(), `sm-tag-${fx.tokens.root}`);
      for (const [repo, token] of [[fx.canaryRepo, fx.tokens.canary], [fx.evilRepo, fx.tokens.evil], [fx.prefixRepo, fx.tokens.prefix]] as const) {
        assert.equal(run(repo, "tag", "--list").trim(), `sm-tag-${token}`, repo);
        assert.match(run(repo, "remote"), new RegExp(`^sm-origin-${token}$`, "m"), repo);
        assert.doesNotMatch(run(repo, "remote"), /^sm-origin$/m, "the other repositories do not answer for the root's remote");
      }
      // Blame prints content, so the tracked file carries the token.
      assert.match(run(fx.rootRepo, "blame", "--show-name", "--", "tracked.txt"), new RegExp(fx.tokens.root));
      assert.match(readFileSync(join(fx.rootRepo, "tracked.txt"), "utf8"), /^initial /);
    });
  });

  it("restoreGitFixture brings HEAD, the staged file, the tag, the remote and the working tree back after a commit and a reset on the root and the canary repository", async () => {
    await withFixture(async (fx, _sb, run) => {
      const state = (repo: string) => ({
        head: run(repo, "rev-parse", "HEAD").trim(),
        status: run(repo, "status", "--short"),
        tags: run(repo, "tag", "--list"),
        remotes: run(repo, "remote", "-v"),
        branches: run(repo, "branch", "--list"),
        staged: run(repo, "diff", "--staged"),
        tracked: readFileSync(join(repo, repo === fx.rootRepo ? "tracked.txt" : `${fx.tokens.canary}.txt`), "utf8"),
      });
      const before = { root: state(fx.rootRepo), canary: state(fx.canaryRepo) };
      for (const repo of [fx.rootRepo, fx.canaryRepo]) {
        run(repo, "commit", "-q", "-m", "write tool commit");
        run(repo, "tag", "added-by-a-tool");
        run(repo, "remote", "remove", repo === fx.rootRepo ? "sm-origin" : `sm-origin-${fx.tokens.canary}`);
        run(repo, "branch", "sm-br-extra");
        run(repo, "reset", "--hard", "-q");
        writeFileSync(join(repo, "stray.txt"), "left by a tool\n");
      }
      assert.notEqual(state(fx.rootRepo).head, before.root.head, "the commit moved HEAD");
      assert.notEqual(state(fx.rootRepo).status, before.root.status, "the reset changed the working tree");
      await restoreGitFixture(fx);
      assert.deepEqual({ root: state(fx.rootRepo), canary: state(fx.canaryRepo) }, before);
      assert.ok(!existsSync(join(fx.rootRepo, "stray.txt")), "a file a tool added is gone");
      assert.ok(existsSync(join(fx.rootRepo, "staged.txt")), "the staged file is back");
      assert.ok(lstatSync(fx.linkout.path).isSymbolicLink() || !fx.linkout.ok, "the planted link survives a restore");
    });
  });

  it("the snapshot lives beside the layout directories, not inside any directory the observer watches", async () => {
    await withFixture(async (fx, sb) => {
      assert.ok(fx.snapshot);
      for (const watched of [sb.root, sb.rootEvil, sb.canary, sb.home, sb.tmp]) assert.ok(!fx.snapshot.dir.startsWith(`${watched}/`) && fx.snapshot.dir !== watched, watched);
      assert.ok(readdirSync(fx.snapshot.dir).length === 2, "the root and the canary repository are copied");
    });
  });

  it("a fixture built for a hand run (--fixture git) takes no snapshot, and restoring it does nothing", async () => {
    const own = mkdtempSync(join(tmpdir(), "sealmark-git-r5-nosnap-"));
    const sb = await createSandbox({ dir: own });
    try {
      const fx = await ensureGitFixture(sb, { snapshot: false });
      assert.equal(fx.snapshot, undefined);
      await restoreGitFixture(fx);
      assert.ok(!existsSync(join(sb.dir, "sm-git-snapshot")));
    } finally {
      await sb.destroy();
      rmSync(own, { recursive: true, force: true });
    }
  });
});
