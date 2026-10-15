import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { writeFixture } from "../fixtures.js";
import { ensureGitFixture, gitAvailable } from "../packs/git.js";
import { createSandbox } from "../sandbox.js";
import { cliKit } from "./helpers.js";

const skip = gitAvailable() ? false : "git is not on PATH";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-fixture-git-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark } = cliKit(() => dir);
const tokenOf = (doc: string, label: string): string => new RegExp(`${label}: (\\S+)`).exec(doc)?.[1] ?? "";
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", windowsHide: true });

describe("run --fixture git", { skip, timeout: 180_000 }, () => {
  it("writes the layout and four repositories whose tokens are in SEALMARK-FIXTURE.txt", () => {
    const into = join(dir, "fx");
    const r = sealmark(["run", "--fixture", "git", "--into", into]);
    assert.equal(r.code, 0, r.err);
    const doc = readFileSync(join(into, "SEALMARK-FIXTURE.txt"), "utf8");
    assert.ok(existsSync(join(into, "root", "ok.txt")), "the fs layout is there too");
    assert.match(git(join(into, "root", "repo"), "log", "--oneline"), new RegExp(tokenOf(doc, "git root token")));
    assert.match(git(join(into, "canary", "repo"), "log", "--oneline"), new RegExp(tokenOf(doc, "git canary token")));
    assert.match(git(join(into, "root-evil"), "log", "--oneline"), new RegExp(tokenOf(doc, "git evil token")));
    assert.match(git(join(into, "root", "repo-evil"), "log", "--oneline"), /sm-prefix-\w+ initial commit/, "the sibling of the configured repository is built too");
    assert.ok(doc.includes(join(into, "root", "repo")), "the repository paths are listed");
    // The fourth repository, the prefix sibling the git pack probes, is listed with its token.
    assert.ok(doc.includes(`repository root/repo-evil: ${join(into, "root", "repo-evil")}`), doc);
    const prefix = tokenOf(doc, "git prefix token");
    assert.match(prefix, /^sm-prefix-/);
    assert.match(git(join(into, "root", "repo-evil"), "log", "--oneline"), new RegExp(prefix));
    assert.match(r.err, /This is what the sandbox builds for \{sandbox\}/);
  });

  it("builds in process: writeFixture returns a promise and awaits the repositories itself", async () => {
    const into = join(dir, "in-process");
    const logged: string[] = [];
    const pending = writeFixture("git", into, (s) => logged.push(s));
    assert.ok(pending instanceof Promise);
    assert.deepEqual(await pending, { code: 0 });
    assert.ok(logged.some((l) => l.startsWith("wrote the git repositories:") && l.includes(join(into, "root", "repo-evil"))), logged.join("\n"));
    assert.match(git(join(into, "root", "repo-evil"), "log", "--oneline"), /sm-prefix-\w+ initial commit/);
    assert.throws(() => writeFixture("nope", into, () => {}), /--fixture must be fs, git, sqlite or duckdb/);
  });

  it("builds the same structure as a real sandbox: branch named after the token, one commit, a dirty tracked file", async () => {
    const into = join(dir, "same");
    assert.equal(sealmark(["run", "--fixture", "git", "--into", into]).code, 0);
    const sb = await createSandbox({ dir: join(dir, "real-parent") });
    try {
      const fx = await ensureGitFixture(sb);
      const shape = (repo: string, file: string) => ({
        branches: git(repo, "branch", "--list").split("\n").map((l) => l.replace(/^[* ]+/, "").replace(/-[0-9a-f]+$/, "")).filter(Boolean).sort(),
        commits: git(repo, "rev-list", "--count", "HEAD").trim(),
        dirty: git(repo, "status", "--short").includes(file),
      });
      const mine = { root: shape(join(into, "root", "repo"), "tracked.txt"), canary: shape(join(into, "canary", "repo"), ".txt"), evil: shape(join(into, "root-evil"), ".txt"), prefix: shape(join(into, "root", "repo-evil"), ".txt") };
      const real = { root: shape(fx.rootRepo, "tracked.txt"), canary: shape(fx.canaryRepo, ".txt"), evil: shape(fx.evilRepo, ".txt"), prefix: shape(fx.prefixRepo, ".txt") };
      assert.deepEqual(mine, real);
      assert.match(fx.tokens.root, /^sm-root-/);
      assert.ok(mine.root.dirty && mine.root.commits === "1");
    } finally {
      await sb.destroy();
    }
  });

  it("the owner's global git configuration is not consulted", () => {
    // core.hooksPath is overridden by the fixture's own -c, so the discriminating setting is excludesFile: with it, `git add` would refuse every file.
    const excludes = join(dir, "excludes");
    writeFileSync(excludes, "*\n");
    const global = join(dir, "gitconfig");
    writeFileSync(global, `[core]\n\thooksPath = ${join(dir, "no-such-hooks").replace(/\\/g, "/")}\n\texcludesFile = ${excludes.replace(/\\/g, "/")}\n`);
    const into = join(dir, "scrubbed");
    const r = sealmark(["run", "--fixture", "git", "--into", into], dir, { GIT_CONFIG_GLOBAL: global });
    assert.equal(r.code, 0, r.err);
    assert.match(git(join(into, "root", "repo"), "log", "--oneline"), /initial commit/);
  });

  it("a second run into the same directory exits 2 before touching the repositories", () => {
    const into = join(dir, "same-dir");
    assert.equal(sealmark(["run", "--fixture", "git", "--into", into]).code, 0);
    const r = sealmark(["run", "--fixture", "git", "--into", into]);
    assert.equal(r.code, 2);
    assert.match(r.err, /already exists/);
  });

  it("without git on PATH it exits 2 and leaves the target empty", () => {
    const into = join(dir, "no-git");
    const r = sealmark(["run", "--fixture", "git", "--into", into], dir, { PATH: join(dir, "empty-path"), Path: join(dir, "empty-path") });
    assert.equal(r.code, 2);
    assert.match(r.err, /--fixture git needs git on PATH/);
    assert.equal(existsSync(join(into, "root")), false);
  });
});
