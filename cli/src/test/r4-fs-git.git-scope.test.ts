import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { describe as describeGit, ensureGitFixture, gitAvailable, pack as gitPack } from "../packs/git.js";
import { createSandbox } from "../sandbox.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { gradeOf } from "./helpers.js";
import { directCtx, gitConfig, insideDir, readTrace, runPacks } from "./packctx.js";

// Round 4, C5-C7: the git fixture stages a change and plants a link to the canary repository; git-repo-scope judges every read tool;
// the git pack needs {sandbox} like the fs pack. Each false pass has a toy that now fails and a near miss that still passes.

const skip = gitAvailable() ? false : "git is not on PATH";
const WIN = process.platform === "win32";
const toyPath = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));

const cfg = (name: string, script: string, args: string[], repo = "{sandbox}/repo"): SealmarkConfig => ({
  name: `toy-${name}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [toyPath(script), ...args, "--repo", repo], env: {} },
});

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};
const scope = (name: string) => results[name].checks.find((c) => c.id === "git-repo-scope")!;
const inject = (name: string) => results[name].checks.find((c) => c.id === "git-arg-injection")!;
const git = (cwd: string, env: NodeJS.ProcessEnv, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env, windowsHide: true });

describe("git pack: the staged change, the link out of the repository, and every read tool judged", { skip, timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-r4-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const runs: Record<string, [SealmarkConfig, string]> = {
      stagedexempt: [cfg("git-stagedexempt", "git-stagedexempt", []), "git-stagedexempt"],
      nosymlink: [cfg("git-nosymlink", "git-nosymlink", []), "git-nosymlink"],
      strict: [cfg("git-scope-strict", "git-scope", ["--mode", "strict"]), "git-scope"],
      writeonly: [cfg("git-scope-write", "git-scope", ["--mode", "strict", "--tools", "write"]), "git-scope"],
      bare: [cfg("git-bare", "git", ["--mode", "good", "--with-branch-type", "bare"]), "git"],
    };
    await Promise.all(
      Object.entries(runs).map(async ([name, [config]]) => {
        traces[name] = join(dir, `trace-${name}.jsonl`);
        config.server.args!.push("--trace", traces[name]);
        results[name] = await runPacks(config, ["git"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a server that exempts the staged-diff tool from the scope check fails on git_diff_staged (the staged change makes its control answer)", () => {
    const c = scope("stagedexempt");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => e.outcome)]));
    assert.match(c.summary, /git_diff_staged on canary-repo/);
    assert.doesNotMatch(c.summary, /git_status|git_diff on /, "the tools that do check are not blamed");
    assert.ok(c.evidence.some((e) => e.tool === "git_diff_staged" && e.code === "git.control"), "the staged tool's control call answered for the harness repository");
    const hit = c.evidence.find((e) => e.code === "git.repo-escape" && e.tool === "git_diff_staged");
    assert.ok(hit);
    assert.match(hit.excerpt ?? "", /sm-canary-[0-9a-f]+ staged/);
  });

  it("a server that normalises .. but never resolves links fails on the symlink probe alone", () => {
    const c = scope("nosymlink");
    assert.equal(c.verdict, "fail", JSON.stringify([c.summary, c.evidence.map((e) => e.outcome)]));
    assert.match(c.summary, /git_status on symlink/);
    assert.match(c.summary, /git_diff_staged on symlink/);
    assert.doesNotMatch(c.summary, /canary-repo|dotdot|evil-repo|prefix-repo/, "the lexical checks it does perform still refuse the other probes");
    const hit = c.evidence.find((e) => e.code === "git.repo-escape" && /linkout/.test(e.probe));
    assert.ok(hit);
    assert.match(JSON.stringify(hit.args), /\{sandbox\}\/repo\/linkout/);
  });

  it("near miss: the realpath-based scope check passes, and every read tool and the write tool are judged (round 5: the write tool is observed, no longer skipped)", () => {
    const c = scope("strict");
    assert.equal(c.verdict, "pass", JSON.stringify([c.summary, c.evidence.map((e) => e.outcome)]));
    assert.match(c.summary, /git_status, git_diff, git_diff_staged, git_add refused the repositories outside \{sandbox\}\/repo/);
    assert.doesNotMatch(c.summary, /not probed|not judged/);
    assert.ok(c.evidence.some((e) => e.code === "git.write-control" && e.tool === "git_add"));
    assert.ok(c.evidence.some((e) => e.code === "git.control" && e.tool === "git_diff_staged"));
    const blocked = c.evidence.filter((e) => e.code === "git.repo-blocked").map((e) => e.outcome).join("\n");
    assert.match(blocked, /symlink/);
    assert.equal(inject("strict").verdict, "pass");
    assert.equal(gradeOf(results.strict, "git")?.letter, "A");
  });

  it("the symlink is aimed at inside the sandbox: every path a probe sent is inside it, the link is in the configured repository", () => {
    const sandboxDir = results.strict.sandbox!.dir!;
    const sent = readTrace(traces.strict).map((t) => String(t.args.repo_path));
    assert.ok(sent.some((p) => /[\\/]repo[\\/]linkout$/.test(p)), JSON.stringify(sent));
    for (const p of sent) assert.ok(insideDir(sandboxDir, p), p);
  });

  it("git-arg-injection lists one line per probed parameter, with the server's own words (C7)", () => {
    const c = inject("strict");
    const lines = c.evidence.filter((e) => e.code === "git.arg-refused");
    assert.ok(lines.length >= 2, JSON.stringify(c.evidence.map((e) => e.code)));
    const diff = lines.find((e) => e.tool === "git_diff");
    assert.ok(diff);
    assert.match(diff.outcome, /^git_diff\.target: --output=… treated as data \(reply: .*Invalid revision/);
    assert.ok(lines.some((e) => /^git_add\.files: --output=…/.test(e.outcome)), "the write-capable tool's parameter is listed too");
    assert.ok(diff.outcome.length < 200);
  });

  it("a server with only write-capable tools: repository scope is judged by observation (round 5), and the injection check says no control could exist (C6)", () => {
    const s = scope("writeonly");
    assert.equal(s.verdict, "pass", JSON.stringify([s.summary, s.evidence.map((e) => [e.code, e.outcome])]));
    assert.match(s.summary, /^git_add refused the repositories outside/);
    const c = inject("writeonly");
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /no read-only git tool exists to make a control call/);
    assert.match(c.summary, /write-capable tools can fail this check but cannot pass it/);
    assert.doesNotMatch(c.summary, /did not answer|answered a benign control call/);
    assert.ok(readTrace(traces.writeonly).length > 0, "the probes were sent, so the check is not n/a");
  });

  it("a read tool whose control call failed makes the scope check a part and is named; nothing leaked, so it is not a fail", () => {
    const c = scope("bare");
    assert.equal(c.verdict, "part", JSON.stringify([c.summary, c.evidence.map((e) => e.outcome)]));
    assert.match(c.summary, /git_branch not judged: its control call failed/);
    assert.match(c.summary, /git_status, git_diff refused the repositories outside \{sandbox\}\/repo/);
    assert.ok(c.evidence.some((e) => e.code === "git.control-failed" && e.tool === "git_branch"));
    const g = gradeOf(results.bare, "git");
    assert.ok(g);
    assert.notEqual(g.letter, "A", "a pack with a critical part is not an A");
  });
});

describe("git pack: the fixture", { skip, timeout: 120_000 }, () => {
  it("every repository has a staged staged.txt carrying its token and a link to the canary repository sits in the root repository", async () => {
    const own = mkdtempSync(join(tmpdir(), "sealmark-git-r4-fixture-"));
    const sb = await createSandbox({ dir: own });
    try {
      const fx = await ensureGitFixture(sb);
      const env = sb.env();
      for (const [repo, token] of [[fx.rootRepo, fx.tokens.root], [fx.canaryRepo, fx.tokens.canary], [fx.evilRepo, fx.tokens.evil], [fx.prefixRepo, fx.tokens.prefix]] as const) {
        assert.equal(git(repo, env, "diff", "--staged", "--name-only").trim(), "staged.txt", repo);
        assert.match(git(repo, env, "diff", "--staged"), new RegExp(`\\+${token} staged`), "git diff --staged prints the token");
        assert.match(git(repo, env, "diff", "HEAD"), new RegExp(`${token} staged`), "git diff HEAD prints it too");
        assert.match(git(repo, env, "status", "--short"), /^A  staged\.txt$/m);
        assert.equal(readFileSync(join(repo, "staged.txt"), "utf8"), `${token} staged\n`);
      }
      assert.equal(fx.linkout.path, join(fx.rootRepo, "linkout"));
      assert.equal(fx.linkout.ok, true, fx.linkout.reason ?? "");
      assert.ok(lstatSync(fx.linkout.path).isSymbolicLink() || WIN);
      if (!WIN) assert.equal(readlinkSync(fx.linkout.path), fx.canaryRepo);
      assert.match(git(fx.rootRepo, env, "status", "--short"), /^\?\? linkout$/m, "the link is untracked");
      // The link does lead to the canary repository: that is what a server which never resolves links would read.
      assert.match(git(fx.linkout.path, env, "log", "--format=%s"), new RegExp(fx.tokens.canary));
    } finally {
      await sb.destroy();
      rmSync(own, { recursive: true, force: true });
    }
  });

  it("commit dates are fixed, so the clock never makes two fixtures differ", async () => {
    const dates: string[] = [];
    for (const n of ["a", "b"]) {
      const own = mkdtempSync(join(tmpdir(), `sealmark-git-r4-date-${n}-`));
      const sb = await createSandbox({ dir: own });
      try {
        const fx = await ensureGitFixture(sb);
        dates.push(git(fx.rootRepo, sb.env(), "log", "--format=%aI %cI").trim());
      } finally {
        await sb.destroy();
        rmSync(own, { recursive: true, force: true });
      }
      await new Promise((r) => setTimeout(r, 1100));
    }
    assert.equal(dates[0], dates[1]);
    assert.match(dates[0], /^2000-01-01T00:00:00(Z|[+-]00:00) 2000-01-01T00:00:00(Z|[+-]00:00)$/);
  });
});

describe("git pack: applicability and wording", { skip, timeout: 120_000 }, () => {
  it("without {sandbox} the pack is not applicable, with the reason doctor prints, and no grade or badge rests on the argument check alone", async () => {
    const d =mkdtempSync(join(tmpdir(), "sealmark-git-r4-nosb-"));
    const p = join(d, "sandboxes");
    mkdirSync(p);
    try {
      const config = cfg("git-scope-strict", "git-scope", ["--mode", "strict"], join(d, "elsewhere"));
      const r = await runPacks(config, ["git"], { dir: d, parent: p });
      assert.equal(r.packs.git?.status, "na");
      assert.match(r.packs.git?.reason ?? "", /the server config has no \{sandbox\} placeholder, so the repository scope cannot be configured/);
      assert.match(r.packs.git?.reason ?? "", /a server given a real repository would reach every other repository legitimately/);
      assert.equal(gradeOf(r, "git"), undefined);
      assert.equal(r.badge?.eligible, false);
      // The pack's own applies() says the same thing to doctor.
      const direct = await directCtx(cfg("git-scope-strict", "git-scope", ["--mode", "strict"], join(d, "elsewhere")), "git", { dir: d, parent: p });
      try {
        const a = gitPack.applies(direct.ctx);
        assert.equal(a.ok, false);
        assert.match((a as { reason: string }).reason, /pass \{sandbox\}\/repo as its repository argument/);
      } finally {
        await direct.close();
      }
      // {dir} is an alias for {sandbox}: the pack applies.
      const alias = await directCtx(gitConfig("good", { repo: "{dir}/repo" }), "git", { dir: d, parent: p });
      try {
        assert.deepEqual(gitPack.applies(alias.ctx), { ok: true });
      } finally {
        await alias.close();
      }
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("describe() documents the symlink probe, the part rule and the {sandbox} requirement", () => {
    const doc = describeGit().find((x) => x.id === "git-repo-scope")!;
    const link = doc.probes.find((p) => p.id === "symlink");
    assert.ok(link);
    assert.match(link.text, /\{sandbox\}\/repo\/linkout/);
    assert.match(link.text, /points at \{canary\}\/repo/);
    assert.match(doc.falseNegative, /a part, never a pass/);
    assert.match(doc.falsePositive, /whole pack is not applicable/);
  });
});
