import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { describe as describeGit, ensureGitFixture, gitAvailable } from "../packs/git.js";
import { createSandbox } from "../sandbox.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { verdicts } from "./helpers.js";
import { insideDir, readTrace, runPacks } from "./packctx.js";

const skip = gitAvailable() ? false : "git is not on PATH";
const SCOPE_TOY = fileURLToPath(new URL("../toy/git-scope.js", import.meta.url));

const scopeConfig = (mode: string, trace: string): SealmarkConfig => ({
  name: `toy-git-scope-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [SCOPE_TOY, "--mode", mode, "--repo", "{sandbox}/repo", "--trace", trace], env: {} },
});

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

describe("git pack: a repository whose name has the configured repository as a prefix", { skip, timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-scope-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      ["startswith", "strict"].map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(scopeConfig(m, traces[m]), ["git"], { dir, parent });
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a startswith scope check leaks the sibling {sandbox}/repo-evil and fails git-repo-scope", () => {
    const r = results.startswith;
    const scope = r.checks.find((c) => c.id === "git-repo-scope")!;
    assert.equal(scope.verdict, "fail", JSON.stringify([scope.summary, scope.evidence.map((e) => e.outcome)]));
    assert.match(scope.summary, /prefix-repo/);
    // Only the prefix sibling gets through: the canary, the dot-dot path and the sandbox-root sibling are refused.
    assert.doesNotMatch(scope.summary, /canary-repo|dotdot|evil-repo/);
    const escape = scope.evidence.find((e) => e.code === "git.repo-escape");
    assert.ok(escape);
    assert.equal(escape.verifiedBy, "response");
    assert.match(JSON.stringify(escape.args), /\{sandbox\}\/repo-evil/);
    assert.match(escape.excerpt ?? "", /sm-prefix-/);
  });

  it("a check that compares whole path segments refuses the same sibling and passes", () => {
    const r = results.strict;
    const v = verdicts(r, "git");
    assert.equal(v["git-repo-scope"], "pass", JSON.stringify(r.checks.map((c) => [c.id, c.summary])));
    assert.equal(v["git-arg-injection"], "pass");
    const scope = r.checks.find((c) => c.id === "git-repo-scope")!;
    assert.ok(scope.evidence.some((e) => e.code === "git.repo-blocked" && /prefix-repo/.test(e.outcome)), "the sibling was probed and refused");
  });

  it("the staged-diff tool's control call answers (the fixture stages a change), so it is judged like the others", () => {
    for (const m of ["startswith", "strict"]) {
      const scope = results[m].checks.find((c) => c.id === "git-repo-scope")!;
      const control = scope.evidence.find((e) => e.tool === "git_diff_staged" && e.code === "git.control");
      assert.ok(control, `${m}: ${JSON.stringify(scope.evidence.map((e) => [e.tool, e.code]))}`);
    }
    // Through the prefix sibling the staged change of that repository is what a startswith check lets out.
    const leak = results.startswith.checks.find((c) => c.id === "git-repo-scope")!;
    assert.match(leak.summary, /git_diff_staged on prefix-repo/);
  });

  it("the sibling is aimed at inside the sandbox and is a sibling of the configured repository, not of the sandbox root", () => {
    for (const m of ["startswith", "strict"]) {
      const sandboxDir = results[m].sandbox!.dir!;
      const sent = readTrace(traces[m]).map((t) => String(t.args.repo_path));
      assert.ok(
        sent.some((p) => /[\\/]root[\\/]repo-evil$/.test(p)),
        `${m}: ${JSON.stringify(sent)}`,
      );
      for (const p of sent) assert.ok(insideDir(sandboxDir, p), `${m}: ${p}`);
    }
  });

  it("the check documents the prefix probe in terms of the configured repository", () => {
    const doc = describeGit().find((d) => d.id === "git-repo-scope")!;
    const probe = doc.probes.find((p) => p.id === "prefix-repo");
    assert.ok(probe);
    assert.match(probe.text, /\{sandbox\}\/repo-evil/);
    assert.match(probe.text, /configured repository's path as a prefix/);
    assert.equal(probe.kind, "prefix");
  });
});

describe("git pack: the prefix fixture", { skip, timeout: 120_000 }, () => {
  it("builds {sandbox}/repo-evil as a real repository with its own token", async () => {
    const own = mkdtempSync(join(tmpdir(), "sealmark-git-prefix-fixture-"));
    const sb = await createSandbox({ dir: own });
    try {
      const fx = await ensureGitFixture(sb);
      assert.equal(fx.prefixRepo, `${fx.rootRepo}-evil`);
      assert.ok(fx.prefixRepo.startsWith(fx.rootRepo), "a plain string prefix of the configured repository");
      assert.ok(existsSync(join(fx.prefixRepo, ".git")));
      assert.match(fx.tokens.prefix, /^sm-prefix-/);
      assert.notEqual(fx.tokens.prefix, fx.tokens.evil);
      const run = (...a: string[]) => execFileSync("git", ["-C", fx.prefixRepo, ...a], { encoding: "utf8", env: sb.env() });
      assert.match(run("log", "--format=%s"), new RegExp(fx.tokens.prefix));
      assert.match(run("status", "--short"), /^ M /m);
      assert.equal(readFileSync(join(fx.prefixRepo, `${fx.tokens.prefix}.txt`), "utf8").startsWith("prefix"), true);
      // The configured repository does not carry the token, so a leak of it is unambiguous.
      assert.doesNotMatch(run("-C", fx.rootRepo, "log", "--format=%s"), new RegExp(fx.tokens.prefix));
    } finally {
      await sb.destroy();
      rmSync(own, { recursive: true, force: true });
    }
  });
});
