import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { REGISTRY } from "../packs/index.js";
import { describe as describeGit, ensureGitFixture, gitAvailable, gitKind, pack as gitPack } from "../packs/git.js";
import { createSandbox } from "../sandbox.js";
import type { RunResult, ToolClassification, Verdict } from "../types.js";
import { gradeOf, verdicts } from "./helpers.js";
import { directCtx, gitConfig, insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

const HAS_GIT = gitAvailable();
const skip = HAS_GIT ? false : "git is not on PATH";

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

/** the design notes: toy/git.ts. */
const TABLE: Record<string, { scope: Verdict; inject: Verdict; letter: string; pct: number }> = {
  good: { scope: "pass", inject: "pass", letter: "A", pct: 100 },
  anyrepo: { scope: "fail", inject: "pass", letter: "D", pct: 50 },
  inject: { scope: "pass", inject: "fail", letter: "D", pct: 50 },
  both: { scope: "fail", inject: "fail", letter: "F", pct: 0 },
};

describe("git pack against the toy git server", { skip, timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      Object.keys(TABLE).map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(gitConfig(m, { trace: traces[m] }), ["git", "effects"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  for (const [mode, row] of Object.entries(TABLE)) {
    it(`${mode}: verdicts and grade match the design table`, () => {
      const r = results[mode];
      const v = verdicts(r, "git");
      assert.deepEqual([v["git-repo-scope"], v["git-arg-injection"]], [row.scope, row.inject], JSON.stringify(r.checks.filter((c) => c.pack === "git").map((c) => [c.id, c.verdict, c.summary])));
      const g = gradeOf(r, "git");
      assert.ok(g);
      assert.equal(g.letter, row.letter);
      assert.equal(g.pct, row.pct);
    });
  }

  it("a repository escape is shown by text only the other repository has; an injection by a file the harness saw appear", () => {
    const scope = results.anyrepo.checks.find((c) => c.id === "git-repo-scope")!;
    assert.ok(scope.evidence.some((e) => e.code === "git.repo-escape" && e.verifiedBy === "response"));
    assert.match(scope.summary, /canary-repo/);
    assert.match(scope.summary, /evil-repo/, "the sibling whose name has the root as a prefix is probed too");
    const inj = results.inject.checks.find((c) => c.id === "git-arg-injection")!;
    const hit = inj.evidence.find((e) => e.code === "git.arg-injection");
    assert.ok(hit);
    assert.equal(hit.verifiedBy, "fs-observer");
    assert.match(hit.outcome, /pwned-/);
  });

  it("a refusal only counts as a pass when a benign control call worked first", () => {
    for (const m of ["good", "anyrepo"]) {
      const inj = results[m].checks.find((c) => c.id === "git-arg-injection")!;
      assert.ok(inj.evidence.some((e) => e.code === "git.control"), m);
    }
    const scope = results.good.checks.find((c) => c.id === "git-repo-scope")!;
    assert.equal(scope.evidence.filter((e) => e.code === "git.control").length, 2);
  });

  it("every repository path the harness sent is inside the sandbox directory (acceptance 9)", () => {
    for (const m of Object.keys(TABLE)) {
      const sandboxDir = results[m].sandbox!.dir!;
      const calls = readTrace(traces[m]);
      assert.ok(calls.length >= 8, `${m}: probes were sent`);
      for (const t of calls) {
        const repo = String(t.args.repo_path);
        assert.ok(insideDir(sandboxDir, repo), `${m}: ${t.tool} was sent ${repo}`);
        const target = typeof t.args.target === "string" ? t.args.target : "";
        if (target.startsWith("--output=")) assert.ok(insideDir(sandboxDir, target.slice("--output=".length)), `${m}: output target ${target}`);
      }
    }
  });

  it("the harness aims arg-injection only at the harness repository and the option writes into it", () => {
    for (const m of ["inject", "both", "good"]) {
      const calls = readTrace(traces[m]).filter((t) => String(t.args.target ?? "").startsWith("--output="));
      assert.equal(calls.length, 1, m);
      assert.match(String(calls[0].args.repo_path), /root[\\/]repo$/);
    }
  });

  it("effects: git tools declared read-only are not blamed for refreshing the index", () => {
    const e = results.good.checks.filter((c) => c.pack === "effects");
    assert.equal(e.find((c) => c.id === "annotation-honesty")?.verdict, "pass");
    assert.equal(e.find((c) => c.id === "openworld-honesty")?.verdict, "pass");
    assert.equal(gradeOf(results.good, "effects")?.letter, "A");
  });

  it("scope and ids are documented; the registry holds the pack", () => {
    for (const c of results.good.checks.filter((x) => x.pack === "git")) assert.match(c.scope, /^server/);
    assert.deepEqual(describeGit().map((d) => d.id), ["git-repo-scope", "git-arg-injection"]);
    assert.ok(REGISTRY.some((p) => p === gitPack));
  });

  it("the sandboxes, repositories included, are gone afterwards", () => {
    assert.deepEqual(readdirSync(parent).filter((n) => n.startsWith("sealmark-")), []);
    for (const m of Object.keys(TABLE)) assert.equal(existsSync(results[m].sandbox!.dir!), false);
  });
});

describe("git pack: fixtures, scope and degraded environments", { skip, timeout: 300_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-test2-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("builds four repositories that name their own tokens and leaves the canary file alone", async () => {
    const sb = await createSandbox({ dir: parent });
    try {
      const fx = await ensureGitFixture(sb);
      assert.equal(await ensureGitFixture(sb), fx, "built once per sandbox");
      assert.equal(readFileSync(sb.files.evil, "utf8"), sb.tokens.evil, "committing root-evil must not rewrite secret.txt");
      assert.equal(readFileSync(sb.files.canary, "utf8"), sb.tokens.canary);
      for (const [repo, token] of [[fx.rootRepo, fx.tokens.root], [fx.canaryRepo, fx.tokens.canary], [fx.evilRepo, fx.tokens.evil], [fx.prefixRepo, fx.tokens.prefix]] as const) {
        assert.ok(existsSync(join(repo, ".git")), repo);
        const { execFileSync } = await import("node:child_process");
        const run = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { encoding: "utf8", env: sb.env() });
        assert.match(run("log", "--format=%s"), new RegExp(token));
        assert.match(run("branch"), new RegExp(token));
        assert.match(run("status", "--short"), /^ M /m, "the working tree is dirty so status names a file");
      }
      assert.match(readFileSync(join(fx.rootRepo, "tracked.txt"), "utf8"), /initial/);
    } finally {
      assert.equal((await sb.destroy()).cleanedUp, true, "read-only git objects can be deleted on this platform");
    }
  });

  it("the git pack is not applicable when the config has no {sandbox}: no grade is built on the argument check alone", async () => {
    const r = await runPacks(gitConfig("anyrepo", { repo: join(dir, "elsewhere") }), ["git"], where());
    assert.equal(r.packs.git?.status, "na");
    assert.match(r.packs.git?.reason ?? "", /no \{sandbox\} placeholder, so the repository scope cannot be configured/);
    assert.match(r.packs.git?.reason ?? "", /pass \{sandbox\}\/repo as its repository argument/);
    assert.equal(r.checks.filter((c) => c.pack === "git").length, 0, "neither check ran");
    assert.equal(gradeOf(r, "git"), undefined);
    assert.equal(r.badge?.eligible, false);
  });

  it("inconclusive when the server never answers for the harness repository", async () => {
    // The toy only accepts the configured repository; configure one the harness never builds a fixture for.
    const r = await runPacks(gitConfig("good", { repo: "{sandbox}/other" }), ["git"], where());
    const v = verdicts(r, "git");
    assert.equal(v["git-repo-scope"], "inconclusive");
    assert.equal(v["git-arg-injection"], "inconclusive");
    assert.equal(r.packs.git?.status, "inconclusive");
    assert.equal(gradeOf(r, "git"), undefined);
  });

  it("is not applicable without git on PATH, and under --no-sandbox", async () => {
    const d = await directCtx(gitConfig("good"), "git", where());
    try {
      assert.deepEqual(gitPack.applies(d.ctx), { ok: true });
      const saved = process.env.PATH;
      const key = Object.keys(process.env).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
      process.env[key] = dir; // a directory with no git in it
      try {
        const a = gitPack.applies(d.ctx);
        assert.equal(a.ok, false);
        assert.match(a.ok ? "" : a.reason, /git is not on PATH/);
      } finally {
        process.env[key] = saved;
      }
      assert.equal(gitPack.applies({ ...d.ctx, sandboxEnabled: false }).ok, false);
    } finally {
      await d.close();
    }
  });

  it("checks.<id>.enabled disables one check with a stated reason", async () => {
    const d = await directCtx(gitConfig("good"), "git", where(), { over: { checks: { "git-arg-injection": { enabled: false, severity: null } } } });
    try {
      const out = await gitPack.run(d.ctx);
      assert.equal(out.find((c) => c.id === "git-arg-injection")?.verdict, "na");
      assert.match(out.find((c) => c.id === "git-arg-injection")?.summary ?? "", /disabled by config/);
      assert.equal(out.find((c) => c.id === "git-repo-scope")?.verdict, "pass");
    } finally {
      await d.close();
    }
  });
});

describe("git pack: reading tool names", () => {
  const cls = (tool: string, ro?: boolean): ToolClassification => ({ tool, class: "git", confidence: "high", params: { repo: "repo_path" }, unfillable: [], reasons: [], ...(ro ? { annotations: { readOnlyHint: true } } : {}) });
  const kind = (name: string, description = "", ro?: boolean) => gitKind({ name, description, inputSchema: { type: "object" } }, cls(name, ro));

  it("the reference server's tools are sorted into readers and writers", () => {
    for (const n of ["git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_log", "git_show", "git_branch"]) assert.equal(kind(n), "read", n);
    for (const n of ["git_commit", "git_add", "git_reset", "git_checkout", "git_create_branch", "git_init"]) assert.equal(kind(n), "write", n);
    assert.equal(kind("git_frobnicate"), "other");
    assert.equal(kind("git_frobnicate", "Show the history of a file."), "read");
    assert.equal(kind("git_frobnicate", "", true), "read");
  });
});
