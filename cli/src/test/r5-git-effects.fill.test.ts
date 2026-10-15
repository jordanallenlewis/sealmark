import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import type { ToolInfo } from "../mcp.js";
import { answersForRoot, controlValues, fillGit, gitTools, writeShape, type GitFixture, type GitTool } from "../packs/git.js";
import type { PackCtx } from "../types.js";

// Round 5, git-2: parameters the classifier has no git role for get values the fixture can answer (a tracked file, HEAD, the fixture's remote);
// a well-formed success with an empty list does not answer for the repository.

const fx = { rootRepo: "/sb/root/repo", canaryRepo: "/sb/canary/repo", evilRepo: "/sb/root-evil", prefixRepo: "/sb/root/repo-evil", tokens: { root: "sm-root-aaaa", canary: "sm-canary-bbbb", evil: "sm-evil-cccc", prefix: "sm-prefix-dddd" }, linkout: { path: "/sb/root/repo/linkout", ok: true } } as GitFixture;

const tool = (name: string, properties: Record<string, unknown>, required: string[], description = "A git tool."): ToolInfo => ({ name, description, inputSchema: { type: "object", properties, required } }) as ToolInfo;
const str = { type: "string" };
const gitToolOf = (t: ToolInfo): GitTool => {
  const classification = classifyTools({ tools: [t] }).classification;
  const ctx = { classification, tools: [t], active: false, sandboxEnabled: true } as unknown as PackCtx;
  const found = gitTools(ctx);
  assert.equal(found.length, 1, `${t.name} is a git tool: ${JSON.stringify(classification)}`);
  return found[0]!;
};

describe("git pack (round 5): control values the fixture can answer", () => {
  it("an object parameter (object, sha, hash, commit, rev) gets HEAD and a file parameter (file, filePath, file_path) gets tracked.txt", () => {
    for (const p of ["object", "sha", "hash", "commit_sha", "rev", "oid"]) {
      const t = gitToolOf(tool("git_show", { repo_path: str, [p]: str }, ["repo_path", p], "Show a commit of a git repository."));
      const args = fillGit(t, controlValues(fx), "sm-tok")!;
      assert.equal(args[p], "HEAD", p);
      assert.equal(args.repo_path, fx.rootRepo);
    }
    for (const p of ["file", "filePath", "file_path", "filename"]) {
      const t = gitToolOf(tool("git_blame", { repo_path: str, [p]: str }, ["repo_path", p], "Blame a file of a git repository."));
      assert.equal(fillGit(t, controlValues(fx), "sm-tok")![p], "tracked.txt", p);
    }
  });

  it("an array-valued file parameter gets [tracked.txt], and a probe aimed at another repository passes that repository's own file", () => {
    const t = gitToolOf(tool("git_log_files", { repo_path: str, filepaths: { type: "array", items: str } }, ["repo_path", "filepaths"], "Show the log of some files of a git repository."));
    assert.deepEqual(fillGit(t, controlValues(fx), "sm-tok")!.filepaths, ["tracked.txt"]);
    assert.deepEqual(fillGit(t, { ...controlValues(fx), repo: fx.canaryRepo, files: ["sm-canary-bbbb.txt"] }, "sm-tok")!.filepaths, ["sm-canary-bbbb.txt"]);
  });

  it("path is a file only when the repository is another parameter; when it is the repository it is left to the repository role", () => {
    const both = gitToolOf(tool("git_blame", { repo: str, path: str }, ["repo", "path"], "Blame a file of a git repository."));
    const args = fillGit(both, controlValues(fx), "sm-tok")!;
    assert.equal(args.repo, fx.rootRepo);
    assert.equal(args.path, "tracked.txt");
    const only = gitToolOf(tool("git_status", { path: str }, ["path"], "Show the status of a git repository."));
    const a2 = fillGit(only, controlValues(fx), "sm-tok")!;
    assert.equal(a2.path, fx.rootRepo, "the repository parameter is never overwritten with a file");
  });

  it("a required remote gets the fixture's remote, and a free-text parameter that names its choices still gets one of them", () => {
    const t = gitToolOf(tool("git_remote_show", { repo_path: str, remote: str }, ["repo_path", "remote"], "Show a remote of a git repository."));
    assert.equal(fillGit(t, controlValues(fx), "sm-tok")!.remote, "sm-origin");
    const named = gitToolOf(tool("git_branch", { repo_path: str, branch_type: { type: "string", description: "Which branches: 'local', 'remote', or 'all'" } }, ["repo_path", "branch_type"], "List the branches of a git repository."));
    assert.equal(fillGit(named, controlValues(fx), "sm-tok")!.branch_type, "local");
  });

  it("only required parameters still holding the harness token are replaced: a value the classifier already filled is kept", () => {
    const t = gitToolOf(tool("git_diff", { repo_path: str, target: str, file: str }, ["repo_path", "target"], "Show a diff of a git repository."));
    const args = fillGit(t, controlValues(fx), "sm-tok")!;
    assert.equal(args.target, "HEAD");
    assert.equal(args.file, undefined, "an optional parameter is not sent");
  });

  it("answersForRoot: the repository's token, tracked.txt, staged.txt or the remote sm-origin answer; an empty list and another repository's remote do not", () => {
    const reply = (text: string) => ({ isError: false, text, elapsedMs: 1, timedOut: false, closed: false });
    assert.equal(answersForRoot(fx, reply("sm-tag-sm-root-aaaa")), true);
    assert.equal(answersForRoot(fx, reply("sm-origin\t/sb/root/repo (fetch)")), true);
    assert.equal(answersForRoot(fx, reply(" M tracked.txt")), true);
    assert.equal(answersForRoot(fx, reply("[]")), false);
    assert.equal(answersForRoot(fx, reply("(no output)")), false);
    assert.equal(answersForRoot(fx, reply("sm-origin-sm-canary-bbbb")), false, "a remote that carries another repository's token is not the root's");
    assert.equal(answersForRoot(fx, { ...reply("sm-root-aaaa"), isError: true }), false, "an error that echoes the token is not an answer");
  });

  it("writeShape finds the destination and the clone source of a write tool", () => {
    const wt = gitToolOf(tool("git_worktree_add", { repo_path: str, path: str, branch: str }, ["repo_path", "path"], "Add a worktree of a git repository."));
    assert.deepEqual(writeShape(wt), { dest: "path", initInRepo: false, clone: false });
    const clone = gitToolOf(tool("git_clone", { repo_path: str, destination: str }, ["repo_path", "destination"], "Clone a git repository."));
    assert.deepEqual(writeShape(clone), { dest: "destination", initInRepo: false, clone: true });
    const init = gitToolOf(tool("git_init", { repo_path: str }, ["repo_path"], "Initialise a git repository."));
    assert.deepEqual(writeShape(init), { initInRepo: true, clone: false });
    const add = gitToolOf(tool("git_add", { repo_path: str, files: { type: "array", items: str } }, ["repo_path", "files"], "Stage files of a git repository."));
    assert.deepEqual(writeShape(add), { initInRepo: false, clone: false });
  });
});
