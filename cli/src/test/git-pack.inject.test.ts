import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { ToolInfo } from "../mcp.js";
import { fillGit, gitAvailable, injectables, type GitTool } from "../packs/git.js";
import type { RunResult, SealmarkConfig, ToolClassification } from "../types.js";
import { verdicts } from "./helpers.js";
import { readTrace, runPacks } from "./packctx.js";

const skip = gitAvailable() ? false : "git is not on PATH";
const INJECT_TOY = fileURLToPath(new URL("../toy/git-inject.js", import.meta.url));

const injectConfig = (mode: string, trace: string): SealmarkConfig => ({
  name: `toy-git-inject-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [INJECT_TOY, "--mode", mode, "--repo", "{sandbox}/repo", "--trace", trace], env: {} },
});

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

describe("git pack: argument injection through an optional (anyOf) parameter", { skip, timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-git-inject-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      ["loose", "strict", "refname"].map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(injectConfig(m, traces[m]), ["git"], { dir, parent });
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("an optional revision handed to git unchecked fails git-arg-injection, seen as a file that appeared", () => {
    const r = results.loose;
    const check = r.checks.find((c) => c.id === "git-arg-injection")!;
    assert.equal(check.verdict, "fail", JSON.stringify([check.summary, check.coverage]));
    assert.match(check.summary, /git_log\.revision/);
    const hit = check.evidence.find((e) => e.code === "git.arg-injection");
    assert.ok(hit);
    assert.equal(hit.verifiedBy, "fs-observer");
    assert.match(hit.outcome, /pwned-/);
    assert.equal(verdicts(r, "git")["git-repo-scope"], "pass", "only the optional parameter is at fault");
    const sent = readTrace(traces.loose).filter((t) => String(t.args.revision ?? "").startsWith("--output="));
    assert.equal(sent.length, 1);
    assert.equal(Object.hasOwn(sent[0].args, "max_count"), false, "the other optional parameter is left unset");
  });

  it("a validating near-miss passes, with no claim that there was nothing to inject", () => {
    const r = results.strict;
    const v = verdicts(r, "git");
    assert.deepEqual([v["git-repo-scope"], v["git-arg-injection"]], ["pass", "pass"], JSON.stringify(r.checks.map((c) => [c.id, c.summary])));
    const inj = r.checks.find((c) => c.id === "git-arg-injection")!;
    assert.ok(inj.evidence.some((e) => e.code === "git.control"), "a benign control call answered first");
    assert.ok(!(inj.coverage?.notCovered ?? []).some((n) => /nothing to inject/.test(n.reason)));
    assert.doesNotMatch(JSON.stringify(r.checks), /nothing to inject/);
    assert.equal(readTrace(traces.strict).filter((t) => String(t.args.revision ?? "").startsWith("--output=")).length, 1, "the value was sent");
  });

  it("a ref under .git named after the option is reported but is not git honouring it", () => {
    const r = results.refname;
    const inj = r.checks.find((c) => c.id === "git-arg-injection")!;
    assert.equal(inj.verdict, "pass", JSON.stringify([inj.summary, inj.evidence.map((e) => [e.code, e.outcome])]));
    assert.ok(!inj.evidence.some((e) => e.code === "git.arg-injection"));
    const ref = inj.evidence.find((e) => e.code === "git.arg-ref");
    assert.ok(ref, "the ref is shown");
    assert.match(ref.outcome, /under \.git/);
    assert.match(ref.outcome, /not counted/);
  });
});

describe("git pack: which parameters can carry an injected option", () => {
  const cls = (name: string, params: ToolClassification["params"] = { repo: "repo_path" }): ToolClassification => ({ tool: name, class: "git", confidence: "high", params, unfillable: [], reasons: [] });
  const gt = (properties: Record<string, unknown>, extra: Record<string, unknown> = {}, params?: ToolClassification["params"]): GitTool => {
    const tool: ToolInfo = { name: "git_thing", description: "", inputSchema: { type: "object", properties, ...extra } as ToolInfo["inputSchema"] };
    return { tool, c: cls("git_thing", params), kind: "read" };
  };
  const names = (t: GitTool) => injectables(t).inject.map((i) => (i.array ? `${i.name}[]` : i.name));

  it("takes anyOf and oneOf branches that can hold a string, and type lists", () => {
    const t = gt({
      repo_path: { type: "string" },
      a: { anyOf: [{ type: "string" }, { type: "null" }], default: null },
      b: { oneOf: [{ type: "integer" }, { type: "string" }] },
      c: { type: ["string", "null"] },
      d: { anyOf: [{ type: "array", items: { type: "string" } }, { type: "null" }] },
      e: { anyOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
    });
    assert.deepEqual(names(t), ["a", "b", "c", "d[]", "e"]);
  });

  it("follows $ref into $defs and definitions", () => {
    const t = gt({ repo_path: { type: "string" }, a: { $ref: "#/$defs/Rev" }, b: { anyOf: [{ $ref: "#/definitions/Names" }, { type: "null" }] } }, { $defs: { Rev: { type: "string" } }, definitions: { Names: { type: "array", items: { type: "string" } } } });
    assert.deepEqual(names(t), ["a", "b[]"]);
  });

  it("never picks an object or an array of objects, and leaves fixed sets of values alone", () => {
    const t = gt({
      repo_path: { type: "string" },
      o: { anyOf: [{ type: "object" }, { type: "null" }] },
      objs: { anyOf: [{ type: "array", items: { type: "object" } }, { type: "null" }] },
      kind: { enum: ["local", "remote"] },
      opt: { anyOf: [{ enum: ["x", "y"] }, { type: "null" }] },
      num: { type: "integer" },
      loose: { $ref: "#/$defs/Missing" },
    });
    assert.deepEqual(names(t), []);
    const skipped = injectables(t).skipped.map((s) => s.name);
    assert.deepEqual(skipped, ["repo_path", "kind", "opt"]);
  });

  it("an object branch next to a string branch still yields the string", () => {
    assert.deepEqual(names(gt({ repo_path: { type: "string" }, a: { anyOf: [{ type: "object" }, { type: "string" }, { type: "null" }] } })), ["a"]);
  });

  it("the repository, message and content parameters are not probed, and are named as skipped with the reason", () => {
    const t = gt({ repo_path: { type: "string" }, message: { type: "string" }, body: { anyOf: [{ type: "string" }, { type: "null" }] } }, {}, { repo: "repo_path", message: "message", content: "body" });
    assert.deepEqual(names(t), []);
    assert.deepEqual(injectables(t).skipped, [
      { name: "repo_path", why: "it is the repository" },
      { name: "message", why: "it is a commit message" },
      { name: "body", why: "it is file content" },
    ]);
  });

  it("fillGit fills a required free-text parameter with the values its description names, and only then", () => {
    const tool: ToolInfo = {
      name: "git_branch",
      description: "List branches.",
      inputSchema: { type: "object", properties: { repo_path: { type: "string" }, branch_type: { type: "string", description: "'local', 'remote', or 'all'" }, note: { type: "string", description: "Some free text about the call, with 'one' quoted word" } }, required: ["repo_path", "branch_type", "note"] },
    };
    const t: GitTool = { tool, c: cls("git_branch"), kind: "read" };
    const args = fillGit(t, { repo: "/x/repo" }, "sm-token");
    assert.deepEqual(args, { repo_path: "/x/repo", branch_type: "local", note: "sm-token" });
  });
});
