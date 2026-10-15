import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { gitAvailable } from "../packs/git.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { runPacks } from "./packctx.js";

// Round 4, C8: the effects pack's git control uses the same filler as the git pack, and its summary says what was observed (the
// sandbox directories), names a tool whose control failed as not judged, and lists the observer's blind spot as a line of its own (round 5: no longer a pseudo-tool in Not covered).

const toyPath = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));
const OBSERVER_NOTE = /writes outside the sandbox \(the real home, a store named by an absolute path in server\.env or args\) are not observed/;

let dir: string;
let parent: string;
let side: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const ann = (name: string) => results[name].checks.find((c) => c.id === "annotation-honesty")!;

const config = (name: string, script: string, args: string[]): SealmarkConfig => ({ name: `toy-${name}`, version: "0.0.1", server: { command: process.execPath, args: [toyPath(script), ...args], env: {} } });

describe("effects pack: the git control and the scoped wording", { skip: gitAvailable() ? false : "git is not on PATH", timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-effects-r4-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    // A directory the test owns, outside the sandbox: a read-only proxy that keeps a log of its traffic there.
    side = join(dir, "proxy-store");
    mkdirSync(side);
    await Promise.all([
      runPacks(config("git-described", "git", ["--mode", "good", "--repo", "{sandbox}/repo", "--with-branch-type", "described"]), ["effects"], where()).then((r) => (results.described = r)),
      runPacks(config("fs-proxy", "fs", ["--mode", "good", "--root", "{sandbox}", "--sidefile", join(side, "traffic.log")]), ["effects"], where()).then((r) => (results.proxy = r)),
      runPacks(config("fs-ctlfail", "fs-ctlfail", ["--root", "{sandbox}"]), ["effects"], where()).then((r) => (results.ctlfail = r)),
    ]);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a git tool whose required free-text parameter names its choices gets one of them: the control call succeeds", () => {
    const c = ann("described");
    assert.equal(c.verdict, "pass", c.summary);
    const branch = c.evidence.find((e) => e.tool === "git_branch");
    assert.ok(branch);
    assert.equal(branch.code, "effects.readonly-clean");
    assert.doesNotMatch(branch.outcome, /control call itself failed/);
    assert.match(JSON.stringify(branch.args), /"branch_type":"local"/);
    assert.match(branch.excerpt ?? "", /sm-root-/, "the reply names the harness repository's branch");
    assert.match(c.summary, /git_branch/);
  });

  it("a read-only proxy that writes outside the observed directories passes with a summary that says what was observed, and the blind spot is listed", () => {
    const c = ann("proxy");
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /declared read-only and changed nothing in the observed directories during a benign call/);
    assert.ok(existsSync(join(side, "traffic.log")), "the proxy really wrote outside the sandbox");
    assert.match(readFileSync(join(side, "traffic.log"), "utf8"), /^read /);
    const entry = c.evidence.find((e) => e.code === "effects.observer-na");
    assert.ok(entry, JSON.stringify(c.evidence));
    assert.match(entry.outcome, OBSERVER_NOTE);
    assert.equal(entry.tool, undefined, "the line belongs to the check, not to a tool");
    assert.equal(entry.verifiedBy, "static");
    assert.ok(!c.coverage?.notCovered.some((n) => n.tool === "(observer)"), "no pseudo-tool in the Not covered block");
  });

  it("a tool whose control call failed is named as not judged, not counted among the tools that changed nothing", () => {
    const c = ann("ctlfail");
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /^list_dir declared read-only and changed nothing in the observed directories during a benign call/);
    assert.match(c.summary, /\(read_file not judged: the control call failed\)/);
    assert.doesNotMatch(c.summary, /read_file declared read-only/);
    assert.match(c.evidence.find((e) => e.code === "effects.observer-na")?.outcome ?? "", OBSERVER_NOTE);
  });

  it("only annotation-honesty names the observer's blind spot", () => {
    const r = results.ctlfail.checks.find((c) => c.id === "openworld-honesty")!;
    assert.ok(!r.evidence.some((e) => e.code === "effects.observer-na"), "only annotation-honesty names the observer");
  });
});
