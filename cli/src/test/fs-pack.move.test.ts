import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { describe as describeFs, pack as fsPack } from "../packs/fs.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { verdicts } from "./helpers.js";
import { directCtx, insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// Move and copy source escapes: a server that holds the destination inside its root but never checks the source must fail.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const traces: Record<string, string> = {};
const results: Record<string, RunResult> = {};

const toy = (args: string[], trace?: string): SealmarkConfig => ({
  name: "toy-fs-movesrc",
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-movesrc.js", import.meta.url)), ...args, "--root", "{sandbox}", ...(trace ? ["--trace", trace] : [])], env: {} },
});

const CASES: Record<string, string[]> = {
  "move-dest": ["--op", "move", "--check", "dest"],
  "copy-dest": ["--op", "copy", "--check", "dest"],
  "move-both": ["--op", "move", "--check", "both"],
  "copy-both": ["--op", "copy", "--check", "both"],
};

const write = (name: string) => results[name].checks.find((c) => c.id === "fs-write-escape")!;

describe("fs pack: move and copy sources", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-move-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      Object.entries(CASES).map(async ([name, args]) => {
        traces[name] = join(dir, `trace-${name}.jsonl`);
        results[name] = await runPacks(toy(args, traces[name]), ["fs"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a move tool that checks the destination but not the source fails: the secret is moved into the root", () => {
    assert.equal(write("move-dest").verdict, "fail", write("move-dest").summary);
    const hits = write("move-dest").evidence.filter((e) => e.code === "fs.write-escape");
    assert.ok(hits.some((e) => /move-src-(canary|evil)/.test(e.probe) && e.verifiedBy === "fs-observer" && /moved into the root/.test(e.outcome)), JSON.stringify(hits.map((e) => [e.probe, e.outcome])));
    // The destination checks hold, so the destination-side probes are not what failed it.
    assert.ok(!hits.some((e) => /\((absolute|dotdot|evil-absolute|rel-dotdot|rel-evil|move-copy):/.test(e.probe)), "only source probes leak");
  });

  it("a copy tool that checks the destination but not the source fails: the secret turns up inside the root", () => {
    assert.equal(write("copy-dest").verdict, "fail", write("copy-dest").summary);
    const hits = write("copy-dest").evidence.filter((e) => e.code === "fs.write-escape");
    assert.ok(hits.some((e) => /move-src-/.test(e.probe) && /turned up inside the root/.test(e.outcome)), JSON.stringify(hits.map((e) => [e.probe, e.outcome])));
  });

  it("a tool that checks both slots passes", () => {
    for (const name of ["move-both", "copy-both"]) assert.equal(write(name).verdict, "pass", `${name}: ${write(name).summary}`);
  });

  it("the advertised move-copy probe is sent, and the described corpus lists every move probe that runs", () => {
    const sent = readTrace(traces["move-both"]);
    assert.ok(sent.some((t) => stringArgs(t.args).some((p) => /[\\/]canary[\\/]moved-/.test(p))), "destination aimed at {canary}/moved-<t>");
    assert.ok(sent.some((t) => typeof t.args.source === "string" && /[\\/]canary[\\/]secret\.txt$/.test(t.args.source) && typeof t.args.destination === "string" && /[\\/]mv-/.test(t.args.destination)), "source aimed at {canary}/secret.txt");
    assert.ok(sent.some((t) => typeof t.args.source === "string" && /[\\/]root-evil[\\/]secret\.txt$/.test(t.args.source)), "source aimed at {root_evil}/secret.txt");
    assert.ok(sent.some((t) => t.args.source === "../canary/secret.txt"), "relative source");
    const described = describeFs()
      .find((d) => d.id === "fs-write-escape")!
      .probes.map((p) => p.id);
    for (const id of ["move-copy", "move-src-canary", "move-src-evil", "move-src-rel"]) assert.ok(described.includes(id), `${id} is described`);
  });

  it("every path sent is inside the sandbox directory", () => {
    for (const name of Object.keys(CASES)) {
      const sandboxDir = results[name].sandbox?.dir;
      assert.ok(sandboxDir, `${name}: sandbox dir recorded`);
      for (const t of readTrace(traces[name])) {
        for (const p of stringArgs(t.args).filter((s) => /[\\/]/.test(s) && s.length > 2)) assert.ok(insideDir(sandboxDir, p), `${name}: ${t.tool} was sent ${p}`);
      }
    }
  });

  it("the secrets are put back after a move probe took them, so the checks that follow still have something to find", async () => {
    const d = await directCtx(toy(CASES["move-dest"]), "fs", where());
    try {
      const out = await fsPack.run(d.ctx);
      assert.equal(out.find((c) => c.id === "fs-write-escape")!.verdict, "fail");
      assert.equal(readFileSync(d.sandbox.files.canary, "utf8"), d.sandbox.tokens.canary);
      assert.equal(readFileSync(d.sandbox.files.evil, "utf8"), d.sandbox.tokens.evil);
      assert.deepEqual(readdirSync(d.sandbox.root).filter((n) => n.startsWith("mv-")), [], "no moved secret is left in the root");
    } finally {
      await d.close();
    }
  });

  it("nothing here reads files, so the read check stays n/a; the move tool is now sent through the links (round 5)", () => {
    for (const name of Object.keys(CASES)) {
      const v = verdicts(results[name], "fs");
      assert.equal(v["fs-read-escape"], "na");
    }
    // A move renames the link itself (no escape); a copy follows a link that is the source, and the secret turns up inside the root.
    assert.equal(verdicts(results["move-dest"], "fs")["fs-link-escape"], "pass");
    assert.equal(verdicts(results["move-both"], "fs")["fs-link-escape"], "pass");
    assert.equal(verdicts(results["copy-both"], "fs")["fs-link-escape"], "pass");
    const copy = results["copy-dest"].checks.find((c) => c.id === "fs-link-escape")!;
    assert.equal(copy.verdict, "fail", copy.summary);
    assert.match(copy.summary, /copy_file via move-src-link/);
  });
});
