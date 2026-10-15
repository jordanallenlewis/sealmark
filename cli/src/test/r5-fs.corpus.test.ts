import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { describe as describeFs } from "../packs/fs.js";
import type { CheckResult, RunResult, SealmarkConfig } from "../types.js";
import { insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// Round 5, package fs: one entry per new corpus family, each with a toy that must now fail and a near-miss that must still pass.

const TOY = fileURLToPath(new URL("../toy/fs-r5.js", import.meta.url));
const WIN = process.platform === "win32";

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

const toy = (name: string, mode: string, extra: string[] = []): SealmarkConfig => {
  traces[name] = join(dir, `trace-${name}.jsonl`);
  return { name: `toy-fs-r5-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [TOY, "--mode", mode, "--root", "{sandbox}", ...extra, "--trace", traces[name]], env: {} } };
};

const check = (name: string, id: string): CheckResult => results[name].checks.find((c) => c.id === id)!;
const verdictsOf = (name: string) => Object.fromEntries(results[name].checks.filter((c) => c.pack === "fs").map((c) => [c.id, c.verdict]));
const hits = (name: string, id: string) => check(name, id).evidence.filter((e) => /^fs\.(read|write|link)-escape$/.test(e.code ?? ""));
const probesOf = (name: string, id: string) => hits(name, id).map((e) => e.probe);

/** The edit tool with an `edits` array is unfillable for the classifier on this branch (the object filler lands with the core package, seam S5), so the run forces its class. */
const OVERRIDE = { tools: { include: ["*"], exclude: [], overrides: { edit_file: { class: "path" as const } } } };

describe("fs pack, round 5: corpus families", { timeout: 600_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-r5-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const runs: [string, string, string[]?, object?][] = [
      ["safe", "safe"],
      ["arrayonly", "arrayonly"],
      ["arrayall-safe", "arrayall-safe"],
      ["bslash", "bslash"],
      ["bslash-safe", "bslash-safe"],
      ["movelink", "movelink"],
      ["move-safe", "move-safe"],
      ["editonly", "editonly"],
      ["edit-safe", "edit-safe"],
      ["editonly-edits", "editonly", ["--edit-shape", "edits"], OVERRIDE],
      ["edit-safe-edits", "edit-safe", ["--edit-shape", "edits"], OVERRIDE],
      ["linkfile", "linkfile"],
      ["dangling", "dangling"],
      ["search-substr", "search-substr"],
      ["search-open", "search-open"],
    ];
    // A few at a time: each run starts its own sandbox and server.
    for (let i = 0; i < runs.length; i += 5) {
      await Promise.all(
        runs.slice(i, i + 5).map(async ([name, mode, extra, over]) => {
          results[name] = await runPacks(toy(name, mode, extra), ["fs"], where(), over ?? {});
        }),
      );
    }
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("the near-miss that handles every family passes every check", () => {
    assert.deepEqual(verdictsOf("safe"), { "fs-read-escape": "pass", "fs-write-escape": "pass", "fs-link-escape": "pass", "fs-size-cap": "pass" });
  });

  describe("array-second", () => {
    it("a multi-path reader that validates paths[0] only fails, and the evidence names the slot", () => {
      assert.equal(check("arrayonly", "fs-read-escape").verdict, "fail", check("arrayonly", "fs-read-escape").summary);
      const h = hits("arrayonly", "fs-read-escape").filter((e) => /array-second/.test(e.probe));
      assert.ok(h.length, JSON.stringify(probesOf("arrayonly", "fs-read-escape")));
      assert.match(h[0].probe, /read_multiple_files\(array-second: \[.*second slot of a path array\)/);
      // Only the array probe leaks: the single-path forms are held by the first-element check.
      assert.deepEqual([...new Set(hits("arrayonly", "fs-read-escape").map((e) => e.tool))], ["read_multiple_files"]);
    });
    it("near miss: a reader that validates every element passes, and the escape was sent in the second slot", () => {
      assert.equal(check("arrayall-safe", "fs-read-escape").verdict, "pass", check("arrayall-safe", "fs-read-escape").summary);
      const sent = readTrace(traces["arrayall-safe"]).filter((t) => t.tool === "read_multiple_files" && Array.isArray(t.args.paths));
      assert.ok(sent.some((t) => (t.args.paths as string[]).length === 2 && /ok\.txt$/.test((t.args.paths as string[])[0]) && /canary[\\/]secret\.txt$/.test((t.args.paths as string[])[1])), JSON.stringify(sent.map((t) => t.args)));
    });
    it("a tool with no array parameter is never sent an array", () => {
      assert.ok(readTrace(traces.safe).every((t) => Object.values(t.args).every((v) => typeof v === "string")));
    });
  });

  describe("backslash", { skip: WIN ? "on Windows the backslash forms are the dot-dot forms and are sent once" : false }, () => {
    it("a server that turns \\ into / after its root check fails read and write through the root-relative form", () => {
      assert.equal(check("bslash", "fs-read-escape").verdict, "fail", check("bslash", "fs-read-escape").summary);
      assert.equal(check("bslash", "fs-write-escape").verdict, "fail", check("bslash", "fs-write-escape").summary);
      assert.ok(probesOf("bslash", "fs-read-escape").some((p) => /rel-backslash/.test(p)), JSON.stringify(probesOf("bslash", "fs-read-escape")));
      assert.ok(probesOf("bslash", "fs-write-escape").some((p) => /rel-backslash/.test(p)), JSON.stringify(probesOf("bslash", "fs-write-escape")));
    });
    it("near miss: a server that treats \\ as an ordinary character passes both", () => {
      assert.equal(check("bslash-safe", "fs-read-escape").verdict, "pass", check("bslash-safe", "fs-read-escape").summary);
      assert.equal(check("bslash-safe", "fs-write-escape").verdict, "pass", check("bslash-safe", "fs-write-escape").summary);
    });
    it("the absolute backslash probe is sent with its backslashes and lies inside the sandbox directory", () => {
      const sent = readTrace(traces["bslash-safe"]);
      const abs = sent.flatMap((t) => stringArgs(t.args)).filter((p) => /root\\\.\.\\canary\\/.test(p));
      assert.ok(abs.length, "an absolute path with literal backslashes was sent");
      for (const p of abs) assert.ok(insideDir(String(results["bslash-safe"].sandbox!.dir), p), p);
      assert.ok(sent.flatMap((t) => stringArgs(t.args)).some((p) => p === "..\\canary\\secret.txt"), "the root-relative form was sent");
    });
    it("explain lists both forms with their backslashes, and none of them is dropped as a duplicate of dot-dot", () => {
      for (const id of ["fs-read-escape", "fs-write-escape"]) {
        const ids = describeFs().find((d) => d.id === id)!.probes.map((p) => p.id);
        for (const want of ["dotdot", "backslash", "rel-backslash"]) assert.ok(ids.includes(want), `${id} lists ${want}`);
      }
    });
  });

  describe("move and copy through links", () => {
    it("a move or copy tool that checks the path lexically fails fs-link-escape through both forms, and the plain write checks hold", () => {
      assert.equal(check("movelink", "fs-link-escape").verdict, "fail", check("movelink", "fs-link-escape").summary);
      assert.equal(check("movelink", "fs-write-escape").verdict, "pass", check("movelink", "fs-write-escape").summary);
      const p = probesOf("movelink", "fs-link-escape");
      assert.ok(p.some((x) => /^move_file\(move or copy a harness-created file .*link-dir\/moved-<t>/.test(x)), JSON.stringify(p));
      assert.ok(p.some((x) => /^copy_file\(move or copy .*link\.txt/.test(x)), JSON.stringify(p));
      const src = hits("movelink", "fs-link-escape").find((e) => /link\.txt/.test(e.probe))!;
      assert.equal(src.verifiedBy, "fs-observer");
      assert.match(src.outcome, /turn up in the root/);
    });
    it("a moved link is not exfiltration: the move tool alone does not fail the source-link probe", () => {
      // rename moves the link itself; only the copy tool follows it.
      assert.ok(!probesOf("movelink", "fs-link-escape").some((x) => /^move_file\(move or copy .*link\.txt \(symbolic link/.test(x)), JSON.stringify(probesOf("movelink", "fs-link-escape")));
    });
    it("near miss: tools that resolve links first pass", () => {
      assert.equal(check("move-safe", "fs-link-escape").verdict, "pass", check("move-safe", "fs-link-escape").summary);
      assert.equal(check("move-safe", "fs-write-escape").verdict, "pass", check("move-safe", "fs-write-escape").summary);
    });
    it("the link check no longer says move and copy tools are not probed", () => {
      for (const n of ["movelink", "move-safe"]) {
        const reasons = (check(n, "fs-link-escape").coverage?.notCovered ?? []).map((x) => x.reason);
        assert.ok(!reasons.some((x) => /link writes are probed through tools/.test(x)), `${n}: ${reasons.join("; ")}`);
        assert.ok((check(n, "fs-link-escape").coverage?.probed ?? []).includes("copy_file"));
      }
    });
  });

  describe("edit tools", () => {
    it("an edit tool that is the only unvalidated tool fails fs-write-escape, and the secret it edited was put back", () => {
      assert.equal(check("editonly", "fs-write-escape").verdict, "fail", check("editonly", "fs-write-escape").summary);
      const h = hits("editonly", "fs-write-escape");
      assert.ok(h.every((e) => e.tool === "edit_file"), JSON.stringify(h.map((e) => e.tool)));
      assert.ok(h.some((e) => /edit_file\(dotdot/.test(e.probe) || /edit_file\(forward-slash/.test(e.probe)));
      assert.ok(h.every((e) => e.verifiedBy === "fs-observer"));
    });
    it("the edit control is its own control: edit {sandbox}/ok.txt changes the file, and the tool is covered", () => {
      const c = check("edit-safe", "fs-write-escape");
      assert.ok(c.evidence.some((e) => e.code === "fs.control.edit" && /edits \{sandbox\}\/ok\.txt/.test(e.probe)), JSON.stringify(c.evidence.map((e) => e.code)));
      assert.ok((c.coverage?.probed ?? []).includes("edit_file"));
    });
    it("near miss: an edit tool that validates its path passes the write and link checks", () => {
      assert.equal(check("edit-safe", "fs-write-escape").verdict, "pass", check("edit-safe", "fs-write-escape").summary);
      assert.equal(check("edit-safe", "fs-link-escape").verdict, "pass", check("edit-safe", "fs-link-escape").summary);
    });
    it("the edits: [{oldText, newText}] shape is built by the pack's own filler, with the class forced (seam S5)", () => {
      assert.equal(check("editonly-edits", "fs-write-escape").verdict, "fail", check("editonly-edits", "fs-write-escape").summary);
      assert.equal(check("edit-safe-edits", "fs-write-escape").verdict, "pass", check("edit-safe-edits", "fs-write-escape").summary);
      const sent = readTrace(traces["edit-safe-edits"]).filter((t) => t.tool === "edit_file");
      assert.ok(sent.length > 10 && sent.every((t) => Array.isArray(t.args.edits) && (t.args.edits as { oldText: string; newText: string }[]).every((e) => typeof e.oldText === "string" && typeof e.newText === "string")));
    });
    it("every edit is aimed at a planted file inside the sandbox directory", () => {
      for (const n of ["editonly", "edit-safe"]) {
        for (const t of readTrace(traces[n]).filter((x) => x.tool === "edit_file")) assert.ok(insideDir(String(results[n].sandbox!.dir), String(t.args.path)), String(t.args.path));
      }
    });
  });

  describe("links the write corpus did not use", () => {
    it("a write that resolves directory links but not a link to a file fails through link-file-write; the dangling link is refused", () => {
      assert.equal(check("linkfile", "fs-link-escape").verdict, "fail", check("linkfile", "fs-link-escape").summary);
      const p = probesOf("linkfile", "fs-link-escape");
      assert.ok(p.some((x) => /link-file-write|link\.txt \(write through/.test(x)), JSON.stringify(p));
      assert.ok(!p.some((x) => /dangling/.test(x)), JSON.stringify(p));
    });
    it("a write that treats a dangling link as a new file fails through dangling-link-write", () => {
      assert.equal(check("dangling", "fs-link-escape").verdict, "fail", check("dangling", "fs-link-escape").summary);
      const p = probesOf("dangling", "fs-link-escape");
      assert.ok(p.some((x) => /link-dangling\.txt/.test(x)), JSON.stringify(p));
      assert.ok(!p.some((x) => /^write_file\(\{sandbox\}\/link\.txt/.test(x)), JSON.stringify(p));
    });
    it("near miss: the near-miss toy refuses all three links, and every write check holds on the toys that fail only a link", () => {
      assert.equal(check("safe", "fs-link-escape").verdict, "pass");
      for (const n of ["linkfile", "dangling"]) assert.equal(check(n, "fs-write-escape").verdict, "pass", `${n}: ${check(n, "fs-write-escape").summary}`);
    });
    it("evil-dotdot is in the write corpus and was sent", () => {
      assert.ok(describeFs().find((d) => d.id === "fs-write-escape")!.probes.some((p) => p.id === "evil-dotdot"));
      assert.ok(readTrace(traces.safe).some((t) => typeof t.args.path === "string" && /root-evil[\\/]w-/.test(t.args.path) && /\.\.[\\/]root-evil/.test(t.args.path)));
    });
  });

  describe("search tools", () => {
    it("a substring-matching search tool is covered and judged (the old wildcard control found nothing)", () => {
      const c = check("search-substr", "fs-read-escape");
      assert.equal(c.verdict, "pass", c.summary);
      assert.ok((c.coverage?.probed ?? []).includes("search_files"), JSON.stringify(c.coverage));
      assert.ok(!(c.coverage?.notCovered ?? []).some((n) => n.tool === "search_files"), JSON.stringify(c.coverage?.notCovered));
    });
    it("near miss reversed: the same tool with no path check fails, because the pattern also matches secret.txt", () => {
      const c = check("search-open", "fs-read-escape");
      assert.equal(c.verdict, "fail", c.summary);
      assert.ok(c.evidence.some((e) => e.tool === "search_files" && /listing shows secret\.txt/.test(e.outcome)));
    });
  });

  describe("explain", () => {
    it("fs-write-escape lists evil-dotdot, backslash, rel-backslash, array-second, the two move-link forms and the two new link forms", () => {
      const ids = describeFs().find((d) => d.id === "fs-write-escape")!.probes.map((p) => p.id);
      for (const want of ["evil-dotdot", "backslash", "rel-backslash", "array-second", "move-dest-link", "move-src-link", "link-file-write", "dangling-link-write"]) assert.ok(ids.includes(want), `${want} in ${ids.join(", ")}`);
      const linkIds = describeFs().find((d) => d.id === "fs-link-escape")!.probes.map((p) => p.id);
      for (const want of ["link-dir-write", "link-file-write", "dangling-link-write", "move-dest-link", "move-src-link"]) assert.ok(linkIds.includes(want), `${want} in ${linkIds.join(", ")}`);
    });
    it("the directory link is a symbolic link to a directory on POSIX and a junction on Windows", () => {
      const text = describeFs().find((d) => d.id === "fs-link-escape")!.probes.map((p) => p.text).join("\n");
      if (WIN) assert.match(text, /junction/);
      else {
        assert.doesNotMatch(text, /junction/);
        assert.match(text, /symbolic link to directory/);
      }
    });
  });
});
