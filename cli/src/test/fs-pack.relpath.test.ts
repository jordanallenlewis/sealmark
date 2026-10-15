import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { RunResult, SealmarkConfig } from "../types.js";
import { verdicts } from "./helpers.js";
import { insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// Relative-path escapes: a server that checks absolute paths and trusts relative ones must fail; one that checks both passes;
// one that takes absolute paths only is not sent relative probes at all.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const traces: Record<string, string> = {};
const results: Record<string, RunResult> = {};

const toy = (file: string, args: string[], trace: string): SealmarkConfig => ({
  name: `toy-${file}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL(`../toy/${file}.js`, import.meta.url)), ...args, "--root", "{sandbox}", "--trace", trace], env: {} },
});

const CASES: Record<string, [string, string[]]> = {
  relonly: ["fs-relonly", []],
  reldeny: ["fs-reldeny", []],
  absonly: ["fs-reldeny", ["--abs-only"]],
};

const check = (name: string, id: string) => results[name].checks.find((c) => c.id === id)!;

describe("fs pack: relative-path escapes", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-rel-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      Object.entries(CASES).map(async ([name, [file, args]]) => {
        traces[name] = join(dir, `trace-${name}.jsonl`);
        results[name] = await runPacks(toy(file, args, traces[name]), ["fs"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a server that checks absolute paths but trusts relative ones fails the read and write checks, through relative probes only", () => {
    const v = verdicts(results.relonly, "fs");
    assert.equal(v["fs-read-escape"], "fail", check("relonly", "fs-read-escape").summary);
    assert.equal(v["fs-write-escape"], "fail", check("relonly", "fs-write-escape").summary);
    for (const id of ["fs-read-escape", "fs-write-escape"]) {
      const leaks = check("relonly", id).evidence.filter((e) => e.code === `fs.${id === "fs-read-escape" ? "read" : "write"}-escape`);
      assert.ok(leaks.length > 0, `${id}: leak evidence`);
      // The absolute forms are validated by this toy, so a leak through one of them would mean the relative probes were not what failed it.
      for (const e of leaks) assert.match(e.probe, /\(rel-/, `${id}: ${e.probe}`);
    }
  });

  it("a server that checks both forms passes, and the relative probes were really sent", () => {
    const v = verdicts(results.reldeny, "fs");
    assert.equal(v["fs-read-escape"], "pass", check("reldeny", "fs-read-escape").summary);
    assert.equal(v["fs-write-escape"], "pass", check("reldeny", "fs-write-escape").summary);
    const sent = readTrace(traces.reldeny).flatMap((t) => stringArgs(t.args));
    assert.ok(sent.includes("../canary/secret.txt"), "rel-dotdot read sent");
    assert.ok(sent.includes("../root-evil/secret.txt"), "rel-evil read sent");
    assert.ok(sent.some((p) => /^\.\.\/canary\/w-/.test(p)), "rel-dotdot write sent");
    assert.ok(sent.some((p) => /^\.\.\/root-evil\/w-/.test(p)), "rel-evil write sent");
  });

  it("a server that takes absolute paths only runs the absolute probes only", () => {
    const v = verdicts(results.absonly, "fs");
    assert.equal(v["fs-read-escape"], "pass", check("absonly", "fs-read-escape").summary);
    assert.equal(v["fs-write-escape"], "pass", check("absonly", "fs-write-escape").summary);
    const sent = readTrace(traces.absonly).flatMap((t) => stringArgs(t.args));
    assert.ok(!sent.some((p) => p.startsWith("../")), "no relative traversal was sent");
    assert.ok(sent.some((p) => /canary/.test(p)), "the absolute probes still ran");
  });

  it("two probes that build the same string are sent once", { skip: process.platform === "win32" }, () => {
    const reads = readTrace(traces.reldeny)
      .filter((t) => t.tool === "read_file")
      .flatMap((t) => stringArgs(t.args))
      .filter((p) => /canary|root-evil/.test(p) && !/link/.test(p));
    assert.ok(reads.length > 5);
    assert.equal(new Set(reads).size, reads.length, "no read path was sent twice");
  });

  it("every path a probe sent is inside the sandbox directory", () => {
    for (const name of Object.keys(CASES)) {
      const sandboxDir = results[name].sandbox?.dir;
      assert.ok(sandboxDir, `${name}: sandbox dir recorded`);
      const calls = readTrace(traces[name]);
      assert.ok(calls.length > 10, `${name}: probes were sent`);
      for (const t of calls) {
        for (const p of stringArgs(t.args).filter((s) => /[\\/]|^file:/.test(s) && s.length > 2)) assert.ok(insideDir(sandboxDir, p), `${name}: ${t.tool} was sent ${p}`);
      }
    }
  });
});
