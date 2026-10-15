import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { describe as describeFs } from "../packs/fs.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// Round 4, C1: the write corpus mirrors the read corpus. A server that applies a lexical root check and then decodes the path (or
// strips a file:// prefix after the check, or does not normalise "./..") passes the old write corpus; the near miss resolves links
// and compares whole path segments and must still pass.

const TOY = fileURLToPath(new URL("../toy/fs-encodedwrite.js", import.meta.url));
const WIN = process.platform === "win32";

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

const toy = (mode: string, trace: string): SealmarkConfig => ({
  name: `toy-fs-encodedwrite-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [TOY, "--mode", mode, "--root", "{sandbox}", "--trace", trace], env: {} },
});

const write = (mode: string) => results[mode].checks.find((c) => c.id === "fs-write-escape")!;

describe("fs-write-escape: encoded and alternate spellings of a path outside the root", { timeout: 300_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-encodedwrite-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      ["safe", "urldec", "fileurl", "dotslash"].map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(toy(m, traces[m]), ["fs"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("urldec (a lexical check, then decodeURIComponent) fails through the percent-encoded probe, on the write tool and on the copy destination", () => {
    const c = write("urldec");
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /write_file via pct-encoded/);
    assert.match(c.summary, /copy_file via pct-encoded/);
    assert.match(c.summary, /copy_file via move-dest-pct/);
    assert.doesNotMatch(c.summary, /dot-slash|file-url|move-dest-fileurl|via dotdot|via absolute/, "only the decoded spelling gets through");
    const hit = c.evidence.find((e) => e.code === "fs.write-escape" && /pct-encoded/.test(e.probe));
    assert.ok(hit);
    assert.equal(hit.verifiedBy, "fs-observer");
    assert.match(JSON.stringify(hit.args), /%2e%2e/);
  });

  it("fileurl (a file:// path accepted unchecked) fails through the file-url probe and the file:// copy destination", () => {
    const c = write("fileurl");
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /write_file via file-url/);
    assert.match(c.summary, /copy_file via move-dest-fileurl/);
    assert.doesNotMatch(c.summary, /pct-encoded|dot-slash|move-dest-pct/);
  });

  it("dotslash (./.. not normalised before the check) fails through the dot-slash probe", () => {
    const c = write("dotslash");
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /write_file via dot-slash/);
    assert.doesNotMatch(c.summary, /pct-encoded|file-url|via dotdot|move-dest/);
  });

  it("safe (realpath, then a separator-bounded prefix check) passes, and the new spellings were really sent", () => {
    const c = write("safe");
    assert.equal(c.verdict, "pass", c.summary);
    const sent = readTrace(traces.safe).filter((t) => t.tool === "write_file").flatMap((t) => stringArgs(t.args));
    assert.ok(sent.some((p) => /%2e%2e[\\/]canary[\\/]w-/.test(p)), `a percent-encoded write was sent: ${JSON.stringify(sent)}`);
    assert.ok(sent.some((p) => /^file:\/\/.*canary.*w-/.test(p)), "a file:// write was sent");
    assert.ok(sent.some((p) => /\.[\\/]\.\.[\\/]canary[\\/]w-/.test(p)), "a dot-slash write was sent");
    const copies = readTrace(traces.safe).filter((t) => t.tool === "copy_file").map((t) => String(t.args.destination));
    assert.ok(copies.some((p) => /%2e%2e[\\/]canary[\\/]moved-/.test(p)), "a percent-encoded copy destination was sent");
    assert.ok(copies.some((p) => /^file:\/\/.*canary.*moved-/.test(p)), "a file:// copy destination was sent");
    // The count in the summary moves with the corpus. On POSIX, per tool that takes absolute and root-relative paths: dotdot, absolute, dot-slash,
    // pct-encoded, evil-dotdot, evil-absolute, file-url, backslash, rel-dotdot, rel-evil, rel-backslash = 11 (forward-slash and rel-dotdot-fwd build
    // the same strings and are sent once; round 5 added evil-dotdot, backslash and rel-backslash). The copy tool adds move-copy, move-src-canary,
    // move-src-evil, move-src-rel, move-dest-pct, move-dest-fileurl = 6: 11 + 11 + 6 = 28 (it was 22).
    const m = /^(\d+) write attempts/.exec(c.summary);
    assert.ok(m, c.summary);
    if (!WIN) assert.equal(Number(m[1]), 28, c.summary);
    else assert.ok(Number(m[1]) >= 22, c.summary);
  });

  it("every path any probe sent lies inside the sandbox directory (the file:// and encoded forms included)", () => {
    for (const m of ["safe", "urldec", "fileurl", "dotslash"]) {
      const sandboxDir = results[m].sandbox!.dir!;
      for (const t of readTrace(traces[m])) for (const p of stringArgs(t.args)) assert.ok(insideDir(sandboxDir, p), `${m}: ${p}`);
    }
  });

  it("evidence labels use the platform's spelling of a probe, not the published Windows one", () => {
    if (WIN) return;
    for (const m of ["safe", "urldec"]) {
      for (const e of write(m).evidence) assert.doesNotMatch(e.probe, /\{sandbox\}\\/, `${m}: ${e.probe}`);
    }
  });

  it("describe() lists the new write probes and the two move destinations", () => {
    const doc = describeFs().find((d) => d.id === "fs-write-escape")!;
    const ids = doc.probes.map((p) => p.id);
    for (const id of ["dot-slash", "pct-encoded", "file-url", "move-dest-pct", "move-dest-fileurl"]) assert.ok(ids.includes(id), id);
    if (!WIN) assert.ok(!ids.includes("extended-length") || doc.probes.find((p) => p.id === "extended-length")!.text.includes("Windows only"));
    assert.equal(doc.probes.find((p) => p.id === "pct-encoded")!.text, "{sandbox}/%2e%2e/canary/w-<t>.txt");
    assert.equal(doc.probes.find((p) => p.id === "file-url")!.text, "file:///{canary}/w-<t>.txt");
  });
});
