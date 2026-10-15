import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { RunResult, SealmarkConfig } from "../types.js";
import { insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// A read tool that returns the file inside an embedded resource block (blob), never as text. The bytes reach the fs pack through
// CallResult.blobs: the control passes on them, and a canary in them is a leak.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const traces: Record<string, string> = {};
const results: Record<string, RunResult> = {};

const toy = (mode: string, trace: string): SealmarkConfig => ({
  name: `toy-fs-blobblock-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-blobblock.js", import.meta.url)), "--mode", mode, "--root", "{sandbox}", "--trace", trace], env: {} },
});

const MODES = ["leaky", "safe"] as const;
const read = (m: string) => results[m].checks.find((c) => c.id === "fs-read-escape")!;

describe("r3 fs-net: resource blocks reach the fs pack", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r3-blob-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      MODES.map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(toy(m, traces[m]), ["fs"], where());
      }),
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a read tool that returns files as resource blobs and does not check the path fails, and the evidence says where the canary was", () => {
    const c = read("leaky");
    assert.equal(c.verdict, "fail", c.summary);
    assert.ok(c.evidence.some((e) => e.code === "fs.control.read"), "the control was passed on the blob's bytes");
    const leak = c.evidence.find((e) => e.code === "fs.read-escape");
    assert.ok(leak && /in a resource block/.test(leak.outcome) && leak.verifiedBy === "response", JSON.stringify(leak));
    assert.ok(c.coverage?.probed.includes("read_media"));
    assert.deepEqual(c.coverage?.notCovered, []);
  });

  it("the same tool with the path held inside the root passes and is no longer listed as not covered", () => {
    const c = read("safe");
    assert.equal(c.verdict, "pass", c.summary);
    assert.deepEqual(c.coverage?.notCovered, [], "the tool was controlled and probed");
    assert.ok(c.coverage?.probed.includes("read_media"));
    assert.ok(readTrace(traces.safe).some((t) => stringArgs(t.args).includes("../canary/secret.txt")), "escape probes were sent to it");
    assert.ok(!c.evidence.some((e) => e.code === "fs.control.failed"));
  });

  it("the link check reads the blob too: nothing escapes through a link in the safe mode", () => {
    const link = results.safe.checks.find((c) => c.id === "fs-link-escape")!;
    assert.notEqual(link.verdict, "fail", link.summary);
  });

  it("every path sent is inside the sandbox directory", () => {
    for (const m of MODES) {
      const sandboxDir = results[m].sandbox?.dir;
      assert.ok(sandboxDir, `${m}: sandbox dir recorded`);
      for (const t of readTrace(traces[m])) {
        for (const p of stringArgs(t.args).filter((s) => /[\\/]/.test(s) && s.length > 2)) assert.ok(insideDir(sandboxDir, p), `${m}: ${t.tool} was sent ${p}`);
      }
    }
  });
});
