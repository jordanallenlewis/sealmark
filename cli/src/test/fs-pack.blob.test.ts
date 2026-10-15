import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { withDecodedBase64 } from "../packs/fs.js";
import type { RunResult, SealmarkConfig } from "../types.js";
import { insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

// Read tools that return bytes encoded: a base64 reply is decoded before the canary is looked for, and so is the blob of a
// resource, image or audio block (CallResult.blobs). A block whose data the harness does not hold would leave the check short of
// a pass instead of silently skipping the tool; the toy here returns its data, so the unvalidated tool is controlled and probed.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const traces: Record<string, string> = {};
const results: Record<string, RunResult> = {};

const toy = (mode: string, trace: string): SealmarkConfig => ({
  name: `toy-fs-blob-${mode}`,
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-blob.js", import.meta.url)), "--mode", mode, "--root", "{sandbox}", "--trace", trace], env: {} },
});

const MODES = ["b64-leaky", "b64-safe", "blob-leaky"] as const;
const read = (m: string) => results[m].checks.find((c) => c.id === "fs-read-escape")!;

describe("fs pack: base64 and blob read tools", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-blob-"));
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

  it("a read tool that returns the file as base64 and does not check the path fails, and the evidence says the canary was encoded", () => {
    assert.equal(read("b64-leaky").verdict, "fail", read("b64-leaky").summary);
    assert.ok(read("b64-leaky").evidence.some((e) => e.code === "fs.control.read"), "the control read was decoded");
    const leak = read("b64-leaky").evidence.find((e) => e.code === "fs.read-escape");
    assert.ok(leak && /base64/.test(leak.outcome) && leak.verifiedBy === "response", JSON.stringify(leak));
  });

  it("the same tool with the path held inside the root passes, and was really probed", () => {
    assert.equal(read("b64-safe").verdict, "pass", read("b64-safe").summary);
    assert.ok(read("b64-safe").coverage?.probed.includes("read_media"));
    assert.ok(readTrace(traces["b64-safe"]).some((t) => stringArgs(t.args).includes("../canary/secret.txt")), "escape probes were sent");
    assert.deepEqual(read("b64-safe").coverage?.notCovered, []);
  });

  it("a resource block is read: its control passes, the unvalidated tool is probed and fails, the validated reader next to it is probed too", () => {
    const c = read("blob-leaky");
    assert.equal(c.verdict, "fail", c.summary);
    assert.deepEqual(c.coverage?.notCovered, [], "read_media is no longer skipped");
    const leak = c.evidence.find((e) => e.code === "fs.read-escape" && e.tool === "read_media");
    assert.ok(leak && /in a resource block/.test(leak.outcome), JSON.stringify(c.evidence.map((e) => [e.tool, e.outcome])));
    assert.ok(c.coverage?.probed.includes("read_text"));
    assert.ok(readTrace(traces["blob-leaky"]).some((t) => t.tool === "read_media" && stringArgs(t.args).some((p) => /canary/.test(p))), "escape probes went to the tool whose blob can now be read");
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

describe("fs pack: base64 decoding", () => {
  const token = "sm-fscanary-0123abcd";
  const b64 = Buffer.from(token).toString("base64");

  it("finds the token in a JSON data field, a data URI, a bare body and a wrapped body", () => {
    assert.ok(withDecodedBase64(JSON.stringify({ mimeType: "text/plain", data: b64 })).includes(token));
    assert.ok(withDecodedBase64(`data:text/plain;base64,${b64}`).includes(token));
    assert.ok(withDecodedBase64(b64).includes(token));
    const long = Buffer.from(`${token} ${"x".repeat(200)}`).toString("base64").replace(/(.{40})/g, "$1\n");
    assert.ok(withDecodedBase64(long).includes(token));
  });

  it("leaves ordinary text alone and never invents the token", () => {
    assert.equal(withDecodedBase64("hello"), "hello");
    assert.ok(!withDecodedBase64("Access denied: the path is outside the allowed directory and that is final").includes(token));
    assert.ok(!withDecodedBase64(Buffer.from("something else entirely, not a canary").toString("base64")).includes(token));
  });
});
