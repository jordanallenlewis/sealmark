import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { REGISTRY, describeAll } from "../packs/index.js";
import { classifyTools } from "../classify.js";
import { describe as describeFs, pack as fsPack, pathKind, pathTools, sizeVerdict } from "../packs/fs.js";
import { createSandbox } from "../sandbox.js";
import type { RunResult, ToolClassification, Verdict } from "../types.js";
import { gradeOf, verdicts } from "./helpers.js";
import { directCtx, fsConfig, insideDir, readTrace, runPacks, stringArgs } from "./packctx.js";

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};
const traces: Record<string, string> = {};

const MODES = ["good", "prefix", "nolink", "traverse", "logger", "nocap", "deaf", "withdelete"] as const;

const FS_IDS = ["fs-read-escape", "fs-write-escape", "fs-link-escape", "fs-size-cap"] as const;

/** the design notes: the acceptance table for toy/fs.ts. */
const TABLE: Record<string, { v: [Verdict, Verdict, Verdict, Verdict]; letter?: string; pct?: number; capped?: boolean }> = {
  good: { v: ["pass", "pass", "pass", "pass"], letter: "A", pct: 100 },
  prefix: { v: ["fail", "fail", "pass", "pass"], letter: "D", pct: 50 },
  nolink: { v: ["pass", "pass", "fail", "pass"], letter: "D", pct: 75, capped: true },
  traverse: { v: ["fail", "fail", "fail", "pass"], letter: "F", pct: 25 },
  logger: { v: ["pass", "pass", "pass", "pass"], letter: "A", pct: 100 },
  nocap: { v: ["pass", "pass", "pass", "fail"], letter: "B", pct: 75 },
  withdelete: { v: ["pass", "pass", "pass", "pass"], letter: "A", pct: 100 },
};

const leftovers = () => readdirSync(parent).filter((n) => n.startsWith("sealmark-"));

describe("fs pack against the toy file server", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(
      MODES.map(async (m) => {
        traces[m] = join(dir, `trace-${m}.jsonl`);
        results[m] = await runPacks(fsConfig(m, { trace: traces[m] }), ["fs", "effects"], where());
      }),
    );
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  for (const [mode, row] of Object.entries(TABLE)) {
    it(`${mode}: verdicts and grade match the design table`, () => {
      const r = results[mode];
      const v = verdicts(r, "fs");
      assert.deepEqual(
        FS_IDS.map((id) => v[id]),
        row.v,
        JSON.stringify(r.checks.filter((c) => c.pack === "fs").map((c) => [c.id, c.verdict, c.summary])),
      );
      const g = gradeOf(r, "fs");
      assert.ok(g, "the pack is graded");
      assert.equal(g.letter, row.letter);
      assert.equal(g.pct, row.pct);
      if (row.capped !== undefined) assert.equal(g.capped, row.capped);
    });
  }

  it("a critical fail caps the grade: nolink is B raw and D after the cap; traverse fails all three critical checks", () => {
    const g = gradeOf(results.nolink, "fs")!;
    assert.equal(g.raw, "B");
    assert.deepEqual(g.criticalFails, ["fs-link-escape"]);
    assert.deepEqual(gradeOf(results.traverse, "fs")!.criticalFails, ["fs-read-escape", "fs-write-escape", "fs-link-escape"]);
    assert.deepEqual(gradeOf(results.prefix, "fs")!.criticalFails, ["fs-read-escape", "fs-write-escape"]);
  });

  it("failures name what escaped, with evidence the harness observed", () => {
    const read = results.prefix.checks.find((c) => c.id === "fs-read-escape")!;
    assert.match(read.summary, /evil-/);
    assert.ok(read.evidence.some((e) => e.code === "fs.read-escape" && e.verifiedBy === "response" && /canary string/.test(e.outcome)));
    const write = results.prefix.checks.find((c) => c.id === "fs-write-escape")!;
    assert.ok(write.evidence.some((e) => e.code === "fs.write-escape" && e.verifiedBy === "fs-observer"));
    const link = results.nolink.checks.find((c) => c.id === "fs-link-escape")!;
    assert.ok(link.evidence.some((e) => e.code === "fs.link-escape" && /link-dir/.test(e.probe)));
    const cap = results.nocap.checks.find((c) => c.id === "fs-size-cap")!;
    assert.match(cap.summary, /dropped|whole|exceeded the harness.s 64 MiB message limit \(the server sent no cap\)/);
  });

  it("the junction probe really runs and a write through it is a link escape, not a write escape", () => {
    // nolink writes through link-dir leave the root; the design lists that probe under fs-link-escape only.
    const trace = readTrace(traces.nolink);
    assert.ok(trace.some((t) => t.tool === "write_file" && stringArgs(t.args).some((p) => /link-dir/.test(p) && /lw-/.test(p))), "link write sent");
    assert.ok(trace.some((t) => t.tool === "read_file" && stringArgs(t.args).some((p) => /link-dir/.test(p))), "junction read sent");
    assert.ok(!trace.some((t) => t.tool === "write_file" && stringArgs(t.args).some((p) => /link-dir/.test(p) && /w-[0-9a-f]/.test(p) && !/lw-/.test(p))), "no write-escape probe goes through the link");
    const write = results.nolink.checks.find((c) => c.id === "fs-write-escape")!;
    assert.equal(write.verdict, "pass");
  });

  it("the file symlink is probed when it could be created and reported otherwise", async () => {
    const trace = readTrace(traces.good);
    const probe = await createSandbox({ dir: parent });
    const fileOk = probe.links.file.ok;
    const dirKind = probe.links.dir.kind;
    await probe.destroy();
    assert.ok(dirKind === "junction" || dirKind === "symlink", "a directory link can be created on this machine");
    const sent = trace.some((t) => stringArgs(t.args).some((p) => /[\\/]link\.txt$/.test(p)));
    assert.equal(sent, fileOk);
    const link = results.good.checks.find((c) => c.id === "fs-link-escape")!;
    assert.equal(link.evidence.some((e) => e.code === "fs.link.symlink-na"), !fileOk);
  });

  it("every path the harness sent is inside the sandbox directory (acceptance 9)", () => {
    for (const m of MODES) {
      const sandboxDir = results[m].sandbox?.dir;
      assert.ok(sandboxDir, `${m}: sandbox dir recorded`);
      const calls = readTrace(traces[m]);
      assert.ok(calls.length > 10, `${m}: probes were sent`);
      for (const t of calls) {
        for (const p of stringArgs(t.args).filter((s) => /[\\/]|^file:/.test(s) && s.length > 2)) {
          assert.ok(insideDir(sandboxDir, p), `${m}: ${t.tool} was sent ${p}`);
        }
      }
    }
  });

  it("deaf: a server whose every call fails makes every check inconclusive, never a pass", () => {
    const r = results.deaf;
    assert.deepEqual(
      FS_IDS.map((id) => verdicts(r, "fs")[id]),
      ["inconclusive", "inconclusive", "inconclusive", "inconclusive"],
    );
    assert.equal(r.packs.fs?.status, "inconclusive");
    assert.equal(gradeOf(r, "fs"), undefined);
    const read = r.checks.find((c) => c.id === "fs-read-escape")!;
    assert.ok(read.coverage?.notCovered.some((n) => /control call/.test(n.reason)));
  });

  it("a delete tool is never called and is listed as not covered", () => {
    const trace = readTrace(traces.withdelete);
    assert.equal(trace.filter((t) => t.tool === "delete_file").length, 0);
    const read = results.withdelete.checks.find((c) => c.id === "fs-read-escape")!;
    assert.ok(read.coverage?.notCovered.some((n) => n.tool === "delete_file" && /delete tool is never called/.test(n.reason)));
    assert.equal(results.withdelete.packs.fs?.status, "graded");
  });

  it("coverage is filled: probed tools and the number of valid calls", () => {
    const read = results.good.checks.find((c) => c.id === "fs-read-escape")!;
    assert.deepEqual([...read.coverage!.probed].sort(), ["list_dir", "read_file", "stat"]);
    assert.ok(read.coverage!.validCalls! >= 20, "Windows-only probes are skipped elsewhere, so the count is lower on Linux and macOS");
    assert.ok(results.good.coverage!.validCalls >= 25);
    assert.ok(["covered", "low"].includes(results.good.coverage!.level));
  });

  it("scope text starts with 'server' and every check id is documented", () => {
    for (const c of results.good.checks.filter((x) => x.pack === "fs")) assert.match(c.scope, /^server/);
    const ids = describeFs().map((d) => d.id);
    for (const id of FS_IDS) assert.ok(ids.includes(id));
    assert.equal(new Set(ids).size, ids.length);
    const all = describeAll().map((d) => d.id);
    assert.equal(new Set(all).size, all.length, "check ids are unique across packs");
    assert.ok(REGISTRY.some((p) => p.id === "fs" && p.describe().length === 4));
  });

  it("the sandboxes are gone afterwards", () => {
    assert.deepEqual(leftovers(), []);
    for (const m of MODES) assert.equal(existsSync(results[m].sandbox!.dir!), false);
  });
});

describe("fs pack: configuration and degraded environments", { timeout: 240_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-test2-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("is not applicable when the server config has no {sandbox}: a wider root would read the canary legitimately", async () => {
    const root = join(dir, "own-root");
    mkdirSync(root);
    const r = await runPacks(fsConfig("good", { root }), ["fs"], where());
    assert.equal(r.packs.fs?.status, "na");
    assert.match(r.packs.fs?.reason ?? "", /\{sandbox\}/);
    assert.equal(r.checks.filter((c) => c.pack === "fs").length, 0);
  });

  it("is not applicable under --no-sandbox", async () => {
    const r = await runPacks(fsConfig("good"), ["fs"], where(), { sandbox: { enabled: false } });
    assert.equal(r.packs.fs?.status, "na");
    assert.match(r.packs.fs?.reason ?? "", /no-sandbox|sandbox is off/);
  });

  it("a file symlink that cannot be created degrades to a stated reason; the junction still decides", async () => {
    const reason = "needs Developer Mode or an elevated shell to create symbolic links";
    const d = await directCtx(fsConfig("nolink"), "fs", where(), {
      tweak: (sb) => ({ ...sb, links: { dir: sb.links.dir, file: { ok: false, kind: "na" as const, reason, path: sb.files.linkFile } } }),
    });
    try {
      const out = await fsPack.run(d.ctx);
      const link = out.find((c) => c.id === "fs-link-escape")!;
      assert.equal(link.verdict, "fail", "the junction alone proves the escape");
      const na = link.evidence.find((e) => e.code === "fs.link.symlink-na");
      assert.ok(na && na.outcome.includes(reason));
      assert.match(link.summary, /file symlink was not created/);
    } finally {
      await d.close();
    }
    const g = await directCtx(fsConfig("good"), "fs", where(), {
      tweak: (sb) => ({ ...sb, links: { dir: sb.links.dir, file: { ok: false, kind: "na" as const, reason, path: sb.files.linkFile } } }),
    });
    try {
      const link = (await fsPack.run(g.ctx)).find((c) => c.id === "fs-link-escape")!;
      assert.equal(link.verdict, "pass");
      assert.match(link.summary, /only the (junction|symbolic link to directory) was tested/);
    } finally {
      await g.close();
    }
  });

  it("with no link at all the link check is not applicable and says why", async () => {
    const reason = "links are not supported here";
    const d = await directCtx(fsConfig("good"), "fs", where(), {
      tweak: (sb) => ({ ...sb, links: { dir: { ok: false, kind: "na" as const, reason, path: sb.files.linkDir }, file: { ok: false, kind: "na" as const, reason, path: sb.files.linkFile } } }),
    });
    try {
      const link = (await fsPack.run(d.ctx)).find((c) => c.id === "fs-link-escape")!;
      assert.equal(link.verdict, "na");
      assert.match(link.summary, /links are not supported here/);
    } finally {
      await d.close();
    }
  });

  it("checks.<id>.enabled and severity from the configuration are honoured", async () => {
    const checks = { "fs-read-escape": { enabled: false, severity: null }, "fs-write-escape": { enabled: true, severity: "advisory" as const }, "fs-link-escape": { enabled: true, severity: "scored" as const } };
    const d = await directCtx(fsConfig("good"), "fs", where(), { over: { checks } });
    try {
      const out = await fsPack.run(d.ctx);
      const by = Object.fromEntries(out.map((c) => [c.id, c]));
      assert.equal(by["fs-read-escape"].verdict, "na");
      assert.match(by["fs-read-escape"].summary, /disabled by config/);
      assert.equal(by["fs-write-escape"].advisory, true);
      assert.equal(by["fs-write-escape"].critical, false);
      assert.equal(by["fs-link-escape"].critical, false);
      assert.equal(by["fs-link-escape"].advisory, undefined);
      assert.equal(by["fs-size-cap"].critical, false);
    } finally {
      await d.close();
    }
  });

  it("corpus.remove drops probes by id and corpus.add appends sandbox-relative targets; a target outside the sandbox is never sent", async () => {
    const trace = join(dir, "trace-corpus.jsonl");
    const remove = ["dotdot", "dot-slash", "evil-dotdot", "evil-absolute"];
    const add = ["{sandbox}/../root-evil/secret.txt", "{sandbox}/../../../outside-the-sandbox.txt"];
    const d = await directCtx(fsConfig("traverse", { trace }), "fs", where(), { over: { checks: { "fs-read-escape": { enabled: true, severity: null, corpus: { add, remove } } } } });
    try {
      const read = (await fsPack.run(d.ctx)).find((c) => c.id === "fs-read-escape")!;
      // The remaining built-in probes are refused by this toy, the added root-evil path is not.
      assert.equal(read.verdict, "fail");
      assert.ok(read.evidence.some((e) => /custom-1/.test(e.probe) && /root-evil/.test(e.probe) && e.code === "fs.read-escape"));
      assert.ok(read.evidence.some((e) => e.code === "fs.skipped" && /outside the sandbox/.test(e.outcome)), "the outside target was refused by the harness");
      const sent = readTrace(trace).flatMap((t) => stringArgs(t.args));
      assert.ok(!sent.some((p) => /outside-the-sandbox/.test(p)));
      // The removed forms were not sent to the read tools (the write corpus is configured by fs-write-escape, which this test leaves alone).
      const toReaders = readTrace(trace).filter((t) => t.tool !== "write_file").flatMap((t) => stringArgs(t.args));
      assert.ok(!toReaders.some((p) => /\.[\\/]\.\.[\\/]canary/.test(p)), "dot-slash removed");
      assert.ok(sent.some((p) => /%2e%2e/.test(p)), "other built-in probes still run");
    } finally {
      await d.close();
    }
  });

  it("a read of a large file is judged by the configured thresholds", async () => {
    const d = await directCtx(fsConfig("nocap"), "fs", where(), { over: { checks: { "fs-size-cap": { enabled: true, severity: null, file_mib: 20, pass_mib: 4 } } } });
    try {
      const cap = (await fsPack.run(d.ctx)).find((c) => c.id === "fs-size-cap")!;
      assert.equal(cap.verdict, "fail");
      assert.match(cap.summary, /whole 20 MiB file/);
    } finally {
      await d.close();
    }
    const g = await directCtx(fsConfig("good"), "fs", where(), { over: { checks: { "fs-size-cap": { enabled: true, severity: null, file_mib: 20, pass_mib: 4 } } } });
    try {
      assert.equal((await fsPack.run(g.ctx)).find((c) => c.id === "fs-size-cap")!.verdict, "pass");
    } finally {
      await g.close();
    }
  });
});

describe("fs pack: pure rules", () => {
  it("sizeVerdict: within the limit passes, between is a part, the whole file or a drop fails, a refusal passes", () => {
    const o = { dropped: false, refused: false, passMib: 16, fileMib: 64 };
    const MiB = 1024 * 1024;
    assert.equal(sizeVerdict({ ...o, bytes: 1000 }).verdict, "pass");
    assert.equal(sizeVerdict({ ...o, bytes: 16 * MiB }).verdict, "pass");
    assert.equal(sizeVerdict({ ...o, bytes: 16 * MiB + 1 }).verdict, "part");
    assert.equal(sizeVerdict({ ...o, bytes: 63 * MiB }).verdict, "part");
    assert.equal(sizeVerdict({ ...o, bytes: 64 * MiB }).verdict, "fail");
    assert.equal(sizeVerdict({ ...o, bytes: 0, dropped: true }).verdict, "fail");
    assert.equal(sizeVerdict({ ...o, bytes: 80, refused: true }).verdict, "pass");
  });

  it("pathKind tells readers from writers, and never mistakes a delete tool for a reader", () => {
    const mk = (name: string, props: Record<string, string>, desc = ""): [{ name: string; description: string; inputSchema: { type: string; properties: Record<string, { type: string }> } }, ToolClassification] => [
      { name, description: desc, inputSchema: { type: "object", properties: Object.fromEntries(Object.keys(props).map((k) => [k, { type: "string" }])) } },
      { tool: name, class: "path", confidence: "high", params: props as ToolClassification["params"], unfillable: [], reasons: [] },
    ];
    const kind = (name: string, props: Record<string, string>, desc?: string) => pathKind(...mk(name, props, desc));
    assert.equal(kind("read_text_file", { path: "path" }), "read");
    assert.equal(kind("read_multiple_files", { paths: "paths" }), "read");
    assert.equal(kind("list_directory", { path: "path" }), "list");
    assert.equal(kind("directory_tree", { path: "path" }), "list");
    assert.equal(kind("search_files", { path: "path" }), "list");
    assert.equal(kind("get_file_info", { path: "path" }), "stat");
    assert.equal(kind("write_file", { path: "path", content: "content" }), "write");
    assert.equal(kind("create_directory", { path: "path" }), "mkdir");
    assert.equal(kind("move_file", { path: "source", dest: "destination" }), "copy");
    assert.equal(kind("delete_file", { path: "path" }), "delete");
    assert.equal(kind("remove_directory", { path: "path" }), "delete");
    assert.equal(kind("frobnicate", { path: "path" }), "other");
    assert.equal(kind("frobnicate", { path: "path" }, "Read the contents of a file."), "read");
  });

  it("a typical file server's tool list: readers, writers, listers and edit tools are probed; path-less tools are not", () => {
    const str = { type: "string" };
    const tool = (name: string, props: Record<string, unknown>, required: string[], annotations?: Record<string, boolean>) => ({ name, description: "", inputSchema: { type: "object", properties: props, required }, ...(annotations ? { annotations } : {}) });
    const tools = [
      tool("read_text_file", { path: str, head: { type: "number" } }, ["path"], { readOnlyHint: true }),
      tool("read_multiple_files", { paths: { type: "array", items: str } }, ["paths"], { readOnlyHint: true }),
      tool("write_file", { path: str, content: str }, ["path", "content"]),
      tool("edit_file", { path: str, edits: { type: "array", items: { type: "object", properties: { oldText: str, newText: str } } } }, ["path", "edits"]),
      tool("create_directory", { path: str }, ["path"]),
      tool("list_directory", { path: str }, ["path"], { readOnlyHint: true }),
      tool("directory_tree", { path: str }, ["path"], { readOnlyHint: true }),
      tool("move_file", { source: str, destination: str }, ["source", "destination"]),
      tool("search_files", { path: str, pattern: str }, ["path", "pattern"], { readOnlyHint: true }),
      tool("get_file_info", { path: str }, ["path"], { readOnlyHint: true }),
      tool("list_allowed_directories", {}, []),
      tool("delete_file", { path: str }, ["path"]),
    ];
    const classification = classifyTools({ tools: tools as never }).classification;
    const picked = pathTools({ classification, tools, active: false, sandboxEnabled: true } as never);
    const kinds = Object.fromEntries(picked.map((p) => [p.tool.name, p.kind]));
    assert.deepEqual(kinds, {
      read_text_file: "read",
      read_multiple_files: "read",
      write_file: "write",
      edit_file: "edit",
      create_directory: "mkdir",
      list_directory: "list",
      directory_tree: "list",
      move_file: "copy",
      search_files: "list",
      get_file_info: "stat",
      delete_file: "delete",
    });
    // Since round 5 the classifier fills a one-level array of objects ({oldText, newText}), so the edit tool is probed, as an edit.
    assert.ok(!("list_allowed_directories" in kinds));
  });

  it("the published corpus never names a target outside the sandbox", () => {
    // Every target in the published corpus starts from a sandbox placeholder or is relative to the server's root.
    const ok = /^(\{[A-Za-z_]+\}|\\\\\?\\\{|file:\/\/\/\{|\.\.|\.\/)/;
    for (const d of describeFs()) {
      for (const p of d.probes.filter((x) => ["traversal", "absolute", "encoding", "prefix", "windows"].includes(x.kind ?? ""))) {
        assert.match(p.text, ok, `${d.id}/${p.id}`);
      }
    }
  });
});

