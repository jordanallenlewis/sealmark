import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { ToolInfo } from "../mcp.js";
import { Tally, editArgsFor, pack as fsPack, pathKind, sizeVerdict, validationReject } from "../packs/fs.js";
import { createSandbox } from "../sandbox.js";
import type { PackCtx, RunResult, SealmarkConfig, ToolClassification } from "../types.js";
import { directCtx, runPacks } from "./packctx.js";

// Round 5, package fs: honest applicability (inconclusive, not n/a), coverage that counts what exercised a tool, the rootless root,
// the verbs, the dangling link, and the harness's own files being put back after probes that change them.

const R5 = fileURLToPath(new URL("../toy/fs-r5.js", import.meta.url));
const CTLFAIL = fileURLToPath(new URL("../toy/fs-ctlfail.js", import.meta.url));

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};

const r5 = (mode: string, extra: string[] = [], root = true): SealmarkConfig => ({ name: `toy-fs-r5-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [R5, "--mode", mode, ...(root ? ["--root", "{sandbox}"] : []), ...extra], env: {} } });
const ctlfail = (extra: string[] = []): SealmarkConfig => ({ name: "toy-fs-ctlfail", version: "0.0.1", server: { command: process.execPath, args: [CTLFAIL, "--root", "{sandbox}", ...extra], env: {} } });
const check = (name: string, id: string) => results[name].checks.find((c) => c.id === id)!;

const tool = (name: string, description = "", props: Record<string, unknown> = { path: { type: "string" } }, required = Object.keys(props)): ToolInfo => ({ name, description, inputSchema: { type: "object", properties: props, required } }) as unknown as ToolInfo;
const cls = (t: ToolInfo, o: Partial<ToolClassification> = {}): ToolClassification => ({ tool: t.name, class: "path", confidence: "high", params: { path: "path" }, unfillable: [], reasons: [], ...o });
const kindOf = (t: ToolInfo, o: Partial<ToolClassification> = {}) => pathKind(t, cls(t, o));

describe("fs pack, round 5: what a tool is", () => {
  it("edit, patch, modify, str_replace, replace_in and apply_diff name an edit tool; a whole-content replacement stays a write", () => {
    const strs = { path: { type: "string" }, old_str: { type: "string" }, new_str: { type: "string" } };
    for (const n of ["edit_file", "patch_file", "modify_file", "str_replace", "replace_in_file", "apply_diff"]) assert.equal(kindOf(tool(n, "", strs)), "edit", n);
    // An "edit" tool whose arguments are a path and the new content is a write (it has nothing to find).
    assert.equal(kindOf(tool("edit_file", "", { path: { type: "string" }, content: { type: "string" } }), { params: { path: "path", content: "content" } }), "write");
  });
  it("export and dump write, import and load read", () => {
    assert.equal(kindOf(tool("export_report"), { params: { path: "path", content: "content" } }), "write");
    assert.equal(kindOf(tool("dump_table"), { params: { path: "path", content: "content" } }), "write");
    assert.equal(kindOf(tool("import_data")), "read");
    assert.equal(kindOf(tool("load_config")), "read");
  });
  it("a state setter is never a reader, whatever its description says", () => {
    const d = "Set the default directory (used by read_file, list_dir and search_files).";
    for (const n of ["set_default_directory", "configure_root", "set_cwd", "chdir"]) assert.equal(kindOf(tool(n, d)), "other", n);
  });
  it("the verb comes from the name first; parenthesised text in the description is not the tool's job", () => {
    assert.equal(kindOf(tool("remember_path", "Keeps a path in the session (does not read, delete or list anything)"), { annotations: { readOnlyHint: false } }), "other");
    assert.equal(kindOf(tool("inspect", "Return the contents of a file (like cat).")), "read");
    // A name with a verb wins over a description with another.
    assert.equal(kindOf(tool("list_things", "Reads files and deletes nothing.")), "list");
  });
  it("the edit filler builds the common shapes from the tool's own schema and refuses what it cannot build", () => {
    const f = (props: Record<string, unknown>) => editArgsFor(tool("e", "", props), { path: "p" }, "OLD", "NEW");
    assert.deepEqual(f({ path: { type: "string" }, old_str: { type: "string" }, new_str: { type: "string" } }), { path: "p", old_str: "OLD", new_str: "NEW" });
    assert.deepEqual(f({ path: { type: "string" }, search: { type: "string" }, replace: { type: "string" } }), { path: "p", search: "OLD", replace: "NEW" });
    assert.deepEqual(f({ path: { type: "string" }, oldText: { type: "string" }, newText: { type: "string" } }), { path: "p", oldText: "OLD", newText: "NEW" });
    assert.deepEqual(
      f({ path: { type: "string" }, edits: { type: "array", items: { type: "object", properties: { oldText: { type: "string" }, newText: { type: "string" }, mode: { type: "string", enum: ["exact", "regex"] } }, required: ["oldText", "newText", "mode"] } } }),
      { path: "p", edits: [{ mode: "exact", oldText: "OLD", newText: "NEW" }] },
    );
    assert.equal(f({ path: { type: "string" }, diff: { type: "string" } }), undefined);
  });
});

describe("fs pack, round 5: coverage counts what exercised a tool", () => {
  it("Tally.note(tool, false) counts nothing; the default counts, so the git pack keeps compiling", () => {
    const t = new Tally();
    t.note("a");
    t.note("b", false);
    t.note("c", true);
    assert.deepEqual(t.coverage().probed, ["a", "c"]);
    assert.equal(t.coverage().validCalls, 2);
  });
  it("a malformed-request reply is not a valid call; a refusal of the path is", () => {
    const r = (text: string, o: { isError?: boolean; rpcError?: string } = {}) => ({ isError: o.isError ?? true, text, ...(o.rpcError ? { rpcError: o.rpcError } : {}) });
    assert.equal(validationReject(r("", { rpcError: "MCP error -32602: Invalid arguments for tool read_file" })), true);
    assert.equal(validationReject(r("Invalid argument: path is required")), true);
    assert.equal(validationReject(r("Error: expected a string for parameter 'paths'")), true);
    assert.equal(validationReject(r("Access denied: ../canary/secret.txt is outside the allowed directory")), false);
    assert.equal(validationReject(r("Invalid path: outside the allowed root")), false);
    assert.equal(validationReject(r("path required must be a string", { isError: false })), false);
  });
  describe("a tool whose control failed, next to a tool whose control worked", () => {
    before(async () => {
      dir = mkdtempSync(join(tmpdir(), "sealmark-fs-r5h-"));
      parent = join(dir, "sandboxes");
      mkdirSync(parent);
      results.broken = await runPacks(ctlfail(), ["fs"], where());
      results.listonly = await runPacks(ctlfail(["--no-read"]), ["fs"], where());
      results.regexfail = await runPacks(r5("search-regexfail"), ["fs"], where());
      results.nodep = await runPacks(r5("search-nodep"), ["fs"], where());
    });
    after(() => rmSync(dir, { recursive: true, force: true }));

    it("it is in notCovered and not in probed, and its failed controls are not valid calls", () => {
      const c = check("broken", "fs-read-escape").coverage!;
      assert.ok(!c.probed.includes("read_file"), JSON.stringify(c));
      assert.ok(c.probed.includes("list_dir"), JSON.stringify(c));
      assert.ok(c.notCovered.some((n) => n.tool === "read_file"), JSON.stringify(c.notCovered));
      // The same listing tool alone makes the same number of valid calls: the failed read_file calls added none.
      assert.equal(c.validCalls, check("listonly", "fs-read-escape").coverage!.validCalls);
      assert.ok(c.validCalls! > 0);
    });
    it("a search-only server whose control failed: fs-size-cap is inconclusive, never n/a", () => {
      for (const n of ["regexfail", "nodep"]) {
        const c = check(n, "fs-size-cap");
        assert.equal(c.verdict, "inconclusive", `${n}: ${c.summary}`);
        assert.doesNotMatch(c.summary, /no tool returns file contents/);
        assert.equal(check(n, "fs-read-escape").verdict, "inconclusive", `${n}: ${check(n, "fs-read-escape").summary}`);
      }
    });
    it("a server with no content reader keeps fs-size-cap n/a", () => {
      assert.equal(check("listonly", "fs-size-cap").verdict, "na");
    });
    it("the reason says what went wrong: the pattern was rejected as a regex, or a dependency of the server is missing", () => {
      assert.ok((check("regexfail", "fs-read-escape").coverage!.notCovered).some((n) => /the control pattern was rejected as a regex/.test(n.reason)), JSON.stringify(check("regexfail", "fs-read-escape").coverage));
      assert.match(check("nodep", "fs-read-escape").summary, /a dependency of the server is missing/);
      assert.match(check("nodep", "fs-size-cap").summary, /a dependency of the server is missing/);
    });
    it("the inconclusive summary quotes the control's error", () => {
      assert.match(check("regexfail", "fs-read-escape").summary, /regex parse error/);
    });
  });
});

describe("fs pack, round 5: a reader that exists but could not be called", () => {
  let d: Awaited<ReturnType<typeof directCtx>>;
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-r5u-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    d = await directCtx(r5("safe"), "fs", where());
  });
  after(async () => {
    await d.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("the only reader is unfillable: inconclusive, naming the parameter, not n/a", async () => {
    // The classifier's own answer for a reader with an array-of-object parameter: opaque, the path class kept as secondary.
    const files = { type: "array", items: { type: "object", properties: { path: { type: "string" } } } };
    const tools = d.ctx.tools.map((t) => (t.name === "read_file" ? ({ ...t, inputSchema: { type: "object", properties: { files }, required: ["files"] } } as ToolInfo) : t));
    const classification = d.ctx.classification.map((c) => (c.tool === "read_file" ? { ...c, class: "opaque" as const, confidence: "low" as const, params: {}, unfillable: ["files"], secondary: ["path" as const] } : c.tool === "list_dir" ? { ...c, class: "opaque" as const, confidence: "low" as const, params: {} } : c));
    const ctx: PackCtx = { ...d.ctx, tools, classification };
    const out = await fsPack.run(ctx);
    const read = out.find((c) => c.id === "fs-read-escape")!;
    assert.equal(read.verdict, "inconclusive", read.summary);
    assert.match(read.summary, /read_file \(files\[\]\)/);
    assert.ok((read.coverage?.notCovered ?? []).some((n) => n.tool === "read_file" && /files\[\]/.test(n.reason)), JSON.stringify(read.coverage));
    assert.equal(out.find((c) => c.id === "fs-size-cap")!.verdict, "inconclusive");
  });
});

describe("fs pack, round 5: a rootless server", () => {
  let d: Awaited<ReturnType<typeof directCtx>>;
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-r5r-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    d = await directCtx(r5("rootless", [], false), "fs", where());
  });
  after(async () => {
    await d.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("without server.rootless the pack is n/a and the reason prints the hint", async () => {
    const a = await fsPack.applies(d.ctx);
    assert.equal(a.ok, false);
    assert.match(a.reason ?? "", /server\.rootless: true/);
  });

  it("with server.rootless the working directory is the allowed root, every probe runs, and a server that reads and writes anywhere fails", async () => {
    const ctx: PackCtx = { ...d.ctx, config: { ...d.ctx.config, server: { ...d.ctx.config.server, rootless: true } as PackCtx["config"]["server"] } };
    assert.deepEqual(await fsPack.applies(ctx), { ok: true });
    const out = await fsPack.run(ctx);
    const by = Object.fromEntries(out.map((c) => [c.id, c]));
    assert.equal(by["fs-read-escape"].verdict, "fail", by["fs-read-escape"].summary);
    assert.equal(by["fs-write-escape"].verdict, "fail", by["fs-write-escape"].summary);
    assert.ok(by["fs-read-escape"].evidence.some((e) => e.code === "fs.rootless" && /server\.rootless/.test(e.outcome)));
  });
});

describe("fs pack, round 5: the sandbox and the harness's own files", () => {
  it("a fresh sandbox holds a dangling link in the root that points into the canary directory, to a file that is not there", async () => {
    const base = mkdtempSync(join(tmpdir(), "sealmark-fs-r5s-"));
    const sb = await createSandbox({ dir: base });
    try {
      if (!sb.links.file.ok) return;
      assert.equal(lstatSync(sb.files.linkDangling).isSymbolicLink(), true);
      assert.equal(existsSync(sb.files.linkDangling), false, "the target does not exist");
      assert.equal(sb.links.dangling?.ok, true);
      const target = readlinkSync(sb.files.linkDangling);
      assert.ok(target.startsWith(sb.canary) && /dangling-/.test(target), target);
      assert.ok(!readdirSync(sb.canary).some((n) => n.startsWith("dangling-")));
    } finally {
      const r = await sb.destroy();
      assert.equal(r.cleanedUp, true);
      assert.equal(existsSync(sb.files.linkDangling), false);
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("after the link and write probes, the secrets, ok.txt and both file links are back, and no dangling target was left behind", async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-r5l-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    try {
      for (const mode of ["movelink", "linkfile", "dangling", "editonly"]) {
        const d = await directCtx(r5(mode), "fs", where());
        try {
          if (!d.sandbox.links.file.ok) continue;
          const out = await fsPack.run(d.ctx);
          assert.ok(out.some((c) => c.verdict === "fail"), `${mode}: the toy is meant to fail something`);
          const sb = d.sandbox;
          assert.equal(readFileSync(sb.files.canary, "utf8"), sb.tokens.canary, `${mode}: canary secret`);
          assert.equal(readFileSync(sb.files.evil, "utf8"), sb.tokens.evil, `${mode}: sibling secret`);
          assert.equal(readFileSync(sb.files.ok, "utf8"), sb.tokens.control, `${mode}: ok.txt`);
          assert.equal(lstatSync(sb.files.linkFile).isSymbolicLink(), true, `${mode}: link.txt is still a link`);
          assert.equal(lstatSync(sb.files.linkDangling).isSymbolicLink(), true, `${mode}: link-dangling.txt is still a link`);
          assert.equal(existsSync(sb.files.linkDangling), false, `${mode}: and still dangling`);
          assert.ok(!readdirSync(sb.canary).some((n) => n.startsWith("dangling-")), `${mode}: no dangling target left in the canary directory`);
        } finally {
          await d.close();
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("fs pack, round 5: size-cap wording", () => {
  const base = { bytes: 0, dropped: true, refused: false, passMib: 16, fileMib: 64 };
  it("says what the harness saw, and keeps the old wording when it saw nothing more", () => {
    assert.match(sizeVerdict({ ...base, cause: "limit" }).why, /exceeded the harness's 64 MiB message limit \(the server sent no cap\)/);
    assert.equal(sizeVerdict({ ...base, cause: "exited" }).why, "the server exited");
    assert.doesNotMatch(sizeVerdict({ ...base, cause: "timeout" }).why, /too large for the transport/);
    assert.match(sizeVerdict(base).why, /the connection dropped or the call timed out/);
    assert.equal(sizeVerdict({ ...base, cause: "limit" }).verdict, "fail");
  });
});
