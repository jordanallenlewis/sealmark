// Round 4, package sql: items D3 (the rig never recreates the sandbox root after an interrupt), D4 (node:sqlite is loaded only when the
// pack can run, so no ExperimentalWarning on a run that has no {sqlite_path}) and D5 (the timeout wording).
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describeAll } from "../packs/index.js";
import { Rig, pack } from "../packs/sqlite.js";
import { sqliteUnavailable } from "../sqlite-fixtures.js";
import type { PackCtx, Sandbox } from "../types.js";
import { CLI } from "./helpers.js";

const SQLITE_PACK = pathToFileURL(fileURLToPath(new URL("../packs/sqlite.js", import.meta.url))).href;

describe("sqlite rig: restore() is a no-op once the sandbox is gone (D3)", () => {
  let tmp: string;
  let pristine: string;
  before(() => {
    tmp = mkdtempSync(join(tmpdir(), "sealmark-r4-rig-"));
    pristine = join(tmp, "pristine.sqlite");
    writeFileSync(pristine, "pristine");
  });
  after(() => rmSync(tmp, { recursive: true, force: true }));

  const rigFor = (sandboxDir: string, interrupted?: () => boolean) => {
    const sb = { dir: sandboxDir } as Sandbox;
    const ctx = { interrupted } as unknown as PackCtx;
    return new Rig(ctx, sb, join(sandboxDir, "root", "fixture.sqlite"), pristine);
  };

  it("puts the pristine fixture back while the sandbox exists (the control)", async () => {
    const dir = join(tmp, "alive");
    mkdirSync(dir);
    const rig = rigFor(dir);
    await rig.restore();
    assert.ok(existsSync(join(dir, "root", "fixture.sqlite")));
  });

  it("does nothing, and creates nothing, once the sandbox directory has been removed", async () => {
    const dir = join(tmp, "removed");
    const rig = rigFor(dir);
    assert.equal(rig.gone, true);
    await rig.restore();
    assert.equal(existsSync(dir), false, "the sandbox root was not recreated");
  });

  it("does nothing while the harness says the run was interrupted, even though the directory is still there", async () => {
    const dir = join(tmp, "interrupted");
    mkdirSync(dir);
    const rig = rigFor(dir, () => true);
    await rig.restore();
    assert.equal(existsSync(join(dir, "root")), false);
  });

  it("does not start a server again after an interrupt", async () => {
    const dir = join(tmp, "interrupted-fresh");
    mkdirSync(dir);
    const rig = rigFor(dir, () => true);
    await assert.rejects(() => rig.fresh({ name: "q" } as never), /the run was interrupted/);
  });
});

describe("sqlite pack: node:sqlite is loaded only when the pack can run (D4)", () => {
  const tool = { name: "query", inputSchema: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } };
  const ctxFor = (args: string[]) => ({
    config: { server: { command: "node", args, env: {} }, checks: {} },
    tools: [tool],
    classification: [{ tool: "query", class: "sql", confidence: "high", params: { sql: "sql" }, unfillable: [], reasons: [] }],
    sandbox: {},
    sandboxEnabled: true,
  });
  /** `applies()` in a fresh process, and the stderr that process wrote. */
  const applies = (args: string[]) => {
    const script = `const { pack } = await import(process.argv[1]); console.log(JSON.stringify(pack.applies(JSON.parse(process.argv[2]))));`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", script, SQLITE_PACK, JSON.stringify(ctxFor(args))], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return { result: JSON.parse(r.stdout.trim()) as { ok: boolean; reason?: string }, stderr: r.stderr };
  };
  // The warning is Node's own; a Node that does not print one on loading node:sqlite makes the test below vacuous, so it is skipped there.
  const probe = spawnSync(process.execPath, ["-e", "process.getBuiltinModule('node:sqlite')"], { encoding: "utf8" });
  const warns = /ExperimentalWarning: SQLite/.test(probe.stderr);

  it("a config with no {sqlite_path} is turned away before node:sqlite is touched: no ExperimentalWarning", { skip: warns ? false : "this Node prints no ExperimentalWarning for node:sqlite" }, () => {
    const { result, stderr } = applies(["server.js", "--db", "literal.sqlite"]);
    assert.equal(result.ok, false);
    assert.match(result.reason ?? "", /no \{sqlite_path\} placeholder/);
    assert.doesNotMatch(stderr, /ExperimentalWarning/);
  });

  it("sealmark run on a SQL server whose config has no {sqlite_path} prints no ExperimentalWarning", { skip: warns ? false : "this Node prints no ExperimentalWarning for node:sqlite" }, () => {
    const toy = fileURLToPath(new URL("../toy/sqlite.js", import.meta.url));
    const r = spawnSync(process.execPath, ["--no-warnings=false", CLI, "run", "--start", `${process.execPath} ${toy} --mode ro --db literal.sqlite`, "--no-embedded", "--format", "summary"], { encoding: "utf8", timeout: 120_000 });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.doesNotMatch(r.stderr, /ExperimentalWarning/);
  });

  it("a config with {sqlite_path} does load it (the control: the warning is what the reordering avoids)", { skip: warns ? false : "this Node prints no ExperimentalWarning for node:sqlite" }, () => {
    const { result, stderr } = applies(["server.js", "--db", "{sqlite_path}"]);
    assert.deepEqual(result, { ok: true });
    assert.match(stderr, /ExperimentalWarning: SQLite/);
  });

  it("the reason names --no-experimental-sqlite when that option is what switched the module off", { skip: process.versions.node.split(".").map(Number)[0] < 22 ? "needs Node 22" : false }, () => {
    const r = spawnSync(
      process.execPath,
      ["--no-experimental-sqlite", "--input-type=module", "-e", `const { sqliteUnavailable } = await import(process.argv[1]); console.log(sqliteUnavailable() ?? "available");`, pathToFileURL(fileURLToPath(new URL("../sqlite-fixtures.js", import.meta.url))).href],
      { encoding: "utf8" },
    );
    // A Node that does not know the flag exits non-zero; one that has no switch-off leaves the module available. Both are fine.
    if (r.status !== 0 || r.stdout.trim() === "available") return;
    assert.match(r.stdout, /--no-experimental-sqlite/);
  });

  it("the unavailable reason, when there is one, is still the plain version message on a normal Node", () => {
    const why = sqliteUnavailable();
    if (why) assert.match(why, /node:sqlite/);
    assert.equal(typeof pack.applies, "function");
  });
});

describe("sqlite-timeout wording (D5)", () => {
  it("explain documents the expected_sec + 8 s window and the flag that moves it", () => {
    const doc = describeAll().find((d) => d.id === "sqlite-timeout");
    assert.ok(doc);
    assert.match(doc.falseNegative, /expected_sec \+ 8 seconds/);
    assert.match(doc.falseNegative, /--timeout-probe/);
  });
});
