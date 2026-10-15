import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { pack as fsPack } from "../packs/fs.js";
import type { CheckResult, RunResult, SealmarkConfig } from "../types.js";
import { directCtx, fsConfig, runPacks } from "./packctx.js";

// The link check: a pass carries evidence and a control (a link that stays inside the root works), and "nothing to test"
// is not applicable while "a control that was tried and failed" is inconclusive.

let dir: string;
let parent: string;
const where = () => ({ dir, parent });
const results: Record<string, RunResult> = {};

const reldeny = (args: string[]): SealmarkConfig => ({
  name: "toy-fs-reldeny",
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-reldeny.js", import.meta.url)), ...args, "--root", "{sandbox}"], env: {} },
});
const movesrc: SealmarkConfig = {
  name: "toy-fs-movesrc",
  version: "0.0.1",
  server: { command: process.execPath, args: [fileURLToPath(new URL("../toy/fs-movesrc.js", import.meta.url)), "--check", "both", "--root", "{sandbox}"], env: {} },
};

const CASES: Record<string, SealmarkConfig> = {
  good: fsConfig("good"),
  follow: reldeny([]),
  refuse: reldeny(["--links", "refuse"]),
  enoent: reldeny(["--links", "enoent"]),
  deaf: fsConfig("deaf"),
  copyonly: movesrc,
};

const link = (name: string): CheckResult => results[name].checks.find((c) => c.id === "fs-link-escape")!;

describe("fs pack: the link check", { timeout: 240_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-fs-link-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    await Promise.all(Object.entries(CASES).map(async ([name, config]) => void (results[name] = await runPacks(config, ["fs"], where()))));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a pass carries one evidence line per link probe, with what the server said, and a control through a link that stays inside the root", () => {
    for (const name of ["good", "follow"]) {
      const c = link(name);
      assert.equal(c.verdict, "pass", `${name}: ${c.summary}`);
      const probes = c.evidence.filter((e) => e.code === "fs.link-refused");
      assert.ok(probes.length >= 3, `${name}: ${probes.length} probe lines`);
      for (const e of probes) {
        assert.ok(e.outcome.length > 20 && /refused/.test(e.outcome), `${name}: ${e.probe}: ${e.outcome}`);
        assert.ok(e.excerpt, `${name}: ${e.probe} shows the server's refusal text`);
      }
      const controls = c.evidence.filter((e) => e.code === "fs.link.control").map((e) => e.tool);
      assert.ok(controls.includes("read_file") && controls.includes("write_file"), `${name}: controls for ${controls.join(", ")}`);
      assert.ok(!c.evidence.some((e) => e.code === "fs.link.control-failed"));
    }
  });

  it("the link made for the control is gone afterwards", async () => {
    const d = await directCtx(fsConfig("good"), "fs", where());
    try {
      const link = (await fsPack.run(d.ctx)).find((c) => c.id === "fs-link-escape")!;
      assert.equal(link.verdict, "pass");
      assert.ok(!readdirSync(d.sandbox.root).some((n) => /^link-(in|ok)$/.test(n)), readdirSync(d.sandbox.root).join(","));
    } finally {
      await d.close();
    }
  });

  it("a server that refuses every link, inside the root or out, still passes and says so", () => {
    const c = link("refuse");
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /also refused a link that stays inside the root/);
    assert.ok(c.evidence.some((e) => e.code === "fs.link.control-failed"));
    assert.ok(c.evidence.filter((e) => e.code === "fs.link-refused").every((e) => /symbolic links are not followed/.test(e.excerpt ?? "")));
  });

  it("answers that look like an unrelated error (no such file) do not pass: a control that was tried and failed is inconclusive", () => {
    const c = link("enoent");
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /unrelated error/);
  });

  it("a server whose every call fails is inconclusive", () => {
    assert.equal(link("deaf").verdict, "inconclusive");
  });

  it("a path tool that neither reads nor writes files is not applicable, not inconclusive", async () => {
    const d = await directCtx(fsConfig("withdelete"), "fs", where());
    try {
      const keep = (n: string) => n === "delete_file";
      const ctx = { ...d.ctx, tools: d.ctx.tools.filter((t) => keep(t.name)), classification: d.ctx.classification.filter((c) => keep(c.tool)) };
      const out = await fsPack.run(ctx);
      const c = out.find((x) => x.id === "fs-link-escape")!;
      assert.equal(c.verdict, "na", c.summary);
      assert.match(c.summary, /no tool reads or writes files/);
      assert.equal(out.find((x) => x.id === "fs-read-escape")!.verdict, "na");
      assert.equal(out.find((x) => x.id === "fs-write-escape")!.verdict, "na");
    } finally {
      await d.close();
    }
  });

  it("a server with only a move tool is sent through the links (round 5): its destination and its source link are probed and refused", () => {
    const c = link("copyonly");
    assert.equal(c.verdict, "pass", c.summary);
    assert.ok(c.coverage?.probed.includes("move_file"), JSON.stringify(c.coverage));
    assert.ok(c.evidence.some((e) => e.code === "fs.link-refused" && /link-dir\/moved-/.test(e.probe)), "the destination through the directory link was sent");
    assert.ok(c.evidence.some((e) => e.code === "fs.link-refused" && /link\.txt \(symbolic link/.test(e.probe)), "the source link was sent");
  });
});
