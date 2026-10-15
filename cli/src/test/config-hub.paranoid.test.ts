import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import type { RunResult } from "../types.js";
import { cliKit } from "./helpers.js";

// A profile, file or environment that lists the exec pack does not get it without --active, and that is not an error.
// Only `--pack exec` typed on the command line without --active is a usage error.

const FS_TOY = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-chparanoid-"));
  mkdirSync(dir, { recursive: true });
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, readJson } = cliKit(() => dir);
const START = ["--start", `${JSON.stringify(process.execPath)} ${JSON.stringify(FS_TOY)} --mode good --root {sandbox}`, "--fail-under", "none", "--timeout-probe", "2"];

describe("exec without --active", () => {
  it("--profile paranoid runs everything else, leaves exec out and prints the warning that names --active", () => {
    const out = join(dir, "paranoid.json");
    const r = sealmark(["run", ...START, "--profile", "paranoid", "--format", "json", "--out", out]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /the exec pack is listed \(profile:paranoid\) but runs only with --active; it was left out of this run \(add --active to run it\)/);
    const rep = readJson<RunResult>(out);
    assert.equal(rep.packs.exec, undefined);
    assert.ok(!rep.options?.packsRequested.includes("exec"), "the report does not claim exec was requested");
    assert.ok(!(rep.config?.locked.packs as string[]).includes("exec"), "nor does config.locked");
    assert.ok(!rep.checks.some((c) => c.pack === "exec"));
    assert.ok(rep.checks.some((c) => c.pack === "fs"));
  });

  it("SEALMARK_PACKS from the environment is treated the same way", () => {
    const r = sealmark(["run", ...START, "--format", "summary"], dir, { SEALMARK_PACKS: "core,exec" });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /the exec pack is listed \(env SEALMARK_PACKS\) but runs only with --active; it was left out/);
  });

  it("--pack exec on the command line without --active is still a usage error (exit 2)", () => {
    const r = sealmark(["run", ...START, "--pack", "core", "--pack", "exec"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /needs --active on the command line/);
  });
});
