import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadSqlite } from "../sqlite-fixtures.js";
import { CLI, hermeticEnv } from "./helpers.js";

// A signal while the sqlite pack is working must not leave `sealmark-<id>/root` behind: the pack's own clean-up (it restores its
// fixture in a finally block) used to run after the harness had deleted the sandbox, and recreated the directory.
// POSIX only (signals); needs node:sqlite.
const POSIX = process.platform !== "win32";
const TOY = fileURLToPath(new URL("../toy/sqlite.js", import.meta.url));

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r4-signal-sqlite-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("r4-harness: a signal during the sqlite pack", { timeout: 120_000, skip: !POSIX || !loadSqlite() }, () => {
  it("SIGINT leaves no sandbox directory (not even an empty root) and exits 130", async () => {
    const parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const cfg = join(dir, "sqlite.yaml");
    // The filter toy has no row cap and no timeout, so the pack spends seconds waiting on it: a wide window for the signal.
    writeFileSync(cfg, `name: sqlite-signal\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--mode", "filter", "--db", "{sqlite_path}"])}\n`);
    const child = spawn(process.execPath, [CLI, "run", "--config", cfg, "--pack", "sqlite", "--sandbox-dir", parent, "--timeout-probe", "2", "--fail-under", "none"], { env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    child.stdout.resume();
    const exited = new Promise<{ code: number | null }>((res) => child.once("exit", (code) => res({ code })));
    try {
      const until = Date.now() + 60_000;
      while (!/sqlite pack/.test(err)) {
        assert.ok(Date.now() < until, `the sqlite pack never started: ${err}`);
        await sleep(50);
      }
      await sleep(3000);
      assert.ok(child.exitCode === null, `the run was still going 3 s into the pack: ${err}`);
      child.kill("SIGINT");
      const done = await Promise.race([exited, sleep(30_000).then(() => assert.fail(`the run did not stop after SIGINT: ${err}`))]);
      assert.equal(done.code, 130, err);
      // The pack's clean-up may still be running when the process exits; give anything it recreates a moment to appear.
      await sleep(500);
      assert.deepEqual(readdirSync(parent).filter((x) => x.startsWith("sealmark-")), [], "no sandbox directory, not even an empty root");
      assert.match(err, /interrupted: cleaning up/);
      assert.match(err, /cleaned up/, "the stderr says the clean-up finished");
      assert.ok(!existsSync(join(parent, "root")));
    } finally {
      child.kill("SIGKILL");
    }
  });
});
