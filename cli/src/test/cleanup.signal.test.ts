import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { CLI, hermeticEnv } from "./helpers.js";

// A signal while the server is still starting must leave no sandbox directory and no server process behind. The sandbox is
// created under a scratch directory (--sandbox-dir), so a leftover is attributable to this test and nothing else.
// Signals cannot be delivered to a child on Windows the way they are on POSIX, so these tests are POSIX only.
const POSIX = process.platform !== "win32";
const SLOW = fileURLToPath(new URL("../toy/slowstart.js", import.meta.url));

let dir: string;
let n = 0;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-cleanup-signal-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};
const pidsIn = (file: string): number[] => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean).map(Number) : []);
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const reap = (file: string): void => {
  for (const p of pidsIn(file))
    try {
      process.kill(p, "SIGKILL");
    } catch {
      /* gone */
    }
};

interface Interrupted {
  code: number | null;
  signal: NodeJS.Signals | null;
  err: string;
  pids: number[];
  sandboxes: string[];
}

/** Starts a run against a toy that is slow to start, signals it once the server process exists, and reports what is left. */
async function interrupt(mode: string, signal: NodeJS.Signals, expectPids: number): Promise<Interrupted> {
  const id = n++;
  const pidFile = join(dir, `pids-${id}.txt`);
  const parent = join(dir, `sandboxes-${id}`);
  mkdirSync(parent);
  const cfg = join(dir, `slow-${id}.yaml`);
  writeFileSync(cfg, `name: slow\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([SLOW, "--mode", mode, "--delay-ms", "60000", "--pid-file", pidFile])}\n`);
  const child = spawn(process.execPath, [CLI, "run", "--config", cfg, "--pack", "core", "--sandbox-dir", parent, "--connect-timeout", "120", "--fail-under", "none"], { env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  child.stdout.resume();
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((res) => child.once("exit", (code, sig) => res({ code, signal: sig })));
  try {
    const until = Date.now() + 30_000;
    while (pidsIn(pidFile).length < expectPids || !/starting the server under test/.test(err)) {
      assert.ok(Date.now() < until, `the server never started: ${err}`);
      await sleep(50);
    }
    assert.equal(readdirSync(parent).filter((x) => x.startsWith("sealmark-")).length, 1, "the sandbox exists while the server is starting");
    child.kill(signal);
    const done = await Promise.race([exited, sleep(30_000).then(() => assert.fail(`the run did not stop after ${signal}: ${err}`))]);
    // Give the kernel a moment to reap what was SIGKILLed.
    const pids = pidsIn(pidFile);
    for (let i = 0; i < 60 && pids.some(alive); i++) await sleep(50);
    return { ...done, err, pids: pids.filter(alive), sandboxes: readdirSync(parent).filter((x) => x.startsWith("sealmark-")) };
  } finally {
    child.kill("SIGKILL");
    reap(pidFile);
  }
}

describe("cleanup: a signal while the server is still starting", { timeout: 180_000, skip: !POSIX }, () => {
  it("SIGINT leaves no sandbox directory and no server process, and exits 130", async () => {
    const r = await interrupt("slow", "SIGINT", 1);
    assert.equal(r.code, 130, r.err);
    assert.deepEqual(r.sandboxes, [], "the sandbox directory is removed");
    assert.deepEqual(r.pids, [], "the server process is gone");
    assert.match(r.err, /cleaning up/);
  });

  it("SIGINT also stops a launcher's children (the whole tree)", async () => {
    const r = await interrupt("wrapper", "SIGINT", 2);
    assert.equal(r.code, 130, r.err);
    assert.deepEqual(r.sandboxes, []);
    assert.deepEqual(r.pids, [], "neither the wrapper nor its child is left");
  });

  it("a server that ignores SIGTERM is still stopped", async () => {
    const r = await interrupt("stubborn", "SIGINT", 1);
    assert.equal(r.code, 130, r.err);
    assert.deepEqual(r.pids, []);
    assert.deepEqual(r.sandboxes, []);
  });

  it("SIGTERM says 'stopping', not 'interrupted' or Ctrl+C, cleans up the same way and exits 143", async () => {
    const r = await interrupt("slow", "SIGTERM", 1);
    assert.equal(r.code, 143, r.err);
    assert.match(r.err, /stopping: cleaning up/);
    assert.doesNotMatch(r.err, /interrupted|Ctrl\+C/);
    assert.deepEqual(r.sandboxes, []);
    assert.deepEqual(r.pids, []);
  });
});
