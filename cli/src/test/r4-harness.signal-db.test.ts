import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CLI, hermeticEnv } from "./helpers.js";

// A signal during a run that starts an embedded Postgres (a config with {dsn}) must leave nothing behind: no sandbox, no data
// directory (`sealmark-pg-*`), no password file (`pg-password-*`), no Postgres process, and no server started after the signal.
// TMPDIR is a scratch directory of the test, so a leftover is attributable to it. POSIX only (signals and TMPDIR); skipped like
// db.test.ts when the embedded Postgres is switched off.
const POSIX = process.platform !== "win32";
const TOY = fileURLToPath(new URL("../toy/dsn-required.js", import.meta.url));
const SKIP = process.env.SEALMARK_SKIP_DB === "1" ? "SEALMARK_SKIP_DB=1" : !POSIX ? "POSIX only" : false;

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r4-signal-db-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};
const lines = (file: string): string[] => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean) : []);

interface Outcome {
  code: number | null;
  err: string;
  tmp: string[];
  sandboxes: string[];
  starts: number;
  livePids: number[];
  postgres: string[];
}

let n = 0;
/** Runs the CLI on a {dsn} config under an isolated TMPDIR; `signalWhen` decides the moment, `extraArgs` go to the toy. */
async function interrupted(signalWhen: (err: string, starts: number) => boolean | void, extraArgs: string[] = []): Promise<Outcome> {
  const id = n++;
  const scratch = join(dir, `run-${id}`);
  const tmp = join(scratch, "tmp");
  const parent = join(scratch, "sandboxes");
  mkdirSync(tmp, { recursive: true });
  mkdirSync(parent);
  const pidFile = join(scratch, "pids.txt"); // outside the sandbox: it survives the sandbox's deletion
  const cfg = join(scratch, "cfg.yaml");
  writeFileSync(cfg, `name: dsn-signal\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([TOY, "--dsn", "{dsn}", "--pid-file", pidFile, ...extraArgs])}\n`);
  const child = spawn(process.execPath, [CLI, "run", "--config", cfg, "--pack", "core", "--pack", "db", "--sandbox-dir", parent, "--timeout-probe", "2", "--fail-under", "none"], {
    env: hermeticEnv({ TMPDIR: tmp }),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let err = "";
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  child.stdout.resume();
  const exited = new Promise<{ code: number | null }>((res) => child.once("exit", (code) => res({ code })));
  try {
    await waitThenSignal(child, () => err, () => lines(pidFile).length, signalWhen);
    const finished = await exited;
    for (let i = 0; i < 40 && lines(pidFile).some((p) => alive(Number(p))); i++) await sleep(50);
    await sleep(300); // a late spawn would show up here
    const ps = spawnSync("ps", ["-axo", "pid=,command="], { encoding: "utf8" }).stdout.split("\n");
    return {
      code: finished.code,
      err,
      tmp: readdirSync(tmp).filter((x) => x.startsWith("sealmark-pg-") || x.startsWith("pg-password-")),
      sandboxes: readdirSync(parent).filter((x) => x.startsWith("sealmark-")),
      starts: lines(pidFile).length,
      livePids: lines(pidFile).map(Number).filter(alive),
      postgres: ps.filter((l) => l.includes(tmp)),
    };
  } finally {
    child.kill("SIGKILL");
    for (const p of lines(pidFile)) {
      try {
        process.kill(Number(p), "SIGKILL");
      } catch {
        /* gone */
      }
    }
  }
}

/** Polls until `when` says now (then sends SIGINT) or the child has exited on its own (a signal the toy sent). */
async function waitThenSignal(child: ReturnType<typeof spawn>, err: () => string, starts: () => number, when: (err: string, starts: number) => boolean | void): Promise<void> {
  const until = Date.now() + 90_000;
  for (;;) {
    assert.ok(Date.now() < until, `the moment never came: ${err()}`);
    if (child.exitCode !== null || child.signalCode !== null) return;
    if (when(err(), starts()) === true) break;
    await sleep(20);
  }
  child.kill("SIGINT");
}

describe("r4-harness: a signal during a run with an embedded Postgres", { timeout: 300_000, skip: SKIP }, () => {
  it("SIGINT sent by the server itself on its second start (the first db role): nothing is started again, nothing is left", async () => {
    // The toy interrupts the CLI 100 ms after it answers the handshake of its second start: the discovery session was the first.
    // The db pack would go on to start a server for the next role; after a signal it must not.
    const r = await interrupted(() => false, ["--signal-parent-on-start", "2"]);
    assert.equal(r.code, 130, r.err);
    assert.equal(r.starts, 2, `no server was started after the signal (starts: ${r.starts})\n${r.err}`);
    assert.deepEqual(r.livePids, [], "no server process is left");
    assert.deepEqual(r.tmp, [], "no sealmark-pg-* data directory and no pg-password-* file");
    assert.deepEqual(r.sandboxes, [], "the sandbox is gone");
    assert.deepEqual(r.postgres, [], "no Postgres process is left");
    assert.match(r.err, /interrupted: cleaning up/);
    assert.match(r.err, /cleaned up/);
  });

  it("SIGINT 100 ms after the embedded Postgres starts to be created: no data directory, no password file, no server", async () => {
    let at: number | undefined;
    const r = await interrupted((err) => {
      if (/starting an embedded Postgres/.test(err)) at ??= Date.now();
      return at !== undefined && Date.now() - at >= 100;
    });
    assert.equal(r.code, 130, r.err);
    assert.equal(r.starts, 0, "no server was started: the database never came up");
    assert.deepEqual(r.tmp, [], "no sealmark-pg-* data directory and no pg-password-* file");
    assert.deepEqual(r.sandboxes, []);
    assert.deepEqual(r.postgres, [], "no Postgres process is left");
    assert.match(r.err, /cleaned up/);
  });

  it("SIGINT as soon as the db pack announces itself: the same, with a started database to shut down", async () => {
    const r = await interrupted((err) => /\bdb pack\b/.test(err));
    assert.equal(r.code, 130, r.err);
    assert.deepEqual(r.livePids, []);
    assert.deepEqual(r.tmp, []);
    assert.deepEqual(r.sandboxes, []);
    assert.deepEqual(r.postgres, []);
    assert.match(r.err, /cleaned up/);
  });
});
