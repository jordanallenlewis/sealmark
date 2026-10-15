import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { START_TIMEOUT_MS, abandonPending, killPostmaster, leftoverDirs, startEmbedded, type EmbeddedOptions } from "../embedded.js";

// embedded-postgres' start() settles only on the "ready" log line or when every stdio pipe of the postmaster closes. A
// postmaster that dies during start-up and leaves workers behind never settles it, which used to hang `npm test` forever.
// These tests stand in for the package with a class whose start() never settles.

type Ctor = NonNullable<EmbeddedOptions["create"]>;

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const waitDead = async (child: ChildProcess, ms = 5000): Promise<boolean> => {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (child.exitCode !== null || child.signalCode !== null || !alive(child.pid!)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
};

function fake(behaviour: { child?: () => ChildProcess; start: "never" | "resolve" | "reject" }): { Ctor: Ctor; made: { child?: ChildProcess; stops: number }[] } {
  const made: { child?: ChildProcess; stops: number }[] = [];
  class Fake {
    process?: ChildProcess;
    rec: { child?: ChildProcess; stops: number } = { stops: 0 };
    constructor(_o: Record<string, unknown>) {
      made.push(this.rec);
    }
    async initialise(): Promise<void> {}
    start(): Promise<void> {
      // The real start() creates its child after a few awaits.
      return new Promise<void>((resolve, reject) => {
        setTimeout(() => {
          if (behaviour.child) this.rec.child = this.process = behaviour.child();
          if (behaviour.start === "resolve") resolve();
          else if (behaviour.start === "reject") reject(new Error("port in use"));
        }, 20);
      });
    }
    async stop(): Promise<void> {
      this.rec.stops++;
    }
  }
  return { Ctor: Fake as unknown as Ctor, made };
}

const sleeper = () => spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", windowsHide: true });

describe("embedded Postgres start-up is bounded", { timeout: 60_000 }, () => {
  it("the default deadline is a minute", () => {
    assert.equal(START_TIMEOUT_MS, 60_000);
  });

  it("a server that never reports ready is rejected at the deadline, killed, and cleaned up", async () => {
    const f = fake({ child: sleeper, start: "never" });
    const t0 = Date.now();
    await assert.rejects(startEmbedded(0, true, { startTimeoutMs: 700, attempts: 1, create: f.Ctor }), /failed to start on port \d+: the server did not report ready within 1 s/);
    const took = Date.now() - t0;
    assert.ok(took < 15_000, `rejected in ${took} ms`);
    assert.ok(f.made[0]!.child, "the stand-in child was started");
    assert.equal(await waitDead(f.made[0]!.child!), true, "the stand-in postmaster was killed");
  });

  it("a postmaster that exits during start-up rejects at once, even though start() never settles", async () => {
    const f = fake({ child: () => spawn(process.execPath, ["-e", "setTimeout(() => process.exit(3), 300)"], { stdio: "ignore", windowsHide: true }), start: "never" });
    const t0 = Date.now();
    await assert.rejects(startEmbedded(0, true, { startTimeoutMs: 30_000, attempts: 1, create: f.Ctor }), /the server exited during startup \(code 3/);
    assert.ok(Date.now() - t0 < 10_000, "well before the 30 s deadline");
  });

  it("a failed attempt is retried on a fresh port, and a server that comes up is returned and can be stopped", async () => {
    let n = 0;
    const seen: number[] = [];
    class Flaky {
      stops = 0;
      constructor(o: Record<string, unknown>) {
        seen.push(o.port as number);
        n++;
        this.fail = n === 1;
      }
      fail: boolean;
      async initialise(): Promise<void> {}
      async start(): Promise<void> {
        if (this.fail) throw new Error("address already in use");
      }
      async stop(): Promise<void> {
        this.stops++;
      }
    }
    const h = await startEmbedded(48_001, true, { startTimeoutMs: 5000, attempts: 3, create: Flaky as unknown as Ctor });
    assert.equal(n, 2);
    assert.equal(seen[0], 48_001);
    assert.notEqual(seen[1], 48_001, "the retry picked another port");
    assert.equal(h.target.host, "127.0.0.1");
    assert.equal(h.target.port, seen[1]);
    await h.stop();
  });

  it("every attempt failing gives one error naming the last cause", async () => {
    const f = fake({ start: "reject" });
    await assert.rejects(startEmbedded(0, true, { startTimeoutMs: 2000, attempts: 2, create: f.Ctor }), /failed to start on port \d+: port in use/);
    assert.equal(f.made.length, 2);
  });

  it("killPostmaster ignores nonsense pids and kills a process tree it was given", async () => {
    await killPostmaster(undefined);
    await killPostmaster(0);
    await killPostmaster(-5);
    const child = sleeper();
    assert.ok(alive(child.pid!));
    await killPostmaster(child.pid);
    assert.equal(await waitDead(child), true);
  });
});

// A signal while the server is still being created finds no handle to stop. The start registers its data directory (and the
// package writes `pg-password-<id>`, holding the password, into the temp directory) the moment it exists; abandonPending() removes both.
describe("a start that has not returned can be abandoned (round 4, E2)", { timeout: 60_000 }, () => {
  const until = async (ok: () => boolean, ms = 5000): Promise<void> => {
    const t0 = Date.now();
    while (!ok()) {
      assert.ok(Date.now() - t0 < ms, "the condition never held");
      await new Promise((r) => setTimeout(r, 20));
    }
  };

  it("removes the data directory and the password file of a start that is still initialising, leaves another run's file alone, and the start gives up", async () => {
    let dir = "";
    let password = "";
    let release: () => void = () => {};
    const files: string[] = [];
    const other = join(tmpdir(), `pg-password-sm-other-${process.pid}-${Date.now()}`);
    let started = false;
    class Slow {
      constructor(o: Record<string, unknown>) {
        dir = o.databaseDir as string;
        password = o.password as string;
      }
      async initialise(): Promise<void> {
        const mine = join(tmpdir(), `pg-password-sm-test-${process.pid}-${Date.now()}`);
        files.push(mine);
        writeFileSync(mine, `${password}\n`);
        writeFileSync(other, "somebody-else's-password\n");
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, "PG_VERSION"), "18\n");
        await new Promise<void>((r) => (release = r));
      }
      async start(): Promise<void> {
        started = true;
      }
      async stop(): Promise<void> {}
    }
    try {
      const p = startEmbedded(0, true, { attempts: 1, create: Slow as unknown as Ctor });
      p.catch(() => {});
      await until(() => files.length > 0 && existsSync(other));
      assert.ok(existsSync(dir) && existsSync(files[0]!), "the directory and the password file exist while it initialises");
      const left = await abandonPending();
      assert.deepEqual(left, [], "nothing is left behind");
      assert.equal(existsSync(dir), false, "the data directory is gone");
      assert.equal(existsSync(files[0]!), false, "the password file is gone");
      assert.equal(existsSync(other), true, "a file that holds another password is not ours to remove");
      release();
      await assert.rejects(p, /the run was interrupted, so the embedded Postgres was not started/);
      assert.equal(started, false, "the server is not started on top of a directory that was removed");
      assert.equal(existsSync(dir), false);
    } finally {
      for (const f of [...files, other]) rmSync(f, { force: true });
    }
  });

  it("kills a postmaster that has started but not reported ready, and removes its directory", async () => {
    const f = fake({ child: sleeper, start: "never" });
    const p = startEmbedded(0, true, { attempts: 1, startTimeoutMs: 30_000, create: f.Ctor });
    p.catch(() => {});
    await until(() => f.made[0]?.child !== undefined);
    const child = f.made[0]!.child!;
    assert.equal(alive(child.pid!), true);
    assert.deepEqual(await abandonPending(), []);
    assert.equal(await waitDead(child), true, "the postmaster is gone");
    await assert.rejects(p, /failed to start/);
  });

  it("nothing pending is a no-op, and `cancelled` stops a start before it creates anything", async () => {
    assert.deepEqual(await abandonPending(), []);
    let built = 0;
    class Never {
      constructor() {
        built++;
      }
      async initialise(): Promise<void> {}
      async start(): Promise<void> {}
      async stop(): Promise<void> {}
    }
    await assert.rejects(startEmbedded(0, true, { attempts: 3, cancelled: () => true, create: Never as unknown as Ctor }), /the run was interrupted/);
    assert.equal(built, 0, "no attempt was made");
  });

  it("near-miss: a start that finished is live, not pending, so abandonPending leaves a running server alone (round 5: it stays registered until stop() has finished)", async () => {
    class Fine {
      async initialise(): Promise<void> {}
      async start(): Promise<void> {}
      async stop(): Promise<void> {}
    }
    const h = await startEmbedded(0, true, { attempts: 1, create: Fine as unknown as Ctor });
    assert.deepEqual(await abandonPending(), [], "nothing pending");
    assert.equal(leftoverDirs().length, 1, "the live server is still registered, so a signal can find it");
    await h.stop();
    assert.deepEqual(leftoverDirs(), [], "stop() removed the entry and the directory");
  });
});
