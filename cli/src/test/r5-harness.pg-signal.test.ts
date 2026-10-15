import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { leftoverDirs, listSegments, parseIpcs, pendingPids, readSegment, releaseSegment, startEmbedded, stopAll, type EmbeddedOptions, type Segment } from "../embedded.js";

// Round 5, G11: a signal at any point of the embedded start stops the postmaster politely, releases its SysV segment by the id the harness
// itself read from postmaster.pid, removes its directory, and names what it could not remove. The real-Postgres test is skipped without the
// optional dependency, and on POSIX without ipcs and ipcrm (the test must be able to clean up what it creates).

const POSIX = process.platform !== "win32";
type Ctor = NonNullable<EmbeddedOptions["create"]>;

const have = (cmd: string): boolean => spawnSync(cmd, ["-h"], { stdio: "ignore" }).error === undefined;
const hasPackage = (): boolean => {
  try {
    createRequire(import.meta.url).resolve("embedded-postgres");
    return true;
  } catch {
    return false;
  }
};
const SKIP_REAL = process.env.SEALMARK_SKIP_DB === "1" ? "SEALMARK_SKIP_DB=1" : !hasPackage() ? "the optional dependency embedded-postgres is not installed" : POSIX && !(have("ipcs") && have("ipcrm")) ? "ipcs or ipcrm is not on the PATH" : false;

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};
const until = async (ok: () => boolean | Promise<boolean>, ms: number, what: string): Promise<void> => {
  const t0 = Date.now();
  while (!(await ok())) {
    assert.ok(Date.now() - t0 < ms, `${what}: never held within ${ms} ms`);
    await new Promise((r) => setTimeout(r, 25));
  }
};
const segmentListed = async (seg: Segment): Promise<boolean> => {
  const rows = (await listSegments()) ?? [];
  return rows.some((r) => r.id === seg.id && r.key === Number(BigInt(seg.key) & 0xffffffffn));
};
const sleeper = (): ChildProcess => spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", windowsHide: true });

describe("r5-harness: the embedded Postgres and its shared-memory segment", { timeout: 900_000 }, () => {
  describe("with the real embedded Postgres", { skip: SKIP_REAL }, () => {
    it("a postmaster that was SIGKILLed leaves its segment; releasing it by the id postmaster.pid named removes it, and nothing else", async () => {
      let seg: Segment | undefined;
      let dir: string | undefined;
      const h = await startEmbedded(0, true, {});
      try {
        dir = leftoverDirs()[0];
        assert.ok(dir, "the registry knows the data directory");
        // The id is read BEFORE anything is killed: line 7 of postmaster.pid, which the package deletes when it stops the server.
        await until(() => (seg = readSegment(dir!)) !== undefined, 10_000, "line 7 of postmaster.pid");
        const pid = h.pid!()!;
        assert.ok(pid > 0);
        process.kill(pid, "SIGKILL");
        await until(() => !alive(pid), 10_000, "the postmaster is gone");
        // The workers notice the postmaster is gone and let go of the segment.
        await until(async () => POSIX === false || (await segmentListed(seg!)), 10_000, "the orphaned segment is listed");
        if (POSIX) {
          assert.equal(await segmentListed(seg!), true, "SIGKILL skipped Postgres's own release: the segment exists");
          assert.equal(await releaseSegment(seg!), true, "ipcrm ran");
          await until(async () => !(await segmentListed(seg!)), 10_000, "the segment is released");
          assert.equal(await releaseSegment(seg!), false, "a segment that is already gone is not an error and not removed twice");
        }
      } finally {
        // Whatever happened above, this test leaves nothing behind: the machine allows only 32 segments.
        if (POSIX && seg) {
          spawnSync("ipcrm", ["-m", String(seg.id)], { stdio: "ignore" });
        }
        await h.stop().catch(() => {});
        if (dir) rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      }
      assert.deepEqual(leftoverDirs(), []);
    });

    it("near-miss: a postmaster stopped politely releases its own segment, and stopAll() does it for a live server the run never got a handle for", async () => {
      const h = await startEmbedded(0, true, {});
      const dir = leftoverDirs()[0]!;
      let seg: Segment | undefined;
      try {
        await until(() => (seg = readSegment(dir)) !== undefined, 10_000, "line 7 of postmaster.pid");
        const pid = h.pid!()!;
        assert.ok(pendingPids().includes(pid), "the postmaster's pid is in the registry");
        const left = await stopAll({ deadlineMs: 20_000 });
        assert.deepEqual(left, [], "stopAll removed the directory");
        assert.equal(existsSync(dir), false);
        assert.equal(alive(pid), false, "the postmaster is gone");
        if (POSIX) assert.equal(await segmentListed(seg!), false, "a polite stop released the segment (nothing to remove)");
        await h.stop(); // idempotent
      } finally {
        if (POSIX && seg && (await segmentListed(seg))) spawnSync("ipcrm", ["-m", String(seg.id)], { stdio: "ignore" });
        if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("with a stand-in for the package", () => {
    class Fake {
      static made: { dir: string; child?: ChildProcess; stops: number; neverSettles: boolean }[] = [];
      process?: ChildProcess;
      rec: { dir: string; child?: ChildProcess; stops: number; neverSettles: boolean };
      constructor(o: Record<string, unknown>) {
        this.rec = { dir: o.databaseDir as string, stops: 0, neverSettles: false };
        Fake.made.push(this.rec);
      }
      async initialise(): Promise<void> {
        mkdirSync(this.rec.dir, { recursive: true });
        writeFileSync(join(this.rec.dir, "PG_VERSION"), "18\n");
      }
      async start(): Promise<void> {
        this.rec.child = this.process = sleeper();
      }
      stop(): Promise<void> {
        this.rec.stops++;
        return this.rec.neverSettles ? new Promise<void>(() => {}) : Promise.resolve();
      }
    }
    const reset = () => (Fake.made = []);

    it("a signal in the window between the server being ready and the handle being taken: stopAll stops it, the directory is gone, the start gives up", async () => {
      reset();
      let during: string[] = [];
      let pidDuring: number[] = [];
      await assert.rejects(
        startEmbedded(0, true, {
          attempts: 1,
          create: Fake as unknown as Ctor,
          afterStart: async () => {
            // The run's signal handler runs now: the registry already knows the start, whichever variable the run holds.
            during = leftoverDirs();
            pidDuring = pendingPids();
            assert.deepEqual(await stopAll({ deadlineMs: 20_000 }), []);
          },
        }),
        /the run was interrupted/,
      );
      assert.equal(during.length, 1, "the data directory was registered while the start was between ready and handed over");
      assert.equal(pidDuring.length, 1, "and so was the postmaster's pid");
      const rec = Fake.made[0]!;
      assert.equal(existsSync(rec.dir), false, "the data directory is removed");
      await until(() => !alive(rec.child!.pid!), 5_000, "the postmaster was stopped");
      assert.deepEqual(leftoverDirs(), []);
      assert.deepEqual(pendingPids(), []);
    });

    it("an interrupt that is only noticed after the server came up (the run's flag flipped, nobody called stopAll yet): the start stops its own server before it hands anything over", async () => {
      reset();
      let flag = false;
      await assert.rejects(startEmbedded(0, true, { attempts: 1, create: Fake as unknown as Ctor, cancelled: () => flag, afterStart: () => void (flag = true) }), /the run was interrupted/);
      const rec = Fake.made[0]!;
      assert.equal(existsSync(rec.dir), false);
      await until(() => !alive(rec.child!.pid!), 5_000, "the postmaster was stopped");
      assert.deepEqual(leftoverDirs(), []);
    });

    it("a live handle is in the registry until stop() has finished, and stopAll() stops it with the kill ladder when its own stop() does nothing", async () => {
      reset();
      const h = await startEmbedded(0, true, { attempts: 1, create: Fake as unknown as Ctor });
      const rec = Fake.made[0]!;
      assert.deepEqual(leftoverDirs(), [rec.dir]);
      assert.ok(pendingPids().includes(rec.child!.pid!));
      assert.deepEqual(await stopAll({ deadlineMs: 20_000 }), []);
      assert.equal(existsSync(rec.dir), false);
      await until(() => !alive(rec.child!.pid!), 5_000, "the ladder stopped the postmaster the fake stop() left running");
      await h.stop(); // already finished: idempotent, no second stop() on the package
      assert.equal(rec.stops, 1);
      assert.deepEqual(pendingPids(), []);
    });

    it("cleanup under interrupt finishes in under 12 s even when the package's stop() never settles", async () => {
      reset();
      class Stuck extends Fake {
        constructor(o: Record<string, unknown>) {
          super(o);
          this.rec.neverSettles = true;
        }
      }
      await startEmbedded(0, true, { attempts: 1, create: Stuck as unknown as Ctor });
      const rec = Fake.made[0]!;
      const t0 = Date.now();
      const left = await stopAll({ deadlineMs: 11_000 });
      const took = Date.now() - t0;
      assert.ok(took < 12_000, `stopAll took ${took} ms`);
      assert.ok(took >= 4_000, `stop() was given its 5 s before the ladder (took ${took} ms)`);
      assert.deepEqual(left, []);
      assert.equal(existsSync(rec.dir), false, "the directory is removed after the bounded wait");
      await until(() => !alive(rec.child!.pid!), 5_000, "the ladder stopped the postmaster");
    });

    it("a deadline that passes before the work is done returns, and names the directory that is still there", async () => {
      reset();
      class Slow extends Fake {
        async initialise(): Promise<void> {
          await super.initialise();
          await new Promise((r) => setTimeout(r, 1_500));
        }
        async start(): Promise<void> {
          await new Promise(() => {}); // never ready
        }
      }
      const p = startEmbedded(0, true, { attempts: 1, startTimeoutMs: 30_000, create: Slow as unknown as Ctor });
      p.catch(() => {});
      await until(() => leftoverDirs().length === 1, 5_000, "the directory was registered");
      const dir = leftoverDirs()[0]!;
      // A stuck start: stopAll abandons it (no postmaster yet), which removes the directory at once; the registry then has nothing left to name.
      assert.deepEqual(await stopAll({ deadlineMs: 5_000 }), []);
      assert.equal(existsSync(dir), false);
      await assert.rejects(p, /interrupted/);
    });
  });

  describe("the 15 s bail names what the cleanup leaves, on stderr, before the process exits", { skip: !POSIX }, () => {
    let tmp: string;
    before(() => {
      tmp = mkdtempSync(join(tmpdir(), "sealmark-r5-bail-"));
    });
    after(() => rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

    const script = (body: string): string => {
      const file = join(tmp, `bail-${Math.random().toString(36).slice(2)}.mjs`);
      const dist = (m: string) => JSON.stringify(pathToFileURL(join(import.meta.dirname, "..", m)).href);
      writeFileSync(file, `import { stopOnSignals } from ${dist("launch.js")};\nimport { startEmbedded } from ${dist("embedded.js")};\n${body}\n`);
      return file;
    };
    const runUntilBail = async (file: string): Promise<{ code: number | null; err: string }> => {
      const child = spawn(process.execPath, [file], { stdio: ["ignore", "pipe", "pipe"] });
      let err = "";
      child.stderr.on("data", (b: Buffer) => (err += b.toString()));
      child.stdout.setEncoding("utf8");
      let ready = false;
      child.stdout.on("data", (d: string) => (ready ||= d.includes("ready")));
      const exited = new Promise<number | null>((res) => child.once("exit", (code) => res(code)));
      await until(() => ready, 30_000, "the child is ready");
      child.kill("SIGINT");
      return { code: await exited, err };
    };

    it("a cleanup that never settles: the line names the registered data directory, then the exit code is the signal's", async () => {
      const file = script(`
class Stuck { constructor(o) { this.dir = o.databaseDir; globalThis.dirOfStart = o.databaseDir; } async initialise() { (await import("node:fs")).mkdirSync(this.dir, { recursive: true }); await new Promise(() => {}); } async start() {} async stop() {} }
startEmbedded(0, true, { attempts: 1, create: Stuck }).catch(() => {});
stopOnSignals(() => new Promise(() => {}), undefined, { bailMs: 600 });
setTimeout(() => process.stdout.write("ready " + globalThis.dirOfStart + "\\n"), 300);
setInterval(() => {}, 1000);
`);
      const r = await runUntilBail(file);
      assert.equal(r.code, 130, r.err);
      assert.match(r.err, /cleanup did not finish: \S*sealmark-pg-\S+ \(remove it by hand\)/, r.err);
      // The child could not clean up after itself: the test does.
      for (const m of r.err.matchAll(/(\S*sealmark-pg-[A-Za-z0-9]+)/g)) rmSync(m[1]!, { recursive: true, force: true });
    });

    it("a cleanup that never settles and leaves no known path still says so", async () => {
      const file = script(`
stopOnSignals(() => new Promise(() => {}), undefined, { bailMs: 400 });
process.stdout.write("ready\\n");
setInterval(() => {}, 1000);
`);
      const r = await runUntilBail(file);
      assert.equal(r.code, 130, r.err);
      assert.match(r.err, /cleanup did not finish within 0 s|cleanup did not finish within \d+ s: something may still be running/, r.err);
    });

    it("near-miss: a cleanup that finishes says nothing about leftovers", async () => {
      const file = script(`
stopOnSignals(async () => {}, undefined, { bailMs: 400 });
process.stdout.write("ready\\n");
setInterval(() => {}, 1000);
`);
      const r = await runUntilBail(file);
      assert.equal(r.code, 130, r.err);
      assert.ok(!/cleanup did not finish/.test(r.err), r.err);
    });
  });

  describe("parseIpcs reads both layouts", () => {
    it("macOS -a: id, key, owner, nattch, size and creator pid", () => {
      const text = `IPC status from <running system> as of Tue Oct 13 12:53:08 PDT 2026
T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP NATTCH  SEGSZ  CPID  LPID   ATIME    DTIME    CTIME
Shared Memory:
m 131072 0x510ed879 --rw------- alice    staff alice    staff      0    152   1386   1386  7:45:15  7:45:31  7:45:15
m 9 0x00000001 --rw------- bob    staff bob    staff      3    4096   77   77  7:45:15  7:45:31  7:45:15
`;
      assert.deepEqual(parseIpcs(text), [
        { id: 131072, key: 0x510ed879, owner: "alice", nattch: 0, size: 152, cpid: 1386 },
        { id: 9, key: 1, owner: "bob", nattch: 3, size: 4096, cpid: 77 },
      ]);
    });

    it("Linux: the default listing has no creator pid; -p has no key", () => {
      const plain = `
------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fe5e36e 32768      alice      600        56         0
0x00000000 32769      alice      600        4096       2          dest
`;
      const creators = `
------ Shared Memory Creator/Last-op PIDs --------
shmid      owner      cpid       lpid
32768      alice      4242       4242
`;
      assert.deepEqual(parseIpcs(plain), [
        { id: 32768, key: 0x2fe5e36e, owner: "alice", nattch: 0, size: 56 },
        { id: 32769, key: 0, owner: "alice", nattch: 2, size: 4096 },
      ]);
      assert.deepEqual(parseIpcs(creators), [{ id: 32768, owner: "alice", cpid: 4242 }]);
    });

    it("garbage and empty output give no rows", () => {
      assert.deepEqual(parseIpcs(""), []);
      assert.deepEqual(parseIpcs("ipcs: command not found\n"), []);
    });
  });

  it("releaseSegment never runs ipcrm for an id that ipcs does not list under that key", async () => {
    if (!POSIX || !have("ipcs")) return;
    // An id nobody holds (and a key nobody holds): nothing is listed, so nothing is removed.
    assert.equal(await releaseSegment({ key: 0x7fffff01, id: 2_147_483_000 }), false);
    // execFileSync here would throw if ipcrm had been run for a missing id and the helper reported it; it must stay a quiet false.
    assert.doesNotThrow(() => execFileSync(process.execPath, ["-e", "0"]));
  });
});
