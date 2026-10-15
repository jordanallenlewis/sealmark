import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { McpSession, SessionError } from "../mcp.js";
import type { ServerSpec } from "../types.js";
import { cliKit } from "./helpers.js";

// A server that never answers `initialize` must not outlive the failed start: not the process, not a launcher's children,
// and not a process that ignores SIGTERM. The toys write their own pids to a file, so "gone" is checked by pid, not by
// name. POSIX and Windows both: the kill is explicit and awaited, not left to the SDK's timers.
const SLOW = fileURLToPath(new URL("../toy/slowstart.js", import.meta.url));

let dir: string;
let n = 0;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-cleanup-connect-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml } = cliKit(() => dir);

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};
const pidsIn = (file: string): number[] => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean).map(Number) : []);
/** Waits until no pid in the file is alive (a reaped zombie takes a moment) and returns the ones that still are. */
async function stillRunning(file: string, withinMs = 3000): Promise<number[]> {
  const until = Date.now() + withinMs;
  for (;;) {
    const up = pidsIn(file).filter(alive);
    if (up.length === 0 || Date.now() > until) return up;
    await new Promise((r) => setTimeout(r, 50));
  }
}
/** Last-resort cleanup so a failing assertion does not leave the toy running. */
const reap = (file: string): void => {
  for (const p of pidsIn(file))
    try {
      process.kill(p, "SIGKILL");
    } catch {
      /* gone */
    }
};
const spec = (mode: string, pidFile: string, extra: string[] = []): ServerSpec => ({ command: process.execPath, args: [SLOW, "--mode", mode, "--pid-file", pidFile, ...extra] });
const ctx = { vars: {}, dsns: {} };
const newPidFile = (): string => join(dir, `pids-${n++}.txt`);

describe("cleanup: a server that never answers initialize is gone after the connect timeout", { timeout: 120_000 }, () => {
  for (const mode of ["never", "stubborn", "wrapper"]) {
    it(`mode ${mode}: open() rejects and every process the toy started is gone`, async () => {
      const pidFile = newPidFile();
      try {
        await assert.rejects(McpSession.open(spec(mode, pidFile), ctx, { connectTimeoutMs: 1500, cleanCwd: true }), (e: unknown) => e instanceof SessionError);
        assert.ok(pidsIn(pidFile).length >= (mode === "wrapper" ? 2 : 1), "the toy started and wrote its pid");
        assert.deepEqual(await stillRunning(pidFile, 500), [], "nothing left running right after open() rejected");
      } finally {
        reap(pidFile);
      }
    });
  }

  it("near miss: a server that answers a little late is not killed by the connect timeout, and close() leaves nothing", async () => {
    const pidFile = newPidFile();
    try {
      const s = await McpSession.open(spec("slow", pidFile, ["--delay-ms", "300"]), ctx, { connectTimeoutMs: 20_000, cleanCwd: true });
      assert.deepEqual(s.tools.map((t) => t.name), ["echo"]);
      assert.equal((await s.call("echo", { text: "hi" })).text, "hi");
      const pid = s.pid;
      assert.ok(pid && alive(pid), "the server is running while the session is open");
      await s.close();
      assert.deepEqual(await stillRunning(pidFile, 500), []);
    } finally {
      reap(pidFile);
    }
  });

  it("the CLI exits 4 on a connect timeout and the server is gone (default sandbox)", async () => {
    const pidFile = newPidFile();
    try {
      const cfg = writeYaml(`never-${n++}.yaml`, `name: never\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([SLOW, "--mode", "never", "--pid-file", pidFile])}\n`);
      const r = sealmark(["run", "--config", cfg, "--pack", "core", "--connect-timeout", "2", "--fail-under", "none"]);
      assert.equal(r.code, 4, r.err);
      assert.match(r.err, /the server did not answer initialize within 2 s \(--connect-timeout\)\. The first start of an npx or uvx server downloads it/);
      assert.ok(pidsIn(pidFile).length >= 1, "the toy started");
      assert.deepEqual(await stillRunning(pidFile, 1000), [], "the process the CLI started is not left running");
    } finally {
      reap(pidFile);
    }
  });
});
