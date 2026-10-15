import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { McpSession } from "../mcp.js";
import type { SealmarkConfig } from "../types.js";
import { runPacks } from "./packctx.js";

// A launcher that exits and leaves its server behind (nothing links the daemon to the launcher by parent any more): close() must
// still stop it, from the process tree it remembered after connecting. POSIX only: Windows does not take the remembered-tree path.
const LAUNCHER = fileURLToPath(new URL("../toy/launcher-orphan.js", import.meta.url));
const POSIX = process.platform !== "win32";

let dir: string;
let n = 0;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r3-orphan-"));
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
async function stillRunning(file: string, withinMs = 3000): Promise<number[]> {
  const until = Date.now() + withinMs;
  for (;;) {
    const up = pidsIn(file).filter(alive);
    if (up.length === 0 || Date.now() > until) return up;
    await new Promise((r) => setTimeout(r, 50));
  }
}
// The daemon is a fresh node process that writes its pid once it has booted, which can lag the session under load.
async function daemonsStarted(file: string, withinMs = 10_000): Promise<number[]> {
  const until = Date.now() + withinMs;
  while (pidsIn(file).length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 50));
  return pidsIn(file);
}
const reap = (file: string): void => {
  for (const p of pidsIn(file))
    try {
      process.kill(p, "SIGKILL");
    } catch {
      /* gone */
    }
};
const newPidFile = (): string => join(dir, `pids-${n++}.txt`);
const spec = (pidFile: string, exitMs?: number) => ({ command: process.execPath, args: [LAUNCHER, "--pid-file", pidFile, ...(exitMs !== undefined ? ["--exit-ms", String(exitMs)] : [])] });

describe("r3 fs-net: a launcher that exits leaves nothing running", { skip: !POSIX && "POSIX only", timeout: 120_000 }, () => {
  it("close() after the launcher has exited stops the daemon it left behind", async () => {
    const pidFile = newPidFile();
    try {
      const s = await McpSession.open(spec(pidFile), { vars: {}, dsns: {} }, {});
      assert.ok(s.tools.length > 0, "the launcher served the toy for its first seconds");
      const started = await daemonsStarted(pidFile);
      assert.equal(started.length, 1, "the daemon started");
      const [daemon] = started;
      assert.ok(alive(daemon!));
      // The launcher exits after 2 s; the daemon has no stdio, so the transport sees the process end.
      const until = Date.now() + 10_000;
      while (!s.closed && Date.now() < until) await new Promise((r) => setTimeout(r, 100));
      assert.equal(s.closed, true, "the session noticed the launcher going away");
      assert.ok(alive(daemon!), "without a close() the daemon outlives the launcher");
      await s.close();
      assert.deepEqual(await stillRunning(pidFile), [], "the daemon is gone after close()");
    } finally {
      reap(pidFile);
    }
  });

  it("a whole run on it, with the launcher gone before the run ends, leaves no daemon running", async () => {
    const pidFile = newPidFile();
    const parent = join(dir, "sandboxes");
    mkdirSync(parent, { recursive: true });
    const config: SealmarkConfig = { name: "toy-launcher-orphan", version: "0.0.1", server: spec(pidFile, 500) as SealmarkConfig["server"] };
    try {
      const run = await runPacks(config, ["core"], { dir, parent }).catch((e: unknown) => e as Error);
      assert.ok((await daemonsStarted(pidFile)).length >= 1, "at least one daemon was started");
      assert.deepEqual(await stillRunning(pidFile), [], `no daemon is left: ${run instanceof Error ? run.message : "run finished"}`);
    } finally {
      reap(pidFile);
    }
  });
});
