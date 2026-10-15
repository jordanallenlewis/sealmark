import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { freePort, hermeticEnv } from "./helpers.js";

// The upstream stub and the launched server are stopped when a signal interrupts the run (the cleanup.signal pattern). POSIX only, like it.
const POSIX = process.platform !== "win32";
const RUNNER = fileURLToPath(new URL("./r6-harness.runner.js", import.meta.url));

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r6-signal-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const answers = async (url: string): Promise<boolean> => {
  try {
    await fetch(url, { signal: AbortSignal.timeout(1500) });
    return true;
  } catch {
    return false;
  }
};

describe("round 6: signals", { timeout: 120_000, skip: !POSIX }, () => {
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    it(`${signal} while the run is starting closes the upstream stub, stops the launched server and leaves no sandbox`, async () => {
      const port = await freePort();
      const parent = join(dir, signal);
      rmSync(parent, { recursive: true, force: true });
      const child = spawn(process.execPath, [RUNNER, String(port), parent], { env: hermeticEnv(), stdio: ["ignore", "ignore", "pipe"] });
      let err = "";
      let stub: string | undefined;
      const exited = new Promise<number | null>((res) => child.once("exit", (code) => res(code)));
      const ready = new Promise<void>((res) => {
        child.stderr.on("data", (d: Buffer) => {
          err += d.toString();
          const m = /upstream stub is listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(err);
          if (m && !stub) {
            stub = m[1];
            res();
          }
        });
      });
      await Promise.race([ready, exited]);
      assert.ok(stub, `the stub announced itself: ${err}`);
      assert.equal(await answers(stub), true, "the stub answers while the run is going");
      child.kill(signal);
      const code = await exited;
      assert.equal(code, signal === "SIGINT" ? 130 : 143, err);
      assert.equal(await answers(stub), false, "nothing answers on the stub's port after the signal");
      assert.equal(await answers(`http://127.0.0.1:${port}/mcp`), false, "the launched server is gone too");
      const left = (() => {
        try {
          return readdirSync(parent).filter((n) => n.startsWith("sealmark-"));
        } catch {
          return [];
        }
      })();
      assert.deepEqual(left, [], "no sandbox directory is left");
    });
  }
});
