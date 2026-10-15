import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { launchServer, type LaunchedServer } from "../launch.js";
import { freePort } from "./helpers.js";

// round 6: launchServer takes a working directory and a replacement environment, reports its output as it comes, and exposes its pid.

/** A child that answers every request with its own cwd and environment variable names, and writes one line to each stream. */
const reporter = (port: number) =>
  `console.log("out-line ready"); console.error("err-line ready");
   require("http").createServer((q, s) => { s.setHeader("content-type", "application/json"); s.end(JSON.stringify({ cwd: process.cwd(), keys: Object.keys(process.env), marker: process.env.SM_R6_MARKER ?? null, extra: process.env.SM_R6_EXTRA ?? null })); }).listen(${port}, "127.0.0.1");`;

let dir: string;
before(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "sealmark-r6-launch-")));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const started: LaunchedServer[] = [];
const run = async (port: number, extra: Partial<Parameters<typeof launchServer>[0]> = {}) => {
  const s = await launchServer({ command: process.execPath, args: ["-e", reporter(port)], env: {}, url: `http://127.0.0.1:${port}/`, timeoutMs: 20_000, ...extra });
  started.push(s);
  return s;
};
const ask = async (port: number) => (await (await fetch(`http://127.0.0.1:${port}/`)).json()) as { cwd: string; keys: string[]; marker: string | null; extra: string | null };

describe("launchServer: sandbox options", { timeout: 60_000 }, () => {
  it("cwd is honoured; without it the process keeps the harness's directory", async () => {
    const port = await freePort();
    const s = await run(port, { cwd: dir });
    assert.equal(realpathSync((await ask(port)).cwd), dir);
    await s.stop();
    const port2 = await freePort();
    const s2 = await run(port2);
    assert.equal(realpathSync((await ask(port2)).cwd), realpathSync(process.cwd()));
    await s2.stop();
  });

  it("baseEnv replaces the harness's environment, and env is merged on top of it", async () => {
    process.env.SM_R6_MARKER = "from-the-harness";
    try {
      const port = await freePort();
      const s = await run(port, { baseEnv: { PATH: process.env.PATH ?? "", SM_R6_BASE: "1" }, env: { SM_R6_EXTRA: "layered" } });
      const seen = await ask(port);
      assert.equal(seen.marker, null, "the harness's own variable did not leak through");
      assert.equal(seen.extra, "layered");
      assert.ok(seen.keys.includes("SM_R6_BASE") && seen.keys.includes("PATH"));
      assert.ok(!seen.keys.includes("SM_R6_MARKER"));
      await s.stop();
      // Without baseEnv the harness's environment is what the process gets (the old behaviour).
      const port2 = await freePort();
      const s2 = await run(port2, { env: { SM_R6_EXTRA: "x" } });
      assert.equal((await ask(port2)).marker, "from-the-harness");
      await s2.stop();
    } finally {
      delete process.env.SM_R6_MARKER;
    }
  });

  it("onOutput receives both streams as they arrive", async () => {
    const port = await freePort();
    const chunks: { stream: string; text: string }[] = [];
    const s = await run(port, { onOutput: (text, stream) => chunks.push({ stream, text }) });
    await ask(port);
    const joined = (stream: string) => chunks.filter((c) => c.stream === stream).map((c) => c.text).join("");
    assert.match(joined("stdout"), /out-line ready/);
    assert.match(joined("stderr"), /err-line ready/);
    await s.stop();
  });

  it("a throwing onOutput does not take the server down", async () => {
    const port = await freePort();
    const s = await run(port, {
      onOutput: () => {
        throw new Error("observer bug");
      },
    });
    assert.equal((await ask(port)).extra, null);
    await s.stop();
  });

  it("pid is the process that was started, and is gone after stop()", async () => {
    const port = await freePort();
    const s = await run(port);
    assert.equal(typeof s.pid, "number");
    assert.doesNotThrow(() => process.kill(s.pid!, 0));
    await s.stop();
    assert.throws(() => process.kill(s.pid!, 0));
  });
});
