import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { freePort } from "./helpers.js";
import { launchServer, LaunchError, type LaunchedServer } from "../launch.js";
import { createServer } from "node:http";

// A throwaway HTTP server started as a child process: answers every request with 401 after `delayMs`.
const serverScript = (port: number, delayMs: number) =>
  `setTimeout(() => require("http").createServer((q, s) => { s.statusCode = 401; s.end("no"); }).listen(${port}, "127.0.0.1"), ${delayMs});`;

describe("launchServer", { timeout: 60_000 }, () => {
  it("waits until the URL answers (any status counts, a 401 is up) and stops the process", async () => {
    const port = await freePort();
    const lines: string[] = [];
    const s = await launchServer({ command: process.execPath, args: ["-e", serverScript(port, 700)], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 20_000, onProgress: (l) => lines.push(l) });
    assert.match(lines.join("\n"), /waiting for http:\/\/127\.0\.0\.1:\d+\/mcp/);
    assert.equal((await fetch(`http://127.0.0.1:${port}/mcp`)).status, 401);
    await s.stop();
    await s.stop(); // twice is fine
    await assert.rejects(fetch(`http://127.0.0.1:${port}/mcp`), "the port is closed after stop()");
  });

  it("fails with the server's own output when it exits before answering", async () => {
    const port = await freePort();
    await assert.rejects(
      launchServer({ command: process.execPath, args: ["-e", "console.error('boom: missing config'); process.exit(3)"], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 10_000 }),
      (e: Error) => e instanceof LaunchError && /exited with code 3 before .* answered/.test(e.message) && e.message.includes("boom: missing config"),
    );
  });

  it("fails, never carries on, when the URL does not answer in time, and leaves no process behind", async () => {
    const port = await freePort();
    await assert.rejects(
      launchServer({ command: process.execPath, args: ["-e", "console.log('up'); setInterval(() => {}, 1000)"], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 1500, onProgress: () => {} }),
      (e: Error) => e instanceof LaunchError && /did not answer within 2 s|did not answer within 1 s/.test(e.message) && /--start-timeout/.test(e.message) && e.message.includes("up"),
    );
  });

  it("names a command that cannot be started", async () => {
    await assert.rejects(launchServer({ command: "/no/such/sealmark-server", args: [], env: {}, url: "http://127.0.0.1:9/mcp", timeoutMs: 5_000 }), /could not start "\/no\/such\/sealmark-server"/);
  });

  it("passes the extra environment to the process", async () => {
    const port = await freePort();
    const script = `const v = process.env.SM_TEST_VALUE; require("http").createServer((q, s) => { s.statusCode = v === "42" ? 401 : 500; s.end(); }).listen(${port}, "127.0.0.1");`;
    const s = await launchServer({ command: process.execPath, args: ["-e", script], env: { SM_TEST_VALUE: "42" }, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 20_000 });
    assert.equal((await fetch(`http://127.0.0.1:${port}/mcp`)).status, 401);
    await s.stop();
  });
});

describe("launchServer safety rules", { timeout: 90_000 }, () => {
  const POSIX = process.platform !== "win32";

  it("refuses to start when something already answers at the URL (a stale server must not be graded)", async () => {
    const port = await freePort();
    const stale = createServer((_q, r) => {
      r.statusCode = 200;
      r.end("stale");
    });
    await new Promise<void>((res) => stale.listen(port, "127.0.0.1", res));
    try {
      await assert.rejects(
        launchServer({ command: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 5_000 }),
        (e: Error) => e instanceof LaunchError && /something is already answering at .* \(HTTP 200\) before the server was started/.test(e.message),
      );
    } finally {
      await new Promise((r) => stale.close(r));
    }
  });

  it("a 404 or 5xx is not ready (wrong path or half-started); the timeout says what the last answer was", async () => {
    const port = await freePort();
    const script = `require("http").createServer((q, s) => { s.statusCode = 404; s.end("nope"); }).listen(${port}, "127.0.0.1");`;
    await assert.rejects(
      launchServer({ command: process.execPath, args: ["-e", script], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 2_500 }),
      (e: Error) => e instanceof LaunchError && /did not answer within/.test(e.message) && /the last answer was HTTP 404/.test(e.message) && /check the URL path/.test(e.message),
    );
  });

  it("a URL that can never work fails at once instead of waiting out the timeout", async () => {
    const t0 = Date.now();
    await assert.rejects(launchServer({ command: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"], env: {}, url: "localhost:8000/mcp", timeoutMs: 30_000 }), (e: Error) => e instanceof LaunchError && /not a valid URL/.test(e.message) && /http:\/\/ or https/.test(e.message));
    assert.ok(Date.now() - t0 < 5_000, "failed fast");
  });

  it("stopping while it is still waiting (a Ctrl+C or SIGTERM mid-start) stops the process: onStarted hands over the handle before the wait", async () => {
    const port = await freePort();
    let handle: LaunchedServer | undefined;
    // This server would only start listening after 3 s.
    const p = launchServer({
      command: process.execPath,
      args: ["-e", serverScript(port, 3_000)],
      env: {},
      url: `http://127.0.0.1:${port}/mcp`,
      timeoutMs: 20_000,
      onStarted: (h) => {
        handle = h;
      },
    });
    await new Promise((r) => setTimeout(r, 600));
    assert.ok(handle, "onStarted was called before the URL answered");
    await handle.stop();
    await assert.rejects(p, LaunchError);
    await new Promise((r) => setTimeout(r, 3_500));
    await assert.rejects(fetch(`http://127.0.0.1:${port}/mcp`), "the server never came up after being stopped");
  });

  it("stop() reaches the processes a launcher started, not just the launcher", { skip: !POSIX }, async () => {
    const port = await freePort();
    // sh starts the real server in the background and waits: killing only sh would leave the server running.
    const server = serverScript(port, 0).replace(/"/g, '\\"');
    const s = await launchServer({ command: "sh", args: ["-c", `"${process.execPath}" -e "${server}" & wait`], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 20_000 });
    assert.equal((await fetch(`http://127.0.0.1:${port}/mcp`)).status, 401);
    await s.stop();
    await assert.rejects(fetch(`http://127.0.0.1:${port}/mcp`), "the grandchild is gone too");
  });

  it("a server that dies after it answered is reported by exited()", async () => {
    const port = await freePort();
    const script = `require("http").createServer((q, s) => { s.statusCode = 401; s.end("no"); }).listen(${port}, "127.0.0.1"); setTimeout(() => process.exit(7), 1500);`;
    const s = await launchServer({ command: process.execPath, args: ["-e", script], env: {}, url: `http://127.0.0.1:${port}/mcp`, timeoutMs: 20_000 });
    assert.equal(s.exited(), undefined);
    await new Promise((r) => setTimeout(r, 2_500));
    assert.equal(s.exited(), "exited with code 7");
    await s.stop();
  });

  it("a certificate or DNS error is fatal, not retried until the timeout", async () => {
    const t0 = Date.now();
    await assert.rejects(launchServer({ command: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"], env: {}, url: "http://sealmark-no-such-host.invalid/mcp", timeoutMs: 30_000 }), (e: Error) => e instanceof LaunchError && /ENOTFOUND|EAI_AGAIN/.test(e.message));
    assert.ok(Date.now() - t0 < 10_000, "failed fast");
  });
});
