import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ConfigError, loadEffectiveConfig } from "../config/index.js";
import { launchServer } from "../launch.js";
import { runDoctor } from "../doctor.js";
import { McpSession, SessionError, SSE_STREAM_LOST, transportMismatch } from "../mcp.js";
import { HarnessError, legacyEffectiveConfig, runHarness } from "../run.js";
import { classifyStartFailure, START_FAILURE_ADVICE, TRANSPORT_MISMATCH } from "../start-failure.js";
import { HTTP_TOY_TOKEN, startHttpToy } from "../toy/http.js";
import { startSseToy } from "../toy/sse.js";
import type { TemplateCtx } from "../config.js";
import type { ServerSpec } from "../types.js";
import { freePort, gradeOf, quiet } from "./helpers.js";

const SSE_TOY = new URL("../toy/sse.js", import.meta.url).pathname;

const CTX: TemplateCtx = { vars: {}, dsns: {} };
const BEARER = { Authorization: `Bearer ${HTTP_TOY_TOKEN}` };

/** Opens a session, calls echo once and closes; the reply text proves a tool call went both ways over the transport. */
async function echoOver(spec: ServerSpec): Promise<{ tools: string[]; reply: string }> {
  const s = await McpSession.open(spec, CTX, { connectTimeoutMs: 10_000 });
  try {
    const r = await s.call("echo", { text: "over the wire" });
    return { tools: s.tools.map((t) => t.name), reply: r.text };
  } finally {
    await s.close();
  }
}

/** The session error a failed open throws, so its message and start-failure kind can be checked. */
async function openError(spec: ServerSpec): Promise<SessionError> {
  try {
    const s = await McpSession.open(spec, CTX, { connectTimeoutMs: 10_000 });
    await s.close();
  } catch (e) {
    assert.ok(e instanceof SessionError, `expected a SessionError, got ${String(e)}`);
    return e;
  }
  return assert.fail("the session opened, but the transport does not match");
}

describe("HTTP transports: one passing session per transport against a fixture", { timeout: 60_000 }, () => {
  it("stdio: the toy server started as a process", async () => {
    assert.deepEqual(await echoOver({ command: process.execPath, args: [SSE_TOY, "--stdio"] }), { tools: ["echo"], reply: "over the wire" });
  });

  it("Streamable HTTP: the http toy, with its bearer token", async () => {
    const toy = await startHttpToy("good");
    try {
      assert.deepEqual(await echoOver({ url: toy.url, headers: BEARER }), { tools: ["echo"], reply: "over the wire" });
    } finally {
      await toy.close();
    }
  });

  it("HTTP+SSE: the sse toy over transport sse, with the configured headers on the event-stream GET and on every POST", async () => {
    const toy = await startSseToy({ token: "sse-toy-token" });
    try {
      const r = await echoOver({ url: toy.url, transport: "sse", headers: { Authorization: "Bearer sse-toy-token" } });
      assert.deepEqual(r, { tools: ["echo"], reply: "over the wire" });
      assert.equal(toy.seen["get /sse"], 1, "one event stream was opened");
      assert.ok((toy.seen["post /messages"] ?? 0) >= 3, "initialize, tools/list and tools/call went to the POST endpoint the stream named");
      assert.equal(toy.seen["post /sse"], undefined, "no Streamable HTTP POST was sent");
    } finally {
      await toy.close();
    }
  });

  it("HTTP+SSE: a missing token is refused on the event stream, and the 401 is what the error says", async () => {
    const toy = await startSseToy({ token: "sse-toy-token" });
    try {
      const e = await openError({ url: toy.url, transport: "sse" });
      assert.match(e.message, /401/);
      assert.equal(e.message.includes(TRANSPORT_MISMATCH), false, "a refused token is not a transport mismatch");
    } finally {
      await toy.close();
    }
  });
});

describe("a transport mismatch is named, with a typed start-failure kind", { timeout: 60_000 }, () => {
  it("Streamable HTTP (the default) against an HTTP+SSE URL: the 405 says to use --transport sse; kind transport-mismatch", async () => {
    const toy = await startSseToy();
    try {
      const e = await openError({ url: toy.url });
      assert.match(e.message, /HTTP 405/);
      assert.ok(e.message.includes(TRANSPORT_MISMATCH));
      assert.match(e.message, /--transport sse/);
      assert.equal(toy.seen["get /sse"], undefined, "the default transport never opened the event stream");
      assert.equal(e.transportMismatch, true);
      assert.deepEqual(classifyStartFailure({ message: e.message, transportMismatch: e.transportMismatch }), { kind: "transport-mismatch", advice: START_FAILURE_ADVICE["transport-mismatch"] });
    } finally {
      await toy.close();
    }
  });

  it("transport sse against a Streamable HTTP URL: no event stream opened; says to drop --transport sse; kind transport-mismatch", async () => {
    const toy = await startHttpToy("good");
    try {
      const e = await openError({ url: toy.url, transport: "sse", headers: BEARER });
      assert.ok(e.message.includes(TRANSPORT_MISMATCH), e.message);
      assert.match(e.message, /drop --transport sse/);
      assert.equal(classifyStartFailure({ message: e.message, transportMismatch: e.transportMismatch }).kind, "transport-mismatch");
    } finally {
      await toy.close();
    }
  });

  it("a wrong path (404) and a server error are not called a transport mismatch", () => {
    for (const code of [404, 500, 401]) {
      assert.equal(transportMismatch({ code, message: "Streamable HTTP error: Error POSTing to endpoint: no" }, { url: "http://127.0.0.1:1/mcp" }), "", `HTTP ${code} over streamable-http`);
      assert.equal(transportMismatch({ code, message: `SSE error: Non-200 status code (${code})` }, { url: "http://127.0.0.1:1/sse", transport: "sse" }), "", `HTTP ${code} over sse`);
    }
    assert.equal(transportMismatch({ code: 405, message: "x" }, {}), "", "a stdio server has no HTTP transport");
    assert.notEqual(transportMismatch({ code: 200, message: 'SSE error: Invalid content type, expected "text/event-stream"' }, { url: "http://127.0.0.1:1/mcp", transport: "sse" }), "");
  });

  it("the kind comes from the session's typed flag, never from text a server printed", () => {
    assert.equal(classifyStartFailure({ message: "MCP error -32000: Connection closed", stderr: `oops: ${TRANSPORT_MISMATCH}` }).kind, "unknown");
    assert.equal(classifyStartFailure({ message: `could not start: x (server stderr: ${TRANSPORT_MISMATCH})` }).kind, "unknown");
    assert.equal(classifyStartFailure({ message: "Error POSTing to endpoint", transportMismatch: true }).kind, "transport-mismatch");
  });

  it("the advice for the new kind names both fixes", () => {
    assert.match(START_FAILURE_ADVICE["transport-mismatch"], /--transport sse/);
    assert.match(START_FAILURE_ADVICE["transport-mismatch"], /leave --transport out/);
  });
});

describe("a dropped HTTP+SSE stream ends the session; it is never silently replaced", { timeout: 60_000 }, () => {
  it("calls after the drop come back closed with the cause, and no second event stream is opened", async () => {
    const toy = await startSseToy({ dropStreamAfterMs: 300 });
    try {
      const s = await McpSession.open({ url: toy.url, transport: "sse" }, CTX, { connectTimeoutMs: 10_000 });
      try {
        assert.equal((await s.call("echo", { text: "before" })).text, "before", "the session works before the drop");
        // Longer than the EventSource's 3 s reconnect delay: without the fix it would have opened a new, uninitialized session by now.
        await new Promise((r) => setTimeout(r, 3_600));
        const r = await s.call("echo", { text: "after" }, 5_000);
        assert.equal(r.closed, true);
        assert.equal(r.isError, true);
        assert.ok((r.rpcError ?? "").includes(SSE_STREAM_LOST), String(r.rpcError));
        assert.equal(s.closed, true);
        assert.equal(toy.seen["get /sse"], 1, "the stream was not reopened");
      } finally {
        await s.close();
      }
    } finally {
      await toy.close();
    }
  });
});

describe("--start with transport sse", { timeout: 60_000 }, () => {
  it("waits for the event-stream URL with a GET (the toy refuses POST there) and then the session works", async () => {
    const port = await freePort();
    const url = `http://127.0.0.1:${port}/sse`;
    const lines: string[] = [];
    const s = await launchServer({ command: process.execPath, args: [SSE_TOY, "--port", String(port)], env: {}, url, transport: "sse", timeoutMs: 20_000, onProgress: (l) => lines.push(l) });
    try {
      assert.match(lines.join("\n"), /the server answered \(HTTP 200\)/, "the probe was a GET that the event-stream URL answers with 200");
      assert.deepEqual(await echoOver({ url, transport: "sse" }), { tools: ["echo"], reply: "over the wire" });
    } finally {
      await s.stop();
    }
  });
});

describe("server.transport in the configuration", () => {
  let root: string;
  let n = 0;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sealmark-sse-cfg-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));
  const proj = (yaml?: string): string => {
    const dir = join(root, `p${n++}`);
    mkdirSync(dir, { recursive: true });
    if (yaml !== undefined) writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\n${yaml}`);
    return dir;
  };
  const load = (dir: string, flags: Record<string, unknown> = {}) => loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, flags });

  it("--transport sse with --url reaches the server spec", () => {
    assert.equal(load(proj(), { url: "http://127.0.0.1:9/sse", transport: "sse" }).server.transport, "sse");
  });

  it("server.transport: sse in sealmark.yaml reaches the spec, for server and for servers.*", () => {
    assert.equal(load(proj("server:\n  url: http://127.0.0.1:9/sse\n  transport: sse\n")).server.transport, "sse");
    const multi = load(proj("servers:\n  legacy:\n    url: http://127.0.0.1:9/sse\n    transport: sse\n  current:\n    url: http://127.0.0.1:9/mcp\n"));
    const specs = Object.fromEntries(multi.servers.map((s) => [s.name, s.spec]));
    assert.equal(specs.legacy.transport, "sse");
    assert.equal("transport" in specs.current, false);
  });

  it("streamable-http is the default: naming it gives the same spec as leaving it out (so reports do not change)", () => {
    const named = load(proj(), { url: "http://127.0.0.1:9/mcp", transport: "streamable-http" }).server;
    const omitted = load(proj(), { url: "http://127.0.0.1:9/mcp" }).server;
    assert.deepEqual(named, omitted);
    assert.equal("transport" in named, false);
  });

  it("a transport without a url is a config error, and so is an unknown transport", () => {
    assert.throws(() => load(proj("server:\n  command: node\n  transport: sse\n")), (e: Error) => e instanceof ConfigError && /server\.transport only applies to an HTTP server/.test(e.message));
    assert.throws(() => load(proj(), { url: "http://127.0.0.1:9/mcp", transport: "websocket" }), (e: Error) => e instanceof ConfigError && /transport/.test(e.message));
  });

  it("the standard config hash does not move: transport is not a locked setting", () => {
    const sse = load(proj(), { url: "http://127.0.0.1:9/sse", transport: "sse" });
    const plain = load(proj(), { url: "http://127.0.0.1:9/sse" });
    assert.equal(sse.integrity.hash, plain.integrity.hash);
  });
});

describe("a run over HTTP+SSE", { timeout: 120_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-sse-run-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const run = async (server: ServerSpec) => {
    const base = legacyEffectiveConfig({ config: { name: "sse-toy", version: "0.0.1", server }, packs: ["core", "http", "oauth"], packsExplicit: false, timeoutProbeSec: 2 });
    return runHarness({ config: { name: "sse-toy", version: "0.0.1", server }, effective: { ...base, sandbox: { ...base.sandbox, dir } }, packs: ["core", "http", "oauth"], packsExplicit: false, timeoutProbeSec: 2, log: quiet });
  };

  it("core grades the server; http and oauth are skipped with the reason, never graded; the report says HTTP+SSE", async () => {
    const toy = await startSseToy();
    try {
      const r = await run({ url: toy.url, transport: "sse" });
      assert.equal(r.server.transport, "http");
      assert.equal(r.server.httpTransport, "sse");
      assert.deepEqual(r.server.tools, ["echo"]);
      assert.ok(gradeOf(r, "core")?.letter, "core has a grade");
      for (const id of ["http", "oauth"] as const) {
        const p = r.packs[id];
        assert.ok(p, `${id} is listed`);
        assert.notEqual(p.status, "graded", `${id} must not be graded over SSE`);
        assert.match(p.reason ?? "", /older HTTP\+SSE transport/, `${id} says why`);
      }
      assert.equal(toy.seen["post /sse"], undefined, "no pack sent a Streamable HTTP request to the event-stream URL");
      assert.deepEqual(readdirSync(dir), []);
    } finally {
      await toy.close();
    }
  });

  it("doctor says what run does: http and oauth would not run over HTTP+SSE, with the same reason", async () => {
    const toy = await startSseToy();
    try {
      const cfgDir = mkdtempSync(join(dir, "..", "sealmark-sse-doctor-"));
      try {
        writeFileSync(join(cfgDir, "sealmark.yaml"), `schema_version: 1\nname: sse-doctor\npacks: [core, http, oauth]\nserver:\n  url: ${toy.url}\n  transport: sse\n`);
        const cfg = loadEffectiveConfig({ cwd: cfgDir, env: {}, isolated: true });
        const r = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
        for (const id of ["http", "oauth"]) {
          const p = r.servers[0].packs.find((x) => x.pack === id);
          assert.ok(p, `${id} is listed`);
          assert.equal(p.applies, false, `${id} must not be reported as applying`);
          assert.match(p.reason, /older HTTP\+SSE transport/);
        }
      } finally {
        rmSync(cfgDir, { recursive: true, force: true });
      }
    } finally {
      await toy.close();
    }
  });

  it("a Streamable HTTP report carries no httpTransport field (reports written before this change read the same)", async () => {
    const toy = await startHttpToy("good");
    try {
      const r = await run({ url: toy.url, headers: BEARER });
      assert.equal(r.server.transport, "http");
      assert.equal("httpTransport" in r.server, false);
    } finally {
      await toy.close();
    }
  });

  it("the default transport against an SSE server fails the run with kind transport-mismatch", async () => {
    const toy = await startSseToy();
    try {
      await assert.rejects(run({ url: toy.url }), (e: Error) => e instanceof HarnessError && e.startFailure?.kind === "transport-mismatch" && /--transport sse/.test(e.message));
    } finally {
      await toy.close();
    }
  });
});
