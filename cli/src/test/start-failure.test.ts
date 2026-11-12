import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyStartFailure, START_FAILURE_ADVICE, type StartFailureKind } from "../start-failure.js";

// Stderr shapes recorded from servers that never started under the fleet harness (sealmark-site fleet/history.jsonl, 2026-11-12),
// shortened to the lines that decide the kind. Package names are kept only where the line needs one.
const CLOSED = "MCP error -32000: Connection closed";

describe("classifyStartFailure", () => {
  const kind = (message: string, stderr?: string): StartFailureKind => classifyStartFailure({ message, stderr }).kind;

  it("dependency-resolution: uv, pip and npm cannot resolve or fetch the package", () => {
    // postgres-mcp, every run since 2026-11-09: its pinned pglast release is gone from PyPI.
    assert.equal(kind(CLOSED, "  × No solution found when resolving tool dependencies:\n  ╰─▶ Because there is no version of pglast==7.2.0 and postgres-mcp==0.3.0 depends on pglast==7.2.0, we can conclude that postgres-mcp==0.3.0 cannot be used."), "dependency-resolution");
    assert.equal(kind(CLOSED, "ERROR: Could not find a version that satisfies the requirement mcp-server-x==9.9 (from versions: 0.1.0)\nERROR: No matching distribution found for mcp-server-x==9.9"), "dependency-resolution");
    assert.equal(kind(CLOSED, "npm error code E404\nnpm error 404 Not Found - GET https://registry.npmjs.org/@acme%2fmcp-gone - Not found"), "dependency-resolution");
    assert.equal(kind(CLOSED, "npm ERR! code ETARGET\nnpm ERR! notarget No matching version found for left-pad@^99.0.0."), "dependency-resolution");
    // An import the package needs but did not install: the same fix (pin or repair the dependency set).
    assert.equal(kind(CLOSED, 'Traceback (most recent call last):\n  File "/x/server.py", line 3, in <module>\nModuleNotFoundError: No module named \'httpx\''), "dependency-resolution");
    assert.equal(kind(CLOSED, "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'zod' imported from /tmp/x/dist/index.js"), "dependency-resolution");
    assert.equal(kind(CLOSED, "Error: Cannot find module 'express'\nRequire stack:\n- /tmp/x/index.js"), "dependency-resolution");
  });

  it("needs-credentials: the server asks for a key, a token or a sign-in before it starts", () => {
    assert.equal(kind(CLOSED, "Error: GITHUB_PERSONAL_ACCESS_TOKEN environment variable is required"), "needs-credentials");
    assert.equal(kind(CLOSED, "ValueError: BRAVE_API_KEY is not set"), "needs-credentials");
    assert.equal(kind(CLOSED, "Missing API key. Set OPENAI_API_KEY and try again."), "needs-credentials");
    assert.equal(kind(CLOSED, "Not signed in. Run `acme login` first."), "needs-credentials");
    assert.equal(kind(CLOSED, "fatal: credentials not found for profile default"), "needs-credentials");
  });

  it("missing-runtime: the launcher or runtime is not on this machine, or is the wrong version", () => {
    assert.equal(kind("spawn uvx ENOENT"), "missing-runtime");
    assert.equal(kind(CLOSED, "sh: 1: deno: not found"), "missing-runtime");
    assert.equal(kind(CLOSED, "/bin/sh: bun: command not found"), "missing-runtime");
    assert.equal(kind(CLOSED, "  × No solution found when resolving tool dependencies:\n  ╰─▶ Because the current Python version (3.10.12) does not satisfy Python>=3.11 and acme-mcp==1.0 depends on Python>=3.11, we can conclude that acme-mcp==1.0 cannot be used."), "missing-runtime");
    assert.equal(kind(CLOSED, "npm error code EBADENGINE\nnpm error engine Unsupported engine\nnpm error notsup Required: {\"node\":\">=24\"}"), "missing-runtime");
    assert.equal(kind(CLOSED, "docker: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"), "missing-runtime");
  });

  it("bad-launch: the process ran but the command, entry file or a required setting is wrong", () => {
    assert.equal(kind(CLOSED, "usage: server.py [-h] --root ROOT\nserver.py: error: the following arguments are required: --root"), "bad-launch");
    assert.equal(kind(CLOSED, "error: unknown option '--stdio'"), "bad-launch");
    assert.equal(kind(CLOSED, "Error: Cannot find module '/tmp/sm-x/node_modules/acme/dist/index.js'\n    at Module._resolveFilename"), "bad-launch");
    assert.equal(kind(CLOSED, "Error [ERR_MODULE_NOT_FOUND]: Cannot find module './build/index.js' imported from /tmp/x"), "bad-launch");
    // cyanheads-fs before sealmark-site#18: the root setting was not given.
    assert.equal(kind(CLOSED, "Fatal: environment variable FS_BASE_DIRECTORY is required"), "bad-launch");
    assert.equal(kind("the server exited with code 126 before the URL answered. Its last output:\nsh: 1: ./server: Permission denied"), "bad-launch");
  });

  it("initialize-timeout: no answer to initialize in time, with nothing more specific on stderr", () => {
    assert.equal(kind("the server did not answer initialize within 60 s (--connect-timeout). The first start ..."), "initialize-timeout");
    assert.equal(kind("MCP error -32001: Request timed out", "Downloading pydantic-core (1.9MiB)\nInstalled 31 packages in 48ms"), "initialize-timeout");
    assert.equal(kind("http://127.0.0.1:9/mcp did not answer within 60 s (no answer yet; raise --start-timeout ...)"), "initialize-timeout");
    // A specific cause on stderr wins over the timeout it led to.
    assert.equal(kind("MCP error -32001: Request timed out", "Error: SLACK_BOT_TOKEN is required"), "needs-credentials");
  });

  it("the last fatal line wins over earlier noise and warnings", () => {
    // npm warns about engines on many npx installs and keeps going: the real cause comes after it.
    assert.equal(kind(CLOSED, "npm warn EBADENGINE Unsupported engine { package: 'x@1', required: { node: '>=22' } }\nError: GITHUB_TOKEN environment variable is required"), "needs-credentials");
    assert.equal(kind(CLOSED, "npm warn EBADENGINE Unsupported engine {\nnpm warn EBADENGINE   required: { node: '>=24' },"), "unknown");
    // A warning-level line about a missing key is not why the process died.
    assert.equal(kind(CLOSED, "WARNING: OPENAI_API_KEY not set, some tools disabled\nTraceback (most recent call last):\nTypeError: 'NoneType' object is not subscriptable"), "unknown");
    assert.equal(kind(CLOSED, "2026-11-12T07:00:00Z [WARN] no credentials configured\nusage: srv [-h] --root ROOT"), "bad-launch");
    // A dependency failure printed after a credential complaint is what stopped the start.
    assert.equal(kind(CLOSED, "Error: API key is required for search tools\nModuleNotFoundError: No module named 'mcp'"), "dependency-resolution");
  });

  it("unknown: an empty or unrecognized stderr", () => {
    assert.equal(kind(CLOSED), "unknown");
    assert.equal(kind(CLOSED, ""), "unknown");
    assert.equal(kind(CLOSED, "   \n\n"), "unknown");
    assert.equal(kind(CLOSED, "server listening\npanic: runtime error: index out of range [3] with length 3"), "unknown");
  });

  it("does not read ordinary words as a cause", () => {
    // A tool description or a startup banner that only mentions tokens or keys is not a credential failure.
    assert.equal(kind(CLOSED, "acme-mcp v1.2 starting; tools: count_tokens, rotate_api_key"), "unknown");
    assert.equal(kind(CLOSED, "loaded 3 credentials from the keychain"), "unknown");
  });

  it("every result carries the advice for its kind, and each kind has advice", () => {
    const kinds: StartFailureKind[] = ["dependency-resolution", "needs-credentials", "missing-runtime", "bad-launch", "initialize-timeout", "unknown"];
    for (const k of kinds) assert.ok(START_FAILURE_ADVICE[k].length > 20, `advice for ${k}`);
    assert.deepEqual(classifyStartFailure({ message: CLOSED }), { kind: "unknown", advice: START_FAILURE_ADVICE.unknown });
    assert.deepEqual(classifyStartFailure({ message: "spawn npx ENOENT" }), { kind: "missing-runtime", advice: START_FAILURE_ADVICE["missing-runtime"] });
  });

  it("stays fast on a huge or hostile stderr (only the last 64 KiB is read)", () => {
    const flood = "token ".repeat(200_000) + "\n" + "a".repeat(500_000);
    const t0 = Date.now();
    assert.equal(kind(CLOSED, flood), "unknown");
    // The decisive line is at the end, where a dying process writes it.
    assert.equal(kind(CLOSED, "x".repeat(2_000_000) + "\nModuleNotFoundError: No module named 'mcp'"), "dependency-resolution");
    assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  });
});
