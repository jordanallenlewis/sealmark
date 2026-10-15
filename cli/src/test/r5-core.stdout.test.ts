import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { McpSession, type CallResult } from "../mcp.js";
import { runCore, type CoreCtx } from "../packs/core.js";
import { runHarness } from "../run.js";
import type { CheckResult, PackId, RunResult, ServerSpec } from "../types.js";
import { quiet } from "./helpers.js";

// Round 5, G3: the protocol check reports lines the server wrote to stdout that are not JSON-RPC, and tools/call replies that are not valid MCP.

const NOISE = fileURLToPath(new URL("../toy/stdout-noise.js", import.meta.url));
const spec = (mode: string): ServerSpec => ({ command: process.execPath, args: [NOISE, "--mode", mode], env: {} });
const cache = new Map<string, Promise<RunResult>>();
const run = (mode: string): Promise<RunResult> => {
  let p = cache.get(mode);
  if (!p) cache.set(mode, (p = runHarness({ config: { name: `stdout-noise-${mode}`, version: "0.0.1", server: spec(mode) }, packs: ["core"] as PackId[], packsExplicit: true, timeoutProbeSec: 6, log: quiet })));
  return p;
};
/** Start every mode at once: the suite runs on a loaded machine, and a toy run is mostly waiting. */
const startAll = (modes: string[]): void => modes.forEach((m) => void run(m).catch(() => {}));
const protocol = (r: RunResult): CheckResult => r.checks.find((c) => c.id === "protocol")!;

describe("protocol reports stdout pollution (toy servers)", { timeout: 600_000 }, () => {
  before(() => startAll(["stdout", "json", "invalid", "stderr"]));
  it("stdout: a banner and a line per call on stdout is part, with the count and the first line, and the check stays non-critical", async () => {
    const r = await run("stdout");
    const c = protocol(r);
    assert.equal(c.verdict, "part", JSON.stringify(c));
    assert.equal(c.critical, false);
    const e = c.evidence.find((x) => x.code === "protocol.stdout-noise")!;
    assert.ok(e, JSON.stringify(c.evidence));
    assert.match(e.outcome, /the server wrote [2-9]\d* non-JSON-RPC line\(s\) to stdout \(first: .*noisy-serve.*\); strict stdio clients break on this/);
    assert.match(c.summary, /non-JSON-RPC line\(s\) on stdout/);
    // Only the protocol check moves: the tool itself behaves.
    assert.equal(r.checks.find((x) => x.id === "robust-input")!.verdict, "pass");
  });

  it("json: a line of valid JSON that is not a JSON-RPC message is noise too", async () => {
    const c = protocol(await run("json"));
    assert.equal(c.verdict, "part");
    assert.match(c.evidence.find((x) => x.code === "protocol.stdout-noise")!.outcome, /not a JSON-RPC message/);
  });

  it("invalid: a tools/call result that is not valid MCP is part, with the tool and the reason, and nothing was written to stdout", async () => {
    const c = protocol(await run("invalid"));
    assert.equal(c.verdict, "part", JSON.stringify(c));
    assert.equal(c.critical, false);
    assert.match(c.evidence.find((x) => x.code === "protocol.invalid-result")!.outcome, /tools\/call result\(s\) were not valid MCP \(echo: /);
    assert.ok(!c.evidence.some((x) => x.code === "protocol.stdout-noise"));
  });

  it("near miss, stderr: the same lines on stderr pass", async () => {
    const c = protocol(await run("stderr"));
    assert.equal(c.verdict, "pass", JSON.stringify(c.evidence));
    assert.ok(!c.evidence.some((x) => x.code === "protocol.stdout-noise"));
  });
});

describe("McpSession counts the lines, and a parse failure is not the cause of a later failure", { timeout: 300_000 }, () => {
  it("the count and the first line reach the session; stderr stays out of it", async () => {
    const noisy = await McpSession.open(spec("stdout"), { vars: {}, dsns: {} }, { cleanCwd: true });
    try {
      assert.equal(noisy.stdoutNoise.count, 1, "the banner arrived during initialize");
      assert.match(noisy.stdoutNoise.first, /noisy-serve/);
      await noisy.call("echo", { text: "hi" });
      assert.equal(noisy.stdoutNoise.count, 2, "and one line per call");
    } finally {
      await noisy.close();
    }
    const quietSession = await McpSession.open(spec("stderr"), { vars: {}, dsns: {} }, { cleanCwd: true });
    try {
      assert.deepEqual(quietSession.stdoutNoise, { count: 0, first: "" });
    } finally {
      await quietSession.close();
    }
  });
});

describe("protocol on a scripted session", () => {
  const ok: CallResult = { isError: true, text: "text must be a string", elapsedMs: 1, timedOut: false, closed: false };
  const mk = (extra: Record<string, unknown>): CoreCtx => {
    const session = {
      tools: [{ name: "t", description: "t does a thing", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }],
      serverInfo: { name: "stub", version: "1.0.0" },
      capabilities: {},
      prompts: [],
      resources: [],
      listErrors: [],
      async call() {
        return ok;
      },
      async alive() {
        return true;
      },
      ...extra,
    } as unknown as McpSession;
    return { session, canaries: ["sm-canary-x"], seen: [], hangMs: 100 };
  };
  const proto = async (ctx: CoreCtx) => (await runCore(ctx)).find((c) => c.id === "protocol")!;

  it("a session that saw no noise and no invalid result is unchanged: pass", async () => {
    assert.equal((await proto(mk({}))).verdict, "pass");
    assert.equal((await proto(mk({ stdoutNoise: { count: 0, first: "" }, invalidResults: { count: 0, samples: [] } }))).verdict, "pass");
  });

  it("stdout noise is part with the code, and a canary the line printed is masked", async () => {
    const c = await proto(mk({ stdoutNoise: { count: 3, first: "token sm-canary-x ready" } }));
    assert.equal(c.verdict, "part");
    const e = c.evidence.find((x) => x.code === "protocol.stdout-noise")!;
    assert.match(e.outcome, /wrote 3 non-JSON-RPC line\(s\) to stdout \(first: token <canary> ready\)/);
    assert.ok(!JSON.stringify(c).includes("sm-canary-x"));
  });

  it("an invalid tools/call result is part with the code, naming the tool and the reason", async () => {
    const c = await proto(mk({ invalidResults: { count: 2, samples: ["t: content.0.type: Invalid input"] } }));
    assert.equal(c.verdict, "part");
    assert.match(c.evidence.find((x) => x.code === "protocol.invalid-result")!.outcome, /2 tools\/call result\(s\) were not valid MCP \(t: content\.0\.type: Invalid input\)/);
    assert.match(c.summary, /1? ?invalid tool result\(s\)|2 invalid tool result\(s\)/);
  });

  it("a real schema problem still fails, whatever else was seen", async () => {
    const ctx = mk({ stdoutNoise: { count: 1, first: "x" } });
    (ctx.session.tools as { name: string }[])[0]!.name = "bad name!";
    assert.equal((await proto(ctx)).verdict, "fail");
  });
});
