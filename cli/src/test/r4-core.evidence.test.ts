// Round 4, package core: what the core evidence says it did (robust-input tool count, the tool that leaked a canary, task-only tools).
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { runCore, type CoreCtx } from "../packs/core.js";
import { requiresTask } from "../packs/shared.js";
import { runValidCalls } from "../probes.js";
import { runHarness } from "../run.js";
import type { CheckResult, PackId } from "../types.js";
import { quiet, toyConfig } from "./helpers.js";

const reply = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: false, text, elapsedMs: 1, timedOut: false, closed: false, ...o });
const rejected = reply("text must be a string", { isError: true });
/** What a task-only server answers to a plain tools/call, before it reads the arguments. */
const taskError = reply("", { isError: true, rpcError: "MCP error -32600: this tool requires task-based execution" });

function stub(o: { tools: ToolInfo[]; call?: (name: string, args: Record<string, unknown>) => CallResult }, ctxExtra: Partial<CoreCtx> = {}) {
  const calls: [string, Record<string, unknown>][] = [];
  const session = {
    tools: o.tools,
    serverInfo: { name: "stub", version: "1.0.0" },
    capabilities: {},
    prompts: [],
    resources: [],
    listErrors: [],
    async call(name: string, args: Record<string, unknown>) {
      calls.push([name, args]);
      return (o.call ?? (() => rejected))(name, args);
    },
    async alive() {
      return true;
    },
  } as unknown as McpSession;
  const ctx: CoreCtx = { session, canaries: ["sm-canary-x"], seen: [], hangMs: 100, ...ctxExtra };
  return { session, ctx, calls };
}
const mk = (name: string, properties: Record<string, Record<string, unknown>>, required: string[] = [], extra: Record<string, unknown> = {}): ToolInfo =>
  ({ name, description: `${name} does a thing`, inputSchema: { type: "object", properties, required }, ...extra }) as ToolInfo;
const find = (checks: CheckResult[], id: string) => checks.find((c) => c.id === id)!;
const text = { text: { type: "string" } };

describe("robust-input evidence counts the tools that received invalid calls", () => {
  it("one tool with arguments among tools that were never called: 5 calls across 1 tool, not across every tool", async () => {
    const { ctx, calls } = stub({
      tools: [mk("a", text, ["text"]), mk("ping", {}, [], { annotations: { readOnlyHint: true } }), mk("reboot", {})],
      call: (n) => (n === "ping" ? reply("pong") : rejected),
    });
    const robust = find(await runCore(ctx), "robust-input");
    assert.equal(robust.verdict, "pass");
    assert.equal(calls.filter(([n]) => n === "a").length, 5);
    const line = robust.evidence.find((e) => /invalid call\(s\) across/.test(e.probe))!;
    assert.equal(line.probe, "5 invalid call(s) across 1 tool(s)");
  });

  it("two tools with arguments: 10 calls across 2 tools", async () => {
    const { ctx } = stub({ tools: [mk("a", text, ["text"]), mk("b", text, ["text"]), mk("c", {})] });
    const robust = find(await runCore(ctx), "robust-input");
    assert.ok(robust.evidence.some((e) => e.probe === "10 invalid call(s) across 2 tool(s)"));
  });
});

describe("secret-echo names the tool that leaked", () => {
  const leak = (a: Record<string, unknown>) => reply(`bad input; env=${JSON.stringify({ SEALMARK_CANARY: "sm-canary-x", HOME: "/home/someone" })} args=${JSON.stringify(a)}`, { isError: true });

  it("a canary in an answer to a malformed call: evidence.tool and args are those of the call, the surrounding text is not quoted", async () => {
    const { ctx } = stub({ tools: [mk("quiet", text, ["text"]), mk("leaky", text, ["text"])], call: (n, a) => (n === "leaky" ? leak(a) : rejected) });
    const secret = find(await runCore(ctx), "secret-echo");
    assert.equal(secret.verdict, "fail");
    const e = secret.evidence[0];
    assert.equal(e.code, "secret.found");
    assert.equal(e.tool, "leaky");
    assert.deepEqual(e.args, {});
    assert.match(secret.summary, /tool leaky/);
    assert.equal(e.excerpt, "SEALMARK_CANARY=<canary>");
    assert.doesNotMatch(JSON.stringify(secret), /someone|sm-canary-x/);
  });

  it("a canary from a probes: valid call is attributed through its masked excerpt (the raw text only reaches seen)", async () => {
    const { ctx } = stub(
      { tools: [mk("echo", text, ["text"]), mk("other", text, ["text"])] },
      {
        seen: ["env SEALMARK_CANARY=sm-canary-x"],
        validCalls: [
          { tool: "other", args: { text: "hi" }, text: "fine", isError: false },
          { tool: "echo", args: { text: "hello" }, text: "env SEALMARK_CANARY=<canary>", isError: false },
        ],
      },
    );
    const e = find(await runCore(ctx), "secret-echo").evidence[0];
    assert.equal(e.tool, "echo");
    assert.deepEqual(e.args, { text: "hello" });
  });

  it("a canary in the tool listing is not blamed on any tool", async () => {
    const { ctx } = stub({ tools: [mk("t", text, ["text"], { description: "uses key sm-canary-x for access" })] });
    const secret = find(await runCore(ctx), "secret-echo");
    assert.equal(secret.verdict, "fail");
    assert.equal(secret.evidence[0].tool, undefined);
    assert.doesNotMatch(secret.summary, /tool /);
  });

  it("near miss: no leak, no attribution, still a pass", async () => {
    const { ctx } = stub({ tools: [mk("t", text, ["text"])] });
    const secret = find(await runCore(ctx), "secret-echo");
    assert.equal(secret.verdict, "pass");
    assert.equal(secret.evidence[0].tool, undefined);
  });

  it("the toy that echoes its environment on bad input: the leak names the tool", async () => {
    const r = await runHarness({ config: toyConfig("echoenv"), packs: ["core"] as PackId[], packsExplicit: true, timeoutProbeSec: 6, log: quiet });
    const secret = r.checks.find((c) => c.id === "secret-echo")!;
    assert.equal(secret.verdict, "fail");
    assert.equal(secret.evidence[0].tool, "query");
  });
});

describe("tools that require task-based execution", () => {
  const taskTool = (taskSupport: string) => mk("job", text, ["text"], { execution: { taskSupport } });

  it("requiresTask reads execution.taskSupport", () => {
    assert.equal(requiresTask(taskTool("required")), true);
    for (const v of ["optional", "forbidden"]) assert.equal(requiresTask(taskTool(v)), false);
    assert.equal(requiresTask(mk("plain", text)), false);
  });

  it("a required-task tool is sent no variants, is listed as not covered, and does not touch the verdict or the counts", async () => {
    const { ctx, calls } = stub({ tools: [mk("a", text, ["text"]), taskTool("required")], call: (n) => (n === "job" ? taskError : rejected) });
    const robust = find(await runCore(ctx), "robust-input");
    assert.equal(robust.verdict, "pass");
    assert.deepEqual(calls.map(([n]) => n), ["a", "a", "a", "a", "a"], "no call reaches the task-only tool");
    assert.deepEqual(robust.coverage?.notCovered, [{ tool: "job", reason: "requires task-based execution, which the harness does not use" }]);
    assert.equal(robust.summary, "5 invalid call(s) rejected cleanly");
    assert.ok(robust.evidence.some((e) => e.probe === "5 invalid call(s) across 1 tool(s)"));
  });

  it("near miss: optional and forbidden task support are probed like any tool", async () => {
    for (const v of ["optional", "forbidden"]) {
      const { ctx, calls } = stub({ tools: [taskTool(v)] });
      const robust = find(await runCore(ctx), "robust-input");
      assert.equal(calls.length, 5, v);
      assert.deepEqual(robust.coverage?.notCovered, [], v);
      assert.equal(robust.verdict, "pass", v);
    }
  });

  it("a server whose only tools are task-only: robust-input is not applicable, and says why", async () => {
    const { ctx, calls } = stub({ tools: [taskTool("required")], call: () => taskError });
    const robust = find(await runCore(ctx), "robust-input");
    assert.equal(calls.length, 0);
    assert.equal(robust.verdict, "na");
    assert.match(robust.summary, /every tool requires task-based execution/);
    assert.equal(robust.coverage?.notCovered.length, 1);
  });

  it("a probes: valid call that a task-only tool refuses with an error is not counted as a valid call", async () => {
    const tools = [mk("job", text, ["text"], { execution: { taskSupport: "required" } }), mk("echo", text, ["text"])];
    const { session } = stub({ tools, call: (n) => (n === "job" ? taskError : reply("echo hi")) });
    const classification = classifyTools({ tools }).classification;
    const v = await runValidCalls({
      session,
      tools,
      classification,
      active: false,
      probes: [
        { tool: "job", args: { text: "hi" } },
        { tool: "echo", args: { text: "hi" } },
      ],
    });
    // The errored-call rule (probes.ts: counted) already covers it; this pins that a -32600 task error is no coverage.
    assert.equal(v.validCalls, 1);
    assert.deepEqual(v.countedTools, ["echo"]);
    assert.equal(v.calls[0].counted, false);
    assert.ok(v.warnings.some((w) => /probe .* returned an error and does not count toward coverage/.test(w)));
  });
});
