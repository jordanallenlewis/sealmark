import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { FAILURE_VETO } from "../packs/net.js";
import { describe as describeCore, rejectionKind, runCore, variantsFor, type CoreCtx } from "../packs/core.js";
import { runHarness } from "../run.js";
import type { CheckResult, PackId, RunResult, ServerSpec } from "../types.js";
import { quiet } from "./helpers.js";

// Round 5, G4: robust-input does not count a failed upstream request or an unhandled runtime error as a clean rejection, and it malforms
// nested items and a second wrong type.

const TOY = fileURLToPath(new URL("../toy/robust-r5.js", import.meta.url));
const spec = (mode: string): ServerSpec => ({ command: process.execPath, args: [TOY, "--mode", mode], env: {} });
const cache = new Map<string, Promise<RunResult>>();
const run = (mode: string): Promise<RunResult> => {
  let p = cache.get(mode);
  if (!p) cache.set(mode, (p = runHarness({ config: { name: `robust-r5-${mode}`, version: "0.0.1", server: spec(mode) }, packs: ["core"] as PackId[], packsExplicit: true, timeoutProbeSec: 6, log: quiet })));
  return p;
};
/** Start every mode at once: the suite runs on a loaded machine, and a toy run is mostly waiting. */
const startAll = (modes: string[]): void => modes.forEach((m) => void run(m).catch(() => {}));
const robust = (r: RunResult): CheckResult => r.checks.find((c) => c.id === "robust-input")!;
const codes = (c: CheckResult) => c.evidence.map((e) => e.code);

describe("robust-input on the round-5 toy servers", { timeout: 600_000 }, () => {
  before(() => startAll(["downstream", "typeerror", "nested", "strict"]));
  it("downstream: an error that is only a failed upstream request is not a clean rejection", async () => {
    const c = robust(await run("downstream"));
    assert.equal(c.verdict, "part", JSON.stringify(c));
    assert.ok(codes(c).includes("robust.lenient-downstream"));
    assert.ok(!codes(c).includes("robust.internal-error"));
    assert.match(c.summary, /reply\(ies\) show the invalid argument was used downstream/);
    assert.doesNotMatch(c.summary, /rejected cleanly/);
    const e = c.evidence.find((x) => x.code === "robust.lenient-downstream")!;
    assert.equal(e.tool, "fetch_page");
    assert.match(e.outcome, /the server used the invalid argument \(an upstream request was attempted with it\) and that request failed/);
    assert.ok(c.evidence.every((x) => x.tool !== "add_entries" || x.code === undefined), "the validating tool is not blamed");
  });

  it("typeerror: an unhandled TypeError is an internals leak, not a rejection", async () => {
    const c = robust(await run("typeerror"));
    assert.equal(c.verdict, "part", JSON.stringify(c));
    assert.ok(codes(c).includes("robust.internal-error"));
    assert.match(c.summary, /unhandled runtime error\(s\)/);
    assert.doesNotMatch(c.summary, /rejected cleanly/);
    assert.match(c.evidence.find((x) => x.code === "robust.internal-error")!.outcome, /an unhandled runtime error, not a validation decision: .*TypeError/);
  });

  it("nested: a string in place of an array of objects, and an item that lacks a required field, are accepted", async () => {
    const c = robust(await run("nested"));
    assert.equal(c.verdict, "part", JSON.stringify(c));
    const lenient = c.evidence.filter((e) => e.code === "robust.lenient");
    assert.deepEqual(lenient.map((e) => e.probe.split(": ")[1]).sort(), ["a string in place of the array of objects", "one array item lacks a required field"]);
    assert.deepEqual(lenient.find((e) => /lacks a required field/.test(e.probe))!.args, { entries: [{ kind: "x" }] });
    assert.ok(lenient.every((e) => e.tool === "add_entries"));
  });

  it("near miss, strict: a server that validates every argument and names it passes, and every reply is a clean rejection", async () => {
    const c = robust(await run("strict"));
    assert.equal(c.verdict, "pass", JSON.stringify(c.evidence));
    assert.match(c.summary, /\d+ invalid call\(s\) rejected cleanly/);
    assert.ok(!codes(c).some((x) => x === "robust.lenient" || x === "robust.lenient-downstream" || x === "robust.internal-error"));
  });
});

describe("rejectionKind", () => {
  const t = { name: "fetch_page", inputSchema: { type: "object", properties: { url: { type: "string" }, timeout: { type: "number" } }, required: ["url"] } } as unknown as ToolInfo;

  it("a failed fetch is downstream, using the net pack's failed-fetch vocabulary", () => {
    for (const text of ["fetch failed: connect ECONNREFUSED 127.0.0.1:1", "getaddrinfo ENOTFOUND sm-not-a-valid-value", "request timed out", "unable to verify the first certificate"]) {
      assert.equal(FAILURE_VETO.test(text), true, text);
      assert.equal(rejectionKind(text, t, { url: 12345 }), "downstream", text);
    }
  });

  it("an unhandled runtime error is internal, whichever runtime it came from", () => {
    for (const text of ["TypeError: url.split is not a function", "Cannot read properties of undefined (reading 'split')", "undefined is not an object (evaluating 'a.b')", "null is not an object", "AttributeError: 'int' object has no attribute 'split'", "KeyError: 'url'", "'NoneType' object is not subscriptable", "x is not a function"]) {
      assert.equal(rejectionKind(text, t), "internal", text);
    }
    // Even when the message happens to name the argument: it is the runtime talking, not a validation decision.
    assert.equal(rejectionKind('TypeError [ERR_INVALID_ARG_TYPE]: The "url" argument must be of type string. Received type number', t), "internal");
  });

  it("near miss: a reply that names the argument is a validation decision, whatever else it mentions", () => {
    assert.equal(rejectionKind("url must be a string", t), "clean");
    assert.equal(rejectionKind("Invalid arguments: timeout must be a number (timed out waiting for a number)", t), "clean");
    assert.equal(rejectionKind("Input validation error: url is required", t), "clean");
    assert.equal(rejectionKind("Error executing tool search_reddit: 7 validation errors for call[search_reddit]\nquery\n  Input should be a valid string [type=string_type, input_value=None, input_type=NoneType]", t), "clean");
    assert.equal(rejectionKind("Invalid params: expected string for the argument", t, { url: 12345 }), "clean");
  });

  it("near miss: an ordinary refusal with none of the vocabularies is a clean rejection", () => {
    for (const text of ["text must be a string", "Invalid input", "arguments rejected", ""]) assert.equal(rejectionKind(text, t), "clean", text);
  });
});

describe("robust-input on a scripted session", () => {
  const reply = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: true, text, elapsedMs: 1, timedOut: false, closed: false, ...o });
  const mk = (name: string, properties: Record<string, unknown>, required: string[] = []): ToolInfo => ({ name, description: `${name} does a thing`, inputSchema: { type: "object", properties, required } }) as ToolInfo;
  function ctxFor(tools: ToolInfo[], call: (n: string, a: Record<string, unknown>) => CallResult): CoreCtx {
    const session = {
      tools,
      serverInfo: { name: "stub", version: "1.0.0" },
      capabilities: {},
      prompts: [],
      resources: [],
      listErrors: [],
      async call(n: string, a: Record<string, unknown>) {
        return call(n, a);
      },
      async alive() {
        return true;
      },
    } as unknown as McpSession;
    return { session, canaries: ["sm-canary-x"], seen: [], hangMs: 100 };
  }
  const check = async (ctx: CoreCtx) => (await runCore(ctx)).find((c) => c.id === "robust-input")!;
  const text = { text: { type: "string" } };

  it("a thrown runtime error that arrives as a JSON-RPC error (no isError text) is internal too", async () => {
    const c = await check(ctxFor([mk("t", text, ["text"])], () => reply("", { rpcError: "MCP error -32603: Cannot read properties of undefined (reading 'trim')" })));
    assert.equal(c.verdict, "part");
    assert.ok(codes(c).includes("robust.internal-error"));
  });

  it("a protocol-level validation error that names the parameter is a clean rejection", async () => {
    const c = await check(ctxFor([mk("t", text, ["text"])], () => reply("", { rpcError: "MCP error -32602: Invalid arguments for tool t: text must be a string" })));
    assert.equal(c.verdict, "pass");
  });

  it("downstream and internal replies are counted apart in the summary, with the leak and lenient counts", async () => {
    let n = 0;
    const c = await check(ctxFor([mk("t", text, ["text"])], () => {
      n++;
      return n === 1 ? reply("connect ECONNREFUSED 127.0.0.1:1") : n === 2 ? reply("TypeError: x is not a function") : n === 3 ? reply("ok", { isError: false }) : reply("text must be a string");
    }));
    assert.equal(c.verdict, "part");
    assert.equal(c.summary, "0 internals leak(s), 1 invalid call(s) accepted, 1 reply(ies) show the invalid argument was used downstream, 1 unhandled runtime error(s)");
  });

  it("the nested variants: an array-of-object parameter gets a string and an item that lacks a required field", () => {
    const entries = { type: "array", items: { type: "object", properties: { name: { type: "string" }, kind: { type: "string" }, n: { type: "integer" } }, required: ["name", "kind", "n"] } };
    const { variants } = variantsFor(mk("add", { entries, note: { type: "string" } }, ["entries"]), true);
    const by = (label: string) => variants.find((v) => v.label === label)!;
    assert.deepEqual(by("a string in place of the array of objects").args, { entries: "not-a-valid-value" });
    assert.deepEqual(by("one array item lacks a required field").args, { entries: [{ kind: "x", n: 1 }] });
    assert.deepEqual(by("every string argument is an object").args, { note: { x: 1 } });
    assert.ok(variants.every((v) => !v.valid));
  });

  it("near miss: no nested variant for an optional array, for items without required fields (one variant only), or for an array of strings", () => {
    const items = { type: "array", items: { type: "object", properties: { name: { type: "string" } } } };
    assert.ok(!variantsFor(mk("add", { entries: items, note: { type: "string" } }, ["note"]), true).variants.some((v) => /array/.test(v.label) && /objects|lacks/.test(v.label)));
    const noRequired = variantsFor(mk("add", { entries: items }, ["entries"]), true).variants.map((v) => v.label);
    assert.ok(noRequired.includes("a string in place of the array of objects"));
    assert.ok(!noRequired.includes("one array item lacks a required field"));
    const strings = variantsFor(mk("add", { names: { type: "array", items: { type: "string" } } }, ["names"]), true).variants.map((v) => v.label);
    assert.ok(!strings.includes("a string in place of the array of objects"));
  });

  it("a string parameter gets a second wrong type (an object); an enum of strings and a number do not", () => {
    const labels = (p: Record<string, unknown>) => variantsFor(mk("t", { a: p }, ["a"]), true).variants.map((v) => v.label);
    assert.ok(labels({ type: "string" }).includes("every string argument is an object"));
    assert.ok(labels({ type: "string", enum: ["x", "y"] }).includes("every string argument is an object"));
    assert.ok(!labels({ type: "number" }).includes("every string argument is an object"));
  });

  it("describe() names both rules and the extra calls", () => {
    const doc = describeCore().find((c) => c.id === "robust-input")!;
    assert.ok(doc.probes.some((p) => p.id === "robust.lenient-downstream"));
    assert.ok(doc.probes.some((p) => p.id === "robust.internal-error"));
    assert.ok(doc.probes.some((p) => p.id === "nested-string" && /one extra call/.test(p.text)));
    assert.match(doc.falsePositive, /robust\.lenient-downstream/);
    assert.match(doc.falsePositive, /robust\.internal-error/);
  });

  it("secret-echo says how many captured replies were successful results", async () => {
    const c = (await runCore(ctxFor([mk("t", text, ["text"])], () => reply("text must be a string")))).find((x) => x.id === "secret-echo")!;
    assert.equal(c.verdict, "pass");
    assert.match(c.summary, /and 5 captured response\(s\), 0 of them successful result\(s\)$/);
    let n = 0;
    const some = (await runCore(ctxFor([mk("t", text, ["text"])], () => (++n === 3 ? reply("fine", { isError: false }) : reply("text must be a string"))))).find((x) => x.id === "secret-echo")!;
    assert.match(some.summary, /5 captured response\(s\), 1 of them successful result\(s\)$/);
  });
});
