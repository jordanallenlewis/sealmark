import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import { McpSession, type CallResult, type ToolInfo } from "../mcp.js";
import { pack, inScope, scopeCorpus, type ScopeSettings } from "../packs/scope.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, PackCtx, PackId } from "../types.js";
import { quiet } from "./packctx.js";

// Round 6 (design 3.3, package P4): the scope pack against a hand-built PackCtx with an in-memory stub and a scripted session, then against the
// stdio toy (no stub: the toy's trace file shows what got through the guard). The real stub arrives with the harness package.

const TOOL: ToolInfo = {
  name: "describe_table",
  description: "Describes one table",
  inputSchema: { type: "object", properties: { table: { type: "string" } }, required: ["table"] },
} as ToolInfo;

const reply = (text: string, isError = false): CallResult => ({ isError, text, elapsedMs: 1, timedOut: false, closed: false });
const ok = (text = "columns: id, name") => reply(text);
const no = (text = "forbidden") => reply(text, true);

/** An in-memory UpstreamStub: the requests the scripted server "forwarded". */
class FakeUpstream {
  private reqs: { id: number; text: string }[] = [];
  forward(text: string): void {
    this.reqs.push({ id: this.reqs.length + 1, text });
  }
  mark(): number {
    return this.reqs.length;
  }
  find(needle: string, since = 0): unknown[] {
    return this.reqs.filter((r) => r.id > since && r.text.toLowerCase().includes(needle.toLowerCase()));
  }
  get count(): number {
    return this.reqs.length;
  }
}

interface Fake {
  /** What the scripted server does with an identifier: whether it forwards it to the backend and what it answers. */
  behave(id: string): { forward: boolean; answer: CallResult };
}

const defaults: ScopeSettings = { tools: [{ tool: "describe_table", param: "table" }], allow: ["sales.public.orders"], deny: ["hr.private.salaries"], separator: ".", case: "insensitive" };

/** The reference server: in scope by the harness's own rule is forwarded and answered, everything else is refused. */
const reference = (s: ScopeSettings): Fake => ({ behave: (id) => (inScope(id, s) ? { forward: true, answer: ok() } : { forward: false, answer: no("refused: not available. Use list_tables instead.") }) });

function build(o: { scope?: Partial<ScopeSettings>; fake?: Fake; stub?: boolean; tools?: ToolInfo[]; over?: Record<string, unknown> } = {}) {
  const scope = { ...defaults, ...o.scope };
  const fake = o.fake ?? reference(scope);
  const stub = o.stub === false ? undefined : new FakeUpstream();
  const sent: string[] = [];
  const session = {
    tools: o.tools ?? [TOOL],
    closed: false,
    async call(_name: string, args: Record<string, unknown>): Promise<CallResult> {
      const id = String(args.table);
      sent.push(id);
      const b = fake.behave(id);
      if (b.forward) stub?.forward(JSON.stringify({ sql: `describe ${id}` }));
      return b.answer;
    },
    async close() {},
  } as unknown as McpSession;
  const tools = o.tools ?? [TOOL];
  const config = { ...legacyEffectiveConfig({ config: { name: "fake", version: "0", server: { command: "x" } }, packs: ["core"], packsExplicit: true, timeoutProbeSec: 2 }), scope, ...(o.over ?? {}) };
  const ctx = { pack: pack.id, config, tools, classification: classifyTools({ tools }).classification, open: async () => session, active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet, ...(stub ? { upstream: stub } : {}) } as unknown as PackCtx;
  return { ctx, stub, sent, scope };
}

const runPack = async (ctx: PackCtx): Promise<CheckResult> => {
  const out = await pack.run(ctx);
  assert.equal(out.length, 1);
  assert.equal(out[0].id, "scope-escape");
  assert.equal(out[0].pack, "scope");
  assert.equal(out[0].critical, true);
  return out[0];
};
const codes = (c: CheckResult): string[] => c.evidence.map((e) => e.code ?? "");

describe("scope-escape with an upstream stub", () => {
  it("good: every out-of-scope identifier is refused and none reaches the stub -> pass", async () => {
    const { ctx, stub, sent } = build();
    const c = await runPack(ctx);
    assert.equal(c.verdict, "pass", c.summary);
    const n = scopeCorpus(defaults).length;
    assert.match(c.summary, new RegExp(`^${n} out-of-scope identifier\\(s\\) were refused and none reached the upstream`));
    assert.ok(c.evidence.every((e) => e.verifiedBy === ("upstream" as string)));
    assert.equal(codes(c).filter((x) => x === "scope.refused").length, n);
    assert.equal(codes(c)[0], "scope.control");
    // Only the control and the case-control were forwarded: the stub saw two requests, none of them out of scope.
    assert.equal(stub!.count, 2);
    assert.equal(sent.length, 1 + 1 + n);
    assert.deepEqual(c.coverage?.probed, ["describe_table"]);
    assert.equal(c.coverage?.validCalls, 1 + n);
  });

  it("leaked: an out-of-scope identifier reaches the stub -> fail, naming the family", async () => {
    const s = defaults;
    const fake: Fake = { behave: (id) => (/orders_sm/i.test(id) ? { forward: true, answer: ok() } : reference(s).behave(id)) };
    const { ctx } = build({ fake });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "fail", c.summary);
    assert.match(c.summary, /describe_table sibling/);
    const leaked = c.evidence.filter((e) => e.code === "scope.leaked");
    // The upper-case sibling reaches the stub too (the stub matches case-insensitively).
    assert.deepEqual(leaked.map((e) => e.probe.split(":")[0]), ["describe_table.table sibling", "describe_table.table case"]);
    assert.match(leaked[0].outcome, /reached the upstream/);
  });

  it("refused wins over a quiet stub only when the reply refuses; a reply that is neither refusal nor forwarded is served-locally -> part", async () => {
    const fake: Fake = { behave: (id) => (/^sales\.public$/i.test(id) ? { forward: false, answer: ok("tables in sales.public: orders, customers") } : reference(defaults).behave(id)) };
    const { ctx } = build({ fake });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "part", c.summary);
    assert.match(c.summary, /answered without it \(served from the server itself\?\): describe_table container/);
    assert.ok(codes(c).includes("scope.served-locally"));
    assert.ok(!codes(c).includes("scope.leaked"));
  });

  it("a leak outranks a local answer", async () => {
    const fake: Fake = { behave: (id) => (/^sales\.public$/i.test(id) ? { forward: false, answer: ok() } : /ordersx/i.test(id) ? { forward: true, answer: ok() } : reference(defaults).behave(id)) };
    const c = await runPack(build({ fake }).ctx);
    assert.equal(c.verdict, "fail");
  });

  it("no control: the allowed name never reaches the stub -> inconclusive, and no escape probe is sent", async () => {
    const fake: Fake = { behave: () => ({ forward: false, answer: no() }) };
    const { ctx, sent } = build({ fake });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /no control call succeeded/);
    assert.match(c.summary, /scope\.allow/);
    assert.deepEqual(codes(c), ["scope.control-failed"]);
    assert.deepEqual(sent, ["sales.public.orders"]);
    assert.deepEqual(c.coverage?.probed, []);
    assert.equal(c.coverage?.validCalls, 0);
    assert.match(c.coverage?.notCovered[0]?.reason ?? "", /no control call succeeded/);
  });

  it("a control that was answered but never reached the stub is not a control", async () => {
    const fake: Fake = { behave: () => ({ forward: false, answer: ok("cached") }) };
    const c = await runPack(build({ fake }).ctx);
    assert.equal(c.verdict, "inconclusive");
    assert.match(c.evidence[0].outcome, /nothing reached the upstream/);
  });

  it("up to three exact controls are tried until one gets through", async () => {
    const s: Partial<ScopeSettings> = { allow: ["sales.public.nope", "sales.public.orders", "sales.public.events"] };
    const fake: Fake = { behave: (id) => (/orders$/i.test(id) ? { forward: true, answer: ok() } : /^sales\.public\.nope/i.test(id) ? { forward: false, answer: no("not found") } : reference({ ...defaults, ...s }).behave(id)) };
    const { ctx, sent } = build({ scope: s, fake });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "pass", c.summary);
    assert.deepEqual(sent.slice(0, 2), ["sales.public.nope", "sales.public.orders"]);
    assert.deepEqual(codes(c).slice(0, 2), ["scope.control-failed", "scope.control"]);
  });

  it("strict-case near miss: the upper-case spelling is refused -> still pass, with the note and never a fail", async () => {
    const strictServer: Fake = { behave: (id) => (id === "sales.public.orders" ? { forward: true, answer: ok() } : { forward: false, answer: no("refused: not available. Use list_tables instead.") }) };
    const c = await runPack(build({ fake: strictServer }).ctx);
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /declared case-insensitive but the upper-case spelling was refused/);
    const note = c.evidence.find((e) => e.code === "scope.case-refused");
    assert.ok(note);
    assert.match(note.outcome, /Noted, never a fail/);
  });

  it("scope.case: sensitive sends no case-control", async () => {
    const { ctx, sent } = build({ scope: { case: "sensitive" } });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "pass");
    assert.ok(!sent.includes("SALES.PUBLIC.ORDERS"));
    assert.ok(!codes(c).includes("scope.case-control"));
  });

  it("coverage counts a probe only when the reply was not a validation error", async () => {
    const fake: Fake = {
      behave: (id) => (id === "sales" ? { forward: false, answer: no("invalid input: expected a qualified table name") } : reference(defaults).behave(id)),
    };
    const c = await runPack(build({ fake }).ctx);
    assert.equal(c.verdict, "pass");
    const n = scopeCorpus(defaults).length;
    assert.equal(c.coverage?.validCalls, 1 + n - 1);
  });

  it("timeouts and closed connections are unjudged: all of them -> inconclusive", async () => {
    const timedOut = { ...no(""), timedOut: true };
    const fake: Fake = { behave: (id) => (inScope(id, defaults) ? { forward: true, answer: ok() } : { forward: false, answer: timedOut }) };
    const c = await runPack(build({ fake }).ctx);
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /no out-of-scope probe got a judgeable reply/);
    assert.ok(codes(c).includes("scope.unjudged"));
  });

  it("the prefix form works the same: a control under the prefix, escapes outside it", async () => {
    const s: Partial<ScopeSettings> = { allow: ["sales.public."] };
    const { ctx, sent } = build({ scope: s });
    const c = await runPack(ctx);
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(sent[0], /^sales\.public\.sm_control_[0-9a-f]{6}$/);
    assert.ok(!sent.includes("SALES.PUBLIC.ORDERS"), "no case-control for a prefix entry");
  });

  it("sql_tools[].args fill the other required parameters", async () => {
    const tool = { name: "describe_table", description: "x", inputSchema: { type: "object", properties: { table: { type: "string" }, tenant: { type: "object" } }, required: ["table", "tenant"] } } as ToolInfo;
    const { ctx } = build({ tools: [tool] });
    const first = await runPack(ctx);
    assert.equal(first.verdict, "inconclusive", "an object the harness cannot invent is not probed");
    assert.match(first.coverage?.notCovered[0]?.reason ?? "", /required parameters \(tenant\)/);
    const withArgs = build({ tools: [tool] });
    (withArgs.ctx as { sqlTools?: unknown }).sqlTools = [{ tool: "describe_table", arg: "table", args: { tenant: { id: 1 } } }];
    const second = await runPack(withArgs.ctx);
    assert.equal(second.verdict, "pass", second.summary);
  });

  it("a scope.tools param that is not a string parameter is listed, not probed", async () => {
    const c = await runPack(build({ scope: { tools: [{ tool: "describe_table", param: "nope" }] } }).ctx);
    assert.equal(c.verdict, "inconclusive");
    assert.match(c.coverage?.notCovered[0]?.reason ?? "", /has no string parameter named "nope" \(its string parameters: table\)/);
  });

  it("checks.scope-escape.enabled: false reports n/a; severity advisory removes the critical flag", async () => {
    const off = (await pack.run(build({ over: { checks: { "scope-escape": { enabled: false, severity: null } } } }).ctx))[0];
    assert.equal(off.verdict, "na");
    assert.match(off.summary, /disabled by config/);
    const adv = (await pack.run(build({ over: { checks: { "scope-escape": { enabled: true, severity: "advisory" } } } }).ctx))[0];
    assert.equal(adv.critical, false);
    assert.equal(adv.advisory, true);
  });
});

describe("scope-escape without a stub (judged on the reply alone)", () => {
  it("refusals pass and the summary says so", async () => {
    const c = await runPack(build({ stub: false }).ctx);
    assert.equal(c.verdict, "pass", c.summary);
    assert.match(c.summary, /\(no upstream stub: judged on responses\)/);
    assert.ok(c.evidence.every((e) => e.verifiedBy === "response"));
  });

  it("a success-looking reply to an out-of-scope name is a leak", async () => {
    const fake: Fake = { behave: (id) => (/^sales\.public$/i.test(id) ? { forward: false, answer: ok() } : reference(defaults).behave(id)) };
    const c = await runPack(build({ stub: false, fake }).ctx);
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /describe_table container/);
    assert.match(c.summary, /no upstream stub: judged on responses/);
  });

  it("a control that is refused is inconclusive", async () => {
    const c = await runPack(build({ stub: false, fake: { behave: () => ({ forward: false, answer: no() }) } }).ctx);
    assert.equal(c.verdict, "inconclusive");
  });
});

describe("applies()", () => {
  it("names the key to add", () => {
    const base = build().ctx;
    const withScope = (scope: unknown, tools = base.tools): PackCtx => ({ ...base, tools, config: { ...base.config, scope } as never });
    assert.deepEqual(pack.applies(withScope({})), { ok: false, reason: "no scope.tools entry: declare the tool and parameter that take an identifier (scope.tools: [{tool, param}]) and scope.allow" });
    assert.deepEqual(pack.applies(withScope({ tools: [{ tool: "other", param: "t" }], allow: ["a.b"] })), { ok: false, reason: "no scope.tools entry names a tool the server declares" });
    assert.deepEqual(pack.applies(withScope({ tools: [{ tool: "describe_table", param: "table" }], allow: [] })), { ok: false, reason: 'scope.allow is empty: list at least one identifier the server may serve (an entry ending in "." is a prefix)' });
    assert.deepEqual(pack.applies(withScope(defaults)), { ok: true });
  });

  it("is a candidate pack id the harness will register", () => {
    assert.equal(pack.id, "scope" as PackId);
  });
});

// ---------------------------------------------------------------------------------------------------------
// The stdio toy: no stub, so the verdict rests on the reply and the toy's trace file shows what got through its guard.
// ---------------------------------------------------------------------------------------------------------

const TOY = fileURLToPath(new URL("../toy/scope-r6.js", import.meta.url));
const dirs: string[] = [];
const sessions: McpSession[] = [];
after(async () => {
  for (const s of sessions) await s.close().catch(() => {});
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function onToy(mode: string, allow: string[]): Promise<{ check: CheckResult; trace: string[]; scope: ScopeSettings }> {
  const dir = mkdtempSync(join(tmpdir(), "sm-scope-r6-"));
  dirs.push(dir);
  const traceFile = join(dir, "trace.jsonl");
  const args = [TOY, "--mode", mode, ...allow.flatMap((a) => ["--allow", a]), "--deny", "hr.private.salaries", "--trace", traceFile];
  const spec = { command: process.execPath, args, env: {} };
  const open = async (): Promise<McpSession> => {
    const s = await McpSession.open(spec, { vars: {}, dsns: {} }, { cleanCwd: true });
    sessions.push(s);
    return s;
  };
  const first = await open();
  const scope: ScopeSettings = { ...defaults, allow };
  const tools = first.tools;
  const config = { ...legacyEffectiveConfig({ config: { name: `toy-${mode}`, version: "0", server: spec }, packs: ["core"], packsExplicit: true, timeoutProbeSec: 2 }), scope };
  const ctx = { pack: pack.id, config, tools, classification: classifyTools({ tools }).classification, open, active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet } as unknown as PackCtx;
  const check = await runPack(ctx);
  let trace: string[] = [];
  try {
    trace = readFileSync(traceFile, "utf8").split("\n").filter(Boolean).map((l) => (JSON.parse(l) as { args: { table: string } }).args.table);
  } catch {
    // no call got through the guard
  }
  return { check, trace, scope };
}

describe("scope-escape on the stdio toy (no stub)", { timeout: 120_000 }, () => {
  it("good (exact): pass; the guard let through the control and the case-control only", async () => {
    const r = await onToy("good", ["sales.public.orders"]);
    assert.equal(r.check.verdict, "pass", r.check.summary);
    assert.deepEqual(r.trace, ["sales.public.orders", "SALES.PUBLIC.ORDERS"]);
  });

  it("good (prefix): pass; only the control got through", async () => {
    const r = await onToy("good", ["sales.public."]);
    assert.equal(r.check.verdict, "pass", r.check.summary);
    assert.equal(r.trace.length, 1);
    assert.match(r.trace[0], /^sales\.public\.sm_control_/);
  });

  it("strict-case: pass with the note", async () => {
    const r = await onToy("strict-case", ["sales.public.orders"]);
    assert.equal(r.check.verdict, "pass", r.check.summary);
    assert.match(r.check.summary, /upper-case spelling was refused/);
    assert.deepEqual(r.trace, ["sales.public.orders"]);
  });

  const flawed: [string, string[], RegExp][] = [
    ["prefix-loose", ["sales.public."], /prefix-abuse/],
    ["container", ["sales.public.orders"], /container/],
    ["partial", ["sales.public.orders"], /partial/],
    // Decoding only changes the verdict under a prefix entry: the decoded name is then an allowed one (an exact entry has no neighbour a decoder could reach).
    ["encoded", ["sales.public."], /separator-encoded|quoted/],
  ];
  for (const [mode, allow, family] of flawed) {
    it(`${mode}: fail, and the trace shows the escape the guard let through`, async () => {
      const r = await onToy(mode, allow);
      assert.equal(r.check.verdict, "fail", r.check.summary);
      assert.match(r.check.summary, family);
      const escaped = r.trace.filter((t) => !inScope(t, r.scope));
      assert.ok(escaped.length > 0, `trace: ${JSON.stringify(r.trace)}`);
      for (const e of r.check.evidence.filter((x) => x.code === "scope.leaked")) assert.ok(e.excerpt);
    });
  }

  it("refuse-all: every control fails -> inconclusive, never pass", async () => {
    const r = await onToy("refuse-all", ["sales.public.orders"]);
    assert.equal(r.check.verdict, "inconclusive", r.check.summary);
    assert.deepEqual(r.trace, []);
  });

  it("deadend: the scope rule holds -> pass (the wording is refusal-quality's business)", async () => {
    const r = await onToy("deadend", ["sales.public.orders"]);
    assert.equal(r.check.verdict, "pass", r.check.summary);
  });
});
