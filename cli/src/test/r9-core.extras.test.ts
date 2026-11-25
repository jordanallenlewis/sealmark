import assert from "node:assert/strict";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { McpSession, type ExtraOutcome, type PromptInfo, type ResourceInfo } from "../mcp.js";
import { runCore } from "../packs/core.js";
import {
  describeExtras,
  MAX_EXTRA_REQUESTS,
  PROMPT_ARGUMENT_VALUE,
  promptsGet,
  resourcesRead,
  UNKNOWN_PROMPT_NAME,
  UNKNOWN_RESOURCE_URI,
  type ExtrasSession,
} from "../packs/extras.js";
import type { CheckResult } from "../types.js";

// Round 9: the resources and prompts candidates. Unit tests drive a hand-built session (every reply chosen by the test); the toy
// tests run the real SDK client against extras-r9 through runCore.

const OK_READ: ExtraOutcome = { ok: true, result: { contents: [{ uri: "x", text: "t" }] } };
const OK_GET: ExtraOutcome = { ok: true, result: { messages: [{ role: "user", content: { type: "text", text: "hi" } }] } };
const err = (code = -32002, message = "not found"): ExtraOutcome => ({ ok: false, message, timedOut: false, closed: false, invalid: false, code });
const CLOSED: ExtraOutcome = { ok: false, message: "Connection closed", timedOut: false, closed: true, invalid: false };
const TIMEOUT: ExtraOutcome = { ok: false, message: "Request timed out", timedOut: true, closed: false, invalid: false };
const INVALID: ExtraOutcome = { ok: false, message: "result is not valid MCP (contents: Required)", timedOut: false, closed: false, invalid: true };

interface Fake extends ExtrasSession {
  reads: string[];
  gets: { name: string; args?: Record<string, string> }[];
}

function fake(opts: {
  resources?: ResourceInfo[];
  prompts?: PromptInfo[];
  caps?: Record<string, unknown>;
  listErrors?: string[];
  closed?: boolean;
  read?: (uri: string) => ExtraOutcome;
  get?: (name: string, args?: Record<string, string>) => ExtraOutcome;
}): Fake {
  const reads: string[] = [];
  const gets: { name: string; args?: Record<string, string> }[] = [];
  return {
    capabilities: opts.caps ?? { resources: {}, prompts: {} },
    resources: opts.resources ?? [],
    prompts: opts.prompts ?? [],
    listErrors: opts.listErrors ?? [],
    ...(opts.closed ? { closed: true } : {}),
    reads,
    gets,
    async readResource(uri) {
      reads.push(uri);
      return (opts.read ?? ((u) => (u === UNKNOWN_RESOURCE_URI ? err() : OK_READ)))(uri);
    },
    async getPrompt(name, args) {
      gets.push({ name, ...(args ? { args } : {}) });
      return (opts.get ?? ((n, a) => (n === UNKNOWN_PROMPT_NAME ? err(-32602) : n === "review" && !a ? err(-32602, "missing code") : OK_GET)))(name, args);
    },
  };
}

const res = (...uris: string[]): ResourceInfo[] => uris.map((uri, i) => ({ uri, name: `r${i}` }));
const codes = (r: CheckResult): string[] => r.evidence.map((e) => e.code ?? "");

describe("resources-read (hand-built session)", () => {
  it("is advisory, never critical, in core", async () => {
    const r = await resourcesRead(fake({ resources: res("a://1") }));
    assert.equal(r.id, "resources-read");
    assert.equal(r.pack, "core");
    assert.equal(r.advisory, true);
    assert.equal(r.critical, false);
  });

  it("n/a without the capability, with an empty listing, or disabled, and then sends nothing", async () => {
    for (const s of [fake({ caps: { prompts: {} }, resources: res("a://1") }), fake({ resources: [] })]) {
      assert.equal((await resourcesRead(s)).verdict, "na");
      assert.deepEqual(s.reads, []);
    }
    const off = fake({ resources: res("a://1") });
    const r = await resourcesRead(off, { enabled: false, severity: null });
    assert.equal(r.verdict, "na");
    assert.equal(r.summary, "disabled by config");
    assert.deepEqual(off.reads, []);
  });

  it("pass: every listed resource reads and the unlisted URI is refused", async () => {
    const s = fake({ resources: res("a://1", "a://2") });
    const r = await resourcesRead(s);
    assert.equal(r.verdict, "pass", r.summary);
    assert.deepEqual(s.reads, ["a://1", "a://2", UNKNOWN_RESOURCE_URI]);
    assert.ok(codes(r).includes("resources.unknown-refused"));
  });

  it("reads at most MAX_EXTRA_REQUESTS listed resources, in listing order, and says so", async () => {
    const uris = Array.from({ length: 9 }, (_, i) => `a://${i}`);
    const s = fake({ resources: res(...uris) });
    const r = await resourcesRead(s);
    assert.deepEqual(s.reads, [...uris.slice(0, MAX_EXTRA_REQUESTS), UNKNOWN_RESOURCE_URI]);
    assert.match(r.summary, new RegExp(`the first ${MAX_EXTRA_REQUESTS} of 9 listed`));
  });

  it("fail: resources/list failed although advertised", async () => {
    const s = fake({ listErrors: ["resources/list failed: boom"] });
    const r = await resourcesRead(s);
    assert.equal(r.verdict, "fail");
    assert.deepEqual(codes(r), ["resources.list-failed"]);
    assert.deepEqual(s.reads, []);
  });

  it("a prompts/list failure does not touch resources-read", async () => {
    assert.equal((await resourcesRead(fake({ resources: res("a://1"), listErrors: ["prompts/list failed: x"] }))).verdict, "pass");
  });

  it("fail: no listed resource reads", async () => {
    const r = await resourcesRead(fake({ resources: res("a://1", "a://2"), read: () => err(-32603, "storage offline") }));
    assert.equal(r.verdict, "fail");
    assert.equal(codes(r).filter((c) => c === "resources.read-error").length, 2);
  });

  it("fail: the connection closes on a read, and nothing more is sent", async () => {
    const s = fake({ resources: res("a://1", "a://2"), read: () => CLOSED });
    const r = await resourcesRead(s);
    assert.equal(r.verdict, "fail");
    assert.deepEqual(s.reads, ["a://1"]);
    assert.deepEqual(codes(r), ["resources.read-closed"]);
  });

  it("fail: the connection closes on the unlisted URI", async () => {
    const r = await resourcesRead(fake({ resources: res("a://1"), read: (u) => (u === UNKNOWN_RESOURCE_URI ? CLOSED : OK_READ) }));
    assert.equal(r.verdict, "fail");
    assert.ok(codes(r).includes("resources.unknown-closed"));
  });

  it("part: one of two listed resources fails, times out, or is not valid MCP", async () => {
    for (const bad of [err(-32603), TIMEOUT, INVALID]) {
      const r = await resourcesRead(fake({ resources: res("a://1", "a://2"), read: (u) => (u === "a://2" ? bad : u === UNKNOWN_RESOURCE_URI ? err() : OK_READ) }));
      assert.equal(r.verdict, "part", JSON.stringify(bad));
    }
  });

  it("part: a read with no contents, a URI listed twice (read once), or the unlisted URI answered as a success or not answered", async () => {
    const empty = await resourcesRead(fake({ resources: res("a://1"), read: (u) => (u === UNKNOWN_RESOURCE_URI ? err() : { ok: true, result: { contents: [] } }) }));
    assert.equal(empty.verdict, "part");
    assert.ok(codes(empty).includes("resources.read-empty"));
    const twice = fake({ resources: res("a://1", "a://1") });
    const t = await resourcesRead(twice);
    assert.equal(t.verdict, "part");
    assert.ok(codes(t).includes("resources.duplicate-uri"));
    assert.deepEqual(twice.reads, ["a://1", UNKNOWN_RESOURCE_URI]);
    const served = await resourcesRead(fake({ resources: res("a://1"), read: () => OK_READ }));
    assert.equal(served.verdict, "part");
    assert.ok(codes(served).includes("resources.unknown-served"));
    const slow = await resourcesRead(fake({ resources: res("a://1"), read: (u) => (u === UNKNOWN_RESOURCE_URI ? TIMEOUT : OK_READ) }));
    assert.equal(slow.verdict, "part");
    assert.ok(codes(slow).includes("resources.unknown-timeout"));
  });

  it("any error code on the unlisted URI counts as a refusal", async () => {
    for (const code of [-32002, -32602, -32603, -32000]) assert.equal((await resourcesRead(fake({ resources: res("a://1"), read: (u) => (u === UNKNOWN_RESOURCE_URI ? err(code) : OK_READ) }))).verdict, "pass", String(code));
  });

  it("inconclusive when the session closed before the check (an earlier request ended it)", async () => {
    const s = fake({ resources: res("a://1"), closed: true });
    assert.equal((await resourcesRead(s)).verdict, "inconclusive");
    assert.deepEqual(s.reads, []);
  });

  it("caps the evidence at 25 lines plus one count line, and cuts long third-party URIs", async () => {
    const many = Array.from({ length: 40 }, (_, i) => `dup://${i}`);
    const r = await resourcesRead(fake({ resources: res(...many, ...many) }));
    assert.equal(r.evidence.length, 26);
    assert.equal(r.evidence.at(-1)?.code, "resources.more");
    const long = await resourcesRead(fake({ resources: res(`a://${"x".repeat(500)}`) }));
    assert.ok(long.evidence.every((e) => e.probe.length < 200 && e.outcome.length < 200));
  });
});

const P = (name: string, required: string[] = [], optional: string[] = []): PromptInfo => ({
  name,
  arguments: [...required.map((n) => ({ name: n, required: true })), ...optional.map((n) => ({ name: n }))],
});

describe("prompts-get (hand-built session)", () => {
  it("is advisory, never critical, in core", async () => {
    const r = await promptsGet(fake({ prompts: [P("summarize")] }));
    assert.equal(r.id, "prompts-get");
    assert.equal(r.pack, "core");
    assert.equal(r.advisory, true);
    assert.equal(r.critical, false);
  });

  it("n/a without the capability, with an empty listing, or disabled, and then sends nothing", async () => {
    for (const s of [fake({ caps: { resources: {} }, prompts: [P("a")] }), fake({ prompts: [] })]) {
      assert.equal((await promptsGet(s)).verdict, "na");
      assert.deepEqual(s.gets, []);
    }
    const off = fake({ prompts: [P("a")] });
    assert.equal((await promptsGet(off, { enabled: false, severity: null })).summary, "disabled by config");
    assert.deepEqual(off.gets, []);
  });

  it("pass: fixed value for required arguments only, missing argument refused, unknown name refused", async () => {
    const s = fake({ prompts: [P("summarize", [], ["style"]), P("review", ["code"], ["lang"])] });
    const r = await promptsGet(s);
    assert.equal(r.verdict, "pass", r.summary);
    assert.deepEqual(s.gets, [{ name: "summarize" }, { name: "review", args: { code: PROMPT_ARGUMENT_VALUE } }, { name: "review" }, { name: UNKNOWN_PROMPT_NAME }]);
  });

  it("no missing-argument probe when no prompt requires one", async () => {
    const s = fake({ prompts: [P("a"), P("b", [], ["x"])] });
    await promptsGet(s);
    assert.deepEqual(s.gets.map((g) => g.name), ["a", "b", UNKNOWN_PROMPT_NAME]);
  });

  it("fetches at most MAX_EXTRA_REQUESTS prompts, in listing order, and says so", async () => {
    const s = fake({ prompts: Array.from({ length: 8 }, (_, i) => P(`p${i}`)) });
    const r = await promptsGet(s);
    assert.deepEqual(s.gets.map((g) => g.name), [...Array.from({ length: MAX_EXTRA_REQUESTS }, (_, i) => `p${i}`), UNKNOWN_PROMPT_NAME]);
    assert.match(r.summary, new RegExp(`the first ${MAX_EXTRA_REQUESTS} of 8 listed`));
  });

  it("fail: prompts/list failed although advertised", async () => {
    const r = await promptsGet(fake({ listErrors: ["prompts/list failed: boom"] }));
    assert.equal(r.verdict, "fail");
    assert.deepEqual(codes(r), ["prompts.list-failed"]);
  });

  it("fail: every prompt without required arguments fails", async () => {
    const r = await promptsGet(fake({ prompts: [P("a"), P("b")], get: () => err(-32603, "templates offline") }));
    assert.equal(r.verdict, "fail");
  });

  it("fail: the connection closes, and nothing more is sent", async () => {
    const s = fake({ prompts: [P("a"), P("review", ["code"])], get: () => CLOSED });
    const r = await promptsGet(s);
    assert.equal(r.verdict, "fail");
    assert.deepEqual(s.gets.map((g) => g.name), ["a"]);
  });

  it("a prompt with required arguments that refuses the fixed value is recorded, not counted", async () => {
    const r = await promptsGet(fake({ prompts: [P("review", ["count"])], get: (n, a) => (n === "review" && a ? err(-32602, "count must be a number") : err(-32602)) }));
    assert.equal(r.verdict, "pass", r.summary);
    assert.ok(codes(r).includes("prompts.get-refused-value"));
  });

  it("but a timeout or an invalid result on such a prompt is counted", async () => {
    for (const bad of [TIMEOUT, INVALID]) {
      const r = await promptsGet(fake({ prompts: [P("a"), P("review", ["code"])], get: (n, a) => (n === "review" && a ? bad : n === "a" ? OK_GET : err(-32602)) }));
      assert.equal(r.verdict, "part", JSON.stringify(bad));
    }
  });

  it("part: a missing required argument or the unlisted name answered as a success", async () => {
    const lax = await promptsGet(fake({ prompts: [P("a"), P("review", ["code"])], get: () => OK_GET }));
    assert.equal(lax.verdict, "part");
    assert.ok(codes(lax).includes("prompts.missing-argument-served"));
    assert.ok(codes(lax).includes("prompts.unknown-served"));
  });

  it("part: no messages, a duplicate prompt name (fetched once), a duplicate argument name", async () => {
    const empty = await promptsGet(fake({ prompts: [P("a")], get: (n) => (n === "a" ? { ok: true, result: { messages: [] } } : err(-32602)) }));
    assert.equal(empty.verdict, "part");
    assert.ok(codes(empty).includes("prompts.get-empty"));
    const twice = fake({ prompts: [P("a"), P("a")] });
    const t = await promptsGet(twice);
    assert.equal(t.verdict, "part");
    assert.ok(codes(t).includes("prompts.duplicate-name"));
    assert.deepEqual(twice.gets.map((g) => g.name), ["a", UNKNOWN_PROMPT_NAME]);
    const arg = await promptsGet(fake({ prompts: [{ name: "a", arguments: [{ name: "x" }, { name: "x" }] }] }));
    assert.equal(arg.verdict, "part");
    assert.ok(codes(arg).includes("prompts.duplicate-argument"));
  });

  it("part: one of two prompts fails", async () => {
    const r = await promptsGet(fake({ prompts: [P("a"), P("b")], get: (n) => (n === "b" ? err(-32603) : n === "a" ? OK_GET : err(-32602)) }));
    assert.equal(r.verdict, "part");
  });

  it("inconclusive when the session closed before the check", async () => {
    const s = fake({ prompts: [P("a")], closed: true });
    assert.equal((await promptsGet(s)).verdict, "inconclusive");
    assert.deepEqual(s.gets, []);
  });
});

describe("describe()", () => {
  it("documents both checks as advisory candidates with their config keys", () => {
    const docs = describeExtras({ pack: "core", thresholds: {}, since: "0.3-draft", status: "shipped" });
    assert.deepEqual(docs.map((d) => d.id), ["resources-read", "prompts-get"]);
    assert.ok(docs.every((d) => d.advisory && !d.critical));
    assert.deepEqual(docs[0]!.configKeys, ["checks.resources-read.enabled", "checks.resources-read.severity"]);
  });
});

const TOY = fileURLToPath(new URL("../toy/extras-r9.js", import.meta.url));
const sessions: McpSession[] = [];
after(async () => {
  for (const s of sessions) await s.close().catch(() => {});
});

async function onToy(mode: string): Promise<CheckResult[]> {
  const s = await McpSession.open({ command: process.execPath, args: [TOY, "--mode", mode], env: {} }, { vars: {}, dsns: {} }, { cleanCwd: true });
  sessions.push(s);
  return runCore({ session: s, canaries: [], seen: [], hangMs: 6000 });
}
const pick = (out: CheckResult[], id: string): CheckResult => out.find((c) => c.id === id)!;
const SCORED = ["protocol", "tool-poisoning", "robust-input", "secret-echo"];

describe("resources-read and prompts-get on the toy server", { timeout: 180_000 }, () => {
  it("run last in core, after the scored checks and the description lint", async () => {
    const out = await onToy("clean");
    assert.deepEqual(out.map((c) => c.id), ["protocol", "tool-poisoning", "robust-input", "secret-echo", "instructions-hygiene", "tool-descriptions", "param-descriptions", "resources-read", "prompts-get"]);
  });

  const expected: Record<string, [string, string]> = {
    clean: ["pass", "pass"],
    lax: ["part", "part"],
    broken: ["fail", "fail"],
    crash: ["fail", "inconclusive"],
    listfail: ["fail", "fail"],
    none: ["na", "na"],
  };
  for (const [mode, [r, p]] of Object.entries(expected)) {
    it(`${mode}: resources-read ${r}, prompts-get ${p}, and the scored checks are the same as with no resources or prompts`, async () => {
      const out = await onToy(mode);
      assert.equal(pick(out, "resources-read").verdict, r, pick(out, "resources-read").summary);
      assert.equal(pick(out, "prompts-get").verdict, p, pick(out, "prompts-get").summary);
      // The scored checks never see these requests: same verdicts as on the mode that advertises neither feature.
      const base = await onToy("none");
      for (const id of SCORED) assert.equal(pick(out, id).verdict, pick(base, id).verdict, `${mode} ${id}: ${pick(out, id).summary}`);
    });
  }

  it("clean: the unlisted URI is refused with the spec's resource-not-found code", async () => {
    const r = pick(await onToy("clean"), "resources-read");
    assert.match(r.evidence.find((e) => e.code === "resources.unknown-refused")!.outcome, /-32002/);
  });
});
