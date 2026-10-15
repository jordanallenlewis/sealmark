import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { gradePack } from "../grade.js";
import { McpSession } from "../mcp.js";
import { SANDBOX_NON_GUARANTEE, createSandbox, type Sandbox } from "../sandbox.js";
import { SCHEME_CORPUS, SSRF_CORPUS, buildProbes, describe as describeNet, outcomeOf, pack, stripUrl, targetProblem } from "../packs/net.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import type { CheckResult, EffectiveConfig, PackCtx, Verdict } from "../types.js";
import { gradeOf, quiet } from "./helpers.js";

const NET_TOY = fileURLToPath(new URL("../toy/net.js", import.meta.url));
const PROBE_SEC = 2;

let parent: string;
interface Outcome {
  checks: CheckResult[];
  verdicts: Record<string, Verdict>;
  letter?: string;
  sandbox: Sandbox;
  listenerTokens: string[];
}
const outcomes: Record<string, Outcome> = {};

function spec(mode: string) {
  return { command: process.execPath, args: [NET_TOY, "--mode", mode], env: {} as Record<string, string> };
}

function configFor(mode: string, over: Partial<EffectiveConfig> = {}): EffectiveConfig {
  return { ...legacyEffectiveConfig({ config: { name: `net-${mode}`, version: "0.0.1", server: spec(mode) }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC }), ...over };
}

async function makeCtx(mode: string, over: Partial<EffectiveConfig> = {}): Promise<{ ctx: PackCtx; sandbox: Sandbox }> {
  const sandbox = await createSandbox({ dir: parent, timeoutProbeSec: PROBE_SEC, log: quiet });
  const server = spec(mode);
  const open = () => McpSession.open(server, { vars: {}, dsns: {} }, { cwd: sandbox.root, baseEnv: sandbox.env(), envMode: "scrubbed" });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const classification = classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;
  const ctx: PackCtx = {
    pack: "net",
    config: configFor(mode, over),
    tools,
    classification,
    sandbox,
    sandboxEnabled: true,
    open,
    active: false,
    timeoutProbeSec: PROBE_SEC,
    hangMs: 2000,
    log: quiet,
  };
  return { ctx, sandbox };
}

async function runPack(mode: string, over: Partial<EffectiveConfig> = {}): Promise<Outcome> {
  const { ctx, sandbox } = await makeCtx(mode, over);
  const applies = pack.applies(ctx);
  assert.equal(applies.ok, true, `${mode}: ${applies.ok ? "" : applies.reason}`);
  const checks = await pack.run(ctx);
  const grade = gradePack("net", checks.filter((c) => c.id !== "net-redirect"));
  // net-redirect is an advisory candidate with its own tests (net-redirect.*.test.ts); these tables are the three scored net checks.
  return { checks, verdicts: Object.fromEntries(checks.filter((c) => c.id !== "net-redirect").map((c) => [c.id, c.verdict])), letter: grade?.letter, sandbox, listenerTokens: [] };
}

const evidenceText = (o: Outcome, id: string) => o.checks.find((c) => c.id === id)!.evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");

describe("net pack on toy servers", { timeout: 240_000 }, () => {
  before(async () => {
    parent = mkdtempSync(join(tmpdir(), "sealmark-net-test-"));
    // The four modes of the design table plus the control-url cases, run in parallel (each has its own sandbox and listener).
    const jobs: Record<string, () => Promise<Outcome>> = {
      good: () => runPack("good"),
      open: () => runPack("open"),
      schemes: () => runPack("schemes"),
      slow: () => runPack("slow"),
      silent: () => runPack("silent"),
      dead: () => runPack("dead"),
      deadrpc: () => runPack("deadrpc"),
      textfail: () => runPack("textfail"),
      decode: () => runPack("decode"),
      jsquirk: () => runPack("jsquirk"),
      deadControl: () => runPack("dead", { net: { control_url: "https://example.invalid/control", allow_dns: false } }),
      silentControl: () => runPack("silent", { net: { control_url: "https://example.invalid/control", allow_dns: false } }),
      silentPrivate: () => runPack("silent", { net: { control_url: "http://192.168.1.1/", allow_dns: false } }),
      disabled: () => runPack("good", { checks: { "net-loopback-ssrf": { enabled: false, severity: null } } }),
      removed: () => runPack("good", { checks: { "net-loopback-ssrf": { enabled: true, severity: null, corpus: { add: [], remove: ["hex", "http://0.0.0.0:{port}/t/{token}"] } } } }),
      evilAdd: () => runPack("good", { checks: { "net-loopback-ssrf": { enabled: true, severity: null, corpus: { add: ["http://169.254.169.254/latest/meta-data/", "http://10.0.0.5:80/x", "http://127.0.0.1:1/t/{token}"], remove: [] } } } }),
    };
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (outcomes[k] = await fn())));
  });

  after(async () => {
    for (const o of Object.values(outcomes)) await o.sandbox.destroy().catch(() => {});
    rmSync(parent, { recursive: true, force: true });
  });

  it("good: refuses every loopback spelling and every scheme; caps are not applicable; grade A", () => {
    const o = outcomes.good;
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "pass", "net-caps": "na" });
    assert.equal(o.letter, "A");
    assert.match(o.checks.find((c) => c.id === "net-caps")!.summary, /the server refused loopback targets \(net-loopback-ssrf passed\)/);
    // The corpus has nine probes (the IPv4-mapped IPv6 spelling joined in round 4) and each refusal names the tier that made it one.
    const refused = o.checks.find((c) => c.id === "net-loopback-ssrf")!.evidence.filter((e) => e.code === "net.ssrf-refused");
    assert.ok(refused.length >= 8, `${refused.length} refused probes`);
    assert.match(evidenceText(o, "net-loopback-ssrf"), /ipv4-mapped: http:\/\/\[::ffff:127\.0\.0\.1\]:\d+\/t\/sm-[0-9a-f]+ \| explicitly refused \(names the address class\)/);
    assert.match(o.checks.find((c) => c.id === "net-loopback-ssrf")!.summary, /^all 9 loopback probes were explicitly refused|^all 8 loopback probes were explicitly refused/);
  });

  it("open: fetches loopback, reads file:, opens raw TCP, has a size cap but no time cap; caps part; grade F", () => {
    const o = outcomes.open;
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "fail", "net-caps": "part" });
    assert.equal(o.letter, "F");
    const ssrf = o.checks.find((c) => c.id === "net-loopback-ssrf")!;
    assert.ok(ssrf.evidence.some((e) => e.verifiedBy === "listener" && e.code === "net.ssrf-hit"), "a listener-verified hit");
    const schemes = evidenceText(o, "net-scheme-allowlist");
    assert.match(schemes, /canary file's content came back/);
    assert.match(schemes, /raw TCP connection/);
    assert.match(evidenceText(o, "net-caps"), /listener sent/);
  });

  it("schemes: loopback refused, file: read; D", () => {
    const o = outcomes.schemes;
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "fail", "net-caps": "na" });
    assert.equal(o.letter, "D");
    assert.match(evidenceText(o, "net-scheme-allowlist"), /canary file's content came back/);
  });

  it("slow: loopback allowed, nothing capped; ssrf fail, scheme pass, caps fail; F", () => {
    const o = outcomes.slow;
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "pass", "net-caps": "fail" });
    assert.equal(o.letter, "F");
    const caps = o.checks.find((c) => c.id === "net-caps")!;
    assert.match(caps.summary, /no reply within 10 s/);
    assert.ok(caps.evidence.every((e) => e.verifiedBy === "listener"));
  });

  it("a server that neither fetches nor refuses is inconclusive, and a working control fetch turns that into a pass", () => {
    assert.equal(outcomes.silent.verdicts["net-loopback-ssrf"], "inconclusive");
    assert.match(outcomes.silent.checks[0]!.summary, /net\.control_url/);
    assert.equal(outcomes.silentControl.verdicts["net-loopback-ssrf"], "pass");
    assert.match(outcomes.silentControl.checks[0]!.summary, /control fetch/);
    assert.equal(outcomes.silent.verdicts["net-caps"], "na");
  });

  it("a tool that fails every fetch for an unrelated reason is inconclusive, never a pass (isError, JSON-RPC error, plain-text error)", () => {
    for (const k of ["dead", "deadrpc", "textfail", "silent"]) {
      const o = outcomes[k];
      assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive", k);
      assert.equal(o.verdicts["net-scheme-allowlist"], "inconclusive", k);
      assert.equal(o.verdicts["net-caps"], "na", k);
      assert.match(o.checks.find((c) => c.id === "net-loopback-ssrf")!.summary, /net.control_url/, k);
      assert.match(o.checks.find((c) => c.id === "net-scheme-allowlist")!.summary, /net.control_url/, k);
      assert.notEqual(o.letter, "A", k);
    }
    assert.match(evidenceText(outcomes.dead, "net-loopback-ssrf"), /failed without saying the target was refused/);
  });

  it("a control fetch that also fails does not rescue a dead tool; a working control does rescue the scheme check too", () => {
    assert.equal(outcomes.deadControl.verdicts["net-loopback-ssrf"], "inconclusive");
    assert.equal(outcomes.deadControl.verdicts["net-scheme-allowlist"], "inconclusive");
    assert.match(evidenceText(outcomes.deadControl, "net-loopback-ssrf"), /control fetch.*failed/);
    assert.equal(outcomes.silentControl.verdicts["net-scheme-allowlist"], "pass");
  });

  it("a text error that merely echoes the data: URL is not a decode; a real decode is part", () => {
    assert.notEqual(outcomes.textfail.verdicts["net-scheme-allowlist"], "part");
    assert.doesNotMatch(outcomes.textfail.checks.find((c) => c.id === "net-scheme-allowlist")!.summary, /accepts data/);
    assert.equal(outcomes.decode.verdicts["net-loopback-ssrf"], "pass");
    assert.equal(outcomes.decode.verdicts["net-scheme-allowlist"], "part");
    assert.match(evidenceText(outcomes.decode, "net-scheme-allowlist"), /decoded the data: URL/);
  });

  it("javascript: is recorded but never scored: a generic error for it does not make the scheme check inconclusive", () => {
    assert.equal(outcomes.jsquirk.verdicts["net-loopback-ssrf"], "pass");
    assert.equal(outcomes.jsquirk.verdicts["net-scheme-allowlist"], "pass");
    assert.equal(outcomes.jsquirk.letter, "A");
  });

  it("an unusable net.control_url (private literal) is not used", () => {
    const o = outcomes.silentPrivate;
    assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive");
    assert.match(evidenceText(o, "net-loopback-ssrf"), /control_url \| not used/);
  });

  it("enabled: false reports na with the reason and sends nothing for that check", () => {
    const c = outcomes.disabled.checks.find((x) => x.id === "net-loopback-ssrf")!;
    assert.equal(c.verdict, "na");
    assert.match(c.summary, /disabled by config/);
    assert.equal(c.evidence.length, 0);
    assert.equal(outcomes.disabled.verdicts["net-scheme-allowlist"], "pass");
    assert.match(outcomes.disabled.checks.find((x) => x.id === "net-caps")!.summary, /did not run/);
  });

  it("corpus.remove drops an entry by id or by exact template", () => {
    const text = evidenceText(outcomes.removed, "net-loopback-ssrf");
    assert.doesNotMatch(text, /hex:/);
    assert.doesNotMatch(text, / unspecified:/);
    assert.match(text, / loopback:/);
    assert.equal(outcomes.removed.verdicts["net-loopback-ssrf"], "pass");
  });

  it("corpus.add entries aimed anywhere but the listener are never sent", () => {
    const ev = outcomes.evilAdd.checks.find((c) => c.id === "net-loopback-ssrf")!.evidence;
    const skipped = ev.filter((e) => /^corpus entry "added-/.test(e.probe));
    assert.equal(skipped.length, 3);
    assert.match(skipped.map((e) => e.outcome).join("\n"), /169\.254\.169\.254 is not a loopback/);
    assert.match(skipped.map((e) => e.outcome).join("\n"), /10\.0\.0\.5 is not a loopback/);
    assert.match(skipped.map((e) => e.outcome).join("\n"), /port 1 is not the harness listener/);
    for (const e of ev) assert.doesNotMatch(String((e.args as { url?: string } | undefined)?.url ?? ""), /169\.254|10\.0\.0\.5/);
    // And the server never saw them: the toy's refusal text only ever names corpus hosts.
    assert.equal(outcomes.evilAdd.verdicts["net-loopback-ssrf"], "pass");
  });

  it("allow_dns is off by default: no probe names nip.io; allow_dns adds exactly that entry", () => {
    for (const k of ["good", "open", "schemes", "slow"]) assert.doesNotMatch(outcomes[k].checks.map((c) => c.evidence.map((e) => e.probe).join("\n")).join("\n"), /nip\.io/);
    const base = { port: 4000, port6: 4001, canaryDir: "C:/s/canary", canaryFile: join(parent, "canary", "secret.txt"), sandboxDir: parent, remove: [], add: [] };
    assert.equal(buildProbes(SSRF_CORPUS, { ...base, allowDns: false }).some((p) => /nip\.io/.test(p.url)), false);
    const dns = buildProbes(SSRF_CORPUS, { ...base, allowDns: true }).find((p) => /nip\.io/.test(p.url));
    assert.ok(dns && !dns.skipped, "the nip.io entry is built and allowed");
  });

  it("every check id the pack emits is documented, scopes start with server, and ids are unique", () => {
    const docs = describeNet();
    const ids = docs.map((d) => d.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const d of docs) {
      assert.equal(d.pack, "net");
      assert.match(d.scope, /^server/);
      assert.ok(d.probes.length > 0 || d.id === "net-caps");
    }
    for (const o of Object.values(outcomes)) for (const c of o.checks) assert.ok(ids.includes(c.id), c.id);
    assert.deepEqual(docs.filter((d) => d.critical).map((d) => d.id), ["net-loopback-ssrf", "net-scheme-allowlist"]);
  });

  it("coverage lists the tools probed with valid calls", () => {
    const c = outcomes.open.checks.find((x) => x.id === "net-loopback-ssrf")!;
    assert.deepEqual(c.coverage?.probed, ["fetch"]);
    assert.ok((c.coverage?.validCalls ?? 0) >= 8);
  });

  it("the sandboxes are destroyed cleanly afterwards", async () => {
    const d = await outcomes.good.sandbox.destroy();
    assert.equal(d.cleanedUp, true);
    assert.deepEqual(d.leftover, []);
  });
});

describe("net pack: safety of every target", () => {
  const sandboxDir = join(tmpdir(), "sealmark-fake");
  const base = { sandboxDir, ports: [5555, 5556] as number[], allowDns: false };

  it("every corpus entry expands to a loopback URL on the listener's port or a canary file inside the sandbox", () => {
    for (const corpus of [SSRF_CORPUS, SCHEME_CORPUS]) {
      const built = buildProbes(corpus, { port: 5555, port6: 5556, canaryDir: join(sandboxDir, "canary"), canaryFile: join(sandboxDir, "canary", "secret.txt"), sandboxDir, allowDns: true, remove: [], add: [] });
      assert.ok(built.length >= 7);
      for (const p of built) assert.equal(p.skipped, undefined, `${p.id}: ${p.skipped}`);
    }
  });

  it("link-local, RFC1918, public hosts, other ports and outside-sandbox files are refused", () => {
    const bad = [
      "http://169.254.169.254:5555/latest/meta-data/",
      "http://10.0.0.1:5555/",
      "http://172.16.5.4:5555/",
      "http://192.168.0.10:5555/",
      "http://[fe80::1]:5555/",
      "http://[fd00::1]:5555/",
      "http://example.com:5555/",
      "http://127.0.0.1:22/",
      "http://127.0.0.1/",
      "ftp://10.1.2.3:5555/",
      "gopher://192.168.1.1:5555/_x",
      "file:///etc/passwd",
      "file:///C:/Windows/win.ini",
      "http://127.0.0.1.nip.io:5555/",
      "http://10.0.0.1.nip.io:5555/",
      "not a url",
    ];
    for (const u of bad) assert.ok(targetProblem(u, base), u);
    assert.ok(targetProblem("http://10.0.0.1.nip.io:5555/", { ...base, allowDns: true }), "nip.io only for loopback quads");
    assert.equal(targetProblem("http://127.0.0.1.nip.io:5555/", { ...base, allowDns: true }), undefined);
  });

  it("loopback spellings the corpus uses are accepted only on the listener ports", () => {
    for (const u of ["http://127.0.0.1:5555/", "http://localhost:5555/", "http://[::1]:5556/", "http://127.1:5555/", "http://0x7f000001:5555/", "http://2130706433:5555/", "http://0.0.0.0:5555/", "data:text/plain,x", "javascript:1"]) {
      assert.equal(targetProblem(u, base), undefined, u);
    }
  });
});

describe("net pack: refusal vocabulary", () => {
  const call = (o: Partial<{ isError: boolean; text: string; rpcError: string; timedOut: boolean; closed: boolean }>) => ({ isError: false, text: "", elapsedMs: 1, timedOut: false, closed: false, ...o });
  const url = "http://localhost:4000/t/sm-abc";
  it("only a response that says the target was refused is a refusal", () => {
    assert.equal(outcomeOf(call({ isError: true, text: "blocked: 127.0.0.1 is a loopback address (not allowed)" }), url), "refused");
    assert.equal(outcomeOf(call({ rpcError: "URL host is not allowed" }), url), "refused");
    assert.equal(outcomeOf(call({ text: "Error: private address forbidden" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, text: "fetch failed: ENETUNREACH" }), url), "failed");
    assert.equal(outcomeOf(call({ rpcError: "network is down" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, text: "connect ECONNREFUSED 127.0.0.1:4000" }), url), "failed");
    assert.equal(outcomeOf(call({ timedOut: true, isError: true, text: "blocked" }), url), "failed");
    assert.equal(outcomeOf(call({ closed: true }), url), "failed");
  });
  it("a refusal in plain words counts without the word loopback: not a public address, refused to fetch, resolves to <address>", () => {
    assert.equal(outcomeOf(call({ isError: true, text: "localhost resolves to 127.0.0.1, which is not a public address" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, text: "refused to fetch the target" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, text: "the host resolves to ::1" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, text: "address is not public" }), url), "refused");
  });
  it("a JSON-RPC invalid-params error counts only when it names the address the URL resolves to", () => {
    assert.equal(outcomeOf(call({ isError: true, rpcError: "MCP error -32602: address 127.0.0.1 is not accepted" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, rpcError: "MCP error -32602: address ::1 is not accepted" }), url), "refused");
    assert.equal(outcomeOf(call({ isError: true, rpcError: "MCP error -32602: url must be a string" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, rpcError: "MCP error -32603: address 127.0.0.1 is not accepted" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, rpcError: `MCP error -32602: invalid params for ${url}` }), url), "failed");
  });
  it("a call that merely failed still is not a refusal: unreachable, nothing resolved, not publicly reachable", () => {
    assert.equal(outcomeOf(call({ isError: true, text: "fetch failed: connect ENETUNREACH 127.0.0.1:80 - network is unreachable" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, text: "fetch failed: the host name resolves to no address (ENOTFOUND)" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, text: "the proxy is not publicly reachable" }), url), "failed");
    assert.equal(outcomeOf(call({ isError: true, text: "the mirror resolves to a stale cache entry" }), url), "failed");
    assert.equal(outcomeOf(call({ text: "the page says it is not a public address book" }), url), "answered");
  });
  it("a success body, or an error that only echoes the probe URL, is not a refusal", () => {
    assert.equal(outcomeOf(call({ text: "<html>see http://localhost:4000/t/sm-abc for the local copy</html>" }), url), "answered");
    assert.equal(outcomeOf(call({ isError: true, text: `failed to load ${url}` }), url), "failed");
    assert.equal(outcomeOf(call({ text: "Error: internal server error" }), url), "failed");
    assert.equal(stripUrl(`a ${encodeURIComponent(url)} b ${url}`, url).trim(), "a   b");
  });
});

describe("net pack: applicability", () => {
  it("is not applicable without a URL tool, with a reason, and never throws on a bare ctx", () => {
    const bare = pack.applies({ pack: "net" } as never);
    assert.equal(bare.ok, false);
    const text = pack.applies({ pack: "net", sandbox: { listener: {} } as never, tools: [], classification: [], active: false } as never);
    assert.equal(text.ok, false);
    if (!text.ok) assert.match(text.reason, /URL/);
  });
});

describe("net pack through the harness", { timeout: 180_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-net-run-"));
    mkdirSync(join(dir, "sb"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const run = (mode: string) => {
    const base = legacyEffectiveConfig({ config: { name: `net-${mode}`, version: "0.0.1", server: spec(mode) }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC });
    return runHarness({ config: { name: `net-${mode}`, version: "0.0.1", server: spec(mode) }, effective: { ...base, sandbox: { ...base.sandbox, dir: join(dir, "sb") } }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC, log: quiet });
  };

  it("good is graded A and counts as covered; schemes is graded D; both leave no sandbox behind", async () => {
    const [good, schemes] = await Promise.all([run("good"), run("schemes")]);
    assert.equal(gradeOf(good, "net")?.letter, "A");
    assert.equal(gradeOf(schemes, "net")?.letter, "D");
    assert.deepEqual(gradeOf(schemes, "net")?.criticalFails, ["net-scheme-allowlist"]);
    assert.ok((good.coverage?.validCalls ?? 0) > 0);
    assert.equal(good.coverage?.toolsCalledValid, 1);
    assert.ok(good.notCovered.some((n) => /link-local and private-range addresses are never contacted/.test(n)));
    assert.ok(good.notCovered.includes(SANDBOX_NON_GUARANTEE));
    assert.deepEqual(readdirSync(join(dir, "sb")), []);
  });
});
