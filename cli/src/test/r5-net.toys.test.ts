// Round 5, package net (G1): the net pack on the toy servers of this round. Each defect toy must now be inconclusive (never a pass),
// and each near miss must keep its pass. Toys: net-refusal (every mode), net-multitool, net-slug, and the existing net toy's good,
// decode and open modes for the twin, the data: rule and net-redirect.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { McpSession } from "../mcp.js";
import { createSandbox, type Sandbox } from "../sandbox.js";
import { pack } from "../packs/net.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, EffectiveConfig, PackCtx, Verdict } from "../types.js";
import { quiet } from "./helpers.js";

const toy = (file: string) => fileURLToPath(new URL(`../toy/${file}.js`, import.meta.url));
const PROBE_SEC = 2;

interface Outcome {
  checks: CheckResult[];
  verdicts: Record<string, Verdict>;
  sandbox: Sandbox;
}

let parent: string;
const out: Record<string, Outcome> = {};

async function runToy(name: string, file: string, args: string[], over: Partial<EffectiveConfig> = {}): Promise<Outcome> {
  const server = { command: process.execPath, args: [toy(file), ...args], env: {} as Record<string, string> };
  const sandbox = await createSandbox({ dir: parent, timeoutProbeSec: PROBE_SEC, log: quiet });
  const open = () => McpSession.open(server, { vars: {}, dsns: {} }, { cwd: sandbox.root, baseEnv: sandbox.env(), envMode: "scrubbed" });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const classification = classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;
  const ctx: PackCtx = {
    pack: "net",
    config: { ...legacyEffectiveConfig({ config: { name, version: "0.0.1", server }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC }), ...over },
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
  const applies = pack.applies(ctx);
  assert.equal(applies.ok, true, `${name}: ${applies.ok ? "" : applies.reason}`);
  const checks = await pack.run(ctx);
  return { checks, verdicts: Object.fromEntries(checks.map((c) => [c.id, c.verdict])), sandbox };
}

const check = (o: Outcome, id: string) => o.checks.find((c) => c.id === id)!;
const evidenceText = (o: Outcome, id: string) => check(o, id).evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");
const codes = (o: Outcome, id: string) => check(o, id).evidence.map((e) => e.code);

const DEFECTS = ["transport-refused", "class-failure", "echo-host", "refuse-all", "refuse-all-host", "refuse-all-rule", "refuse-all-echo", "refuse-all-class"] as const;
/** Modes whose loopback replies are refusals in words, so the twin decides. */
const SAME_TEXT = ["refuse-all", "refuse-all-host", "refuse-all-rule", "refuse-all-echo", "refuse-all-class"];
const NEAR_MISSES = ["guard-public", "guard-rule-failure", "guard-cannot-access", "guard-validation"] as const;

/** Runs jobs a few at a time: each toy starts a sandbox, a listener and a server. */
async function inBatches(jobs: [string, () => Promise<Outcome>][], size: number): Promise<void> {
  for (let i = 0; i < jobs.length; i += size) await Promise.all(jobs.slice(i, i + size).map(async ([k, fn]) => void (out[k] = await fn())));
}

describe("r5 net: toys", { timeout: 900_000 }, () => {
  before(async () => {
    parent = mkdtempSync(join(tmpdir(), "sealmark-r5-net-"));
    const jobs: [string, () => Promise<Outcome>][] = [];
    for (const m of [...DEFECTS, ...NEAR_MISSES]) jobs.push([`refusal-${m}`, () => runToy(`refusal-${m}`, "net-refusal", ["--mode", m])]);
    jobs.push(["multitool", () => runToy("multitool", "net-multitool", [])]);
    for (const m of ["slug", "decode"]) jobs.push([`slug-${m}`, () => runToy(`slug-${m}`, "net-slug", ["--mode", m])]);
    for (const m of ["good", "decode", "open", "slow", "noredir"]) jobs.push([`net-${m}`, () => runToy(`net-${m}`, "net", ["--mode", m])]);
    jobs.push(["revalidate", () => runToy("revalidate", "net-revalidate", ["--mode", "revalidate"])]);
    // The refuse-all stub with a control URL the harness may not use: the evidence line says why, and nothing is sent to it.
    jobs.push(["refuse-all-private-control", () => runToy("refuse-all-private-control", "net-refusal", ["--mode", "refuse-all"], { net: { allow_dns: false, control_url: "http://127.0.0.1:9/ok" } } as Partial<EffectiveConfig>)]);
    await inBatches(jobs, 4);
  });

  after(async () => {
    for (const o of Object.values(out)) await o.sandbox.destroy().catch(() => {});
    rmSync(parent, { recursive: true, force: true });
  });

  for (const m of DEFECTS) {
    it(`net-refusal ${m}: a tool that fetches nothing never passes a critical net check`, () => {
      const o = out[`refusal-${m}`];
      assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive", `${m}: ${check(o, "net-loopback-ssrf").summary}`);
      assert.equal(o.verdicts["net-scheme-allowlist"], "inconclusive", `${m}: ${check(o, "net-scheme-allowlist").summary}`);
      assert.equal(o.verdicts["net-caps"], "na", m);
      assert.ok(check(o, "net-loopback-ssrf").evidence.every((e) => e.code !== "net.ssrf-hit"), m);
    });
  }

  it("transport-refused, class-failure and echo-host are failures by the veto: no refusal is claimed and no twin is needed", () => {
    for (const m of ["transport-refused", "class-failure", "echo-host"]) {
      const o = out[`refusal-${m}`];
      assert.doesNotMatch(evidenceText(o, "net-loopback-ssrf"), /explicitly refused/, m);
      assert.match(evidenceText(o, "net-loopback-ssrf"), /failed without saying the target was refused/, m);
      assert.ok(!codes(o, "net-loopback-ssrf").includes("net.ssrf-sametext"), m);
      assert.equal(check(o, "net-loopback-ssrf").coverage?.validCalls, 0, `${m}: a failed fetch exercised nothing`);
    }
  });

  it("the refuse-everything stubs: every loopback probe is refused in words, and the hostless twin got the same reply", () => {
    for (const m of SAME_TEXT) {
      const o = out[`refusal-${m}`];
      const ssrf = check(o, "net-loopback-ssrf");
      assert.match(evidenceText(o, "net-loopback-ssrf"), /explicitly refused/, m);
      assert.equal(ssrf.evidence.filter((e) => e.code === "net.ssrf-sametext").length, 1, m);
      assert.match(ssrf.summary, /a data: URL with no host got the same reply word for word/, m);
      assert.match(ssrf.summary, /set net\.control_url to a URL it can reach/, m);
      // Refusal-only probes keep their coverage credit: the refusal is the behaviour under test.
      assert.ok((ssrf.coverage?.validCalls ?? 0) >= 8, m);
    }
  });

  it("near misses: a guard that checks the address passes on text, and the evidence names the tier and says no fetch was shown", () => {
    const tiers: Record<string, RegExp> = {
      "guard-public": /explicitly refused \(names the rule\)/,
      "guard-rule-failure": /explicitly refused \(names the rule\)/,
      "guard-cannot-access": /explicitly refused \(validation error naming the address\)/,
      "guard-validation": /explicitly refused \(names the rule\)/,
    };
    for (const m of NEAR_MISSES) {
      const o = out[`refusal-${m}`];
      const ssrf = check(o, "net-loopback-ssrf");
      assert.equal(ssrf.verdict, "pass", `${m}: ${ssrf.summary}`);
      assert.match(evidenceText(o, "net-loopback-ssrf"), tiers[m]!, m);
      assert.equal(ssrf.evidence.filter((e) => e.code === "net.ssrf-text-only").length, 1, m);
      assert.match(ssrf.summary, /a hostless URL got a different reply; no fetch of any URL was shown to work/, m);
      assert.ok(ssrf.evidence.every((e) => e.code !== "net.ssrf-hit"), m);
    }
  });

  it("near misses: the scheme check passes where the guard speaks about the scheme, and is inconclusive where only a host guard spoke", () => {
    for (const m of ["guard-public", "guard-rule-failure", "guard-validation"]) {
      const s = check(out[`refusal-${m}`], "net-scheme-allowlist");
      assert.equal(s.verdict, "pass", `${m}: ${s.summary}`);
      assert.match(s.summary, /explicitly refused for the scheme/, m);
      assert.doesNotMatch(s.summary, /passes trivially/, m);
    }
    // guard-cannot-access refuses ftp:, gopher: and dict: by their host: that says nothing about the scheme.
    const s = check(out["refusal-guard-cannot-access"], "net-scheme-allowlist");
    assert.equal(s.verdict, "inconclusive", s.summary);
    assert.match(evidenceText(out["refusal-guard-cannot-access"], "net-scheme-allowlist"), /refused for another reason \(host guard, not the scheme\)/);
  });

  it("the existing good net toy keeps its pass with the twin: its data: reply is a scheme refusal, so it differs", () => {
    const o = out["net-good"];
    assert.equal(o.verdicts["net-loopback-ssrf"], "pass", check(o, "net-loopback-ssrf").summary);
    assert.equal(o.verdicts["net-scheme-allowlist"], "pass");
    const twin = check(o, "net-loopback-ssrf").evidence.find((e) => e.code === "net.ssrf-text-only");
    assert.ok(twin, "the twin was sent and its reply differs");
    assert.match(twin!.outcome, /names the rule/);
  });

  it("net-multitool: the tool that never contacts anything gets no hit line and no coverage credit", () => {
    const o = out.multitool;
    const ssrf = check(o, "net-loopback-ssrf");
    assert.equal(ssrf.verdict, "fail");
    const hits = ssrf.evidence.filter((e) => e.code === "net.ssrf-hit");
    assert.ok(hits.length >= 8, "the fetching tool reached the listener");
    assert.ok(hits.every((e) => e.tool === "fetch_page"), "every hit line is the fetching tool's");
    assert.ok(!ssrf.evidence.some((e) => e.tool === "lookup_page" && e.code === "net.ssrf-hit"));
    assert.deepEqual(ssrf.coverage?.probed, ["fetch_page"]);
    assert.ok(ssrf.evidence.filter((e) => e.tool === "lookup_page").every((e) => e.code === "net.ssrf-unreached"));
    assert.deepEqual(check(o, "net-scheme-allowlist").coverage?.probed.includes("lookup_page"), false);
  });

  it("net-slug: an echo of the probe inside a percent-encoded slug is not a decoded data: URL; a real decode still is", () => {
    const slug = out["slug-slug"];
    assert.ok(!codes(slug, "net-scheme-allowlist").includes("net.scheme-data"), "the slug echo is not a decode");
    // Not part: nothing was decoded. Not pass either: the tool answered the data: URL without refusing it and was never shown to fetch
    // (a control URL would settle that), so the honest reading is inconclusive.
    assert.equal(slug.verdicts["net-scheme-allowlist"], "inconclusive", check(slug, "net-scheme-allowlist").summary);
    const decode = out["slug-decode"];
    assert.ok(codes(decode, "net-scheme-allowlist").includes("net.scheme-data"));
    assert.equal(decode.verdicts["net-scheme-allowlist"], "part");
    const real = out["net-decode"];
    assert.equal(real.verdicts["net-scheme-allowlist"], "part");
  });

  it("an unusable net.control_url is not used, and the report says why", () => {
    const o = out["refuse-all-private-control"];
    assert.match(evidenceText(o, "net-loopback-ssrf"), /net\.control_url \| not used: it is a loopback address/);
    assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive", "the twin still decides");
  });

  it("net-redirect: a server that accepts loopback directly and follows the hop is inconclusive, never part; net-revalidate still passes", () => {
    for (const m of ["net-open", "net-slow"]) {
      const r = check(out[m], "net-redirect");
      assert.equal(r.verdict, "inconclusive", `${m}: ${r.summary}`);
      assert.match(r.summary, /re-validation cannot be measured on a server that accepts loopback targets directly/);
    }
    assert.equal(check(out.revalidate, "net-redirect").verdict, "pass");
    assert.equal(check(out["net-noredir"], "net-redirect").verdict, "pass");
  });

  it("net-redirect: the IPv6 loopback hop is sent when the host has the listener, and named when it does not", () => {
    for (const m of ["net-open", "net-slow", "revalidate"]) {
      const o = out[m];
      const r = check(o, "net-redirect");
      const hasV6 = o.sandbox.listener.port6 !== undefined;
      const hop6 = r.evidence.filter((e) => e.probe.includes(" hop6:"));
      if (hasV6) assert.ok(hop6.some((e) => e.code === "net.redirect-followed" || e.code === "net.redirect-stopped"), `${m}: the hop to [::1] was sent`);
      else {
        assert.ok(hop6.some((e) => /no IPv6 loopback listener/.test(e.outcome)), m);
        assert.match(r.summary, /the IPv6 loopback family was not tried/, m);
      }
    }
  });
});
