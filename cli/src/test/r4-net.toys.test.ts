// Round 4, package net: the net pack on the toy servers of this round. Each defect toy must now fail or be inconclusive, and each
// near miss must keep its pass. Servers: net-offline (A1, A6), net-reserved (A1), net-mapped6 (A2), net-revalidate (A3), net-ambig (B1).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { gradePack } from "../grade.js";
import { McpSession } from "../mcp.js";
import { createSandbox, type Sandbox } from "../sandbox.js";
import { pack } from "../packs/net.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, PackCtx, ToolClassification, Verdict } from "../types.js";
import { quiet } from "./helpers.js";

const toy = (file: string) => fileURLToPath(new URL(`../toy/${file}.js`, import.meta.url));
const PROBE_SEC = 2;

interface Outcome {
  applies: { ok: boolean; reason?: string };
  checks: CheckResult[];
  verdicts: Record<string, Verdict>;
  letter?: string;
  classification: ToolClassification[];
  sandbox: Sandbox;
}

let parent: string;
const out: Record<string, Outcome> = {};

async function runToy(name: string, file: string, args: string[]): Promise<Outcome> {
  const server = { command: process.execPath, args: [toy(file), ...args], env: {} as Record<string, string> };
  const sandbox = await createSandbox({ dir: parent, timeoutProbeSec: PROBE_SEC, log: quiet });
  const open = () => McpSession.open(server, { vars: {}, dsns: {} }, { cwd: sandbox.root, baseEnv: sandbox.env(), envMode: "scrubbed" });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const classification = classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;
  const ctx: PackCtx = {
    pack: "net",
    config: legacyEffectiveConfig({ config: { name, version: "0.0.1", server }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC }),
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
  if (!applies.ok) return { applies, checks: [], verdicts: {}, classification, sandbox };
  const checks = await pack.run(ctx);
  const grade = gradePack("net", checks.filter((c) => c.id !== "net-redirect"));
  return { applies, checks, verdicts: Object.fromEntries(checks.map((c) => [c.id, c.verdict])), letter: grade?.letter, classification, sandbox };
}

const check = (o: Outcome, id: string) => o.checks.find((c) => c.id === id)!;
const evidenceText = (o: Outcome, id: string) => check(o, id).evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");

describe("r4 net: toys", { timeout: 400_000 }, () => {
  before(async () => {
    parent = mkdtempSync(join(tmpdir(), "sealmark-r4-net-"));
    const jobs: Record<string, () => Promise<Outcome>> = {};
    for (const m of ["blocked-proxy", "restricted", "unreachable"]) jobs[`offline-${m}`] = () => runToy(`offline-${m}`, "net-offline", ["--mode", m]);
    for (const m of ["reserved", "unsafe", "nonroutable", "notroutable", "isError-32602", "rpc-32602"]) jobs[`reserved-${m}`] = () => runToy(`reserved-${m}`, "net-reserved", ["--mode", m]);
    for (const m of ["denylist", "strict"]) jobs[`mapped6-${m}`] = () => runToy(`mapped6-${m}`, "net-mapped6", ["--mode", m]);
    for (const m of ["revalidate", "initial-only"]) jobs[`revalidate-${m}`] = () => runToy(`revalidate-${m}`, "net-revalidate", ["--mode", m]);
    for (const m of ["open", "guarded", "nearmiss"]) jobs[`ambig-${m}`] = () => runToy(`ambig-${m}`, "net-ambig", ["--mode", m]);
    jobs.hop = () => runToy("hop", "net", ["--mode", "hop"]);
    jobs.noredir = () => runToy("noredir", "net", ["--mode", "noredir"]);
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (out[k] = await fn())));
  });

  after(async () => {
    for (const o of Object.values(out)) await o.sandbox.destroy().catch(() => {});
    rmSync(parent, { recursive: true, force: true });
  });

  it("net-offline: a tool that can fetch nothing never passes a critical check, whatever it says (blocked by proxy, restricted, unreachable)", () => {
    for (const m of ["blocked-proxy", "restricted", "unreachable"]) {
      const o = out[`offline-${m}`];
      assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive", m);
      assert.equal(o.verdicts["net-scheme-allowlist"], "inconclusive", m);
      assert.equal(o.verdicts["net-caps"], "na", m);
      assert.match(check(o, "net-loopback-ssrf").summary, /a reply that only reports a failed fetch \(proxy, socket, DNS\) is not read as a refusal/, m);
      assert.match(evidenceText(o, "net-loopback-ssrf"), /failed without saying the target was refused/, m);
      assert.doesNotMatch(evidenceText(o, "net-loopback-ssrf"), /explicitly refused/, m);
      assert.equal(o.letter, undefined, `${m}: not graded`);
    }
  });

  it("net-offline: no call counts as a valid call (an errored call exercised nothing)", () => {
    for (const m of ["blocked-proxy", "restricted", "unreachable"]) {
      for (const id of ["net-loopback-ssrf", "net-scheme-allowlist"]) {
        const c = check(out[`offline-${m}`], id);
        assert.equal(c.coverage?.validCalls, 0, `${m} ${id}`);
        assert.deepEqual(c.coverage?.probed, [], `${m} ${id}`);
      }
    }
  });

  it("net-reserved: four refusal wordings and two validation errors that were inconclusive are refusals now; the listener saw nothing", () => {
    for (const m of ["reserved", "unsafe", "nonroutable", "notroutable", "isError-32602", "rpc-32602"]) {
      const o = out[`reserved-${m}`];
      assert.equal(o.verdicts["net-loopback-ssrf"], "pass", m);
      assert.equal(o.verdicts["net-scheme-allowlist"], "pass", m);
      const ssrf = check(o, "net-loopback-ssrf");
      assert.ok(ssrf.evidence.every((e) => e.code !== "net.ssrf-hit"), `${m}: the listener saw nothing`);
      assert.match(ssrf.summary, /explicitly refused/, m);
      assert.ok(ssrf.evidence.filter((e) => e.code === "net.ssrf-refused").length >= 8, m);
      assert.ok((ssrf.coverage?.validCalls ?? 0) >= 8, `${m}: refused probes are valid calls`);
    }
    assert.match(evidenceText(out["reserved-reserved"], "net-loopback-ssrf"), /explicitly refused \(names the address class\)/);
    assert.match(evidenceText(out["reserved-isError-32602"], "net-loopback-ssrf"), /explicitly refused \(validation error naming the address\)/);
    assert.match(evidenceText(out["reserved-rpc-32602"], "net-loopback-ssrf"), /explicitly refused \(validation error naming the address\)/);
  });

  it("net-mapped6: a server that denies four literals fetches the IPv4-mapped spelling, and the check fails on the probe ipv4-mapped", () => {
    const o = out["mapped6-denylist"];
    assert.equal(o.verdicts["net-loopback-ssrf"], "fail");
    const ssrf = check(o, "net-loopback-ssrf");
    assert.match(ssrf.summary, /\(ipv4-mapped\): 1 of \d probes reached it/);
    const hit = ssrf.evidence.filter((e) => e.code === "net.ssrf-hit");
    assert.equal(hit.length, 1);
    assert.match(hit[0]!.probe, /ipv4-mapped: http:\/\/\[::ffff:127\.0\.0\.1\]:\d+\//);
    assert.equal(hit[0]!.verifiedBy, "listener");
    assert.equal(o.letter, "D", `a failed critical check caps the grade at D (verdicts ${JSON.stringify(o.verdicts)}; ${o.checks.map((c) => `${c.id}: ${c.summary}`).join(" | ")})`);
  });

  it("near miss: the same tool that also rejects IPv4-mapped hosts passes", () => {
    const o = out["mapped6-strict"];
    assert.equal(o.verdicts["net-loopback-ssrf"], "pass");
    assert.equal(o.verdicts["net-scheme-allowlist"], "pass");
    assert.match(evidenceText(o, "net-loopback-ssrf"), /ipv4-mapped: .*explicitly refused/);
  });

  it("net-revalidate: a server that follows a same-origin redirect and refuses the redirect to a refused spelling passes net-redirect", () => {
    const o = out["revalidate-revalidate"];
    const r = check(o, "net-redirect");
    assert.equal(r.verdict, "pass", r.summary);
    assert.match(r.summary, /redirects are followed and the redirect to localhost, which the server refused when given directly, was not: the target is re-validated/);
    assert.ok(r.evidence.some((e) => e.code === "net.redirect-followed"));
    assert.ok(r.evidence.some((e) => e.code === "net.redirect-stopped"));
    assert.equal(o.verdicts["net-loopback-ssrf"], "fail", "it fetches 127.0.0.1, which is what lets net-redirect observe it");
  });

  it("near miss: the same tool that checks only the first URL fails net-redirect; the older hop and noredir toys keep their verdicts", () => {
    const f = check(out["revalidate-initial-only"], "net-redirect");
    assert.equal(f.verdict, "fail", f.summary);
    assert.match(f.summary, /followed a redirect to a target it refused when given directly \(localhost\)/);
    assert.equal(check(out.hop, "net-redirect").verdict, "fail");
    assert.equal(check(out.noredir, "net-redirect").verdict, "pass");
    assert.match(check(out.noredir, "net-redirect").summary, /redirects are not followed/);
  });

  it("net-ambig open: fetch_file(path, url) is probed by the net pack through its secondary url class, and fails the loopback check", () => {
    const o = out["ambig-open"];
    assert.equal(o.applies.ok, true);
    const c = o.classification[0]!;
    assert.equal(c.class, "path");
    assert.deepEqual(c.secondary, ["url"]);
    assert.ok(c.reasons.includes("secondary: url (probed by net)"));
    assert.equal(o.verdicts["net-loopback-ssrf"], "fail");
    assert.equal(check(o, "net-loopback-ssrf").evidence.find((e) => e.code === "net.ssrf-hit")?.tool, "fetch_file");
    assert.deepEqual(check(o, "net-loopback-ssrf").coverage?.probed, ["fetch_file"]);
  });

  it("net-ambig guarded: the same tool that refuses loopback with a reason passes both critical checks", () => {
    const o = out["ambig-guarded"];
    assert.equal(o.applies.ok, true);
    assert.equal(o.verdicts["net-loopback-ssrf"], "pass");
    assert.equal(o.verdicts["net-scheme-allowlist"], "pass");
    assert.equal(o.letter, "A");
  });

  it("near miss: save_report(path, title) has no url class and the net pack does not apply", () => {
    const o = out["ambig-nearmiss"];
    assert.equal(o.applies.ok, false);
    assert.match(o.applies.reason ?? "", /no tool is classified as taking a URL/);
    assert.equal(o.classification[0]!.secondary, undefined);
  });
});
