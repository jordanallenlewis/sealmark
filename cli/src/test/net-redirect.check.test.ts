// net-redirect on the toy servers, on a hand-made "server" for the cases a toy cannot make, and through the CLI (STANDARD stays STANDARD).
// The three scored net checks are re-asserted for every pre-existing toy mode: this check must not move any of them.
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { standardHash } from "../config/index.js";
import { gradePack } from "../grade.js";
import type { CallResult } from "../mcp.js";
import { targetProblem, pack, type Caller, type SsrfOutcome } from "../packs/net.js";
import { describeRedirect, redirectCheck } from "../packs/net-redirect.js";
import type { CheckResult, RunResult, Verdict } from "../types.js";
import { cliKit } from "./helpers.js";
import { directCtx, type Direct } from "./packctx.js";

const NET_TOY = fileURLToPath(new URL("../toy/net.js", import.meta.url));
const SCORED = ["net-loopback-ssrf", "net-scheme-allowlist", "net-caps"];

let parent: string;
const { writeYaml, writeConfig, sealmark, readJson } = cliKit(() => parent);

const toyConfig = (mode: string) => ({ name: `net-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [NET_TOY, "--mode", mode], env: {} as Record<string, string> } });

interface Outcome {
  checks: CheckResult[];
  verdicts: Record<string, Verdict>;
  redirect: CheckResult;
  /** The net letter from the three scored checks alone, and from every check: they must be the same. */
  letter?: string;
  letterAll?: string;
}
const outcomes: Record<string, Outcome> = {};
const directs: Direct[] = [];

async function runMode(mode: string): Promise<Outcome> {
  const where = { dir: parent, parent };
  const d = await directCtx(toyConfig(mode), "net", where);
  directs.push(d);
  assert.equal(pack.applies(d.ctx).ok, true, mode);
  const checks = await pack.run(d.ctx);
  const redirect = checks.find((c) => c.id === "net-redirect")!;
  return {
    checks,
    verdicts: Object.fromEntries(checks.filter((c) => c.id !== "net-redirect").map((c) => [c.id, c.verdict])),
    redirect,
    letter: gradePack("net", checks.filter((c) => SCORED.includes(c.id)))?.letter,
    letterAll: gradePack("net", checks)?.letter,
  };
}

const text = (c: CheckResult) => c.evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");

before(async () => {
  parent = mkdtempSync(join(tmpdir(), "sealmark-net-redirect-"));
  const modes = ["good", "open", "schemes", "slow", "silent", "dead", "deadrpc", "textfail", "decode", "jsquirk", "hop", "noredir", "anyscheme"];
  await Promise.all(modes.map(async (m) => void (outcomes[m] = await runMode(m))));
});
after(async () => {
  for (const d of directs) await d.close().catch(() => {});
  rmSync(parent, { recursive: true, force: true });
});

describe("net-redirect on the toy servers", { timeout: 240_000 }, () => {
  it("good, schemes, silent, dead, deadrpc, textfail, decode and jsquirk: n/a (the server blocks loopback or never fetched)", () => {
    for (const m of ["good", "schemes", "silent", "dead", "deadrpc", "textfail", "decode", "jsquirk"]) {
      const r = outcomes[m]!.redirect;
      assert.equal(r.verdict, "na", m);
      assert.equal(r.evidence.length, 0, m);
      assert.match(r.summary, /the server refused or never reached the loopback listener, so redirect handling could not be observed/, m);
    }
  });

  it("open and slow: redirects are followed, nothing was refused directly, so there is nothing to re-validate against: inconclusive (round 5, never half a point)", () => {
    for (const m of ["open", "slow"]) {
      const r = outcomes[m]!.redirect;
      assert.equal(r.verdict, "inconclusive", m);
      assert.match(r.summary, /^redirects are followed; re-validation cannot be measured on a server that accepts loopback targets directly/, m);
      assert.ok(r.evidence.some((e) => e.code === "net.redirect-followed" && e.verifiedBy === "listener"), m);
      // Node's fetch refuses a redirect to file: and gopher:, so no scheme finding.
      assert.ok(!r.evidence.some((e) => e.code === "net.redirect-file-read" || e.code === "net.redirect-raw-tcp" || e.code === "net.redirect-hop"), m);
      assert.ok(!r.evidence.some((e) => e.code === "net.redirect-refused-target"), m);
    }
  });

  it("hop: a redirect to localhost is followed although localhost was refused directly: fail, with the spelling in the summary", () => {
    const r = outcomes.hop!.redirect;
    assert.equal(r.verdict, "fail");
    // The toy refuses [::1] too: with an IPv6 listener the second hop, to [::1], is a finding as well (round 5).
    assert.match(r.summary, /^the server followed a redirect to a target it refused when given directly \(localhost\)(; the server followed a redirect to a target it refused when given directly \(\[::1\]\))?$/);
    const ev = r.evidence.find((e) => e.code === "net.redirect-hop")!;
    assert.equal(ev.verifiedBy, "listener");
    assert.match(ev.outcome, /localhost, a spelling it refused when given directly \(Host: localhost:\d+\)/);
    assert.ok(!r.evidence.some((e) => e.code === "net.redirect-file-read" || e.code === "net.redirect-raw-tcp"));
    // The three scored checks: loopback allowed, http(s) only, size cap but no time cap.
    assert.deepEqual(outcomes.hop!.verdicts, { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "pass", "net-caps": "part" });
  });

  it("noredir: the 302 is reported and never followed: pass", () => {
    const r = outcomes.noredir!.redirect;
    assert.equal(r.verdict, "pass");
    assert.equal(r.summary, "redirects are not followed: the server fetched the redirecting URL and stopped at the 302");
    assert.ok(r.evidence.length >= 4 && r.evidence.every((e) => e.code === "net.redirect-stopped"), text(r));
    assert.deepEqual(outcomes.noredir!.verdicts, { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "pass", "net-caps": "fail" });
  });

  it("anyscheme: a redirect to a file: URL returns the canary and one to gopher: opens a raw connection: fail", () => {
    const r = outcomes.anyscheme!.redirect;
    assert.equal(r.verdict, "fail");
    assert.match(r.summary, /redirect to a file: URL and returned the sandbox canary/);
    assert.match(r.summary, /redirect to a gopher: URL and opened a raw connection/);
    const file = r.evidence.find((e) => e.code === "net.redirect-file-read")!;
    assert.equal(file.verifiedBy, "response");
    const raw = r.evidence.find((e) => e.code === "net.redirect-raw-tcp")!;
    assert.equal(raw.verifiedBy, "listener");
    assert.deepEqual(outcomes.anyscheme!.verdicts, { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "fail", "net-caps": "part" });
  });

  it("the three scored net checks keep their verdicts on every pre-existing mode (the table in net.test.ts)", () => {
    const table: Record<string, Record<string, Verdict>> = {
      good: { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "pass", "net-caps": "na" },
      open: { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "fail", "net-caps": "part" },
      schemes: { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "fail", "net-caps": "na" },
      slow: { "net-loopback-ssrf": "fail", "net-scheme-allowlist": "pass", "net-caps": "fail" },
      silent: { "net-loopback-ssrf": "inconclusive", "net-scheme-allowlist": "inconclusive", "net-caps": "na" },
      dead: { "net-loopback-ssrf": "inconclusive", "net-scheme-allowlist": "inconclusive", "net-caps": "na" },
      deadrpc: { "net-loopback-ssrf": "inconclusive", "net-scheme-allowlist": "inconclusive", "net-caps": "na" },
      textfail: { "net-loopback-ssrf": "inconclusive", "net-scheme-allowlist": "inconclusive", "net-caps": "na" },
      decode: { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "part", "net-caps": "na" },
      jsquirk: { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "pass", "net-caps": "na" },
    };
    for (const [m, want] of Object.entries(table)) assert.deepEqual(outcomes[m]!.verdicts, want, m);
  });

  it("the result order is unchanged: net-caps stays third, net-redirect is last", () => {
    assert.deepEqual(outcomes.open!.checks.map((c) => c.id), ["net-loopback-ssrf", "net-scheme-allowlist", "net-caps", "net-redirect"]);
  });

  it("net-redirect is scored and not critical in every result, so the net letter now includes it (0.3-draft promotion)", () => {
    for (const [m, o] of Object.entries(outcomes)) {
      assert.equal(o.redirect.advisory, undefined, `${m}: scored, so no advisory flag`);
      assert.equal(o.redirect.critical, false, m);
    }
    // A scored n/a check is left out of the grade, so the modes where the server blocks loopback keep their letter.
    for (const m of ["good", "schemes", "silent", "dead", "deadrpc", "textfail", "decode", "jsquirk"]) assert.equal(outcomes[m]!.letterAll, outcomes[m]!.letter, m);
    assert.equal(outcomes.open!.letterAll, "F");
    assert.equal(outcomes.slow!.letterAll, "F");
    assert.equal(outcomes.good!.letterAll, "A");
    // The verdict change of the promotion: hop passed the three older checks to a D; its failed redirect check now pulls the net grade to F.
    assert.equal(outcomes.hop!.letter, "D");
    assert.equal(outcomes.hop!.letterAll, "F");
    // And the other way: noredir was an F from the older three; a passing, now scored, redirect check lifts the net grade to a D.
    assert.equal(outcomes.noredir!.letter, "F");
    assert.equal(outcomes.noredir!.letterAll, "D");
    assert.equal(outcomes.anyscheme!.letterAll, "F");
  });

  it("every URL sent passes the net pack's target gate, and no evidence names another host", () => {
    for (const [m, o] of Object.entries(outcomes)) {
      const sandboxDir = directs.find((d) => d.ctx.config?.server.args?.includes(m))!.sandbox.dir;
      for (const e of o.redirect.evidence) {
        const url = (e.args as { url?: string } | undefined)?.url;
        if (!url) continue;
        const u = new URL(url);
        assert.match(u.pathname, /^\/redir(?:-to)?\//, m);
        const ports = [Number(u.port)];
        assert.equal(targetProblem(url, { sandboxDir, ports, allowDns: false }), undefined, `${m}: ${url}`);
        const to = u.searchParams.get("to");
        if (to) assert.equal(targetProblem(to, { sandboxDir, ports, allowDns: false }), undefined, `${m}: ${to}`);
      }
    }
  });

  it("the listener never had to refuse its own redirect target (no net.redirect-refused-target on any toy)", () => {
    for (const [m, o] of Object.entries(outcomes)) assert.ok(!o.redirect.evidence.some((e) => e.code === "net.redirect-refused-target"), m);
  });

  it("coverage lists the tool and the number of calls sent", () => {
    for (const m of ["open", "hop", "noredir", "anyscheme"]) {
      // Four probes, and a fifth (the hop to [::1]) when the host has an IPv6 loopback listener (round 5).
      const hop6 = outcomes[m]!.redirect.evidence.some((e) => e.probe.includes(" hop6:") && e.verifiedBy !== "static");
      assert.deepEqual(outcomes[m]!.redirect.coverage, { probed: ["fetch"], notCovered: [], validCalls: hop6 ? 5 : 4 }, m);
    }
  });

  it("describeRedirect: the documented probes, scored, not critical, shipped since 0.2-draft", () => {
    const [d] = describeRedirect();
    assert.deepEqual(d!.probes.map((p) => p.id), ["follow", "hop", "scheme-file", "scheme-raw"]);
    assert.deepEqual([d!.id, d!.critical, d!.advisory, d!.since, d!.status], ["net-redirect", false, false, "0.2-draft", "shipped"]);
  });
});

// A "server" that is not a toy: it follows a redirect itself and chooses the Host header of the request that follows.
describe("net-redirect: what counts as a hop", { timeout: 60_000 }, () => {
  const get = (url: string, host?: string, connectTo?: { host: string; port: number }) =>
    new Promise<{ status: number; location?: string; body: string }>((resolve, reject) => {
      const u = new URL(url);
      const req = http.request({ host: connectTo?.host ?? u.hostname.replace(/^\[|\]$/g, ""), port: connectTo?.port ?? Number(u.port), path: u.pathname + u.search, headers: host ? { host } : {} }, (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c.toString("latin1")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, location: res.headers.location, body }));
      });
      req.on("error", reject);
      req.end();
    });
  const reply = (text: string): CallResult => ({ isError: false, text, elapsedMs: 0, timedOut: false, closed: false });

  /** A Caller whose server fetches the URL it is given and follows a 302 with `follow(locationUrl, port)`. */
  const caller = (follow: (location: URL, port: number) => Promise<string>): Caller =>
    ({
      async call(_tool: string, args: Record<string, unknown>) {
        const url = String(args.url);
        const first = await get(url, undefined, { host: "127.0.0.1", port: Number(new URL(url).port) });
        if (first.status === 302 && first.location && /^https?:/.test(first.location) === false && first.location.startsWith("/")) {
          return reply((await get(new URL(first.location, url).href, undefined, { host: "127.0.0.1", port: Number(new URL(url).port) })).body);
        }
        if (first.status === 302 && first.location && /^https?:/.test(first.location)) return reply(await follow(new URL(first.location), Number(new URL(url).port)));
        return reply(first.body);
      },
      async drop() {},
    }) as unknown as Caller;

  let d: Direct;
  before(async () => {
    d = await directCtx(toyConfig("good"), "net", { dir: parent, parent });
  });
  after(async () => {
    await d.close();
  });

  const ssrf = (refused: string[]): SsrfOutcome => ({
    result: { id: "net-loopback-ssrf" } as CheckResult,
    allowed: { target: { tool: d.ctx.tools![0]!, cls: d.ctx.classification![0]!, urlParam: "url" }, template: "http://127.0.0.1:{port}/t/{token}" },
    refused: refused.map((template, i) => ({ id: `r${i}`, template })),
  });

  it("a server that follows to the refused spelling and sends that Host is a hop: fail", async () => {
    const honest = caller((loc, port) => get(loc.href, loc.host, { host: "127.0.0.1", port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, honest, ssrf(["http://localhost:{port}/t/{token}"]), true);
    assert.equal(r.verdict, "fail");
    assert.match(r.summary, /\(localhost\)/);
    assert.ok(r.evidence.some((e) => e.code === "net.redirect-hop"));
  });

  it("a request that follows with the same Host as the original fetch is not a hop, even though it followed (must fail)", async () => {
    const rewriter = caller((loc, port) => get(loc.href, `127.0.0.1:${port}`, { host: "127.0.0.1", port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, rewriter, ssrf(["http://localhost:{port}/t/{token}"]), true);
    assert.notEqual(r.verdict, "fail");
    assert.equal(r.verdict, "part");
    assert.ok(!r.evidence.some((e) => e.code === "net.redirect-hop"), text(r));
    assert.match(text(r), /the Host header does not show that spelling/);
    assert.doesNotMatch(r.summary, /refused when given directly/);
  });

  it("a refused spelling that the URL parser rewrites to the fetched host is never the hop target", async () => {
    // 127.1 becomes 127.0.0.1 in the Host header: following it could not be told from a plain follow, so localhost is used instead.
    const honest = caller((loc, port) => get(loc.href, loc.host, { host: "127.0.0.1", port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, honest, ssrf(["http://127.1:{port}/t/{token}"]), true);
    assert.equal(r.verdict, "inconclusive");
    assert.ok(!r.evidence.some((e) => e.code === "net.redirect-hop"), text(r));
    assert.match(r.summary, /cannot be measured/);
  });

  it("with an earlier refused spelling that cannot be told apart, the next one that can is used", async () => {
    const honest = caller((loc, port) => get(loc.href, loc.host, { host: "127.0.0.1", port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, honest, ssrf(["http://127.1:{port}/t/{token}", "http://localhost:{port}/t/{token}"]), true);
    assert.equal(r.verdict, "fail");
    assert.match(r.summary, /\(localhost\)/);
  });

  it("a server that follows same-origin redirects and refuses the redirect to the spelling it refused directly re-validates: pass (round 4, A3)", async () => {
    const stops = caller(async () => "blocked: localhost is not allowed");
    const r = await redirectCheck(d.ctx, stops, ssrf(["http://localhost:{port}/t/{token}"]), true);
    assert.equal(r.verdict, "pass", text(r));
    assert.equal(r.summary, "redirects are followed and the redirect to localhost, which the server refused when given directly, was not: the target is re-validated");
    assert.ok(r.evidence.some((e) => e.code === "net.redirect-stopped" && /302 to localhost/.test(e.outcome)), text(r));
    assert.ok(r.evidence.some((e) => e.code === "net.redirect-followed"), text(r));
  });

  it("the same server is part, not pass, when the hop probe's redirecting request never reached the listener (nothing to say it re-validated)", async () => {
    const inner = caller(async () => "blocked: localhost is not allowed");
    const lost = {
      async call(tool: string, args: Record<string, unknown>) {
        if (String(args.url).includes("/redir-to/")) return reply("nothing was fetched");
        return (inner as unknown as { call(t: string, a: Record<string, unknown>): Promise<CallResult> }).call(tool, args);
      },
      async drop() {},
    } as unknown as Caller;
    const r = await redirectCheck(d.ctx, lost, ssrf(["http://localhost:{port}/t/{token}"]), true);
    assert.equal(r.verdict, "part", text(r));
    assert.match(r.summary, /redirects are followed; the redirect probe to localhost could not be sent, or the listener did not see its redirecting request/);
  });

  it("a server that follows the hop to a spelling it never refused cannot be measured: inconclusive (no refused spelling to compare with)", async () => {
    const honest = caller((loc, port) => get(loc.href, loc.host, { host: "127.0.0.1", port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, honest, ssrf([]), true);
    assert.equal(r.verdict, "inconclusive");
    assert.match(r.summary, /re-validation cannot be measured on a server that accepts loopback targets directly/);
  });

  it("an IPv6 refused spelling is sent as [::1] on the listener's IPv6 port and is a hop when that Host comes back", async function (t) {
    if (d.ctx.sandbox!.listener.port6 === undefined) return t.skip("no IPv6 loopback on this host");
    const honest = caller((loc, port) => get(loc.href, loc.host, { host: "::1", port: Number(loc.port) || port }).then((r) => r.body));
    const r = await redirectCheck(d.ctx, honest, ssrf(["http://[::1]:{port6}/t/{token}"]), true);
    assert.equal(r.verdict, "fail", text(r));
    assert.match(r.summary, /\(\[::1\]\)/);
  });

  it("n/a without an allowed form, and when net-loopback-ssrf did not run; inconclusive when the first hop is never seen", async () => {
    const none = caller(async () => "");
    const refused = await redirectCheck(d.ctx, none, { result: {} as CheckResult, refused: [] }, true);
    assert.equal(refused.verdict, "na");
    assert.match(refused.summary, /server refused or never reached the loopback listener/);
    const skipped = await redirectCheck(d.ctx, none, { result: {} as CheckResult, refused: [] }, false);
    assert.equal(skipped.verdict, "na");
    assert.equal(skipped.summary, "net-loopback-ssrf did not run, so no loopback URL is known to be fetchable");
    const silent: Caller = { async call() { return reply("ok"); }, async drop() {} } as unknown as Caller;
    const lost = await redirectCheck(d.ctx, silent, ssrf([]), true);
    assert.equal(lost.verdict, "inconclusive");
    assert.equal(lost.summary, "the listener did not see the redirect probe, so redirect handling could not be observed");
    assert.equal(lost.coverage?.validCalls, 1);
  });

  it("disabled by config reports n/a with that text and sends nothing; a severity override is honoured", async () => {
    let calls = 0;
    const counting: Caller = { async call() { calls++; return reply(""); }, async drop() {} } as unknown as Caller;
    const off = { ...d.ctx, config: { ...d.ctx.config!, checks: { ...d.ctx.config!.checks, "net-redirect": { enabled: false, severity: null } } } };
    const r = await redirectCheck(off, counting, ssrf([]), true);
    assert.equal(r.verdict, "na");
    assert.match(r.summary, /^disabled by config/);
    assert.equal(calls, 0);
    const scored = { ...d.ctx, config: { ...d.ctx.config!, checks: { ...d.ctx.config!.checks, "net-redirect": { enabled: true, severity: "scored" as const } } } };
    const s = await redirectCheck(scored, caller(async () => ""), ssrf([]), true);
    assert.equal(s.advisory, undefined, "severity: scored counts (it is also the default now)");
    const adv = { ...d.ctx, config: { ...d.ctx.config!, checks: { ...d.ctx.config!.checks, "net-redirect": { enabled: true, severity: "advisory" as const } } } };
    assert.equal((await redirectCheck(adv, caller(async () => ""), ssrf([]), true)).advisory, true, "severity: advisory removes it from the score");
    assert.equal(s.critical, false);
    const crit = { ...d.ctx, config: { ...d.ctx.config!, checks: { ...d.ctx.config!.checks, "net-redirect": { enabled: true, severity: "critical" as const } } } };
    assert.equal((await redirectCheck(crit, caller(async () => ""), ssrf([]), true)).critical, true);
  });
});

describe("net-redirect through the CLI", { timeout: 240_000 }, () => {
  const FAST_NET = ["--pack", "net", "--timeout-probe", "2", "--fail-under", "none"];

  it("a STANDARD run (toy open) prints STANDARD, keeps the standard hash and the net letter, and lists the scored check", () => {
    const cfg = writeConfig("open.yaml", process.execPath, [NET_TOY, "--mode", "open"]);
    const json = join(parent, "open.json");
    // No --pack and no --timeout-probe: either one is a CUSTOM run. The toy is a net server, so the other packs are n/a.
    const r = sealmark(["run", "--config", cfg, "--fail-under", "none", "--format", "json", "--out", json]);
    assert.equal(r.code, 0, r.err);
    const run = readJson<RunResult>(json);
    assert.equal(run.config?.standard, true);
    assert.deepEqual(run.config?.standardDiff, []);
    assert.equal(run.config?.hash, standardHash());
    assert.equal(run.packs.net?.grade?.letter, "F");
    const redirect = run.checks.find((c) => c.id === "net-redirect")!;
    assert.equal(redirect.verdict, "inconclusive");
    assert.equal(redirect.advisory, undefined, "scored since the 0.3-draft promotion");
    assert.deepEqual(run.checks.filter((c) => c.pack === "net" && c.id !== "net-redirect").map((c) => [c.id, c.verdict]), [
      ["net-loopback-ssrf", "fail"],
      ["net-scheme-allowlist", "fail"],
      ["net-caps", "part"],
    ]);
    const text = sealmark(["run", "--config", cfg, "--fail-under", "none"]);
    assert.match(text.out, /STANDARD/);
    assert.match(text.out, /\[INCL\] Redirects are re-validated/);
    assert.doesNotMatch(text.out, /\[ADV \] \[INCL\] Redirects are re-validated/);
  });

  it("checks.net-redirect.severity: advisory takes the check out of the score and makes the run CUSTOM", () => {
    const cfg = writeYaml(
      "advisory.yaml",
      `schema_version: 1\nname: advisory\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([NET_TOY, "--mode", "hop"])}\nchecks:\n  net-redirect:\n    severity: advisory\n  net-caps:\n    enabled: false\n`,
    );
    const json = join(parent, "advisory.json");
    const r = sealmark(["run", "--config", cfg, ...FAST_NET, "--format", "json", "--out", json]);
    assert.equal(r.code, 0, r.err);
    const run = readJson<RunResult>(json);
    assert.equal(run.config?.standard, false);
    assert.ok(run.config?.standardDiff.some((x) => x.path === "checks.net-redirect.severity"));
    const redirect = run.checks.find((c) => c.id === "net-redirect")!;
    assert.equal(redirect.verdict, "fail");
    assert.equal(redirect.advisory, true);
  });

  it("checks.net-redirect.enabled: false gives n/a 'disabled by config' and a CUSTOM run", () => {
    const cfg = writeYaml(
      "off.yaml",
      `schema_version: 1\nname: off\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([NET_TOY, "--mode", "hop"])}\nchecks:\n  net-redirect:\n    enabled: false\n  net-caps:\n    enabled: false\n`,
    );
    const json = join(parent, "off.json");
    const r = sealmark(["run", "--config", cfg, ...FAST_NET, "--format", "json", "--out", json]);
    assert.equal(r.code, 0, r.err);
    const run = readJson<RunResult>(json);
    assert.equal(run.config?.standard, false);
    assert.ok(run.config?.standardDiff.some((x) => x.path === "checks.net-redirect.enabled"));
    const redirect = run.checks.find((c) => c.id === "net-redirect")!;
    assert.equal(redirect.verdict, "na");
    assert.match(redirect.summary, /^disabled by config/);
  });

  it("standardHash() equals the pinned fixture", () => {
    const fixture = join(fileURLToPath(new URL("../../src/test/fixtures/config/", import.meta.url)), "standard.hash.txt");
    assert.equal(standardHash(), readFileSync(fixture, "utf8").split("\r\n").join("\n").trim());
  });
});
