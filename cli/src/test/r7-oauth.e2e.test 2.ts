// Round 7 (docs/round7-design.md section 6): the oauth toy (toy/oauth-http.ts) through runHarness with the example config
// (fixtures/config/oauth-http.yaml) and nothing else. The correct toy passes every new check; each broken mode fails exactly the check for its
// one flaw (every check that is neither pass nor n/a is listed); a server that does not trust the stub issuer leaves the token checks
// inconclusive; reports never carry a minted token.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig, toSealmarkConfig, type EffectiveConfig } from "../config/index.js";
import { renderDoctor, runDoctor } from "../doctor.js";
import { startAuthServer } from "../observers/authserver.js";
import { JWT_SHAPE } from "../oauth.js";
import { pack as oauthPack } from "../packs/oauth.js";
import { FORMATS, renderReport } from "../report.js";
import { HarnessError, runHarness } from "../run.js";
import { startCredToy, type CredToy } from "../toy/cred-r6.js";
import { OAUTH_TOY_MODES, type OauthToyMode } from "../toy/oauth-http.js";
import type { PackCtx, PackId, RunResult, Verdict } from "../types.js";
import { freePort, quiet } from "./helpers.js";
import { effectiveFor } from "./packctx.js";

const FIXTURE = fileURLToPath(new URL("../../src/test/fixtures/config/oauth-http.yaml", import.meta.url));
const TOY = fileURLToPath(new URL("../toy/oauth-http.js", import.meta.url));

interface Expect {
  pack: PackId;
  check: string;
  verdict: Verdict;
}
const E = (pack: string, check: string, verdict: Verdict): Expect => ({ pack: pack as PackId, check, verdict });

/** One row per broken mode: the one check its flaw must fail, and nothing else may be anything but pass or n/a. */
const ROWS: { mode: Exclude<OauthToyMode, "good" | "strict-tls">; expect: Expect[]; why: string }[] = [
  { mode: "alg-none", expect: [E("oauth", "oauth-token-forgery", "fail")], why: "accepts alg none in any spelling" },
  { mode: "jku", expect: [E("oauth", "oauth-token-forgery", "fail")], why: "takes its key from the token's jku" },
  { mode: "hs-confusion", expect: [E("oauth", "oauth-token-forgery", "fail")], why: "HS256 keyed with the RSA public key" },
  { mode: "no-aud", expect: [E("oauth", "oauth-claims", "fail")], why: "ignores aud" },
  { mode: "no-exp", expect: [E("oauth", "oauth-claims", "fail")], why: "ignores exp" },
  { mode: "no-iss", expect: [E("oauth", "oauth-claims", "fail")], why: "ignores iss" },
  { mode: "query-token", expect: [E("oauth", "oauth-scope", "fail")], why: "reads ?access_token=" },
  { mode: "no-scope", expect: [E("oauth", "oauth-scope", "fail")], why: "ignores scope" },
  { mode: "passthrough", expect: [E("upstream", "upstream-token-passthrough", "fail")], why: "forwards the caller's token" },
  { mode: "session-unbound", expect: [E("http", "http-session-binding", "fail")], why: "a session serves any valid caller (advisory in http)" },
  { mode: "no-metadata", expect: [E("oauth", "oauth-discovery", "fail")], why: "no WWW-Authenticate challenge, no RFC 9728 metadata" },
];
const NEW_CHECKS = ["oauth-token-forgery", "oauth-claims", "oauth-discovery", "oauth-scope", "upstream-token-passthrough", "http-session-binding"];

let work: string;
before(() => {
  work = mkdtempSync(join(tmpdir(), "sm-r7-e2e-"));
});
after(() => rmSync(work, { recursive: true, force: true }));

async function runMode(mode: OauthToyMode, edit: (yaml: string) => string = (y) => y): Promise<RunResult> {
  const port = await freePort();
  const dir = mkdtempSync(join(work, "run-"));
  const text = edit(readFileSync(FIXTURE, "utf8").replaceAll("dist/toy/oauth-http.js", TOY).replaceAll("8080", String(port)).replace('"--mode", "good"', `"--mode", "${mode}"`));
  writeFileSync(join(dir, "sealmark.yaml"), text);
  const cfg: EffectiveConfig = loadEffectiveConfig({ cwd: dir, isolated: true, env: {} });
  return runHarness({ config: toSealmarkConfig(cfg), effective: cfg, packs: cfg.packs as PackId[], packsExplicit: cfg.packsExplicit, timeoutProbeSec: cfg.timeoutProbeSec, log: quiet });
}
const notPassing = (r: RunResult): string[] => r.checks.filter((c) => c.verdict !== "pass" && c.verdict !== "na").map((c) => `${c.pack}/${c.id}=${c.verdict}`).sort();
const verdictOf = (r: RunResult, id: string) => r.checks.find((c) => c.id === id);
/** A fresh, non-global copy: JWT_SHAPE is a /g regex, whose test() keeps state between calls. */
const hasJwt = (s: string): boolean => new RegExp(JWT_SHAPE.source).test(s);

describe("round 7 oauth matrix", { timeout: 1_200_000 }, () => {
  let good: RunResult;
  before(async () => {
    good = await runMode("good");
  });

  it("enumerates every broken mode of the toy exactly once (strict-tls is the https near miss, tested below)", () => {
    assert.deepEqual(ROWS.map((r) => r.mode).sort(), OAUTH_TOY_MODES.filter((m) => m !== "good" && m !== "strict-tls").sort());
  });

  it("good: every new check passes; oauth, upstream, http and core grade A; the pack was added by the declaration", () => {
    for (const id of NEW_CHECKS) assert.equal(verdictOf(good, id)?.verdict, "pass", `${id}: ${verdictOf(good, id)?.summary}`);
    for (const p of ["core", "http", "upstream", "oauth"]) {
      const pk = good.packs[p as PackId];
      assert.equal(pk?.status === "graded" ? pk.grade?.letter : pk?.status, "A", `pack ${p}`);
    }
    assert.deepEqual(notPassing(good), [], "good: every check passes or is n/a");
    assert.ok(good.warnings?.includes("oauth was declared in the config, so the pack is included"));
    // upstream-credential grades opaque per-caller tokens; with the stub issuer the tokens are audience-bound, so it steps aside.
    assert.equal(verdictOf(good, "upstream-credential")?.verdict, "na");
    assert.match(verdictOf(good, "upstream-credential")!.summary, /upstream-token-passthrough grades/);
    assert.deepEqual(good.identities, { names: ["a", "b"], source: "stub" });
    assert.equal(good.oauth?.mode, "stub");
    assert.equal(good.oauth?.tls, true, "https is the default (D41)");
    assert.equal(good.oauth?.jwksFetched, true, "the server fetched the stub's key set");
    assert.deepEqual(good.oauth?.scopes, ["mcp:tools"]);
    assert.equal(good.badge?.eligible, true, "a candidate pack never withholds the badge of a standard run");
    assert.equal(good.config?.standard, true, "declaring oauth adds coverage and keeps the run STANDARD");
  });

  it("good: the forgery evidence names every probe, and the control and the key-set fetch", () => {
    const f = verdictOf(good, "oauth-token-forgery")!;
    const codes = f.evidence.map((e) => e.code);
    assert.equal(codes.filter((c) => c === "oauth.forgery-refused").length, 16);
    assert.ok(codes.includes("oauth.control") && codes.includes("oauth.control.jwks-fetched"));
    assert.ok(f.evidence.every((e) => !hasJwt(`${e.probe} ${e.outcome}`)), "no token in evidence");
  });

  for (const row of ROWS) {
    it(`${row.mode}: ${row.expect.map((e) => `${e.check} ${e.verdict}`).join(", ")} (${row.why})`, { timeout: 120_000 }, async () => {
      const r = await runMode(row.mode);
      for (const e of row.expect) assert.equal(r.checks.find((c) => c.pack === e.pack && c.id === e.check)?.verdict, e.verdict, `${e.pack}/${e.check}: ${verdictOf(r, e.check)?.summary}`);
      assert.deepEqual(notPassing(r), row.expect.map((e) => `${e.pack}/${e.check}=${e.verdict}`).sort(), `${row.mode}: the checks that did not pass`);
      if (row.mode === "jku") assert.match(verdictOf(r, "oauth-token-forgery")!.summary, /fetched the attacker key URL/);
      if (row.mode === "session-unbound") assert.equal(verdictOf(r, "http-session-binding")!.advisory, true, "advisory in the standard http pack");
    });
  }

  it("a server that does not trust the stub issuer: the token checks are inconclusive and say what to set, never pass or fail", { timeout: 120_000 }, async () => {
    const r = await runMode("good", (y) => y.replace('TOY_ISSUER: "{issuer}"', 'TOY_ISSUER: "https://not-the-harness.example"'));
    for (const id of ["oauth-token-forgery", "oauth-claims", "oauth-scope"]) {
      const c = verdictOf(r, id)!;
      assert.equal(c.verdict, "inconclusive", id);
      assert.match(c.summary, /does not trust the harness issuer/);
      assert.match(c.summary, /\{issuer\}.*\{jwks\}.*\{audience\}/);
    }
    assert.equal(r.packs.core?.status, "inconclusive");
    assert.match(r.packs.core && "reason" in r.packs.core ? String(r.packs.core.reason) : "", /stub issuer signed/);
    assert.ok(r.suggestions?.some((s) => s.id === "oauth:trust" && s.kind === "oauth"), "a suggestion says what to set");
    assert.ok(r.checks.every((c) => !(["oauth-token-forgery", "oauth-claims", "oauth-scope"].includes(c.id) && ["pass", "fail"].includes(c.verdict))));
  });

  it("reports never carry a minted token, in any format; the issuer and its port are placeholders", async () => {
    const r = await runMode("passthrough");
    for (const run of [good, r]) {
      for (const f of FORMATS) {
        const out = renderReport(f, [run], { verbosity: "verbose" });
        assert.ok(!hasJwt(out), `${f}: a JWT-shaped string in the report`);
        assert.ok(!out.includes(String(run.oauth?.issuer).replace("http://", "")), `${f}: the issuer's real address`);
      }
      const json = JSON.parse(renderReport("json", [run])) as RunResult;
      assert.equal(json.oauth?.issuer, "{issuer}");
    }
  });

  it("the report normaliser rewrites any JWT a check carried (the backstop), in every format", async () => {
    const stub = await startAuthServer();
    try {
      const token = stub.mint({ iss: stub.issuer, sub: "sm-sub-a", aud: "x", exp: 1 });
      const leaked: RunResult = { ...good, checks: good.checks.map((c, i) => (i === 0 ? { ...c, summary: `${c.summary} ${token}`, evidence: [...c.evidence, { probe: "p", outcome: `Bearer ${token}`, verifiedBy: "response", excerpt: token }] } : c)) };
      for (const f of FORMATS) {
        const out = renderReport(f, [leaked], { verbosity: "verbose" });
        assert.ok(!out.includes(token) && !out.includes(token.split(".")[2]!), `${f} carries the raw token`);
      }
      assert.ok(renderReport("json", [leaked]).includes("{jwt}"));
    } finally {
      await stub.close();
    }
  });

  it("two runs of good give the same JSON apart from the fields the determinism claim lists", async () => {
    const again = await runMode("good");
    const strip = (r: RunResult): unknown => {
      const j = JSON.parse(renderReport("json", [r])) as Record<string, unknown> & { probes?: { calls?: { elapsedMs?: number }[] }; sandbox?: Record<string, unknown>; upstream?: Record<string, unknown>; server: Record<string, unknown> };
      delete j.startedAt;
      delete j.durationMs;
      if (j.sandbox) delete j.sandbox.listenerPort;
      for (const c of j.probes?.calls ?? []) delete c.elapsedMs;
      // The toy's own port is chosen per run by this test (the server URL and the audience carry it).
      return JSON.parse(JSON.stringify(j).replace(/127\.0\.0\.1:\d+/g, "127.0.0.1:{toy_port}"));
    };
    assert.deepEqual(strip(again), strip(good));
  });
});

describe("oauth pack without the stub", () => {
  let toy: CredToy;
  before(async () => {
    toy = await startCredToy("anon-open", { backend: "http://127.0.0.1:9" });
  });
  after(() => toy.close());

  const ctxFor = (issuer: "external" | null, url: string): PackCtx => {
    const config = effectiveFor({ name: "t", version: "0", server: { url } }, ["oauth"], { dir: work, parent: work }, { oauth: { issuer, audience: null, scopes: [], client_id: "sealmark" } } as never);
    return { pack: "oauth", config, tools: [], classification: [], open: () => Promise.reject(new Error("no sessions")), active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet, vars: {} };
  };

  it("oauth-discovery is n/a on a server that answers without a token (http-auth grades that); the token checks need the stub", async () => {
    const checks = await oauthPack.run(ctxFor("external", toy.url));
    const d = checks.find((c) => c.id === "oauth-discovery")!;
    assert.equal(d.verdict, "na");
    assert.match(d.summary, /without a token \(http-auth grades that\)/);
    for (const id of ["oauth-token-forgery", "oauth-claims", "oauth-scope"]) {
      const c = checks.find((x) => x.id === id)!;
      assert.equal(c.verdict, "na", id);
      assert.match(c.summary, /oauth\.issuer is external: needs the harness's stub issuer: pass --oauth/);
    }
  });

  it("does not apply to a stdio server", () => {
    const ctx = ctxFor("external", toy.url);
    const r = oauthPack.applies({ ...ctx, config: { ...ctx.config, server: { command: "node" } } });
    assert.equal(r.ok, false);
  });
});

describe("doctor with --oauth", { timeout: 300_000 }, () => {
  const doctorFor = async (edit: (y: string) => string = (y) => y) => {
    const port = await freePort();
    const dir = mkdtempSync(join(work, "doc-"));
    writeFileSync(join(dir, "sealmark.yaml"), edit(readFileSync(FIXTURE, "utf8").replaceAll("dist/toy/oauth-http.js", TOY).replaceAll("8080", String(port))));
    const cfg = loadEffectiveConfig({ cwd: dir, isolated: true, env: {} });
    return runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
  };

  it("starts the real stub issuer, so a server that trusts it starts as in a run, and says the oauth pack would run", async () => {
    const r = await doctorFor();
    assert.equal(r.ok, true, renderDoctor(r));
    const oauth = r.servers[0]!.packs.find((p) => p.pack === "oauth")!;
    assert.deepEqual([oauth.requested, oauth.applies], [true, true]);
    assert.ok(r.servers[0]!.items.some((i) => i.id === "pack-auto" && /oauth was declared/.test(i.title)));
  });

  it("a server that trusts another issuer: the advice names {issuer}, {jwks} and {audience} and this run's values", async () => {
    const r = await doctorFor((y) => y.replace('TOY_ISSUER: "{issuer}"', 'TOY_ISSUER: "https://not-the-harness.example"'));
    assert.equal(r.ok, false);
    const advice = r.servers[0]!.items.find((i) => i.id === "advice" && /stub issuer signed/.test(i.title))!;
    assert.ok(advice, renderDoctor(r));
    assert.match(advice.detail ?? "", /\{issuer\}.*\{jwks\}.*\{audience\}/);
    assert.match(advice.detail ?? "", /In this doctor run \{issuer\} was https:\/\/127\.0\.0\.1:\d+, \{ca_file\} \S+oauth-ca\.pem/);
    assert.match(advice.detail ?? "", /SSL_CERT_FILE/);
  });
});

describe("https stub issuer (D41) and a hardened server", { timeout: 600_000 }, () => {
  const strict = (y: string) => y.replace('TOY_REQUIRED_SCOPES: "mcp:tools"', 'TOY_REQUIRED_SCOPES: "mcp:tools"\n    TOY_CA_FILE: "{ca_file}"');

  it("strict-tls (refuses non-https trust roots, trusts {ca_file}): every new check passes over https", async () => {
    const r = await runMode("strict-tls", strict);
    for (const id of NEW_CHECKS) assert.equal(verdictOf(r, id)?.verdict, "pass", `${id}: ${verdictOf(r, id)?.summary}`);
    assert.deepEqual(notPassing(r), []);
    assert.equal(r.oauth?.tls, true);
    assert.equal(r.oauth?.jwksFetched, true, "the key set was fetched over https with the CA file");
    const json = renderReport("json", [r]);
    assert.ok(r.sandbox?.dir && !json.includes(r.sandbox.dir), "the CA file's real sandbox path is not in the report");
  });

  it("strict-tls with --no-oauth-tls refuses to start, and the error says https and {ca_file}", async () => {
    await assert.rejects(
      runMode("strict-tls", (y) => `${strict(y)}`.replace("oauth:\n  issuer: stub", "oauth:\n  issuer: stub\n  tls: false")),
      (e: unknown) => {
        assert.ok(e instanceof HarnessError, String(e));
        assert.match(e.hint ?? "", /oauth\.tls: false.*refuses to start.*https.*\{ca_file\}/);
        return true;
      },
    );
  });

  it("http mode still works for a server that accepts an http issuer", async () => {
    const r = await runMode("good", (y) => y.replace("oauth:\n  issuer: stub", "oauth:\n  issuer: stub\n  tls: false"));
    assert.equal(r.oauth?.tls, false);
    for (const id of ["oauth-token-forgery", "oauth-claims"]) assert.equal(verdictOf(r, id)?.verdict, "pass", id);
  });
});
