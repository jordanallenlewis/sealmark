// Round 7 (docs/round7-design.md sections 2 and 5): the oauth keys, the --oauth flag, the placeholders, the errors that say what to type,
// STANDARD vs CUSTOM and the unmoved hash, and what describe, list-checks and explain publish for the six new check ids.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CHECKS, CANDIDATE_CHECKS, ConfigError, PACK_IDS, SCHEMA, STANDARD_PACKS, loadEffectiveConfig, type EffectiveConfig, type LoadOptions } from "../config/index.js";
import { HARNESS_KEYS } from "../config/placeholders.js";
import { describeAllJson } from "../describe.js";
import { autoAddedPacks, suggestionsAfterRun } from "../doctor.js";
import { REMEDIATION, explainCheck, listChecks, renderExplain } from "../explain.js";
import { describeAll, RUN_ORDER } from "../packs/index.js";
import { validateProbes } from "../probes.js";
import { CANDIDATE_PACKS, BUILTIN_PACKS } from "../types.js";

const PINNED = readFileSync(fileURLToPath(new URL("../../src/test/fixtures/config/standard.hash.txt", import.meta.url)), "utf8").trim();
let root: string;
let n = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-r7cfg-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

const LAUNCHED = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n  env: { OAUTH_ISSUER: '{issuer}', OAUTH_JWKS_URL: '{jwks}', OAUTH_AUDIENCE: '{audience}' }\n  url: http://127.0.0.1:8080/mcp\n";
const load = (text: string, o: Partial<LoadOptions> = {}): EffectiveConfig => {
  const dir = join(root, `p${n++}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "sealmark.yaml"), text);
  return loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, ...o });
};
const bad = (text: string, o: Partial<LoadOptions> = {}): string => {
  try {
    load(text, o);
  } catch (e) {
    assert.ok(e instanceof ConfigError, String(e));
    return e.message;
  }
  return assert.fail("expected a ConfigError");
};

const R7 = [
  { id: "oauth-token-forgery", pack: "oauth", critical: true, advisory: false },
  { id: "oauth-claims", pack: "oauth", critical: true, advisory: false },
  { id: "oauth-discovery", pack: "oauth", critical: false, advisory: false },
  { id: "oauth-scope", pack: "oauth", critical: false, advisory: false },
  { id: "upstream-token-passthrough", pack: "upstream", critical: true, advisory: false },
  { id: "http-session-binding", pack: "http", critical: false, advisory: true },
];

describe("r7 config: oauth keys and --oauth", () => {
  it("defaults declare nothing; --oauth sets oauth.issuer: stub and the harness sends the identities as Authorization: Bearer {bearer}", () => {
    const none = load(LAUNCHED.replace(/\n {2}env:.*\n/, "\n"));
    assert.deepEqual(none.oauth, { issuer: null, audience: null, scopes: [], client_id: "sealmark", tls: true });
    const cfg = load(LAUNCHED, { flags: { oauth: true } });
    assert.equal(cfg.oauth?.issuer, "stub");
    assert.deepEqual(cfg.server.headers, { Authorization: "Bearer {bearer}" });
    assert.equal(cfg.origins["/oauth/issuer"]?.layer, "flag");
    // D41: https by default; --no-oauth-tls (or oauth.tls: false, or the env variable) serves http.
    assert.equal(cfg.oauth?.tls, true);
    assert.equal(load(LAUNCHED, { flags: { oauth: true, "oauth-tls": false } }).oauth?.tls, false);
    assert.equal(load(LAUNCHED, { flags: { oauth: true }, env: { SEALMARK_OAUTH__TLS: "false" } }).oauth?.tls, false);
  });

  it("the file form, and an env variable, set the same keys", () => {
    const cfg = load(`${LAUNCHED}oauth:\n  issuer: stub\n  audience: https://mcp.example/mcp\n  scopes: [mcp:tools, mcp:read]\n  client_id: my-client\n`);
    assert.deepEqual(cfg.oauth, { issuer: "stub", audience: "https://mcp.example/mcp", scopes: ["mcp:tools", "mcp:read"], client_id: "my-client", tls: true });
    const env = load(LAUNCHED, { env: { SEALMARK_OAUTH__ISSUER: "stub" } });
    assert.equal(env.oauth?.issuer, "stub");
  });

  it("a header the user wrote with {bearer} is kept as written", () => {
    const cfg = load(`${LAUNCHED}  headers: { X-Token: "Bearer {bearer}" }\noauth: { issuer: stub }\n`);
    assert.deepEqual(cfg.server.headers, { "X-Token": "Bearer {bearer}" });
  });

  it("{issuer}, {jwks} and {audience} are harness placeholders", () => {
    for (const k of ["issuer", "jwks", "audience", "ca_file"]) assert.ok(HARNESS_KEYS.includes(k), k);
    const names = describeAllJson().placeholders.map((p) => p.name).join(" | ");
    assert.ok(names.includes("{issuer} {jwks} {audience} {ca_file}"));
  });

  it("errors say what to type", () => {
    assert.match(bad("schema_version: 1\nserver:\n  command: node\n  args: [srv.js, '{issuer}']\noauth: { issuer: stub }\n"), /oauth\.issuer needs an HTTP server \(server\.url\)/);
    assert.match(bad("schema_version: 1\nserver:\n  url: http://127.0.0.1:8080/mcp\noauth: { issuer: stub }\n"), /needs a server Sealmark starts .*Use oauth\.issuer: external/);
    assert.match(bad("schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n  url: http://127.0.0.1:8080/mcp\noauth: { issuer: stub }\n"), /never use \{issuer\} or \{jwks\}.*OAUTH_ISSUER: "\{issuer\}"/);
    assert.match(bad(`${LAUNCHED}  headers: { Authorization: "Bearer fixed-value" }\noauth: { issuer: stub }\n`), /has a fixed value, but oauth\.issuer: stub sends tokens the harness's issuer signed: write Authorization: "Bearer \{bearer\}"/);
    assert.match(bad(`${LAUNCHED}oauth: { issuer: stub }\nidentities: { a: tok-a }\n`), /identities\.a and identities\.b cannot be used with oauth\.issuer: stub/);
    assert.match(bad(`${LAUNCHED}oauth: { scopes: [x] }\n`), /oauth\.scopes is set but oauth\.issuer is not: set oauth\.issuer: stub \(or pass --oauth\)/);
    assert.match(bad(`${LAUNCHED}oauth: { issuer: maybe }\n`), /stub|external/);
  });

  it("external works for a server that is already running", () => {
    const cfg = load("schema_version: 1\nserver:\n  url: http://127.0.0.1:8080/mcp\n  headers: { Authorization: 'Bearer ${TOKEN}' }\noauth: { issuer: external }\n", { env: { TOKEN: "t0k3n-value" } });
    assert.equal(cfg.oauth?.issuer, "external");
    assert.deepEqual(cfg.server.headers, { Authorization: "Bearer ${TOKEN}" }, "external never rewrites the headers");
  });
});

describe("r7 config: STANDARD, CUSTOM and the hash", () => {
  it("the new checks are unlocked candidates with no corpus leaves; the oauth keys are unlocked", () => {
    for (const { id } of R7) {
      assert.ok(CHECKS.find((c) => c.id === id)?.candidate, id);
      assert.ok((CANDIDATE_CHECKS as readonly string[]).includes(id), id);
      for (const k of ["enabled", "severity"]) assert.ok(SCHEMA.some((l) => l.path === `checks.${id}.${k}` && !l.standardLocked), `${id}.${k}`);
    }
    for (const k of ["oauth.issuer", "oauth.audience", "oauth.scopes", "oauth.client_id", "oauth.tls"]) assert.ok(SCHEMA.some((l) => l.path === k && !l.standardLocked), k);
  });

  it("declaring oauth keeps a run STANDARD with the pinned hash; disabling a candidate check makes it CUSTOM", () => {
    const cfg = load(`${LAUNCHED}oauth: { issuer: stub, scopes: [mcp:tools] }\n`);
    assert.equal(cfg.integrity.standard, true);
    assert.equal(cfg.integrity.hash, PINNED);
    const off = load(`${LAUNCHED}oauth: { issuer: stub }\nchecks:\n  oauth-claims: { enabled: false }\n`);
    assert.equal(off.integrity.standard, false);
    assert.deepEqual(off.integrity.standardDiff.map((d) => d.path), ["checks.oauth-claims.enabled"]);
    assert.equal(off.integrity.hash, PINNED);
  });

  it("oauth is a candidate pack: a valid pack name, outside the standard, registered and in the run order", () => {
    assert.ok((PACK_IDS as readonly string[]).includes("oauth"));
    assert.ok((BUILTIN_PACKS as readonly string[]).includes("oauth"));
    assert.ok(CANDIDATE_PACKS.includes("oauth"));
    assert.ok(!STANDARD_PACKS.includes("oauth"));
    assert.ok(RUN_ORDER.includes("oauth"));
  });

  it("the declaration adds the pack to a list nobody chose, and is reported skipped from a list the user chose", () => {
    const cfg = load(`${LAUNCHED}oauth: { issuer: stub }\n`);
    const auto = autoAddedPacks(cfg, { hasSqlTool: false });
    assert.deepEqual(auto.packs, ["oauth"]);
    assert.deepEqual(auto.notes, ["oauth was declared in the config, so the pack is included"]);
    const chosen = load(`${LAUNCHED}oauth: { issuer: stub }\npacks: [core, http]\n`);
    assert.match(autoAddedPacks(chosen, { hasSqlTool: false }).skipped.join("\n"), /oauth was declared in the config but the pack list omits oauth/);
  });

  it("{issuer}, {jwks} and {audience} are refused in a probe's arguments, with the reason", () => {
    const tools = [{ name: "lookup", inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } }];
    assert.throws(() => validateProbes([{ tool: "lookup", args: { id: "{issuer}" } } as never], { tools: tools as never, classification: [] }), /\{issuer\}, \{jwks\}, \{audience\} and \{ca_file\} cannot be used in a probe's arguments/);
  });

  it("after a run, an inconclusive token check because of trust becomes an oauth suggestion with the YAML to paste", () => {
    const s = suggestionsAfterRun([{ id: "oauth-claims", verdict: "inconclusive", summary: "... the server does not trust the harness issuer, so ..." }]);
    const o = s.find((x) => x.id === "oauth:trust")!;
    assert.equal(o.kind, "oauth");
    assert.match(o.config, /OAUTH_ISSUER: "\{issuer\}"/);
    assert.deepEqual(o.flags, ["--oauth"]);
  });
});

describe("r7: describe, list-checks and explain", () => {
  it("every new id is in the registry with its pack, severity and docs fields", () => {
    for (const r of R7) {
      const d = describeAll().find((x) => x.id === r.id);
      assert.ok(d, r.id);
      assert.deepEqual([d.pack, d.critical, d.advisory, d.status, d.since], [r.pack, r.critical, r.advisory, "shipped", "0.3-draft"], r.id);
      assert.ok(d.probes.length && d.falsePositive && d.falseNegative && d.configKeys.length, r.id);
    }
    const j = describeAllJson();
    assert.deepEqual(j.packs.find((p) => p.id === "oauth"), { id: "oauth", standard: false, candidate: true, checks: ["oauth-token-forgery", "oauth-claims", "oauth-discovery", "oauth-scope"] });
    assert.equal(j.checks.find((c) => c.id === "upstream-token-passthrough")?.candidatePack, true);
    assert.equal(j.checks.find((c) => c.id === "http-session-binding")?.candidatePack, false);
  });

  it("list-checks --pack oauth lists the four oauth checks", () => {
    assert.deepEqual(listChecks({ pack: "oauth" }).map((c) => c.id), ["oauth-token-forgery", "oauth-claims", "oauth-discovery", "oauth-scope"]);
    assert.ok(listChecks({ pack: "http" }).some((c) => c.id === "http-session-binding" && c.severity === "advisory"));
  });

  it("explain works for each new id, with remediation text and the published corpus", () => {
    for (const { id } of R7) {
      const e = explainCheck(id);
      assert.ok((REMEDIATION[id] ?? "").length > 80, id);
      const text = renderExplain(e);
      assert.match(text, /What to fix:\n {2}\S/);
      assert.ok(text.includes(REMEDIATION[id]!.slice(0, 40)), id);
    }
    const forgery = renderExplain(explainCheck("oauth-token-forgery"));
    for (const p of ["alg-none", "alg-NONE-nodot", "hs256-pem", "jku", "x5u", "kid-traversal", "untrusted-key", "payload-tampered"]) assert.ok(forgery.includes(`- ${p} (`), p);
    assert.match(renderExplain(explainCheck("oauth-claims")), /other-resource/);
  });
});
