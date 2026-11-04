// The `oauth` candidate pack (docs/round7-design.md): does the server check the bearer tokens it is sent, as the MCP authorization specification
// (2025-06-18) and the OAuth documents it builds on require? Scored inside its own pack, labelled, off the badge (decision D34, D38).
//
// The token checks need the harness's stub authorization server (`oauth.issuer: stub`, `--oauth`): the server under test is configured to trust
// {issuer}/{jwks} for {audience}, the harness signs a well-formed control token, and every probe is the same request with one thing wrong. A
// control the server refuses makes those checks inconclusive, never a pass or a fail. oauth-discovery needs no stub: it reads what the server
// tells a client that has no token (RFC 9728). Everything goes to the configured server URL (and same-origin metadata URLs) with fetch, never
// through the MCP SDK; no token is ever written into evidence.
import { randomBytes } from "node:crypto";
import { looksSecret, stripUserinfo } from "../config/placeholders.js";
import { expandHarness } from "../mcp.js";
import { OAUTH_SUB, OAUTH_TRUST_HINT, accessTokenClaims, canonicalResource, oauthSettings, sameResource } from "../oauth.js";
import type { AuthServerMintOptions, AuthServerStub, CheckDoc, CheckResult, Evidence, Pack, PackApplies, PackCtx, PackId, Verdict } from "../types.js";
import { describeReply, excerpt, hasTools, initialize, listTools, send, terminate, type Conn, type Reply, type Session } from "./http.js";

const PACK: PackId = "oauth";
const SINCE = "0.3-draft";
const SCOPE = "server as deployed (the bearer tokens the endpoint accepts, and what it tells a client that has none)";
const NEEDS_STUB = "needs the harness's stub issuer: pass --oauth (oauth.issuer: stub) and point the server's issuer, JWKS URL and audience at {issuer}, {jwks} and {audience}";
/** Claims a probe must stay clear of: the server may allow this much clock skew, so a time probe is an hour off (RFC 7519 4.1.4 leeway). */
export const SKEW_SEC = 60;
const HOUR = 3600;
const OTHER_ISSUER = "https://sm-other-issuer.example";
const OTHER_RESOURCE = "https://other.example/mcp";
const WRONG_AUDIENCE = "sm-wrong-audience";

interface Meta {
  id: string;
  label: string;
  critical: boolean;
}
const META = {
  forgery: { id: "oauth-token-forgery", label: "Forged and unsigned tokens are refused", critical: true },
  claims: { id: "oauth-claims", label: "Expired, early, wrong-issuer and wrong-audience tokens are refused", critical: true },
  discovery: { id: "oauth-discovery", label: "A client without a token is told where to authorize (RFC 9728)", critical: false },
  scope: { id: "oauth-scope", label: "Scopes are enforced and tokens are read from the header only", critical: false },
} satisfies Record<string, Meta>;

// ---------------------------------------------------------------------------------------------------------
// The published corpora
// ---------------------------------------------------------------------------------------------------------

interface TokenProbe {
  id: string;
  text: string;
  /** Claims replaced (undefined removes) over the control token's claims. */
  claims?: (now: number, o: { issuer: string; audience: string; scopes: readonly string[] }) => Record<string, unknown>;
  mint?: (stub: AuthServerStub, scopes: readonly string[]) => AuthServerMintOptions;
  /** A probe whose token names an attacker URL: a fetch of it is evidence even when the token is refused. */
  attackerPath?: string;
}

/** oauth-token-forgery: one thing wrong with the signature or the key; every claim is the control token's. */
export const FORGERY_PROBES: readonly TokenProbe[] = [
  ...(["none", "None", "NONE"] as const).flatMap((name): TokenProbe[] => [
    { id: `alg-${name}`, text: `header alg "${name}", empty signature (header.payload.)`, mint: () => ({ alg: "none", algName: name }) },
    { id: `alg-${name}-nodot`, text: `header alg "${name}", no signature and no trailing dot (header.payload)`, mint: () => ({ alg: "none", algName: name, trailingDot: false }) },
  ]),
  { id: "sig-stripped", text: "RS256 header, signature removed (header.payload.)", mint: () => ({ signature: "strip" }) },
  { id: "sig-random", text: "RS256 header, 256 random bytes in place of the signature", mint: () => ({ signature: "random" }) },
  { id: "payload-tampered", text: "a correctly signed token whose payload was changed after signing (sub sm-sub-admin, scope admin)", mint: (_s, scopes) => ({ tamper: { sub: "sm-sub-admin", scope: ["admin", ...scopes].join(" ") } }) },
  { id: "untrusted-key", text: "RS256 signed by a key that is not in {jwks}, with the published kid", mint: () => ({ key: "untrusted" }) },
  { id: "hs256-pem", text: "alg HS256 with the published RSA public key (SPKI PEM bytes) as the HMAC secret: algorithm confusion", mint: (s) => ({ alg: "HS256", hmacSecret: s.publicPem }) },
  { id: "hs256-jwk", text: "alg HS256 with the published public key as JWK JSON bytes as the HMAC secret", mint: (s) => ({ alg: "HS256", hmacSecret: s.publicJwkJson }) },
  { id: "jku", text: "RS256 signed by an attacker key, header jku pointing at the attacker key set ({issuer}/attacker/jwks); a fetch of that URL is recorded", mint: (s) => ({ key: "attacker", header: { jku: s.attackerJwksUri } }), attackerPath: "/attacker/jwks" },
  { id: "x5u", text: "RS256 signed by an attacker key, header x5u pointing at an attacker URL ({issuer}/attacker/x5u); a fetch of that URL is recorded", mint: (s) => ({ key: "attacker", header: { x5u: s.attackerX5uUri } }), attackerPath: "/attacker/x5u" },
  { id: "kid-traversal", text: 'alg HS256 with an empty key and kid "../../../../../../dev/null"', mint: () => ({ alg: "HS256", hmacSecret: "", header: { kid: "../../../../../../dev/null" } }) },
  { id: "kid-sql", text: `alg HS256 keyed with "sm-kid-sql" and kid "x' UNION SELECT 'sm-kid-sql' -- "`, mint: () => ({ alg: "HS256", hmacSecret: "sm-kid-sql", header: { kid: "x' UNION SELECT 'sm-kid-sql' -- " } }) },
];

/** oauth-claims: correctly signed by the published key; one claim wrong. Time probes are an hour off, far outside any 60 s skew. */
export const CLAIM_PROBES: readonly TokenProbe[] = [
  { id: "expired", text: "exp one hour in the past (iat two hours)", claims: (now) => ({ exp: now - HOUR, iat: now - 2 * HOUR }) },
  { id: "not-yet-valid", text: "nbf one hour in the future", claims: (now) => ({ nbf: now + HOUR }) },
  { id: "no-exp", text: "no exp claim", claims: () => ({ exp: undefined }) },
  { id: "wrong-issuer", text: `iss ${OTHER_ISSUER} (signed by the same key)`, claims: () => ({ iss: OTHER_ISSUER }) },
  { id: "wrong-audience", text: `aud "${WRONG_AUDIENCE}"`, claims: () => ({ aud: WRONG_AUDIENCE }) },
  { id: "no-audience", text: "no aud claim", claims: () => ({ aud: undefined }) },
  { id: "other-resource", text: `aud ${OTHER_RESOURCE}: a token the same issuer minted for another resource (RFC 8707)`, claims: () => ({ aud: OTHER_RESOURCE }) },
];

/** oauth-scope, insufficient-scope leg (only when oauth.scopes is declared). */
export const SCOPE_PROBES: readonly TokenProbe[] = [
  { id: "no-scope", text: "no scope claim", claims: () => ({ scope: undefined }) },
  { id: "unrelated-scope", text: 'scope "sm-unrelated"', claims: () => ({ scope: "sm-unrelated" }) },
];

const DISCOVERY_METHODS = ["tools/list", "tools/call", "resources/list", "prompts/list"] as const;

export function describe(): CheckDoc[] {
  const keys = (id: string, extra: string[] = []) => [`checks.${id}.enabled`, `checks.${id}.severity`, "oauth.issuer", "oauth.audience", ...extra, "server.url", "server.headers"];
  const mk = (m: Meta, o: Pick<CheckDoc, "verifiedBy" | "probes" | "falsePositive" | "falseNegative" | "configKeys">): CheckDoc => ({ id: m.id, pack: PACK, label: m.label, critical: m.critical, advisory: false, scope: SCOPE, thresholds: {}, since: SINCE, status: "shipped", ...o });
  const control = { id: "control", text: "a well-formed RS256 token from the harness's issuer, unexpired, with the right iss, aud and scope: initialize and tools/list must succeed, or the check is inconclusive", kind: "control" };
  return [
    mk(META.forgery, {
      verifiedBy: ["http", "authserver"],
      probes: [control, ...FORGERY_PROBES.map((p) => ({ id: p.id, text: p.text, kind: "forgery" }))],
      falsePositive: "None known: every probe token is invalid by construction. A probe answered HTTP 500 is not counted as served, but is named in the evidence.",
      falseNegative: "Only initialize and tools/list are tried with each token; a server that checks tokens there but not on tools/call is not seen. The x5u URL serves a real certificate chain for the attacker key (a leaf and its own attacker CA, written by the harness's X.509 writer); a server that would trust x5u only for a chain to a CA it already trusts refuses it, which is correct.",
      configKeys: keys(META.forgery.id),
    }),
    mk(META.claims, {
      verifiedBy: ["http"],
      probes: [control, ...CLAIM_PROBES.map((p) => ({ id: p.id, text: p.text, kind: "claims" }))],
      falsePositive: "A server that accepts tokens without exp by design (the JWT access-token profile, RFC 9068, makes exp required) fails no-exp.",
      falseNegative: `Times are an hour off, so a server with a clock skew allowance of up to an hour passes; nothing within ${SKEW_SEC} s is probed. Only the claims listed are probed (not jti replay, not typ).`,
      configKeys: keys(META.claims.id),
    }),
    mk(META.discovery, {
      verifiedBy: ["http"],
      probes: [
        { id: "no-token-initialize", text: "initialize without a token: HTTP 401 with WWW-Authenticate: Bearer resource_metadata=\"<url>\"", kind: "discovery" },
        { id: "metadata", text: "GET the resource_metadata URL (same origin only) and the RFC 9728 well-known paths (path-suffixed and root): JSON whose resource is the server URL (no trailing slash) and whose authorization_servers is not empty (with --oauth: names {issuer})", kind: "discovery" },
        ...DISCOVERY_METHODS.flatMap((m) => [
          { id: `${m}-no-token`, text: `${m} without a token: HTTP 401`, kind: "discovery" },
          { id: `${m}-garbage-token`, text: `${m} with a garbage bearer token: HTTP 401`, kind: "discovery" },
        ]),
      ],
      falsePositive: "A resource_metadata URL on another origin is not fetched (the harness contacts only the server's origin); the well-known paths are tried instead. A deployment that publishes its metadata only on another origin fails.",
      falseNegative: "The metadata is checked for resource and authorization_servers only; the authorization server's own metadata is not fetched. n/a when the server answers requests without a token (http-auth grades that).",
      configKeys: keys(META.discovery.id),
    }),
    mk(META.scope, {
      verifiedBy: ["http"],
      probes: [
        control,
        ...SCOPE_PROBES.map((p) => ({ id: p.id, text: `${p.text} (only when oauth.scopes is declared): refused, 403 insufficient_scope preferred, 401 accepted`, kind: "scope" })),
        { id: "query-token", text: "the control token as ?access_token= in the URL and no Authorization header: never served (RFC 6750 2.3; the MCP specification requires the header)", kind: "transport" },
      ],
      falsePositive: "None known: the scope probes run only for scopes the configuration says the server requires.",
      falseNegative: "Scopes are checked on initialize and tools/list only; a server that enforces scopes per tool is not probed tool by tool. Without oauth.scopes only the query-token leg runs.",
      configKeys: keys(META.scope.id, ["oauth.scopes"]),
    }),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Results with checks.<id>.enabled and .severity applied (the pattern of packs/http.ts and packs/upstream.ts)
// ---------------------------------------------------------------------------------------------------------

function result(ctx: PackCtx, m: Meta, verdict: Verdict, summary: string, evidence: Evidence[]): CheckResult {
  const c = ctx.config?.checks?.[m.id];
  const origin = ctx.config?.origins?.[`/checks/${m.id}/enabled`]?.source ?? "config";
  const sev = c?.severity ?? null;
  const critical = sev === "critical" ? true : sev === "scored" || sev === "advisory" ? false : m.critical;
  const base: CheckResult = { id: m.id, pack: PACK, label: m.label, critical, ...(sev === "advisory" ? { advisory: true } : {}), scope: SCOPE, verdict, summary, evidence };
  return c && c.enabled === false ? { ...base, verdict: "na", summary: `disabled by config (${origin})`, evidence: [] } : base;
}

export const pack: Pack = {
  id: PACK,
  describe,
  applies(ctx: PackCtx): PackApplies {
    if (!ctx.config?.server?.url) return { ok: false, reason: "the oauth pack grades the authorization of an HTTP server (server.url); a stdio server takes its credentials from the environment" };
    return { ok: true };
  },
  run,
};
export default pack;

// ---------------------------------------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------------------------------------

/** What a token probe got: served means initialize and tools/list both answered as for a valid caller. */
interface Tried {
  served: boolean;
  initOk: boolean;
  reply: Reply;
}

const statusWord = (r: Reply): string => (r.status === 0 ? `no response (${r.error})` : `HTTP ${r.status}`);

/** RFC 6750 3 / RFC 9110 11.6.1: the auth-params of a `WWW-Authenticate: Bearer` challenge (quoted or token values). */
export function bearerChallenge(header: string | null): { bearer: boolean; params: Record<string, string> } {
  if (!header) return { bearer: false, params: {} };
  const at = header.search(/(^|,\s*)Bearer(\s|$)/i);
  if (at < 0) return { bearer: false, params: {} };
  const rest = header.slice(at).replace(/^,?\s*Bearer\s*/i, "");
  const params: Record<string, string> = {};
  const re = /([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  for (let m = re.exec(rest); m; m = re.exec(rest)) {
    const key = m[1]!.toLowerCase();
    // A later scheme starts a new challenge: stop at the next "<scheme> " that is not a parameter.
    if (key in params) break;
    params[key] = m[2] !== undefined ? m[2].replace(/\\(.)/g, "$1") : m[3]!;
  }
  return { bearer: true, params };
}

/** The RFC 9728 3.1 well-known URLs for a resource: the path-suffixed one (when the resource has a path) and the root one. */
export function wellKnownUrls(resource: string): string[] {
  try {
    const u = new URL(resource);
    const path = u.pathname.replace(/\/+$/, "");
    const root = `${u.origin}/.well-known/oauth-protected-resource`;
    return path ? [`${root}${path}`, root] : [root];
  } catch {
    return [];
  }
}

async function getJson(url: string, ms: number): Promise<{ status: number; json?: unknown; error?: string; type?: string }> {
  try {
    const r = await fetch(url, { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(ms) });
    const text = (await r.text().catch(() => "")).slice(0, 64 * 1024);
    const type = r.headers.get("content-type") ?? "";
    try {
      return { status: r.status, json: JSON.parse(text), type };
    } catch {
      return { status: r.status, type, error: text ? `not JSON: ${excerpt(text, 80)}` : "empty body" };
    }
  } catch (e) {
    const err = e as Error & { cause?: { code?: string } };
    return { status: 0, error: err.name === "TimeoutError" ? `no response within ${ms / 1000} s` : (err.cause?.code ?? err.message) };
  }
}

// ---------------------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------------------

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const spec = ctx.config.server;
  const settings = oauthSettings(ctx.config);
  const stub = ctx.authServer;
  const vars = ctx.vars ?? {};
  const tctx = { vars, dsns: {}, env: ctx.config.env };
  const url = expandHarness(spec.url!, tctx);
  const shown = stripUserinfo(url);
  const configured = Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k, expandHarness(v, tctx)]));
  const probeMs = ctx.config.timeouts?.probe_ms ?? 10_000;
  const conn: Conn = { url, headers: configured, reqMs: Math.min(30_000, Math.max(3_000, probeMs)) };
  const creds = Object.keys(configured).filter((k) => looksSecret(k));
  /** Every credential header removed. */
  const bare: Record<string, null> = Object.fromEntries(creds.map((k) => [k, null]));
  // The header that carries the caller's token, and how it is written ("Bearer {bearer}"); Authorization when nothing says otherwise.
  const tokenHeader = Object.entries(spec.headers ?? {}).find(([, v]) => /\{bearer(?::[ab])?\}/.test(v));
  const headerName = tokenHeader?.[0] ?? "Authorization";
  const asToken = (token: string): Record<string, string | null> => ({ ...bare, [headerName]: tokenHeader ? expandHarness(tokenHeader[1].replace(/\{bearer(?::[ab])?\}/g, () => token), tctx) : `Bearer ${token}` });
  const audience = ctx.oauth?.audience ?? vars.audience ?? settings.audience ?? canonicalResource(url);
  const scopes = ctx.oauth?.scopes ?? settings.scopes;
  const issuer = stub?.issuer ?? vars.issuer ?? "";
  const claimsFor = (sub: string, over: Record<string, unknown> = {}, now?: number) => accessTokenClaims({ issuer, audience, scopes, clientId: settings.client_id }, sub, over, now);

  const created: { s: Session; headers: Record<string, string | null> }[] = [];
  const out: CheckResult[] = [];
  const off = (m: Meta): boolean => ctx.config?.checks?.[m.id]?.enabled === false;
  const res = (m: Meta, verdict: Verdict, summary: string, evidence: Evidence[] = []) => result(ctx, m, verdict, summary, evidence);

  /** initialize, then (when it was accepted) tools/list on that session, both carrying `headers`. */
  const tryHeaders = async (headers: Record<string, string | null>, c: Conn = conn): Promise<Tried> => {
    const s = await initialize(c, { headers });
    if (s.sessionId) created.push({ s, headers });
    if (!s.ok) return { served: false, initOk: false, reply: s.reply };
    const l = await listTools(c, s, { headers });
    return { served: hasTools(l), initOk: true, reply: l };
  };
  const tryToken = (token: string): Promise<Tried> => tryHeaders(asToken(token));
  const outcome = (t: Tried): string => (t.served ? "served (initialize and tools/list answered)" : t.initOk ? `initialize answered, tools/list refused (${describeReply(t.reply)})` : `refused: ${describeReply(t.reply)}`);
  const refusedWith500 = (t: Tried): boolean => !t.served && t.reply.status >= 500;

  try {
    // ---- the control: a token the server must accept, or the token checks cannot be judged ----
    let control: Tried | undefined;
    let controlEv: Evidence | undefined;
    if (stub) {
      control = await tryToken(stub.mint(claimsFor(OAUTH_SUB.control)));
      controlEv = { probe: `POST initialize and tools/list to ${shown} with a control token from {issuer} (RS256, aud {audience}${scopes.length ? `, scope "${scopes.join(" ")}"` : ""}, exp in 10 minutes)`, outcome: outcome(control), verifiedBy: "http", code: "oauth.control" };
    }
    const fetchedJwks = stub ? stub.requests().some((r) => r.path === "/jwks") : false;
    const jwksEv: Evidence | undefined = stub ? { probe: "requests the stub issuer received", outcome: fetchedJwks ? "the server fetched {jwks}" : "the server never fetched {jwks} (it may hold the key another way)", verifiedBy: "authserver", code: fetchedJwks ? "oauth.control.jwks-fetched" : "oauth.control.jwks-not-fetched" } : undefined;
    const notTrusted = (): string =>
      `the control token (well-formed, signed by the harness's issuer, unexpired, right iss and aud${scopes.length ? " and scope" : ""}) was refused (${control ? describeReply(control.reply) : "not sent"}): the server does not trust the harness issuer, so a refusal of a bad token proves nothing; ${OAUTH_TRUST_HINT}`;
    /** undefined when the token checks can be judged; otherwise the result for `m`. */
    const gate = (m: Meta): CheckResult | undefined => {
      if (off(m)) return res(m, "na", "disabled by config");
      if (!stub) return res(m, "na", settings.issuer === "external" ? `oauth.issuer is external: ${NEEDS_STUB}` : NEEDS_STUB);
      if (!control!.served) return res(m, "inconclusive", notTrusted(), [controlEv!, jwksEv!]);
      return undefined;
    };

    // ---- oauth-token-forgery ----
    out.push(
      gate(META.forgery) ??
        (await (async () => {
          const m = META.forgery;
          const st = stub!;
          const evidence: Evidence[] = [controlEv!, jwksEv!];
          const served: string[] = [];
          const errors: string[] = [];
          const fetched: string[] = [];
          for (const p of FORGERY_PROBES) {
            const mark = st.mark();
            const t = await tryToken(st.mint(claimsFor(OAUTH_SUB.a), p.mint!(st, scopes)));
            const hit = p.attackerPath ? st.requests(mark).some((r) => r.path === p.attackerPath) : false;
            if (t.served) served.push(p.id);
            if (refusedWith500(t)) errors.push(p.id);
            if (hit) fetched.push(p.id);
            evidence.push({ probe: `token: ${p.text}`, outcome: `${outcome(t)}${hit ? "; the server fetched the attacker URL" : ""}${refusedWith500(t) ? " (a server error, not served; 401 is the answer)" : ""}`, verifiedBy: hit ? "authserver" : "http", code: t.served ? "oauth.forgery-served" : hit ? "oauth.attacker-fetch" : "oauth.forgery-refused" });
          }
          const tail = errors.length ? `; ${errors.length} probe(s) got a server error instead of 401 (${errors.join(", ")})` : "";
          if (served.length) return res(m, "fail", `the server accepted ${served.length} forged token(s): ${served.join(", ")}${fetched.length ? `; it also fetched the attacker key URL named in the token header (${fetched.join(", ")})` : ""}${tail}`, evidence);
          if (fetched.length) return res(m, "part", `every forged token was refused, but the server fetched the attacker-controlled key URL a token header named (${fetched.join(", ")}): a server must take its keys from its configured issuer only, never from the token (a request forgery and key-injection risk)${tail}`, evidence);
          return res(m, "pass", `all ${FORGERY_PROBES.length} forged or unsigned tokens were refused while the control token was accepted${tail}`, evidence);
        })()),
    );

    // ---- oauth-claims ----
    out.push(
      gate(META.claims) ??
        (await (async () => {
          const m = META.claims;
          const st = stub!;
          const evidence: Evidence[] = [controlEv!];
          const served: string[] = [];
          const errors: string[] = [];
          for (const p of CLAIM_PROBES) {
            const now = Math.floor(Date.now() / 1000);
            const t = await tryToken(st.mint(claimsFor(OAUTH_SUB.a, p.claims!(now, { issuer, audience, scopes }), now)));
            if (t.served) served.push(p.id);
            if (refusedWith500(t)) errors.push(p.id);
            evidence.push({ probe: `token: ${p.text}`, outcome: outcome(t), verifiedBy: "http", code: t.served ? "oauth.claim-served" : "oauth.claim-refused" });
          }
          const tail = errors.length ? `; ${errors.length} probe(s) got a server error instead of 401 (${errors.join(", ")})` : "";
          if (served.length) return res(m, "fail", `the server accepted ${served.length} token(s) it must refuse: ${served.join(", ")}${tail}`, evidence);
          return res(m, "pass", `all ${CLAIM_PROBES.length} tokens with a wrong or missing exp, nbf, iss or aud were refused while the control token was accepted${tail}`, evidence);
        })()),
    );

    // ---- oauth-discovery (no stub needed) ----
    out.push(await discovery(ctx, { conn, shown, bare, asToken, stub, audience, url, created, res: (v, s, e) => res(META.discovery, v, s, e), off: off(META.discovery) }));

    // ---- oauth-scope ----
    out.push(
      gate(META.scope) ??
        (await (async () => {
          const m = META.scope;
          const st = stub!;
          const evidence: Evidence[] = [controlEv!];
          const fails: string[] = [];
          const notes: string[] = [];
          if (scopes.length) {
            for (const p of SCOPE_PROBES) {
              const now = Math.floor(Date.now() / 1000);
              const t = await tryToken(st.mint(claimsFor(OAUTH_SUB.a, p.claims!(now, { issuer, audience, scopes }), now)));
              const challenge = bearerChallenge(t.reply.headers.get("www-authenticate"));
              const insufficient = challenge.params.error === "insufficient_scope";
              evidence.push({ probe: `token: ${p.text}`, outcome: `${outcome(t)}${insufficient ? ' (WWW-Authenticate error="insufficient_scope")' : ""}`, verifiedBy: "http", code: t.served ? "oauth.scope-served" : "oauth.scope-refused" });
              if (t.served) fails.push(`a token with ${p.id === "no-scope" ? "no scope" : "an unrelated scope"} was served (required: ${scopes.join(" ")})`);
              else if (t.reply.status === 401) notes.push(`${p.id}: refused with 401 (RFC 6750 3.1 names 403 insufficient_scope)`);
              else if (t.reply.status !== 403) notes.push(`${p.id}: refused with ${statusWord(t.reply)}`);
            }
          } else notes.push("the scope probes did not run: oauth.scopes is empty");
          // The token in the query string, no header (RFC 6750 2.3; MCP authorization: tokens MUST NOT be in the URI query string).
          const token = st.mint(claimsFor(OAUTH_SUB.a));
          const q = new URL(conn.url);
          q.searchParams.set("access_token", token);
          const t = await tryHeaders(bare, { ...conn, url: q.toString() });
          evidence.push({ probe: `the control token as ?access_token= in the URL, no ${creds.join(", ") || headerName} header`, outcome: outcome(t), verifiedBy: "http", code: t.served ? "oauth.query-token-served" : "oauth.query-token-refused" });
          if (t.served) fails.push("a token sent as ?access_token= in the URL was accepted (tokens belong in the Authorization header only)");
          const tail = notes.length ? ` (${notes.join("; ")})` : "";
          if (fails.length) return res(m, "fail", `${fails.join("; ")}${tail}`, evidence);
          return res(m, "pass", `${scopes.length ? "tokens without the required scope were refused and " : ""}a token in the query string was refused${tail}`, evidence);
        })()),
    );
  } finally {
    // Sessions the probes opened are ended so the server does not keep them (with the headers they were opened with).
    for (const { s, headers } of created) await terminate(conn, s, { headers }).catch(() => {});
  }
  return out;
}

interface DiscoveryIn {
  conn: Conn;
  shown: string;
  bare: Record<string, null>;
  asToken: (t: string) => Record<string, string | null>;
  stub?: AuthServerStub;
  audience: string;
  url: string;
  created: { s: Session; headers: Record<string, string | null> }[];
  res: (v: Verdict, summary: string, evidence?: Evidence[]) => CheckResult;
  off: boolean;
}

async function discovery(_ctx: PackCtx, d: DiscoveryIn): Promise<CheckResult> {
  if (d.off) return d.res("na", "disabled by config");
  const { conn, bare } = d;
  const evidence: Evidence[] = [];
  const fails: string[] = [];
  const parts: string[] = [];
  // ---- initialize with no token ----
  const anon = await initialize(conn, { headers: bare });
  if (anon.sessionId) d.created.push({ s: anon, headers: bare });
  const www = anon.reply.headers.get("www-authenticate");
  evidence.push({ probe: `POST initialize to ${d.shown} without a token`, outcome: anon.ok ? "valid InitializeResult" : `${describeReply(anon.reply)}${www ? `; WWW-Authenticate: ${excerpt(www, 200)}` : "; no WWW-Authenticate header"}`, verifiedBy: "http", code: "oauth.no-token" });
  if (anon.reply.status === 0) return d.res("inconclusive", `no response to an initialize without a token (${anon.reply.error})`, evidence);
  if (anon.ok) {
    const l = await listTools(conn, anon, { headers: bare });
    evidence.push({ probe: "POST tools/list without a token", outcome: hasTools(l) ? "tools returned" : describeReply(l), verifiedBy: "http", code: "oauth.no-token" });
    if (hasTools(l)) return d.res("na", "the server answers initialize and tools/list without a token (http-auth grades that), so it has no authorization for a client to discover", evidence);
    parts.push("initialize is answered without a token (only tools/list is protected)");
  } else if (anon.reply.status !== 401) parts.push(`a request without a token got ${describeReply(anon.reply)}, not 401`);
  const challenge = bearerChallenge(www);
  const rmUrl = challenge.params.resource_metadata;
  if (anon.reply.status === 401 && !challenge.bearer) parts.push("the 401 carries no WWW-Authenticate: Bearer challenge (RFC 6750 3)");
  else if (!anon.ok && !rmUrl) parts.push("the WWW-Authenticate challenge does not name resource_metadata (MCP authorization: servers MUST point clients at their protected-resource metadata)");

  // ---- the protected-resource metadata (RFC 9728) ----
  const origin = new URL(conn.url).origin;
  const candidates: string[] = [];
  if (rmUrl) {
    let same = false;
    try {
      same = new URL(rmUrl, conn.url).origin === origin;
    } catch {
      parts.push(`resource_metadata is not a URL (${excerpt(rmUrl, 80)})`);
    }
    if (same) candidates.push(new URL(rmUrl, conn.url).toString());
    else if (rmUrl) evidence.push({ probe: "resource_metadata URL", outcome: `${excerpt(stripUserinfo(rmUrl), 120)} is on another origin: not fetched (the harness contacts only the server's origin)`, verifiedBy: "static", code: "oauth.metadata-cross-origin" });
  }
  for (const w of wellKnownUrls(conn.url)) if (!candidates.includes(w)) candidates.push(w);
  let doc: Record<string, unknown> | undefined;
  let docUrl = "";
  for (const c of candidates) {
    const r = await getJson(c, conn.reqMs);
    const ok = r.status === 200 && r.json !== null && typeof r.json === "object" && !Array.isArray(r.json);
    evidence.push({ probe: `GET ${stripUserinfo(c)}`, outcome: ok ? "JSON metadata" : r.status === 0 ? `no response (${r.error})` : `HTTP ${r.status}${r.error ? `: ${r.error}` : ""}`, verifiedBy: "http", code: ok ? "oauth.metadata" : "oauth.metadata-missing" });
    if (ok && !doc) {
      doc = r.json as Record<string, unknown>;
      docUrl = c;
    }
  }
  if (!doc) fails.push("no protected-resource metadata was found (RFC 9728): neither the WWW-Authenticate challenge nor the well-known paths lead to it, so a client cannot discover the authorization server");
  else {
    const resource = typeof doc.resource === "string" ? doc.resource : undefined;
    const servers = Array.isArray(doc.authorization_servers) ? doc.authorization_servers.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
    evidence.push({ probe: `metadata at ${stripUserinfo(docUrl)}`, outcome: `resource ${resource === undefined ? "(absent)" : excerpt(resource, 120)}; authorization_servers ${servers.length ? servers.map((s) => excerpt(s, 80)).join(", ") : "(none)"}`, verifiedBy: "http", code: "oauth.metadata-fields" });
    if (!resource) fails.push("the metadata has no resource field");
    else if (!sameResource(resource, d.audience)) fails.push(`the metadata names resource ${excerpt(resource, 120)}, not this server (${canonicalResource(d.audience)}): a client would bind its tokens to the wrong audience`);
    if (resource && conn.url.startsWith("https:") && resource.startsWith("http:")) fails.push("the metadata advertises an http:// resource for an https server");
    if (!servers.length) fails.push("the metadata lists no authorization_servers");
    else if (d.stub && !servers.some((s) => sameResource(s, d.stub!.issuer))) parts.push("the metadata does not list the harness's issuer ({issuer}), which --oauth expects the server to trust: a client would ask another authorization server for its tokens");
  }

  // ---- every method without a token and with a garbage one: 401 each time ----
  // On a session of the caller's own when one opens with the configured headers (so only the token differs), else without a session.
  const own = await initialize(conn);
  if (own.sessionId) d.created.push({ s: own, headers: {} });
  const garbage = `sm-garbage-${randomBytes(6).toString("hex")}`;
  const sessionHeaders = { ...(own.ok && own.sessionId ? { "mcp-session-id": own.sessionId } : {}), "mcp-protocol-version": own.protocolVersion ?? "2025-06-18" };
  const notServed: string[] = [];
  const served: string[] = [];
  let n = 0;
  for (const method of DISCOVERY_METHODS) {
    for (const [label, headers] of [["no token", bare], ["a garbage token", d.asToken(garbage)]] as const) {
      const params = method === "tools/call" ? { name: "sm-no-such-tool", arguments: {} } : {};
      const body = { jsonrpc: "2.0", id: 9000 + n++, method, params };
      const r = await send(conn, { headers: { ...headers, ...sessionHeaders }, body });
      const ok = r.status >= 200 && r.status < 300;
      if (ok) served.push(`${method} with ${label}`);
      else if (r.status !== 401) notServed.push(`${method} with ${label}: ${statusWord(r)}`);
      evidence.push({ probe: `POST ${method} with ${label}${own.ok && own.sessionId ? " on a valid session" : ""}`, outcome: ok ? `answered (HTTP ${r.status})` : describeReply(r), verifiedBy: "http", code: ok ? "oauth.unauthenticated-served" : "oauth.unauthenticated-refused" });
    }
  }
  if (served.length) fails.push(`requests without a valid token were answered: ${served.join("; ")}`);
  if (notServed.length) parts.push(`refused without the 401 the specification names: ${notServed.join("; ")}`);
  if (fails.length) return d.res("fail", [...fails, ...parts].join("; "), evidence);
  if (parts.length) return d.res("part", parts.join("; "), evidence);
  return d.res("pass", `a request without a token gets 401 with a Bearer challenge naming the protected-resource metadata, which names this server and its authorization server${d.stub ? " (the harness's issuer)" : ""}; ${DISCOVERY_METHODS.length * 2} requests without a valid token were refused with 401`, evidence);
}
