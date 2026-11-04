// Round 7: small helpers shared by the configuration, run, doctor and the oauth pack.
// Written from the public specifications: the MCP authorization specification (2025-06-18), RFC 8707 (resource indicators), RFC 9728
// (protected resource metadata), RFC 6750 (bearer tokens) and RFC 9068 (JWT access tokens).
import { randomBytes } from "node:crypto";
import type { OauthSettings } from "./config/model.js";
import type { EffectiveConfig, ServerSpec } from "./types.js";

/** What `--oauth` adds to an HTTP server's headers when none carries the caller's token: the identities travel as bearer tokens (RFC 6750 2.1). */
export const OAUTH_HEADER_VALUE = "Bearer {bearer}";

/** The sentence every "the server does not trust the harness's issuer" message ends with: what to set, by placeholder. */
export const OAUTH_TRUST_HINT =
  "configure the server to trust the harness's issuer: set its issuer to {issuer}, its JWKS URL to {jwks} and its expected audience to {audience} (in server.env or server.args); with the default https issuer it must also trust the throwaway CA in {ca_file} (SSL_CERT_FILE for Python's ssl and urllib and httpx, REQUESTS_CA_BUNDLE for requests, NODE_EXTRA_CA_CERTS for Node: the harness sets all three unless server.env does, so point the server's own CA setting at {ca_file} if it has one)";

/**
 * the variables common TLS stacks read their trust store from. The harness sets them, for a server it starts with the stub issuer in
 * https mode, to a bundle of the throwaway CA and the public roots (so the server's other https calls keep working), unless server.env sets them.
 * SSL_CERT_FILE: OpenSSL's default verify paths (Python ssl, urllib, httpx). REQUESTS_CA_BUNDLE: requests. NODE_EXTRA_CA_CERTS: Node.
 */
export const CA_ENV_VARS = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"] as const;

/** What to say when a server configured for the stub issuer stopped before it answered (a hardened server refusing its trust root). */
export function oauthStartupHint(tls: boolean): string {
  return tls
    ? "with --oauth the server is given an https issuer ({issuer}, {jwks}) whose certificate chains to a throwaway CA in {ca_file}: if it refused its trust root, point the server's CA setting at {ca_file} (the harness already sets SSL_CERT_FILE, REQUESTS_CA_BUNDLE and NODE_EXTRA_CA_CERTS unless server.env sets them), and check that it reads {issuer}, {jwks} and {audience} where you passed them"
    : "with --oauth and oauth.tls: false the server is given a plain http issuer ({issuer}, {jwks}); a server that requires an https trust root refuses to start: drop --no-oauth-tls (oauth.tls: false) so the stub serves https, and point the server's CA setting, or SSL_CERT_FILE, at {ca_file}";
}

/** The sub claims of the two identities the stub mints (fixed, so reports are the same from run to run; each token still differs by jti and time). */
export const OAUTH_SUB = { a: "sm-sub-a", b: "sm-sub-b", control: "sm-sub-control" } as const;

/** The `oauth:` settings with their defaults, also for a configuration built by hand (tests, library callers). */
export function oauthSettings(eff: Pick<EffectiveConfig, "oauth" | "value">): OauthSettings {
  const tree = ((eff.value ?? {}) as { oauth?: Partial<OauthSettings> }).oauth;
  const o: Partial<OauthSettings> = eff.oauth ?? tree ?? {};
  return {
    issuer: o.issuer === "stub" || o.issuer === "external" ? o.issuer : null,
    audience: typeof o.audience === "string" && o.audience ? o.audience : null,
    scopes: Array.isArray(o.scopes) ? o.scopes.filter((s): s is string => typeof s === "string" && s.length > 0) : [],
    client_id: typeof o.client_id === "string" && o.client_id ? o.client_id : "sealmark",
    tls: o.tls !== false,
  };
}

/**
 * The canonical form of a resource URI (RFC 8707 2 and the MCP authorization specification, "Canonical Server URI"): scheme and host in lower
 * case (the URL parser does that), no fragment, no trailing slash. Query strings are kept: a server whose endpoint carries one names it.
 */
export function canonicalResource(url: string): string {
  try {
    const u = new URL(url);
    u.hash = "";
    const s = u.href;
    return s.endsWith("/") ? s.replace(/\/+$/, "") : s;
  } catch {
    return url.replace(/#.*$/, "").replace(/\/+$/, "");
  }
}

/** True when two resource URIs name the same resource after canonicalisation. */
export function sameResource(a: string, b: string): boolean {
  return canonicalResource(a) === canonicalResource(b);
}

const usesBearerValue = (v: unknown): boolean => typeof v === "string" && /\{bearer(?::[ab])?\}/.test(v);

/**
 * `oauth.issuer: stub` on an HTTP server: when no header carries `{bearer}` and no Authorization header is configured, the harness sends the
 * identities as `Authorization: Bearer {bearer}` (so `--oauth` alone is enough). Idempotent; returns the spec unchanged otherwise.
 */
export function withOauthHeader(spec: ServerSpec, settings: Pick<OauthSettings, "issuer">): ServerSpec {
  if (settings.issuer !== "stub" || !spec.url) return spec;
  const headers = spec.headers ?? {};
  if (Object.values(headers).some(usesBearerValue)) return spec;
  if (Object.keys(headers).some((k) => k.toLowerCase() === "authorization")) return spec;
  return { ...spec, headers: { ...headers, Authorization: OAUTH_HEADER_VALUE } };
}

export interface ClaimsInput {
  issuer: string;
  audience: string;
  scopes: readonly string[];
  clientId: string;
}

/**
 * The claims of a well-formed access token for this run (RFC 9068 2.2): iss, sub, aud, exp (10 minutes; long enough for a pack, short
 * enough to be honest), iat, jti, client_id, and scope when scopes are declared. `over` replaces or (with undefined) removes claims.
 */
export function accessTokenClaims(i: ClaimsInput, sub: string, over: Record<string, unknown> = {}, now = Math.floor(Date.now() / 1000), ttlSec = 600): Record<string, unknown> {
  const c: Record<string, unknown> = {
    iss: i.issuer,
    sub,
    aud: i.audience,
    exp: now + ttlSec,
    iat: now,
    jti: `sm-jti-${randomBytes(8).toString("hex")}`,
    client_id: i.clientId,
    ...(i.scopes.length ? { scope: i.scopes.join(" ") } : {}),
  };
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) delete c[k];
    else c[k] = v;
  }
  return c;
}

/** The JWT-shaped strings in `s` (three base64url segments, the first a JSON header): what the report normaliser and the packs rewrite. */
export const JWT_SHAPE = /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/g;
