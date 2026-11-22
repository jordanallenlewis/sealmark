// `sealmark oauth-debug <url>`: walks the steps an MCP client takes to authorize against a remote HTTP server, from no token to the
// token endpoint, and says which step breaks. Written from the public specifications: the MCP authorization specification
// (2025-06-18 and 2025-11-25), RFC 9728 (protected resource metadata), RFC 8414 (authorization server metadata), OpenID Connect
// Discovery, RFC 7591 (dynamic client registration), RFC 7636 (PKCE), RFC 6749 5.2 (token errors) and RFC 8707 (resource indicators).
//
// It grades nothing: no check, verdict, pack or report changes. It sends no token to the server, completes no authorization (no
// user, no consent, no real code), and contacts only two origins: the URL's and that of the first authorization server its metadata
// names. Redirects are reported, never followed; a metadata URL or endpoint on any other origin is named, never contacted.
import { randomBytes } from "node:crypto";
import { JWT_SHAPE, canonicalResource, sameResource } from "./oauth.js";
import { bearerChallenge, wellKnownUrls } from "./packs/oauth.js";
import { inert } from "./report/sanitize.js";

export const OAUTH_DEBUG_FORMAT = "sealmark.oauth-debug/1";
export const STEP_IDS = ["challenge", "resource-metadata", "auth-server-metadata", "registration", "pkce", "token", "refresh"] as const;
export type StepId = (typeof STEP_IDS)[number];
export type StepStatus = "ok" | "warn" | "fail" | "skipped";

export interface Step {
  id: StepId;
  title: string;
  status: StepStatus;
  summary: string;
  /** What was sent and what came back, one line each (inert, tokens and secrets never included). */
  evidence: string[];
}

export interface OauthDebugResult {
  format: typeof OAUTH_DEBUG_FORMAT;
  url: string;
  /** false when the server answered initialize without a token (no flow to debug), null when it did not answer. */
  authRequired: boolean | null;
  /** The first step whose status is fail, or null. */
  failedAt: StepId | null;
  steps: Step[];
}

export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

const TITLES: Record<StepId, string> = {
  challenge: "challenge: a request without a token gets 401 and a pointer to the metadata",
  "resource-metadata": "protected-resource metadata (RFC 9728)",
  "auth-server-metadata": "authorization-server metadata (RFC 8414, OpenID Connect discovery)",
  registration: "client registration (RFC 7591)",
  pkce: "PKCE with S256 (RFC 7636)",
  token: "token endpoint refuses a made-up code with an RFC 6749 error",
  refresh: "refresh grant refuses a made-up refresh token",
};

/** The redirect URI the test registration and the token request name: loopback, as RFC 8252 7.3 lets native clients use. */
export const REDIRECT_URI = "http://127.0.0.1/callback";
const CLIENT_ID = "sealmark-oauth-debug";
const BODY_CAP = 256 * 1024;
const TOKEN_ERRORS = new Set(["invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "invalid_target"]);

/** The URL to debug: http or https, no credentials in it (they would be sent and printed). */
export function parseDebugUrl(value: string): string {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new Error(`"${inert(value, 200)}" is not a URL`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`the URL must be http or https, not ${inert(u.protocol, 20)}`);
  if (u.username || u.password) throw new Error("the URL carries a user name or password; give the server URL without them");
  return u.toString();
}

/**
 * Where a client looks for an authorization server's metadata (MCP authorization 2025-11-25): RFC 8414 with the issuer's path
 * inserted after the well-known segment, then OpenID Connect discovery with the path inserted, then with it appended.
 */
export function authServerMetadataUrls(issuer: string): string[] {
  let u: URL;
  try {
    u = new URL(issuer);
  } catch {
    return [];
  }
  const path = u.pathname.replace(/\/+$/, "");
  const o = u.origin;
  if (!path) return [`${o}/.well-known/oauth-authorization-server`, `${o}/.well-known/openid-configuration`];
  return [`${o}/.well-known/oauth-authorization-server${path}`, `${o}/.well-known/openid-configuration${path}`, `${o}${path}/.well-known/openid-configuration`];
}

interface Reply {
  status: number;
  headers: Headers | null;
  text: string;
  json?: unknown;
  /** Why there is no status (status 0), or why the body is incomplete (the server answered but did not finish in time). */
  error?: string;
}

/** True once `text` holds one complete Server-Sent Event with data (a Streamable HTTP server may keep the stream open after it). */
const sseEventDone = (text: string): boolean => /(^|\n)data:[^\n]*\r?\n\r?\n/.test(text);

/** The body, at most BODY_CAP bytes; for an event stream, up to its first complete event. A read cut by the timer keeps what arrived. */
async function readCapped(r: Response, sse: boolean): Promise<{ text: string; cut: boolean }> {
  if (!r.body) return { text: "", cut: false };
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  let cut = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      n += value.byteLength;
      if (n >= BODY_CAP || (sse && sseEventDone(Buffer.concat(chunks).toString("utf8")))) {
        await reader.cancel().catch(() => {});
        break;
      }
    }
  } catch {
    cut = true;
  }
  return { text: Buffer.concat(chunks).toString("utf8").slice(0, BODY_CAP), cut };
}

async function request(fetcher: Fetcher, url: string, init: RequestInit, ms: number): Promise<Reply> {
  const ac = new AbortController();
  // A plain timer (not AbortSignal.timeout) so it keeps the event loop alive while a request is outstanding, and is cleared after.
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    // Redirects are reported, never followed: the report contacts only the origins it names (see `reachable` below).
    const r = await fetcher(url, { ...init, redirect: "manual", signal: ac.signal });
    const { text, cut } = await readCapped(r, (r.headers.get("content-type") ?? "").includes("text/event-stream"));
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: r.status, headers: r.headers, text, json, ...(cut ? { error: `the body did not finish within ${ms / 1000} s` } : {}) };
  } catch (e) {
    // undici puts the socket error in cause (an AggregateError of each address tried when several were).
    const err = e as Error & { cause?: { code?: string; message?: string; errors?: { code?: string }[] } };
    const cause = err.cause?.code ?? err.cause?.errors?.find((x) => x?.code)?.code ?? err.cause?.message;
    return { status: 0, headers: null, text: "", error: ac.signal.aborted ? `no response within ${ms / 1000} s` : (cause ?? err.message) };
  } finally {
    clearTimeout(timer);
  }
}

const SECRET_PARAM = /\b(access_token|refresh_token|id_token|client_secret)(["']?\s*[:=]\s*["']?)[^"'&\s,}]+/gi;
/** Server-chosen text made safe to print: one line, no control characters, no JWT-shaped value or token parameter. */
const show = (v: unknown, max = 160): string => inert(String(v ?? "").replace(JWT_SHAPE, "{jwt}").replace(SECRET_PARAM, "$1$2{redacted}"), max);
const obj = (v: unknown): Record<string, unknown> | undefined => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : []);
const word = (r: Reply): string => (r.status === 0 ? `no response (${show(r.error, 120)})` : `HTTP ${r.status}`);
const isRedirect = (r: Reply): boolean => r.status >= 300 && r.status < 400;
/** A redirect target for an evidence line: origin and path only (a query can carry a code or a token). */
function where(r: Reply): string {
  const loc = r.headers?.get("location");
  if (!loc) return "no Location header";
  try {
    const u = new URL(loc, "http://relative.invalid");
    return u.origin === "http://relative.invalid" ? show(u.pathname, 120) : show(`${u.origin}${u.pathname}`, 160);
  } catch {
    return "a Location that is not a URL";
  }
}
/**
 * What came back, for an evidence line: the status, a redirect's target, the RFC 6749 error of a JSON body. A body that is not JSON
 * is never echoed (it can be a form-encoded token or a login page): only its content type and size are.
 */
function outcome(r: Reply): string {
  if (r.status === 0) return word(r);
  if (isRedirect(r)) return `HTTP ${r.status}, redirect to ${where(r)} (not followed)`;
  const j = obj(r.json);
  if (j && typeof j.error === "string") return `HTTP ${r.status}, error ${show(j.error, 60)}${typeof j.error_description === "string" ? ` (${show(j.error_description, 120)})` : ""}`;
  if (j) return `HTTP ${r.status}, JSON`;
  return `HTTP ${r.status}${r.text ? `, not JSON (${show(r.headers?.get("content-type") || "no content type", 60)}, ${Buffer.byteLength(r.text)} bytes; body not shown)` : ", empty body"}`;
}

/** True when the reply is an initialize result: a JSON-RPC result with a protocolVersion, as JSON or in an event stream's data. */
export function isInitializeResult(r: Pick<Reply, "text" | "json">): boolean {
  const ok = (v: unknown) => typeof obj(obj(v)?.result)?.protocolVersion === "string";
  if (ok(r.json)) return true;
  const data = r.text.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
  return data.some((d) => {
    try {
      return ok(JSON.parse(d));
    } catch {
      return false;
    }
  });
}

/** True for an http:// URL whose host is not loopback (MCP authorization requires https for authorization-server endpoints). */
export function plainHttpOffLoopback(u: string): boolean {
  try {
    const x = new URL(u);
    return x.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(x.hostname);
  } catch {
    return false;
  }
}

const originOf = (u: string): string | undefined => {
  try {
    return new URL(u).origin;
  } catch {
    return undefined;
  }
};

async function firstJson(fetcher: Fetcher, urls: string[], ms: number, evidence: string[]): Promise<{ doc: Record<string, unknown>; url: string } | undefined> {
  for (const url of urls) {
    const r = await request(fetcher, url, { headers: { accept: "application/json" } }, ms);
    const doc = r.status === 200 ? obj(r.json) : undefined;
    evidence.push(`GET ${show(url)} -> ${doc ? "HTTP 200, JSON object" : outcome(r)}`);
    if (doc) return { doc, url };
  }
  return undefined;
}

/** Walk the flow. Every step runs when it has what it needs, so one report shows every break; `failedAt` names the first. */
export async function oauthDebug(url: string, o: { register?: boolean; fetcher?: Fetcher; timeoutMs?: number } = {}): Promise<OauthDebugResult> {
  const fetcher = o.fetcher ?? fetch;
  const ms = o.timeoutMs ?? 10_000;
  const steps: Step[] = [];
  const add = (id: StepId, status: StepStatus, summary: string, evidence: string[] = []) => steps.push({ id, title: TITLES[id], status, summary, evidence });
  const skipRest = (why: string) => {
    for (const id of STEP_IDS) if (!steps.some((s) => s.id === id)) add(id, "skipped", why);
  };
  const done = (authRequired: boolean | null): OauthDebugResult => ({ format: OAUTH_DEBUG_FORMAT, url: show(url, 500), authRequired, failedAt: steps.find((s) => s.status === "fail")?.id ?? null, steps });

  // 1. challenge
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "sealmark", version: "oauth-debug" } } };
  const c = await request(fetcher, url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify(init) }, ms);
  const www = c.headers?.get("www-authenticate") ?? null;
  const ev1 = [`POST initialize without a token -> ${isRedirect(c) ? outcome(c) : word(c)}${www ? `; WWW-Authenticate: ${show(www, 240)}` : c.status ? "; no WWW-Authenticate header" : ""}`];
  if (c.status === 0) {
    add("challenge", "fail", `no response from the server: ${show(c.error, 120)}`, ev1);
    skipRest("the server did not answer");
    return done(null);
  }
  if (c.status >= 200 && c.status < 300) {
    if (isInitializeResult(c)) {
      add("challenge", "ok", "the server answered initialize without a token: it asks for no authorization, so there is no OAuth flow to debug (only initialize was tried)", ev1);
      skipRest("the server asks for no token");
      return done(false);
    }
    ev1.push(`the body: ${outcome(c)}${c.error ? `; ${show(c.error, 80)}` : ""}`);
    add("challenge", "fail", `HTTP ${c.status} without an MCP initialize result: this URL is not an MCP endpoint, or it answered with a page (a login page, a proxy) instead of a 401`, ev1);
    skipRest("the server answered neither an MCP initialize result nor a 401");
    return done(null);
  }
  // Only a 401 says the server wants a token; any other refusal leaves it open (a wrong path, a proxy, a server error).
  const authRequired = c.status === 401 ? true : null;
  const ch = bearerChallenge(www);
  let rmUrl: string | undefined;
  if (ch.params.resource_metadata) {
    try {
      rmUrl = new URL(ch.params.resource_metadata, url).toString();
    } catch {
      rmUrl = undefined;
    }
  }
  if (c.status !== 401) add("challenge", "fail", `a request without a token got HTTP ${c.status}, not 401: a client only starts authorization on a 401 (MCP authorization, RFC 6750 3.1)`, ev1);
  else if (!ch.bearer) add("challenge", "warn", "the 401 carries no WWW-Authenticate: Bearer challenge (RFC 6750 3): clients can only guess the well-known metadata URL", ev1);
  else if (!rmUrl) add("challenge", "warn", "the Bearer challenge names no resource_metadata URL (RFC 9728 5.1): clients fall back to the well-known URLs, which older clients do not try", ev1);
  else add("challenge", "ok", "401 with a Bearer challenge naming the protected-resource metadata", ev1);

  // 2. protected-resource metadata
  const ev2: string[] = [];
  if (rmUrl && originOf(rmUrl) !== originOf(url)) {
    ev2.push(`resource_metadata ${show(rmUrl)} is on another origin than the server: not fetched (the report contacts only the server's origin and the authorization server's)`);
    rmUrl = undefined;
  }
  const candidates = [...new Set([...(rmUrl ? [rmUrl] : []), ...wellKnownUrls(url)])];
  const prm = await firstJson(fetcher, candidates, ms, ev2);
  if (!prm) {
    add("resource-metadata", "fail", "no protected-resource metadata: neither the challenge nor the well-known URLs lead to a JSON document, so a client cannot find the authorization server", ev2);
    skipRest("needs the authorization server named in the protected-resource metadata");
    return done(authRequired);
  }
  const resource = typeof prm.doc.resource === "string" ? prm.doc.resource : undefined;
  const servers = strs(prm.doc.authorization_servers);
  ev2.push(`resource ${resource === undefined ? "(absent)" : show(resource)}; authorization_servers ${servers.length ? servers.map((s) => show(s, 120)).join(", ") : "(none)"}${strs(prm.doc.scopes_supported).length ? `; scopes_supported ${strs(prm.doc.scopes_supported).map((s) => show(s, 40)).join(" ")}` : ""}`);
  const bad: string[] = [];
  if (!resource) bad.push("the metadata has no resource field");
  else if (!sameResource(resource, url)) bad.push(`the metadata names resource ${show(resource)}, not this server (${show(canonicalResource(url))}): clients refuse it, or bind tokens to the wrong audience`);
  if (!servers.length) bad.push("the metadata lists no authorization_servers");
  add("resource-metadata", bad.length ? "fail" : "ok", bad.length ? bad.join("; ") : `found at ${show(prm.url)}; names this server and ${servers.length} authorization server(s)`, ev2);
  if (!servers.length) {
    skipRest("needs an authorization server named in the protected-resource metadata");
    return done(authRequired);
  }

  // 3. authorization-server metadata (the first server listed, as a client with no preference picks)
  const issuer = servers[0]!;
  const ev3: string[] = servers.length > 1 ? [`${servers.length} authorization servers listed; the first is used`] : [];
  const asm = await firstJson(fetcher, authServerMetadataUrls(issuer), ms, ev3);
  if (!asm) {
    add("auth-server-metadata", "fail", `no metadata for the authorization server ${show(issuer)} at the RFC 8414 or OpenID Connect discovery URLs`, ev3);
    skipRest("needs the authorization server's metadata");
    return done(authRequired);
  }
  const m = asm.doc;
  const field = (k: string) => (typeof m[k] === "string" && (m[k] as string).length ? (m[k] as string) : undefined);
  const tokenEndpoint = field("token_endpoint");
  ev3.push(`issuer ${field("issuer") ? show(field("issuer")) : "(absent)"}; authorization_endpoint ${field("authorization_endpoint") ? show(field("authorization_endpoint")) : "(absent)"}; token_endpoint ${tokenEndpoint ? show(tokenEndpoint) : "(absent)"}`);
  const asBad: string[] = [];
  const asWarn: string[] = [];
  const got = field("issuer");
  if (got !== issuer) {
    if (got && got.replace(/\/+$/, "") === issuer.replace(/\/+$/, "")) asWarn.push(`issuer ${show(got)} differs from ${show(issuer)} only by a trailing slash: strict clients compare them exactly (RFC 8414 3.3)`);
    else asBad.push(`issuer ${got ? show(got) : "(absent)"} is not ${show(issuer)}: clients must reject metadata whose issuer differs (RFC 8414 3.3)`);
  }
  if (!field("authorization_endpoint")) asBad.push("no authorization_endpoint");
  if (!tokenEndpoint) asBad.push("no token_endpoint");
  if (!strs(m.response_types_supported).includes("code")) asWarn.push('response_types_supported does not list "code"');
  const plain = ["issuer", "authorization_endpoint", "token_endpoint"].filter((k) => field(k) && plainHttpOffLoopback(field(k)!));
  if (plain.length) asWarn.push(`${plain.join(", ")} ${plain.length > 1 ? "are" : "is"} http:// on a host that is not loopback: MCP authorization requires https for authorization-server endpoints`);
  // The report contacts only these two origins; an endpoint elsewhere is named, never contacted.
  const reachable = (u: string) => originOf(u) === originOf(url) || originOf(u) === originOf(issuer);
  const elsewhere = (k: string, u: string) => `${k} ${show(u)} is on another origin than the server and the authorization server: not contacted`;
  add("auth-server-metadata", asBad.length ? "fail" : asWarn.length ? "warn" : "ok", [...asBad, ...asWarn].join("; ") || `found at ${show(asm.url)}`, ev3);

  // 4. registration
  const regEndpoint = field("registration_endpoint");
  let clientId = CLIENT_ID;
  if (!regEndpoint) {
    if (m.client_id_metadata_document_supported === true) add("registration", "ok", "no registration_endpoint, but client ID metadata documents are supported: a client can use an https URL as its client id");
    else add("registration", "warn", "no registration_endpoint and no client ID metadata document support: a client needs a client id issued in advance (MCP authorization: dynamic registration SHOULD be supported)");
  } else if (!o.register) {
    add("registration", "ok", `registration_endpoint ${show(regEndpoint)} is advertised, not exercised: nothing was sent (--register sends one test registration, which creates a client on the authorization server)`);
  } else if (!reachable(regEndpoint)) {
    add("registration", "skipped", elsewhere("registration_endpoint", regEndpoint));
  } else {
    const meta = { client_name: "sealmark oauth-debug", redirect_uris: [REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
    const r = await request(fetcher, regEndpoint, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(meta) }, ms);
    const j = obj(r.json);
    const id = j && typeof j.client_id === "string" && j.client_id ? j.client_id : undefined;
    const ev4 = [`POST ${show(regEndpoint)} (client_name "sealmark oauth-debug", redirect_uris ${REDIRECT_URI}, token_endpoint_auth_method none) -> ${id ? `HTTP ${r.status}, client_id ${show(id, 80)}${j && "client_secret" in j ? ", a client_secret (not shown)" : ""}` : outcome(r)}`];
    if (id && r.status >= 200 && r.status < 300) {
      clientId = id;
      add("registration", "ok", `registered: client_id ${show(id, 80)}${r.status !== 201 ? ` (HTTP ${r.status}; RFC 7591 3.2.1 names 201)` : ""}`, ev4);
    } else if (isRedirect(r)) add("registration", "warn", `the registration endpoint redirected (${where(r)}), which the report does not follow`, ev4);
    else add("registration", "fail", id ? `a client_id came back with HTTP ${r.status}` : `the test registration was refused or gave no client_id: ${outcome(r)}`, ev4);
  }

  // 5. PKCE
  const methods = m.code_challenge_methods_supported;
  if (!Array.isArray(methods)) add("pkce", "fail", "no code_challenge_methods_supported in the metadata: MCP clients must refuse to go on, because PKCE support cannot be confirmed (MCP authorization 2025-11-25)");
  else if (!strs(methods).includes("S256")) add("pkce", "fail", `code_challenge_methods_supported lists ${strs(methods).map((x) => show(x, 20)).join(", ") || "nothing"}, not S256 (OAuth 2.1, MCP authorization)`);
  else add("pkce", "ok", "S256 is listed in code_challenge_methods_supported");

  // 6. token endpoint, 7. refresh grant: made-up values must get an RFC 6749 5.2 error, never a token
  if (!tokenEndpoint) {
    skipRest("needs the token_endpoint from the authorization-server metadata");
    return done(authRequired);
  }
  if (!reachable(tokenEndpoint)) {
    skipRest(elsewhere("token_endpoint", tokenEndpoint));
    return done(authRequired);
  }
  const tokenProbe = async (id: "token" | "refresh", form: Record<string, string>, what: string) => {
    const r = await request(fetcher, tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: new URLSearchParams(form).toString() }, ms);
    const j = obj(r.json);
    const ev = [`POST ${show(tokenEndpoint)} grant_type=${form.grant_type} with ${what}, client_id ${show(form.client_id, 80)}, resource ${show(form.resource)} -> ${j && typeof j.access_token === "string" ? `HTTP ${r.status}, an access token (not shown)` : outcome(r)}`];
    if (r.status === 0) return add(id, "fail", `no response from the token endpoint: ${show(r.error, 120)}`, ev);
    if (j && typeof j.access_token === "string") return add(id, "fail", `the authorization server issued an access token for ${what}`, ev);
    if (r.status >= 200 && r.status < 300) return add(id, "fail", `the token endpoint answered HTTP ${r.status} to ${what} (body not shown): it must refuse it with an error`, ev);
    if (isRedirect(r)) return add(id, "warn", `the token endpoint redirected (${where(r)}), which the report does not follow`, ev);
    const err = j && typeof j.error === "string" ? j.error : undefined;
    if ((r.status === 400 || r.status === 401) && err) {
      const notes = [...(TOKEN_ERRORS.has(err) ? [] : ["not an RFC 6749 5.2 error code, but a client can read it"]), ...(r.status === 401 && err !== "invalid_client" ? ["RFC 6749 5.2 keeps 401 for invalid_client"] : [])];
      return add(id, "ok", `refused with ${show(err, 60)}${notes.length ? ` (${notes.join("; ")})` : ""}`, ev);
    }
    return add(id, "fail", `${outcome(r)}: a client cannot tell why; RFC 6749 5.2 names HTTP 400 (401 for invalid_client) with a JSON error`, ev);
  };
  const resourceParam = canonicalResource(url);
  await tokenProbe("token", { grant_type: "authorization_code", code: `sm-made-up-${randomBytes(8).toString("hex")}`, redirect_uri: REDIRECT_URI, code_verifier: randomBytes(32).toString("base64url"), client_id: clientId, resource: resourceParam }, "a made-up authorization code");
  if (!strs(m.grant_types_supported).includes("refresh_token")) {
    add("refresh", "skipped", `refresh_token is not advertised in grant_types_supported${Array.isArray(m.grant_types_supported) ? "" : " (absent, which RFC 8414 reads as authorization_code and implicit)"}: when the access token expires a client sends the user through authorization again`);
  } else await tokenProbe("refresh", { grant_type: "refresh_token", refresh_token: `sm-made-up-${randomBytes(8).toString("hex")}`, client_id: clientId, resource: resourceParam }, "a made-up refresh token");
  return done(authRequired);
}

const LABEL: Record<StepStatus, string> = { ok: "ok  ", warn: "warn", fail: "FAIL", skipped: "skip" };

export function renderOauthDebug(r: OauthDebugResult): string {
  const lines = [`OAuth flow for ${r.url}`, "Steps an MCP client takes with no token. No token was sent to the server and nothing was graded.", ""];
  r.steps.forEach((s, i) => {
    lines.push(`${LABEL[s.status]}  ${i + 1} ${s.title}`);
    lines.push(`      ${s.summary}`);
    for (const e of s.evidence) lines.push(`      - ${e}`);
  });
  lines.push("");
  const first = r.steps.find((s) => s.id === r.failedAt);
  lines.push(first ? `First failing step: ${r.steps.indexOf(first) + 1} ${first.id}. ${first.summary}` : r.authRequired === false ? "No step failed: the server asks for no token." : "No step failed.");
  return `${lines.join("\n")}\n`;
}

export function oauthDebugJson(r: OauthDebugResult): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}
