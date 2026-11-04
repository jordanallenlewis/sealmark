// Toy Streamable HTTP MCP server for the round 7 `oauth` pack: a resource server that validates JWT access
// tokens against a configurable issuer, JWKS URL and audience, written from the public specifications only (MCP authorization 2025-06-18,
// RFC 9728, RFC 8707, RFC 6750, RFC 7515/7517/7519) with node:crypto. Not part of the product surface; synthetic, loopback only.
//
// Run: node dist/toy/oauth-http.js --mode <mode> [--port <n>] [--backend <url>]
// The issuer, JWKS URL, audience and required scopes come from the environment (TOY_ISSUER, TOY_JWKS_URI, TOY_AUDIENCE, TOY_REQUIRED_SCOPES,
// space separated) or from --issuer, --jwks, --audience, --scopes: the way a real server is pointed at {issuer}, {jwks} and {audience}.
// Prints `listening http://127.0.0.1:<port>/mcp`.
//
//   good             RS256 only (alg allowlist), key from the configured JWKS by kid, iss, aud, exp (required), nbf, scope; token from the
//                    Authorization header only; each session bound to the token's sub; RFC 9728 metadata and WWW-Authenticate on 401;
//                    the backend is called with the server's own credential, never the caller's token
//   alg-none         also accepts alg none (any case), unsigned                          -> oauth-token-forgery
//   jku              takes the verification key from a jku URL in the token header       -> oauth-token-forgery
//   hs-confusion     alg HS256 is verified with the RSA public key (PEM) as HMAC secret  -> oauth-token-forgery
//   no-aud           does not check aud                                                  -> oauth-claims
//   no-exp           does not check exp (expired and missing exp accepted)               -> oauth-claims
//   no-iss           does not check iss                                                  -> oauth-claims
//   query-token      also reads ?access_token= from the URL                              -> oauth-scope (query-token leg)
//   no-scope         does not check scope                                                -> oauth-scope (insufficient-scope leg)
//   passthrough      sends the caller's own token to the backend                         -> upstream-token-passthrough
//   session-unbound  a session answers any valid token, not only its own caller's      -> http-session-binding
//   no-metadata      no WWW-Authenticate challenge and no protected-resource metadata    -> oauth-discovery
//   strict-tls       good, hardened: refuses to start unless the issuer and JWKS URL are https, and trusts the CA file in TOY_CA_FILE
//                    (not a flaw: the near miss for the stub's https mode)
import { AsyncLocalStorage } from "node:async_hooks";
import { createHmac, createPublicKey, randomUUID, timingSafeEqual, verify as rsaVerify, type webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export const OAUTH_TOY_MODES = ["good", "alg-none", "jku", "hs-confusion", "no-aud", "no-exp", "no-iss", "query-token", "no-scope", "passthrough", "session-unbound", "no-metadata", "strict-tls"] as const;
export type OauthToyMode = (typeof OAUTH_TOY_MODES)[number];

export interface OauthToyOptions {
  port?: number;
  issuer: string;
  jwksUri: string;
  audience: string;
  scopes?: string[];
  /** Base URL of the backend (the harness's upstream stub); without it `lookup` answers locally. */
  backend?: string;
  backendTimeoutMs?: number;
  /** A PEM file of CAs the toy trusts for its issuer's https (TOY_CA_FILE); without it the process's default trust store is used. */
  caFile?: string;
}

/** What strict-tls says, and why it refuses to start, when a trust root is not https (the behaviour of a hardened server). */
export class TrustRootError extends Error {}

export interface OauthToy {
  mode: OauthToyMode;
  port: number;
  url: string;
  close(): Promise<void>;
}

/** The server's own credential for its backend: what a server that does not pass tokens through sends. */
export const TOY_SERVICE_CREDENTIAL = "Bearer sm-toy-service-credential";
const SKEW = 30;

type JsonWebKey = webcrypto.JsonWebKey;

const caller = new AsyncLocalStorage<{ authorization: string; sub: string }>();

type Claims = Record<string, unknown>;
type Verdict = { ok: true; claims: Claims } | { ok: false; status: 401 | 403; error: string; description: string };

const b64json = (seg: string): Record<string, unknown> => {
  const v = JSON.parse(Buffer.from(seg, "base64url").toString("utf8")) as unknown;
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
  return v as Record<string, unknown>;
};

/** GET a key set; with `ca`, an https URL is verified against those CAs only (a server's own CA setting). */
async function fetchKeys(url: string, ca?: string): Promise<JsonWebKey[]> {
  let text: string;
  if (ca && url.startsWith("https:")) {
    text = await new Promise<string>((resolve, reject) => {
      const req = https.get(url, { ca, timeout: 3000 }, (res) => {
        let d = "";
        res.on("data", (c: Buffer) => (d += c));
        res.on("end", () => ((res.statusCode ?? 0) < 300 ? resolve(d) : reject(new Error(`JWKS ${res.statusCode}`))));
      });
      req.on("timeout", () => req.destroy(new Error("JWKS timeout")));
      req.on("error", reject);
    });
  } else {
    const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) throw new Error(`JWKS ${r.status}`);
    text = await r.text();
  }
  const j = JSON.parse(text) as { keys?: JsonWebKey[] };
  return Array.isArray(j.keys) ? j.keys : [];
}

function makeValidator(mode: OauthToyMode, o: OauthToyOptions) {
  let cache: JsonWebKey[] = [];
  const ca = o.caFile ? readFileSync(o.caFile, "utf8") : undefined;
  const keyFor = async (kid: unknown): Promise<JsonWebKey | undefined> => {
    const find = () => cache.find((k) => (k as { kid?: unknown }).kid === kid && k.kty === "RSA");
    if (!find()) cache = await fetchKeys(o.jwksUri, ca).catch(() => cache);
    return find();
  };
  const bad = (description: string): Verdict => ({ ok: false, status: 401, error: "invalid_token", description });
  return async (token: string): Promise<Verdict> => {
    const parts = token.split(".");
    let header: Record<string, unknown>;
    let claims: Claims;
    try {
      header = b64json(parts[0] ?? "");
      claims = b64json(parts[1] ?? "");
    } catch {
      return bad("malformed token");
    }
    const alg = typeof header.alg === "string" ? header.alg : "";
    const input = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = Buffer.from(parts[2] ?? "", "base64url");
    if (mode === "alg-none" && alg.toLowerCase() === "none") {
      // the flaw: an unsigned token is taken at its word
    } else if (alg === "RS256") {
      if (parts.length !== 3) return bad("malformed token");
      let jwk: JsonWebKey | undefined;
      if (mode === "jku" && typeof header.jku === "string") {
        // the flaw: the token names where its own key lives
        const keys = await fetchKeys(header.jku, ca).catch(() => []);
        jwk = keys.find((k) => (k as { kid?: unknown }).kid === header.kid) ?? keys[0];
      } else jwk = await keyFor(header.kid);
      if (!jwk) return bad("unknown key");
      let okSig = false;
      try {
        okSig = rsaVerify("sha256", input, createPublicKey({ key: jwk, format: "jwk" }), sig);
      } catch {
        okSig = false;
      }
      if (!okSig) return bad("bad signature");
    } else if (mode === "hs-confusion" && alg === "HS256") {
      // the flaw: the RSA public key, as PEM text, is used as an HMAC secret
      const jwk = (await keyFor(header.kid)) ?? cache[0];
      if (!jwk) return bad("unknown key");
      const pem = String(createPublicKey({ key: jwk, format: "jwk" }).export({ type: "spki", format: "pem" }));
      const want = createHmac("sha256", pem).update(input).digest();
      if (want.length !== sig.length || !timingSafeEqual(want, sig)) return bad("bad signature");
    } else return bad(`algorithm ${alg || "(none)"} not allowed`);

    const now = Math.floor(Date.now() / 1000);
    if (mode !== "no-exp") {
      if (typeof claims.exp !== "number") return bad("no exp");
      if (claims.exp < now - SKEW) return bad("expired");
    }
    if (typeof claims.nbf === "number" && claims.nbf > now + SKEW) return bad("not yet valid");
    if (mode !== "no-iss" && claims.iss !== o.issuer) return bad("wrong issuer");
    if (mode !== "no-aud") {
      const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!aud.includes(o.audience)) return bad("wrong audience");
    }
    if (typeof claims.sub !== "string" || !claims.sub) return bad("no sub");
    const need = o.scopes ?? [];
    if (mode !== "no-scope" && need.length) {
      const have = typeof claims.scope === "string" ? claims.scope.split(" ") : [];
      const missing = need.filter((s) => !have.includes(s));
      if (missing.length) return { ok: false, status: 403, error: "insufficient_scope", description: `needs ${need.join(" ")}` };
    }
    return { ok: true, claims };
  };
}

function makeServer(mode: OauthToyMode, o: OauthToyOptions): Server {
  const server = new Server({ name: `sealmark-toy-oauth-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: "whoami", description: "Say which caller this is.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } },
      { name: "lookup", description: "Look up one record by id.", inputSchema: { type: "object", properties: { id: { type: "string", description: "Record id" } }, required: ["id"] }, annotations: { readOnlyHint: true } },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const who = caller.getStore();
    if (req.params.name === "whoami") return { content: [{ type: "text", text: `caller ${who?.sub ?? "unknown"}` }] };
    const id = (req.params.arguments ?? {}).id;
    if (typeof id !== "string") return { content: [{ type: "text", text: "id must be a string" }], isError: true };
    if (!o.backend) return { content: [{ type: "text", text: `found 0 record(s) for ${id}` }] };
    const authorization = mode === "passthrough" ? (who?.authorization ?? "") : TOY_SERVICE_CREDENTIAL;
    try {
      const r = await fetch(`${o.backend}/lookup`, { method: "POST", headers: { "content-type": "application/json", authorization }, body: JSON.stringify({ id }), signal: AbortSignal.timeout(o.backendTimeoutMs ?? 1000) });
      const text = await r.text();
      if (!r.ok) return { content: [{ type: "text", text: `the backend could not run the lookup (status ${r.status}); nothing from its reply is shown` }], isError: true };
      let rows = 0;
      try {
        const j = JSON.parse(text) as { rows?: unknown[] };
        rows = Array.isArray(j.rows) ? j.rows.length : 0;
      } catch {
        // a non-JSON reply counts as no rows
      }
      return { content: [{ type: "text", text: `found ${rows} record(s) for ${id}` }] };
    } catch {
      return { content: [{ type: "text", text: "the backend did not answer in time" }], isError: true };
    }
  });
  return server;
}

function readBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function jsonError(res: http.ServerResponse, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }));
}

export async function startOauthToy(mode: OauthToyMode, opts: OauthToyOptions): Promise<OauthToy> {
  if (mode === "strict-tls") {
    const bad = [["issuerUrl", opts.issuer], ["jwksUri", opts.jwksUri]].filter(([, u]) => !u!.startsWith("https://"));
    if (bad.length) throw new TrustRootError(`auth is enabled but a configured trust root is not https (${bad.map(([k, u]) => `${k}='${u}'`).join("; ")}): refusing to start rather than trusting a spoofable key source`);
  }
  const o: OauthToyOptions = { ...opts, ...(opts.backend ? { backend: opts.backend.replace(/\/$/, "") } : {}) };
  const validate = makeValidator(mode, o);
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server; sub: string }>();
  let port = 0;
  const metadataPath = "/.well-known/oauth-protected-resource/mcp";
  const metadataUrl = () => `http://127.0.0.1:${port}${metadataPath}`;
  const challenge = (extra = ""): Record<string, string> => (mode === "no-metadata" ? {} : { "www-authenticate": `Bearer ${extra}${extra ? ", " : ""}resource_metadata="${metadataUrl()}"` });

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    if (req.method === "GET" && (url.pathname === metadataPath || url.pathname === "/.well-known/oauth-protected-resource")) {
      if (mode === "no-metadata") return jsonError(res, 404, -32000, "Not found");
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ resource: o.audience, authorization_servers: [o.issuer], bearer_methods_supported: ["header"], ...(o.scopes?.length ? { scopes_supported: o.scopes } : {}) }));
    }
    if (url.pathname !== "/mcp") return jsonError(res, 404, -32000, "Not found");
    const host = req.headers.host;
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return jsonError(res, 403, -32000, "Forbidden: invalid Host header");
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    if (origin && origin !== `http://127.0.0.1:${port}` && origin !== `http://localhost:${port}`) return jsonError(res, 403, -32000, "Forbidden: invalid Origin header");
    const header = typeof req.headers.authorization === "string" ? /^Bearer\s+(\S+)$/i.exec(req.headers.authorization)?.[1] : undefined;
    // RFC 6750 2.3 allows a URI query token; the MCP specification forbids it. Only query-token reads it.
    const token = header ?? (mode === "query-token" ? (url.searchParams.get("access_token") ?? undefined) : undefined);
    if (!token) return jsonError(res, 401, -32001, "Unauthorized", challenge());
    const v = await validate(token);
    if (!v.ok) return jsonError(res, v.status, -32001, v.status === 403 ? "Forbidden: insufficient scope" : "Unauthorized", challenge(`error="${v.error}"${v.status === 403 ? `, scope="${(o.scopes ?? []).join(" ")}"` : ""}`));
    const sub = String(v.claims.sub);
    const who = { authorization: `Bearer ${token}`, sub };
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await readBody(req);
      } catch {
        return jsonError(res, 400, -32700, "Parse error");
      }
    }
    const sid = typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : undefined;
    if (sid) {
      const s = sessions.get(sid);
      if (!s) return jsonError(res, 404, -32001, "Session not found");
      if (mode !== "session-unbound" && s.sub !== sub) return jsonError(res, 403, -32001, "Forbidden: the session belongs to another caller");
      return caller.run(who, () => s.transport.handleRequest(req, res, body));
    }
    if (req.method === "POST" && isInitializeRequest(body)) {
      const server = makeServer(mode, o);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => void sessions.set(id, { transport, server, sub }) });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      return caller.run(who, () => transport.handleRequest(req, res, body));
    }
    return jsonError(res, 400, -32000, "Bad Request: Mcp-Session-Id header is required");
  };

  const httpServer = http.createServer((req, res) => {
    handler(req, res).catch((e: unknown) => jsonError(res, 500, -32603, e instanceof Error ? e.message : "internal error"));
  });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.port ?? 0, "127.0.0.1", () => resolve());
  });
  port = (httpServer.address() as { port: number }).port;
  return {
    mode,
    port,
    url: `http://127.0.0.1:${port}/mcp`,
    async close() {
      for (const { transport, server } of sessions.values()) {
        await transport.close().catch(() => {});
        await server.close().catch(() => {});
      }
      sessions.clear();
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
        httpServer.closeAllConnections();
      });
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({
    options: { mode: { type: "string" }, port: { type: "string" }, backend: { type: "string" }, issuer: { type: "string" }, jwks: { type: "string" }, audience: { type: "string" }, scopes: { type: "string" }, "backend-timeout-ms": { type: "string" } },
    strict: true,
  });
  const mode = (values.mode ?? "good") as OauthToyMode;
  const issuer = values.issuer ?? process.env.TOY_ISSUER;
  const jwksUri = values.jwks ?? process.env.TOY_JWKS_URI;
  const audience = values.audience ?? process.env.TOY_AUDIENCE;
  const scopes = (values.scopes ?? process.env.TOY_REQUIRED_SCOPES ?? "").split(/[\s,]+/).filter(Boolean);
  const caFile = process.env.TOY_CA_FILE || undefined;
  if (!OAUTH_TOY_MODES.includes(mode) || !issuer || !jwksUri || !audience) {
    process.stderr.write(`toy oauth server: --mode must be one of ${OAUTH_TOY_MODES.join(", ")}, and the issuer, JWKS URL and audience are required (TOY_ISSUER, TOY_JWKS_URI, TOY_AUDIENCE or --issuer, --jwks, --audience)\n`);
    process.exit(2);
  }
  let toy: OauthToy;
  try {
    toy = await startOauthToy(mode, { port: values.port ? Number(values.port) : 0, issuer, jwksUri, audience, scopes, ...(caFile ? { caFile } : {}), ...(values.backend ? { backend: values.backend } : {}), ...(values["backend-timeout-ms"] ? { backendTimeoutMs: Number(values["backend-timeout-ms"]) } : {}) });
  } catch (e) {
    process.stderr.write(`toy oauth server: ${(e as Error).message}\n`);
    process.exit(1);
  }
  process.stdout.write(`listening ${toy.url}\n`);
  const stop = () => void toy.close().finally(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
