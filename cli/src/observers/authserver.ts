import { createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign as rsaSign, type KeyObject } from "node:crypto";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import type { AuthServerMintOptions, AuthServerRequest, AuthServerStub } from "../types.js";
import { createCertificate, loopbackTls } from "./x509.js";

/**
 * The stub authorization server: a loopback HTTP server the harness owns, standing in for the OAuth
 * issuer the server under test trusts. Written from the public specifications only: RFC 8414 (authorization server metadata), RFC 7517
 * (JWK Set), RFC 7515/7519 (JWS, JWT), RFC 9068 (JWT access tokens). It
 *
 * - makes a fresh RSA-2048 signing key per run with a random `kid`, and serves only its public half at `/jwks`;
 * - serves `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` (issuer, jwks_uri, a token endpoint stub);
 * - signs tokens with `mint()`, which can also forge them on purpose (alg none, a stripped or random signature, a payload changed after
 *   signing, an untrusted key, HS256 keyed with the public key, `jku`/`x5u`/`kid` header tricks);
 * - serves an attacker key set at `/attacker/jwks` and, at `/attacker/x5u`, a real certificate chain for the attacker key (leaf and its own
 *   CA, PEM, RFC 7515 4.1.5), and records every request, so a check can prove that the server fetched the real key set and did not fetch
 *   an attacker URL;
 * - with `tls: true` (the run's default, this release) serves all of it over https with a throwaway CA and a leaf for 127.0.0.1 and
 *   localhost, made per run by the dependency-free X.509 writer in `x509.ts`; `caPem` is what the server under test must trust ({ca_file}).
 *
 * It never issues a token to anyone over the network (`/token` answers `unsupported_grant_type`), never proxies and never contacts
 * another host; it binds 127.0.0.1 only.
 */

const b64u = (b: Buffer | string): string => Buffer.from(b).toString("base64url");
const rand = (n: number): string => randomBytes(n).toString("hex");
/** More than this many requests are not kept (the oldest go first). */
const MAX_KEPT = 10_000;

interface KeyPair {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** The public key as a JWK, with kid, alg and use. */
  jwk: Record<string, unknown>;
}

function keyPair(kid: string): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const raw = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  return { kid, privateKey, publicKey, jwk: { kty: raw.kty, n: raw.n, e: raw.e, kid, alg: "RS256", use: "sig" } };
}

/** `header.payload` as a JWS signing input. */
const signingInput = (header: Record<string, unknown>, payload: Record<string, unknown>): string => `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;

export interface AuthServerOptions {
  log?: (s: string) => void;
  /** Serve https with a throwaway CA (default false here; run.ts passes oauth.tls, which defaults to true). */
  tls?: boolean;
}

export async function startAuthServer(o: AuthServerOptions = {}): Promise<AuthServerStub> {
  const real = keyPair(`sm-kid-${rand(6)}`);
  // A second key the server was never told about (not in /jwks) and an attacker key published only at /attacker/*.
  const untrusted = keyPair(real.kid);
  const attacker = keyPair(`sm-attacker-kid-${rand(6)}`);
  // A real chain for the attacker key: a leaf certifying it, signed by an attacker CA (what an x5u URL is meant to serve).
  const attackerCa = createCertificate({ cn: "sm attacker CA", ca: true });
  const attackerLeaf = createCertificate({ cn: "sm-attacker-signer", ca: false, issuer: attackerCa, keys: { privateKey: attacker.privateKey, publicKey: attacker.publicKey } });
  const attackerChainPem = `${attackerLeaf.pem}${attackerCa.pem}`;
  const tls = o.tls ? loopbackTls("Sealmark stub issuer") : undefined;
  const kept: AuthServerRequest[] = [];
  let lastId = 0;
  let closed = false;
  let issuer = "";

  const metadata = (): Record<string, unknown> => ({
    issuer,
    jwks_uri: `${issuer}/jwks`,
    token_endpoint: `${issuer}/token`,
    authorization_endpoint: `${issuer}/authorize`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["RS256"],
    subject_types_supported: ["public"],
  });

  const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    req.on("data", () => {});
    req.on("error", () => {});
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://authserver.invalid");
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
      kept.push({ id: ++lastId, at: Date.now(), method: req.method ?? "GET", path: url.pathname, query: url.search, headers });
      if (kept.length > MAX_KEPT) kept.splice(0, kept.length - MAX_KEPT);
      o.log?.(`authserver: ${req.method} ${url.pathname}`);
      if (closed || res.destroyed) return;
      const json = (status: number, body: unknown) => {
        const text = JSON.stringify(body);
        res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "content-length": String(Buffer.byteLength(text)) });
        res.end(text);
      };
      switch (url.pathname) {
        case "/.well-known/oauth-authorization-server":
        case "/.well-known/openid-configuration":
          return json(200, metadata());
        case "/jwks":
          return json(200, { keys: [real.jwk] });
        case "/attacker/jwks":
          return json(200, { keys: [attacker.jwk] });
        case "/attacker/x5u":
          // RFC 7515 4.1.5: the certificate (chain) in PEM, the certificate containing the signing key first.
          res.writeHead(200, { "content-type": "application/pem-certificate-chain", "content-length": String(Buffer.byteLength(attackerChainPem)) });
          return void res.end(attackerChainPem);
        case "/token":
          return json(400, { error: "unsupported_grant_type", error_description: "the harness's stub issuer mints tokens itself; it issues none over the network" });
        default:
          return json(404, { error: "not_found" });
      }
    });
  };
  const server = tls ? https.createServer({ key: tls.leaf.privateKey.export({ type: "pkcs8", format: "pem" }), cert: tls.leaf.pem }, handler) : http.createServer(handler);

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // Loopback only: the stub is the server's issuer for the length of a run and must never be reachable from the network.
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;
  issuer = `${tls ? "https" : "http"}://127.0.0.1:${port}`;
  const publicPem = String(real.publicKey.export({ type: "spki", format: "pem" }));
  const publicJwkJson = JSON.stringify(real.jwk);

  const mint = (claims: Record<string, unknown>, m: AuthServerMintOptions = {}): string => {
    const alg = m.alg ?? "RS256";
    const signer = m.key === "untrusted" ? untrusted : m.key === "attacker" ? attacker : real;
    const header: Record<string, unknown> = { alg: m.algName ?? alg, typ: "at+jwt", ...(m.omitKid || alg === "none" ? {} : { kid: signer.kid }), ...(m.header ?? {}) };
    const input = signingInput(header, claims);
    let sig: string;
    if (alg === "none") sig = "";
    else if (alg === "HS256") sig = b64u(createHmac("sha256", m.hmacSecret ?? "").update(input).digest());
    else sig = b64u(rsaSign("sha256", Buffer.from(input), signer.privateKey));
    if (m.signature === "random") sig = b64u(randomBytes(256));
    if (m.signature === "strip") sig = "";
    // A payload replaced after signing keeps the original header and signature (the claims a server must not trust without verifying).
    const head = m.tamper ? `${input.split(".")[0]}.${b64u(JSON.stringify({ ...claims, ...m.tamper }))}` : input;
    if (m.signature === "strip-dot" || (alg === "none" && m.trailingDot === false)) return head;
    return `${head}.${sig}`;
  };

  return {
    issuer,
    jwksUri: `${issuer}/jwks`,
    attackerJwksUri: `${issuer}/attacker/jwks`,
    attackerX5uUri: `${issuer}/attacker/x5u`,
    port,
    tls: Boolean(tls),
    ...(tls ? { caPem: tls.ca.pem } : {}),
    attackerChainPem,
    kid: real.kid,
    attackerKid: attacker.kid,
    publicPem,
    publicJwkJson,
    // A key that verifies an RS256 token: what a test needs to check what `mint` produced.
    verifyKey: () => createPublicKey({ key: real.jwk as never, format: "jwk" }),
    mint,
    mark: () => lastId,
    requests: (mark) => kept.filter((r) => r.id > (mark ?? 0)).map((r) => ({ ...r, headers: { ...r.headers } })),
    async close() {
      if (closed) return;
      closed = true;
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}
