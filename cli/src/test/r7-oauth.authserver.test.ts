// Round 7: the stub authorization server over real HTTP on loopback, and the tokens it mints.
import assert from "node:assert/strict";
import { createHmac, createPublicKey, verify as rsaVerify } from "node:crypto";
import net from "node:net";
import { afterEach, describe, it } from "node:test";
import { startAuthServer } from "../observers/authserver.js";
import { JWT_SHAPE, accessTokenClaims, canonicalResource, sameResource, withOauthHeader } from "../oauth.js";
import type { AuthServerStub } from "../types.js";

const open: AuthServerStub[] = [];
const start = async (): Promise<AuthServerStub> => {
  const s = await startAuthServer();
  open.push(s);
  return s;
};
afterEach(async () => {
  while (open.length) await open.pop()!.close();
});

const seg = (token: string, i: number): Record<string, unknown> => JSON.parse(Buffer.from(token.split(".")[i]!, "base64url").toString("utf8")) as Record<string, unknown>;
const verifies = (s: AuthServerStub, token: string): boolean => {
  const [h, p, sig] = token.split(".");
  return rsaVerify("sha256", Buffer.from(`${h}.${p}`), s.verifyKey(), Buffer.from(sig ?? "", "base64url"));
};
const claims = (s: AuthServerStub) => accessTokenClaims({ issuer: s.issuer, audience: "http://127.0.0.1:9/mcp", scopes: ["mcp:tools"], clientId: "sealmark" }, "sm-sub-a");

describe("stub issuer: endpoints", () => {
  it("binds loopback only, and names issuer and jwks from its own port", async () => {
    const s = await start();
    assert.match(s.issuer, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(s.jwksUri, `${s.issuer}/jwks`);
    const probe = net.connect({ host: "127.0.0.1", port: s.port });
    await new Promise<void>((res, rej) => (probe.once("connect", res), probe.once("error", rej)));
    assert.equal(probe.remoteAddress, "127.0.0.1");
    probe.destroy();
  });

  it("serves RFC 8414 metadata at both well-known paths, with issuer, jwks_uri and a token endpoint", async () => {
    const s = await start();
    for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
      const j = (await (await fetch(`${s.issuer}${p}`)).json()) as Record<string, unknown>;
      assert.equal(j.issuer, s.issuer);
      assert.equal(j.jwks_uri, s.jwksUri);
      assert.equal(j.token_endpoint, `${s.issuer}/token`);
    }
    const t = await fetch(`${s.issuer}/token`, { method: "POST" });
    assert.equal(t.status, 400, "the token endpoint is a stub: it issues nothing");
  });

  it("serves the public key only, as an RSA JWK with kid, alg and use, and the attacker set separately", async () => {
    const s = await start();
    const j = (await (await fetch(s.jwksUri)).json()) as { keys: Record<string, unknown>[] };
    assert.equal(j.keys.length, 1);
    const k = j.keys[0]!;
    assert.deepEqual(Object.keys(k).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
    assert.equal(k.kid, s.kid);
    assert.equal(k.kty, "RSA");
    assert.ok(!("d" in k) && !("p" in k), "no private part");
    const a = (await (await fetch(s.attackerJwksUri)).json()) as { keys: Record<string, unknown>[] };
    assert.equal(a.keys[0]!.kid, s.attackerKid);
    assert.notEqual(a.keys[0]!.n, k.n);
  });

  it("records every request, by mark, so a check can tell a key-set fetch from an attacker-URL fetch", async () => {
    const s = await start();
    await fetch(s.jwksUri);
    const m = s.mark();
    await fetch(s.attackerX5uUri);
    await fetch(`${s.issuer}/nothing?x=1`);
    assert.deepEqual(s.requests(m).map((r) => `${r.method} ${r.path}${r.query}`), ["GET /attacker/x5u", "GET /nothing?x=1"]);
    assert.deepEqual(s.requests().map((r) => r.path), ["/jwks", "/attacker/x5u", "/nothing"]);
  });
});

describe("stub issuer: mint", () => {
  it("a default token is RS256, typ at+jwt, kid of the published key, and verifies with that key; the claims are RFC 9068's", async () => {
    const s = await start();
    const t = s.mint(claims(s));
    assert.equal(t.split(".").length, 3);
    assert.deepEqual(seg(t, 0), { alg: "RS256", typ: "at+jwt", kid: s.kid });
    const c = seg(t, 1);
    assert.equal(c.iss, s.issuer);
    assert.equal(c.aud, "http://127.0.0.1:9/mcp");
    assert.equal(c.sub, "sm-sub-a");
    assert.equal(c.scope, "mcp:tools");
    assert.ok(typeof c.exp === "number" && typeof c.iat === "number" && (c.exp as number) > (c.iat as number));
    assert.ok(verifies(s, t));
    // The published JWK verifies it too (the server's view).
    const j = (await (await fetch(s.jwksUri)).json()) as { keys: Record<string, unknown>[] };
    const [h, p, sig] = t.split(".");
    assert.ok(rsaVerify("sha256", Buffer.from(`${h}.${p}`), createPublicKey({ key: j.keys[0] as never, format: "jwk" }), Buffer.from(sig!, "base64url")));
  });

  it("alg none in any spelling: no kid, empty signature, with or without the trailing dot", async () => {
    const s = await start();
    for (const name of ["none", "None", "NONE"]) {
      const t = s.mint(claims(s), { alg: "none", algName: name });
      assert.ok(t.endsWith("."), name);
      assert.equal(t.split(".").length, 3);
      assert.deepEqual(seg(t, 0), { alg: name, typ: "at+jwt" });
      const nodot = s.mint(claims(s), { alg: "none", algName: name, trailingDot: false });
      assert.equal(nodot.split(".").length, 2);
    }
  });

  it("signature forms: strip, random, tampered payload (header and signature kept), untrusted key (same kid)", async () => {
    const s = await start();
    const c = claims(s);
    assert.ok(s.mint(c, { signature: "strip" }).endsWith("."));
    const r = s.mint(c, { signature: "random" });
    assert.equal(Buffer.from(r.split(".")[2]!, "base64url").length, 256);
    assert.ok(!verifies(s, r));
    const good = s.mint(c);
    const tampered = s.mint(c, { tamper: { sub: "sm-sub-admin" } });
    assert.equal(seg(tampered, 1).sub, "sm-sub-admin");
    assert.equal(tampered.split(".")[0], good.split(".")[0]);
    assert.ok(!verifies(s, tampered), "the payload no longer matches the signature");
    const untrusted = s.mint(c, { key: "untrusted" });
    assert.equal(seg(untrusted, 0).kid, s.kid);
    assert.ok(!verifies(s, untrusted));
  });

  it("HS256 keyed with the public key's PEM or JWK bytes is a real HMAC over the signing input", async () => {
    const s = await start();
    for (const secret of [s.publicPem, s.publicJwkJson]) {
      const t = s.mint(claims(s), { alg: "HS256", hmacSecret: secret });
      const [h, p, sig] = t.split(".");
      assert.equal(seg(t, 0).alg, "HS256");
      assert.equal(sig, createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url"));
    }
    assert.match(s.publicPem, /^-----BEGIN PUBLIC KEY-----\n/);
  });

  it("header tricks: jku and x5u name the attacker URLs and the attacker key signs; kid can be anything", async () => {
    const s = await start();
    const jku = s.mint(claims(s), { key: "attacker", header: { jku: s.attackerJwksUri } });
    assert.deepEqual(seg(jku, 0), { alg: "RS256", typ: "at+jwt", kid: s.attackerKid, jku: s.attackerJwksUri });
    const kid = s.mint(claims(s), { alg: "HS256", hmacSecret: "", header: { kid: "../../../../../../dev/null" } });
    assert.equal(seg(kid, 0).kid, "../../../../../../dev/null");
  });

  it("every minted token is JWT-shaped, so the report normaliser can find it", async () => {
    const s = await start();
    for (const t of [s.mint(claims(s)), s.mint(claims(s), { alg: "none", trailingDot: false }), s.mint(claims(s), { signature: "strip" })]) {
      assert.equal(`x ${t} y`.replace(JWT_SHAPE, "{jwt}"), "x {jwt} y", t.slice(0, 20));
    }
  });
});

describe("oauth helpers", () => {
  it("canonicalResource drops the fragment and the trailing slash and lower-cases scheme and host", () => {
    assert.equal(canonicalResource("HTTP://Example.COM:8080/mcp/#frag"), "http://example.com:8080/mcp");
    assert.equal(canonicalResource("https://mcp.example/"), "https://mcp.example");
    assert.ok(sameResource("https://mcp.example/mcp/", "https://MCP.example/mcp"));
    assert.ok(!sameResource("https://mcp.example/mcp", "https://other.example/mcp"));
  });

  it("accessTokenClaims removes a claim given undefined and replaces one given a value", () => {
    const c = accessTokenClaims({ issuer: "i", audience: "a", scopes: [], clientId: "c" }, "s", { aud: undefined, iss: "x" });
    assert.ok(!("aud" in c));
    assert.ok(!("scope" in c), "no scope claim without declared scopes");
    assert.equal(c.iss, "x");
  });

  it("withOauthHeader adds Authorization: Bearer {bearer} only for the stub, an HTTP server, and no header of its own", () => {
    const http = { command: "node", url: "http://127.0.0.1:1/mcp" };
    assert.deepEqual(withOauthHeader(http, { issuer: "stub" }).headers, { Authorization: "Bearer {bearer}" });
    assert.equal(withOauthHeader(http, { issuer: "external" }), http);
    assert.equal(withOauthHeader({ command: "node" }, { issuer: "stub" }).headers, undefined);
    const own = { ...http, headers: { "X-Api-Token": "Bearer {bearer:a}" } };
    assert.equal(withOauthHeader(own, { issuer: "stub" }), own, "a header that already carries the identity is kept as written");
  });
});
