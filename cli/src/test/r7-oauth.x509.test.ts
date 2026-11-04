// Round 7 follow-up (D41): the dependency-free X.509 writer (observers/x509.ts), the https mode of the stub issuer, and the real certificate
// chain its x5u probe serves. Certificates are read back with node:crypto's X509Certificate and used in real TLS handshakes.
import assert from "node:assert/strict";
import { X509Certificate, createPublicKey } from "node:crypto";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { afterEach, describe, it } from "node:test";
import { startAuthServer } from "../observers/authserver.js";
import { createCertificate, loopbackTls, oid, tlv } from "../observers/x509.js";
import type { AuthServerStub } from "../types.js";

const get = (url: string, ca?: string): Promise<{ status: number; body: string; type: string }> =>
  new Promise((resolve, reject) => {
    https
      .get(url, { ...(ca ? { ca } : {}), timeout: 5000 }, (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body, type: String(res.headers["content-type"] ?? "") }));
      })
      .on("error", reject);
  });
const pemCerts = (pem: string): string[] => pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n?/g) ?? [];

describe("x509 writer: DER", () => {
  it("encodes OIDs and lengths per X.690", () => {
    assert.equal(oid("1.2.840.113549.1.1.11").toString("hex"), "06092a864886f70d01010b");
    assert.equal(oid("2.5.29.17").toString("hex"), "0603551d11");
    assert.equal(tlv(0x04, Buffer.alloc(200)).subarray(0, 3).toString("hex"), "0481c8");
    assert.equal(tlv(0x04, Buffer.alloc(300)).subarray(0, 4).toString("hex"), "0482012c");
  });
});

describe("x509 writer: certificates", () => {
  const { ca, leaf } = loopbackTls("test");
  const c = new X509Certificate(ca.pem);
  const l = new X509Certificate(leaf.pem);

  it("a CA: v3, self-signed, cA, about a day of validity", () => {
    assert.equal(c.ca, true);
    assert.ok(c.verify(c.publicKey), "self-signed");
    assert.equal(c.subject, c.issuer);
    const hours = (Date.parse(c.validTo) - Date.parse(c.validFrom)) / 3600_000;
    assert.ok(hours >= 24 && hours <= 26, `${hours} h`);
    assert.ok(Date.parse(c.validFrom) < Date.now() && Date.parse(c.validTo) > Date.now());
  });

  it("a leaf for 127.0.0.1 and localhost, issued and signed by the CA, with serverAuth and the key ids strict verifiers need", () => {
    assert.equal(l.ca, false);
    assert.equal(l.subjectAltName, "IP Address:127.0.0.1, DNS:localhost");
    assert.ok(l.checkIssued(c) && l.verify(c.publicKey));
    assert.equal(l.checkIP("127.0.0.1"), "127.0.0.1");
    assert.equal(l.checkHost("localhost"), "localhost");
    assert.ok(l.keyUsage?.includes("1.3.6.1.5.5.7.3.1"), "extKeyUsage serverAuth");
    assert.equal(l.publicKey.export({ type: "spki", format: "der" }).toString("hex"), leaf.publicKey.export({ type: "spki", format: "der" }).toString("hex"));
    assert.notEqual(l.serialNumber, c.serialNumber);
    // authorityKeyIdentifier of the leaf = subjectKeyIdentifier of the CA
    assert.ok(l.raw.includes(ca.keyId) && c.raw.includes(ca.keyId));
  });

  it("a real TLS handshake: trusted with the CA on both names, refused without it", async () => {
    const srv = https.createServer({ key: leaf.privateKey.export({ type: "pkcs8", format: "pem" }), cert: leaf.pem }, (_q, r) => r.end("ok"));
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const port = (srv.address() as AddressInfo).port;
    try {
      for (const host of ["127.0.0.1", "localhost"]) assert.equal((await get(`https://${host}:${port}/`, ca.pem)).body, "ok", host);
      await assert.rejects(get(`https://127.0.0.1:${port}/`), /self.signed|unable to verify|certificate/i);
      const other = createCertificate({ cn: "another CA", ca: true });
      await assert.rejects(get(`https://127.0.0.1:${port}/`, other.pem), /unable to verify|certificate/i);
    } finally {
      srv.close();
      srv.closeAllConnections();
    }
  });
});

describe("stub issuer over https (D41)", () => {
  const open: AuthServerStub[] = [];
  afterEach(async () => {
    while (open.length) await open.pop()!.close();
  });

  it("issuer and jwks are https; metadata and keys are served to a client that trusts caPem, and to no other", async () => {
    const s = await startAuthServer({ tls: true });
    open.push(s);
    assert.equal(s.tls, true);
    assert.match(s.issuer, /^https:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(s.jwksUri, `${s.issuer}/jwks`);
    const meta = JSON.parse((await get(`${s.issuer}/.well-known/oauth-authorization-server`, s.caPem)).body) as { issuer: string; jwks_uri: string };
    assert.deepEqual([meta.issuer, meta.jwks_uri], [s.issuer, s.jwksUri]);
    const keys = JSON.parse((await get(s.jwksUri, s.caPem)).body) as { keys: { kid: string }[] };
    assert.equal(keys.keys[0]!.kid, s.kid);
    await assert.rejects(get(s.jwksUri), /self.signed|unable to verify|certificate/i);
  });

  it("http stays available (oauth.tls: false) and has no CA", async () => {
    const s = await startAuthServer();
    open.push(s);
    assert.equal(s.tls, false);
    assert.equal(s.caPem, undefined);
    assert.match(s.issuer, /^http:\/\//);
  });

  it("x5u serves a real chain: a certificate for the attacker key, issued by an attacker CA", async () => {
    const s = await startAuthServer({ tls: true });
    open.push(s);
    const r = await get(s.attackerX5uUri, s.caPem);
    assert.equal(r.type, "application/pem-certificate-chain");
    const [leafPem, caPem] = pemCerts(r.body);
    assert.ok(leafPem && caPem, "two certificates");
    const leaf = new X509Certificate(leafPem);
    const ca = new X509Certificate(caPem);
    assert.ok(leaf.checkIssued(ca) && leaf.verify(ca.publicKey) && ca.ca);
    const attackerJwk = (JSON.parse((await get(s.attackerJwksUri, s.caPem)).body) as { keys: Record<string, unknown>[] }).keys[0]!;
    const fromJwk = createPublicKey({ key: attackerJwk as never, format: "jwk" }).export({ type: "spki", format: "der" });
    assert.equal(leaf.publicKey.export({ type: "spki", format: "der" }).toString("hex"), fromJwk.toString("hex"), "the chain certifies the key that signs the x5u probe");
    assert.equal(r.body, s.attackerChainPem);
  });
});
