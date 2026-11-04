import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { isIP } from "node:net";

/**
 * A small, dependency-free X.509 v3 certificate writer (RFC 5280), for the round 7 stub issuer's TLS mode and its x5u probe
 *. node:crypto can read certificates (X509Certificate) and sign, but not create them, and the harness
 * must not depend on an openssl binary. Only what the stub needs is encoded: RSA keys, sha256WithRSAEncryption, a CN-only name, a validity
 * window, and the extensions basicConstraints, keyUsage, extKeyUsage, subjectAltName, subjectKeyIdentifier and authorityKeyIdentifier
 * (the last two are what strict verifiers, for example Python 3.13's default context, require).
 */

// ---- DER (X.690) ----------------------------------------------------------------------------------------

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
export const tlv = (tag: number, content: Buffer): Buffer => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const seq = (...items: Buffer[]): Buffer => tlv(0x30, Buffer.concat(items));
const set = (...items: Buffer[]): Buffer => tlv(0x31, Buffer.concat(items));
/** A non-negative INTEGER from big-endian bytes (a leading zero is added when the top bit is set, leading zeros are trimmed). */
function int(bytes: Buffer | number): Buffer {
  let b = typeof bytes === "number" ? Buffer.from([bytes]) : bytes;
  let i = 0;
  while (i < b.length - 1 && b[i] === 0 && (b[i + 1]! & 0x80) === 0) i++;
  b = b.subarray(i);
  return tlv(0x02, b[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
}
const bool = (v: boolean): Buffer => tlv(0x01, Buffer.from([v ? 0xff : 0]));
const nul = (): Buffer => Buffer.from([0x05, 0x00]);
const octets = (b: Buffer): Buffer => tlv(0x04, b);
const bits = (b: Buffer, unused = 0): Buffer => tlv(0x03, Buffer.concat([Buffer.from([unused]), b]));
const utf8 = (s: string): Buffer => tlv(0x0c, Buffer.from(s, "utf8"));
const explicit = (n: number, inner: Buffer): Buffer => tlv(0xa0 | n, inner);
export function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const out: number[] = [parts[0]! * 40 + parts[1]!];
  for (const p of parts.slice(2)) {
    const enc: number[] = [p & 0x7f];
    for (let v = Math.floor(p / 128); v > 0; v = Math.floor(v / 128)) enc.unshift((v & 0x7f) | 0x80);
    out.push(...enc);
  }
  return tlv(0x06, Buffer.from(out));
}
/** UTCTime (RFC 5280 4.1.2.5.1: YYMMDDHHMMSSZ, for years 1950 to 2049). */
function utcTime(d: Date): Buffer {
  const p = (n: number) => String(n).padStart(2, "0");
  return tlv(0x17, Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`, "ascii"));
}

// ---- certificates ---------------------------------------------------------------------------------------

const SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), nul());
const name = (cn: string): Buffer => seq(set(seq(oid("2.5.4.3"), utf8(cn))));
const ext = (id: string, critical: boolean, value: Buffer): Buffer => seq(oid(id), ...(critical ? [bool(true)] : []), octets(value));

/** One DER TLV at `at`: where its content starts and where it ends. */
function readTlv(b: Buffer, at: number): { content: number; end: number } {
  const l = b[at + 1]!;
  if (!(l & 0x80)) return { content: at + 2, end: at + 2 + l };
  const k = l & 0x7f;
  let n = 0;
  for (let i = 0; i < k; i++) n = n * 256 + b[at + 2 + i]!;
  return { content: at + 2 + k, end: at + 2 + k + n };
}

/** The key identifier of RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT STRING (without its unused-bits byte). */
export function keyId(publicKey: KeyObject): Buffer {
  const spki = publicKey.export({ type: "spki", format: "der" });
  // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const outer = readTlv(spki, 0);
  const alg = readTlv(spki, outer.content);
  const key = readTlv(spki, alg.end);
  return createHash("sha1").update(spki.subarray(key.content + 1, key.end)).digest();
}

export interface CertKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** DER and PEM of the certificate. */
  der: Buffer;
  pem: string;
  /** The subject's key identifier (for the issued certificates' authorityKeyIdentifier). */
  keyId: Buffer;
  cn: string;
}

export interface CertOptions {
  cn: string;
  /** A CA certificate (basicConstraints cA, keyCertSign) or a TLS server leaf (digitalSignature, keyEncipherment, serverAuth). */
  ca: boolean;
  /** DNS names and IP addresses for subjectAltName (a leaf). */
  san?: string[];
  /** Who signs: a CA from `createCertificate`; absent = self-signed. */
  issuer?: CertKey;
  /** The subject key; a fresh RSA-2048 pair when absent. */
  keys?: { privateKey: KeyObject; publicKey: KeyObject };
  /** Validity in hours from one hour ago (default 24). */
  hours?: number;
}

export const toPem = (der: Buffer, label = "CERTIFICATE"): string => `-----BEGIN ${label}-----\n${der.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;

/** Creates and signs one certificate. */
export function createCertificate(o: CertOptions): CertKey {
  const keys = o.keys ?? generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = keys.publicKey.export({ type: "spki", format: "der" });
  const kid = keyId(keys.publicKey);
  const issuerName = o.issuer?.cn ?? o.cn;
  const signer = o.issuer?.privateKey ?? keys.privateKey;
  const authorityId = o.issuer?.keyId ?? kid;
  const serial = randomBytes(16);
  serial[0] = (serial[0]! & 0x7f) | 0x01; // positive and non-zero
  const now = Date.now();
  const extensions: Buffer[] = [
    ext("2.5.29.19", true, o.ca ? seq(bool(true), int(0)) : seq()),
    // keyUsage: CA = digitalSignature, keyCertSign, cRLSign (bits 0, 5, 6); leaf = digitalSignature, keyEncipherment (bits 0, 2).
    ext("2.5.29.15", true, o.ca ? bits(Buffer.from([0x86]), 1) : bits(Buffer.from([0xa0]), 5)),
    ext("2.5.29.14", false, octets(kid)),
    ext("2.5.29.35", false, seq(tlv(0x80, authorityId))),
  ];
  if (!o.ca) extensions.push(ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.1"))));
  if (o.san?.length) {
    const names = o.san.map((s) => {
      if (isIP(s) === 4) return tlv(0x87, Buffer.from(s.split(".").map(Number)));
      if (isIP(s) === 6) throw new Error("IPv6 subjectAltName is not supported by this encoder");
      return tlv(0x82, Buffer.from(s, "ascii"));
    });
    extensions.push(ext("2.5.29.17", false, seq(...names)));
  }
  const tbs = seq(
    explicit(0, int(2)), // v3
    int(serial),
    SHA256_RSA,
    name(issuerName),
    seq(utcTime(new Date(now - 3600_000)), utcTime(new Date(now + (o.hours ?? 24) * 3600_000))),
    name(o.cn),
    Buffer.from(spki),
    explicit(3, seq(...extensions)),
  );
  const signature = sign("sha256", tbs, signer);
  const der = seq(tbs, SHA256_RSA, bits(signature));
  return { privateKey: keys.privateKey, publicKey: keys.publicKey, der, pem: toPem(der), keyId: kid, cn: o.cn };
}

/** A throwaway CA and a TLS leaf for 127.0.0.1 and localhost, signed by it: what the stub issuer serves over https. */
export function loopbackTls(label = "Sealmark harness"): { ca: CertKey; leaf: CertKey } {
  const ca = createCertificate({ cn: `${label} CA (throwaway, this run only)`, ca: true });
  const leaf = createCertificate({ cn: "127.0.0.1", ca: false, san: ["127.0.0.1", "localhost"], issuer: ca });
  return { ca, leaf };
}
