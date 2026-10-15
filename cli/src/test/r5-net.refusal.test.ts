// Round 5, package net (G1): the pure functions of the refusal model. The sixteen wordings of the verification and the tier names are
// pinned in r4-net.refusal.test.ts (updated this round); here: the host:port echo, the reply normalisation of the hostless twin, the
// URL-shaped runs of the data: decode rule, the control-URL gate, and what describe() lists. The toy servers are in r5-net.toys.test.ts.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SSRF_CORPUS, controlHostProblem, describe as describeNet, normaliseReply, outcomeOf, outsideUrls, refusalTier, stripUrl } from "../packs/net.js";

const call = (o: Partial<{ isError: boolean; text: string; rpcError: string; timedOut: boolean; closed: boolean }>) => ({ isError: false, text: "", elapsedMs: 1, timedOut: false, closed: false, ...o });
const err = (text: string) => call({ isError: true, text });
const URL_PROBE = "http://127.0.0.1:4000/t/sm-abc123abc123";

describe("r5 net: stripUrl removes the host:port echo of the listener", () => {
  it("every corpus spelling with the port, bracketed and percent-encoded, is removed; the bare host is not", () => {
    for (const host of ["127.0.0.1", "localhost", "[::1]", "127.1", "0x7f000001", "2130706433", "0.0.0.0", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]"]) {
      const out = stripUrl(`Request for ${host}:4000 failed; also ${encodeURIComponent(`${host}:4000`)} and ${host} alone`, "http://other/", [4000]);
      assert.doesNotMatch(out, /:4000/, host);
      assert.doesNotMatch(out, /%3A4000/i, host);
      assert.ok(out.includes(`${host} alone`), `the bare ${host} stays`);
    }
  });
  it("the probe URL's own parsed host and port are removed without being told the ports", () => {
    const out = stripUrl("bad host [::ffff:7f00:1]:4000 and 127.0.0.1:4000", "http://[::ffff:127.0.0.1]:4000/t/x");
    assert.doesNotMatch(out, /:4000/);
  });
  it("a port that is not the listener's is left alone", () => {
    assert.ok(stripUrl("the service at 127.0.0.1:9999 is down", URL_PROBE, [4000]).includes("127.0.0.1:9999"));
  });
  it("an echo of the parsed host with the port is a failure report, not a validation error naming the address", () => {
    const text = "Request for 127.0.0.1:4000 refused: invalid";
    assert.equal(outcomeOf(err(text), URL_PROBE, [4000]), "failed");
    assert.equal(outcomeOf(err("Request for [::ffff:7f00:1]:4000 failed: access restricted"), "http://[::ffff:127.0.0.1]:4000/t/x", [4000]), "failed");
  });
  it("without the veto, the address tier still needs a refusal word and the address", () => {
    assert.deepEqual(refusalTier(err("Bad request for 127.0.0.1"), URL_PROBE, [4000]), { outcome: "refused", tier: "validation error naming the address" });
  });
});

describe("r5 net: normaliseReply (the hostless twin's comparison)", () => {
  const n = (text: string, url: string, token: string) => normaliseReply(call({ isError: true, text }), url, token, [4000]);
  it("removes the probe URL, the listener host:port, the token, the probe's own host, whitespace and case", () => {
    const token = "sm-0123456789ab";
    const a = n(`Refused:   http://127.0.0.1:4000/t/${token} is a LOOPBACK address\nand 127.0.0.1:4000 too`, `http://127.0.0.1:4000/t/${token}`, token);
    const t2 = "sm-ba9876543210";
    const b = n(`refused: data:text/plain,${t2} is a loopback address and too`, `data:text/plain,${t2}`, t2);
    assert.equal(a, b);
    assert.equal(a, "refused: is a loopback address and too");
  });
  it("a reply that echoes the parsed host differs from a hostless reply only by that host, which is removed", () => {
    const a = n("refused: 127.0.0.1 is not allowed", "http://127.0.0.1:4000/t/sm-111111111111", "sm-111111111111");
    const b = n("refused:  is not allowed", "data:text/plain,sm-222222222222", "sm-222222222222");
    assert.equal(a, b);
  });
  it("different sentences stay different: a scheme sentence is not a loopback sentence", () => {
    const a = n("blocked: 127.0.0.1 is a loopback address (not allowed)", "http://127.0.0.1:4000/t/sm-111111111111", "sm-111111111111");
    const b = n("blocked: scheme data: is not allowed (only http and https)", "data:text/plain,sm-222222222222", "sm-222222222222");
    assert.notEqual(a, b);
  });
  it("it reads the full reply and the JSON-RPC error text, never an excerpt", () => {
    const long = "x".repeat(400);
    assert.notEqual(n(`${long} one`, URL_PROBE, "sm-abc123abc123"), n(`${long} two`, URL_PROBE, "sm-abc123abc123"));
    assert.match(normaliseReply(call({ rpcError: "MCP error -32602: Bad URL" }), URL_PROBE, "sm-abc123abc123", [4000]), /bad url/);
  });
});

describe("r5 net: a data: probe counts as decoded only outside URL-shaped runs", () => {
  const token = "sm-0123456789ab";
  it("an echo inside a percent-encoded slug or an https URL is not content", () => {
    assert.equal(outsideUrls(`searched for text%2Fplain%2C${token} (page 1)`).includes(token), false);
    assert.equal(outsideUrls(`see https://search.example/q/${token} for more`).includes(token), false);
    assert.equal(outsideUrls(`https://search.example/q?x=1 ${token}`).includes(token), true, "a token after the URL is outside it");
  });
  it("the decoded content on its own is outside any URL", () => {
    assert.equal(outsideUrls(`HTTP 200\n${token}`).includes(token), true);
    assert.equal(outsideUrls(`${token}`).includes(token), true);
  });
});

describe("r5 net: net.control_url may not name a host the harness owns or a private range", () => {
  const refused = ["localhost", "app.localhost", "127.0.0.1", "127.8.9.1", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "[::1]", "::", "[::ffff:7f00:1]", "[::ffff:127.0.0.1]", "[::ffff:a00:1]", "fd00::1", "fe80::1"];
  for (const h of refused) it(`${h} is refused`, () => assert.ok(controlHostProblem(h), h));
  const allowed = ["example.com", "93.184.216.34", "172.32.0.1", "172.15.0.1", "100.63.0.1", "[2606:4700::1111]", "8.8.8.8"];
  for (const h of allowed) it(`${h} is allowed`, () => assert.equal(controlHostProblem(h), undefined, h));
});

describe("r5 net: describe()", () => {
  const doc = describeNet().find((d) => d.id === "net-loopback-ssrf")!;
  it("lists the twin probe as a control probe, and both phrase families with the twin rule in the limits", () => {
    const twin = doc.probes.find((p) => p.id === "twin");
    assert.equal(twin?.kind, "control");
    assert.match(twin!.text, /data: URL with no host/);
    assert.equal(doc.probes.length, SSRF_CORPUS.length + 1);
    assert.match(doc.falsePositive, /The rule:/);
    assert.match(doc.falsePositive, /The address class:/);
    assert.match(doc.falsePositive, /names the tier that decided/);
  });
  it("says that a refuse-everything tool whose hostless reply differs passes on text, and names the control URL as the way to show a fetch", () => {
    assert.match(doc.falseNegative, /refuse-everything tool whose reply to the hostless URL differs from its loopback refusals passes on text/);
    assert.match(doc.falseNegative, /net\.control_url/);
    assert.match(doc.falseNegative, /refused to connect/);
  });
  it("net-scheme-allowlist and net-redirect describe the honesty rules", () => {
    const scheme = describeNet().find((d) => d.id === "net-scheme-allowlist")!;
    assert.match(scheme.falseNegative, /refused for its scheme or a tool shown to fetch/);
    assert.match(scheme.falseNegative, /outside any URL-shaped text/);
    const redirect = describeNet().find((d) => d.id === "net-redirect")!;
    assert.match(redirect.falseNegative, /re-validation cannot be measured and the check is inconclusive/);
    assert.match(redirect.probes.find((p) => p.id === "hop")!.text, /http:\/\/\[::1\]:<port6>/);
  });
});
