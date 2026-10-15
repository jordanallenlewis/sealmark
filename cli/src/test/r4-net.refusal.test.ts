// Round 4, package net (updated in round 5, G1: the refusal model splits its strong phrases into the rule family and the address-class family, and a transport verb is no refusal): the tiered refusal model (A1), the corpus (A2, A5), the fillers and the secondary class (B1, B2, B3). Pure
// functions only; the toy servers are exercised by r4-net.toys.test.ts.
import assert from "node:assert/strict";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it } from "node:test";
import { classifyTools, coreOnlyHint, coreOnlyNotes, classificationBlock, fillArgs, packsFor, secondaryUrlParam } from "../classify.js";
import type { ToolInfo } from "../mcp.js";
import { CLASS_NOUN, FAILURE_VETO, RULE_PHRASE, SCHEME_CORPUS, SSRF_CORPUS, buildProbes, describe as describeNet, outcomeOf, refusalTier } from "../packs/net.js";
import type { ToolClassification } from "../types.js";

const call = (o: Partial<{ isError: boolean; text: string; rpcError: string; timedOut: boolean; closed: boolean }>) => ({ isError: false, text: "", elapsedMs: 1, timedOut: false, closed: false, ...o });
const URL_PROBE = "http://localhost:4000/t/sm-abc";
const err = (text: string) => call({ isError: true, text });

describe("net refusal model: the rule family and the address-class family (round 5)", () => {
  const rules = [
    "SSRF protection",
    "unsafe destination",
    "unsafe host",
    "unsafe target",
    "unsafe URL",
    "unsafe address",
    "the host resolves to 10.0.0.5",
    "the host resolves to ::1",
    "the host resolves to a non-public address",
    "only https URLs are allowed",
    "only public hosts are permitted",
    "only http and https are supported",
    "Only public hosts may be fetched.",
    "only allowed domains may be fetched",
    "request denied by egress policy",
    "egress rule violated",
    "request failed validation",
    "validation failed for the URL",
    "unsupported scheme",
    "invalid scheme",
    "unknown protocol",
    "disallowed URL scheme",
    "Unsupported URI scheme",
    "scheme file: is not accepted",
    "supported schemes are http and https",
    "https only",
  ];
  for (const text of rules) {
    it(`"${text}" is a refusal that names the rule`, () => {
      assert.equal(RULE_PHRASE.test(text), true);
      assert.deepEqual(refusalTier(err(text), URL_PROBE), { outcome: "refused", tier: "names the rule" });
    });
  }
  const classes = [
    "loopback addresses are not reachable",
    "link-local addresses are not reachable",
    "private address",
    "private IP",
    "private range",
    "private network",
    "private host",
    "private subnet",
    "internal address",
    "internal IP",
    "internal host",
    "internal network",
    "internal URL",
    "internal resource",
    "internal target",
    "internal service",
    "reserved address",
    "reserved IP",
    "reserved range",
    "the target is non-routable",
    "the target is not routable",
    "non routable network",
    "not a public address",
    "not public",
    "non-public",
    "Fetching local network resources is not supported.",
    "local address",
    "local host",
    "public domains only",
    "metadata endpoint",
    "metadata service",
  ];
  for (const text of classes) {
    it(`"${text}" is a refusal that names the address class`, () => {
      assert.equal(CLASS_NOUN.test(text) || RULE_PHRASE.test(text), true);
      const t = refusalTier(err(text), URL_PROBE);
      assert.equal(t.outcome, "refused");
      assert.match(t.tier ?? "", /^names the (address class|rule)$/);
    });
  }
  it("a rule phrase wins over a failure word, a class noun wins only in a clause that refuses", () => {
    assert.equal(outcomeOf(err("connections to a private address are not allowed"), URL_PROBE), "refused");
    assert.equal(outcomeOf(err("proxy: loopback targets are not allowed"), URL_PROBE), "refused");
    assert.equal(outcomeOf(err("timed out resolving: the host resolves to 127.0.0.1"), URL_PROBE), "refused");
    assert.equal(outcomeOf(err("Request to a private address failed validation"), URL_PROBE), "refused");
    assert.equal(refusalTier(err("Request to a private address failed validation"), URL_PROBE).tier, "names the rule");
    assert.equal(outcomeOf(err("Failed to fetch: host resolves to a non-public address"), URL_PROBE), "refused");
  });
  it("the near misses of the phrases are not phrases", () => {
    for (const text of ["internal service error", "internal server error", "the proxy is not publicly reachable", "the mirror resolves to a stale cache entry", "resolves to no address", "a private matter"]) {
      assert.equal(RULE_PHRASE.test(text) || CLASS_NOUN.test(text), false, text);
    }
  });
});

describe("net refusal model: the sixteen wordings of the round-5 verification", () => {
  const wordings: [string, "refused" | "failed", string | undefined][] = [
    ["Failed to fetch <URL>: the sandbox refused to connect", "failed", undefined],
    ["127.0.0.1 refused to connect", "failed", undefined],
    ["Failed to connect to loopback interface: ECONNREFUSED", "failed", undefined],
    ["Request failed: private network unreachable", "failed", undefined],
    ["Connection to internal resource timed out", "failed", undefined],
    ["Request for 127.0.0.1 failed: access restricted", "failed", undefined],
    ["Only public hosts may be fetched.", "refused", "names the rule"],
    ["Fetching local network resources is not supported.", "refused", "names the address class"],
    ["Request denied by egress policy.", "refused", "names the rule"],
    ["This tool cannot access localhost.", "refused", "validation error naming the address"],
    ["Failed to fetch: host resolves to a non-public address", "refused", "names the rule"],
    ["Unsupported URI scheme", "refused", "names the rule"],
    ["Request to a private address failed validation", "refused", "names the rule"],
    ["network access is restricted", "failed", undefined],
    ["fetch failed", "failed", undefined],
    ["Invalid URL", "failed", undefined],
  ];
  for (const [text, outcome, tier] of wordings) {
    it(`"${text}" is ${outcome}${tier ? ` (${tier})` : ""}`, () => {
      const t = refusalTier(err(text.replace("<URL>", URL_PROBE)), URL_PROBE);
      assert.equal(t.outcome, outcome);
      assert.equal(t.tier, tier);
    });
  }
  it("a transport verb is no refusal: 'refused to connect' is a failure, 'refused to fetch' needs a word for the target", () => {
    assert.equal(outcomeOf(err("refused to connect"), URL_PROBE), "failed");
    assert.equal(outcomeOf(err("refused to fetch"), URL_PROBE), "failed");
    assert.equal(outcomeOf(err("refused to request"), URL_PROBE), "failed");
    assert.equal(refusalTier(err("refused to fetch the target"), URL_PROBE).tier, "refusal tied to the host");
  });
  it("cannot access / won't fetch are refusal words that need a word for the target or the loopback address", () => {
    assert.deepEqual(refusalTier(err("This tool cannot access that host."), URL_PROBE), { outcome: "refused", tier: "refusal tied to the host" });
    assert.deepEqual(refusalTier(err("I can't fetch that URL"), URL_PROBE), { outcome: "refused", tier: "refusal tied to the host" });
    assert.deepEqual(refusalTier(err("won't fetch that address"), URL_PROBE), { outcome: "refused", tier: "refusal tied to the host" });
    assert.equal(outcomeOf(err("cannot access"), URL_PROBE), "failed");
  });
  it("the listener host:port is stripped from the reply before the address tier", () => {
    for (const host of ["127.0.0.1", "localhost", "[::1]", "[::ffff:127.0.0.1]", "0.0.0.0"]) {
      const text = `Request for ${host}:4000 failed: access restricted`;
      assert.equal(outcomeOf(err(text), URL_PROBE, [4000]), "failed", text);
    }
    assert.equal(outcomeOf(err("Request for 127.0.0.1:4000 refused: invalid"), URL_PROBE, [4000]), "failed", "the echo no longer names the address");
    assert.equal(outcomeOf(err("blocked: 127.0.0.1 is not allowed"), URL_PROBE, [4000]), "refused", "a bare host is not stripped");
  });
});

describe("net refusal model: tier 4, the failure veto", () => {
  const vetoed = [
    "ECONNREFUSED 127.0.0.1:4000",
    "ECONNRESET",
    "ENETUNREACH",
    "ENETDOWN",
    "EHOSTUNREACH",
    "ETIMEDOUT",
    "EAI_AGAIN",
    "ENOTFOUND",
    "connection refused",
    "connection reset by peer",
    "connection closed",
    "connection failed",
    "connection error",
    "connection aborted",
    "connection blocked by proxy",
    "network is unreachable",
    "network unreachable",
    "host is unreachable",
    "host unreachable",
    "request timed out",
    "timeout while fetching",
    "read time out",
    "bad proxy configuration",
    "socket hang up",
    "dns lookup failed",
    "name resolution failed",
    "getaddrinfo failed",
    "certificate has expired",
    "TLS handshake failed",
    "SSL error",
    "Failed to fetch the page",
    "download failed",
    "refused to connect",
    "could not connect",
    "unreachable",
  ];
  for (const text of vetoed) {
    it(`"${text}" is a failure, whatever else it says`, () => {
      assert.equal(FAILURE_VETO.test(text), true);
      assert.equal(outcomeOf(err(`${text}: the URL is blocked`), URL_PROBE), "failed");
      assert.equal(outcomeOf(err(text), URL_PROBE), "failed");
    });
  }
  it("generic failures of a tool that cannot fetch are not refusals", () => {
    for (const text of ["connection blocked by proxy", "network access is restricted in this environment", "network is unreachable", "fetch failed", "request failed", "access denied", "blocked", "restricted", "forbidden", "Invalid URL", "invalid request"]) {
      assert.equal(outcomeOf(err(text), URL_PROBE), "failed", text);
    }
  });
});

describe("net refusal model: tier 5, a refusal word with a word for the target", () => {
  const words = ["blocked", "not allowed", "not permitted", "forbidden", "disallowed", "prohibited", "denied", "rejected", "refused", "restricted", "unsafe"];
  const nouns = ["host", "hostname", "address", "destination", "target", "URL", "domain", "IP", "origin", "site"];
  it("every refusal word next to every target noun is a refusal tied to the host", () => {
    for (const w of words) for (const n of nouns) assert.deepEqual(refusalTier(err(`this ${n} is ${w}`), URL_PROBE), { outcome: "refused", tier: "refusal tied to the host" }, `${n} ${w}`);
  });
  it("a refusal word alone, or a noun alone, is not enough", () => {
    for (const w of words) assert.equal(outcomeOf(err(`it is ${w}`), URL_PROBE), "failed", w);
    for (const n of nouns) assert.equal(outcomeOf(err(`the ${n} is fine`), URL_PROBE), "failed", n);
  });
  it("the noun must be a whole word: localhost is not a host, the address rule (tier 6) decides it", () => {
    assert.equal(outcomeOf(err("localhost is blocked"), URL_PROBE), "refused");
    assert.equal(refusalTier(err("localhost is blocked"), URL_PROBE).tier, "validation error naming the address");
    assert.equal(outcomeOf(err("blocked by the ghostwriter"), URL_PROBE), "failed");
  });
  it("only the first 300 characters are read for the words", () => {
    assert.equal(outcomeOf(err(`${"x".repeat(310)} the URL is blocked`), URL_PROBE), "failed");
  });
  it("the plain-text refusal that never set isError counts the same", () => {
    assert.equal(outcomeOf(call({ text: "Error: URL host is not allowed" }), URL_PROBE), "refused");
  });
});

describe("net refusal model: tier 6, a validation error that names the address", () => {
  it("a JSON-RPC invalid-params error that names the address is a refusal, with or without a word", () => {
    assert.deepEqual(refusalTier(call({ rpcError: "MCP error -32602: address 127.0.0.1 is not accepted" }), URL_PROBE), { outcome: "refused", tier: "validation error naming the address" });
    assert.equal(outcomeOf(call({ rpcError: "MCP error -32602: Invalid params: [::1] is not an accepted address" }), URL_PROBE), "refused");
    assert.equal(outcomeOf(call({ rpcError: "MCP error -32602: 0.0.0.0 is not valid here" }), URL_PROBE), "refused");
    assert.equal(outcomeOf(call({ rpcError: "MCP error -32602: [::ffff:7f00:1] is not valid here" }), URL_PROBE), "refused");
  });
  it("an isError reply that names the address and says invalid, bad request or a refusal word is a refusal", () => {
    assert.deepEqual(refusalTier(err("Bad request for 127.0.0.1"), URL_PROBE), { outcome: "refused", tier: "validation error naming the address" });
    assert.equal(outcomeOf(err("Invalid host: 127.0.0.1"), URL_PROBE), "refused");
    assert.equal(outcomeOf(err("blocked: localhost is not allowed"), URL_PROBE), "refused");
    assert.equal(outcomeOf(err("[::ffff:7f00:1] was rejected"), URL_PROBE), "refused");
  });
  it("it never turns a failed connection into a refusal", () => {
    for (const text of ["connect to 127.0.0.1:4000 failed", "fetch failed: connect ECONNREFUSED 127.0.0.1:4000", "Bad request: timed out talking to 127.0.0.1", "invalid response from the proxy at 127.0.0.1", "127.0.0.1 did not answer"]) {
      assert.equal(outcomeOf(err(text), URL_PROBE), "failed", text);
    }
  });
  it("it needs the address, and for a protocol error the code -32602", () => {
    assert.equal(outcomeOf(call({ rpcError: "MCP error -32602: url must be a string" }), URL_PROBE), "failed");
    assert.equal(outcomeOf(call({ rpcError: "MCP error -32603: address 127.0.0.1 is not accepted", isError: false }), URL_PROBE), "failed");
    assert.equal(outcomeOf(err("address 127.0.0.1 is not accepted"), URL_PROBE), "failed");
    assert.equal(outcomeOf(err(`Bad request for ${URL_PROBE}`), URL_PROBE), "failed", "the probe URL itself is removed first");
  });
});

describe("net refusal model: the first two tiers", () => {
  it("answered, timed out and closed", () => {
    assert.equal(outcomeOf(call({ text: "HTTP 200 ok" }), URL_PROBE), "answered");
    assert.equal(outcomeOf(call({ timedOut: true, isError: true, text: "loopback is not allowed" }), URL_PROBE), "failed");
    assert.equal(outcomeOf(call({ closed: true, isError: true, text: "loopback is not allowed" }), URL_PROBE), "failed");
  });
});

describe("net corpus: the IPv4-mapped spelling and the tokens", () => {
  const sandboxDir = join(tmpdir(), "sealmark-fake");
  const o = { port: 5555, port6: 5556, canaryDir: join(sandboxDir, "canary"), canaryFile: join(sandboxDir, "canary", "secret.txt"), sandboxDir, allowDns: false, remove: [], add: [] };
  it("the SSRF corpus has the IPv4-mapped entry after unspecified, sent to the IPv4 listener port, and the safety gate accepts it", () => {
    const ids = SSRF_CORPUS.map((e) => e.id);
    assert.equal(ids[ids.indexOf("unspecified") + 1], "ipv4-mapped");
    const e = SSRF_CORPUS.find((x) => x.id === "ipv4-mapped")!;
    assert.equal(e.template, "http://[::ffff:127.0.0.1]:{port}/t/{token}");
    assert.equal(e.needs, undefined);
    const p = buildProbes(SSRF_CORPUS, o).find((x) => x.id === "ipv4-mapped")!;
    assert.equal(p.skipped, undefined);
    assert.match(p.url, /^http:\/\/\[::ffff:127\.0\.0\.1\]:5555\/t\/sm-[0-9a-f]{12}$/);
  });
  it("nine probes are built without DNS and the check documents every one of them, and the hostless twin", () => {
    assert.equal(buildProbes(SSRF_CORPUS, o).length, 9);
    const probes = describeNet().find((d) => d.id === "net-loopback-ssrf")!.probes;
    assert.equal(probes.length, SSRF_CORPUS.length + 1);
    assert.ok(probes.some((p) => p.id === "twin" && p.kind === "control" && /data: URL with no host/.test(p.text)));
    assert.ok(probes.some((p) => p.id === "ipv4-mapped" && /IPv4-mapped/.test(p.text)));
  });
  it("no scheme probe carries a doubled sm- token", () => {
    for (const p of buildProbes(SCHEME_CORPUS, o)) {
      assert.doesNotMatch(p.url, /sm-sm-|sm-data-/, p.id);
      assert.equal(p.skipped, undefined, p.id);
    }
    assert.match(buildProbes(SCHEME_CORPUS, o).find((p) => p.id === "data")!.url, /^data:text\/plain,sm-[0-9a-f]{12}$/);
    assert.match(buildProbes(SCHEME_CORPUS, o).find((p) => p.id === "gopher")!.url, /\/_sm-[0-9a-f]{12}$/);
  });
  it("net-caps documents the longer-server-timeout false positive", () => {
    assert.match(describeNet().find((d) => d.id === "net-caps")!.falsePositive, /timeout_probe_sec \+ 8 s fails the time half although it does cap: set --timeout-probe/);
  });
});

const tool = (name: string, properties: Record<string, unknown>, required: string[], description = ""): ToolInfo => ({ name, description, inputSchema: { type: "object", properties, required } }) as ToolInfo;
const classify = (...tools: ToolInfo[]) => classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;

describe("fillArgs: a boolean in a union is filled with false (B2)", () => {
  it("a required boolean-or-string parameter gets false, not a token", () => {
    const t = tool("fetch_page", { url: { type: "string", format: "uri" }, next: { type: ["boolean", "string"] } }, ["url", "next"], "Fetch a web page");
    const c = classify(t)[0]!;
    assert.deepEqual(fillArgs(t, c, { url: "http://x/" }, "sm-tok"), { url: "http://x/", next: false });
  });
  it("anyOf unions too, and a plain string, an enum and a default are unchanged", () => {
    const t = tool(
      "fetch_page",
      { url: { type: "string" }, a: { anyOf: [{ type: "string" }, { type: "boolean" }] }, b: { type: "string" }, c: { type: ["boolean", "string"], default: "keep" }, d: { enum: ["x", "y"] } },
      ["url", "a", "b", "c", "d"],
      "Fetch a web page",
    );
    const c = classify(t)[0]!;
    assert.deepEqual(fillArgs(t, c, { url: "http://x/" }, "sm-tok"), { url: "http://x/", a: false, b: "sm-tok", c: "keep", d: "x" });
  });
  it("the classification does not change: the union is still a string for the class tables", () => {
    const c = classify(tool("fetch_page", { url: { type: "string" }, next: { type: ["boolean", "string"] } }, ["url"], "Fetch a web page"))[0]!;
    assert.equal(c.class, "url");
  });
});

describe("a secondary url class is probed by the net pack (B1)", () => {
  const ambig = () => tool("fetch_file", { path: { type: "string", description: "Where to save" }, url: { type: "string", format: "uri" } }, ["path", "url"], "Downloads a file from a URL and saves it to a path.");
  it("fetch_file(path, url format uri) is a path tool with a secondary url class, and its net parameter is url", () => {
    const c = classify(ambig())[0]!;
    assert.equal(c.class, "path");
    assert.deepEqual(c.secondary, ["url"]);
    assert.equal(c.secondaryParams?.url?.url, "url");
    assert.equal(secondaryUrlParam(c), "url");
    assert.deepEqual(packsFor(c, { active: false, sandboxEnabled: true }), ["fs", "effects", "net"]);
    assert.deepEqual(packsFor(c, { active: false, sandboxEnabled: false }), ["net"]);
    assert.ok(c.reasons.includes("secondary: url (probed by net)"));
    assert.match(classificationBlock([c]).join("\n"), /secondary: url \(probed by net\)/);
  });
  it("the harness's url goes in the url slot and the path slot gets a token", () => {
    const t = ambig();
    const c = classify(t)[0]!;
    const asUrl = { ...c, class: "url" as const, params: { ...c.params, url: secondaryUrlParam(c)! } };
    assert.deepEqual(fillArgs(t, asUrl, { url: "http://127.0.0.1:1/t/x" }, "sm-tok"), { path: "sm-tok", url: "http://127.0.0.1:1/t/x" });
  });
  it("near miss: a path tool whose other parameter is no URL has no secondary class and no net pack", () => {
    const c = classify(tool("save_report", { path: { type: "string" }, title: { type: "string" } }, ["path", "title"], "Saves a report file to a path."))[0]!;
    assert.equal(c.secondary, undefined);
    assert.equal(secondaryUrlParam(c), undefined);
    assert.deepEqual(packsFor(c, { active: false, sandboxEnabled: true }), ["fs", "effects"]);
  });
  it("only url is consumed: a url tool with a path secondary gains nothing; a command or low-confidence tool is never probed through a URL", () => {
    const urlFirst = classify(tool("load_file_resource", { name: { type: "string" }, data: { type: "string", format: "uri" } }, ["name", "data"], "Loads a remote file resource."))[0]!;
    assert.equal(urlFirst.class, "url");
    assert.deepEqual(packsFor(urlFirst, { active: false, sandboxEnabled: true }), ["net", "effects"]);
    const cmd = classify(tool("run_command", { command: { type: "string" }, url: { type: "string", format: "uri" } }, ["command", "url"], "Run a shell command"))[0]!;
    assert.equal(cmd.class, "command");
    assert.equal(secondaryUrlParam(cmd), undefined);
    assert.equal(packsFor(cmd, { active: false, sandboxEnabled: true }).includes("net"), false);
  });
  it("an excluded or overridden tool is not probed through a secondary class", () => {
    const t = ambig();
    const excluded = classifyTools({ tools: [t], overrides: {}, include: ["*"], exclude: ["fetch_*"] }).classification[0]!;
    assert.equal(secondaryUrlParam(excluded), undefined);
    const overridden = classifyTools({ tools: [t], overrides: { fetch_file: { class: "path" } }, include: ["*"], exclude: [] }).classification[0]!;
    assert.equal(secondaryUrlParam(overridden), undefined);
  });
});

describe("the hint for a tool only the core checks reach (B3)", () => {
  const row = (over: Partial<ToolClassification>): ToolClassification => ({ tool: "t", class: "text", confidence: "low", params: {}, unfillable: [], reasons: ["string parameters only"], ...over });
  it("a low-confidence heuristic reading keeps the hint report.test.ts pins", () => {
    assert.equal(coreOnlyHint(row({})), "add it under tools: to include it");
    assert.match(coreOnlyNotes([row({})])[0]!, /; add it under tools: to include it$/);
    assert.match(classificationBlock([row({})]).join("\n"), /core only: string parameters only; add it under tools: to include it/);
  });
  it("a tool excluded by tools.exclude keeps it too: putting it under tools: is the fix", () => {
    const x = row({ class: "opaque", confidence: "explicit", reasons: ["excluded by tools.exclude (t)"], excluded: true, source: "override" });
    assert.equal(coreOnlyHint(x), "add it under tools: to include it");
  });
  it("an overridden tool is told to write a probes: entry, not to add it under tools:", () => {
    const o = row({ class: "text", confidence: "explicit", reasons: ["override: tools.overrides"], source: "override" });
    assert.equal(coreOnlyHint(o), "it is overridden to class text, which no pack probes; write a probes: entry to call it");
    assert.doesNotMatch(coreOnlyNotes([o])[0]!, /add it under tools/);
    assert.match(classificationBlock([o]).join("\n"), /overridden to class text/);
  });
  it("an unfillable tool names the parameters it cannot fill and says the same", () => {
    const u = row({ class: "text", confidence: "low", unfillable: ["options", "filters"], reasons: ["string parameters only"] });
    assert.equal(coreOnlyHint(u), 'its required parameters "options", "filters" cannot be filled by the harness; write a probes: entry to call it');
    const opaque = classify(tool("fetch_page", { url: { type: "string" }, options: { type: "object" } }, ["url", "options"], "Fetch a web page"))[0]!;
    assert.equal(opaque.class, "opaque");
    assert.match(coreOnlyNotes([opaque])[0]!, /cannot be filled by the harness; write a probes: entry to call it$/);
    assert.doesNotMatch(coreOnlyNotes([opaque])[0]!, /harness; its required/);
  });
});
