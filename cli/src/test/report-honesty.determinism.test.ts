import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderJson, renderReport, renderText } from "../report.js";
import { makeRunNormaliser, redactResult } from "../report/redact.js";
import type { CheckResult, RunResult } from "../types.js";

/** One run of a toy server, with the per-run parts (port, tokens) as parameters, the way two real runs differ. */
function run(port: number, hex: (n: number) => string, o: { kept?: boolean } = {}): RunResult {
  const sb = "/tmp/sealmark-sb-" + hex(6);
  const url = `http://127.0.0.1:${port}/t/sm-${hex(12)}`;
  const checks: CheckResult[] = [
    {
      id: "net-loopback-ssrf",
      pack: "net",
      label: "Fetch refuses loopback",
      critical: true,
      scope: "server (address validation)",
      verdict: "fail",
      summary: `fetched ${url}`,
      evidence: [
        { probe: `fetch ${url}`, outcome: `the listener at 127.0.0.1:${port} and [::1]:${port} was hit with sm-${hex(12)}`, verifiedBy: "listener", tool: "fetch", args: { url, note: `ann-sm-${hex(12)}.txt` } },
        { probe: `write ${sb}/root/ann-sm-${hex(12)}.txt`, outcome: `control sm-ctl-${hex(8)} and sm-ctl-${hex(12)}, git sm-root-${hex(12)} sm-canary-${hex(12)} sm-evil-${hex(12)}`, verifiedBy: "fs-observer", tool: "write" },
        { probe: `sqlite alias sm_s_${hex(6)} VACUUM INTO '${sb}/canary/vac-${hex(6)}.db' ATTACH '${sb}/canary/att-${hex(6)}.db'`, outcome: `--output=pwned-${hex(12)}.txt; program sm-canary and sm-echo ran; another server's port 9999`, verifiedBy: "fs-observer" },
      ],
    },
  ];
  return {
    sealmark: { version: "0.2.1", methodology: "0.2-draft" },
    server: { name: "Toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["fetch"], sqlTools: [] },
    options: { packsRequested: ["core", "net"], timeoutProbeSec: 10, sandbox: true },
    startedAt: `2026-10-12T00:00:0${port % 10}.000Z`,
    durationMs: 1000 + port,
    packs: { net: { status: "graded", grade: { pack: "net", points: 0, scored: 1, pct: 0, raw: "F", letter: "F", capped: true, criticalFails: ["net-loopback-ssrf"], provisional: false, excluded: [] } } },
    checks,
    notCovered: [],
    sandbox: { dir: sb, envMode: "scrubbed", listenerPort: port, cleanedUp: !o.kept, kept: o.kept ?? false, leftoverProcesses: [], active: false, enabled: true },
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
  };
}

/** A deterministic hex source, different for every `seed`. */
const hexOf = (seed: number) => {
  let i = seed * 7919;
  return (n: number) => Array.from({ length: n }, () => "0123456789abcdef"[(i = (i * 31 + 17) % 9973) % 16]).join("");
};
const a = () => run(41234, hexOf(1));
const b = () => run(50987, hexOf(2));

describe("the redacted report is the same for two runs that differ in port and tokens", () => {
  it("the inputs really differ", () => {
    assert.notEqual(JSON.stringify(a()), JSON.stringify(b()));
  });

  it("markdown (verbose, with every evidence line) is byte-identical", () => {
    const x = renderReport("markdown", [a()], { verbosity: "verbose" });
    const y = renderReport("markdown", [b()], { verbosity: "verbose" });
    assert.equal(x, y);
    assert.match(x, /listener 127\.0\.0\.1:\{listener_port\}/);
    assert.match(x, /\{token\}/);
  });

  it("text (verbose) is byte-identical too: the sandbox line says {listener_port}, not the real port", () => {
    const x = renderText(a(), { verbosity: "verbose" });
    const y = renderText(b(), { verbosity: "verbose" });
    assert.equal(x, y);
    assert.match(x, /listener 127\.0\.0\.1:\{listener_port\}/);
    assert.ok(!x.includes("41234"), "the real port never reaches the redacted text");
  });

  it("the JSON evidence is identical; only the numeric port field and the timestamps differ", () => {
    const strip = (r: RunResult) => ({ ...r, startedAt: "", durationMs: 0, sandbox: { ...r.sandbox!, dir: "", listenerPort: 0 } });
    assert.deepEqual(strip(JSON.parse(renderJson(a())) as RunResult), strip(JSON.parse(renderJson(b())) as RunResult));
  });

  it("every token family is rewritten to a stable name", () => {
    const text = renderReport("markdown", [a()], { verbosity: "verbose" });
    for (const want of ["{listener_port}", "{token}", "{ctl}", "{token:root}", "{token:canary}", "{token:evil}", "{alias}", "pwned-{token}", "vac-{token}", "att-{token}", "ann-{token}"]) {
      assert.ok(text.includes(want), `${want} appears`);
    }
    assert.ok(!/sm-[0-9a-f]{12}|sm-ctl-[0-9a-f]|sm_s_[0-9a-f]|pwned-[0-9a-f]|(vac|att)-[0-9a-f]{6}/.test(text), "no raw token is left");
  });

  it("only this run's shapes are rewritten: program names, other ports and short words stay", () => {
    const text = renderReport("markdown", [a()], { verbosity: "verbose" });
    assert.match(text, /program sm-canary and sm-echo ran/);
    assert.match(text, /another server's port 9999/);
    const norm = makeRunNormaliser(41234);
    assert.equal(norm("sm-canary"), "sm-canary");
    assert.equal(norm("sm-abc"), "sm-abc");
    assert.equal(norm("xsm-0123456789ab"), "xsm-0123456789ab");
    assert.equal(norm("sm-0123456789abc"), "sm-0123456789abc", "a longer hex run is not one of ours");
    assert.equal(norm("127.0.0.1:412345"), "127.0.0.1:412345", "a longer port is another port");
    assert.equal(norm("127.0.0.1:41234"), "127.0.0.1:{listener_port}");
    assert.equal(norm("http://localhost:41234/x"), "http://localhost:{listener_port}/x");
    assert.equal(makeRunNormaliser(undefined)("127.0.0.1:41234"), "127.0.0.1:41234");
  });
});

describe("--no-redact and a kept sandbox keep the real values", () => {
  it("--no-redact leaves the port and the tokens as they were, in every format", () => {
    const r = a();
    const md = renderReport("markdown", [r], { verbosity: "verbose", redact: false });
    assert.match(md, /listener 127\.0\.0\.1:41234/);
    assert.match(md, /sm-[0-9a-f]{12}/);
    assert.ok(!md.includes("{token}"));
    assert.equal(redactResult(r, { redact: false }), r);
    const text = renderText(r, { verbosity: "verbose", redact: false });
    assert.match(text, /sm-[0-9a-f]{12}/);
    assert.match(text, /listener 127\.0\.0\.1:41234/);
    assert.ok(!text.includes("{listener_port}"));
  });

  it("a kept sandbox is one the reader will open: its tokens and port stay", () => {
    const r = run(41234, hexOf(1), { kept: true });
    const md = renderReport("markdown", [r], { verbosity: "verbose" });
    assert.match(md, /listener 127\.0\.0\.1:41234/);
    assert.match(md, /sm-[0-9a-f]{12}/);
    assert.match(renderText(r, { verbosity: "verbose" }), /listener 127\.0\.0\.1:41234/);
  });
});
