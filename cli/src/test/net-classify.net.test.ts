// The net pack on the toy servers of the net-classify package: classification by evidence strength, net-caps by bytes consumed,
// plain-language refusals, and data: URLs returned as a blob. Each defect toy has a near-miss that must keep its old verdict.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { gradePack } from "../grade.js";
import { McpSession } from "../mcp.js";
import { createSandbox, type Sandbox } from "../sandbox.js";
import { pack } from "../packs/net.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, PackCtx, ToolClassification, Verdict } from "../types.js";
import { quiet } from "./helpers.js";

const toy = (file: string) => fileURLToPath(new URL(`../toy/${file}.js`, import.meta.url));
const PROBE_SEC = 2;

interface Outcome {
  checks: CheckResult[];
  verdicts: Record<string, Verdict>;
  letter?: string;
  classification: ToolClassification[];
  sandbox: Sandbox;
}

let parent: string;
const out: Record<string, Outcome> = {};

async function runToy(name: string, file: string, args: string[]): Promise<Outcome> {
  const server = { command: process.execPath, args: [toy(file), ...args], env: {} as Record<string, string> };
  const sandbox = await createSandbox({ dir: parent, timeoutProbeSec: PROBE_SEC, log: quiet });
  const open = () => McpSession.open(server, { vars: {}, dsns: {} }, { cwd: sandbox.root, baseEnv: sandbox.env(), envMode: "scrubbed" });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const classification = classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;
  const ctx: PackCtx = {
    pack: "net",
    config: legacyEffectiveConfig({ config: { name, version: "0.0.1", server }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC }),
    tools,
    classification,
    sandbox,
    sandboxEnabled: true,
    open,
    active: false,
    timeoutProbeSec: PROBE_SEC,
    hangMs: 2000,
    log: quiet,
  };
  const applies = pack.applies(ctx);
  assert.equal(applies.ok, true, `${name}: ${applies.ok ? "" : applies.reason}`);
  const checks = await pack.run(ctx);
  const grade = gradePack("net", checks.filter((c) => c.id !== "net-redirect"));
  return { checks, verdicts: Object.fromEntries(checks.filter((c) => c.id !== "net-redirect").map((c) => [c.id, c.verdict])), letter: grade?.letter, classification, sandbox };
}

const check = (o: Outcome, id: string) => o.checks.find((c) => c.id === id)!;
const evidenceText = (o: Outcome, id: string) => check(o, id).evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");

describe("net-classify: net pack on the new toy servers", { timeout: 300_000 }, () => {
  before(async () => {
    parent = mkdtempSync(join(tmpdir(), "sealmark-net-classify-"));
    const jobs: Record<string, () => Promise<Outcome>> = {
      uriname: () => runToy("uriname", "classify-uriname", []),
      eat: () => runToy("eat", "net-bodyeater", ["--mode", "eat"]),
      cap: () => runToy("cap", "net-bodyeater", ["--mode", "cap"]),
      refuse: () => runToy("refuse", "net-plainrefuse", ["--mode", "refuse"]),
      rpc: () => runToy("rpc", "net-plainrefuse", ["--mode", "rpc"]),
      cannot: () => runToy("cannot", "net-plainrefuse", ["--mode", "cannot"]),
      nxdomain: () => runToy("nxdomain", "net-plainrefuse", ["--mode", "nxdomain"]),
      hostguard: () => runToy("hostguard", "net-plainrefuse", ["--mode", "hostguard"]),
      blob: () => runToy("blob", "net-datadecode", ["--mode", "blob"]),
      strict: () => runToy("strict", "net-datadecode", ["--mode", "strict"]),
      open: () => runToy("open", "net", ["--mode", "open"]),
    };
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (out[k] = await fn())));
  });

  after(async () => {
    for (const o of Object.values(out)) await o.sandbox.destroy().catch(() => {});
    rmSync(parent, { recursive: true, force: true });
  });

  it("classify-uriname: a format:uri parameter makes it a url tool (path secondary), and the net pack runs and passes the guards", () => {
    const o = out.uriname;
    const c = o.classification[0]!;
    assert.equal(c.class, "url");
    assert.equal(c.confidence, "medium");
    assert.deepEqual(c.secondary, ["path"]);
    assert.equal(c.params.url, "data");
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "pass", "net-caps": "na" });
    assert.equal(o.letter, "A");
    assert.match(check(o, "net-caps").summary, /the server refused loopback targets \(net-loopback-ssrf passed\)/);
  });

  it("net-bodyeater eat: reads the whole 64 MiB body and returns a small reply; the size half fails by bytes the listener served", () => {
    const o = out.eat;
    assert.equal(o.verdicts["net-loopback-ssrf"], "fail", "it fetches loopback, which is what lets net-caps measure it");
    const caps = check(o, "net-caps");
    assert.match(caps.summary, /size: the server read the whole 64 MiB body \(the listener sent 64 of 64 MiB\) and returned 0\.00 MiB/);
    assert.match(caps.summary, /time: replied after/);
    assert.equal(caps.verdict, "part", "size fails, time passes: half the points");
    assert.match(evidenceText(o, "net-caps"), /the listener sent 64 of 64 MiB, the whole body, and the server consumed all of it/);
    assert.ok(caps.evidence.every((e) => e.verifiedBy === "listener"));
  });

  it("near miss: the same fetcher with a genuine 1 MiB read cap, and the net toy's open mode, keep a size pass", () => {
    for (const k of ["cap", "open"]) {
      const caps = check(out[k], "net-caps");
      assert.match(caps.summary, /size: the reply was \d\.\d\d MiB \(limit 16 MiB\)/, k);
      assert.match(evidenceText(out[k], "net-caps"), /cut off by the client/, k);
    }
    assert.equal(check(out.cap, "net-caps").verdict, "pass");
  });

  it("net-plainrefuse: a refusal that never says 'loopback' (not a public address) earns the pass", () => {
    const o = out.refuse;
    assert.deepEqual(o.verdicts, { "net-loopback-ssrf": "pass", "net-scheme-allowlist": "pass", "net-caps": "na" });
    assert.match(check(o, "net-loopback-ssrf").summary, /explicitly refused/);
    const said = check(o, "net-loopback-ssrf").evidence.filter((e) => e.code === "net.ssrf-refused");
    assert.ok(said.length >= 7);
    for (const e of said) assert.doesNotMatch(e.outcome, /loopback|private|internal|blocked|forbidden|denied|restricted|not allowed/i);
    assert.equal(o.letter, "A");
  });

  it("net-plainrefuse rpc: a JSON-RPC invalid-params error that names the address is a refusal", () => {
    const o = out.rpc;
    assert.equal(o.verdicts["net-loopback-ssrf"], "pass");
    assert.match(evidenceText(o, "net-loopback-ssrf"), /MCP error -32602: address 127\.0\.0\.1 is not accepted/);
  });

  it("near miss: a tool that cannot fetch (ENETUNREACH, or a host name that resolves to nothing) stays inconclusive, never a pass", () => {
    for (const k of ["cannot", "nxdomain"]) {
      const o = out[k];
      assert.equal(o.verdicts["net-loopback-ssrf"], "inconclusive", k);
      assert.equal(o.verdicts["net-scheme-allowlist"], "inconclusive", k);
      assert.match(check(o, "net-loopback-ssrf").summary, /net\.control_url/, k);
      assert.notEqual(o.letter, "A", k);
      assert.match(check(o, "net-caps").summary, /net-loopback-ssrf was inconclusive/, k);
    }
  });

  it("net-datadecode: a data: URL decoded into a blob is accepted (scheme part); refusing data: like every other scheme passes", () => {
    const blob = out.blob;
    assert.equal(blob.verdicts["net-loopback-ssrf"], "pass");
    assert.equal(blob.verdicts["net-scheme-allowlist"], "part");
    assert.match(evidenceText(blob, "net-scheme-allowlist"), /the server decoded the data: URL and returned its content as a resource block/);
    assert.doesNotMatch(evidenceText(blob, "net-scheme-allowlist"), /not readable as text/, "the blob's bytes are compared now, not guessed from the marker");
    assert.match(check(blob, "net-scheme-allowlist").summary, /accepts data: URLs \(data\)/);
    const strict = out.strict;
    assert.equal(strict.verdicts["net-scheme-allowlist"], "pass");
  });

  it("a refusal that names no scheme is labelled as the host guard's, and does not make a scheme verdict it cannot back", () => {
    // net-datadecode refuses ftp: by scheme; net-plainrefuse hostguard refuses ftp://127.0.0.1 only because of the host.
    assert.match(evidenceText(out.strict, "net-scheme-allowlist"), /ftp: .*explicitly refused: blocked: scheme ftp: is not allowed/s);
    const o = out.hostguard;
    assert.equal(o.verdicts["net-loopback-ssrf"], "pass");
    assert.match(evidenceText(o, "net-scheme-allowlist"), /ftp: .*refused for another reason \(host guard, not the scheme\)/s);
    assert.equal(o.verdicts["net-scheme-allowlist"], "inconclusive", "file: and data: were never refused, so there is no positive evidence either way");
  });
});
