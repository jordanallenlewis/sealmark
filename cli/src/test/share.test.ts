import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { inflateRawSync } from "node:zlib";
import { LONG_LINK, MAX_FRAGMENT, VIEWER_URL, shareLink, shareView } from "../share.js";
import type { RunResult } from "../types.js";
import { CLI, hermeticEnv } from "./helpers.js";

/** A report the way `--format json` writes one, with fields the link must leave out (env, sandbox, args, excerpts). */
function run(over: Record<string, unknown> = {}): RunResult {
  return {
    sealmark: { version: "1.0.1", methodology: "0.3-draft" },
    server: { name: "demo", version: "2.0.0", command: "node demo.js", transport: "stdio", env: { API_KEY: "hunter2-secret" }, tools: ["a", "b"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 5 },
    startedAt: "2026-11-20T10:00:00.000Z",
    durationMs: 4200,
    packs: {
      core: { status: "graded", grade: { pack: "core", points: 9, scored: 10, pct: 90, raw: "B", letter: "B", capped: false, provisional: false, criticalFails: [], excluded: [] } },
      db: { status: "na", reason: "no database tool" },
    },
    checks: [
      {
        id: "core.errors",
        pack: "core",
        label: "Errors are errors",
        critical: true,
        scope: "server: bad input",
        verdict: "pass",
        summary: "ok",
        evidence: [{ probe: "call a with {}", outcome: "isError true", verifiedBy: "response", tool: "a", args: { token: "arg-secret" }, excerpt: "excerpt-secret" }],
      },
    ],
    notCovered: ["b: no valid input"],
    sandbox: { enabled: true, dir: "/home/me/sandbox-secret" },
    config: { standard: true, hash: "sha256:abc" },
    ...over,
  } as unknown as RunResult;
}

const decode = (url: string): Record<string, unknown> => JSON.parse(inflateRawSync(Buffer.from(url.split("#r=")[1]!, "base64url")).toString("utf8")) as Record<string, unknown>;

describe("share: what the link carries", () => {
  it("is the viewer URL with # then base64url of raw deflate of the JSON", () => {
    const l = shareLink([run()]);
    assert.ok(l.url.startsWith(`${VIEWER_URL}#r=`));
    assert.match(l.url.split("#r=")[1]!, /^[A-Za-z0-9_-]+$/);
    assert.equal(l.fragmentChars, l.url.split("#r=")[1]!.length);
    assert.equal(l.runs, 1);
    assert.deepEqual(l.servers, ["demo"]);
  });

  it("holds what the viewer shows: server, grades, checks, evidence, not covered, configuration", () => {
    const v = decode(shareLink([run()]).url) as { server: { name: string }; packs: Record<string, { grade?: { letter: string }; reason?: string }>; checks: { id: string; verdict: string; evidence: { probe: string; outcome: string; tool: string }[] }[]; notCovered: string[]; config: { standard: boolean } };
    assert.equal(v.server.name, "demo");
    assert.equal(v.packs.core!.grade!.letter, "B");
    assert.equal(v.packs.db!.reason, "no database tool");
    assert.equal(v.checks[0]!.verdict, "pass");
    assert.deepEqual(v.checks[0]!.evidence[0], { probe: "call a with {}", outcome: "isError true", verifiedBy: "response", tool: "a" });
    assert.deepEqual(v.notCovered, ["b: no valid input"]);
    assert.equal(v.config.standard, true);
  });

  it("leaves out the environment, sandbox path, arguments and response excerpts", () => {
    const s = JSON.stringify(shareView(run()));
    for (const secret of ["hunter2-secret", "arg-secret", "excerpt-secret", "sandbox-secret"]) assert.ok(!s.includes(secret), secret);
    assert.ok(!s.includes("API_KEY"));
  });

  it("several runs go in as { runs }, one run as the run itself", () => {
    assert.ok(Array.isArray((decode(shareLink([run(), run()]).url) as { runs: unknown[] }).runs));
    assert.equal((decode(shareLink([run()]).url) as { runs?: unknown }).runs, undefined);
  });

  it("cuts long text and caps checks and evidence", () => {
    const evidence = Array.from({ length: 30 }, () => ({ probe: "p".repeat(900), outcome: "o", verifiedBy: "response" }));
    const checks = Array.from({ length: 450 }, (_, i) => ({ id: `c${i}`, pack: "core", label: "L", critical: false, scope: "s", verdict: "pass", summary: "s", evidence }));
    const v = decode(shareLink([run({ checks })]).url) as { checks: { evidence: { probe: string }[] }[] };
    assert.equal(v.checks.length, 400);
    assert.equal(v.checks[0]!.evidence.length, 12);
    assert.ok(v.checks[0]!.evidence[0]!.probe.length <= 401);
  });

  it("refuses a report whose link would be longer than the viewer reads", () => {
    // Random text does not compress, so a few hundred checks of it pass the 1.4 MB limit.
    const rnd = (n: number) => Array.from({ length: n }, () => String.fromCharCode(33 + Math.floor(Math.random() * 90))).join("");
    const checks = Array.from({ length: 400 }, (_, i) => ({ id: `c${i}`, pack: "core", label: rnd(400), critical: false, scope: rnd(400), verdict: "pass", summary: rnd(400), evidence: Array.from({ length: 12 }, () => ({ probe: rnd(400), outcome: rnd(400), verifiedBy: "response" })) }));
    assert.throws(() => shareLink([run({ checks })]), /too large for a link/);
    assert.ok(MAX_FRAGMENT > LONG_LINK);
  });
});

describe("sealmark share: the command", () => {
  let dir = "";
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-share-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));
  const sealmark = (args: string[]) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: "utf8", timeout: 60_000, env: hermeticEnv() });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };

  it("prints the link first, then what it holds, exit 0", () => {
    const f = join(dir, "r.json");
    writeFileSync(f, JSON.stringify(run()));
    const r = sealmark(["share", f]);
    assert.equal(r.code, 0, r.err);
    const lines = r.out.split("\n");
    assert.ok(lines[0]!.startsWith(`${VIEWER_URL}#r=`));
    assert.match(r.out, /Nothing was uploaded/);
    assert.match(r.out, /Read the report before you send it/);
    assert.equal((decode(lines[0]!) as { server: { name: string } }).server.name, "demo");
  });

  it("--json prints url, runs, servers, fragmentChars and long", () => {
    const f = join(dir, "r2.json");
    writeFileSync(f, JSON.stringify({ runs: [run(), run({ server: { name: "two", version: "1", command: "c", transport: "stdio", env: {}, tools: [], sqlTools: [] } })] }));
    const j = JSON.parse(sealmark(["share", f, "--json"]).out) as { url: string; runs: number; servers: string[]; long: boolean };
    assert.equal(j.runs, 2);
    assert.deepEqual(j.servers, ["demo", "two"]);
    assert.equal(j.long, false);
    assert.ok(j.url.startsWith(VIEWER_URL));
  });

  it("exit 2 with a reason for no file, a missing file, text that is not JSON and JSON with no run", () => {
    assert.equal(sealmark(["share"]).code, 2);
    assert.match(sealmark(["share"]).err, /needs a report file/);
    const missing = sealmark(["share", join(dir, "nope.json")]);
    assert.equal(missing.code, 2);
    assert.match(missing.err, /cannot read the report/);
    writeFileSync(join(dir, "bad.json"), "{nope");
    assert.match(sealmark(["share", join(dir, "bad.json")]).err, /not valid JSON/);
    writeFileSync(join(dir, "empty.json"), "{}");
    assert.match(sealmark(["share", join(dir, "empty.json")]).err, /no sealmark run/);
    assert.equal(sealmark(["share", join(dir, "empty.json")]).code, 2);
  });

  it("takes one file and no other flags", () => {
    assert.equal(sealmark(["share", "a.json", "b.json"]).code, 2);
    assert.match(sealmark(["share", "a.json", "--url", "http://x"]).err, /does not apply to "sealmark share"/);
  });

  it("is listed in help", () => {
    assert.match(sealmark(["--help"]).out, /share <report\.json>/);
  });
});
