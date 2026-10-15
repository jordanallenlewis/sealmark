import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { renderJson, renderReport, renderText, type FailedRun } from "../report.js";
import { makePathRewriter, makeRunNormaliser, makeSecretScrubber, redactFailed, redactResult } from "../report/redact.js";
import { secretLiterals } from "../report/secrets.js";
import { renderJunit } from "../report/junit.js";
import { renderSarif } from "../report/sarif.js";
import type { CheckResult, RunResult } from "../types.js";
import { check } from "./helpers.js";
import { kids, parseXml } from "./shape.js";

const PORT = 41234;
const norm = makeRunNormaliser(PORT);
const hex = (n: number, seed = 7) => Array.from({ length: n }, (_, i) => "0123456789abcdef"[(seed * (i + 3) + i * i) % 16]).join("");

describe("every per-run token shape is rewritten to a stable name", () => {
  it("control files and probe files: the -abs, -rel and -<digits> suffixes and the extension do not hide the token", () => {
    assert.equal(norm(`w-ctl-sm-${hex(12)}-abs.txt`), "w-ctl-{token}-abs.txt");
    assert.equal(norm(`w-ctl-sm-${hex(12)}-rel.txt`), "w-ctl-{token}-rel.txt");
    assert.equal(norm(`w-sm-${hex(12)}-3.txt`), "w-{token}-3.txt");
    assert.equal(norm(`mk-sm-${hex(12)}-12`), "mk-{token}-12");
    assert.equal(norm(`cp-src-sm-${hex(12)}-abs.txt`), "cp-src-{token}-abs.txt");
    assert.equal(norm(`lw-ctl-sm-${hex(12)}.txt`), "lw-ctl-{token}.txt");
  });

  it("a token inside a longer word, or followed by other letters, is left alone", () => {
    assert.equal(norm(`sm-${hex(12)}-abcd`), `sm-${hex(12)}-abcd`);
    assert.equal(norm(`xsm-${hex(12)}`), `xsm-${hex(12)}`);
    assert.equal(norm(`sm-${hex(12)}0`), `sm-${hex(12)}0`);
  });

  it("the control token, pwned files of any length from 12 to 16, and the git root and prefix tokens", () => {
    assert.equal(norm(`read sm-control-${hex(16)} ok`), "read {control} ok");
    assert.equal(norm(`--output=pwned-${hex(12)}.txt`), "--output=pwned-{token}.txt");
    assert.equal(norm(`--output=pwned-${hex(16)}.txt`), "--output=pwned-{token}.txt");
    assert.equal(norm(`pwned-${hex(11)}`), `pwned-${hex(11)}`);
    assert.equal(norm(`sm-prefix-${hex(12)}/x`), "{token:prefix}/x");
    assert.equal(norm(`sm-root-${hex(12)}`), "{token:root}");
  });

  it("a 40-digit commit id and an abbreviated range become {sha}; a sha256 and a longer hex word are kept", () => {
    const sha = hex(40);
    assert.equal(norm(`commit ${sha} on main`), "commit {sha} on main");
    assert.equal(norm(`${sha}..${hex(40, 9)}`), "{sha}..{sha}");
    assert.equal(norm(`${hex(7)}..${hex(7, 5)}`), "{sha}..{sha}");
    assert.equal(norm(`sha256:${hex(64)}`), `sha256:${hex(64)}`);
    assert.equal(norm(`id ${hex(41)}`), `id ${hex(41)}`);
  });
});

describe("a timestamp the server printed is the time of this run", () => {
  it("an ISO instant in a stat reply becomes {time}; a date alone, a version and a long digit run are kept", () => {
    assert.equal(norm(`{"size":27,"mtime":"2026-10-13T20:25:18.461Z"}`), `{"size":27,"mtime":"{time}"}`);
    assert.equal(norm("at 2026-10-13T20:25:18+02:00 and 2026-10-13T20:25:18.5Z"), "at {time} and {time}");
    assert.equal(norm("released 2026-10-13, v1.2.3, id 20261013202518"), "released 2026-10-13, v1.2.3, id 20261013202518");
  });

  it("the run's own startedAt is left alone, so a baseline and the JUnit and SARIF start times keep working", () => {
    const r = redactResult(run({ startedAt: "2026-10-13T20:25:18.461Z" }));
    assert.equal(r.startedAt, "2026-10-13T20:25:18.461Z");
    assert.match(renderSarif([r]), /"startTimeUtc": "2026-10-13T20:25:18\.461Z"/);
  });
});

describe("a sandbox path fragment never leaks", () => {
  const SB = "/Users/someone/tmp/sealmark-0123456789";
  const rw = makePathRewriter(SB);

  it("an excerpt cut inside the random part of the directory name", () => {
    assert.equal(rw("failed at /Users/someone/tmp/sealmark-01234"), "failed at {sandbox_dir}");
    assert.equal(rw("failed at /Users/someone/tmp/sealmark-"), "failed at {sandbox_dir}");
    assert.equal(rw("x /Users/someone/tmp/sealmark-0123/canary/sec"), "x {sandbox_dir}/canary/sec");
  });

  it("a near-miss is left alone: another directory, or the prefix of an unrelated name", () => {
    assert.equal(rw("/Users/someone/tmp/other-0123"), "/Users/someone/tmp/other-0123");
    assert.equal(rw("/Users/someone/work/sealmark-0123"), "/Users/someone/work/sealmark-0123");
    assert.equal(rw("/Users/someone/tmp/sealmark-0129"), "/Users/someone/tmp/sealmark-0129", "other letters: not a part of this directory's name");
    assert.equal(rw("/Users/someone/tmp/sealmark-0123456789abc"), "/Users/someone/tmp/sealmark-0123456789abc", "a longer name is another directory");
  });

  it("the file://localhost/ form, the file:/// form and the percent-encoded forms with %2F and %5C", () => {
    assert.ok(!rw(`file://localhost${SB}/root/a.txt`).includes("someone"));
    assert.equal(rw(`file:///Users/someone/tmp/sealmark-0123456789/canary/x`), "file:{canary}/x");
    assert.equal(rw("u=%2FUsers%2Fsomeone%2Ftmp%2Fsealmark-0123456789%2Fcanary%2Fx"), "u=%2F{canary}%2Fx");
    assert.equal(rw("u=%2FUsers%2Fsomeone%2Ftmp%2Fsealmark-01%2Fcanary"), "u=%2F{sandbox_dir}%2Fcanary");
    assert.ok(!rw("%5CUsers%5Csomeone%5Ctmp%5Csealmark-0123456789%5Croot%5Cx").includes("someone"));
  });

  it("a failed run's message and hint lose the sandbox directory, whatever its parent, and the per-run tokens", () => {
    const f: FailedRun = {
      status: "failed",
      server: "toy",
      error: `could not start: ENOENT /var/folders/ab/xyz/T/sealmark-0123456789/root/data.db (sm-${hex(12)})`,
      hint: `see /home/me/tmp/sealmark-abcdef0123/bin/x`,
      sealmark: { version: "0.2.1", methodology: "0.2-draft" },
    };
    const r = redactFailed(f);
    assert.equal(r.error, "could not start: ENOENT {sandbox}/data.db ({token})");
    assert.equal(r.hint, "see {sandbox_bin}/x");
    assert.equal(redactFailed(f, { redact: false }), f);
    assert.ok(!renderReport("json", [f]).includes("/var/folders"));
    assert.ok(!renderReport("text", [f]).includes("sealmark-0123456789"));
  });

  it("a directory that merely starts with sealmark- (a user's own) is not taken for a sandbox", () => {
    const f: FailedRun = { status: "failed", server: "t", error: "no such file /home/me/sealmark-demo/data.db", sealmark: { version: "0.2.1", methodology: "0.2-draft" } };
    assert.equal(redactFailed(f).error, "no such file /home/me/sealmark-demo/data.db");
  });
});

function run(over: Partial<RunResult> = {}, checks: CheckResult[] = [check("protocol", "pass")]): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "Toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["t"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10, sandbox: true },
    startedAt: "2026-10-13T00:00:00.000Z",
    durationMs: 5,
    packs: { core: { status: "graded", grade: { pack: "core", points: 1, scored: 1, pct: 100, raw: "A", letter: "A", capped: false, criticalFails: [], provisional: false, excluded: [] } } },
    checks,
    notCovered: [],
    config: { hash: "sha256:aa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} },
    ...over,
  };
}

describe("config.path is stored relative to the working directory", () => {
  const abs = resolve("sub", "sealmark.yaml");
  const base = run({ config: { hash: "sha256:aa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {}, path: abs } });

  it("the JSON report carries no user directory; the file name and line survive", () => {
    const j = JSON.parse(renderJson(base)) as RunResult;
    assert.equal(j.config!.path, "sub/sealmark.yaml");
    assert.ok(!renderJson(base).includes(resolve(".")));
  });

  it("a path outside the working directory keeps only its file name; --no-redact keeps everything", () => {
    const outside = run({ config: { ...base.config!, path: resolve("..", "..", "elsewhere", "sealmark.yaml") } });
    assert.equal(redactResult(outside).config!.path, "sealmark.yaml");
    assert.equal(redactResult(base, { redact: false }).config!.path, abs);
  });
});

describe("the secret scrubber leaves settings and check names alone", () => {
  it("a mode word under a secret-looking name is never scrubbed, a real secret still is", () => {
    for (const w of ["true", "false", "none", "required", "Strict", "default", "enabled"]) assert.equal(makeSecretScrubber([w])(`auth is ${w} and ${w}`), `auth is ${w} and ${w}`, w);
    assert.equal(makeSecretScrubber(["hunter22", "none"])("pw hunter22 none"), "pw <redacted> none");
  });

  it("secretLiterals does not return a mode word", () => {
    const cfg = {
      servers: [{ name: "s", spec: { command: "x", env: { AUTH_REQUIRED: "true", API_TOKEN: "none", MY_SECRET: "s3cr3t-value" } } }],
      db: { pg: null },
      origins: {},
      value: {},
      env: {},
    } as unknown as Parameters<typeof secretLiterals>[0];
    assert.deepEqual(secretLiterals(cfg), ["s3cr3t-value"]);
  });

  it("the id, label, scope and pack of a check are never rewritten, the rest of the check still is", () => {
    const c: CheckResult = { ...check("fs-read-escape", "fail", { pack: "fs", critical: true }), label: "Reads stay inside the root", scope: "server (path validation)", summary: "read root hunter22 failed", evidence: [{ probe: "read hunter22", outcome: "ok", verifiedBy: "response" }] };
    const r = redactResult(run({}, [c]), { secrets: ["hunter22", "root", "path", "server"] });
    assert.equal(r.checks[0]!.id, "fs-read-escape");
    assert.equal(r.checks[0]!.pack, "fs");
    assert.equal(r.checks[0]!.label, "Reads stay inside the root");
    assert.equal(r.checks[0]!.scope, "server (path validation)");
    assert.equal(r.checks[0]!.summary, "read <redacted> <redacted> failed");
    assert.equal(r.checks[0]!.evidence[0]!.probe, "read <redacted>");
  });
});

describe("the run warnings reach JUnit and SARIF", () => {
  const warned = run({ warnings: ["the run was interrupted (SIGINT) while the fs pack ran", "serverInfo.version 1.0.0 differs from config version 2.0.0"] });

  it("JUnit: one sealmark.warning property per warning in every suite", () => {
    const suite = kids(parseXml(renderJunit([warned])), "testsuite")[0]!;
    const props = kids(kids(suite, "properties")[0]!, "property");
    const values = props.filter((p) => p.attrs.name === "sealmark.warning").map((p) => p.attrs.value);
    assert.deepEqual(values, warned.warnings);
  });

  it("SARIF: the warnings sit in the run properties; no warnings, no key", () => {
    const sarif = JSON.parse(renderSarif([warned])) as { runs: { properties: Record<string, unknown> }[] };
    assert.deepEqual(sarif.runs[0]!.properties.warnings, warned.warnings);
    const plain = JSON.parse(renderSarif([run()])) as { runs: { properties: Record<string, unknown> }[] };
    assert.equal("warnings" in plain.runs[0]!.properties, false);
  });

  it("the text format still lists them (unchanged)", () => {
    assert.match(renderText(warned), /Warnings:\n {2}- the run was interrupted/);
  });
});
