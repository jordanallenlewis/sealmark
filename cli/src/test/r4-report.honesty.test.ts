import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderReport, renderText } from "../report.js";
import { badgeText } from "../report/badge.js";
import { compareBaseline } from "../report/baseline.js";
import { summaryLine } from "../report/common.js";
import { decideExit, type ExitPolicy } from "../report/exit.js";
import { renderSummary } from "../report/summary.js";
import type { CheckResult, Evidence, Letter, PackGrade, PackId, RunResult } from "../types.js";
import { check } from "./helpers.js";
import { kids, parseXml } from "./shape.js";

const grade = (pack: PackId, letter: Letter, o: Partial<PackGrade> = {}): PackGrade => ({ pack, points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o });

function run(over: Partial<RunResult> = {}, checks: CheckResult[] = [check("protocol", "pass")]): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "stdio", tools: ["a"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-12T00:00:00.000Z",
    durationMs: 10,
    packs: { core: { status: "graded", grade: grade("core", "A") } },
    checks,
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} },
    coverage: { validCalls: 4, toolsCalledValid: 1, toolsTotal: 1, level: "covered" },
    ...over,
  };
}

const ev = (probe: string, code?: string): Evidence => ({ probe, outcome: "o", verifiedBy: "response", ...(code ? { code } : {}) });

describe("F2: the stderr grade line", () => {
  it("an uncapped F with a critical fail names it", () => {
    const r = run({ packs: { db: { status: "graded", grade: grade("db", "F", { capped: false, criticalFails: ["mutating-sql"] }) } } }, [check("mutating-sql", "fail", { critical: true, pack: "db" })]);
    assert.equal(summaryLine(r), "db F critical fail: mutating-sql");
  });

  it("a capped grade keeps its wording", () => {
    const r = run({ packs: { db: { status: "graded", grade: grade("db", "D", { capped: true, criticalFails: ["mutating-sql"] }) } } }, [check("mutating-sql", "fail", { critical: true, pack: "db" })]);
    assert.equal(summaryLine(r), "db D capped: critical fail: mutating-sql");
  });

  it("a critical check at part is marked; an advisory or non-critical part is not", () => {
    const r = run({ packs: { net: { status: "graded", grade: grade("net", "B") } } }, [check("net-redirect", "part", { critical: true, pack: "net" }), check("net-caps", "part", { pack: "net" }), check("net-x", "part", { advisory: true, pack: "net" })]);
    assert.equal(summaryLine(r), "net B critical part: net-redirect");
  });

  it("a clean grade is unchanged", () => {
    assert.equal(summaryLine(run()), "core A");
  });
});

describe("F3: the summary format", () => {
  const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

  it("inconclusive and not-applicable packs are listed apart, and an unrequested pack is not listed", () => {
    const r = run({
      options: { packsRequested: ["core", "effects", "db", "http"], timeoutProbeSec: 10 },
      packs: { core: { status: "graded", grade: grade("core", "A") }, effects: { status: "inconclusive", reason: "no write tool could be called" }, db: { status: "na", reason: "no dsn" }, http: { status: "na", reason: "stdio" }, exec: { status: "na", reason: "needs --active" } },
    });
    const out = renderSummary([r]);
    assert.match(out, /inconclusive: effects \(no write tool could be called\)/);
    assert.match(out, /not applicable: db, http /);
    assert.ok(!/exec/.test(out.replace(/CLOSING/g, "")) || !/not applicable:.*exec/.test(out), "exec was not requested");
    assert.ok(!/no applicable checks/.test(out));
  });

  it("without a requested list every not-applicable pack is listed", () => {
    const r = run({ options: { timeoutProbeSec: 10 } as RunResult["options"], packs: { core: { status: "graded", grade: grade("core", "A") }, exec: { status: "na", reason: "needs --active" } } });
    assert.match(renderSummary([r]), /not applicable: exec /);
  });

  it("a provisional A at the A gate is BELOW the gate, never 'all graded packs at A'", () => {
    const r = run({ packs: { core: { status: "graded", grade: grade("core", "A") }, fs: { status: "graded", grade: grade("fs", "A", { provisional: true }) } } });
    const out = strip(renderSummary([r], { gate: "A" }));
    assert.match(out, /BELOW A: fs A\*/);
    assert.match(out, /an A\* does not meet the A gate/);
    assert.ok(!/ALL GRADED PACKS AT A OR BETTER/.test(out));
    // The exit code says the same.
    const d = decideExit([r], policy("A"));
    assert.equal(d.code, 1);
  });

  it("near miss: a provisional A at gate B and a plain A at gate A still pass", () => {
    const prov = run({ packs: { core: { status: "graded", grade: grade("core", "A", { provisional: true }) } } });
    assert.match(strip(renderSummary([prov], { gate: "B" })), /ALL GRADED PACKS AT B OR BETTER/);
    assert.match(strip(renderSummary([run()], { gate: "A" })), /ALL GRADED PACKS AT A OR BETTER/);
    assert.equal(decideExit([prov], policy("B")).code, 0);
  });

  it("the cited evidence is the deciding line, not the control call, not the first non-control line", () => {
    const k: CheckResult = { ...check("sqlite-timeout", "fail", { critical: true, pack: "core" }), evidence: [ev("control read", "fs.control.read"), ev("setup note", "fs.note"), ev("the real escape", "fs.write-escape")] };
    const out = renderSummary([run({ packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: ["sqlite-timeout"] }) } } }, [k])]);
    assert.match(out, /evidence: the real escape/);
  });

  it("a check with only control and note lines cites the first non-control line", () => {
    const k: CheckResult = { ...check("x", "fail", { pack: "core" }), evidence: [ev("control read", "fs.control.read"), ev("a plain line", "fs.note")] };
    assert.match(renderSummary([run({}, [k])]), /evidence: a plain line/);
  });

  it("a NOT COVERED block prints the first 8 lines and a count", () => {
    const notCovered = Array.from({ length: 11 }, (_, i) => `tool "t${i}" is covered by the core checks only`);
    const out = strip(renderSummary([run({ notCovered })]));
    assert.match(out, /NOT COVERED \(11\)/);
    assert.match(out, /t7" is covered/);
    assert.ok(!/t8" is covered/.test(out));
    assert.match(out, /\.\.\. and 3 more/);
  });

  it("no NOT COVERED block when nothing is listed", () => {
    assert.ok(!/NOT COVERED/.test(renderSummary([run()])));
  });

  it("WHAT TO FIX tags a critical check at part", () => {
    const k = check("net-redirect", "part", { critical: true, pack: "core" });
    assert.match(strip(renderSummary([run({}, [k])])), /core\/net-redirect {2}PART {2}critical part/);
    assert.ok(!/critical part/.test(strip(renderSummary([run({}, [check("plain", "part", { pack: "core" })])]))));
  });
});

type Sarif = { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }[] }[] }[] };

describe("F4: SARIF and JUnit carry the config line", () => {
  const cfg = (line?: number) => ({ hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {}, path: "/work/proj/sealmark.yaml", ...(line === undefined ? {} : { line }) });
  const failing = [check("a", "fail", { critical: true })];

  it("config.line 7 becomes the SARIF startLine and the JUnit line", () => {
    const r = run({ config: cfg(7) as RunResult["config"], packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: ["a"] }) } } }, failing);
    const sarif = JSON.parse(renderReport("sarif", [r])) as Sarif;
    const loc = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation;
    assert.equal(loc.region.startLine, 7);
    assert.equal(loc.artifactLocation.uri, "sealmark.yaml");
    const cases = kids(kids(parseXml(renderReport("junit", [r])), "testsuite")[0]!, "testcase");
    assert.ok(cases.length > 0);
    for (const c of cases) {
      assert.equal(c.attrs.file, "sealmark.yaml");
      assert.equal(c.attrs.line, "7");
    }
  });

  it("without a line it falls back to 1; a bad line too", () => {
    for (const line of [undefined, 0, -3, 2.5, Number.NaN]) {
      const r = run({ config: cfg(line) as RunResult["config"], packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: ["a"] }) } } }, failing);
      const sarif = JSON.parse(renderReport("sarif", [r])) as Sarif;
      assert.equal(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region.startLine, 1, String(line));
      const c = kids(kids(parseXml(renderReport("junit", [r])), "testsuite")[0]!, "testcase")[0]!;
      assert.equal(c.attrs.line, "1", String(line));
    }
  });

  it("a run with no config file points SARIF at the default name and JUnit names no file", () => {
    const r = run({ packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: ["a"] }) } } }, failing);
    const sarif = JSON.parse(renderReport("sarif", [r])) as Sarif;
    assert.deepEqual(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region, { startLine: 1 });
    assert.equal(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri, "sealmark.yaml");
    const c = kids(kids(parseXml(renderReport("junit", [r])), "testsuite")[0]!, "testcase")[0]!;
    assert.equal(c.attrs.file, undefined);
  });
});

const policy = (failUnder: Letter | undefined, o: Partial<ExitPolicy> = {}): ExitPolicy => ({
  failUnder,
  treatInconclusiveAs: "pass",
  criticalFail: 0,
  failOnGate: true,
  failOnRegressions: true,
  failOnDrift: false,
  regressions: [],
  drift: [],
  baseline: false,
  ...o,
});

describe("F5: the inconclusive warnings do not depend on the gate", () => {
  const r = () => run({ packs: { core: { status: "graded", grade: grade("core", "A") }, effects: { status: "inconclusive", reason: "no write tool" } } });

  it("--fail-under none still warns", () => {
    const d = decideExit([r()], policy(undefined));
    assert.equal(d.code, 0);
    assert.deepEqual(d.messages, ["warning: pack effects was inconclusive (no write tool)"]);
  });

  it("with treat_inconclusive_as fail and the gate off, a note says it has no effect, once", () => {
    const d = decideExit([r(), r()], policy(undefined, { treatInconclusiveAs: "fail" }));
    assert.equal(d.code, 0, "the exit code stays tied to the gate");
    assert.equal(d.messages.filter((m) => m.startsWith("note:")).length, 1);
    assert.ok(d.messages.includes("note: output.exit_policy.treat_inconclusive_as is fail, but the gate is off (--fail-under none), so it does not affect the exit code"));
    assert.equal(d.messages.filter((m) => m.startsWith("warning:")).length, 2);
  });

  it("with the gate on nothing changes: the 0.2 messages and the exit code", () => {
    assert.deepEqual(decideExit([r()], policy("A")).messages, ["warning: pack effects was inconclusive (no write tool) and is not covered by --fail-under A"]);
    const f = decideExit([r()], policy("A", { treatInconclusiveAs: "fail" }));
    assert.equal(f.code, 1);
    assert.deepEqual(f.messages, ["pack effects was inconclusive (no write tool); output.exit_policy.treat_inconclusive_as is fail"]);
  });

  it("with a gate set but not deciding (--fail-on regressions) the note names that", () => {
    const d = decideExit([r()], policy("A", { failOnGate: false, treatInconclusiveAs: "fail" }));
    assert.equal(d.code, 0);
    assert.ok(d.messages.some((m) => /does not include the gate/.test(m)));
  });

  it("a run with no inconclusive pack prints nothing extra", () => {
    assert.deepEqual(decideExit([run()], policy(undefined, { treatInconclusiveAs: "fail" })).messages, []);
  });
});

describe("F6: text, markdown, badge and diff wording", () => {
  it("the sandbox line lists the inherited environment when the harness recorded it", () => {
    const sandbox = { dir: "/tmp/sealmark-x", envMode: "scrubbed" as const, listenerPort: null, cleanedUp: true, leftoverProcesses: [], active: false, enabled: true, kept: false, inherited: ["HOME", "PATH"] };
    const r = run({ sandbox });
    assert.match(renderText(r), /sandbox: .* · env scrubbed · inherited: HOME, PATH · cleaned up/);
    assert.match(renderReport("markdown", [r]), /env scrubbed, inherited: HOME, PATH, cleaned up/);
    const none = run({ sandbox: { ...sandbox, inherited: undefined } as RunResult["sandbox"] });
    assert.ok(!/inherited:/.test(renderText(none)));
    assert.ok(!/inherited:/.test(renderText(run({ sandbox: { ...sandbox, inherited: [] } as RunResult["sandbox"] }))));
  });

  it("several versions in the cache: the line says unknown, lists them and says what to do", () => {
    const resolved = { configVersion: "1.0.0", serverInfoVersion: "1.2.3", package: { name: "toytool", source: "uv-cache" as const, version: "1.2.9", candidates: ["1.2.3", "1.2.9"] } };
    const r = run({ server: { ...run().server, resolved: resolved as NonNullable<RunResult["server"]["resolved"]> } });
    const want = "toytool unknown (several versions in the uv cache: 1.2.3, 1.2.9; the server announced 1.2.3; pin the version)";
    assert.ok(renderText(r).includes(`resolved package: ${want}`));
    assert.ok(renderReport("markdown", [r]).includes(want));
    assert.ok(!renderText(r).includes("1.2.9 (uv-cache)"), "the wrong version is not printed as resolved");
  });

  it("candidates without an announced version drop that clause", () => {
    const resolved = { configVersion: "1.0.0", package: { name: "toytool", source: "uv-cache" as const, candidates: ["1.0", "2.0"] } };
    const r = run({ server: { ...run().server, resolved: resolved as NonNullable<RunResult["server"]["resolved"]> } });
    assert.ok(renderText(r).includes("toytool unknown (several versions in the uv cache: 1.0, 2.0; pin the version)"));
  });

  it("a core-only run says 'core only' on the badge", () => {
    assert.equal(badgeText(run({ badge: { eligible: false, reason: "core-only run: hygiene checks only" } })).message, "no badge: core only");
  });

  it("diff notes a different configuration when exactly one report is CUSTOM, even with equal hashes", () => {
    const std = run();
    const custom = run({ config: { ...std.config!, standard: false, standardDiff: [{ path: "x", standard: 1, effective: 2, origin: "flag" }] } });
    const d = compareBaseline([std], [custom]);
    assert.ok(d.notes.some((n) => /different configuration \(STANDARD vs CUSTOM\)/.test(n)), d.notes.join("\n"));
    assert.equal(compareBaseline([std], [run()]).notes.length, 0, "identical configurations: no note");
    const h = run({ config: { ...std.config!, hash: "sha256:bbbb" } });
    assert.equal(compareBaseline([std], [h]).notes.filter((n) => /different configuration/.test(n)).length, 1, "a hash difference still says it once");
  });
});
