import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderReport, renderText, type FailedRun } from "../report.js";
import { redactResult } from "../report/redact.js";
import { inertDeep, inertLines, MAX_REPORT_FIELD } from "../report/sanitize.js";
import type { CheckResult, PackGrade, RunResult } from "../types.js";
import { check } from "./helpers.js";

function grade(pack: string, letter: PackGrade["letter"], o: Partial<PackGrade> = {}): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o };
}

function run(over: Partial<RunResult> = {}, checks: CheckResult[] = [check("protocol", "pass"), check("secret-echo", "fail", { critical: true })]): RunResult {
  return {
    sealmark: { version: "0.2.0", methodology: "0.2-draft" },
    server: { name: "my-server", version: "1.0.0", command: "node server.js", env: {}, transport: "stdio", tools: ["a", "b"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 10,
    packs: { core: { status: "graded", grade: grade("core", "B") } },
    checks,
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    coverage: { validCalls: 4, toolsCalledValid: 1, toolsTotal: 2, level: "covered" },
    classification: [{ tool: "a", class: "text", confidence: "low", params: {}, unfillable: [], reasons: ["generic"] }],
    ...over,
  };
}

const ESC = "\x1b";
const HOSTILE = [
  `1.0${ESC}[2K${ESC}[1;32mALL GOOD`,
  `x\r[ PASS ] core/forged\bx y`,
  `x${ESC}]8;;https://evil.example${ESC}\\link${ESC}]8;;${ESC}\\`,
  `bad${ESC}[31mname\x07\x00\x7f\x9b2J`,
];
// Every C0 control except tab (0x09) and newline (0x0a) is a byte a terminal acts on; the renderers' own output may have \n only.
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;
const noRaw = (out: string, what: string) => {
  assert.ok(!CONTROL.test(out), `${what}: a control byte got through`);
  assert.ok(!out.includes(" ") && !out.includes(" ") && !/[\u0080-\u009f]/.test(out), `${what}: a Unicode line or C1 control got through`);
};

function hostile(payload: string): RunResult {
  const bad = check("tool-poisoning", "fail", { critical: true });
  Object.assign(bad, { label: payload, summary: payload });
  bad.evidence = [{ probe: payload, outcome: payload, verifiedBy: "response", tool: payload, args: { q: payload } }];
  bad.coverage = { notCovered: [{ tool: payload, reason: payload }] } as CheckResult["coverage"];
  return run(
    {
      server: { name: payload, version: payload, command: payload, env: { [payload]: payload }, transport: "stdio", tools: [payload, "ok"], sqlTools: [] },
      warnings: [payload],
      notCovered: [payload],
      classification: [{ tool: payload, class: "text", confidence: "low", params: {}, unfillable: [], reasons: [payload] }],
      packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: [bad.id] }) }, [payload]: { status: "na", reason: payload } } as RunResult["packs"],
      config: { hash: "sha256:b", profile: "quick", standard: false, standardDiff: [{ path: payload, standard: payload, effective: payload, origin: payload }], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    },
    [check("protocol", "pass"), bad],
  );
}

describe("report-sanitize: text and markdown reports make server text inert", () => {
  for (const payload of HOSTILE) {
    for (const verbosity of ["normal", "verbose"] as const) {
      it(`${verbosity}: ${JSON.stringify(payload).slice(0, 36)}`, () => {
        const r = hostile(payload);
        const failed: FailedRun = { status: "failed", server: payload, error: `boom ${payload}\n${payload}`, hint: payload, stderrFile: payload, sealmark: { version: "0.2.0", methodology: "0.2-draft" } };
        noRaw(renderText(r, { verbosity }), "text");
        noRaw(renderReport("markdown", [r], { verbosity }), "markdown");
        noRaw(renderReport("text", [r, failed], { verbosity }), "text matrix with a failed run");
        noRaw(renderReport("markdown", [r, failed], { verbosity }), "markdown matrix with a failed run");
        noRaw(renderReport("text", [failed]), "failed text");
        noRaw(renderReport("markdown", [failed]), "failed markdown");
      });
    }

    it(`a user template cannot print raw text: ${JSON.stringify(payload).slice(0, 36)}`, () => {
      const template = "{{server.name}} {{server.version}} {{summary}} {{#each checks}}{{label}} {{summary}} {{/each}}{{json server}}{{header}}";
      noRaw(renderReport("text", [hostile(payload)], { template }), "text template");
      noRaw(renderReport("markdown", [hostile(payload)], { template }), "markdown template");
    });
  }

  it("a forged row folds onto its own line instead of starting a new one", () => {
    const out = renderText(hostile(`x\n[ PASS ] core/forged`));
    assert.ok(out.includes("x [ PASS ] core/forged"));
    assert.ok(!/^ *\[PASS\] core\/forged/m.test(out) && !/^\[ PASS \]/m.test(out));
  });

  it("shows the escape instead of obeying it", () => {
    const out = renderText(run({ server: { name: "s", version: `1.0${ESC}[2K`, command: "c", env: {}, transport: "stdio", tools: [`bad${ESC}[31mname`], sqlTools: [] } }));
    assert.ok(out.includes("bad\\u001b[31mname"), out);
    assert.ok(out.includes("1.0\\u001b[2K"), out);
  });

  it("a plain report is untouched: the result is its own inert form, so nothing changes in the text or markdown", () => {
    const plain = run({ warnings: ["serverInfo.version 0.0.1 differs from config version 1.0.0"], notCovered: ["tool b: no valid call"] });
    const verbose = run({ ...plain, checks: [{ ...check("protocol", "pass"), summary: "ok — 3 probes (naïve → 日本語 😀)", evidence: [{ probe: "initialize", outcome: "ok; excerpt of 4 KiB stays", verifiedBy: "response", tool: "a", args: { x: 1, y: "z" } }] }] });
    for (const r of [plain, verbose]) assert.deepEqual(inertDeep(redactResult(r, {}), MAX_REPORT_FIELD), redactResult(r, {}));
  });

  it("a verbose evidence excerpt of 4 KiB survives whole", () => {
    const long = "e".repeat(4096);
    const c = { ...check("protocol", "pass"), evidence: [{ probe: "p", outcome: long, verifiedBy: "response" as const }] };
    assert.ok(renderText(run({}, [c]), { verbosity: "verbose" }).includes(long));
    assert.ok(renderReport("markdown", [run({}, [c])], { verbosity: "verbose" }).includes(long));
  });

  it("JSON is left as it was: the raw value is there, escaped by JSON itself", () => {
    const out = renderReport("json", [hostile(HOSTILE[0])]);
    assert.ok(out.includes("\\u001b[2K"));
    assert.ok(!CONTROL.test(out.replace(/\n/g, "")));
    assert.equal((JSON.parse(out) as RunResult).server.version, HOSTILE[0]);
  });
});

describe("report-sanitize: inertLines", () => {
  it("keeps the lines, drops what a terminal acts on", () => {
    assert.equal(inertLines(`a${ESC}[2K\r\nb\rc\n  d e`), "a\\u001b[2K\nb c\n  d e");
    assert.equal(inertLines("one"), "one");
    assert.equal(inertLines(""), "");
    assert.equal(inertLines(undefined), "");
    assert.equal(inertLines("a\n   \nb"), "a\n\nb");
  });

  it("caps the number of lines and says how many were left out", () => {
    const out = inertLines(Array.from({ length: 500 }, (_, i) => `l${i}`).join("\n"), 3);
    assert.equal(out, "l0\nl1\nl2\n… (497 more lines)");
  });

  it("is linear: a million short lines and one huge line are quick", () => {
    const t = Date.now();
    inertLines("x\n".repeat(1_000_000));
    inertLines("y".repeat(5_000_000));
    assert.ok(Date.now() - t < 2000);
  });
});
