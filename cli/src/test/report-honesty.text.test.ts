import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderReport, renderText } from "../report.js";
import { badgeText } from "../report/badge.js";
import { renderSummary } from "../report/summary.js";
import type { CheckResult, RunResult, ToolClassification } from "../types.js";

const check = (id: string, verdict: CheckResult["verdict"], o: Partial<CheckResult> = {}): CheckResult => ({ id, pack: "core", label: id, critical: false, scope: "test", verdict, summary: "test", evidence: [], ...o });

const grade = { pack: "core" as const, points: 3, scored: 4, pct: 75, raw: "C" as const, letter: "C" as const, capped: false, criticalFails: [], provisional: false, excluded: [] };

function run(over: Partial<RunResult> = {}): RunResult {
  return {
    sealmark: { version: "0.2.1", methodology: "0.2-draft" },
    server: { name: "Toy", version: "1.0.0", command: "uvx toytool", env: {}, transport: "stdio", tools: ["read_thing"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-12T00:00:00.000Z",
    durationMs: 10,
    packs: { core: { status: "graded", grade }, effects: { status: "graded", grade: { ...grade, pack: "effects" } } },
    checks: [check("protocol", "pass"), check("annotation-honesty", "pass", { pack: "effects" }), check("undeclared-writes", "na", { pack: "effects", advisory: true, summary: "no tool declared readOnlyHint" }), check("write-gate", "fail", { pack: "effects", advisory: true })],
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    badge: { eligible: false, reason: "core-only run: hygiene checks only" },
    ...over,
  };
}

describe("the summary format prints the badge decision", () => {
  it("a run that is not badge-eligible says so, with the reason", () => {
    const out = renderSummary([run()]);
    assert.match(out, /not badge-eligible: core-only run: hygiene checks only/);
  });

  it("an eligible run says so", () => {
    assert.match(renderSummary([run({ badge: { eligible: true } })]), /^badge: eligible$/m);
  });

  it("a result that carries no badge decision prints no badge line", () => {
    const { badge: _b, ...rest } = run();
    assert.ok(!/badge/i.test(renderSummary([rest as RunResult]).replace(/Never a security endorsement/i, "")));
  });
});

describe("the badge text for a provisional run", () => {
  it("'a pack is provisional' and 'an inconclusive critical check' both read 'no badge: provisional'", () => {
    for (const reason of ["a pack is provisional: a critical check was inconclusive", "a pack has an inconclusive critical check"]) {
      const t = badgeText(run({ badge: { eligible: false, reason } }));
      assert.equal(t.message, "no badge: provisional", reason);
      assert.equal(t.color, "lightgrey");
    }
  });

  it("the existing reasons keep their text", () => {
    assert.equal(badgeText(run({ badge: { eligible: false, reason: "custom run: the configuration differs" } })).message, "no badge: custom run");
    assert.equal(badgeText(run({ badge: { eligible: false, reason: "core-only run: hygiene checks only" } })).message, "no badge: core only");
  });
});

const cls: ToolClassification[] = [
  { tool: "fetch_file", class: "path", confidence: "medium", params: { path: "target" }, unfillable: [], reasons: ['param "target"'], secondary: ["url"] },
  { tool: "plain", class: "path", confidence: "high", params: { path: "path" }, unfillable: [], reasons: ['param "path"'] },
];

describe("a tool's secondary class is visible", () => {
  it("the text classification block names it under the tool, and only for tools that have one", () => {
    const t = renderText(run({ classification: cls }));
    const lines = t.split("\n");
    const i = lines.findIndex((l) => l.includes("fetch_file"));
    assert.ok(i > 0, t);
    assert.equal(lines[i + 1], "    secondary: url");
    assert.ok(lines[i + 2]!.includes("plain"), "the next row follows directly");
    assert.equal(t.match(/secondary:/g)?.length, 1);
  });

  it("a block with no secondary class is printed as before", () => {
    const t = renderText(run({ classification: [cls[1]!] }));
    assert.ok(!t.includes("secondary:"));
    assert.match(t, /\n {2}plain {2}path {2}high {2}← param "path"\n/);
  });

  it("the markdown table shows it in the Why column", () => {
    const md = renderReport("markdown", [run({ classification: cls })]);
    assert.match(md, /\| fetch_file \| path \| medium \| param "target"; secondary: url \|/);
    assert.match(md, /\| plain \| path \| high \| param "path" \|/);
  });
});

describe("the resolved-package line", () => {
  const resolved = (pkg: NonNullable<RunResult["server"]["resolved"]>["package"], serverInfoVersion?: string) => run({ server: { ...run().server, resolved: { configVersion: "1.0.0", ...(serverInfoVersion ? { serverInfoVersion } : {}), package: pkg } } });

  it("a resolved uv package prints its version and source", () => {
    const r = resolved({ name: "toytool", version: "1.2.3", source: "uv-cache" });
    assert.match(renderText(r), /\nresolved package: toytool 1\.2\.3 \(uv-cache\)\n/);
    assert.match(renderReport("markdown", [r]), /- Resolved package: `toytool 1\.2\.3 \(uv-cache\)`/);
  });

  it("when nothing was found the announced version is the label, and the line says so", () => {
    const r = resolved({ name: "toytool", version: "unknown", source: "not found" }, "9.8.7");
    const t = renderText(r);
    assert.match(t, /\nresolved package: toytool 9\.8\.7 \(serverInfo version; the package was not found in the cache\)\n/);
    assert.ok(!t.includes("unknown"));
    assert.match(renderReport("markdown", [r]), /toytool 9\.8\.7 \(serverInfo version; the package was not found in the cache\)/);
  });

  it("when nothing was found and the server announced nothing, the line says the version is unknown", () => {
    const r = resolved({ name: "toytool", version: "unknown", source: "not found" });
    assert.match(renderText(r), /\nresolved package: toytool \(version unknown, not found\)\n/);
    assert.match(renderReport("markdown", [r]), /- Resolved package: `toytool \(version unknown, not found\)`/);
  });

  it("an absent version (the field is optional) reads the same as the 'unknown' marker, and never prints 'undefined'", () => {
    const r = resolved({ name: "toytool", source: "npx-cache" } as never);
    const t = renderText(r);
    assert.match(t, /\nresolved package: toytool \(version unknown, npx-cache\)\n/);
    assert.ok(!t.includes("undefined"));
  });
});
