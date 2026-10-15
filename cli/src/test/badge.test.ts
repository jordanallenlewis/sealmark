import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { METHODOLOGY } from "../config/index.js";
import type { FailedRun } from "../report.js";
import { badgeText, renderBadge, renderShields } from "../report/badge.js";
import type { PackGrade, RunResult } from "../types.js";
import { FAST, check, cliKit, srv } from "./helpers.js";
import { kids, parseXml } from "./shape.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-badge-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeYaml, toyConfig } = cliKit(() => dir);
/** Nothing a grade depends on is changed (--pack and --timeout-probe are locked, --fail-under is not), so the run follows the standard profile; toy nosql has no SQL tool, so only core is graded. */
const STD = ["--fail-under", "none"];

function grade(pack: string, letter: PackGrade["letter"], o: Partial<PackGrade> = {}): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o };
}

type Graded = Record<string, PackGrade["letter"] | [PackGrade["letter"], boolean]>;

/** A run whose packs are `graded` ({ id: letter }, or [letter, provisional]); the server name is hostile on purpose. */
function run(graded: Graded, over: Partial<RunResult> = {}): RunResult {
  const packs: RunResult["packs"] = {};
  for (const [id, v] of Object.entries(graded)) {
    const [letter, provisional] = Array.isArray(v) ? v : [v, false];
    packs[id as PackGrade["pack"]] = { status: "graded", grade: grade(id, letter, { provisional }) };
  }
  return {
    sealmark: { version: "0.2.1", methodology: "0.2-draft" },
    server: { name: "evil-<server>&name", version: "6.6.6", command: "node server.js", env: {}, transport: "stdio", tools: ["a"], sqlTools: [] },
    options: { packsRequested: Object.keys(graded) as PackGrade["pack"][], timeoutProbeSec: 10 },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 10,
    packs,
    checks: [check("protocol", "pass")],
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    coverage: { validCalls: 4, toolsCalledValid: 1, toolsTotal: 1, level: "covered" },
    badge: { eligible: true },
    ...over,
  };
}

const failed: FailedRun = { status: "failed", server: "evil-<server>&name", error: "boom", sealmark: { version: "0.2.1", methodology: "0.2-draft" } };
const opts = {} as Parameters<typeof renderBadge>[1];

describe("badgeText", () => {
  it("an eligible run lists graded packs in pack order, keeps the provisional star and says self-reported", () => {
    const t = badgeText(run({ fs: "A", db: ["B", true], core: "A" }));
    assert.deepEqual(t, { label: "sealmark 0.2-draft", message: "core A · db B* · fs A · self-reported", color: "green" });
  });

  it("the colour follows the worst letter among graded packs", () => {
    const colour = (g: Graded) => badgeText(run(g)).color;
    assert.equal(colour({ core: "A", db: "A" }), "brightgreen");
    assert.equal(colour({ core: "A", db: "B" }), "green");
    assert.equal(colour({ core: "A", db: "C" }), "yellow");
    assert.equal(colour({ core: "A", db: "D", fs: "A" }), "orange");
    assert.equal(colour({ core: "F", db: "A" }), "red");
    assert.equal(colour({ core: "A", db: ["A", true] }), "brightgreen", "the star does not change the colour");
  });

  it("packs that are not graded are left out of the message and the colour", () => {
    const r = run({ core: "A", db: "A" });
    r.packs.fs = { status: "inconclusive", reason: "x" };
    r.packs.net = { status: "na", reason: "y" };
    assert.equal(badgeText(r).message, "core A · db A · self-reported");
    assert.equal(badgeText(r).color, "brightgreen");
  });

  it("a custom run shows no letter", () => {
    const r = run({ core: "A", db: "A" }, { badge: { eligible: false, reason: "custom run: the configuration differs from the published standard profile" }, config: { ...run({}).config!, standard: false, profile: "quick" } });
    const t = badgeText(r);
    assert.deepEqual(t, { label: "sealmark 0.2-draft", message: "no badge: custom run", color: "lightgrey" });
    assert.ok(!/\b[A-F]\b/.test(t.message));
  });

  it("a core-only run says core only", () => {
    const r = run({ core: "A" }, { badge: { eligible: false, reason: "core-only run: hygiene checks only" } });
    assert.equal(badgeText(r).message, "no badge: core only");
    assert.equal(badgeText(r).color, "lightgrey");
  });

  it("nothing graded, an unknown reason and a missing badge block each have their own words", () => {
    assert.equal(badgeText(run({}, { badge: { eligible: false, reason: "something new" } })).message, "no badge: nothing graded");
    const withNa = run({}, { badge: { eligible: false, reason: "something new" } });
    withNa.packs.db = { status: "na", reason: "no SQL tool" };
    assert.equal(badgeText(withNa).message, "no badge: nothing graded");
    assert.equal(badgeText(run({ core: "A", db: "A" }, { badge: { eligible: false } })).message, "no badge: not eligible");
    assert.equal(badgeText(run({ core: "A", db: "A" }, { badge: undefined })).message, "no badge: not eligible");
    assert.equal(badgeText(run({ core: "A", db: "A" }, { badge: { eligible: false, reason: "the run did not load a configuration" } })).message, "no badge: not eligible");
  });

  it("a failed run carries the methodology label and no letter", () => {
    assert.deepEqual(badgeText(failed), { label: "sealmark 0.2-draft", message: "no badge: server failed", color: "lightgrey" });
  });

  it("never carries the server name", () => {
    for (const r of [run({ core: "A", db: "B" }), run({ core: "A" }, { badge: { eligible: false, reason: "core-only run: x" } }), failed]) {
      assert.ok(!JSON.stringify(badgeText(r)).includes("evil"));
    }
  });
});

describe("renderShields", () => {
  it("is the endpoint document: exactly schemaVersion, label, message, color", () => {
    const out = renderShields([run({ core: "A", db: ["B", true] })], opts);
    assert.ok(out.endsWith("\n"));
    const j = JSON.parse(out);
    assert.deepEqual(Object.keys(j).sort(), ["color", "label", "message", "schemaVersion"]);
    assert.equal(j.schemaVersion, 1);
    assert.equal(j.label, "sealmark 0.2-draft");
    assert.equal(j.message, "core A · db B* · self-reported");
    assert.equal(j.color, "green");
    assert.ok(!out.includes("evil"));
  });

  it("uses the first run when given several and appends nothing", () => {
    const out = renderShields([failed, run({ core: "A", db: "A" })], opts);
    assert.equal(JSON.parse(out).message, "no badge: server failed");
  });
});

describe("renderBadge", () => {
  const svg = renderBadge([run({ core: "A", db: ["B", true], fs: "A" })], opts);
  const s = parseXml(svg);

  it("is valid XML with a title and an aria-label, and no script or external reference", () => {
    assert.equal(s.name, "svg");
    const full = "sealmark 0.2-draft: core A · db B* · fs A · self-reported";
    assert.equal(s.attrs.role, "img");
    assert.equal(s.attrs["aria-label"], full);
    assert.equal(kids(s, "title")[0].text, full);
    assert.ok(!/<script/i.test(svg));
    assert.ok(!/(href|src)=|url\(http|@import|https?:\/\/(?!www\.w3\.org)/i.test(svg), "no external reference");
    assert.ok(svg.endsWith("</svg>\n"));
    assert.ok(!svg.includes("evil"), "the server name never reaches the image");
  });

  it("widths are integers and the two rects add up to the total", () => {
    const total = Number(s.attrs.width);
    assert.ok(Number.isInteger(total));
    assert.equal(s.attrs.height, "20");
    const rects = kids(kids(s, "g")[0], "rect").slice(0, 2);
    const [l, r] = rects;
    assert.equal(l.attrs.fill, "#555");
    assert.equal(r.attrs.fill, "#97ca00");
    const lw = Number(l.attrs.width);
    const rw = Number(r.attrs.width);
    assert.ok(Number.isInteger(lw) && Number.isInteger(rw));
    assert.equal(lw + rw, total);
    assert.equal(Number(r.attrs.x), lw);
    const label = "sealmark 0.2-draft";
    const message = "core A · db B* · fs A · self-reported";
    assert.equal(lw, 10 + Math.ceil(label.length * 6.5));
    assert.equal(rw, 10 + Math.ceil(message.length * 6.5));
  });

  it("the right side takes its colour from the colour map", () => {
    const fills: Record<string, string> = { brightgreen: "#4c1", green: "#97ca00", yellow: "#dfb317", orange: "#fe7d37", red: "#e05d44", lightgrey: "#9f9f9f" };
    const cases: [RunResult | FailedRun, string][] = [
      [run({ core: "A", db: "A" }), "brightgreen"],
      [run({ core: "A", db: "C" }), "yellow"],
      [run({ core: "A", db: "D" }), "orange"],
      [run({ core: "F", db: "A" }), "red"],
      [run({ core: "A" }, { badge: { eligible: false, reason: "core-only run: x" } }), "lightgrey"],
      [failed, "lightgrey"],
    ];
    for (const [r, c] of cases) assert.ok(renderBadge([r], opts).includes(`fill="${fills[c]}"`), c);
  });

  it("a failed or ineligible run draws the words and no letter", () => {
    for (const r of [failed, run({ core: "A", db: "A" }, { badge: { eligible: false, reason: "custom run: x" } })]) {
      const t = parseXml(renderBadge([r], opts));
      assert.match(t.attrs["aria-label"], /^sealmark 0\.2-draft: no badge: (server failed|custom run)$/);
    }
  });

  it("is deterministic", () => {
    const r = run({ core: "A", db: ["B", true] });
    assert.equal(renderBadge([r], opts), renderBadge([r], opts));
  });
});

describe("badge and shields on the command line", () => {
  it("--format shields --out writes the endpoint document; a core-only run says core only", () => {
    const sub = mkdtempSync(join(dir, "shields-"));
    const out = join(sub, "b.json");
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), ...STD, "--format", "shields", "--out", out], sub);
    assert.equal(r.code, 0, r.err);
    const j = JSON.parse(readFileSync(out, "utf8"));
    assert.deepEqual(j, { schemaVersion: 1, label: `sealmark ${METHODOLOGY}`, message: "no badge: core only", color: "lightgrey" });
  });

  it("--format badge --out writes an SVG that parses and shows no letter and no server name", () => {
    const sub = mkdtempSync(join(dir, "svg-"));
    const out = join(sub, "b.svg");
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), ...STD, "--format", "badge", "--out", out], sub);
    assert.equal(r.code, 0, r.err);
    const text = readFileSync(out, "utf8");
    const s = parseXml(text);
    assert.equal(s.name, "svg");
    assert.equal(s.attrs["aria-label"], `sealmark ${METHODOLOGY}: no badge: core only`);
    assert.ok(!text.includes("cli-test"), "the server name is not in the image");
  });

  it("a custom run (--pack core is not the standard pack list) gets no letter", () => {
    const sub = mkdtempSync(join(dir, "custom-"));
    const out = join(sub, "c.json");
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), ...FAST, "--format", "shields", "--out", out], sub);
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(readFileSync(out, "utf8")).message, "no badge: custom run");
  });

  it("--format badge,json writes both into ./sealmark-report with the FORMAT_EXT names", () => {
    const sub = mkdtempSync(join(dir, "multi-"));
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), ...FAST, "--format", "badge,json"], sub);
    assert.equal(r.code, 0, r.err);
    parseXml(readFileSync(join(sub, "sealmark-report", "sealmark-report.badge.svg"), "utf8"));
    JSON.parse(readFileSync(join(sub, "sealmark-report", "sealmark-report.json"), "utf8"));
  });

  it("--format shields,badge --out-dir writes sealmark-report.shields.json and .badge.svg there", () => {
    const sub = mkdtempSync(join(dir, "outdir-"));
    mkdirSync(join(sub, "o"));
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), ...FAST, "--format", "shields,badge", "--out-dir", "o"], sub);
    assert.equal(r.code, 0, r.err);
    assert.ok(existsSync(join(sub, "o", "sealmark-report.shields.json")));
    assert.ok(existsSync(join(sub, "o", "sealmark-report.badge.svg")));
  });

  it("two servers with --format badge exit 2 with the wiring message", () => {
    const sub = mkdtempSync(join(dir, "two-"));
    const cfg = writeYaml("two.yaml", `schema_version: 1\nname: two\nversion: 1.0.0\nservers:\n  a:\n    ${srv("nosql")}\n  b:\n    ${srv("nosql")}\n`);
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "badge"], sub);
    assert.equal(r.code, 2);
    assert.match(r.err, /the badge and shields formats take one server; run with --server <name>/);
  });
});
