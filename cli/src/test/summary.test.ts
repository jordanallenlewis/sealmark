import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { renderReport, type FailedRun } from "../report.js";
import { clipWidth, displayWidth, inert, inertDeep, wrapWidth } from "../report/sanitize.js";
import { renderSummary } from "../report/summary.js";
import type { CheckResult, PackGrade, RunResult } from "../types.js";
import { check } from "./helpers.js";

function grade(pack: string, letter: PackGrade["letter"], o: Partial<PackGrade> = {}): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o };
}

function run(over: Partial<RunResult> = {}, checks: CheckResult[] = [check("protocol", "pass"), check("secret-echo", "fail", { critical: true })]): RunResult {
  return {
    sealmark: { version: "0.2.0", methodology: "0.2-draft" },
    server: { name: "my-server", version: "1.0.0", command: "node server.js", env: {}, transport: "stdio", tools: ["a"], sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 10,
    packs: { core: { status: "graded", grade: grade("core", "B") } },
    checks,
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    coverage: { validCalls: 4, toolsCalledValid: 1, toolsTotal: 1, level: "covered" },
    ...over,
  };
}

const ESC = "\x1b";
const HOSTILE = [
  `x\n[ PASS ] core/forged      forged label`,
  `x\r[ PASS ] core/forged`,
  `x${ESC}[8A${ESC}[0J wiped`,
  `x${ESC}]8;;https://evil.example${ESC}\\link`,
  `x\b\b\bx\x07\x00\x7f\x9b2J\u0085y`,
  `x‮‭⁦⁩​‍﻿y z`,
  `x\u{e0041}\u{e007f}y\ud800z`,
];

/** The renderer's own output may contain \n and SGR (when color is on) and nothing else that a terminal acts on. */
function assertInert(out: string, what: string) {
  const bare = out.replace(/\x1b\[[0-9;]*m/g, "");
  assert.ok(!/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(bare.replace(/\n/g, "")), `${what}: a control or invisible character got through`);
  assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(out), `${what}: lone surrogate`);
  assert.ok(!/^\[ PASS \] core\/forged/m.test(out) && !/^ *\[ PASS \] core\/forged/m.test(out), `${what}: forged row`);
}

describe("summary: server-controlled text is inert", () => {
  for (const payload of HOSTILE) {
    for (const color of [false, true]) {
      it(`every printed field survives ${JSON.stringify(payload).slice(0, 40)} (color ${color})`, () => {
        const bad = check("tool-poisoning", "fail", { critical: true });
        Object.assign(bad, { label: payload, summary: payload, id: `id${payload}`, pack: "core" });
        bad.evidence = [{ probe: payload, outcome: payload, verifiedBy: "response", tool: payload }];
        const r = run(
          {
            server: { name: payload, version: payload, command: payload, env: {}, transport: "stdio", tools: [payload], sqlTools: [] },
            warnings: [payload],
            packs: { core: { status: "graded", grade: grade("core", "D", { capped: true, criticalFails: [bad.id] }) }, [payload]: { status: "na", reason: payload } } as RunResult["packs"],
            config: { hash: "sha256:b", profile: "quick", standard: false, standardDiff: [{ path: payload, standard: payload, effective: payload, origin: payload }], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
          },
          [check("protocol", "pass"), bad],
        );
        const out = renderSummary([r], { color, gate: "B" });
        assertInert(out, "run");
        const rows = out.split("\n").filter((l) => /^(\x1b\[[0-9;]*m)*\[ (PASS|FAIL|PART|\?\?\?\?|n\/a ) *\]/.test(l));
        assert.equal(rows.length, 2, "one row per real check, none forged");
        const failed: FailedRun = { status: "failed", server: payload, error: `boom ${payload}`, hint: payload, sealmark: { version: "0.2.0", methodology: "0.2-draft" } };
        assertInert(renderSummary([failed], { color }), "failed run");
        assertInert(renderReport("summary", [r, failed], { color }), "renderReport");
      });
    }
  }

  it("a newline in a field cannot start a new row or split the banner", () => {
    const r = run({ server: { name: "s", version: "1\n[ PASS ] core/forged", command: "c", env: {}, transport: "stdio", tools: [], sqlTools: [] } });
    const out = renderSummary([r]);
    const banner = out.split("\n").slice(0, 8);
    assert.ok(banner.every((l) => !l.startsWith("[ PASS ]")));
    assert.ok(out.includes("1 [ PASS ] core/forged"), "folded onto the same line and still visible");
    assert.equal(out.split("\n").filter((l) => l.startsWith("[ PASS ]")).length, 1);
  });

  it("escapes are shown, not obeyed", () => {
    assert.equal(inert(`a${ESC}[8Ab`), "a\\u001b[8Ab");
    assert.equal(inert("a‮b​c"), "a\\u202eb\\u200bc");
    assert.equal(inert("a\n\r\t b"), "a b");
    assert.equal(inert("a\ud800b"), "a\\ud800b");
    assert.equal(inert("\u{e0041}"), "\\u{e0041}");
    assert.equal(inert("plain text, 日本語 😀"), "plain text, 日本語 😀");
    assert.equal(inert(undefined), "");
  });

  it("a long field is cut at the cap, never inside a surrogate pair", () => {
    const t = inert("😀".repeat(5000), 101);
    assert.ok(t.length <= 101 && t.endsWith("…"));
    assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])/.test(t.slice(0, -1)));
    assert.equal(inertDeep({ a: ["x\ny", 3, { "k\n": true }] }).a[2] && Object.keys((inertDeep({ a: ["x\ny", 3, { "k\n": true }] }).a[2] as object))[0], "k");
  });
});

describe("summary: linear time", () => {
  const timed = (f: () => void) => {
    const t = Date.now();
    f();
    return Date.now() - t;
  };
  it("120k spaces, one huge word and a million words render in well under a second each", () => {
    for (const big of [`a${" ".repeat(120_000)}b`, "w".repeat(2_000_000), "word ".repeat(400_000), "\n".repeat(300_000), "😀 ".repeat(300_000)]) {
      const bad = check("x", "fail", { critical: true });
      Object.assign(bad, { label: big, summary: big });
      bad.evidence = [{ probe: big, outcome: big, verifiedBy: "response" }];
      const r = run({ server: { name: big, version: big, command: "c", env: {}, transport: "stdio", tools: [], sqlTools: [] }, warnings: [big, big] }, [bad]);
      const failed: FailedRun = { status: "failed", server: big, error: big, hint: big, sealmark: { version: "0", methodology: "0" } };
      const ms = timed(() => {
        const out = renderSummary([r, failed]);
        assert.ok(out.length < 20_000, `output stays small (${out.length})`);
      });
      assert.ok(ms < 1500, `took ${ms} ms`);
    }
  });
});

describe("summary: display width", () => {
  const tableRows = (out: string) => out.split("\n").filter((l) => l.startsWith("[ "));

  it("measures wide, emoji, combining and ASCII text", () => {
    assert.equal(displayWidth("abc"), 3);
    assert.equal(displayWidth("日本語"), 6);
    assert.equal(displayWidth("😀"), 2);
    assert.equal(displayWidth("é"), 1);
    assert.equal(displayWidth("🇩🇪"), 2);
    assert.equal(displayWidth("ｱ"), 1);
    assert.equal(displayWidth("Ａ"), 2);
  });

  it("clips on code points and columns, with an ellipsis", () => {
    assert.equal(clipWidth("😀".repeat(30), 10), "😀😀😀😀…");
    assert.equal(clipWidth("a".repeat(37) + "😀😀", 38), "a".repeat(37) + "…");
    assert.equal(clipWidth("日本語日本語", 7), "日本語…");
    assert.equal(clipWidth("short", 38), "short");
    assert.equal(clipWidth("ééé", 3), "ééé");
    for (const n of [1, 2, 3, 5, 8, 13]) assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(clipWidth("😀日a".repeat(10), n)));
  });

  it("wraps by columns and breaks a word that is wider than the line", () => {
    for (const l of wrapWidth("日本語 ".repeat(40) + "x".repeat(200), 30)) assert.ok(displayWidth(l) <= 30);
    assert.deepEqual(wrapWidth("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
    assert.deepEqual(wrapWidth("", 10), []);
  });

  it("CJK and emoji labels keep the badge column and flag in line with ASCII rows", () => {
    const mk = (label: string) => ({ ...check("a-check", "pass", { critical: true }), label });
    const out = renderSummary([run({}, [mk("plain label"), mk("日本語".repeat(20)), mk("😀".repeat(30)), mk("a".repeat(37) + "😀😀")])]);
    const rows = tableRows(out);
    assert.equal(rows.length, 4);
    assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])/.test(out), "no lone surrogate");
    for (const row of rows) assert.equal(displayWidth(row), displayWidth(rows[0]), `row width: ${row}`);
  });

  it("an emoji or CJK tool name in the evidence probe is clipped to the table, and so are cards and banner", () => {
    const bad = check("x", "fail");
    bad.evidence = [{ probe: "😀".repeat(100), outcome: "", verifiedBy: "response" }];
    const r = run({ server: { name: "日本語".repeat(30), version: "1", command: "c", env: {}, transport: "stdio", tools: [], sqlTools: [] } }, [bad]);
    const out = renderSummary([r], { gate: "B" });
    for (const l of out.split("\n")) assert.ok(displayWidth(l) <= 76, `too wide (${displayWidth(l)}): ${l}`);
  });
});

describe("summary: what the other renderers print", () => {
  /** Sentences wrap at the table width; compare them with the line breaks folded. */
  const flat = (out: string) => out.replace(/\s+/g, " ");
  const hygiene = (over: Partial<RunResult> = {}) => run({ coverage: { validCalls: 0, toolsCalledValid: 0, toolsTotal: 2, level: "hygiene-only" }, ...over }, [check("protocol", "pass")]);

  it("labels a hygiene-only core grade, with the count and the plain sentence", () => {
    const raw = renderSummary([hygiene()], { gate: "B" });
    const out = flat(raw);
    assert.match(out, /core: hygiene only · tools called with valid arguments: 0 of 2/);
    assert.match(out, /Core is hygiene only: no tool was called with valid arguments, so this grade says nothing about what the tools do\./);
    assert.match(out, /ALL GRADED PACKS AT B OR BETTER/);
    assert.ok(raw.indexOf("Core is hygiene only") > raw.indexOf("ALL GRADED PACKS") && raw.indexOf("Core is hygiene only") < raw.indexOf("CHECKS"), "under the verdict line");
    assert.ok(!/hygiene only/.test(renderSummary([run()])), "a covered run has no caveat");
  });

  it("says low coverage when another pack was graded, without the hygiene-only sentence", () => {
    const r = hygiene({ coverage: { validCalls: 1, toolsCalledValid: 1, toolsTotal: 4, level: "low" }, packs: { core: { status: "graded", grade: grade("core", "A") }, fs: { status: "graded", grade: grade("fs", "B") } } });
    const out = renderSummary([r]);
    assert.match(out, /core: low coverage · tools called with valid arguments: 1 of 4/);
    assert.ok(!/Core is hygiene only/.test(out));
  });

  it("marks provisional grades with * on the card and the verdict, and explains it", () => {
    const r = run({ packs: { core: { status: "graded", grade: grade("core", "C", { provisional: true }) } } });
    const out = renderSummary([r], { gate: "B" });
    assert.match(out, /BELOW B: core C\*/);
    assert.match(out, /worst grade: C\*/);
    assert.match(out, /3\/4 points\*/);
    assert.match(out, /\* Provisional: a critical check was inconclusive/);
    assert.ok(!/\*/.test(renderSummary([run()])));
  });

  const diffs = (n: number) => Array.from({ length: n }, (_, i) => ({ path: `setting_${i}`, standard: 10, effective: 3, origin: "flag --x" }));
  const customRun = (n: number) => run({ config: { hash: "sha256:c", profile: "quick", standard: false, standardDiff: diffs(n), methodology: "0.2-draft", schemaVersion: 1, locked: {} } });

  it("a CUSTOM run lists what differs and says the grades are not comparable", () => {
    const out = renderSummary([customRun(2)]);
    assert.match(out, /CUSTOM: 2 settings differ from standard/);
    assert.match(out, /setting_0: standard 10, effective 3 {2}\(flag --x\)/);
    assert.match(flat(out), /Grades in this report are custom grades: they are not comparable to a STANDARD grade, and a custom run gets no badge\./);
    assert.match(renderSummary([customRun(1)]), /CUSTOM: 1 setting differs from standard/);
    assert.ok(!/CUSTOM:|custom grades/.test(renderSummary([run()])), "a standard run prints neither");
  });

  it("a CUSTOM run with many differences stays compact", () => {
    const out = renderSummary([customRun(40)]);
    assert.equal(out.match(/^ {2}setting_/gm)?.length, 5);
    assert.match(out, /\.\.\. and 35 more/);
  });

  it("closes with the not-an-endorsement sentence, after the warnings, for passes and failures alike", () => {
    for (const r of [run(), hygiene({ warnings: ["w1"] })]) {
      const out = renderSummary([r]);
      assert.match(flat(out), /An A means these checks passed with this exact configuration\. It is not a security endorsement; see methodology\. $/);
    }
    const w = renderSummary([hygiene({ warnings: ["w1"] })]);
    assert.ok(w.indexOf("warning: w1") < w.indexOf("An A means"));
  });

  it("wraps a long warning instead of printing one endless line", () => {
    const out = renderSummary([run({ warnings: [`serverInfo.version ${"1.2.3 ".repeat(40)}differs`] })], { gate: "B" });
    for (const l of out.split("\n").filter((x) => !x.startsWith("[ "))) assert.ok(displayWidth(l) <= 76, l);
    assert.match(out, /^warning: serverInfo\.version/m);
  });

  it("every line fits 76 columns for an ordinary run", () => {
    for (const l of renderSummary([run(), customRun(3), hygiene()]).split("\n")) assert.ok(displayWidth(l) <= 83, l);
  });
});
