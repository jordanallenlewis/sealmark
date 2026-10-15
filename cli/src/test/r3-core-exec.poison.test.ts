import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { describe as describeCore } from "../packs/core.js";
import { scanText } from "../packs/core.js";
import type { RunResult } from "../types.js";
import { FAST, cliKit } from "./helpers.js";

const POISON_CTL = fileURLToPath(new URL("../toy/poison-ctl.js", import.meta.url));

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r3-poison-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeConfig } = cliKit(() => dir);

const tiers = (s: string) => scanText(s).map((i) => i.tier);

describe("tool-poisoning: control characters", () => {
  it("ESC, NUL and every C1 control are strong", () => {
    assert.deepEqual(tiers("red \u001b[31mtext"), ["strong"]);
    assert.deepEqual(tiers("a\u0000b"), ["strong"]);
    for (const cp of [0x80, 0x85, 0x9b, 0x9d, 0x9f]) assert.deepEqual(tiers(`a${String.fromCharCode(cp)}b`), ["strong"], `U+${cp.toString(16)}`);
    assert.match(scanText("\u001b")[0].outcome, /terminal control characters \(ESC, NUL or a C1 control\)/);
  });

  it("the other C0 controls and DEL are weak", () => {
    for (const cp of [0x01, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x1a, 0x1c, 0x1f, 0x7f]) assert.deepEqual(tiers(`a${String.fromCharCode(cp)}b`), ["weak"], `U+${cp.toString(16)}`);
    assert.match(scanText("\u0007")[0].outcome, /C0 control characters \(other than tab, newline and carriage return\) or DEL/);
  });

  it("tab, line feed, carriage return and ordinary text are clean", () => {
    assert.deepEqual(tiers("a\tb"), []);
    assert.deepEqual(tiers("line one\nline two"), []);
    assert.deepEqual(tiers("line one\r\nline two"), []);
    assert.deepEqual(tiers("plain text, with é and   and €"), []);
  });

  it("a strong control character wins over a weak one, and the hidden-Unicode rule still reports separately", () => {
    assert.deepEqual(tiers("\u0007 and \u001b"), ["strong"]);
    assert.deepEqual(tiers("\u001b and a zero width space​"), ["strong", "strong"]);
  });

  it("the England flag exemption is untouched", () => {
    assert.deepEqual(tiers("flag \u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}"), []);
  });

  it("describe() names the ranges and the deliberate-colour false positive", () => {
    const tp = describeCore().find((c) => c.id === "tool-poisoning")!;
    const strong = tp.probes.find((p) => p.id === "ctl-strong")!;
    const weak = tp.probes.find((p) => p.id === "ctl-weak")!;
    assert.equal(strong.kind, "strong");
    assert.match(strong.text, /U\+001B/);
    assert.match(strong.text, /U\+0080 to U\+009F/);
    assert.equal(weak.kind, "weak");
    assert.match(weak.text, /U\+007F/);
    assert.match(tp.falsePositive, /ANSI colour/);
  });
});

describe("tool-poisoning: control characters on toy servers", { timeout: 120_000 }, () => {
  const run = (mode: string) => {
    const cfg = writeConfig(`${mode}.yaml`, process.execPath, [POISON_CTL, "--mode", mode]);
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json"]);
    return { ...r, result: JSON.parse(r.out) as RunResult };
  };
  const poisoning = (r: RunResult) => r.checks.find((c) => c.id === "tool-poisoning")!;

  for (const [mode, verdict] of [["esc", "fail"], ["nul", "fail"], ["c1", "fail"], ["c0", "part"], ["del", "part"], ["crlf", "pass"], ["tab", "pass"]] as const) {
    it(`${mode}: tool-poisoning ${verdict}`, () => {
      const r = run(mode);
      assert.equal(poisoning(r.result).verdict, verdict, r.err);
      if (verdict === "fail") assert.ok(poisoning(r.result).evidence.some((e) => e.code === "poisoning.strong" && e.tool === "echo"));
    });
  }

  it("esc: the grade is capped at D, and the text report prints no raw ESC byte", () => {
    const r = run("esc");
    const core = r.result.packs.core;
    assert.equal(core?.status, "graded");
    assert.equal(core?.grade?.letter, "D");
    const cfg = writeConfig("esc-text.yaml", process.execPath, [POISON_CTL, "--mode", "esc"]);
    const text = sealmark(["run", "--config", cfg, ...FAST]);
    assert.ok(!text.out.includes("\u001b"), "stdout has a raw ESC byte");
    assert.ok(!text.err.includes("\u001b"), "stderr has a raw ESC byte");
    assert.match(text.out, /tool-poisoning/);
  });
});
