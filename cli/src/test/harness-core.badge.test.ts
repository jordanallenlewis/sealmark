// A badge shows letters a reader will trust, so it is withheld when a grade rests on a critical check nobody could measure.
// A plain grade of any letter stays eligible: the badge shows the per-pack letters, so a low one is honest.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { badgeFor, legacyEffectiveConfig, runHarness } from "../run.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, PackGrade, RunResult } from "../types.js";
import { check, quiet, toyConfig } from "./helpers.js";

let dir: string;
let parent: string;

const STANDARD: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

const grade = (letter: PackGrade["letter"], provisional = false): PackGrade => ({ pack: "fs", points: 1, scored: 1, pct: 100, raw: letter, letter, capped: false, criticalFails: [], provisional, excluded: [] });
const graded = (letter: PackGrade["letter"], provisional = false) => ({ status: "graded" as const, grade: grade(letter, provisional) });

describe("harness-core: badgeFor", () => {
  it("a provisional grade in any graded pack withholds the badge, with the reason", () => {
    const out = badgeFor(STANDARD, { core: graded("A"), fs: graded("A", true) });
    assert.deepEqual(out, { eligible: false, reason: "a pack is provisional: a critical check was inconclusive" });
  });

  it("an inconclusive critical check in a pack that was not graded withholds it too; an advisory one does not", () => {
    const packs = { core: graded("A"), fs: graded("A"), net: { status: "inconclusive" as const, reason: "the control failed" } };
    const critical = check("net-caps", "inconclusive", { critical: true, pack: "net" });
    assert.deepEqual(badgeFor(STANDARD, packs, [critical]), { eligible: false, reason: "a pack has an inconclusive critical check" });
    const advisory = check("net-note", "inconclusive", { critical: true, advisory: true, pack: "net" });
    assert.deepEqual(badgeFor(STANDARD, packs, [advisory, check("net-x", "inconclusive", { pack: "net" })]), { eligible: true });
  });

  it("near-miss: a plain grade of any letter stays eligible, a D included", () => {
    for (const letter of ["A", "B", "D", "F"] as const) assert.deepEqual(badgeFor(STANDARD, { core: graded("A"), fs: graded(letter) }, [check("fs-x", "fail", { pack: "fs" })]), { eligible: true }, letter);
  });

  it("the earlier reasons come first: a custom run and a core-only run say so, not 'provisional'", () => {
    assert.match(badgeFor({ ...STANDARD, standard: false }, { core: graded("A"), fs: graded("A", true) }).reason ?? "", /^custom run/);
    assert.match(badgeFor(STANDARD, { core: graded("A", true) }).reason ?? "", /^core-only run/);
  });
});

const plugin = (id: string, checks: [string, boolean, string][]) => `export default {
  id: "plugin:${id}", version: "1.0.0", sealmark: "*",
  describe: () => [${checks.map(([cid, critical]) => `{ id: "${cid}", pack: "plugin:${id}", label: "Probe", critical: ${critical}, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }`).join(", ")}],
  applies: () => ({ ok: true }),
  run: async (ctx) => [${checks.map(([cid, critical, verdict]) => `ctx.helpers.done({ id: "${cid}", label: "Probe", critical: ${critical}, scope: "server (test)" }, "${verdict}", "ran", [])`).join(", ")}],
};`;

describe("harness-core: a STANDARD run", { timeout: 120_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-hc-badge-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  async function runWith(name: string, checks: [string, boolean, string][]): Promise<RunResult> {
    writeFileSync(join(dir, `${name}.mjs`), plugin(name, checks));
    const base = legacyEffectiveConfig({ config: toyConfig("nosql"), packs: ["core"], packsExplicit: false, timeoutProbeSec: 2 });
    const effective: EffectiveConfig = { ...base, integrity: STANDARD, cwd: dir, plugins: [{ module: `./${name}.mjs` }], sandbox: { ...base.sandbox, dir: parent } } as EffectiveConfig;
    return runHarness({ config: toyConfig("nosql"), effective, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: quiet });
  }

  it("with a provisional non-core pack is badge-ineligible, and says why", async () => {
    const r = await runWith("provisional", [
      ["prov-a", false, "pass"],
      ["prov-critical", true, "inconclusive"],
    ]);
    const p = r.packs["plugin:provisional" as keyof typeof r.packs];
    assert.equal(p?.status === "graded" && p.grade?.provisional, true);
    assert.deepEqual(r.badge, { eligible: false, reason: "a pack is provisional: a critical check was inconclusive" });
    assert.ok(r.checks.some((c: CheckResult) => c.id === "prov-critical"));
  });

  it("with a clean A stays eligible", async () => {
    const r = await runWith("clean", [
      ["clean-a", false, "pass"],
      ["clean-critical", true, "pass"],
    ]);
    assert.deepEqual(r.badge, { eligible: true });
  });
});
