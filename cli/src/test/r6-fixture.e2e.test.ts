// The full matrix of the design notes through runHarness: every broken mode and near miss of the scoped toy, graded with the
// example config (fixtures/config/scoped-http.yaml) and nothing else. Each mode must be caught by exactly the checks its row names: every
// check that does not pass (fail, part or inconclusive) is listed, so a mode that trips a neighbouring check, or a near miss that fails
// something, breaks the row.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig, toSealmarkConfig, type EffectiveConfig } from "../config/index.js";
import { runHarness } from "../run.js";
import { SCOPED_TOY_MODES, type ScopedToyMode } from "../toy/scoped-http.js";
import type { PackId, RunResult, Verdict } from "../types.js";
import { freePort, quiet } from "./helpers.js";

const FIXTURE = fileURLToPath(new URL("../../src/test/fixtures/config/scoped-http.yaml", import.meta.url));
const TOY = fileURLToPath(new URL("../toy/scoped-http.js", import.meta.url));

interface Expect {
  pack: PackId;
  check: string;
  verdict: Verdict;
}
interface Row {
  mode: ScopedToyMode;
  /** The check that must catch the mode (broken) or that must pass despite it (near miss). */
  expect: Expect[];
  why: string;
  /** Other checks the same one defect is expected to trip (each with the reason); nothing else may be anything but pass or n/a. */
  also?: Expect[];
}
const E = (pack: string, check: string, verdict: Verdict): Expect => ({ pack: pack as PackId, check, verdict });

/** Section 6, both tables, one entry per row. */
export const ROWS: Row[] = [
  // ---- broken modes: the check that must catch each ----
  { mode: "scope-first-ref", expect: [E("sql-guard", "sql-guard-references", "fail")], why: "only the first table reference is checked" },
  { mode: "scope-prefix-loose", expect: [E("scope", "scope-escape", "fail")], why: "prefix-abuse" },
  { mode: "scope-container", expect: [E("scope", "scope-escape", "fail")], why: "container" },
  { mode: "scope-partial", expect: [E("scope", "scope-escape", "fail")], why: "partial" },
  { mode: "scope-encoded", expect: [E("scope", "scope-escape", "fail")], why: "separator-encoded" },
  { mode: "guard-fail-open", expect: [E("sql-guard", "sql-guard-statements", "fail")], why: "unparseable, unbalanced" },
  { mode: "guard-first-keyword", expect: [E("sql-guard", "sql-guard-statements", "fail")], why: "cte-dml, stacked, terminator" },
  { mode: "guard-comment-strip", expect: [E("sql-guard", "sql-guard-statements", "fail")], why: "obfuscated" },
  { mode: "rowcap-missing", expect: [E("sql-guard", "sql-guard-rowcap", "fail")], why: "no cap at the wire, then a huge LIMIT forwarded" },
  { mode: "rowcap-passthrough", expect: [E("sql-guard", "sql-guard-rowcap", "fail")], why: "the client's larger LIMIT is kept" },
  { mode: "bytecap-missing", expect: [E("custom", "custom-byte-cap", "fail")], why: "rule big-reply-capped (expect.response.max_bytes)" },
  { mode: "agg-raw-rows", expect: [E("custom", "custom-aggregate-only", "fail")], why: "rule agg-never-rows (token_echoed)" },
  { mode: "cred-static", expect: [E("upstream", "upstream-credential", "fail")], why: "static credential" },
  { mode: "cred-swap", expect: [E("upstream", "upstream-credential", "fail")], why: "the other identity's token" },
  { mode: "cred-logged", expect: [E("upstream", "log-secret", "fail")], why: "Authorization on stderr" },
  // The bearers are in the core secret-echo scan list (design seam S9), so an echoed token is a secret-echo finding as well.
  { mode: "cred-echoed", expect: [E("upstream", "upstream-credential-echo", "fail")], also: [E("core", "secret-echo", "fail")], why: "token in replies" },
  { mode: "err-leak", expect: [E("upstream", "upstream-error-leak", "fail")], why: "backend error body relayed raw" },
  { mode: "no-timeout", expect: [E("upstream", "upstream-slow", "fail")], why: "waits for the backend forever" },
  { mode: "deadend", expect: [E("core", "refusal-quality", "fail")], why: "every refusal is forbidden (advisory)" },
  { mode: "prompt-leftover", expect: [E("core", "instructions-hygiene", "fail")], why: "export_csv (clause 1) and the deny pattern (clause 2)" },
  { mode: "origin-open", expect: [E("http", "http-origin", "fail")], why: "no Host/Origin check (existing check)" },
  // ---- near misses: must pass the check they neighbour ----
  { mode: "strict-case", expect: [E("scope", "scope-escape", "pass")], why: "upper-case spelling refused: pass with the note" },
  { mode: "limit-subquery", expect: [E("sql-guard", "sql-guard-rowcap", "pass")], why: "outer FETCH FIRST instead of LIMIT" },
  { mode: "comment-ok", expect: [E("sql-guard", "sql-guard-statements", "pass")], why: "a comment is not a statement" },
  {
    mode: "refuse-all",
    expect: [E("scope", "scope-escape", "inconclusive"), E("sql-guard", "sql-guard-statements", "inconclusive"), E("sql-guard", "sql-guard-references", "inconclusive")],
    // Nothing reaches the stub, so the other stub checks cannot be judged either; the custom rules expect a working call, and a
    // one-sentence refusal routes nowhere.
    also: [
      E("sql-guard", "sql-guard-rowcap", "inconclusive"),
      E("upstream", "upstream-credential", "inconclusive"),
      E("upstream", "upstream-error-leak", "inconclusive"),
      E("upstream", "upstream-slow", "inconclusive"),
      E("custom", "custom-aggregate-only", "fail"),
      E("custom", "custom-submitter-tag", "fail"),
      E("core", "refusal-quality", "fail"),
    ],
    why: "every control fails, so nothing may pass",
  },
  // The near miss serves anonymous callers, which is what http-auth grades.
  { mode: "anon-upstream-no-auth", expect: [E("upstream", "upstream-credential", "pass")], also: [E("http", "http-auth", "fail")], why: "the anonymous leg reaches the backend with no credential header" },
];

const GOOD_PACKS = ["core", "http", "scope", "sql-guard", "upstream", "custom"];
const GOOD_CHECKS = ["scope-escape", "sql-guard-statements", "sql-guard-references", "sql-guard-rowcap", "upstream-credential", "upstream-credential-echo", "log-secret", "upstream-error-leak", "upstream-slow", "refusal-quality", "instructions-hygiene"];

async function runMode(mode: ScopedToyMode): Promise<RunResult> {
  const port = await freePort();
  const dir = mkdtempSync(join(tmpdir(), "sm-r6-e2e-"));
  try {
    const text = readFileSync(FIXTURE, "utf8").replaceAll("dist/toy/scoped-http.js", TOY).replaceAll("8080", String(port)).replace('"--mode", "good"', `"--mode", "${mode}"`);
    writeFileSync(join(dir, "sealmark.yaml"), text);
    const cfg: EffectiveConfig = loadEffectiveConfig({ cwd: dir, isolated: true, env: {} });
    return await runHarness({ config: toSealmarkConfig(cfg), effective: cfg, packs: cfg.packs as PackId[], packsExplicit: cfg.packsExplicit, timeoutProbeSec: cfg.timeoutProbeSec, log: quiet });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const find = (r: RunResult, e: Expect) => r.checks.find((c) => c.pack === e.pack && c.id === e.check);
/** Every check of the run whose verdict is neither pass nor n/a, as pack/id=verdict, sorted. */
const notPassing = (r: RunResult): string[] => r.checks.filter((c) => c.verdict !== "pass" && c.verdict !== "na").map((c) => `${c.pack}/${c.id}=${c.verdict}`).sort();

describe("round 6 fixture matrix (section 6)", { timeout: 1_800_000 }, () => {
  it("enumerates every non-good mode of the toy exactly once: 21 broken modes and 5 near misses", () => {
    const modes = ROWS.map((r) => r.mode);
    assert.equal(new Set(modes).size, modes.length);
    assert.deepEqual([...modes].sort(), SCOPED_TOY_MODES.filter((m) => m !== "good").sort());
    assert.equal(modes.length, 26);
  });

  it("good: core, http, scope, sql-guard, upstream and custom grade A; every candidate check passes", { timeout: 300_000 }, async () => {
    const r = await runMode("good");
    for (const p of GOOD_PACKS) {
      const pk = r.packs[p as PackId];
      assert.equal(pk?.status === "graded" ? pk.grade?.letter : pk?.status, "A", `pack ${p}`);
    }
    for (const id of GOOD_CHECKS) {
      const c = r.checks.find((x) => x.id === id);
      assert.equal(c?.verdict, "pass", `${id}: ${c?.summary}`);
    }
    for (const p of ["fs", "git", "sqlite"]) assert.equal(r.packs[p as PackId]?.status, "na", `pack ${p}`);
    assert.deepEqual(notPassing(r), [], "good: every check passes or is n/a");
  });

  for (const row of ROWS) {
    it(`${row.mode}: ${row.expect.map((e) => `${e.check} ${e.verdict}`).join(", ")} (${row.why})`, { timeout: 300_000 }, async () => {
      const r = await runMode(row.mode);
      for (const e of row.expect) assert.equal(find(r, e)?.verdict, e.verdict, `${e.pack}/${e.check}: ${find(r, e)?.summary}`);
      // Exactly these: the expected catches plus the listed neighbours, and nothing else.
      const want = [...row.expect, ...(row.also ?? [])].filter((e) => e.verdict !== "pass").map((e) => `${e.pack}/${e.check}=${e.verdict}`).sort();
      assert.deepEqual(notPassing(r), want, `${row.mode}: the checks that did not pass`);
    });
  }
});
