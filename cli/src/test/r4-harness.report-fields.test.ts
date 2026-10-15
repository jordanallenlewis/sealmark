import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { MAX_GAP_LINES, badgeFor, capabilityGaps, runHarness } from "../run.js";
import type { CheckResult, ConfigIntegrity, PackId, RunResult } from "../types.js";
import { q } from "./helpers.js";

// What the harness puts into the result for the report to print: the inherited environment, the configuration line, the "Not covered" lines (E6, E8, E9, E11).
const DUAL = fileURLToPath(new URL("../toy/dual-class.js", import.meta.url));
const NET = fileURLToPath(new URL("../toy/net.js", import.meta.url));

let dir: string;
let parent: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r4-fields-"));
  parent = join(dir, "sandboxes");
  mkdirSync(parent);
});
after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

async function runFile(name: string, serverArgs: string[], packs: string[] = ["core"]): Promise<{ r: RunResult; file: string }> {
  const file = join(dir, `${name}.yaml`);
  writeFileSync(file, `schema_version: 1\nname: ${name}\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: ${q(serverArgs)}\nsandbox:\n  dir: ${q(parent)}\n`);
  const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file, pack: packs }, env: {}, isolated: true });
  const r = await runHarness({ config: { name: eff.name, version: eff.version, server: eff.server }, effective: eff, packs: eff.packs as PackId[], packsExplicit: eff.packsExplicit, timeoutProbeSec: 2, log: () => {} });
  return { r, file };
}

describe("r4-harness: the sandbox's inherited list and the configuration line are in the result (E8, E11)", { timeout: 120_000 }, () => {
  it("sandbox.inherited names what the server inherited, and never a value", async () => {
    const { r } = await runFile("inherited", [DUAL]);
    const inherited = r.sandbox?.inherited;
    assert.ok(inherited && inherited.length > 0, JSON.stringify(r.sandbox));
    assert.ok(inherited.includes("PATH (system part)"));
    assert.ok(inherited.includes("LANG"));
    for (const x of inherited) assert.ok(!/[=/\\]/.test(x.replace("PATH (system part)", "")), `a name, not a value or a path: ${x}`);
  });

  it("config.line is the line of the server's command in the file", async () => {
    const { r } = await runFile("line", [DUAL]);
    // schema_version, name, version, server:, command: is the fifth line.
    assert.equal(r.config?.line, 5);
  });

  it("a run that loaded no file has no line", async () => {
    const r = await runHarness({ config: { name: "nofile", version: "0.0.1", server: { command: process.execPath, args: [DUAL], env: {} } }, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: () => {} });
    assert.equal(r.config, undefined);
  });
});

describe("r4-harness: Not covered says what was left out (E6)", { timeout: 120_000 }, () => {
  it("a tool with a secondary class that no pack consumed is named, and the capability-gated tools line is there", async () => {
    const { r } = await runFile("dual", [DUAL]);
    assert.deepEqual(r.classification?.find((c) => c.tool === "download")?.secondary, ["url"], "the toy is a path tool with a url secondary");
    assert.ok(r.notCovered.includes('tool "download" also looks like a url tool (secondary class); only its primary class (path) was probed'), r.notCovered.join("\n"));
    assert.ok(r.notCovered.includes("tools that a server lists only for clients that declare roots, sampling or elicitation capabilities are not seen: the harness declares none"));
  });

  it("near-miss: a tool with no secondary class gets no such line (the capability line stays)", async () => {
    const { r } = await runFile("plain-net", [NET, "--mode", "good"]);
    assert.ok(!r.notCovered.some((l) => /secondary class/.test(l)), r.notCovered.join("\n"));
    assert.ok(r.notCovered.some((l) => /roots, sampling or elicitation/.test(l)));
  });

  const gap = (pack: PackId, tool: string, reason: string): CheckResult => ({
    id: `${pack}-x`,
    pack,
    label: "x",
    critical: false,
    scope: "server",
    verdict: "pass",
    summary: "s",
    evidence: [],
    coverage: { probed: [], notCovered: [{ tool, reason }], validCalls: 0 },
  });

  it("capabilityGaps: one line per tool (the first reason wins), skipping tools already named, bounded with a count", () => {
    const checks = [gap("fs", "a", "no path parameter"), gap("git", "a", "not a repository"), gap("net", "b", "no url parameter"), gap("core", "c", "core is not listed here"), gap("effects", "d", "declared writer tool")];
    // "declared writer tool" notes are not gaps (coverageNotes leaves them out); core is not one of the packs listed.
    assert.deepEqual(capabilityGaps(checks), ['tool "a" was not covered by the fs pack: no path parameter', 'tool "b" was not covered by the net pack: no url parameter']);
    assert.deepEqual(capabilityGaps(checks, new Set(["a"])), ['tool "b" was not covered by the net pack: no url parameter']);

    const many = Array.from({ length: MAX_GAP_LINES + 3 }, (_, i) => gap("fs", `t${i}`, "no path parameter"));
    const out = capabilityGaps(many);
    assert.equal(out.length, MAX_GAP_LINES + 1);
    assert.match(out.at(-1)!, /^3 more tool gaps/);
    assert.deepEqual(capabilityGaps(many.slice(0, MAX_GAP_LINES)).length, MAX_GAP_LINES, "exactly the bound: no count line");
  });
});

describe("r4-harness: the core-only badge reason says what it means (E9)", () => {
  const STANDARD: ConfigIntegrity = { hash: "h", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} };
  it("core graded alone: no capability pack was graded", () => {
    assert.deepEqual(badgeFor(STANDARD, { core: { status: "graded" } }), { eligible: false, reason: "core-only run: no capability pack was graded" });
  });
});
