import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CLI, TOY, hermeticEnv } from "./helpers.js";

// Round 5, G10: a signal that lands as the last pack finishes. The signal handler sets the exit code, so the exit line must not say the gate
// was met, and the report must say it may be incomplete. A kept sandbox is `kept`, not `cleanedUp`.

const POSIX = process.platform !== "win32";
const LATE = fileURLToPath(new URL("../toy/r5-late-signal.js", import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r5-interrupt-"));
  parent = join(dir, "sandboxes");
  mkdirSync(parent);
});
after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

let n = 0;
interface Out {
  code: number | null;
  err: string;
  json?: { interrupted?: boolean; warnings?: string[]; sandbox?: { kept?: boolean; cleanedUp?: boolean; dir?: string } };
}
/** Runs the CLI on the toy and returns what it printed, its exit code and the JSON report it wrote. */
async function cli(toyArgs: string[], flags: string[] = [], script = LATE): Promise<Out> {
  const id = n++;
  const cfg = join(dir, `cfg-${id}.yaml`);
  const report = join(dir, `report-${id}.json`);
  writeFileSync(cfg, `schema_version: 1\nname: r5-interrupt\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([script, ...toyArgs])}\n`);
  const child = spawn(process.execPath, [CLI, "run", "--config", cfg, "--pack", "core", "--sandbox-dir", parent, "--format", "json", "--out", report, "--timeout-probe", "2", "--fail-under", "none", ...flags], {
    cwd: dir,
    env: hermeticEnv(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let err = "";
  child.stderr.on("data", (b: Buffer) => (err += b.toString()));
  child.stdout.on("data", () => {});
  const code = await new Promise<number | null>((res) => child.once("exit", (c) => res(c)));
  return { code, err, ...(existsSync(report) ? { json: JSON.parse(readFileSync(report, "utf8")) as Out["json"] } : {}) };
}

describe("r5-harness: an interrupt that lands as the last pack finishes", { timeout: 900_000, skip: !POSIX }, () => {
  it("the exit line says 'interrupted' with the signal's code, never 'every graded pack meets the gate', and the exit code is 130", async () => {
    const r = await cli(["--signal-parent-on-close"]);
    assert.equal(r.code, 130, r.err);
    assert.match(r.err, /sealmark exit 130: interrupted/, r.err);
    assert.ok(!/sealmark exit 0/.test(r.err), `the line contradicts the exit code:\n${r.err}`);
    const last = r.err.trimEnd().split("\n").pop()!;
    assert.match(last, /sealmark exit 130: interrupted/, "it is the last line a CI log shows");
  });

  it("the report carries interrupted: true and the warning that it may be incomplete", async () => {
    const r = await cli(["--signal-parent-on-close"]);
    assert.ok(r.json, `no report was written:\n${r.err}`);
    assert.equal(r.json.interrupted, true);
    assert.ok((r.json.warnings ?? []).includes("the run was interrupted; the report may be incomplete"), JSON.stringify(r.json.warnings));
  });

  it("near-miss: the same run with no signal exits 0, says so, and has no interrupted field", async () => {
    const r = await cli([]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /sealmark exit 0/);
    assert.ok(!/interrupted/.test(r.err), r.err);
    assert.equal(r.json?.interrupted, undefined);
    assert.ok(!(r.json?.warnings ?? []).some((w) => /interrupted/.test(w)));
  });

  it("an interrupted run with --keep-sandbox ends by naming the kept sandbox (not 'cleaned up') and the report says it was kept, not cleaned up", async () => {
    const before = new Set(readdirSync(parent));
    const r = await cli(["--signal-parent-on-close"], ["--keep-sandbox"]);
    const made = readdirSync(parent).filter((x) => !before.has(x) && x.startsWith("sealmark-"));
    try {
      assert.equal(r.code, 130, r.err);
      assert.equal(made.length, 1, "the sandbox was kept");
      const lines = r.err.trimEnd().split("\n");
      const kept = lines.filter((l) => l.startsWith("kept sandbox: "));
      assert.equal(kept.length, 1, r.err);
      assert.ok(kept[0]!.endsWith(made[0]!), `the line names the kept path: ${kept[0]}`);
      assert.ok(!/(^|\n)cleaned up\n/.test(r.err), "a kept sandbox is not 'cleaned up'");
      assert.equal(r.json?.sandbox?.kept, true);
      assert.equal(r.json?.sandbox?.cleanedUp, false, "kept is not cleaned up");
    } finally {
      for (const d of made) rmSync(join(parent, d), { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  });

  it("a plain --keep-sandbox run (no signal): cleanedUp is false, kept is true", async () => {
    const before = new Set(readdirSync(parent));
    const r = await cli(["--mode", "nosql"], ["--keep-sandbox"], TOY);
    const made = readdirSync(parent).filter((x) => !before.has(x) && x.startsWith("sealmark-"));
    try {
      assert.equal(r.json?.sandbox?.kept, true, r.err);
      assert.equal(r.json?.sandbox?.cleanedUp, false);
    } finally {
      for (const d of made) rmSync(join(parent, d), { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  });

  it("near-miss: a normal run cleans up and says cleanedUp: true", async () => {
    const r = await cli([]);
    assert.equal(r.json?.sandbox?.cleanedUp, true, r.err);
    assert.equal(r.json?.sandbox?.kept, false);
  });

  it("in a library call: runHarness returns interrupted: true when the signal came after the last pack (a pack that raises it as it ends)", () => {
    const out = join(dir, "lib-result.json");
    const plugin = join(dir, "last.mjs");
    writeFileSync(
      plugin,
      `export default {
  id: "plugin:last", version: "1.0.0", sealmark: "*",
  describe: () => [{ id: "last-check", pack: "plugin:last", label: "Probe", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  run: async (ctx) => { setTimeout(() => process.emit("SIGINT"), 0); return [ctx.helpers.done({ id: "last-check", label: "Probe", critical: false, scope: "server (test)" }, "pass", "ran", [])]; },
};`,
    );
    const runUrl = pathToFileURL(join(import.meta.dirname, "..", "run.js")).href;
    const child = join(dir, "lib-child.mjs");
    writeFileSync(
      child,
      `import { writeFileSync } from "node:fs";
import { runHarness, legacyEffectiveConfig } from ${q(runUrl)};
const config = { name: "t", version: "0.0.1", server: { command: process.execPath, args: [${q(TOY)}, "--mode", "nosql"], env: {} } };
const base = legacyEffectiveConfig({ config, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2 });
const effective = { ...base, cwd: ${q(dir)}, plugins: [{ module: "./last.mjs" }], sandbox: { ...base.sandbox, dir: ${q(parent)} } };
// The signal handler ends the process once its cleanup is done; held back here so that what the library call returned can be written first.
const realExit = process.exit.bind(process);
let handlerExit;
process.exit = (c) => { handlerExit = c; };
const r = await runHarness({ config, effective, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: () => {} });
writeFileSync(${q(out)}, JSON.stringify({ interrupted: r.interrupted, warnings: r.warnings, sandboxCleanedUp: r.sandbox?.cleanedUp }));
await new Promise((res) => setTimeout(res, 2000)); // the handler's own exit, if it has not happened yet
realExit(handlerExit ?? 0);
`,
    );
    const r = spawnSync(process.execPath, [child], { encoding: "utf8", timeout: 90_000 });
    // The exit code is the signal's; the file is the evidence of what the library returned.
    assert.equal(r.status, 130, r.stderr);
    assert.ok(existsSync(out), `the library call did not return:\n${r.stderr}`);
    const got = JSON.parse(readFileSync(out, "utf8")) as { interrupted?: boolean; warnings?: string[] };
    assert.equal(got.interrupted, true);
    assert.ok((got.warnings ?? []).includes("the run was interrupted; the report may be incomplete"));
  });
});
