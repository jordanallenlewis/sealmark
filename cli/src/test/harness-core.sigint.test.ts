// After a signal the orchestrator starts nothing new: a pack scheduled after "interrupted: cleaning up" would run against a server and a
// sandbox that are being torn down, and could leave a process behind.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CLI, TOY, hermeticEnv } from "./helpers.js";

const POSIX = process.platform !== "win32";
const FS = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
const HANG = fileURLToPath(new URL("../toy/hang.js", import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;

const leftovers = () => readdirSync(parent).filter((n) => n.startsWith("sealmark-"));

describe("harness-core: no pack is scheduled after an interrupt", { timeout: 240_000, skip: !POSIX }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-hc-sigint-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  it("the next pack in the list is never started once the signal has arrived", () => {
    const marker = (n: string) => join(dir, `ran-${n}.txt`);
    const plugin = (id: string, body: string) => `export default {
  id: "plugin:${id}", version: "1.0.0", sealmark: "*",
  describe: () => [{ id: "${id}-check", pack: "plugin:${id}", label: "Probe", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  run: async (ctx) => { (await import("node:fs")).writeFileSync(${q(marker(id))}, "x"); ${body} return [ctx.helpers.done({ id: "${id}-check", label: "Probe", critical: false, scope: "server (test)" }, "pass", "ran", [])]; },
};`;
    // The first pack raises the signal the way a terminal does and returns at once; the second must not be started.
    writeFileSync(join(dir, "first.mjs"), plugin("first", 'process.emit("SIGINT");'));
    writeFileSync(join(dir, "second.mjs"), plugin("second", ""));
    const runUrl = pathToFileURL(join(import.meta.dirname, "..", "run.js")).href;
    const child = join(dir, "sigint-child.mjs");
    writeFileSync(
      child,
      `import { runHarness, legacyEffectiveConfig } from ${q(runUrl)};
const config = { name: "t", version: "0.0.1", server: { command: process.execPath, args: [${q(TOY)}, "--mode", "nosql"], env: {} } };
const base = legacyEffectiveConfig({ config, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2 });
const effective = { ...base, cwd: ${q(dir)}, plugins: [{ module: "./first.mjs" }, { module: "./second.mjs" }], sandbox: { ...base.sandbox, dir: ${q(parent)} } };
await runHarness({ config, effective, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: (s) => process.stderr.write(s + "\\n") });
`,
    );
    const r = spawnSync(process.execPath, [child], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 130, r.stderr);
    assert.ok(existsSync(marker("first")), "the pack that was running when the signal came did start");
    assert.equal(existsSync(marker("second")), false, `the next pack was started after the signal:\n${r.stderr}`);
    assert.ok(!/plugin:second pack/.test(r.stderr), r.stderr);
    assert.deepEqual(leftovers(), [], "the sandbox is gone");
  });

  it("from the command line: a signal during one pack stops the run before the next pack is logged", async () => {
    const sandboxes = join(dir, "cli-sandboxes");
    mkdirSync(sandboxes);
    const cfg = join(dir, "cli.yaml");
    writeFileSync(cfg, `schema_version: 1\nname: sigint-cli\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: [${q(FS)}, "--mode", "good", "--root", "{sandbox}"]\n`);
    const args = [CLI, "run", "--config", cfg, "--sandbox-dir", sandboxes, "--pack", "core", "--pack", "fs", "--pack", "effects", "--timeout-probe", "2", "--fail-under", "none"];
    const child = spawn(process.execPath, args, { cwd: dir, env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    child.stderr.on("data", (b: Buffer) => (err += b.toString()));
    child.stdout.on("data", () => {});
    const exited = new Promise<number | null>((res) => child.once("exit", (code) => res(code)));
    const t0 = Date.now();
    while (!/fs pack/.test(err)) {
      assert.ok(Date.now() - t0 < 90_000, `the fs pack never started: ${err}`);
      if (child.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    child.kill("SIGINT");
    const code = await exited;
    const after = err.slice(err.indexOf("interrupted"));
    assert.equal(code, 130, err);
    assert.match(err, /interrupted: cleaning up/, err);
    assert.ok(!/effects pack/.test(after), `a pack was started after the signal:\n${after}`);
    assert.deepEqual(readdirSync(sandboxes), [], "no sandbox is left behind");
  });

  it("a signal while the server is still starting leaves no process and no sandbox", async () => {
    const sandboxes = join(dir, "start-sandboxes");
    mkdirSync(sandboxes);
    const marker = `sm-hang-${process.pid}-${Date.now()}`;
    const cfg = join(dir, "hang.yaml");
    writeFileSync(cfg, `schema_version: 1\nname: sigint-start\nversion: 0.0.1\nserver:\n  command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "hang", ${q(marker)}]\n`);
    const child = spawn(process.execPath, [CLI, "run", "--config", cfg, "--sandbox-dir", sandboxes, "--pack", "core", "--fail-under", "none"], { cwd: dir, env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    child.stderr.on("data", (b: Buffer) => (err += b.toString()));
    child.stdout.on("data", () => {});
    const exited = new Promise<number | null>((res) => child.once("exit", (code) => res(code)));
    const alive = () => spawnSync("ps", ["-A", "-o", "command="], { encoding: "utf8" }).stdout.split("\n").filter((l) => l.includes(marker) && !l.includes("ps -A"));
    const t0 = Date.now();
    while (alive().length === 0) {
      assert.ok(Date.now() - t0 < 30_000, `the server never started: ${err}`);
      await new Promise((r) => setTimeout(r, 50));
    }
    child.kill("SIGINT");
    assert.equal(await exited, 130, err);
    const t1 = Date.now();
    while (alive().length && Date.now() - t1 < 8_000) await new Promise((r) => setTimeout(r, 100));
    const left = alive();
    for (const l of left) {
      const pid = Number(l.trim().split(/\s+/)[0]);
      if (pid) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
    assert.deepEqual(left, [], "the server that was still starting was stopped");
    assert.deepEqual(readdirSync(sandboxes), [], "no sandbox is left behind");
  });
});
