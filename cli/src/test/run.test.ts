import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { ConfigError } from "../config.js";
import { loadEffectiveConfig } from "../config/index.js";
import { HarnessError, badgeFor, coverageLevel, legacyEffectiveConfig, packStatus, runHarness, type RunOptions } from "../run.js";
import { SANDBOX_NON_GUARANTEE } from "../sandbox.js";
import type { CheckResult, ConfigIntegrity, EffectiveConfig, PackId, RunResult, Verdict } from "../types.js";
import { TOY, gradeOf, quiet, toyConfig } from "./helpers.js";

let dir: string;
let parent: string;
const results: Record<string, RunResult> = {};

const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

/** A plugin in the module format of the design notes 6.6. `body` is the run() implementation. */
const plugin = (id: string, body: string, extra = "") => `export default {
  id: "plugin:${id}", version: "1.0.0", sealmark: "*",
  describe: () => [{ id: "${id}-check", pack: "plugin:${id}", label: "Probe", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  run: async (ctx) => { ${body} },
  ${extra}
};`;
const done = (id: string, verdict = "pass", more = "") => `return [{ ...ctx.helpers.done({ id: "${id}-check", label: "Probe", critical: false, scope: "server (test)" }, "${verdict}", "ran", []), ${more} }];`;

function effective(mode: string, over: Omit<Partial<EffectiveConfig>, "sandbox"> & { sandbox?: Partial<EffectiveConfig["sandbox"]> } = {}, packs: PackId[] = ["core"]): EffectiveConfig {
  const base = legacyEffectiveConfig({ config: toyConfig(mode), packs, packsExplicit: false, timeoutProbeSec: 2 });
  const { sandbox, ...rest } = over;
  return { ...base, integrity: INTEGRITY, cwd: dir, ...rest, sandbox: { ...base.sandbox, dir: parent, ...sandbox } };
}

const run = (o: Partial<RunOptions> & { effective?: EffectiveConfig; mode?: string }) =>
  runHarness({ config: toyConfig(o.mode ?? "nosql"), packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log: quiet, ...o });

const leftovers = () => readdirSync(parent).filter((n) => n.startsWith("sealmark-"));

describe("run.ts integration", { timeout: 180_000 }, () => {
  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-run-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    const mod = (name: string, src: string) => {
      writeFileSync(join(dir, name), src);
      return { module: `./${name}` };
    };
    const plugins = {
      env: mod(
        "env.mjs",
        plugin(
          "env",
          `const s = await ctx.open(); const r = await s.call("query", {}); const env = JSON.parse(r.text.slice(r.text.indexOf("env=") + 4));
           const home = process.platform === "win32" ? env.USERPROFILE : env.HOME;
           const ok = home === ctx.sandbox.home && env.TEMP === ctx.sandbox.tmp && env.SEALMARK_CANARY === undefined;
           globalThis.__smEnvProbe = { home, sandboxHome: ctx.sandbox.home, path: env.PATH ?? env.Path, bin: ctx.sandbox.bin, dir: ctx.sandbox.dir, enabled: ctx.sandboxEnabled, hasPrior: Array.isArray(ctx.prior) };
           return [ctx.helpers.done({ id: "env-check", label: "Probe", critical: false, scope: "server (test)" }, ok ? "pass" : "fail", "env", [])];`,
        ),
      ),
      cover: mod(
        "cover.mjs",
        plugin("cover", `return [{ ...ctx.helpers.done({ id: "cover-check", label: "Probe", critical: false, scope: "server (test)" }, "pass", "ran", []), coverage: { probed: ["query"], notCovered: [], validCalls: 3 } }];`),
      ),
      slow: mod("slow.mjs", plugin("slow", `const s = await ctx.open(); await new Promise((r) => setTimeout(r, 20000).unref()); ${done("slow")}`)),
      crash: mod("crash.mjs", plugin("crash", `throw new Error("plugin blew up");`)),
      wrongPack: mod("wrong.mjs", plugin("wrong", `return [{ id: "wrong-check", pack: "core", label: "x", critical: false, scope: "server", verdict: "pass", summary: "s", evidence: [] }];`)),
      collide: mod("collide.mjs", plugin("collide", done("collide")).replace('id: "collide-check"', 'id: "protocol"').replace('"collide-check"', '"protocol"')),
      newer: mod("newer.mjs", plugin("newer", done("newer")).replace('sealmark: "*"', 'sealmark: ">=9"')),
    };

    const jobs: Record<string, () => Promise<RunResult>> = {
      // A server that exposes no path, url, git or command tool and no SQL: everything beyond core has to say why it did not run.
      bare: () => run({ packs: ["core", "db", "http", "fs", "git", "net", "sqlite", "exec", "effects", "custom"], packsExplicit: false }),
      noSandbox: () => run({ effective: effective("nosql", { sandbox: { enabled: false } }, ["core", "fs", "net", "effects"]), packs: ["core", "fs", "net", "effects"] }),
      env: () => run({ mode: "echoenv", effective: effective("echoenv", { plugins: [plugins.env] }), packs: ["core"] }),
      covered: () => run({ mode: "nosql", effective: effective("nosql", { plugins: [plugins.cover] }), packs: ["core"] }),
      slow: () => run({ effective: effective("nosql", { plugins: [plugins.slow], sandbox: { pack_timeout_sec: 1 } }), packs: ["core"] }),
      crash: () => run({ effective: effective("nosql", { plugins: [plugins.crash] }), packs: ["core"] }),
      wrongPack: () => run({ effective: effective("nosql", { plugins: [plugins.wrongPack] }), packs: ["core"] }),
      kept: () => run({ effective: effective("nosql", { sandbox: { keep: true } }), packs: ["core"] }),
    };
    for (const [k, fn] of Object.entries(jobs)) results[k] = await fn();
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a core-only run is graded as before, says it is hygiene only, and claims no configuration identity", () => {
    const r = results.bare;
    assert.equal(gradeOf(r, "core")?.letter, "A");
    assert.equal(r.sealmark.methodology, "0.1-draft");
    assert.equal(r.config, undefined);
    assert.equal(r.coverage?.level, "hygiene-only");
    assert.equal(r.coverage?.validCalls, 0);
    assert.equal(r.badge?.eligible, false);
    assert.deepEqual(r.warnings?.filter((w) => !/serverInfo\.version/.test(w)), []);
  });

  it("every pack beyond core says why it did not run", () => {
    const p = results.bare.packs;
    assert.equal(p.db?.status, "na");
    assert.match(p.db?.reason ?? "", /placeholder/);
    assert.match(p.http?.reason ?? "", /stdio.*server\.url/);
    assert.match(p.fs?.reason ?? "", /file path/);
    assert.match(p.net?.reason ?? "", /URL/);
    assert.match(p.git?.reason ?? "", /git repository/);
    assert.match(p.exec?.reason ?? "", /--active/);
    assert.match(p.effects?.reason ?? "", /annotations|harness-owned target/);
    assert.match(p.custom?.reason ?? "", /probes/);
    assert.match(p.sqlite?.reason ?? "", /SQL/);
    for (const id of ["db", "http", "fs", "net", "git", "exec", "effects", "custom", "sqlite"] as const) assert.equal(p[id]?.status, "na", id);
  });

  it("classifies the server's tools and lists them as covered by core only", () => {
    const r = results.bare;
    assert.deepEqual(r.classification?.map((c) => c.tool).sort(), ["add", "echo"]);
    assert.ok(r.classification?.every((c) => c.confidence === "low" || c.confidence === "explicit"));
    assert.ok(r.notCovered.some((n) => /tool "echo" is covered by the core checks only/.test(n)));
  });

  it("states the sandbox is not a boundary, verbatim", () => {
    assert.ok(results.bare.notCovered.includes(SANDBOX_NON_GUARANTEE));
  });

  it("creates a sandbox, reports it, and deletes it", () => {
    const sb = results.bare.sandbox;
    assert.ok(sb);
    assert.equal(sb.enabled, true);
    assert.equal(sb.envMode, "scrubbed");
    assert.equal(sb.cleanedUp, true);
    assert.equal(sb.active, false);
    assert.ok(sb.listenerPort && sb.listenerPort > 0);
    assert.equal(existsSync(sb.dir!), false);
    assert.deepEqual(sb.leftoverProcesses, []);
    assert.equal(results.bare.options.active, false);
    assert.equal(results.bare.options.sandbox, true);
  });

  it("--keep-sandbox keeps the directory and says so", () => {
    const r = results.kept;
    assert.equal(r.sandbox?.kept, true);
    assert.ok(existsSync(r.sandbox!.dir!));
    assert.ok(r.warnings?.some((w) => /kept at/.test(w)));
  });

  it("with the sandbox off, fs/git/exec/effects are not applicable, the server inherits the environment, and net still has its listener", () => {
    const r = results.noSandbox;
    assert.equal(gradeOf(r, "core")?.letter, "A");
    for (const id of ["fs", "effects"] as const) {
      assert.equal(r.packs[id]?.status, "na", id);
      assert.match(r.packs[id]?.reason ?? "", /--no-sandbox/);
    }
    assert.doesNotMatch(r.packs.net?.reason ?? "", /--no-sandbox/);
    assert.equal(r.sandbox?.enabled, false);
    assert.equal(r.sandbox?.envMode, "inherited");
    assert.equal(r.options.sandbox, false);
    assert.ok(r.notCovered.some((n) => /--no-sandbox/.test(n)));
    assert.ok(!r.notCovered.includes(SANDBOX_NON_GUARANTEE));
    assert.equal(r.config?.hash, "test-hash");
  });

  it("a pack gets a fresh session started in the sandbox with a scrubbed environment", () => {
    const r = results.env;
    const probe = (globalThis as unknown as { __smEnvProbe: { home: string; sandboxHome: string; path: string; bin: string; enabled: boolean; hasPrior: boolean } }).__smEnvProbe;
    assert.equal(probe.home, probe.sandboxHome);
    assert.ok(probe.path.toLowerCase().startsWith(probe.bin.toLowerCase()), "sandbox bin first on PATH");
    assert.equal(probe.enabled, true);
    assert.equal(probe.hasPrior, true);
    const p = r.packs["plugin:env"];
    assert.equal(p?.status, "graded");
    assert.equal(p?.grade?.letter, "A");
  });

  it("plugin checks are labelled and carry the plugin pack id; a plugin makes no badge on its own", () => {
    const r = results.env;
    const c = r.checks.find((x) => x.id === "env-check")!;
    assert.equal(c.pack, "plugin:env");
    assert.equal(c.label, "[plugin:env] Probe");
    assert.equal(r.config?.standard, true); // run.ts reports what config/ computed; config/ is what flips it for plugins
  });

  it("coverage is aggregated from CheckResult.coverage and sets the badge", () => {
    const r = results.covered;
    assert.equal(r.coverage?.validCalls, 3);
    assert.equal(r.coverage?.toolsCalledValid, 1);
    assert.equal(r.coverage?.toolsTotal, 2);
    assert.equal(r.coverage?.level, "covered");
    assert.deepEqual(r.badge, { eligible: true });
  });

  it("a pack past sandbox.pack_timeout_sec is inconclusive, and the run still finishes", () => {
    const r = results.slow;
    assert.equal(r.packs["plugin:slow"]?.status, "inconclusive");
    assert.match(r.packs["plugin:slow"]?.reason ?? "", /pack_timeout_sec \(1 s\)/);
    assert.equal(gradeOf(r, "core")?.letter, "A");
    assert.equal(r.sandbox?.cleanedUp, true);
  });

  it("a pack that throws is inconclusive with the error, not a harness failure", () => {
    const r = results.crash;
    assert.equal(r.packs["plugin:crash"]?.status, "inconclusive");
    assert.match(r.packs["plugin:crash"]?.reason ?? "", /plugin blew up/);
    assert.ok(r.warnings?.some((w) => /pack plugin:crash failed/.test(w)));
  });

  it("a plugin that reports a check for another pack is refused", () => {
    const r = results.wrongPack;
    assert.equal(r.packs["plugin:wrong"]?.status, "inconclusive");
    assert.match(r.packs["plugin:wrong"]?.reason ?? "", /may only report its own pack/);
    assert.ok(!r.checks.some((c) => c.id === "wrong-check"));
  });

  it("exec asked for by name without --active is a config error; implied by defaults it is just not applicable", async () => {
    await assert.rejects(run({ packs: ["core", "exec"], packsExplicit: true }), (e: unknown) => e instanceof ConfigError && /--active/.test((e as Error).message));
    assert.equal(results.bare.packs.exec?.status, "na");
  });

  it("config errors in plugins stop the run before any server starts and leave nothing behind", async () => {
    const before = leftovers().length;
    await assert.rejects(run({ effective: effective("nosql", { plugins: [{ module: "./collide.mjs" }] }) }), (e: unknown) => e instanceof ConfigError && /check id "protocol"/.test((e as Error).message));
    await assert.rejects(run({ effective: effective("nosql", { plugins: [{ module: "./newer.mjs" }] }) }), (e: unknown) => e instanceof ConfigError && /requires sealmark >=9/.test((e as Error).message));
    assert.equal(leftovers().length, before);
  });

  it("a bad tools.overrides entry fails the run with a ConfigError and the sandbox is still removed", async () => {
    const before = leftovers().length;
    const eff = effective("nosql", { tools: { include: ["*"], exclude: [], overrides: { echo: { class: "path", params: { path: "nope" } } } } });
    await assert.rejects(run({ effective: eff }), (e: unknown) => e instanceof ConfigError && /no parameter "nope"/.test((e as Error).message));
    assert.equal(leftovers().length, before);
  });

  it("a server that dies on a missing module fails the run with a pin hint and its stderr", async () => {
    const script = join(dir, "dies.mjs");
    writeFileSync(script, "console.error('ModuleNotFoundError: No module named x'); process.exit(1);");
    const config = { name: "dies", version: "0.0.1", server: { command: process.execPath, args: [script], env: {} } };
    const before = leftovers().length;
    await assert.rejects(run({ config, effective: effective("nosql", { server: config.server }) }), (e: unknown) => e instanceof HarnessError && /pin them/.test(e.hint ?? "") && /ModuleNotFoundError/.test(e.stderr ?? ""));
    assert.equal(leftovers().length, before, "the sandbox is removed after a harness failure too");
  });

  it("SIGINT during a pack still kills the server and deletes the sandbox, and exits 130", () => {
    const marker = join(dir, "sigint-marker.txt");
    writeFileSync(join(dir, "sigint-plugin.mjs"), plugin("sigint", `const s = await ctx.open(); (await import("node:fs")).writeFileSync(${JSON.stringify(marker)}, ctx.sandbox.dir); process.emit("SIGINT"); await new Promise(() => {});`));
    const runUrl = pathToFileURL(join(import.meta.dirname, "..", "run.js")).href;
    const child = join(dir, "sigint-child.mjs");
    writeFileSync(
      child,
      `import { runHarness, legacyEffectiveConfig } from ${JSON.stringify(runUrl)};
const config = { name: "t", version: "0.0.1", server: { command: process.execPath, args: [${JSON.stringify(TOY)}, "--mode", "nosql"], env: {} } };
const base = legacyEffectiveConfig({ config, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2 });
const effective = { ...base, cwd: ${JSON.stringify(dir)}, plugins: [{ module: "./sigint-plugin.mjs" }], sandbox: { ...base.sandbox, dir: ${JSON.stringify(parent)} } };
await runHarness({ config, effective, packs: ["core"], packsExplicit: false, timeoutProbeSec: 2, log() {} });
`,
    );
    const r = spawnSync(process.execPath, [child], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 130, r.stderr);
    const sandboxDir = readFileSync(marker, "utf8");
    assert.equal(existsSync(sandboxDir), false, "the sandbox directory is gone");
  });

  it("runs on an EffectiveConfig loaded from a project file and reports its identity", async () => {
    const file = join(dir, "sealmark.yaml");
    writeFileSync(file, `schema_version: 1
name: from-file
version: 0.0.1
server:
  command: ${JSON.stringify(process.execPath)}
  args: [${JSON.stringify(TOY)}, "--mode", "nosql"]
`);
    const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
    const r = await runHarness({ config: toyConfig("nosql"), effective: { ...eff, sandbox: { ...eff.sandbox, dir: parent } }, packs: eff.packs as PackId[], packsExplicit: eff.packsExplicit, timeoutProbeSec: 2, log: quiet });
    assert.equal(r.server.name, "from-file");
    assert.equal(gradeOf(r, "core")?.letter, "A");
    assert.equal(r.config?.hash, eff.integrity.hash);
    assert.equal(r.config?.standard, true);
    assert.equal(r.config?.path, file);
    assert.equal(r.sealmark.methodology, eff.integrity.methodology);
    assert.equal(r.badge?.eligible, false);
    assert.equal(r.badge?.reason, "core-only run: no capability pack was graded");
    assert.equal(r.packs.db?.status, "na");
    assert.equal(r.packs.fs?.status, "na");
  });

  it("an excluded tool is listed as excluded and is not handed to packs", async () => {
    const eff = effective("nosql", { tools: { include: ["*"], exclude: ["echo"], overrides: {} } });
    const r = await run({ effective: eff });
    const echo = r.classification!.find((c) => c.tool === "echo")!;
    assert.equal(echo.excluded, true);
    assert.ok(r.notCovered.some((n) => /tool "echo".*excluded by tools\.exclude \(echo\)/.test(n)));
  });
});

describe("coverage level and badge rules", () => {
  it("coverageLevel: none is hygiene-only, under half is low, half or more is covered", () => {
    assert.equal(coverageLevel(0, 0, 14), "hygiene-only");
    assert.equal(coverageLevel(5, 1, 14), "low");
    assert.equal(coverageLevel(5, 6, 14), "low");
    assert.equal(coverageLevel(5, 7, 14), "covered");
    assert.equal(coverageLevel(1, 1, 1), "covered");
    assert.equal(coverageLevel(2, 2, 3), "covered"); // ceil(3/2) = 2
    assert.equal(coverageLevel(2, 1, 3), "low");
    assert.equal(coverageLevel(2, 1, 4), "low");
  });

  it("badgeFor: only a standard run with a graded non-core pack is eligible", () => {
    const graded = { status: "graded" as const };
    assert.deepEqual(badgeFor(INTEGRITY, { core: graded, fs: graded }), { eligible: true });
    assert.equal(badgeFor(INTEGRITY, { core: graded })?.reason, "core-only run: no capability pack was graded");
    assert.equal(badgeFor(INTEGRITY, { core: graded, db: { status: "na" } }).eligible, false);
    assert.match(badgeFor({ ...INTEGRITY, standard: false }, { core: graded, fs: graded }).reason ?? "", /custom run/);
    assert.equal(badgeFor(undefined, { core: graded, fs: graded }).eligible, false);
  });
});

describe("packStatus: inconclusive dominates not-applicable", () => {
  const check = (id: string, verdict: Verdict, summary: string, extra: Partial<CheckResult> = {}): CheckResult => ({ id, pack: "fs", label: id, critical: false, scope: "server", verdict, summary, evidence: [], ...extra });

  it("[na, inconclusive] is inconclusive and keeps the failed control's reason", () => {
    const s = packStatus("fs", [check("fs-read-escape", "inconclusive", "no read tool could read the harness's control file"), check("fs-write-escape", "na", "no tool takes file content"), check("fs-link-escape", "inconclusive", "link control failed")]);
    assert.equal(s.status, "inconclusive");
    assert.equal(s.reason, "no read tool could read the harness's control file");
    const reversed = packStatus("fs", [check("a", "na", "nothing to write"), check("b", "inconclusive", "control failed")]);
    assert.equal(reversed.status, "inconclusive");
    assert.equal(reversed.reason, "control failed");
  });
  it("all na stays na with the first na reason; all inconclusive stays inconclusive; any scored verdict grades", () => {
    assert.deepEqual(packStatus("fs", [check("a", "na", "one"), check("b", "na", "two")]), { status: "na", reason: "one" });
    assert.equal(packStatus("fs", [check("a", "inconclusive", "x"), check("b", "inconclusive", "y")]).status, "inconclusive");
    assert.equal(packStatus("fs", [check("a", "na", "one"), check("b", "pass", "ok")]).status, "graded");
    assert.deepEqual(packStatus("fs", []), { status: "na", reason: "the pack produced no checks" });
  });
  it("advisory checks never decide the status", () => {
    const s = packStatus("fs", [check("a", "na", "none"), check("adv", "inconclusive", "advisory trouble", { advisory: true })]);
    assert.equal(s.status, "na");
  });
});
