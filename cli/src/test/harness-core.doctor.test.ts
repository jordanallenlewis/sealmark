// doctor and run read the same configuration the same way: fixtures a config points at exist, and the wording of what would run
// and what was not covered does not depend on which command printed it.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { renderDoctor, runDoctor, type DoctorReport } from "../doctor.js";
import { runHarness } from "../run.js";
import { sqliteUnavailable } from "../sqlite-fixtures.js";
import type { PackId, RunResult } from "../types.js";
import { TOY } from "./helpers.js";

const toy = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;
let counter = 0;

function load(server: { command: string; args: string[] }, extra = "") {
  const file = join(dir, `c${++counter}.yaml`);
  writeFileSync(file, `schema_version: 1\nname: doc-run\nversion: 0.0.1\nserver:\n  command: ${q(server.command)}\n  args: ${q(server.args)}\nsandbox:\n  dir: ${q(parent)}\n${extra}`);
  return loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
}
const doctor = (cfg: ReturnType<typeof load>): Promise<DoctorReport> => runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
const run = (cfg: ReturnType<typeof load>, packs: PackId[]): Promise<RunResult> =>
  runHarness({ config: { name: cfg.name, version: cfg.version, server: cfg.server }, effective: cfg, packs, packsExplicit: true, timeoutProbeSec: 2, log: () => {} });
const node = (...args: string[]) => ({ command: process.execPath, args });

describe("harness-core: doctor and run agree", { timeout: 240_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-hc-doctor-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  it("doctor builds the fixtures a config points at: a server that needs {sandbox}/repo and {sqlite_path} at startup passes", async () => {
    // A server that checks its repository and database at startup and dies without them, as real ones do.
    const wrapper = join(dir, "startup-check.mjs");
    writeFileSync(
      wrapper,
      `import { existsSync } from "node:fs";
const [repo, db] = process.argv.slice(2, 4);
if (!existsSync(repo + "/.git")) { console.error("startup-check: repository missing: " + repo); process.exit(3); }
if (!existsSync(db)) { console.error("startup-check: database missing: " + db); process.exit(3); }
process.argv.splice(2, 2);
await import(${q(pathToFileURL(TOY).href)});
`,
    );
    const cfg = load(node(wrapper, "{sandbox}/repo", "{sqlite_path}", "--mode", "nosql"));
    const d = await doctor(cfg);
    assert.equal(d.exitCode, 0, renderDoctor(d));
    assert.equal(d.servers[0]!.items.find((i) => i.id === "start")?.status, "ok");
    // The same config runs, so the two commands no longer disagree about whether the server starts.
    const r = await run(cfg, ["core"]);
    assert.equal(r.packs.core?.status, "graded");
  });

  it("effects: doctor and run give the same reason when it does not apply, and doctor says 'may run' when it does", async () => {
    // The nosql toy has no path, repository or URL tool and no annotations, so nothing can be compared with what the sandbox observed
    // (an unannotated path tool is enough for the gate since round 5, so the probes toy no longer stands for "does not apply").
    const plain = load(node(TOY, "--mode", "nosql"), "packs: [core, effects]\n");
    const d = await doctor(plain);
    const dp = d.servers[0]!.packs.find((p) => p.pack === "effects")!;
    assert.equal(dp.applies, false);
    const r = await run(plain, ["core", "effects"]);
    const rp = r.packs.effects;
    assert.equal(rp?.status, "na");
    assert.equal(rp && "reason" in rp ? rp.reason : undefined, dp.reason, "one wording in both commands");
    assert.doesNotMatch(dp.reason, /readOnlyHint/);

    // The fs toy annotates its tools and takes {sandbox}: effects applies.
    const annotated = load(node(toy("fs"), "--mode", "good", "--root", "{sandbox}"), "packs: [core, effects]\n");
    const d2 = await doctor(annotated);
    assert.equal(d2.servers[0]!.packs.find((p) => p.pack === "effects")?.applies, true);
    assert.match(renderDoctor(d2), /effects +may run /);
    const r2 = await run(annotated, ["core", "effects"]);
    assert.notEqual(r2.packs.effects?.status, "na", JSON.stringify(r2.packs.effects));
  });

  it("the engine line is not printed when the sqlite pack ran, and is when no engine pack could", async (t) => {
    const why = sqliteUnavailable();
    if (why) return t.skip(why);
    const engine = /no engine pack ran/;
    // {sqlite_path} is given and the sqlite pack runs: the line would be false.
    const ran = await run(load(node(toy("sqlite"), "--mode", "open", "--db", "{sqlite_path}")), ["core", "sqlite"]);
    assert.ok(ran.checks.some((c) => c.pack === "sqlite"), "the sqlite pack produced checks");
    assert.ok(!ran.notCovered.some((n) => engine.test(n)), ran.notCovered.join("\n"));
    // {sqlite_path} is given but the pack was not asked for: it says so, and does not claim there is no placeholder.
    const notAsked = await run(load(node(toy("sqlite"), "--mode", "open", "--db", "{sqlite_path}")), ["core"]);
    assert.ok(notAsked.notCovered.some((n) => /sqlite pack did not run/.test(n)), notAsked.notCovered.join("\n"));
    assert.ok(!notAsked.notCovered.some((n) => engine.test(n)));
    // Near-miss: a SQL tool and no placeholder at all: the original line stands.
    const none = await run(load(node(TOY, "--mode", "good", "--dsn", "postgres://nobody@127.0.0.1:1/none")), ["core"]);
    assert.ok(none.notCovered.some((n) => engine.test(n)), none.notCovered.join("\n"));
  });

  it("a classified tool no pack probed is listed in Not covered with its pack's reason; one that was probed is not", async () => {
    const cfg = () => load(node(toy("fs"), "--mode", "good", "--root", "{sandbox}"));
    const without = await run(cfg(), ["core"]);
    assert.ok(without.notCovered.some((n) => /^tool "read_file" \(path\) was not probed by the fs pack: the pack was not requested$/.test(n)), without.notCovered.join("\n"));
    const withFs = await run(cfg(), ["core", "fs"]);
    assert.ok(!withFs.notCovered.some((n) => /^tool "read_file" \(path\) was not probed/.test(n)), withFs.notCovered.join("\n"));
  });
});
