import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { SCHEMA_FILE, schemaText, standardProfileText } from "../config/gen-schema.js";
import { CANDIDATE_CHECKS, CHECKS, ConfigError, SCHEMA, loadEffectiveConfig, standardHash, type LoadOptions } from "../config/index.js";
import { replayablePaths } from "../config/integrity.js";
import { DESCRIBE_SCHEMA, describeAllJson, renderDescribe, validateSchema } from "../describe.js";
import { Caller, checkSettings, excerpt, expandTemplate, listenerPorts, makeResult, newToken } from "../packs/net.js";
import { describeRedirect } from "../packs/net-redirect.js";
import { FORMATS, FORMAT_EXT, renderReport } from "../report.js";
import { driftFails, surfaceDrift, type DriftEntry } from "../report/drift.js";
import { captureSurface } from "../surface.js";
import { stageFiles } from "../staged-files.js";
import { writeFixture } from "../fixtures.js";
import { CANDIDATE_PACKS, type PackCtx, type PackId, type RunResult } from "../types.js";
import { FAST, cliKit, q, srv } from "./helpers.js";

const FIX = fileURLToPath(new URL("../../src/test/fixtures/config/", import.meta.url));
const NET_TOY = fileURLToPath(new URL("../toy/net.js", import.meta.url));
const lf = (s: string) => s.split("\r\n").join("\n");

let dir: string;
let n = 0;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-wiring-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeYaml, writeConfig, toyConfig, readJson } = cliKit(() => dir);

const BASE = "schema_version: 1\nserver:\n  command: node\n  args: [srv.js]\n";

function load(yaml: string, o: Partial<LoadOptions> = {}) {
  const root = join(dir, `p${n++}`);
  mkdirSync(root);
  writeFileSync(join(root, "sealmark.yaml"), yaml);
  return loadEffectiveConfig({ cwd: root, isolated: true, env: {}, ...o });
}

function failure(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `expected a ConfigError, got ${String(e)}`);
    return e.message;
  }
  assert.fail("expected a ConfigError");
}

describe("wiring: the standard profile does not move", () => {
  it("standardHash() equals the pinned fixture and the shipped standard.yaml equals the generated text", () => {
    assert.equal(standardHash(), lf(readFileSync(join(FIX, "standard.hash.txt"), "utf8")).trim());
    assert.equal(lf(readFileSync(new URL("../../src/config/profiles/standard.yaml", import.meta.url), "utf8")), standardProfileText());
    assert.equal(lf(readFileSync(SCHEMA_FILE, "utf8")), schemaText());
  });

  it("a candidate check has two unlocked settings; replay and the locked set never carry them", () => {
    assert.deepEqual([...CANDIDATE_CHECKS], CHECKS.filter((c) => c.candidate).map((c) => c.id));
    const paths = replayablePaths();
    const c = load(BASE);
    for (const id of CANDIDATE_CHECKS) {
      const since = CHECKS.find((x) => x.id === id)!.since;
      for (const k of ["enabled", "severity"]) {
        assert.ok(!paths.has(`checks.${id}.${k}`), `${id}.${k} is not replayable`);
        assert.ok(SCHEMA.some((l) => l.path === `checks.${id}.${k}` && l.since === since && !l.standardLocked), `${id}.${k} is an unlocked leaf`);
      }
      assert.ok(!Object.keys(c.integrity.locked).some((k) => k.startsWith(`checks.${id}`)), `${id} is not in config.locked`);
    }
  });

  it("a plain config is STANDARD with each candidate present; scoring one or switching it off is CUSTOM with one entry each", () => {
    const plain = load(BASE);
    assert.equal(plain.integrity.standard, true);
    assert.equal(plain.integrity.hash, standardHash());
    for (const id of CANDIDATE_CHECKS) {
      // A candidate may carry settings of its own (sql-guard-rowcap.row_cap, refusal-quality.patterns, ...): plain unlocked leaves.
      assert.equal(plain.checks[id]?.enabled, true, id);
      assert.equal(plain.checks[id]?.severity, null, id);

      const scored = load(`${BASE}checks:\n  ${id}:\n    severity: scored\n`);
      assert.equal(scored.integrity.standard, false, id);
      assert.deepEqual(scored.integrity.standardDiff.map((d) => [d.path, d.standard, d.effective]), [[`checks.${id}.severity`, null, "scored"]]);
      assert.equal(scored.integrity.hash, standardHash(), "the hash does not see an unlocked leaf; the diff does");

      const off = load(`${BASE}checks:\n  ${id}:\n    enabled: false\n`);
      assert.equal(off.integrity.standard, false, id);
      assert.deepEqual(off.integrity.standardDiff.map((d) => [d.path, d.standard, d.effective]), [[`checks.${id}.enabled`, true, false]]);

      const advisory = load(`${BASE}checks:\n  ${id}:\n    severity: advisory\n`);
      assert.equal(advisory.integrity.standard, false, "any non-null severity is a difference, even the one it already has");
    }
  });

  it("a candidate has no corpus leaves, and candidate settings validate like any check's", () => {
    for (const id of CANDIDATE_CHECKS) {
      assert.ok(!SCHEMA.some((l) => l.path.startsWith(`checks.${id}.corpus`)), id);
      assert.match(failure(() => load(`${BASE}checks:\n  ${id}:\n    severity: loud\n`)), /expected one of critical, scored, advisory/);
      assert.match(failure(() => load(`${BASE}checks:\n  ${id}:\n    corpus:\n      add: [x]\n`)), /unknown key "corpus"/);
    }
  });
});

describe("wiring: describe --json", () => {
  const d = describeAllJson();
  const wire = JSON.parse(renderDescribe(d)) as ReturnType<typeof describeAllJson>;

  it("validates, lists every registered check, and marks exactly the candidates", () => {
    assert.deepEqual(validateSchema(DESCRIBE_SCHEMA, wire), []);
    assert.equal(wire.checks.length, CHECKS.length);
    assert.deepEqual(wire.checks.filter((c) => c.candidate).map((c) => c.id).sort(), [...CANDIDATE_CHECKS].sort());
    for (const c of wire.checks.filter((x) => x.candidate)) {
      // A candidate check in a standard pack is shipped advisory; one in a candidate pack (round 6) is scored inside that pack.
      if (CANDIDATE_PACKS.includes(c.pack as PackId)) {
        assert.equal(c.advisory, false, `${c.id} is scored inside its candidate pack`);
        assert.equal(c.candidatePack, true, c.id);
        assert.equal(c.severity, c.critical ? "critical" : "scored", c.id);
      } else {
        assert.equal(c.advisory, true, `${c.id} is shipped advisory`);
        assert.equal(c.critical, false, c.id);
        assert.equal(c.severity, "advisory", c.id);
      }
      assert.equal(c.standardLocked, false, c.id);
      for (const k of ["enabled", "severity"]) assert.ok(c.configKeys.includes(`checks.${c.id}.${k}`), `${c.id}: checks.${c.id}.${k}`);
    }
    // A check that is not a candidate is never reported as unlocked advisory because of this flag.
    for (const c of wire.checks.filter((x) => !x.candidate)) assert.ok(!CANDIDATE_CHECKS.includes(c.id as (typeof CANDIDATE_CHECKS)[number]), c.id);
    const redirect = wire.checks.find((c) => c.id === "net-redirect")!;
    assert.equal(redirect.pack, "net");
    assert.equal(redirect.inStandardPacks, true);
    assert.equal(redirect.candidate, (CANDIDATE_CHECKS as readonly string[]).includes("net-redirect"));
    const netChecks = wire.packs.find((p) => p.id === "net")!.checks;
    for (const id of ["net-loopback-ssrf", "net-scheme-allowlist", "net-caps", "net-redirect"]) assert.ok(netChecks.includes(id), id);
    assert.equal(wire.configKeys.length, SCHEMA.length);
  });

  it("publishes the diff command, the new fixture text and no planned flag", () => {
    const diff = wire.cli.commands.find((c) => c.name === "diff")!;
    assert.equal(diff.usage, "diff <before.json> <after.json> [--json]");
    assert.deepEqual(diff.args?.map((a) => [a.name, a.required]), [["before.json", true], ["after.json", true]]);
    assert.ok(wire.cli.flags.find((f) => f.name === "json")!.commands.includes("diff"));
    assert.equal(wire.cli.flags.find((f) => f.name === "fixture")!.metavar, "<fs|git|sqlite>");
    assert.ok(!wire.cli.flags.some((f) => f.status === "planned"));
    const failOn = wire.cli.flags.find((f) => f.name === "fail-on")!;
    assert.equal(failOn.type, "list");
    assert.equal(failOn.schemaPath, "output.fail_on");
  });

  it("publishes the new keys", () => {
    const key = (p: string) => wire.configKeys.find((k) => k.path === p)!;
    assert.equal(key("server.files").type, "list");
    assert.equal(key("servers.*.files").type, "list");
    assert.equal(key("output.fail_on").type, "string[]");
    assert.deepEqual(key("output.fail_on").default, ["any"]);
    assert.deepEqual(key("output.fail_on").enum, ["any", "regressions", "drift"]);
    for (const p of ["server.files", "servers.*.files", "checks.net-redirect.enabled", "checks.net-redirect.severity"]) assert.equal(key(p).since, CHECKS.find((c) => c.id === "net-redirect")!.since, p);
  });
});

describe("wiring: output.fail_on", () => {
  it("defaults to [any]", () => assert.deepEqual(load(BASE).output.fail_on, ["any"]));

  it("reads a YAML scalar and a YAML list", () => {
    assert.deepEqual(load(`${BASE}output:\n  fail_on: regressions\n`).output.fail_on, ["regressions"]);
    assert.deepEqual(load(`${BASE}output:\n  fail_on: [regressions, drift]\n`).output.fail_on, ["regressions", "drift"]);
  });

  it("reads --fail-on (comma or repeated) and SEALMARK_OUTPUT__FAIL_ON", () => {
    assert.deepEqual(load(BASE, { flags: { "fail-on": ["regressions,drift"] } }).output.fail_on, ["regressions", "drift"]);
    assert.deepEqual(load(BASE, { flags: { "fail-on": ["regressions", "drift"] } }).output.fail_on, ["regressions", "drift"]);
    assert.deepEqual(load(BASE, { env: { SEALMARK_OUTPUT__FAIL_ON: "drift" } }).output.fail_on, ["drift"]);
    assert.deepEqual(load(BASE, { env: { SEALMARK_OUTPUT__FAIL_ON: "regressions,drift" } }).output.fail_on, ["regressions", "drift"]);
  });

  it("refuses an unknown value and says what to type", () => {
    assert.match(failure(() => load(`${BASE}output:\n  fail_on: sometimes\n`)), /expected one of any, regressions, drift/);
    assert.match(failure(() => load(BASE, { flags: { "fail-on": ["bogus"] } })), /expected one of any, regressions, drift/);
  });

  it("the generated JSON Schema accepts the scalar and the list", () => {
    const s = JSON.parse(schemaText()) as { properties: { output: { properties: { fail_on: { oneOf: { type?: string; enum?: string[] }[]; default: string[] } } } } };
    const f = s.properties.output.properties.fail_on;
    assert.deepEqual(f.default, ["any"]);
    assert.deepEqual(f.oneOf.map((x) => x.type ?? "enum"), ["array", "enum"]);
  });

  it("accepts the new output formats everywhere a format is accepted", () => {
    assert.deepEqual(load(`${BASE}output:\n  format: badge\n`).output.format, "badge");
    assert.deepEqual(load(`${BASE}output:\n  formats: [json, shields]\n`).output.formats, ["json", "shields"]);
    assert.deepEqual(load(`${BASE}output:\n  format: summary\n`).output.format, "summary");
  });
});

describe("wiring: server.files", () => {
  const files = (body: string, at = "server") => `schema_version: 1\n${at}:\n  command: node\n  args: [srv.js]\n  files:\n${body}`;

  it("reads a list of { path, content } under server and under servers.*", () => {
    const c = load(files('    - path: "{sandbox}/conf/app.json"\n      content: "hello {listener} ${HOME}"\n    - { path: "{sandbox_home}/.rc", content: "" }\n'), { env: { HOME: "/h" } });
    assert.deepEqual(c.server.files, [
      { path: "{sandbox}/conf/app.json", content: "hello {listener} ${HOME}" },
      { path: "{sandbox_home}/.rc", content: "" },
    ]);
    const multi = load(`schema_version: 1\nservers:\n  a:\n    command: node\n    files:\n      - { path: "{dir}/x", content: y }\n`);
    assert.deepEqual(multi.servers[0].spec.files, [{ path: "{dir}/x", content: "y" }]);
    assert.equal(load(BASE).server.files, undefined, "unset stays unset");
  });

  it("refuses a path outside the sandbox", () => {
    for (const p of ["/etc/passwd", "relative/file", "{canary}/secret.txt", "~/x"]) {
      assert.match(failure(() => load(files(`    - { path: ${q(p)}, content: x }\n`))), /staged files are written only inside the sandbox; start the path with \{sandbox\} or \{sandbox_home\}/, p);
    }
  });

  it("refuses database placeholders in content, and a missing key", () => {
    for (const c of ["postgres://{dsn}", "host={host}", "{dsn:analyst}", "pw={password}"]) {
      assert.match(failure(() => load(files(`    - { path: "{sandbox}/c", content: ${q(c)} }\n`))), /server\.files cannot carry database placeholders: the server is started once per database role/, c);
    }
    assert.match(failure(() => load(files('    - { path: "{sandbox}/c" }\n'))), /missing required key "content"/);
    assert.match(failure(() => load(files('    - { content: x }\n'))), /missing required key "path"/);
    assert.match(failure(() => load(files('    - { path: "{sandbox}/c", content: x, mode: 600 }\n'))), /unknown key "mode"/);
  });

  it("is refused in a profile, and a ${VAR} that is not set is a config error like in args", () => {
    assert.match(failure(() => load(`${BASE}profiles:\n  mine:\n    server:\n      files: []\n`)), /server/);
    assert.match(failure(() => load(files('    - { path: "{sandbox}/c", content: "token=${NOPE_NOT_SET_1}" }\n'))), /NOPE_NOT_SET_1/);
  });
});

describe("wiring: entry points the feature packages fill in keep their contract", () => {
  it("the drift entry points: captureSurface returns a list, surfaceDrift entries carry a server, driftFails keeps breaking and notable", () => {
    assert.ok(Array.isArray(captureSurface([], [])));
    const run = (tools: string[]) => ({ server: { name: "s", tools }, classification: [] }) as unknown as RunResult;
    for (const e of surfaceDrift(run(["a", "gone"]), run(["a", "new"]))) assert.equal(e.server, "s");
    const entry = (severity: "breaking" | "notable" | "info"): DriftEntry => ({ server: "s", kind: "tool-added", severity, text: severity });
    assert.deepEqual(driftFails([entry("breaking"), entry("notable"), entry("info")]).map((e) => e.severity), ["breaking", "notable"]);
  });

  it("stageFiles with nothing to stage writes nothing; writeFixture refuses an unknown name and duckdb", () => {
    assert.deepEqual(stageFiles(undefined, { vars: {}, dsns: {} }, { sandbox: dir, home: dir }, () => {}), []);
    assert.deepEqual(stageFiles([], { vars: {}, dsns: {} }, { sandbox: dir, home: dir }, () => {}), []);
    assert.throws(() => writeFixture("nope", dir, () => {}), /--fixture must be fs, git, sqlite or duckdb/);
    assert.throws(() => writeFixture("duckdb", dir, () => {}), /not available in this build yet/);
  });

  it("makeResult honours checks.<id>.severity: null keeps the check's own default, advisory, scored and critical override it", () => {
    const [doc] = describeRedirect();
    const result = (severity: string | null) => makeResult({ config: { checks: { "net-redirect": { enabled: true, severity } }, origins: {} } } as unknown as PackCtx, doc, "na", "s", []);
    assert.deepEqual([result(null).advisory, result(null).critical], [doc.advisory ? true : undefined, doc.critical]);
    assert.deepEqual([result("advisory").advisory, result("advisory").critical], [true, false]);
    assert.deepEqual([result("scored").advisory, result("scored").critical], [undefined, false]);
    assert.deepEqual([result("critical").advisory, result("critical").critical], [undefined, true]);
  });

  it("the net helpers feature packages build on are exported", () => {
    for (const f of [expandTemplate, makeResult, checkSettings, listenerPorts, newToken, excerpt]) assert.equal(typeof f, "function");
    assert.equal(typeof Caller, "function");
    const [doc] = describeRedirect();
    assert.deepEqual([doc.id, doc.pack, doc.critical, doc.advisory, doc.status], ["net-redirect", "net", false, (CANDIDATE_CHECKS as readonly string[]).includes("net-redirect"), "shipped"]);
    assert.deepEqual(doc.probes.map((p) => p.id), ["follow", "hop", "scheme-file", "scheme-raw"]);
    assert.deepEqual(doc.configKeys, ["checks.net-redirect.enabled", "checks.net-redirect.severity"]);
  });
});

describe("wiring: report formats", () => {
  it("FORMATS and FORMAT_EXT know badge and shields, and renderReport answers for them", () => {
    assert.ok(FORMATS.includes("badge") && FORMATS.includes("shields"));
    assert.equal(FORMAT_EXT.badge, "badge.svg");
    assert.equal(FORMAT_EXT.shields, "shields.json");
    for (const f of FORMATS) assert.ok(FORMAT_EXT[f], f);
    const failed = { status: "failed", server: "x", error: "boom", sealmark: { version: "0", methodology: "0.2-draft" } } as never;
    assert.match(renderReport("badge", [failed]), /^<svg /);
    const shields = JSON.parse(renderReport("shields", [failed])) as Record<string, unknown>;
    assert.deepEqual(Object.keys(shields), ["schemaVersion", "label", "message", "color"]);
  });
});

describe("wiring: the command line", { timeout: 300_000 }, () => {
  const report = (name: string, mode = "nosql"): string => {
    const out = join(dir, `${name}.json`);
    const r = sealmark(["run", "--config", toyConfig(`${name}.yaml`, mode), ...FAST, "--format", "json", "--out", out]);
    assert.equal(r.code, 0, r.err);
    return out;
  };

  it("sealmark diff: identical core-only reports exit 0; a missing argument or file exits 2", () => {
    const a = report("same");
    const r = sealmark(["diff", a, a]);
    assert.equal(r.code, 0, r.err);
    const j = sealmark(["diff", a, a, "--json"]);
    assert.equal(j.code, 0, j.err);
    const body = JSON.parse(j.out) as Record<string, unknown>;
    assert.equal(body.format, "sealmark.diff/1");
    assert.deepEqual(Object.keys(body).sort(), ["drift", "format", "improvements", "notes", "regressions"]);
    const one = sealmark(["diff", a]);
    assert.equal(one.code, 2);
    assert.match(one.err, /diff needs two report files: sealmark diff before.json after.json/);
    const three = sealmark(["diff", a, a, a]);
    assert.equal(three.code, 2);
    assert.match(three.err, /unexpected argument/);
    const missing = sealmark(["diff", a, join(dir, "missing.json")]);
    assert.equal(missing.code, 2);
    assert.match(missing.err, /cannot read the after report/);
    assert.match(sealmark(["run", "--config", toyConfig("x.yaml", "nosql"), "--json"]).err, /--json does not apply to "sealmark run"/);
  });

  it("sealmark diff: a regression or a tool-surface change exits 1", () => {
    const good = readJson<RunResult>(report("d-good"));
    const worse = structuredClone(good);
    worse.packs.core!.grade!.letter = "C";
    const wf = join(dir, "d-worse.json");
    writeFileSync(wf, JSON.stringify(worse));
    const r = sealmark(["diff", join(dir, "d-good.json"), wf]);
    assert.equal(r.code, 1, r.err);
    assert.match(r.out, /^regression: .*grade dropped A -> C/m);

    const removed = structuredClone(good);
    removed.server.tools = [...removed.server.tools, "ghost"];
    const rf = join(dir, "d-ghost.json");
    writeFileSync(rf, JSON.stringify(removed));
    const d = sealmark(["diff", rf, join(dir, "d-good.json")]);
    assert.equal(d.code, 1, d.err);
    assert.match(d.out, /^drift: .*ghost/m);
  });

  it("--fail-on drift and --fail-on regressions need a baseline (exit 2) and name the flag to add", () => {
    const cfg = toyConfig("fo.yaml", "nosql");
    for (const v of ["drift", "regressions", "regressions,drift"]) {
      const r = sealmark(["run", "--config", cfg, ...FAST, "--fail-on", v]);
      assert.equal(r.code, 2, `${v}: ${r.err}`);
      assert.match(r.err, /--fail-on (drift|regressions) compares with a baseline; add --baseline <report.json>/, v);
    }
    const yaml = writeYaml("fo-yaml.yaml", `schema_version: 1\nname: fo\nversion: 1.0.0\noutput:\n  fail_on: drift\nserver:\n  ${srv("nosql", 2)}\n`);
    assert.equal(sealmark(["run", "--config", yaml, ...FAST]).code, 2);
  });

  it("--fail-on regressions,drift parses with a baseline; drift decides only when asked; the note says how", () => {
    const base = report("fo-base");
    const edited = readJson<RunResult>(base);
    edited.server.tools = [...edited.server.tools, "ghost"];
    const drifted = join(dir, "fo-drifted.json");
    writeFileSync(drifted, JSON.stringify(edited));
    const cfg = toyConfig("fo2.yaml", "nosql");
    const args = ["run", "--config", cfg, ...FAST, "--format", "json", "--out", join(dir, "fo-out.json")];

    const same = sealmark([...args, "--baseline", base, "--fail-on", "regressions,drift"]);
    assert.equal(same.code, 0, same.err);
    assert.match(same.err, /sealmark exit 0: no regression or tool-surface drift against the baseline/);
    assert.ok(!/drift:/.test(same.err));

    const gate = sealmark([...args, "--baseline", drifted]);
    assert.equal(gate.code, 0, gate.err);
    assert.match(gate.err, /^drift: .*ghost/m);
    assert.match(gate.err, /^note: \d+ tool-surface change\(s\) do not affect the exit code; add --fail-on drift to fail on them$/m);

    for (const v of [["--fail-on", "drift"], ["--fail-on", "any,drift"], ["--fail-on", "regressions", "--fail-on", "drift"]]) {
      const hit = sealmark([...args, "--baseline", drifted, ...v]);
      assert.equal(hit.code, 1, `${v.join(" ")}: ${hit.err}`);
      assert.match(hit.err, /sealmark exit 1: the tool surface drifted against the baseline/);
      assert.ok(!/^note: /m.test(hit.err), "no note when the drift is already failing the run");
    }
    const regOnly = sealmark([...args, "--baseline", drifted, "--fail-on", "regressions"]);
    assert.equal(regOnly.code, 0, regOnly.err);
    assert.match(regOnly.err, /^note: \d+ tool-surface change/m);
  });

  it("the old exit_policy.regressions_only still means regressions only", () => {
    const base = report("ro-base", "bad");
    const yaml = writeYaml("ro.yaml", `schema_version: 1\nname: ro\nversion: 1.0.0\noutput:\n  exit_policy:\n    regressions_only: true\n    fail_under: A\nserver:\n  ${srv("bad", 2)}\n`);
    const r = sealmark(["run", "--config", yaml, "--pack", "core", "--timeout-probe", "2", "--baseline", base]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /no regression against the baseline/);
  });

  it("--format badge and --format shields take one server (exit 2, before any run)", () => {
    const yaml = writeYaml("two.yaml", `schema_version: 1\nname: two\nversion: 1.0.0\nservers:\n  a:\n    ${srv("nosql")}\n  b:\n    ${srv("nosql")}\n`);
    for (const f of ["badge", "shields"]) {
      const r = sealmark(["run", "--config", yaml, ...FAST, "--format", f]);
      assert.equal(r.code, 2, `${f}: ${r.err}`);
      assert.match(r.err, /the badge and shields formats take one server; run with --server <name>/);
    }
    const one = sealmark(["run", "--config", yaml, ...FAST, "--server", "a", "--format", "shields"]);
    assert.equal(one.code, 0, one.err);
    assert.deepEqual(Object.keys(JSON.parse(one.out) as object), ["schemaVersion", "label", "message", "color"]);
  });

  it("server.files: --no-sandbox and a server that is already running are config errors (exit 2)", () => {
    const withFiles = (server: string) => writeYaml(`files-${n++}.yaml`, `schema_version: 1\nname: f\nversion: 1.0.0\nserver:\n  ${server}\n  files:\n    - { path: "{sandbox}/a.txt", content: hi }\n`);
    const url = sealmark(["run", "--config", withFiles('url: "http://127.0.0.1:9/mcp"'), ...FAST]);
    assert.equal(url.code, 2, url.err);
    assert.match(url.err, /staged files need a server Sealmark starts; a server that is already running cannot see the sandbox/);
    const bare = sealmark(["run", "--config", withFiles(srv("nosql", 2)), ...FAST, "--no-sandbox"]);
    assert.equal(bare.code, 2, bare.err);
    assert.match(bare.err, /staged files \(server\.files\) need the sandbox: remove --no-sandbox/);
  });

  it("a STANDARD run of a net toy still says STANDARD; the only new line is the n/a net-redirect line", () => {
    const cfg = writeConfig("net-good.yaml", process.execPath, [NET_TOY, "--mode", "good"]);
    const json = join(dir, "net-good.json");
    const r = sealmark(["run", "--config", cfg, "--fail-under", "none", "--format", "json", "--out", json]);
    assert.equal(r.code, 0, r.err);
    const run = readJson<RunResult>(json);
    assert.equal(run.config?.standard, true);
    assert.equal(run.config?.hash, standardHash());
    assert.equal(run.packs.net?.grade?.letter, "A");
    assert.deepEqual(run.checks.filter((c) => c.pack === "net").map((c) => [c.id, c.verdict]), [
      ["net-loopback-ssrf", "pass"],
      ["net-scheme-allowlist", "pass"],
      ["net-caps", "na"],
      ["net-redirect", "na"],
    ]);
    assert.equal(run.checks.find((c) => c.id === "net-redirect")!.advisory === true, (CANDIDATE_CHECKS as readonly string[]).includes("net-redirect"));
    assert.ok(Array.isArray(run.server.surface), "server.surface is a list (empty until the drift package fills it in)");
    const text = sealmark(["run", "--config", cfg, "--fail-under", "none"]);
    assert.match(text.out, /STANDARD/);
    assert.match(text.out, /\[N\/A \] Redirects are re-validated/);
    assert.match(text.out, /PACK net {2}GRADE A/);
  });
});
