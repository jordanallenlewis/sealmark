import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { CLOSING_LINE, renderJson, renderText } from "../report.js";
import { METHODOLOGY } from "../config/index.js";
import type { CheckResult, RunResult } from "../types.js";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HTTP_TOY_TOKEN } from "../toy/http.js";
import { FAST, TOY, check, cliKit, freePort, q, srv } from "./helpers.js";
import { validateJunit } from "./shape.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-cli-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml, writeConfig, toyConfig, noClients, readJson } = cliKit(() => dir);

/** A command line that starts the repo's good HTTP toy server (a real MCP server over Streamable HTTP) on `port`. */
const httpToyCommand = (port: number): string => {
  const mod = pathToFileURL(fileURLToPath(new URL("../toy/http.js", import.meta.url))).href;
  const script = `import(${JSON.stringify(mod)}).then((m) => m.startHttpToy("good", { port: ${port}, token: ${JSON.stringify(HTTP_TOY_TOKEN)} }))`;
  return `${process.execPath} -e '${script}'`;
};

describe("cli", { timeout: 300_000 }, () => {
  it("exits 1 when a graded pack is below --fail-under", () => {
    const r = sealmark(["run", "--config", toyConfig("bad.yaml", "bad"), "--fail-under", "A", "--timeout-probe", "2"]);
    assert.equal(r.code, 1, r.err);
    assert.match(r.out, /PACK core {2}GRADE F/);
    assert.match(r.err, /below --fail-under A/);
  });

  it("exits 0 when the grade meets --fail-under", () => {
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--fail-under", "B", "--pack", "core", "--timeout-probe", "2"]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /PACK core {2}GRADE A/);
    assert.ok(r.out.includes(CLOSING_LINE));
  });

  it("the default gate is A: a pack below A exits 1 with no gate flag; --fail-under none or F lets the same run exit 0", () => {
    const cfg = toyConfig("defgate.yaml", "bad");
    const base = ["run", "--config", cfg, "--pack", "core", "--timeout-probe", "2"];
    const dflt = sealmark(base);
    assert.equal(dflt.code, 1, dflt.err);
    assert.match(dflt.err, /below the gate \(A\)/);
    for (const gate of ["none", "F"]) {
      const r = sealmark([...base, "--fail-under", gate]);
      assert.equal(r.code, 0, `--fail-under ${gate}: ${r.err}`);
      assert.ok(!/below the gate/.test(r.err), `--fail-under ${gate}: ${r.err}`);
    }
    // The same switch in a file: an explicit null is a value, not "unset", so it does not fall back to the default A.
    const off = writeYaml("defgate-off.yaml", `schema_version: 1\nname: gate-off\nversion: 1.0.0\noutput:\n  exit_policy:\n    fail_under: null\nserver:\n  ${srv("bad", 2)}\n`);
    const viaFile = sealmark(["run", "--config", off, "--pack", "core", "--timeout-probe", "2"]);
    assert.equal(viaFile.code, 0, viaFile.err);
  });

  it("exits 3 when no pack is graded (nosql has no SQL tool)", () => {
    // The {dsn} placeholder gets past the placeholder gate; --no-embedded keeps the test from starting a database.
    const cfg = writeConfig("nosql-dsn.yaml", process.execPath, [TOY, "--mode", "nosql", "--dsn", "{dsn}"]);
    const r = sealmark(["run", "--config", cfg, "--pack", "db", "--no-embedded", "--timeout-probe", "2"]);
    assert.equal(r.code, 3, r.err);
    assert.match(r.out, /PACK db {2}not graded: no tool takes a SQL string/);
  });

  it("exits 3 and names the placeholder when the config has none", () => {
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "db", "--timeout-probe", "2"]);
    assert.equal(r.code, 3, r.err);
    assert.match(r.out, /PACK db {2}not graded: server config has no \{dsn\}/);
  });

  it("exits 2 when sql_tools names an argument the tool does not have", () => {
    const path = join(dir, "badarg.yaml");
    writeFileSync(path, `server:
  command: ${JSON.stringify(process.execPath)}
  args: ${JSON.stringify([TOY, "--mode", "poison"])}
sql_tools:
  - { tool: query, arg: sqll }
`);
    const r = sealmark(["run", "--config", path, "--pack", "core", "--timeout-probe", "2"]);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /no string argument named "sqll" \(its string arguments: sql\)/);
  });

  it("exits 2 when the config file is missing", () => {
    const r = sealmark(["run", "--config", join(dir, "nope.yaml")]);
    assert.equal(r.code, 2);
    assert.match(r.err, /Cannot read/);
  });

  it("exits 4 when the server exits immediately", () => {
    const r = sealmark(["run", "--config", writeConfig("dead.yaml", process.execPath, ["-e", "0"]), "--pack", "core", "--timeout-probe", "2"]);
    assert.equal(r.code, 4, r.err);
  });

  it("init writes a template once and refuses to overwrite it", () => {
    const cwd = mkdtempSync(join(dir, "init-"));
    const first = sealmark(["init"], cwd, noClients());
    assert.equal(first.code, 0, first.err);
    assert.ok(existsSync(join(cwd, "sealmark.yaml")));
    const second = sealmark(["init"], cwd, noClients());
    assert.equal(second.code, 2);
    assert.match(second.err, /already exists/);
    assert.equal(sealmark(["init", "--force"], cwd, noClients()).code, 0);
  });

  it("exits 2 for bad flags", () => {
    const cfg = toyConfig("nosql.yaml", "nosql");
    assert.equal(sealmark(["run", "--config", cfg, "--fail-under", "Z"]).code, 2);
    assert.equal(sealmark(["run", "--config", cfg, "--format", "xml"]).code, 2);
    assert.equal(sealmark(["run", "--config", cfg, "--pack", "web"]).code, 2);
    assert.equal(sealmark(["run", "--config", cfg, "--bogus"]).code, 2);
    assert.equal(sealmark(["frobnicate"]).code, 2);
  });

  it("requires --yes with --pg", () => {
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pg", "postgres://u:p@127.0.0.1:1/postgres"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /--yes/);
  });

  it("--format json --out writes a parseable RunResult and keeps stdout empty", () => {
    const out = join(dir, "result.json");
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "core", "--format", "json", "--out", out, "--timeout-probe", "2"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, "");
    const parsed = JSON.parse(readFileSync(out, "utf8")) as RunResult;
    // The CLI loads the layered configuration, so a CLI run reports the current methodology (0.1-draft was the pre-config library path).
    assert.equal(parsed.sealmark.methodology, METHODOLOGY);
    assert.equal(parsed.packs.core?.grade?.letter, "A");
    assert.equal(parsed.server.transport, "stdio");
    assert.deepEqual(parsed.options.packsRequested, ["core"]);
    assert.ok(Array.isArray(parsed.notCovered));
  });
});

// ---- report rendering from a hand-built result (no harness involved) ----

function fixture(): RunResult {
  const checks: CheckResult[] = [
    check("protocol", "pass"),
    check("tool-poisoning", "pass", { critical: true }),
    check("robust-input", "fail"),
    check("secret-echo", "inconclusive", { critical: true }),
    { ...check("rls", "fail", { critical: true, pack: "db" }), label: "Row-level security respected" },
    check("pii", "pass", { critical: true, pack: "db" }),
    { ...check("write-gate", "fail", { advisory: true, pack: "db" }), label: "Write approval gate" },
  ];
  return {
    sealmark: { version: "0.1.0", methodology: "0.1-draft" },
    server: { name: "Server A", version: "1.2.3", command: "node server.js {dsn}", env: { DATABASE_URL: "{dsn}", SEALMARK_CANARY: "<canary>" }, transport: "stdio", tools: ["query"], sqlTools: [{ tool: "query", arg: "sql" }] },
    db: { mode: "embedded", seed: "0.1", roles: ["analyst", "support", "admin"], timeoutProbeSec: 10 },
    options: { packsRequested: ["core", "db"], timeoutProbeSec: 10 },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 1234,
    packs: {
      core: { status: "graded", grade: { pack: "core", points: 2, scored: 3, pct: 66.7, raw: "C", letter: "C", capped: false, criticalFails: [], provisional: true, excluded: ["secret-echo"] } },
      db: { status: "graded", grade: { pack: "db", points: 1, scored: 2, pct: 50, raw: "D", letter: "D", capped: false, criticalFails: ["rls"], provisional: false, excluded: [] } },
    },
    checks,
    notCovered: ["audit logging (0.1)"],
  };
}

describe("report", () => {
  it("renderJson round-trips the result", () => {
    const r = fixture();
    assert.deepEqual(JSON.parse(renderJson(r)), JSON.parse(JSON.stringify(r)));
    assert.ok(renderJson(r).startsWith('{\n  "sealmark": {')); // pretty-printed, two-space indent
  });

  it("renderText prints the config verbatim, grades, failures first, markers and the closing line", () => {
    const t = renderText(fixture());
    assert.match(t, /^sealmark 0\.1\.0 · methodology 0\.1-draft · Server A 1\.2\.3\n/);
    assert.match(t, /server: node server\.js \{dsn\}/);
    assert.match(t, /DATABASE_URL=\{dsn\}/);
    assert.match(t, /SEALMARK_CANARY=<canary>/);
    assert.match(t, /db: embedded Postgres, seed 0\.1, roles analyst, support, admin/);
    assert.match(t, /PACK core {2}GRADE C\* {2}\(2\/3 points, 66\.7% · 1 of 4 checks not scored\)/);
    assert.match(t, /PACK db {2}GRADE D {2}\(1\/2 points, 50%\)/);
    assert.match(t, /\* Provisional/);
    assert.match(t, /\[INCL\] secret-echo/);
    assert.match(t, /\[FAIL\] Write approval gate — test \(advisory, not scored\)/);
    assert.match(t, /\n {8}scope: test\n/);
    assert.match(t, /Not covered:\n {2}- audit logging \(0\.1\)/);
    assert.ok(t.trimEnd().endsWith(CLOSING_LINE));
    // The failing check leads its pack block.
    assert.ok(t.indexOf("[FAIL] robust-input") < t.indexOf("[PASS] protocol"));
  });

  it("renderText shows the cap and the reason for an ungraded pack", () => {
    const r = fixture();
    r.packs.db = { status: "na", reason: "no tool takes a SQL string" };
    r.packs.core!.grade = { ...r.packs.core!.grade!, raw: "B", letter: "D", capped: true, criticalFails: ["tool-poisoning"], provisional: false };
    const t = renderText(r);
    assert.match(t, /PACK db {2}not graded: no tool takes a SQL string/);
    assert.match(t, /Capped at D: critical fail\(s\): tool-poisoning\. Without the cap this would be B/);
  });

  it("renderText says when no database was used", () => {
    const r = fixture();
    delete r.db;
    assert.match(renderText(r), /db: not used/);
  });
});

describe("cli: integrity label, coverage and redaction", { timeout: 300_000 }, () => {
  const nosql = () => toyConfig("nosql.yaml", "nosql");

  it("a plain run is STANDARD and a core-only result is hygiene only with no badge", () => {
    const out = join(dir, "std.json");
    const r = sealmark(["run", "--config", nosql(), "--format", "json", "--out", out]);
    assert.equal(r.code, 0, r.err);
    const parsed = readJson(out);
    assert.equal(parsed.config?.standard, true, JSON.stringify(parsed.config?.standardDiff));
    assert.match(parsed.config?.hash ?? "", /^sha256:[0-9a-f]{64}$/);
    assert.equal(parsed.coverage?.level, "hygiene-only");
    assert.equal(parsed.badge?.eligible, false);
    assert.match(parsed.badge?.reason ?? "", /core-only/);
    assert.ok(Array.isArray(parsed.classification));
    assert.equal(parsed.sandbox?.cleanedUp, true);
    assert.equal(parsed.sandbox?.dir, "{sandbox_dir}", "the real sandbox path never reaches a report");
    // item 22: the grade is on stderr when the report goes to a file
    assert.match(r.err, /^core A \(hygiene only\)$/m);
    assert.match(r.err, /report written to /);
  });

  it("the text report says STANDARD and tags the core grade hygiene only", () => {
    const r = sealmark(["run", "--config", nosql()]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, new RegExp(`^sealmark \\S+ · methodology ${METHODOLOGY.replace(/\./g, "\\.")} · STANDARD · cli-test 1\\.0\\.0\\n`));
    assert.match(r.out, /PACK core {2}GRADE A {2}\(4\/4 points, 100%\) {2}hygiene only · tools called with valid arguments: 0 of \d+\n/);
    assert.match(r.out, /\nClassification:\n/);
    assert.match(r.out, /\nsandbox: \{sandbox_dir\} · env scrubbed · inherited: PATH \(system part\)[^\n]* · listener 127\.0\.0\.1:\{listener_port\} · cleaned up\n/);
    assert.match(r.out, /\nBadge: not eligible: core-only run/);
    assert.doesNotMatch(r.out, /custom grade/);
    assert.ok(!r.out.includes(tmpdir()), "no temp path in the report");
  });

  it("--replay re-runs with the report's locked settings; a tampered report is refused (exit 2)", () => {
    const std = join(dir, "std.json");
    const out = join(dir, "replayed.json");
    const r = sealmark(["run", "--config", nosql(), "--replay", std, "--format", "json", "--out", out]);
    assert.equal(r.code, 0, r.err);
    assert.equal(readJson(out).config?.hash, readJson(std).config?.hash);
    const bad = readJson<{ config: { locked: Record<string, unknown> } }>(std);
    bad.config.locked.timeout_probe_sec = 99;
    const tampered = writeYaml("tampered.json", JSON.stringify(bad));
    const t = sealmark(["run", "--config", nosql(), "--replay", tampered, ...FAST]);
    assert.equal(t.code, 2);
    assert.match(t.err, /--replay/);
    assert.equal(sealmark(["run", "--config", nosql(), "--replay", join(dir, "nope.json")]).code, 2);
  });

  it("--no-sandbox makes the run CUSTOM, says so, and turns the sandbox line off", () => {
    const r = sealmark(["run", "--config", nosql(), ...FAST, "--no-sandbox"]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /· CUSTOM \(not the published methodology: \d+ differences?\) ·/);
    assert.match(r.out, /\n {2}sandbox\.enabled: standard true, effective false {2}\(flag --(?:no-)?sandbox\)\n/);
    assert.match(r.out, /\nsandbox: off \(--no-sandbox\)/);
    assert.match(r.out, /PACK core {2}GRADE A .*custom grade/);
    assert.match(r.err, /sandbox is off/);
  });

  it("--no-redact warns on stderr", () => {
    const r = sealmark(["run", "--config", nosql(), ...FAST, "--no-redact"]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /--no-redact prints secret-looking values/);
  });

  it("a secret in sealmark.local.yaml never reaches the report", () => {
    const sub = mkdtempSync(join(dir, "local-"));
    writeFileSync(join(sub, "sealmark.yaml"), `schema_version: 1\nname: sec\nserver:\n  ${srv("echoenv", 2)}\n`);
    writeFileSync(join(sub, "sealmark.local.yaml"), `server:\n  env:\n    GREETING: "zz-local-secret-value-9"\n`);
    const r = sealmark(["run", "--fail-under", "none", ...FAST, "--format", "json"], sub);
    assert.equal(r.code, 0, r.err);
    assert.ok(!r.out.includes("zz-local-secret-value-9"), r.out.slice(0, 400));
    assert.match(r.out, /<redacted>/);
  });

  it("sealmark.local.yaml is an ordinary layer: only its secrets are scrubbed, not the settings it carries", () => {
    const sub = mkdtempSync(join(dir, "local2-"));
    writeFileSync(join(sub, "sealmark.yaml"), `schema_version: 1\nname: sec\nserver:\n  ${srv("nosql", 2)}\n`);
    writeFileSync(join(sub, "sealmark.local.yaml"), `packs: [core]\ntimeout_probe_sec: 2\nserver:\n  env:\n    GREETING: "zz-local-secret-value-9"\n`);
    const r = sealmark(["run"], sub);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /PACK core {2}GRADE A/, "the word core is not scrubbed");
    assert.match(r.out, /\n {2}packs: standard \[.*\], effective \["core"\] {2}\(sealmark\.local\.yaml/);
    assert.match(r.out, /\nsandbox: \{sandbox_dir\} · /);
    assert.match(r.out, /\n {2}GREETING=<redacted>\n/);
    assert.ok(!r.out.includes("zz-local-secret-value-9"));
  });
});

describe("cli: failures", { timeout: 300_000 }, () => {
  it("a server that cannot start: exit 4, hint, status failed in the report, full stderr saved", () => {
    const cfg = writeYaml("drift.yaml", `schema_version: 1\nname: drift\nserver:\n  command: ${q(process.execPath)}\n  args: ${q(["-e", "console.error('ModuleNotFoundError: No module named foo'); process.exit(1)"])}\n`);
    const out = join(dir, "drift.json");
    const r = sealmark(["run", "--config", cfg, "--pack", "core", "--format", "json", "--out", out]);
    assert.equal(r.code, 4, r.err);
    assert.match(r.err, /hint: the server's dependencies may have drifted; pin them/);
    const failed = readJson<{ status: string; error: string; stderrFile: string; hint: string }>(out);
    assert.equal(failed.status, "failed");
    assert.match(failed.error, /ModuleNotFoundError/);
    assert.ok(failed.stderrFile.endsWith("drift.json.stderr.log"));
    assert.match(readFileSync(failed.stderrFile, "utf8"), /ModuleNotFoundError: No module named foo/);
  });

  it("--pack exec without --active is a usage error (exit 2) and says why", () => {
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "exec"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /needs --active/);
  });

  it("flags that do not belong to the command, and --fail-on regressions without a baseline, are exit 2", () => {
    const a = sealmark(["init", "--pack", "core"], dir, noClients());
    assert.equal(a.code, 2);
    assert.match(a.err, /--pack does not apply to "sealmark init"/);
    const b = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--fail-on", "regressions"]);
    assert.equal(b.code, 2);
    assert.match(b.err, /--baseline/);
    assert.equal(sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--baseline", join(dir, "missing.json")]).code, 2);
    const nonsense = writeYaml("nonsense.json", '{"hello":1}');
    const c = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--baseline", nonsense]);
    assert.equal(c.code, 2);
    assert.match(c.err, /no sealmark run/);
    assert.equal(sealmark(["config"]).code, 2);
    assert.equal(sealmark([]).code, 2);
  });

  it("--format may be repeated or comma-separated, and a flag overrides output.formats in the config", () => {
    const cfg = writeYaml("flagfmt.yaml", `schema_version: 1
name: flagfmt
server:
  ${srv("nosql", 2)}
output:
  formats: [text]
`);
    for (const args of [["--format", "json", "--format", "junit"], ["--format", "json,junit"]]) {
      const sub = mkdtempSync(join(dir, "flagfmt-"));
      const r = sealmark(["run", "--config", cfg, ...FAST, ...args], sub);
      assert.equal(r.code, 0, r.err);
      assert.match(r.err, /2 report formats \(json, junit\)/);
      readJson(join(sub, "sealmark-report", "sealmark-report.json"));
      validateJunit(readFileSync(join(sub, "sealmark-report", "sealmark-report.junit.xml"), "utf8"));
      assert.ok(!existsSync(join(sub, "sealmark-report", "sealmark-report.txt")), "the flag replaces the config's formats instead of adding to them");
    }
    const bad = sealmark(["run", "--config", cfg, ...FAST, "--format", "json,nope"]);
    assert.equal(bad.code, 2);
  });

  it("--soft-fail turns a low grade into a warning and exit 0, but harness errors still fail", () => {
    const cfg = toyConfig("bad.yaml", "bad");
    const hard = sealmark(["run", "--config", cfg, "--fail-under", "A", "--timeout-probe", "2"]);
    assert.equal(hard.code, 1);
    const soft = sealmark(["run", "--config", cfg, "--fail-under", "A", "--timeout-probe", "2", "--soft-fail"]);
    assert.equal(soft.code, 0, soft.err);
    assert.match(soft.err, /soft-fail: the gate \(.*\) would exit 1; exiting 0 because --soft-fail is set/);
    const broken = sealmark(["run", "--start", "/no/such/sealmark-server --x", "--url", "http://127.0.0.1:9/mcp", "--soft-fail"]);
    assert.equal(broken.code, 4, "a server that cannot start is never softened");
  });

  it("with only flags and no file: --start + --url launches the server, grades it, prints the summary and stops it", async () => {
    const sub = mkdtempSync(join(dir, "flagsonly-"));
    const port = await freePort();
    const r = sealmark(["run", "--start", httpToyCommand(port), "--url", `http://127.0.0.1:${port}/mcp`, "--header", `Authorization: Bearer ${HTTP_TOY_TOKEN}`, "--pack", "core", "--pack", "http", "--format", "summary", "--timeout-probe", "2"], sub);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /starting the server \(.*\) and waiting for http:\/\/127\.0\.0\.1:\d+\/mcp/);
    assert.match(r.err, /the server answered \(HTTP \d+\) after/);
    assert.match(r.out, /S E A L M A R K/);
    assert.ok(!existsSync(join(sub, "sealmark.yaml")), "no config file was needed or written");
    await assert.rejects(fetch(`http://127.0.0.1:${port}/mcp`), "the server was stopped when the run ended");
  });

  it("CI=true: the ci profile is used, the summary goes to the log and JUnit + JSON go to files", () => {
    const sub = mkdtempSync(join(dir, "ciauto-"));
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "core", "--timeout-probe", "2"], sub, { CI: "true" });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /CI detected: using the ci profile/);
    assert.match(r.out, /S E A L M A R K/);
    assert.ok(existsSync(join(sub, "sealmark-report", "sealmark-report.junit.xml")));
    assert.ok(existsSync(join(sub, "sealmark-report", "sealmark-report.json")));
    assert.ok(!existsSync(join(sub, "sealmark-report", "sealmark-report.summary.txt")), "the summary is for the log, not a file");
    assert.ok(r.out.includes("\x1b["), "a CI log gets colors");
    const plain = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "core", "--timeout-probe", "2"], mkdtempSync(join(dir, "ciauto-")), { CI: "true", NO_COLOR: "1" });
    assert.ok(!plain.out.includes("\x1b["), "NO_COLOR wins");
    const off = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "core", "--timeout-probe", "2", "--profile", "standard"], mkdtempSync(join(dir, "ciauto-")), { CI: "true" });
    assert.ok(!/CI detected/.test(off.err), "an explicit profile turns the detection off");
  });

  it("a launch that dies printing a secret never leaks it: not in the log, the summary, JSON or JUnit", () => {
    const sub = mkdtempSync(join(dir, "leak-"));
    const token = "sk-live-0123456789abcdef";
    const dying = `console.error("settings: input_value='${token}'"); console.error("env: ${token.slice(0, 12)}" + process.env.SM_LEAK_SECRET_TOKEN); process.exit(1)`;
    const r = sealmark(["run", "--start", `${process.execPath} -e "${dying.replace(/"/g, '\\"')}"`, "--url", "http://127.0.0.1:9/mcp", "--header", `Authorization: Bearer ${token}`], sub, { CI: "true", SM_LEAK_SECRET_TOKEN: "env-secret-value-98765" });
    assert.equal(r.code, 4);
    const everything = [r.out, r.err, ...["sealmark-report.json", "sealmark-report.junit.xml"].map((f) => (existsSync(join(sub, "sealmark-report", f)) ? readFileSync(join(sub, "sealmark-report", f), "utf8") : ""))].join("\n");
    assert.ok(!everything.includes(token), "the header token was scrubbed everywhere");
    assert.ok(!everything.includes("env-secret-value-98765"), "an inherited secret-named variable was scrubbed everywhere");
    assert.match(r.err, /exited with code 1 before .* answered/);
  });

  it("CI=true with --out keeps the standard behaviour: no ci profile, no summary files, and the notice is not printed", () => {
    const sub = mkdtempSync(join(dir, "ciout-"));
    const r = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--pack", "core", "--timeout-probe", "2", "--out", "r.txt"], sub, { CI: "true" });
    assert.equal(r.code, 0, r.err);
    assert.ok(!/CI detected/.test(r.err));
    assert.ok(existsSync(join(sub, "r.txt")) && !existsSync(join(sub, "sealmark-report")));
    assert.ok(!readFileSync(join(sub, "r.txt"), "utf8").includes("\x1b["), "a report file never gets color codes");
  });

  it("the summary without a gate reports the worst grade and does not judge it; a summary written to a file is plain", () => {
    const sub = mkdtempSync(join(dir, "nogate-"));
    const r = sealmark(["run", "--fail-under", "none", "--config", toyConfig("bad.yaml", "bad"), "--pack", "core", "--timeout-probe", "2", "--format", "summary"], sub, { FORCE_COLOR: "1" });
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /WORST GRADE: /);
    assert.ok(!/BELOW [A-F]|ALL GRADED PACKS/.test(r.out), "no verdict without a gate");
    const gated = sealmark(["run", "--config", toyConfig("bad.yaml", "bad"), "--pack", "core", "--timeout-probe", "2", "--format", "summary", "--fail-under", "A"], sub, { FORCE_COLOR: "1" });
    assert.match(gated.out, /BELOW A: /);
    const file = sealmark(["run", "--config", toyConfig("bad.yaml", "bad"), "--pack", "core", "--timeout-probe", "2", "--format", "summary", "--fail-under", "A", "--out", "s.txt"], sub, { FORCE_COLOR: "1" });
    assert.ok(!readFileSync(join(sub, "s.txt"), "utf8").includes("\x1b["), "no color codes in a file even when colors are forced for the console");
  });

  it("a server Sealmark started itself gets canaries and the secret-echo check, and the report says so", async () => {
    const sub = mkdtempSync(join(dir, "selfstart-"));
    const port = await freePort();
    const r = sealmark(["run", "--start", httpToyCommand(port), "--url", `http://127.0.0.1:${port}/mcp`, "--header", `Authorization: Bearer ${HTTP_TOY_TOKEN}`, "--pack", "core", "--format", "json", "--timeout-probe", "2"], sub);
    assert.equal(r.code, 0, r.err);
    const j = JSON.parse(r.out) as RunResult;
    assert.equal(j.server.launched, true);
    assert.ok(j.checks.some((c) => c.id === "secret-echo" && c.verdict !== "na"), "secret-echo ran against the launched server");
    // Since round 6 a launched server runs inside the sandbox, so the "full environment and no sandbox" line is gone.
    assert.ok(!j.notCovered.some((n) => /started by Sealmark with your full environment and no sandbox/.test(n)));
    assert.equal(j.sandbox?.enabled, true);
    const text = sealmark(["run", "--start", httpToyCommand(await freePort()), "--url", "http://127.0.0.1:1/mcp", "--start-timeout", "2", "--pack", "core"], sub);
    assert.equal(text.code, 4, "a launch whose URL never answers is a harness failure");
  });

  it("init --ci prints a ready-to-paste job for gitlab or github and writes nothing", () => {
    const sub = mkdtempSync(join(dir, "initci-"));
    const gl = sealmark(["init", "--ci", "gitlab"], sub);
    assert.equal(gl.code, 0, gl.err);
    assert.match(gl.out, /^# Paste into \.gitlab-ci\.yml/);
    // A folded block with one flag per line, so adding a flag never needs YAML quoting (see ci-snippet.test.ts).
    assert.match(gl.out, /    - >\n      npx -y sealmark@\d+\.\d+\.\d+ run\n      --start "my-server --port 8000"\n      --url http:\/\/localhost:8000\/mcp\n/);
    assert.match(gl.out, /junit: sealmark-report\/sealmark-report\.junit\.xml/);
    const gh = sealmark(["init", "--ci", "github"], sub);
    assert.match(gh.out, /uses: actions\/upload-artifact@v4/);
    assert.equal(sealmark(["init", "--ci", "svn"], sub).code, 2);
    assert.ok(!existsSync(join(sub, "sealmark.yaml")));
  });

  it("several formats without --out-dir go to ./sealmark-report/, and the ci profile does the same", () => {
    const sub = mkdtempSync(join(dir, "multi-"));
    const cfg = writeYaml("multi.yaml", `schema_version: 1
name: multi
server:
  ${srv("nosql", 2)}
output:
  formats: [json, junit]
`);
    const r = sealmark(["run", "--config", cfg, ...FAST], sub);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /2 report formats \(json, junit\): writing one file each into /);
    assert.equal(r.out, "");
    readJson(join(sub, "sealmark-report", "sealmark-report.json"));
    validateJunit(readFileSync(join(sub, "sealmark-report", "sealmark-report.junit.xml"), "utf8"));
    const ci = mkdtempSync(join(dir, "ci-"));
    const c = sealmark(["run", "--config", toyConfig("nosql.yaml", "nosql"), "--profile", "ci", "--pack", "core"], ci);
    assert.equal(c.code, 0, c.err);
    assert.ok(existsSync(join(ci, "sealmark-report", "sealmark-report.junit.xml")));
  });
});

