import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CLOSING_LINE, renderJson, renderReport, renderText, summaryLine, type AnyRun, type FailedRun } from "../report.js";
import { compareBaseline, parseBaseline } from "../report/baseline.js";
import { decideExit, type ExitPolicy } from "../report/exit.js";
import { makePathRewriter, makeSecretScrubber, redactResult } from "../report/redact.js";
import { renderTemplate, TemplateError, applyTemplate } from "../report/template.js";
import { renderMarkdown } from "../report/markdown.js";
import { renderSummary } from "../report/summary.js";
import { secretLiterals } from "../report/secrets.js";
import type { CheckResult, PackGrade, RunResult, ToolClassification } from "../types.js";
import { check } from "./helpers.js";
import { kids, parseXml, validateJunit, validateSarifShape } from "./shape.js";

// ---------------------------------------------------------------------------------------------------------
// A full 0.2 result built by hand: no harness involved.
// ---------------------------------------------------------------------------------------------------------

const SB = process.platform === "win32" ? "C:\\Users\\jo\\AppData\\Local\\Temp\\sealmark-abc123" : "/tmp/sealmark-abc123";
const sep = process.platform === "win32" ? "\\" : "/";

function grade(pack: string, letter: PackGrade["letter"], o: Partial<PackGrade> = {}): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [], ...o };
}

const classification: ToolClassification[] = [
  { tool: "read_file", class: "path", confidence: "high", params: { path: "path" }, unfillable: [], annotations: { readOnlyHint: true }, reasons: ['param "path"', "name matches /read|file/"] },
  { tool: "search", class: "text", confidence: "low", params: {}, unfillable: [], reasons: ['generic parameter "query" with no hint'] },
];

function fullRun(over: Partial<RunResult> = {}): RunResult {
  const checks: CheckResult[] = [
    check("protocol", "pass"),
    { ...check("tool-poisoning", "pass", { critical: true }), label: "No tool-poisoning indicators" },
    check("robust-input", "pass"),
    check("secret-echo", "pass", { critical: true }),
    { ...check("fs-read-escape", "fail", { critical: true, pack: "fs" }), label: "Reads outside the root are refused", summary: `read ${SB}${sep}canary${sep}secret.txt succeeded`, scope: "server (path validation)" },
    { ...check("fs-write-escape", "pass", { critical: true, pack: "fs" }), label: "Writes outside the root are refused" },
    { ...check("fs-link-escape", "part", { critical: true, pack: "fs" }), label: "Links do not escape" },
    { ...check("fs-size-cap", "inconclusive", { pack: "fs" }), label: "Large reads are capped" },
    { ...check("annotation-honesty", "na", { pack: "effects" }), label: "Annotations are honest" },
    { ...check("write-gate", "fail", { advisory: true, pack: "db" }), label: "Write approval gate" },
  ];
  checks[4].evidence = [{ probe: `read_file ${SB}${sep}root${sep}..${sep}canary${sep}secret.txt`, outcome: `sm-fscanary-1 at ${SB.replace(/\\/g, "/")}/canary/secret.txt`, verifiedBy: "response", tool: "read_file" }];
  return {
    sealmark: { version: "0.2.0", methodology: "0.2-draft" },
    server: { name: "Server A", version: "1.2.3", command: "node server.js {sandbox}", env: { API_TOKEN: "<redacted>" }, transport: "stdio", tools: ["read_file", "search"], sqlTools: [], resolved: { configVersion: "1.2.3", package: { name: "server-a", version: "1.2.4", source: "npx-cache" } } },
    options: { packsRequested: ["core", "fs"], timeoutProbeSec: 10, active: false, sandbox: true },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 4321,
    packs: {
      core: { status: "graded", grade: grade("core", "A") },
      db: { status: "na", reason: "server config has no {dsn} placeholder" },
      fs: { status: "graded", grade: grade("fs", "D", { pct: 50, raw: "C", capped: true, criticalFails: ["fs-read-escape"], excluded: ["fs-size-cap"] }) },
      effects: { status: "na", reason: "no annotated tool" },
    },
    checks,
    notCovered: ["audit logging (not measured in methodology 0.1)"],
    classification,
    sandbox: { dir: SB, envMode: "scrubbed", listenerPort: 4455, cleanedUp: true, leftoverProcesses: [], active: false, enabled: true, kept: false },
    config: { hash: "sha256:aaaa1111bbbb2222cccc3333", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {}, path: "C:\\proj\\sealmark.yaml" },
    coverage: { validCalls: 6, toolsCalledValid: 1, toolsTotal: 2, level: "covered" },
    badge: { eligible: true },
    warnings: ["serverInfo.version 1.2.3 differs from config version 1.2.4"],
    ...over,
  };
}

const custom = (n = 2): RunResult =>
  fullRun({
    config: {
      hash: "sha256:dddd",
      profile: "quick",
      standard: false,
      standardDiff: [
        { path: "timeout_probe_sec", standard: 10, effective: 3, origin: "flag --timeout-probe" },
        { path: "packs", standard: ["core", "db", "fs"], effective: ["core"], origin: "sealmark.yaml:4" },
      ].slice(0, n),
      methodology: "0.2-draft",
      schemaVersion: 1,
      locked: {},
    },
    badge: { eligible: false, reason: "custom run: the configuration differs from the published standard profile" },
  });

// ---------------------------------------------------------------------------------------------------------

describe("text report", () => {
  it("STANDARD header, no diff lines, pack lines without a custom tag", () => {
    const t = renderText(fullRun());
    assert.match(t, /^sealmark 0\.2\.0 · methodology 0\.2-draft · STANDARD · Server A 1\.2\.3\n/);
    assert.match(t, /PACK core {2}GRADE A {2}\(3\/4 points, 75%\)\n/);
    assert.ok(!t.includes("custom grade"));
    assert.ok(t.trimEnd().endsWith(CLOSING_LINE));
  });

  it("CUSTOM header counts and lists the differences with their origin, and tags every grade", () => {
    const t = renderText(custom());
    assert.match(t, /^sealmark 0\.2\.0 · methodology 0\.2-draft · CUSTOM \(not the published methodology: 2 differences\) · Server A 1\.2\.3\n/);
    assert.match(t, /\n {2}timeout_probe_sec: standard 10, effective 3 {2}\(flag --timeout-probe\)\n/);
    assert.match(t, /\n {2}packs: standard \["core","db","fs"\], effective \["core"\] {2}\(sealmark\.yaml:4\)\n/);
    assert.match(t, /PACK core {2}GRADE A {2}\(3\/4 points, 75%\) {2}custom grade\n/);
    assert.match(t, /PACK fs {2}GRADE D {2}\(.*\) {2}custom grade\n/);
    assert.match(t, /Badge: not eligible: custom run/);
    assert.equal(renderText(custom(1)).includes("1 difference)"), true, "singular");
  });

  it("core coverage tag: hygiene only when nothing else graded, low coverage otherwise, nothing when covered", () => {
    const only = fullRun({ packs: { core: { status: "graded", grade: grade("core", "A") } }, checks: fullRun().checks.filter((c) => c.pack === "core"), coverage: { validCalls: 0, toolsCalledValid: 0, toolsTotal: 14, level: "hygiene-only" }, badge: { eligible: false, reason: "core-only run: hygiene checks only" } });
    const t = renderText(only);
    assert.match(t, /PACK core {2}GRADE A {2}\(3\/4 points, 75%\) {2}hygiene only · tools called with valid arguments: 0 of 14\n/);
    assert.match(t, /Core is hygiene only/);
    assert.match(t, /Badge: not eligible: core-only run/);
    assert.match(renderText(fullRun({ coverage: { validCalls: 2, toolsCalledValid: 1, toolsTotal: 9, level: "low" } })), /PACK core.*low coverage · tools called with valid arguments: 1 of 9/);
    assert.ok(!/hygiene only|low coverage/.test(renderText(fullRun()).split("\n").find((l) => l.startsWith("PACK core"))!));
  });

  it("prints the classification block, the sandbox line, the resolved package, warnings and the badge", () => {
    const t = renderText(fullRun());
    assert.match(t, /\nClassification:\n {2}read_file {2}path {2}high {2}\[readOnly\] {2}← param "path", name matches \/read\|file\/\n/);
    assert.match(t, /search +text +low +core only: generic parameter "query" with no hint; add it under tools: to include it/);
    assert.match(t, /packs applied: core, fs\n/); // effects is na; core is listed like any pack that ran
    assert.match(t, /\nsandbox: \{sandbox_dir\} · env scrubbed · listener 127\.0\.0\.1:\{listener_port\} · cleaned up\n/);
    assert.match(t, /\nresolved package: server-a 1\.2\.4 \(npx-cache\)\n/);
    assert.match(t, /\nWarnings:\n {2}- serverInfo\.version 1\.2\.3 differs/);
    assert.match(t, /\nBadge: eligible/);
  });

  it("describes a sandbox that is off, kept or not cleaned up", () => {
    const off = renderText(fullRun({ sandbox: { dir: null, envMode: "inherited", listenerPort: 1, cleanedUp: true, leftoverProcesses: [], active: false, enabled: false, kept: false } }));
    assert.match(off, /sandbox: off \(--no-sandbox\)/);
    const dirty = renderText(fullRun({ sandbox: { dir: SB, envMode: "scrubbed", listenerPort: null, cleanedUp: false, leftoverProcesses: ["node (4242)"], active: true, enabled: true, kept: false } }));
    assert.match(dirty, /--active · NOT cleaned up \(still running: node \(4242\)\)/);
    const kept = renderText(fullRun({ sandbox: { dir: SB, envMode: "scrubbed", listenerPort: null, cleanedUp: true, leftoverProcesses: [], active: false, enabled: true, kept: true } }));
    assert.ok(kept.includes(`sandbox: ${SB} ·`), "a kept sandbox shows its real path so the user can find it");
  });

  it("sorts failures first, marks provisional, and shows the cap", () => {
    const t = renderText(fullRun());
    const fsBlock = t.slice(t.indexOf("PACK fs"));
    assert.ok(fsBlock.indexOf("[FAIL] Reads outside") < fsBlock.indexOf("[PART] Links do not escape"));
    assert.ok(fsBlock.indexOf("[PART]") < fsBlock.indexOf("[INCL]"));
    assert.ok(fsBlock.indexOf("[INCL]") < fsBlock.indexOf("[PASS]"));
    assert.match(t, /Capped at D: critical fail\(s\): Reads outside the root are refused\. Without the cap this would be C \(50%\)\./);
    assert.match(t, /INCL = inconclusive/);
  });

  it("quiet drops passing checks and the context blocks; verbose prints the evidence", () => {
    const quiet = renderText(fullRun(), { verbosity: "quiet" });
    assert.ok(!quiet.includes("[PASS]") && !quiet.includes("Classification:") && !quiet.includes("Not covered:"));
    assert.match(quiet, /\[FAIL\] Reads outside/);
    const verbose = renderText(fullRun(), { verbosity: "verbose" });
    assert.match(verbose, /· \[response read_file\] read_file /);
  });

  it("no double space when the version is empty", () => {
    const r = fullRun();
    r.server.version = "";
    assert.match(renderText(r), /^sealmark 0\.2\.0 · methodology 0\.2-draft · STANDARD · Server A\n/);
    assert.ok(!/Server A {2}/.test(renderText(r).split("\n")[0]));
  });

  it("summaryLine names the capped pack and its critical fails, tags hygiene only and custom", () => {
    assert.equal(summaryLine(fullRun()), "core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape");
    assert.equal(summaryLine(custom()), "core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape · custom");
    const only = fullRun({ packs: { core: { status: "graded", grade: grade("core", "A") } }, coverage: { validCalls: 0, toolsCalledValid: 0, toolsTotal: 3, level: "hygiene-only" } });
    assert.equal(summaryLine(only), "core A (hygiene only)");
    assert.equal(summaryLine(fullRun({ packs: { core: { status: "na", reason: "x" } } })), "nothing graded");
    assert.equal(summaryLine(fullRun({ packs: { core: { status: "inconclusive", reason: "x" } } })), "core inconclusive");
  });
});

describe("redaction", () => {
  it("rewrites sandbox paths in both separator forms, doubled backslashes and URLs", () => {
    const rw = makePathRewriter(SB);
    const fwd = SB.replace(/\\/g, "/");
    assert.equal(rw(`${SB}${sep}root${sep}ok.txt`), "{sandbox}/ok.txt");
    assert.equal(rw(`${fwd}/root/sub/a b`), "{sandbox}/sub/a b", "a path ends at whitespace");
    assert.equal(rw(`${fwd}/canary/secret.txt`), "{canary}/secret.txt");
    assert.equal(rw(`${fwd}/root-evil/secret.txt`), "{sandbox_evil}/secret.txt", "root-evil is not read as root");
    assert.equal(rw(`${fwd}/home`), "{sandbox_home}");
    assert.equal(rw(`${fwd}/bin/sm-echo`), "{sandbox_bin}/sm-echo");
    assert.equal(rw(`dir=${SB}`), "dir={sandbox_dir}");
    assert.equal(rw(`${SB}-other${sep}x`), `${SB}-other${sep}x`, "a longer sibling name is left alone");
    if (process.platform === "win32") {
      assert.equal(rw(`file:///${fwd}/root/a.txt`), "file:///{sandbox}/a.txt");
      assert.equal(rw(SB.replace(/\\/g, "\\\\") + "\\\\root\\\\x.txt"), "{sandbox}/x.txt", "JSON-escaped backslashes");
      assert.equal(rw(SB.toUpperCase() + "\\ROOT\\x"), "{sandbox}/x", "Windows paths are case-insensitive");
      assert.equal(rw("\\\\?\\" + SB + "\\root\\x"), "{sandbox}/x", "\\\\?\\ prefix");
    }
    assert.equal(makePathRewriter(null)("anything"), "anything");
  });

  it("scrubs secret literals, longest first, and ignores short ones", () => {
    const s = makeSecretScrubber(["abc", "hunter2-long", "hunter2"]);
    assert.equal(s("x hunter2-long y hunter2 z abc"), "x <redacted> y <redacted> z abc");
  });

  it("applies to every string in the result, text and JSON", () => {
    const r = fullRun();
    const json = renderJson(r, { secrets: ["API_TOKEN-value-1"] });
    assert.ok(!json.includes("abc123"), "no sandbox id survives");
    assert.ok(!json.includes("AppData"), "no user path survives");
    const parsed = JSON.parse(json) as RunResult;
    assert.equal(parsed.checks[4].evidence[0].outcome, "sm-fscanary-1 at {canary}/secret.txt");
    assert.equal(parsed.sandbox?.dir, "{sandbox_dir}");
    const withSecret = fullRun();
    withSecret.checks[0].summary = "token API_TOKEN-value-1 echoed";
    assert.match(renderText(withSecret, { secrets: ["API_TOKEN-value-1"] }), /token <redacted> echoed/);
  });

  it("--no-redact and a kept sandbox leave real paths alone", () => {
    assert.ok(renderJson(fullRun(), { redact: false }).includes("abc123"));
    const kept = fullRun();
    kept.sandbox = { ...kept.sandbox!, kept: true };
    assert.ok(renderJson(kept).includes("abc123"));
  });

  it("does not mutate its input", () => {
    const r = fullRun();
    const before = JSON.stringify(r);
    redactResult(r);
    assert.equal(JSON.stringify(r), before);
  });
});

describe("renderReport", () => {
  it("json: one run is the RunResult, several runs are { runs }", () => {
    const a = fullRun();
    const b = fullRun();
    b.server.name = "Server B";
    assert.equal((JSON.parse(renderReport("json", [a])) as RunResult).server.name, "Server A");
    const multi = JSON.parse(renderReport("json", [a, b])) as { runs: RunResult[] };
    assert.deepEqual(multi.runs.map((r) => r.server.name), ["Server A", "Server B"]);
  });

  it("text: several runs print one block per server and a Matrix summary", () => {
    const b = custom();
    b.server.name = "Server B";
    const t = renderReport("text", [fullRun(), b]);
    assert.equal(t.match(/^sealmark 0\.2\.0/gm)?.length, 2);
    assert.match(t, /Matrix:\n {2}Server A {2}core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape\n {2}Server B {2}core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape · custom\n/);
  });

  it("a failed run appears in every format", () => {
    const f: FailedRun = { status: "failed", server: "dead", error: "could not start <x> & y", hint: "pin it", stderrFile: "out.stderr.log", sealmark: { version: "0.2.0", methodology: "0.2-draft" } };
    const runs: AnyRun[] = [fullRun(), f];
    assert.match(renderReport("text", runs), /server dead: FAILED\n {2}could not start <x> & y\n {2}hint: pin it/);
    assert.deepEqual((JSON.parse(renderReport("json", runs)) as { runs: unknown[] }).runs[1], f);
    assert.match(renderReport("markdown", runs), /\*\*FAILED:\*\* could not start &lt;x> & y/);
    const j = validateJunit(renderReport("junit", runs));
    assert.equal(j.attrs.errors, "1");
    const s = validateSarifShape(renderReport("sarif", runs));
    assert.ok(s.runs.some((r: { results: { ruleId: string }[] }) => r.results.some((x) => x.ruleId === "harness-failure")));
  });
});

describe("junit", () => {
  it("one suite per pack, one testcase per check, failure only for scored fails, skipped for na and inconclusive", () => {
    const root = validateJunit(renderReport("junit", [fullRun()]));
    assert.deepEqual(root.children.map((s) => s.attrs.name), ["core", "db", "fs", "effects"]);
    const fs = root.children.find((s) => s.attrs.name === "fs")!;
    const cases = kids(fs, "testcase");
    const fail = cases.find((c) => c.attrs.name.startsWith("fs-read-escape"))!;
    assert.equal(kids(fail, "failure").length, 1);
    assert.equal(kids(fail, "failure")[0].attrs.type, "critical-fail");
    assert.equal(kids(cases.find((c) => c.attrs.name.startsWith("fs-size-cap"))!, "skipped").length, 1);
    const part = cases.find((c) => c.attrs.name.startsWith("fs-link-escape"))!;
    assert.equal(part.children.filter((k) => k.name === "failure").length, 0);
    assert.match(kids(part, "system-out")[0].text, /PART/);
    // The advisory write-gate fails, but an advisory check never turns the CI step red.
    const db = root.children.find((s) => s.attrs.name === "db")!;
    assert.equal(db.attrs.failures, "0");
    assert.match(kids(kids(db, "testcase")[0], "system-out")[0].text, /advisory FAIL/);
    // The pack that never ran still shows up, as one skipped case with the reason.
    const effects = root.children.find((s) => s.attrs.name === "effects")!;
    assert.equal(effects.attrs.skipped, "1");
  });

  it("carries the STANDARD/CUSTOM label in a comment, in properties and in system-out", () => {
    const xml = renderReport("junit", [custom()]);
    validateJunit(xml);
    assert.match(xml, /<!-- sealmark 0\.2\.0 · methodology 0\.2-draft · CUSTOM/);
    assert.match(xml, /<property name="sealmark\.standard" value="false"\/>/);
    assert.match(xml, /<system-out>sealmark 0\.2\.0 · methodology 0\.2-draft · CUSTOM/);
    assert.match(renderReport("junit", [fullRun()]), /name="sealmark\.standard" value="true"/);
  });

  it("escapes markup in check text and removes control characters", () => {
    const r = fullRun();
    r.checks[4].summary = 'a <b> & "c" \u0001 \'d\'';
    const xml = renderReport("junit", [r]);
    validateJunit(xml);
    assert.ok(xml.includes("a &lt;b&gt; &amp; &quot;c&quot; ? &apos;d&apos;"));
  });

  it("several servers: suite names carry the server", () => {
    const b = fullRun();
    b.server.name = "Server B";
    const root = validateJunit(renderReport("junit", [fullRun(), b]));
    assert.ok(root.children.some((s) => s.attrs.name === "Server B / fs"));
  });

  it("the parser used here rejects malformed XML (so the checks above mean something)", () => {
    assert.throws(() => parseXml("<a><b></a>"));
    assert.throws(() => parseXml('<a x="1" x="2"/>'));
    assert.throws(() => parseXml("<a>1 < 2</a>"));
    assert.throws(() => parseXml("<a>R&D</a>"));
  });
});

describe("sarif", () => {
  it("has the required shape; results only for fail and part; levels follow severity", () => {
    const sarif = validateSarifShape(renderReport("sarif", [fullRun()]));
    const run = sarif.runs[0];
    const byRule = Object.fromEntries(run.results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]));
    assert.deepEqual(byRule, { "fs-read-escape": "error", "fs-link-escape": "warning", "write-gate": "warning" });
    assert.ok(run.tool.driver.rules.some((r: { id: string }) => r.id === "protocol"), "passing checks are still rules");
    const first = run.results.find((r: { ruleId: string }) => r.ruleId === "fs-read-escape");
    assert.equal(first.partialFingerprints["sealmarkCheck/v1"], "Server A:fs-read-escape:read_file");
    assert.equal(first.locations[0].physicalLocation.artifactLocation.uri, "sealmark.yaml");
    assert.ok(!JSON.stringify(sarif).includes("abc123"), "sandbox paths are redacted");
    assert.equal(run.properties.standard, true);
    assert.equal(run.properties.configHash, "sha256:aaaa1111bbbb2222cccc3333");
  });

  it("a custom run says so", () => {
    const sarif = validateSarifShape(renderReport("sarif", [custom()]));
    assert.equal(sarif.runs[0].properties.standard, false);
    assert.match(sarif.runs[0].properties.header, /CUSTOM/);
  });
});

describe("markdown", () => {
  it("has the header, tables and sections; table cells are escaped", () => {
    const r = custom();
    r.checks[4].summary = "a | b\nc";
    const md = renderMarkdown([r]);
    assert.match(md, /^# Sealmark report: Server A 1\.2\.3\n/);
    assert.match(md, /> sealmark 0\.2\.0 · methodology 0\.2-draft · CUSTOM/);
    assert.match(md, /\| `timeout_probe_sec` \| 10 \| 3 \| flag --timeout-probe \|/);
    assert.match(md, /## Pack `fs`/);
    assert.match(md, /\| FAIL \(critical\) \| `fs-read-escape` .* \| a \\\| b c \|/);
    assert.match(md, /## Classification\n\n\| Tool \| Class \| Confidence \| Why \|/);
    assert.match(md, /\*\*core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape · custom\*\*/);
    assert.ok(md.trimEnd().endsWith(`_${CLOSING_LINE}_`));
    assert.ok(!md.includes("abc123"));
  });

  it("--verbosity verbose adds every evidence line and probe argument; normal does not", () => {
    const r = fullRun();
    r.checks[0].evidence = [{ probe: "initialize | tools/list", outcome: "ok", verifiedBy: "protocol", tool: "read_file", args: { path: "a" } }];
    const verbose = renderMarkdown([r], { verbosity: "verbose" });
    assert.match(verbose, /\*\*Evidence for `protocol`\*\*\n\n- \[protocol read_file\] initialize \\\| tools\/list → ok \(args: `\{"path":"a"\}`\)/);
    assert.ok(!renderMarkdown([r]).includes("Evidence for"));
    assert.ok(!renderMarkdown([r], { verbosity: "quiet" }).includes("Evidence for"));
  });

  it("an HTTP server's sandbox line says the server was not started, not that --no-sandbox was passed", () => {
    const sandbox = { dir: null, envMode: "inherited" as const, listenerPort: 1, cleanedUp: true, leftoverProcesses: [], active: false, enabled: false, kept: false };
    const base = fullRun({ sandbox });
    const http = { ...base, server: { ...base.server, transport: "http" as const } };
    assert.match(renderText(http), /sandbox: not used: the server was already running over HTTP/);
    assert.ok(!renderText(http).includes("--no-sandbox"));
    assert.match(renderMarkdown([http]), /- Sandbox: not used; the server was already running over HTTP/);
    assert.ok(!renderMarkdown([http]).includes("--no-sandbox"));
    assert.match(renderMarkdown([{ ...base, server: { ...base.server, transport: "stdio" as const } }]), /- Sandbox: off \(`--no-sandbox`\)/);
  });

  it("several runs get one section each under a matrix heading", () => {
    const md = renderMarkdown([fullRun(), fullRun()]);
    assert.match(md, /^# Sealmark matrix report\n/);
    assert.equal(md.match(/^## Sealmark report: /gm)?.length, 2);
  });
});

describe("summary", () => {
  it("shows the banner, a grade card per graded pack, failures first, and says what caps a grade", () => {
    const t = renderSummary([custom()], { gate: "B" });
    assert.match(t, /S E A L M A R K {3}·/);
    assert.match(t, /Server A 1\.2\.3 {2}·  CUSTOM profile/);
    assert.match(t, /│ +core +│ +│ +fs +│/); // cards side by side
    assert.match(t, /capped at D/);
    assert.match(t, /BELOW B: fs D/);
    const rows = t.split("\n").filter((l) => l.startsWith("[ "));
    assert.match(rows[0], /^\[ FAIL \] fs\/fs-read-escape +/);
    assert.ok(rows.findIndex((l) => l.startsWith("[ PASS ]")) > rows.findIndex((l) => l.startsWith("[ FAIL ]")), "failures sort before passes");
    assert.match(t, /WHAT TO FIX\n\n ▸ fs\/fs-read-escape {2}FAIL {2}← caps the fs grade at D\n {5}read /);
    assert.ok(!t.includes("abc123"), "sandbox paths are redacted like every other format");
    assert.ok(!t.includes("\x1b["), "no colors unless asked");
  });

  it("colors only on request, and the gate letter drives the verdict line", () => {
    assert.ok(renderSummary([custom()], { color: true }).includes("\x1b[31;1m"));
    const ok = fullRun();
    for (const p of Object.values(ok.packs)) if (p?.grade) Object.assign(p.grade, { letter: "A", capped: false, criticalFails: [] });
    ok.checks.forEach((c) => (c.verdict = "pass"));
    assert.match(renderSummary([ok], { gate: "B" }), /ALL GRADED PACKS AT B OR BETTER/);
    assert.match(renderSummary([ok]), /WORST GRADE: A/, "without a gate the summary reports and does not judge");
    assert.ok(!/BELOW|ALL GRADED PACKS/.test(renderSummary([custom()])), "no verdict without a gate");
    assert.match(renderSummary([ok], { gate: "A" }), /ALL GRADED PACKS AT A OR BETTER/);
  });

  it("a server that failed to run is one clear line, not a crash", () => {
    const failed: FailedRun = { status: "failed", server: "svc", error: "the server exited with code 3", sealmark: { version: "0.2.0", methodology: "0.2-draft" } };
    assert.match(renderSummary([failed]), /svc: FAILED\n {2}the server exited with code 3/);
  });

  it("renderReport routes the summary format", () => {
    assert.match(renderReport("summary", [custom()], {}), /S E A L M A R K/);
  });
});

describe("failed runs are scrubbed", () => {
  it("a server's own output in a failed run's message never reaches any format when it holds a known secret", () => {
    const failed: FailedRun = { status: "failed", server: "svc", error: "the server exited with code 1 before the URL answered. Its last output:\ninput_value='sk-live-abcdef0123456789'", hint: "token sk-live-abcdef0123456789 was rejected", sealmark: { version: "0.2.0", methodology: "0.2-draft" } };
    const o = { secrets: ["sk-live-abcdef0123456789"] };
    for (const f of ["text", "json", "markdown", "junit", "sarif", "summary"] as const) {
      const out = renderReport(f, [failed], o);
      assert.ok(!out.includes("sk-live-abcdef0123456789"), `${f} leaked the secret`);
      assert.ok(/redacted/.test(out), `${f} shows that something was removed`);
    }
    assert.ok(renderReport("json", [failed], { ...o, redact: false }).includes("sk-live-abcdef0123456789"), "--no-redact still prints it, as documented");
  });
});

describe("templates", () => {
  const ctx = { server: { name: "S" }, list: ["a", "b", "c"], empty: [], flag: true, obj: { x: 1, y: 2 }, nested: [{ id: 1, tags: ["p", "q"] }] };

  it("substitutes, loops with @index/@first/@last, branches, and reads enclosing scopes", () => {
    assert.equal(renderTemplate("Hi {{server.name}}!", ctx), "Hi S!");
    assert.equal(renderTemplate("{{#each list}}{{@index}}={{this}}{{#if @last}}.{{else}},{{/if}}{{/each}}", ctx), "0=a,1=b,2=c.");
    assert.equal(renderTemplate("{{#each obj}}{{@key}}:{{this}};{{/each}}", ctx), "x:1;y:2;");
    assert.equal(renderTemplate("{{#if empty}}yes{{else}}no{{/if}}|{{#unless empty}}u{{/unless}}|{{#if flag}}f{{/if}}", ctx), "no|u|f");
    assert.equal(renderTemplate("{{#each nested}}{{id}}@{{server.name}}[{{#each tags}}{{this}}{{/each}}]{{/each}}", ctx), "1@S[pq]");
    assert.equal(renderTemplate("[{{missing.thing}}]{{! a comment }}", ctx), "[]");
    assert.equal(renderTemplate("{{json obj}}", ctx), '{\n  "x": 1,\n  "y": 2\n}');
    assert.equal(renderTemplate("{{{server.name}}}", ctx), "S");
  });

  it("rejects broken templates with a message", () => {
    assert.throws(() => renderTemplate("{{#each list}}x", ctx), TemplateError);
    assert.throws(() => renderTemplate("{{/if}}", ctx), /unexpected/);
    assert.throws(() => renderTemplate("{{#with x}}{{/with}}", ctx), /unknown block/);
    assert.throws(() => renderTemplate("{{#each list}}{{else}}{{/each}}", ctx), /only allowed inside/);
  });

  it("cannot read anything but the context (no code execution)", () => {
    assert.equal(renderTemplate("{{constructor.constructor}}{{__proto__}}{{process.env.PATH}}", {}), "");
  });

  it("the integrity header and the closing sentence are added around any template", () => {
    const out = applyTemplate("only my words: {{server.name}}", custom(), "text");
    assert.match(out, /^sealmark 0\.2\.0 · methodology 0\.2-draft · CUSTOM \(not the published methodology: 2 differences\)/);
    assert.match(out, /only my words: Server A/);
    assert.ok(out.trimEnd().endsWith(CLOSING_LINE));
    // A template that tries to hide the header cannot: the header is not part of what it renders.
    const sneaky = applyTemplate("{{#if config.standard}}STANDARD{{/if}}", custom(), "text");
    assert.ok(sneaky.includes("CUSTOM") && !sneaky.replace(/^[^\n]*\n/, "").includes("STANDARD (not"));
    const viaReport = renderReport("text", [custom()], { template: "# {{standardLabel}} {{summary}}\n{{#each packList}}{{id}}:{{status}} {{/each}}" });
    assert.match(viaReport, /# CUSTOM \(not the published methodology: 2 differences\) core A · fs D capped: critical fail: fs-read-escape critical part: fs-link-escape · custom\ncore:graded db:na fs:graded effects:na/);
    assert.match(renderReport("markdown", [fullRun()], { template: "## {{server.name}}" }), /## Server A/);
  });
});

describe("baseline", () => {
  const withVerdicts = (name: string, v: Record<string, CheckResult["verdict"]>, letters: Record<string, PackGrade["letter"]>, hash = "sha256:same"): RunResult => {
    const r = fullRun();
    r.server.name = name;
    r.config = { ...r.config!, hash };
    for (const c of r.checks) if (v[c.id]) c.verdict = v[c.id];
    for (const [p, l] of Object.entries(letters)) r.packs[p as keyof RunResult["packs"]] = { status: "graded", grade: grade(p, l) };
    return r;
  };

  it("an identical run has no regressions", () => {
    const d = compareBaseline([fullRun()], [fullRun()]);
    assert.deepEqual(d.regressions, []);
    assert.deepEqual(d.improvements, []);
  });

  it("flags a verdict that dropped and a letter that dropped, and only those", () => {
    const base = withVerdicts("S", { protocol: "pass", "fs-link-escape": "part", "fs-read-escape": "fail" }, { core: "A", fs: "C" });
    const cur = withVerdicts("S", { protocol: "fail", "fs-link-escape": "fail", "fs-read-escape": "fail", "tool-poisoning": "part" }, { core: "B", fs: "C" });
    const d = compareBaseline([base], [cur]);
    assert.deepEqual(d.regressions.map((r) => `${r.kind}:${r.check ?? r.pack}:${r.from}>${r.to}`).sort(), ["check:fs-link-escape:part>fail", "check:protocol:pass>fail", "check:tool-poisoning:pass>part", "letter:core:A>B"]);
  });

  it("improvements, new checks, and na/inconclusive changes are not regressions", () => {
    const base = withVerdicts("S", { "fs-link-escape": "fail", "fs-size-cap": "pass", "write-gate": "pass" }, { fs: "D" });
    const cur = withVerdicts("S", { "fs-link-escape": "pass", "fs-size-cap": "inconclusive", "write-gate": "na" }, { fs: "B" });
    cur.checks.push(check("brand-new", "fail"));
    const d = compareBaseline([base], [cur]);
    assert.deepEqual(d.regressions, []);
    assert.ok(d.improvements.some((i) => i.includes("fs-link-escape: fail -> pass")));
    assert.ok(d.improvements.some((i) => i.includes("grade rose D -> B")));
    assert.ok(d.notes.some((n) => n.includes("fs-size-cap") && n.includes("not ranked")));
  });

  it("a pack that stopped being graded is a regression; a pack that was never graded is not", () => {
    const base = fullRun();
    const cur = fullRun();
    cur.packs.fs = { status: "na", reason: "the sandbox is off" };
    const d = compareBaseline([base], [cur]);
    assert.equal(d.regressions.length, 1);
    assert.equal(d.regressions[0].kind, "pack-not-graded");
    assert.match(d.regressions[0].text, /pack fs: was graded D, now na \(the sandbox is off\)/);
  });

  it("advisory regressions are marked; a different configuration hash is noted", () => {
    const base = withVerdicts("S", { "write-gate": "pass" }, {});
    const cur = withVerdicts("S", { "write-gate": "fail" }, {}, "sha256:other");
    const d = compareBaseline([base], [cur]);
    assert.equal(d.regressions[0].advisory, true);
    assert.ok(d.notes.some((n) => n.includes("different configuration")));
  });

  it("matches servers by name; an unmatched server is a note; one against one ignores a rename", () => {
    const a = fullRun();
    const b = fullRun();
    b.server.name = "B";
    assert.deepEqual(compareBaseline([a, b], [b, a]).regressions, []);
    const renamed = fullRun();
    renamed.server.name = "Renamed";
    renamed.packs.core = { status: "graded", grade: grade("core", "C") };
    const d = compareBaseline([fullRun()], [renamed]);
    assert.equal(d.regressions.length, 1);
    assert.ok(d.notes.some((n) => n.includes('"Server A"')));
    assert.ok(compareBaseline([a, b], [renamed]).notes.some((n) => n.includes("not in the baseline")));
  });

  it("parseBaseline accepts one run or { runs } and explains anything else", () => {
    assert.equal(parseBaseline(JSON.stringify(fullRun())).length, 1);
    assert.equal(parseBaseline(JSON.stringify({ runs: [fullRun(), fullRun()] })).length, 2);
    assert.throws(() => parseBaseline("{nope"), /not valid JSON/);
    assert.throws(() => parseBaseline('{"hello":1}'), /no sealmark run/);
    assert.throws(() => parseBaseline(JSON.stringify({ runs: [{ status: "failed" }] })), /no sealmark run/);
  });
});

describe("exit policy", () => {
  const base: ExitPolicy = { treatInconclusiveAs: "pass", criticalFail: 0, failOnGate: true, failOnRegressions: true, failOnDrift: false, regressions: [], drift: [], baseline: false };
  const ok = (letter: PackGrade["letter"], extra: Partial<RunResult> = {}): RunResult => fullRun({ packs: { core: { status: "graded", grade: grade("core", letter) } }, ...extra });
  const failedRun: FailedRun = { status: "failed", server: "x", error: "e", sealmark: { version: "1", methodology: "m" } };

  it("0 when graded and no gate; 1 below --fail-under; 3 when nothing graded; 4 for a failed server", () => {
    assert.equal(decideExit([ok("F")], base).code, 0);
    const gate = { ...base, failUnder: "B" as const };
    assert.equal(decideExit([ok("A")], gate).code, 0);
    const below = decideExit([ok("C")], gate);
    assert.equal(below.code, 1);
    assert.deepEqual(below.messages, ["pack core graded C, below --fail-under B"]);
    const none = decideExit([fullRun({ packs: { core: { status: "na", reason: "r" } } })], gate);
    assert.equal(none.code, 3);
    assert.deepEqual(none.messages, ["no pack was graded; see the reasons in the report"]);
    assert.equal(decideExit([failedRun], gate).code, 4);
  });

  it("several servers: the worst code wins and messages name the server", () => {
    const b = ok("F");
    b.server.name = "B";
    const d = decideExit([ok("A"), b, failedRun], { ...base, failUnder: "B" });
    assert.equal(d.code, 4);
    assert.deepEqual(d.messages, ["server B: pack core graded F, below --fail-under B"]);
  });

  it("an inconclusive pack warns by default and fails with treat_inconclusive_as: fail", () => {
    const r = ok("A");
    r.packs.fs = { status: "inconclusive", reason: "the pack timed out" };
    const warn = decideExit([r], { ...base, failUnder: "B" });
    assert.equal(warn.code, 0);
    assert.match(warn.messages[0], /^warning: pack fs was inconclusive \(the pack timed out\) and is not covered by --fail-under B$/);
    assert.equal(decideExit([r], { ...base, failUnder: "B", treatInconclusiveAs: "fail" }).code, 1);
    assert.equal(decideExit([r], { ...base, treatInconclusiveAs: "fail" }).code, 0, "no gate, no failure");
  });

  it("critical_fail sets the exit code for a capped pack; 0 keeps 0.1 behavior", () => {
    const capped = fullRun();
    assert.equal(decideExit([capped], base).code, 0);
    const d = decideExit([capped], { ...base, criticalFail: 1 });
    assert.equal(d.code, 1);
    assert.match(d.messages[0], /critical fail in pack fs \(fs-read-escape\); exit code 1/);
  });

  it("regressions fail the run; without failOnGate (--fail-on regressions) --fail-under is ignored", () => {
    const reg = { server: "S", pack: "core" as const, kind: "letter" as const, from: "A", to: "B", text: "grade dropped" };
    const withBaseline = { ...base, baseline: true, regressions: [reg] };
    assert.equal(decideExit([ok("A")], withBaseline).code, 1);
    assert.match(decideExit([ok("A")], withBaseline).messages[0], /^regression: grade dropped$/);
    const only = decideExit([ok("F")], { ...base, baseline: true, failUnder: "B", failOnGate: false });
    assert.equal(only.code, 0, "F is below B but nothing regressed");
    assert.equal(only.reason, "no regression against the baseline");
    assert.equal(decideExit([ok("F")], { ...base, baseline: true, failUnder: "B" }).code, 1);
    assert.equal(decideExit([ok("A")], { ...withBaseline, failOnRegressions: false }).code, 0, "drift alone: a regression does not decide");
  });

  it("tool-surface drift fails the run only with failOnDrift, and only for breaking or notable entries", () => {
    const entry = (severity: "breaking" | "notable" | "info") => ({ server: "S", kind: "tool-removed" as const, severity, text: `a ${severity} change` });
    const drifted = { ...base, baseline: true, failOnGate: false, failOnRegressions: false, failOnDrift: true };
    assert.equal(decideExit([ok("F")], { ...drifted, drift: [entry("info")] }).code, 0);
    assert.equal(decideExit([ok("F")], { ...drifted, drift: [entry("info")] }).reason, "no tool-surface drift against the baseline");
    for (const severity of ["breaking", "notable"] as const) {
      const d = decideExit([ok("A")], { ...drifted, drift: [entry(severity)] });
      assert.deepEqual([d.code, d.reason], [1, "the tool surface drifted against the baseline"]);
    }
    assert.equal(decideExit([ok("A")], { ...drifted, failOnDrift: false, drift: [entry("breaking")] }).code, 0, "not asked for");
    assert.equal(decideExit([ok("A")], { ...drifted, baseline: false, drift: [entry("breaking")] }).code, 0, "no baseline, no drift");
    assert.equal(decideExit([ok("A")], { ...drifted, failOnRegressions: true }).reason, "no regression or tool-surface drift against the baseline");
  });
});

describe("secret harvesting", () => {
  type Arg = Parameters<typeof secretLiterals>[0];
  const cfg = (over: Record<string, unknown> = {}): Arg =>
    ({
      servers: [{ name: "s", spec: { command: "x", env: { API_KEY: "literal-key-123", PLAIN: "keepthis-1234", TOKEN_REF: "${MY_TOKEN}" }, headers: { Authorization: "Bearer abc-secret-0001" } } }],
      db: { embedded: null, pg: "postgres://su:pgpass-123@h:5432/postgres" },
      origins: {},
      value: {},
      env: { MY_TOKEN: "resolved-token-77" },
      ...over,
    }) as unknown as Arg;

  it("takes secret-named env and header values, resolves references, and takes url and --pg passwords", () => {
    const s = secretLiterals(cfg({ servers: [{ name: "s", spec: { url: "https://u:urlpass-9@host/mcp", env: { API_KEY: "literal-key-123", PLAIN: "keepthis-1234", TOKEN_REF: "${MY_TOKEN}" }, headers: { Authorization: "Bearer abc-secret-0001" } } }] }));
    for (const want of ["literal-key-123", "Bearer abc-secret-0001", "resolved-token-77", "pgpass-123", "urlpass-9"]) assert.ok(s.includes(want), `${want} is harvested`);
    for (const no of ["keepthis-1234", "${MY_TOKEN}"]) assert.ok(!s.includes(no), `${no} is not`);
  });

  it("from sealmark.local.yaml takes a server's env, headers, url and secret-looking arguments, and nothing else it carries", () => {
    const local = { layer: "local", source: "sealmark.local.yaml" };
    const s = secretLiterals(
      cfg({
        db: { embedded: null, pg: null },
        origins: { "/packs": local, "/sandbox/dir": local, "/server/env/GREETING": local, "/server/args": local, "/server/url": local },
        value: {
          packs: ["core"],
          sandbox: { dir: "D:/sandboxes/work" },
          server: { url: "https://host/mcp?k=urlsecret-5", env: { GREETING: "hello-secret-99" }, args: ["--db", "{sqlite_path}", "--api-key=abc-123-xyz", "--token", "tok-9999-zz", "server.js"] },
        },
      }),
    );
    for (const want of ["hello-secret-99", "--api-key=abc-123-xyz", "abc-123-xyz", "tok-9999-zz", "https://host/mcp?k=urlsecret-5"]) assert.ok(s.includes(want), `${want} is harvested`);
    for (const no of ["core", "D:/sandboxes/work", "{sqlite_path}", "server.js", "--db"]) assert.ok(!s.includes(no), `${no} is not`);
  });

  it("looks at servers.<name> too, and ignores other layers", () => {
    const s = secretLiterals(cfg({ db: { embedded: null, pg: null }, origins: { "/servers/a/env/X": { layer: "local", source: "l" }, "/servers/b/env/Y": { layer: "project", source: "p" } }, value: { servers: { a: { env: { X: "from-local-a" } }, b: { env: { Y: "from-project-b" } } } } }));
    assert.ok(s.includes("from-local-a") && !s.includes("from-project-b"));
  });
});

describe("secret harvesting for a server Sealmark starts itself", () => {
  type Arg = Parameters<typeof secretLiterals>[0];
  it("takes the token after an auth scheme on its own, and the real environment (the launched server is not sandboxed)", () => {
    const cfg = {
      servers: [{ name: "s", spec: { command: "my-server", url: "http://localhost:8000/mcp", headers: { Authorization: "Bearer tok-abcdef-123456" } } }],
      db: { embedded: null, pg: null },
      origins: {},
      value: {},
      env: { DEPLOY_API_SECRET: "env-secret-value-98765", HOME: "/home/runner" },
      sandbox: { enabled: true, scrub_env: true, keep_env: [] },
    } as unknown as Arg;
    const got = secretLiterals(cfg);
    assert.ok(got.includes("Bearer tok-abcdef-123456"), "the whole header value");
    assert.ok(got.includes("tok-abcdef-123456"), "the token alone, in case a server echoes only that");
    assert.ok(got.includes("env-secret-value-98765"), "a launched server inherits the environment, so it can echo any of it");
    assert.ok(!got.includes("/home/runner"), "ordinary paths stay readable");
  });
});
