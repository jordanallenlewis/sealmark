import type { CheckResult, RunResult } from "../types.js";
import { configLocation, headerBlock, headerLine, isFailed, orderedPackIds, summaryLine, xmlEscape as x, type AnyRun } from "./common.js";
import { redactResult, type RedactOptions } from "./redact.js";

/**
 * JUnit XML (the de-facto Ant/Jenkins layout: testsuites > testsuite > testcase with failure / skipped children).
 *
 * One testsuite per pack, one testcase per check:
 *   fail                      -> <failure>   (a scored or critical failure turns the CI step red)
 *   pass                      -> plain testcase
 *   part                      -> plain testcase, <system-out> says PART (JUnit has no warning state; the exit code and
 *                                --fail-under are the gate, not this file)
 *   na / inconclusive         -> <skipped>
 *   advisory (any verdict)    -> never a <failure>: advisory checks are not scored. The verdict is in <system-out>.
 * A server that could not be run (harness failure) is a testsuite with one <error> testcase.
 * The STANDARD/CUSTOM header is repeated in every suite's <properties> and <system-out> and as a leading XML comment.
 */

const attr = (k: string, v: string | number) => ` ${k}="${x(String(v))}"`;

function evidenceText(c: CheckResult): string {
  const lines = [`scope: ${c.scope}`, `summary: ${c.summary}`];
  if (c.enforcedBy) lines.push(`enforced by: ${c.enforcedBy}`);
  for (const e of c.evidence.slice(0, 40)) lines.push(`[${e.verifiedBy}${e.tool ? ` ${e.tool}` : ""}] ${e.probe} -> ${e.outcome}`);
  return lines.join("\n");
}

function testcase(c: CheckResult, suite: string, where: string): string[] {
  const name = `${c.id}: ${c.label}`;
  const open = `<testcase${attr("classname", `sealmark.${suite}`)}${attr("name", name)}${where}${attr("time", "0")}`;
  const flag = `${c.critical ? "critical " : ""}${c.advisory ? "advisory " : ""}${c.verdict.toUpperCase()}`;
  if (c.verdict === "fail" && !c.advisory) {
    return [`${open}>`, `<failure${attr("message", c.summary)}${attr("type", c.critical ? "critical-fail" : "fail")}>${x(evidenceText(c))}</failure>`, "</testcase>"];
  }
  if (c.verdict === "na" || c.verdict === "inconclusive") {
    return [`${open}>`, `<skipped${attr("message", `${c.verdict}: ${c.summary}`)}/>`, "</testcase>"];
  }
  if (c.verdict === "pass" && !c.advisory) return [`${open}/>`];
  return [`${open}>`, `<system-out>${x(`${flag}: ${c.summary}\n${evidenceText(c)}`)}</system-out>`, "</testcase>"];
}

function suites(r: RunResult, multi: boolean, ts: string): { xml: string[]; tests: number; failures: number; skipped: number } {
  const xml: string[] = [];
  let tests = 0;
  let failures = 0;
  let skipped = 0;
  // The configuration file and the line of the selected server in it, on every testcase (a run without a config file has none to name).
  const at = configLocation(r);
  const where = at ? `${attr("file", at.file)}${attr("line", at.line)}` : "";
  for (const id of orderedPackIds(r)) {
    const p = r.packs[id]!;
    const checks = r.checks.filter((c) => c.pack === id);
    const f = checks.filter((c) => c.verdict === "fail" && !c.advisory).length;
    const s = checks.filter((c) => c.verdict === "na" || c.verdict === "inconclusive").length;
    // A pack that never ran has no testcases; keep it visible as one skipped case so a dashboard shows why.
    const cases = checks.length ? checks.flatMap((c) => testcase(c, id, where)) : [`<testcase${attr("classname", `sealmark.${id}`)}${attr("name", `${id}: pack`)}${where}${attr("time", "0")}>`, `<skipped${attr("message", p.reason ?? p.status)}/>`, "</testcase>"];
    const n = checks.length || 1;
    const sk = checks.length ? s : 1;
    const name = multi ? `${r.server.name} / ${id}` : id;
    xml.push(`<testsuite${attr("name", name)}${attr("tests", n)}${attr("failures", f)}${attr("errors", 0)}${attr("skipped", sk)}${attr("time", "0")}${attr("timestamp", ts)}>`);
    xml.push("<properties>");
    xml.push(`<property${attr("name", "sealmark.server")}${attr("value", r.server.name)}/>`);
    xml.push(`<property${attr("name", "sealmark.methodology")}${attr("value", r.sealmark.methodology)}/>`);
    if (r.config) {
      xml.push(`<property${attr("name", "sealmark.standard")}${attr("value", String(r.config.standard))}/>`);
      xml.push(`<property${attr("name", "sealmark.config_hash")}${attr("value", r.config.hash)}/>`);
    }
    if (p.grade) xml.push(`<property${attr("name", "sealmark.grade")}${attr("value", `${p.grade.letter}${p.grade.capped ? " (capped)" : ""}`)}/>`);
    xml.push(`<property${attr("name", "sealmark.pack_status")}${attr("value", p.status)}/>`);
    // The run's warnings (a package that could not be resolved, an interrupted run, ...) travel with every suite, as the architecture says.
    for (const w of r.warnings ?? []) xml.push(`<property${attr("name", "sealmark.warning")}${attr("value", w)}/>`);
    xml.push("</properties>", ...cases);
    xml.push(`<system-out>${x(headerBlock(r).join("\n") + (p.grade ? `\nPACK ${id} GRADE ${p.grade.letter}` : `\nPACK ${id} not graded: ${p.reason ?? p.status}`))}</system-out>`, "</testsuite>");
    tests += n;
    failures += f;
    skipped += sk;
  }
  return { xml, tests, failures, skipped };
}

export function renderJunit(runs: AnyRun[], o: RedactOptions = {}): string {
  const multi = runs.length > 1;
  const body: string[] = [];
  let tests = 0;
  let failures = 0;
  let errors = 0;
  let skipped = 0;
  let ms = 0;
  const comments: string[] = [];
  for (const run of runs) {
    if (isFailed(run)) {
      errors += 1;
      tests += 1;
      body.push(`<testsuite${attr("name", `${run.server} / harness`)}${attr("tests", 1)}${attr("failures", 0)}${attr("errors", 1)}${attr("skipped", 0)}${attr("time", "0")}>`);
      body.push(`<testcase${attr("classname", "sealmark.harness")}${attr("name", `${run.server}: run`)}${attr("time", "0")}>`, `<error${attr("message", run.error)}${attr("type", "harness-failure")}>${x([run.error, run.hint ? `hint: ${run.hint}` : ""].filter(Boolean).join("\n"))}</error>`, "</testcase>", "</testsuite>");
      comments.push(`server ${run.server}: harness failure`);
      continue;
    }
    const r = redactResult(run, o);
    const s = suites(r, multi, r.startedAt);
    body.push(...s.xml);
    tests += s.tests;
    failures += s.failures;
    skipped += s.skipped;
    ms += r.durationMs;
    comments.push(`${headerLine(r)} | ${summaryLine(r)}`);
  }
  // "--" is not allowed inside an XML comment.
  const comment = comments.map((c) => c.replace(/--+/g, "-")).join(" ## ");
  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<!-- ${x(comment).replace(/&apos;/g, "'").replace(/&quot;/g, '"')} -->`,
    `<testsuites${attr("name", "sealmark")}${attr("tests", tests)}${attr("failures", failures)}${attr("errors", errors)}${attr("skipped", skipped)}${attr("time", (ms / 1000).toFixed(3))}>`,
    ...body,
    "</testsuites>",
    "",
  ].join("\n");
}
