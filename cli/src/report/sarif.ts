import type { CheckResult, RunResult } from "../types.js";
import { configLocation, headerLine, isFailed, orderedPackIds, summaryLine, type AnyRun } from "./common.js";
import { redactResult, type RedactOptions } from "./redact.js";

/**
 * SARIF 2.1.0. One rule per check id that appeared in the run (so a scorecard can show what was measured), and one result
 * per failed or partial check. Levels: fail -> error, part -> warning; advisory checks are one step lower (warning, note)
 * because they are not scored. na and inconclusive checks produce no result: SARIF results are findings, and "could not be
 * measured" is not a finding. The run's `properties` carry the STANDARD/CUSTOM label, the config hash and the run's warnings.
 *
 * `partialFingerprints.sealmarkCheck/v1` is `<check id>:<tool names from the evidence>` so a code-scanning service can match
 * the same finding across runs. Every result points at the configuration file: the finding is about how the server under
 * the configuration behaved, not about a line of code, and code-scanning services want a location.
 */

const SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

type Level = "none" | "note" | "warning" | "error";

function level(c: CheckResult): Level {
  if (c.verdict === "fail") return c.advisory ? "warning" : "error";
  if (c.verdict === "part") return c.advisory ? "note" : "warning";
  return "none";
}

// A secret echo is a property of the server (the environment it was given), and which tool happened to carry it can change from run to
// run: its evidence names the tool for the reader, but the fingerprint stays `<server>:secret-echo:server`.
const tools = (c: CheckResult) => [...new Set(c.evidence.filter((e) => e.code !== "secret.found").map((e) => e.tool).filter((t): t is string => Boolean(t)))].sort();

/** The configuration file (a run without one points at the default name) and the line of the selected server's `command`/`url` in it (1 when unknown). */
function locationOf(r: RunResult): { uri: string; line: number } {
  const at = configLocation(r);
  return { uri: at?.file ?? "sealmark.yaml", line: at?.line ?? 1 };
}

export function renderSarif(runs: AnyRun[], o: RedactOptions = {}): string {
  const sarifRuns = runs.flatMap((run): object[] => {
    if (isFailed(run)) {
      return [
        {
          tool: { driver: { name: "sealmark", version: run.sealmark.version, rules: [{ id: "harness-failure", name: "harness-failure", shortDescription: { text: "The harness could not run the server" } }] } },
          results: [{ ruleId: "harness-failure", ruleIndex: 0, level: "error" as Level, message: { text: `${run.server}: ${run.error}` } }],
          properties: { server: run.server, status: "failed" },
        },
      ];
    }
    const r = redactResult(run, o);
    const ids: string[] = [];
    const rules: object[] = [];
    for (const id of orderedPackIds(r)) {
      for (const c of r.checks.filter((x) => x.pack === id)) {
        if (ids.includes(c.id)) continue;
        ids.push(c.id);
        rules.push({
          id: c.id,
          name: c.id,
          shortDescription: { text: c.label },
          fullDescription: { text: `${c.label}. Scope: ${c.scope}` },
          defaultConfiguration: { level: c.advisory ? "note" : "error" },
          properties: { pack: c.pack, critical: c.critical, advisory: Boolean(c.advisory), scope: c.scope, tags: [c.pack, ...(c.critical ? ["critical"] : [])] },
        });
      }
    }
    const at = locationOf(r);
    const loc = { physicalLocation: { artifactLocation: { uri: at.uri, uriBaseId: "%SRCROOT%" }, region: { startLine: at.line } } };
    const results = r.checks
      .filter((c) => level(c) !== "none")
      .map((c) => ({
        ruleId: c.id,
        ruleIndex: ids.indexOf(c.id),
        level: level(c),
        message: { text: `${c.label}: ${c.summary} (${c.scope})` },
        locations: [loc],
        partialFingerprints: { "sealmarkCheck/v1": `${r.server.name}:${c.id}:${tools(c).join(",") || "server"}` },
        properties: { pack: c.pack, verdict: c.verdict, critical: c.critical, advisory: Boolean(c.advisory), server: r.server.name },
      }));
    return [
      {
        tool: { driver: { name: "sealmark", version: r.sealmark.version, rules } },
        automationDetails: { id: `sealmark/${r.server.name}/` },
        results,
        invocations: [{ executionSuccessful: true, startTimeUtc: r.startedAt }],
        properties: {
          server: r.server.name,
          methodology: r.sealmark.methodology,
          header: headerLine(r),
          standard: r.config?.standard ?? null,
          configHash: r.config?.hash ?? null,
          summary: summaryLine(r),
          ...(r.warnings?.length ? { warnings: r.warnings } : {}),
        },
      },
    ];
  });
  return JSON.stringify({ $schema: SCHEMA, version: "2.1.0", runs: sarifRuns }, null, 2);
}
