import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { deflateRawSync } from "node:zlib";
import { UsageError, type CommandOutput } from "./commands.js";
import { parseBaseline } from "./report/baseline.js";
import { inert } from "./report/sanitize.js";
import type { RunResult } from "./types.js";

/** Where the viewer lives. The report goes after the `#`, which a browser never sends to a server. */
export const VIEWER_URL = "https://sealmark.dev/report/";
/** The viewer refuses a fragment longer than this (web/lib/report-view.mjs MAX_FRAGMENT). */
export const MAX_FRAGMENT = 1_400_000;
/** Chat and mail tools often cut or refuse links much longer than this; the command says so past it. */
export const LONG_LINK = 8000;
const MAX_FILE = 5_000_000;
const MAX_TEXT = 400;
const MAX_CHECKS = 400;
const MAX_EVIDENCE = 12;
const MAX_RUNS = 20;

const text = (v: unknown, max = MAX_TEXT): string | undefined => (typeof v === "string" && v ? (v.length > max ? `${v.slice(0, max)}…` : v) : undefined);

/**
 * What the viewer shows and nothing else: server, versions, pack grades, every check with its evidence lines, what was not covered,
 * warnings. Environment, sandbox paths, tool lists, classification, arguments and response excerpts are left out, so the link is
 * shorter and carries less than the report file does.
 */
export function shareView(r: RunResult): Record<string, unknown> {
  const packs: Record<string, unknown> = {};
  for (const [id, p] of Object.entries(r.packs).slice(0, 40)) {
    if (!p) continue;
    packs[id] = { status: p.status, ...(p.reason ? { reason: text(p.reason) } : {}), ...(p.grade ? { grade: { letter: p.grade.letter, pct: p.grade.pct, provisional: p.grade.provisional, capped: p.grade.capped } } : {}) };
  }
  return {
    sealmark: { version: text(r.sealmark?.version, 40), methodology: text(r.sealmark?.methodology, 40) },
    server: { name: text(r.server.name, 200), version: text(r.server.version, 120), command: text(r.server.command, 600), transport: r.server.transport },
    startedAt: text(r.startedAt, 40),
    packs,
    checks: r.checks.slice(0, MAX_CHECKS).map((c) => ({
      id: text(c.id, 120),
      pack: text(c.pack, 60),
      label: text(c.label),
      scope: text(c.scope),
      verdict: c.verdict,
      summary: text(c.summary),
      ...(c.critical ? { critical: true } : {}),
      ...(c.advisory ? { advisory: true } : {}),
      evidence: c.evidence.slice(0, MAX_EVIDENCE).map((e) => ({ probe: text(e.probe), outcome: text(e.outcome), verifiedBy: e.verifiedBy, ...(e.tool ? { tool: text(e.tool, 120) } : {}), ...(e.role ? { role: text(e.role, 60) } : {}) })),
    })),
    notCovered: (r.notCovered ?? []).slice(0, 40).map((n) => text(n)).filter(Boolean),
    ...(r.config ? { config: { standard: r.config.standard, hash: text(r.config.hash, 80) } } : {}),
    ...(r.coverage ? { coverage: { level: r.coverage.level } } : {}),
    ...(r.warnings?.length ? { warnings: r.warnings.slice(0, 20).map((n) => text(n)).filter(Boolean) } : {}),
  };
}

export interface ShareLink {
  url: string;
  runs: number;
  servers: string[];
  /** Characters after the `#`. */
  fragmentChars: number;
}

/** base64url of the raw-deflated JSON of the viewer's view of the runs. Throws UsageError for a report that cannot be linked. */
export function shareLink(runs: RunResult[], viewer = VIEWER_URL): ShareLink {
  const views = runs.slice(0, MAX_RUNS).map(shareView);
  const json = JSON.stringify(views.length === 1 ? views[0] : { runs: views });
  const frag = deflateRawSync(Buffer.from(json, "utf8"), { level: 9 }).toString("base64url");
  if (frag.length > MAX_FRAGMENT) throw new UsageError(`this report is too large for a link (${frag.length} characters; the viewer reads up to ${MAX_FRAGMENT}). Open the file at ${viewer} instead`);
  return { url: `${viewer}#r=${frag}`, runs: views.length, servers: runs.slice(0, MAX_RUNS).map((r) => r.server.name), fragmentChars: frag.length };
}

/**
 * `sealmark share report.json`: prints a sealmark.dev/report/ link that opens the report in the browser, with the report inside the
 * link. Reads one file and prints; contacts nothing, uploads nothing, writes nothing.
 */
export function shareCommand(path: string | undefined, o: { json: boolean }): CommandOutput {
  if (!path) throw new UsageError("share needs a report file: sealmark share report.json (written by sealmark run --format json or --write-baseline)");
  let raw: string;
  try {
    const abs = resolve(path);
    if (statSync(abs).size > MAX_FILE) throw new UsageError(`${inert(path, 200)} is larger than a Sealmark report can be (${MAX_FILE} bytes)`);
    raw = readFileSync(abs, "utf8");
  } catch (e) {
    if (e instanceof UsageError) throw e;
    throw new UsageError(`cannot read the report ${inert(path, 200)} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`);
  }
  let runs: RunResult[];
  try {
    runs = parseBaseline(raw, `the report ${path}`);
  } catch (e) {
    throw new UsageError(inert((e as Error).message, 600));
  }
  const link = shareLink(runs);
  if (o.json) return { code: 0, stdout: `${JSON.stringify({ ...link, long: link.fragmentChars > LONG_LINK }, null, 2)}\n` };
  const names = link.servers.map((s) => inert(s, 120)).join(", ");
  const lines = [link.url, ""];
  lines.push(`${link.runs === 1 ? "1 run" : `${link.runs} runs`} (${names}) in a link of ${link.fragmentChars} characters. Nothing was uploaded: the report is in the link itself, after the #, which a browser does not send to a server.`);
  lines.push("Anyone with the link can read what it holds: server and tool names, the commands and outcomes in the evidence. Read the report before you send it.");
  if (link.fragmentChars > LONG_LINK) lines.push(`Some chat and mail tools cut links this long. If this one is cut, send the file and open it at ${VIEWER_URL} instead.`);
  return { code: 0, stdout: `${lines.join("\n")}\n` };
}
