import type { CheckConfig } from "../config/model.js";
import type { ExtraOutcome, PromptInfo, ResourceInfo } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence } from "../types.js";
import { brief } from "./shared.js";

// Resources and prompts (round 9): two advisory candidate checks in core for the MCP features beyond tools. Each sends a few fixed
// requests to what the server itself listed (resources/read, prompts/get), plus one request for a name it did not list, and reads
// only the protocol's answer. No model is asked, so the same server gives the same verdicts anywhere. Advisory: they are listed in
// every report and never move a letter (grade.ts skips advisory checks). They run after every scored core check, on the same session,
// so nothing a scored check sees changes.

export const RESOURCES_READ_META = { id: "resources-read", label: "Listed resources can be read", scope: "server" };
export const PROMPTS_GET_META = { id: "prompts-get", label: "Listed prompts can be fetched", scope: "server" };

/** Listed resources read, and listed prompts fetched, in listing order: enough to show the feature works, bounded for a server that lists thousands. */
export const MAX_EXTRA_REQUESTS = 5;
/** Per-request budget: a read or a get is a lookup, not work. */
export const EXTRA_TIMEOUT_MS = 10_000;
/** A URI no server lists: a harness-owned scheme, so no resource template of the server can match it. */
export const UNKNOWN_RESOURCE_URI = "sealmark-probe://not-listed/resource";
/** A prompt name no server lists. */
export const UNKNOWN_PROMPT_NAME = "sealmark-probe-not-listed";
/** The value sent for every required prompt argument. */
export const PROMPT_ARGUMENT_VALUE = "sealmark";
/** Evidence lines per check; the rest are counted in one closing line. */
const MAX_FINDINGS = 25;

/** The part of a session these checks use (McpSession has it; tests hand-build it). */
export interface ExtrasSession {
  capabilities: Record<string, unknown>;
  prompts: PromptInfo[];
  resources: ResourceInfo[];
  listErrors: string[];
  /** The connection is already gone (an earlier request ended it): nothing can be sent, so the check is inconclusive. */
  closed?: boolean;
  readResource(uri: string, timeoutMs: number): Promise<ExtraOutcome>;
  getPrompt(name: string, args: Record<string, string> | undefined, timeoutMs: number): Promise<ExtraOutcome>;
}

const label = (s: unknown): string => brief(String(s), 120);
type Done = (r: Pick<CheckResult, "verdict" | "summary" | "evidence">) => CheckResult;

function finisher(meta: { id: string; label: string; scope: string }): Done {
  const base = { id: meta.id, pack: "core" as const, label: meta.label, critical: false, advisory: true as const, scope: meta.scope };
  return (r) => ({ ...base, ...r });
}

function capped(found: Evidence[], probe: string, code: string): Evidence[] {
  if (found.length <= MAX_FINDINGS) return found;
  return [...found.slice(0, MAX_FINDINGS), { probe, outcome: `${found.length - MAX_FINDINGS} more line(s) not listed`, verifiedBy: "protocol", code }];
}

/** How a failed request reads in one evidence line. */
function failure(o: Extract<ExtraOutcome, { ok: false }>): string {
  if (o.closed) return `the connection closed (${o.message})`;
  if (o.timedOut) return `no answer within ${EXTRA_TIMEOUT_MS / 1000} s`;
  return o.code !== undefined ? `error ${o.code}: ${o.message}` : o.message;
}

/** What `listErrors` says about one list, or undefined when that list was read. */
const listError = (s: ExtrasSession, method: string): string | undefined => (s.listErrors ?? []).find((e) => e.startsWith(`${method} failed`));

/** Common verdict for both checks: fail on a closed connection or when no listed item worked; part on any other finding; else pass. */
function verdictOf(closed: boolean, tried: number, worked: number, findings: number): CheckResult["verdict"] {
  if (closed || (tried > 0 && worked === 0)) return "fail";
  return findings ? "part" : "pass";
}

/**
 * `resources-read` (advisory candidate). n/a unless the server advertises `resources` and lists at least one. Reads the first
 * MAX_EXTRA_REQUESTS listed resources (listing order) and one URI it did not list. fail: resources/list failed although advertised,
 * the connection closed, or no listed resource could be read. part: some listed resource could not be read, a read came back with no
 * contents, a URI is listed twice, or the unlisted URI was answered as a success (the spec asks for an error) or not answered in time.
 */
export async function resourcesRead(session: ExtrasSession, cfg?: CheckConfig): Promise<CheckResult> {
  const done = finisher(RESOURCES_READ_META);
  if (cfg?.enabled === false) return done({ verdict: "na", summary: "disabled by config", evidence: [] });
  if (!session.capabilities?.resources) return done({ verdict: "na", summary: "the server does not advertise resources", evidence: [] });
  const listFailed = listError(session, "resources/list");
  if (listFailed) return done({ verdict: "fail", summary: "resources/list failed although the server advertises resources", evidence: [{ probe: "resources/list", outcome: label(listFailed), verifiedBy: "protocol", code: "resources.list-failed" }] });
  const listed = session.resources ?? [];
  if (!listed.length) return done({ verdict: "na", summary: "the server advertises resources but lists none", evidence: [] });
  if (session.closed) return done({ verdict: "inconclusive", summary: "the session closed before resources could be requested", evidence: [] });

  const found: Evidence[] = [];
  const counted = new Map<string, number>();
  for (const r of listed) counted.set(r.uri, (counted.get(r.uri) ?? 0) + 1);
  const twice = [...counted].filter(([, n]) => n > 1).map(([u]) => u);
  for (const uri of twice.slice(0, MAX_FINDINGS)) found.push({ probe: "resources/list", outcome: `${label(uri)} is listed ${counted.get(uri)} times`, verifiedBy: "protocol", code: "resources.duplicate-uri" });

  const targets = [...new Set(listed.map((r) => r.uri))].slice(0, MAX_EXTRA_REQUESTS);
  let worked = 0;
  let closed = false;
  for (const uri of targets) {
    const probe = `resources/read ${label(uri)}`;
    const o = await session.readResource(uri, EXTRA_TIMEOUT_MS);
    if (o.ok) {
      const contents = (o.result as { contents?: unknown[] }).contents ?? [];
      worked++;
      if (contents.length) found.push({ probe, outcome: `read: ${contents.length} content item(s)`, verifiedBy: "protocol", code: "resources.read-ok" });
      else found.push({ probe, outcome: "answered with no contents", verifiedBy: "protocol", code: "resources.read-empty" });
      continue;
    }
    found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: o.closed ? "resources.read-closed" : o.timedOut ? "resources.read-timeout" : o.invalid ? "resources.read-invalid" : "resources.read-error" });
    if (o.closed) {
      closed = true;
      break;
    }
  }
  if (!closed) {
    const probe = `resources/read ${UNKNOWN_RESOURCE_URI} (not listed)`;
    const o = await session.readResource(UNKNOWN_RESOURCE_URI, EXTRA_TIMEOUT_MS);
    if (o.ok) found.push({ probe, outcome: "answered as a success; a URI the server does not have should be an error", verifiedBy: "protocol", code: "resources.unknown-served" });
    else if (o.closed) {
      closed = true;
      found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "resources.unknown-closed" });
    } else if (o.timedOut) found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "resources.unknown-timeout" });
    else found.push({ probe, outcome: label(`refused: ${failure(o)}`), verifiedBy: "protocol", code: "resources.unknown-refused" });
  }
  const findings = found.filter((e) => e.code !== "resources.read-ok" && e.code !== "resources.unknown-refused").length;
  const verdict = verdictOf(closed, targets.length, worked, findings);
  const tail = listed.length > targets.length ? ` (the first ${targets.length} of ${listed.length} listed)` : "";
  const summary = closed
    ? "the connection closed during resources/read"
    : `${worked} of ${targets.length} listed resource(s) read${tail}${findings ? `, ${findings} finding(s)` : ""}`;
  return done({ verdict, summary, evidence: capped(found, "resources/read", "resources.more") });
}

/**
 * `prompts-get` (advisory candidate). n/a unless the server advertises `prompts` and lists at least one. Fetches the first
 * MAX_EXTRA_REQUESTS listed prompts (listing order) with PROMPT_ARGUMENT_VALUE for every required argument, the first prompt that has a
 * required argument once with no arguments, and one name it did not list. A prompt with required arguments that refuses the fixed value
 * is recorded and not counted (the value may simply not fit). fail: prompts/list failed although advertised, the connection closed, or
 * every prompt without required arguments failed. part: a prompt is listed twice or names an argument twice, a fetch failed or came back
 * with no messages, a missing required argument or the unlisted name was answered as a success (the spec asks for an error), or a probe
 * was not answered in time.
 */
export async function promptsGet(session: ExtrasSession, cfg?: CheckConfig): Promise<CheckResult> {
  const done = finisher(PROMPTS_GET_META);
  if (cfg?.enabled === false) return done({ verdict: "na", summary: "disabled by config", evidence: [] });
  if (!session.capabilities?.prompts) return done({ verdict: "na", summary: "the server does not advertise prompts", evidence: [] });
  const listFailed = listError(session, "prompts/list");
  if (listFailed) return done({ verdict: "fail", summary: "prompts/list failed although the server advertises prompts", evidence: [{ probe: "prompts/list", outcome: label(listFailed), verifiedBy: "protocol", code: "prompts.list-failed" }] });
  const listed = session.prompts ?? [];
  if (!listed.length) return done({ verdict: "na", summary: "the server advertises prompts but lists none", evidence: [] });
  if (session.closed) return done({ verdict: "inconclusive", summary: "the session closed before prompts could be requested", evidence: [] });

  const found: Evidence[] = [];
  const seen = new Map<string, number>();
  for (const p of listed) seen.set(p.name, (seen.get(p.name) ?? 0) + 1);
  for (const [name, n] of [...seen].filter(([, k]) => k > 1).slice(0, MAX_FINDINGS)) found.push({ probe: "prompts/list", outcome: `${label(name)} is listed ${n} times`, verifiedBy: "protocol", code: "prompts.duplicate-name" });
  for (const p of listed) {
    const names = (p.arguments ?? []).map((a) => a.name);
    const dup = names.filter((n, i) => names.indexOf(n) !== i);
    if (dup.length) found.push({ probe: "prompts/list", outcome: `${label(p.name)} names the argument ${label([...new Set(dup)].join(", "))} more than once`, verifiedBy: "protocol", code: "prompts.duplicate-argument" });
  }

  const required = (p: PromptInfo): string[] => [...new Set((p.arguments ?? []).filter((a) => a.required).map((a) => a.name))];
  const unique = listed.filter((p, i) => listed.findIndex((q) => q.name === p.name) === i);
  const targets = unique.slice(0, MAX_EXTRA_REQUESTS);
  let tried = 0;
  let worked = 0;
  let closed = false;
  for (const p of targets) {
    const req = required(p);
    const args = req.length ? Object.fromEntries(req.map((n) => [n, PROMPT_ARGUMENT_VALUE])) : undefined;
    const probe = `prompts/get ${label(p.name)}${req.length ? ` with ${req.map((n) => `${label(n)}="${PROMPT_ARGUMENT_VALUE}"`).join(", ")}` : ""}`;
    const o = await session.getPrompt(p.name, args, EXTRA_TIMEOUT_MS);
    if (!req.length) tried++;
    if (o.ok) {
      const messages = (o.result as { messages?: unknown[] }).messages ?? [];
      if (!req.length) worked++;
      if (messages.length) found.push({ probe, outcome: `fetched: ${messages.length} message(s)`, verifiedBy: "protocol", code: "prompts.get-ok" });
      else found.push({ probe, outcome: "answered with no messages", verifiedBy: "protocol", code: "prompts.get-empty" });
      continue;
    }
    if (o.closed) {
      closed = true;
      found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "prompts.get-closed" });
      break;
    }
    if (req.length && !o.timedOut && !o.invalid) {
      found.push({ probe, outcome: label(`refused the fixed value (not counted): ${failure(o)}`), verifiedBy: "protocol", code: "prompts.get-refused-value" });
      continue;
    }
    found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: o.timedOut ? "prompts.get-timeout" : o.invalid ? "prompts.get-invalid" : "prompts.get-error" });
  }

  const withRequired = unique.find((p) => required(p).length > 0);
  if (!closed && withRequired) {
    const probe = `prompts/get ${label(withRequired.name)} with no arguments (it requires ${label(required(withRequired).join(", "))})`;
    const o = await session.getPrompt(withRequired.name, undefined, EXTRA_TIMEOUT_MS);
    if (o.ok) found.push({ probe, outcome: "answered as a success; a missing required argument should be an error", verifiedBy: "protocol", code: "prompts.missing-argument-served" });
    else if (o.closed) {
      closed = true;
      found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "prompts.missing-argument-closed" });
    } else if (o.timedOut) found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "prompts.missing-argument-timeout" });
    else found.push({ probe, outcome: label(`refused: ${failure(o)}`), verifiedBy: "protocol", code: "prompts.missing-argument-refused" });
  }
  if (!closed) {
    const probe = `prompts/get ${UNKNOWN_PROMPT_NAME} (not listed)`;
    const o = await session.getPrompt(UNKNOWN_PROMPT_NAME, undefined, EXTRA_TIMEOUT_MS);
    if (o.ok) found.push({ probe, outcome: "answered as a success; a prompt the server does not have should be an error", verifiedBy: "protocol", code: "prompts.unknown-served" });
    else if (o.closed) {
      closed = true;
      found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "prompts.unknown-closed" });
    } else if (o.timedOut) found.push({ probe, outcome: label(failure(o)), verifiedBy: "protocol", code: "prompts.unknown-timeout" });
    else found.push({ probe, outcome: label(`refused: ${failure(o)}`), verifiedBy: "protocol", code: "prompts.unknown-refused" });
  }
  const quiet = new Set(["prompts.get-ok", "prompts.get-refused-value", "prompts.missing-argument-refused", "prompts.unknown-refused"]);
  const findings = found.filter((e) => !quiet.has(e.code ?? "")).length;
  const verdict = verdictOf(closed, tried, worked, findings);
  const tail = unique.length > targets.length ? ` (the first ${targets.length} of ${unique.length} listed)` : "";
  const fetched = found.filter((e) => e.code === "prompts.get-ok" || e.code === "prompts.get-empty").length;
  const summary = closed
    ? "the connection closed during prompts/get"
    : `${fetched} of ${targets.length} listed prompt(s) fetched${tail}${findings ? `, ${findings} finding(s)` : ""}`;
  return done({ verdict, summary, evidence: capped(found, "prompts/get", "prompts.more") });
}

/** Both checks as `inconclusive` (the listing could not be parsed, so nothing was listed to read). */
export function extrasInconclusive(reason: string): CheckResult[] {
  return [RESOURCES_READ_META, PROMPTS_GET_META].map((m) => ({ id: m.id, pack: "core", label: m.label, critical: false, advisory: true, scope: m.scope, verdict: "inconclusive", summary: reason, evidence: [] }));
}

/** The two checks for describe(); `common` carries pack, thresholds, since and status from core's list. */
export function describeExtras(common: Omit<CheckDoc, "id" | "label" | "critical" | "advisory" | "scope" | "verifiedBy" | "probes" | "falsePositive" | "falseNegative" | "configKeys">): CheckDoc[] {
  return [
    {
      ...common,
      id: RESOURCES_READ_META.id,
      label: RESOURCES_READ_META.label,
      critical: false,
      advisory: true,
      scope: RESOURCES_READ_META.scope,
      verifiedBy: ["protocol"],
      probes: [
        { id: "list", text: "resources/list answers when the server advertises resources", core: false, kind: "protocol" },
        { id: "read-listed", text: `resources/read on the first ${MAX_EXTRA_REQUESTS} listed resources (listing order), each within ${EXTRA_TIMEOUT_MS / 1000} s, answers with at least one content item`, core: false, kind: "protocol" },
        { id: "duplicate-uri", text: "no URI is listed twice", core: false, kind: "protocol" },
        { id: "read-unknown", text: `resources/read on ${UNKNOWN_RESOURCE_URI}, a URI no server lists, is answered with an error`, core: false, kind: "protocol" },
        { id: "verdict", text: "fail when resources/list fails although advertised, the connection closes, or no listed resource can be read; part for any other finding; pass with none; n/a when resources are not advertised or none is listed", core: false, kind: "advisory" },
      ],
      falsePositive: "A resource can be listed but need state the harness does not set up (a login, a file that appears later), and a server may answer an unknown URI with empty contents on purpose; the check is advisory and never moves a letter.",
      falseNegative: `Only the first ${MAX_EXTRA_REQUESTS} listed resources are read, the contents are not compared with anything, and resource templates, subscriptions and list-changed notifications are not tested.`,
      configKeys: [`checks.${RESOURCES_READ_META.id}.enabled`, `checks.${RESOURCES_READ_META.id}.severity`],
      since: "0.3-draft",
    },
    {
      ...common,
      id: PROMPTS_GET_META.id,
      label: PROMPTS_GET_META.label,
      critical: false,
      advisory: true,
      scope: PROMPTS_GET_META.scope,
      verifiedBy: ["protocol"],
      probes: [
        { id: "list", text: "prompts/list answers when the server advertises prompts; no prompt name and no argument name within a prompt is listed twice", core: false, kind: "protocol" },
        { id: "get-listed", text: `prompts/get on the first ${MAX_EXTRA_REQUESTS} listed prompts (listing order), each required argument set to "${PROMPT_ARGUMENT_VALUE}", answers with at least one message within ${EXTRA_TIMEOUT_MS / 1000} s; a prompt with required arguments that refuses that value is recorded and not counted`, core: false, kind: "protocol" },
        { id: "missing-argument", text: "prompts/get with no arguments on the first prompt that has a required argument is answered with an error", core: false, kind: "protocol" },
        { id: "get-unknown", text: `prompts/get on ${UNKNOWN_PROMPT_NAME}, a name no server lists, is answered with an error`, core: false, kind: "protocol" },
        { id: "verdict", text: "fail when prompts/list fails although advertised, the connection closes, or every fetched prompt without required arguments fails; part for any other finding; pass with none; n/a when prompts are not advertised or none is listed", core: false, kind: "advisory" },
      ],
      falsePositive: `A prompt may fill a missing argument with a default on purpose, and "${PROMPT_ARGUMENT_VALUE}" may be a value a prompt cannot use (that case is not counted); the check is advisory and never moves a letter.`,
      falseNegative: `Only the first ${MAX_EXTRA_REQUESTS} listed prompts are fetched, message text is not judged, and completion, pagination limits and list-changed notifications are not tested.`,
      configKeys: [`checks.${PROMPTS_GET_META.id}.enabled`, `checks.${PROMPTS_GET_META.id}.severity`],
      since: "0.3-draft",
    },
  ];
}
