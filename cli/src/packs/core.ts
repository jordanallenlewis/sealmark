import type { CheckConfig } from "../config/model.js";
import { rejectedBeforeRunning, type McpSession, type ToolInfo } from "../mcp.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, ToolAnnotations } from "../types.js";
import { FAILURE_VETO } from "./net.js";
import { brief, excerpt, refusedInTextOnly, requiresTask, TASK_ONLY_REASON } from "./shared.js";

/** A call made with schema-valid arguments before robust-input (a `probes:` entry). Its response is scanned for internals. */
export interface ValidCall {
  tool: string;
  args: Record<string, unknown>;
  text: string;
  isError: boolean;
  rpcError?: string;
}

export interface CoreCtx {
  session: McpSession;
  /** Secret strings placed in the server's environment. Seeing one in any response is a leak. Empty for HTTP servers. */
  canaries: string[];
  /** Responses collected by every check, scanned for canaries at the end. */
  seen: string[];
  /** How long a tool call may take before the server counts as hung. */
  hangMs: number;
  /** Valid calls made earlier (`probes:`). They count toward coverage and are scanned for stack traces. */
  validCalls?: ValidCall[];
  /** Tools that must not receive any valid call, even a read-only one with no arguments. */
  noValidCalls?: Iterable<string>;
  /** checks.robust-input.max_tools. Default 25. */
  maxTools?: number;
  /** Record one evidence line per robust-input call (tool, variant, arguments, outcome). Defaults to setCallEvidence(), which the CLI turns on for --verbosity verbose. */
  callEvidence?: boolean;
  /** `checks.<id>.enabled` and `.severity` from the configuration. Absent means every check runs with its built-in severity. */
  checks?: Record<string, CheckConfig>;
  /**
   * Filled by robust-input: which tool and arguments produced each response it pushed onto `seen` (the bounded text, see keeper), so
   * secret-echo can name the tool that leaked. Leave it unset; runCore creates it.
   */
  calls?: { tool: string; args: Record<string, unknown>; texts: string[]; /** The reply was a successful result (no isError, no protocol error). */ ok?: boolean }[];
}

/**
 * Applies `checks.<id>.severity` and `checks.<id>.enabled` to a finished check, the same rule fs.ts metaFor applies to its own.
 * With the shipped defaults (enabled, severity null) the result is the very same object.
 */
export function applyCheckConfig(r: CheckResult, cfg: CheckConfig | undefined): CheckResult {
  if (!cfg) return r;
  let critical = r.critical;
  let advisory = Boolean(r.advisory);
  if (cfg.severity === "critical") [critical, advisory] = [true, false];
  else if (cfg.severity === "scored") [critical, advisory] = [false, false];
  else if (cfg.severity === "advisory") [critical, advisory] = [false, true];
  if (cfg.enabled === false) return { id: r.id, pack: r.pack, label: r.label, critical, ...(advisory ? { advisory: true } : {}), scope: r.scope, verdict: "na", summary: "disabled by config", evidence: [] };
  if (critical === r.critical && advisory === Boolean(r.advisory)) return r;
  const { advisory: _was, ...rest } = r;
  return { ...rest, critical, ...(advisory ? { advisory: true } : {}) };
}

export const applyChecksConfig = (rs: CheckResult[], checks: Record<string, CheckConfig> | undefined): CheckResult[] => (checks ? rs.map((r) => applyCheckConfig(r, checks[r.id])) : rs);

const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
export const MAX_TOOLS_PROBED = 25;
const MAX_HANGS = 3;
const UNEXPECTED_ARG = "sm_unexpected";

type Tier = "strong" | "weak";

/**
 * Tiered on purpose: tool-poisoning is a critical check, so only phrases that have no innocent
 * reading may fail it. Phrases that a careful, honest description could contain only earn "part".
 */
// Credential files an injected instruction would point the model at.
const CRED = String.raw`(?:~\/\.ssh|\.ssh\/id_|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws\/credentials|\/etc\/(?:passwd|shadow)|\.netrc|\.git-credentials)`;
/** "Upload the file using your API token" says how the tool authenticates; the token is not the thing being sent. */
const withoutAuthUse = (s: string) =>
  s.replace(/\b(?:using|with|via|authenticat\w+ (?:with|using))\s+(?:(?:your|the|a|an|my|its)\s+)?(?:[\w-]+\s+){0,2}?(?:credentials?|secrets?|passwords?|api[ _-]?keys?|tokens?|private keys?)\b/gi, " ");

const INJECTION: [Tier, string, RegExp, ((s: string) => string)?][] = [
  ["strong", "tells the model to ignore prior instructions", /ignore (all |any )?(the |your )?(previous|prior|above|earlier) (instructions|prompts?|rules)/i],
  ["strong", "uses an <IMPORTANT> block aimed at the model", /<\s*important\s*>/i],
  // A bare path is documentation ("e.g. ~/.ssh/id_ed25519"); an instruction to read or send it is not.
  ["strong", "tells the model to read or send a credential file", new RegExp(String.raw`\b(?:you (?:must|should|need to|have to)|first|then|also|always|please|before\b[^.;]{0,40}?)\s+(?:read|cat|open|send|upload|post|forward|attach|include|copy)\b[^.;]{0,60}?${CRED}`, "i")],
  ["strong", "asks the model to send a credential file to a URL", new RegExp(String.raw`\b(?:send|post|upload|forward|transmit|leak)\b[^.;]{0,60}?${CRED}[^;]{0,80}?https?:\/\/`, "i")],
  ["weak", "mentions a credential file path", new RegExp(CRED, "i")],
  ["strong", "asks the model to send secrets or conversation data to a URL", /\b(send|post|upload|forward|transmit|leak)\b[^.;]{0,80}\b(credentials?|secrets?|passwords?|api[ _-]?keys?|tokens?|private keys?|ssh|conversation|chat history|system prompt|\.env)\b[^.;]{0,80}https?:\/\//i, withoutAuthUse],
  ["strong", "mentions exfiltration", /\bexfiltrat/i],
  ["strong", "asks the model to read a .env file and pass it on", /\b(read|cat|open|include|attach|send|upload|copy)\b[^.]{0,40}\.env\b/i],
  ["weak", "tells the model to hide something from the user", /(do not|don't|never) (tell|inform|mention|show|reveal|let)[^.]{0,40}\buser\b/i],
  ["weak", "references the system prompt", /system prompt/i],
  ["weak", "mentions a .env file", /\.env\b/i],
  ["weak", "uses a <system> or <instructions> tag", /<\s*(system|instructions?)\s*>/i],
  ["weak", "asks the model to call another tool first", /before (using|calling|running) this tool[^.]{0,40}(call|use|read|run)/i],
  ["weak", "overrides prior guidance", /\b(overrid(?:e|es|ing)|supersed(?:e|es)|takes? precedence over)\b[^.]{0,40}\b(instructions|guidance|rules|prompt)/i],
  ["weak", "asks the model to send user data to a URL", /\b(send|post|upload|forward)\b[^.]{0,40}\b(user'?s|all|every)\b[^.]{0,30}\b(data|files?|messages?|conversation|history|context)\b[^.]{0,60}https?:\/\//i],
];

/**
 * Invisible and bidirectional control characters, written as escapes (literal ones get stripped by editors and formatters).
 * ZWNJ, ZWJ, LRM and RLM are ordinary in emoji sequences and right-to-left text, so alone they only count as weak;
 * a run of three or more is the classic zero-width encoding and counts as strong, like the other invisible characters.
 */
const HIDDEN_STRONG = /[\u200B\u202A-\u202E\u2060-\u2064\u2066-\u2069\u{E0000}-\u{E007F}]|[\u200B-\u200F\u2060\uFEFF]{3,}|[^\uFEFF]\uFEFF/u;
const HIDDEN_WEAK = /[\u200C-\u200F]|^\uFEFF/;
/**
 * Control characters that a terminal acts on. ESC starts an ANSI or OSC sequence, NUL ends a C string early and the C1 range (the
 * 8-bit forms of the same sequences) is read as control by some terminals, so all three are strong. The rest of C0 and DEL are
 * usually accidents (copied binary text) and are weak. Tab, line feed and carriage return are ordinary text and are not matched.
 */
const CTL_STRONG = /[\u0000\u001B\u0080-\u009F]/;
const CTL_WEAK = /[\u0001-\u0008\u000B\u000C\u000E-\u001A\u001C-\u001F\u007F]/;
/**
 * The England, Scotland and Wales flag emoji are a black flag plus tag characters. Only those three exact
 * sequences are exempt: tag characters can also smuggle ASCII text, so any other run stays a strong indicator.
 */
const tagged = (s: string) => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
const FLAG_EMOJI = new RegExp(`\u{1F3F4}(?:${["gbeng", "gbsct", "gbwls"].map(tagged).join("|")})\u{E007F}`, "gu");

export interface Indicator {
  tier: Tier;
  outcome: string;
}

/** Every injection or hidden-character indicator in one piece of tool metadata text. Pure, so the false-positive cases can be unit tested. */
export function scanText(text: string): Indicator[] {
  const found: Indicator[] = [];
  const visible = text.replace(FLAG_EMOJI, "");
  if (CTL_STRONG.test(visible)) found.push({ tier: "strong", outcome: "contains terminal control characters (ESC, NUL or a C1 control) that can hide text or drive a terminal" });
  else if (CTL_WEAK.test(visible)) found.push({ tier: "weak", outcome: "contains C0 control characters (other than tab, newline and carriage return) or DEL" });
  if (HIDDEN_STRONG.test(visible)) found.push({ tier: "strong", outcome: "contains hidden or bidirectional control characters" });
  else if (HIDDEN_WEAK.test(visible)) found.push({ tier: "weak", outcome: "contains zero-width or direction marks (ordinary in emoji and right-to-left text, but check)" });
  for (const [tier, label, re, pre] of INJECTION) {
    const m = (pre ? pre(text) : text).match(re);
    if (m) found.push({ tier, outcome: `${label}: "${m[0].slice(0, 80)}"` });
  }
  return found;
}

const STACK = [
  /Traceback \(most recent call last\)/,
  /^\s*at (?:async )?(?:[\w$.<>[\] ]+ \()?(?:file:\/\/|[A-Za-z]:[\\/]|\/|node:)[^\s)]*:\d+:\d+\)?\s*$/m,
  /\bat [\w$.<>]+ \([^)]*:\d+:\d+\)/,
  /File "[^"]+", line \d+/,
  // A frame shape (file:line) is required: a bare node_modules/ shows up in PATH-style env dumps and is not a stack trace.
  /(?:node_modules|site-packages)[\\/][^\s)"']*\.(?:[cm]?[jt]sx?|py):\d+/,
  /\.py", line/,
  /[A-Za-z]:\\(?:Users|Windows|Program Files)\\/,
  // A bare home-directory path is also what an ENOENT message or a PATH dump contains; require a file:line shape.
  /\/(?:home|Users|root)\/[\w.-]+\/[^\s)"']*:\d+/,
];
export const hasStack = (s: string) => STACK.some((re) => re.test(s));

type SchemaProp = { type?: string | string[]; enum?: unknown[]; [k: string]: unknown };

/** Values whose JSON type is easy to tell apart. A wrong value must break the schema's own type. */
const WRONG_CANDIDATES: { value: unknown; types: string[] }[] = [
  { value: 12345, types: ["number", "integer"] },
  { value: "not-a-valid-value", types: ["string"] },
  { value: true, types: ["boolean"] },
  { value: ["x"], types: ["array"] },
  { value: { x: 1 }, types: ["object"] },
];

const declaredTypes = (p: SchemaProp | undefined): string[] => [p?.type].flat().filter((t): t is string => typeof t === "string");

type ItemSchema = SchemaProp & { properties?: Record<string, SchemaProp>; required?: string[] };

/** An array whose items are declared objects (by type or by having properties). */
function isArrayOfObjects(p: SchemaProp | undefined): boolean {
  if (!declaredTypes(p).includes("array")) return false;
  const items = p?.items as ItemSchema | undefined;
  return Boolean(items && typeof items === "object" && (declaredTypes(items).includes("object") || items.properties));
}

/** One array item with every required field but the first, each filled by its declared type: schema-invalid, and nothing more. undefined when the items declare no required field. */
function itemLackingRequired(p: SchemaProp): Record<string, unknown> | undefined {
  const items = p.items as ItemSchema;
  const req = (items.required ?? []).filter((r): r is string => typeof r === "string");
  if (!req.length) return undefined;
  const item: Record<string, unknown> = {};
  for (const r of req.slice(1)) {
    const f = items.properties?.[r];
    const types = declaredTypes(f);
    item[r] = Array.isArray(f?.enum) ? f.enum[0] : types.includes("number") || types.includes("integer") ? 1 : types.includes("boolean") ? false : types.includes("array") ? [] : types.includes("object") ? {} : "x";
  }
  return item;
}

/** undefined when the property has no declared type: any value might be valid, and the harness never sends valid-looking input to a tool it has not classified. */
function wrongValue(p: SchemaProp | undefined): { value: unknown } | undefined {
  const declared = [p?.type].flat().filter((t): t is string => typeof t === "string");
  if (!declared.length) return undefined;
  for (const c of WRONG_CANDIDATES) {
    if (c.types.some((t) => declared.includes(t))) continue;
    if (p?.enum?.some((e) => JSON.stringify(e) === JSON.stringify(c.value))) continue;
    return { value: c.value };
  }
  return undefined;
}

/**
 * What an `isError` reply to a schema-invalid call shows about the server: `internal` for an unhandled runtime error (the argument
 * reached code that was never meant to see it), `downstream` for a failed upstream request (the server used the argument before it
 * failed), `clean` for everything else, which is a validation decision. A reply that names a parameter the tool declares (or an
 * argument the harness sent) and says it is invalid, required or expected is always a validation decision, whatever else it mentions.
 */
export type RejectionKind = "clean" | "downstream" | "internal";

/** The ways a JavaScript or Python runtime reports a value of the wrong shape reaching code that assumed another. */
const RUNTIME_ERROR = /\bTypeError\b|Cannot read propert(?:y|ies)|is not a function|\bundefined is not\b|\bnull is not an object\b|\bAttributeError\b|\bKeyError\b|\bNoneType\b/;

export function rejectionKind(reply: string, tool: ToolInfo, sent: Record<string, unknown> = {}): RejectionKind {
  // pydantic validation errors print the received type ("input_type=NoneType"); that is the validator describing the bad
  // argument, not the runtime crashing on it, so it does not count toward RUNTIME_ERROR.
  if (RUNTIME_ERROR.test(reply.replace(/\binput_type=\w+/g, ""))) return "internal";
  if (!FAILURE_VETO.test(reply)) return "clean";
  const declared = Object.fromEntries(Object.keys(tool.inputSchema?.properties ?? {}).map((k) => [k, true]));
  // `rejectedBeforeRunning` is the same test coverage applies: a validation error that names a parameter never ran the tool's behaviour.
  return rejectedBeforeRunning({ isError: true, text: reply, timedOut: false, closed: false }, { ...declared, ...sent }) ? "clean" : "downstream";
}

function protocolCheck(ctx: CoreCtx): CheckResult {
  const tools = ctx.session.tools;
  const info = ctx.session.serverInfo;
  const evidence: Evidence[] = [
    {
      probe: "initialize + tools/list",
      outcome: `server ${[info.name ?? "?", info.version].filter(Boolean).join(" ")} answered; ${tools.length} tool(s)`,
      verifiedBy: "protocol",
      code: "protocol.server-info",
      // run.ts compares serverInfo.version with the configured version and the resolved package (addendum item 15).
      excerpt: JSON.stringify({ serverInfo: info, capabilities: Object.keys(ctx.session.capabilities ?? {}) }),
    },
  ];
  const bad: string[] = [];
  const soft: string[] = [];
  const names = new Set<string>();
  for (const t of tools) {
    if (!TOOL_NAME.test(t.name)) bad.push(`tool name "${t.name}" is not 1-128 chars of A-Z a-z 0-9 _ . -`);
    if (names.has(t.name)) bad.push(`duplicate tool name "${t.name}"`);
    names.add(t.name);
    if (!t.description || t.description.trim().length < 10) soft.push(`${t.name}: no useful description`);
  }
  if (!tools.length) soft.push("the server declares no tools");
  for (const m of [...bad, ...soft]) evidence.push({ probe: "tools/list schema review", outcome: m, verifiedBy: "protocol" });
  // What the session saw on the wire. Only the core session is measured: other packs' sessions are not, so the check's input stays fixed.
  const noise = ctx.session.stdoutNoise ?? { count: 0, first: "" };
  const invalidResults = ctx.session.invalidResults ?? { count: 0, samples: [] };
  if (noise.count) {
    // The line is the server's own text: never show a canary it may have printed.
    const first = ctx.canaries.reduce((t, c) => (c ? t.split(c).join("<canary>") : t), noise.first);
    evidence.push({ probe: "every line the server wrote to stdout", outcome: `the server wrote ${noise.count} non-JSON-RPC line(s) to stdout (first: ${first}); strict stdio clients break on this`, verifiedBy: "protocol", code: "protocol.stdout-noise" });
  }
  if (invalidResults.count) {
    evidence.push({ probe: "tools/call results", outcome: `${invalidResults.count} tools/call result(s) were not valid MCP (${invalidResults.samples.join("; ")})`, verifiedBy: "protocol", code: "protocol.invalid-result" });
  }
  const verdict = bad.length ? "fail" : soft.length || noise.count || invalidResults.count ? "part" : "pass";
  const wire = [noise.count ? `${noise.count} non-JSON-RPC line(s) on stdout` : "", invalidResults.count ? `${invalidResults.count} invalid tool result(s)` : ""].filter(Boolean);
  const lead = !tools.length ? "no tools declared" : bad.length ? `${bad.length} schema problem(s)` : soft.length ? `${soft.length} tool(s) lack a useful description` : "";
  return {
    id: "protocol",
    pack: "core",
    label: "Valid MCP handshake and tool schemas",
    critical: false,
    scope: "server",
    verdict,
    summary: [lead, ...wire].filter(Boolean).join(", ") || `handshake ok, ${tools.length} well-formed tool(s)`,
    evidence,
  };
}

/** Every string in a tool definition (name, title, description, schema text, enum values, defaults) with its path. */
function* strings(v: unknown, path: string, depth = 0): Generator<[string, string]> {
  if (typeof v === "string") yield [path, v];
  else if (depth < 8 && Array.isArray(v)) for (const [i, x] of v.entries()) yield* strings(x, `${path}[${i}]`, depth + 1);
  else if (depth < 8 && v && typeof v === "object") for (const [k, x] of Object.entries(v)) yield* strings(x, `${path}.${k}`, depth + 1);
}

function hygieneCheck(ctx: CoreCtx): CheckResult {
  const base = { id: "tool-poisoning", pack: "core" as const, label: "No tool-poisoning indicators in tool metadata", critical: true, scope: "server (what it declares, not what it does)" };
  const evidence: Evidence[] = [];
  let strong = 0;
  let weak = 0;
  /** Which kinds of text carried an indicator, for the summary. */
  const places = new Set<string>();
  const note = (tier: Tier, tool: string | undefined, where: string, outcome: string) => {
    if (tier === "strong") strong++;
    else weak++;
    places.add(tool ? "tool metadata" : /^serverInfo /.test(where) ? "serverInfo" : where === "server instructions" ? "the server instructions" : "prompt or resource text");
    evidence.push({ probe: `scan ${where}`, outcome: `${tier === "strong" ? "STRONG" : "weak"} indicator: ${outcome}`, verifiedBy: "static", ...(tool ? { tool } : {}), code: `poisoning.${tier}` });
  };
  for (const t of ctx.session.tools) {
    for (const [path, text] of strings(t, t.name)) {
      const where = path.replace(/\.inputSchema\.properties\./, " param ").replace(/\.inputSchema/, " schema");
      for (const ind of scanText(text)) note(ind.tier, t.name, where, ind.outcome);
    }
    if ((t.description ?? "").length > 4000) note("weak", t.name, `length of ${t.name} description`, `${t.description!.length} characters; very long descriptions are where hidden instructions live`);
  }
  // The server's instructions and its serverInfo are model-visible text too: a client puts the instructions into the model's context
  // next to the tool list. Long instructions are ordinary, so only the pattern and hidden-character scans apply to them, no length rule.
  const instructions = ctx.session.instructions;
  if (instructions) for (const ind of scanText(instructions)) note(ind.tier, undefined, "server instructions", ind.outcome);
  const info = ctx.session.serverInfo ?? {};
  for (const field of ["name", "title", "description", "websiteUrl"] as const) {
    const v = info[field];
    if (typeof v === "string" && v) for (const ind of scanText(v)) note(ind.tier, undefined, `serverInfo ${field}`, ind.outcome);
  }
  // Prompts and resources are text the model reads, so they are poisoned the same way (addendum item 16).
  const prompts = ctx.session.prompts ?? [];
  const resources = ctx.session.resources ?? [];
  for (const p of prompts) {
    for (const [where, text] of promptTexts(p)) for (const ind of scanText(text)) note(ind.tier, undefined, where, ind.outcome);
  }
  for (const r of resources) {
    for (const [where, text] of resourceTexts(r)) for (const ind of scanText(text)) note(ind.tier, undefined, where, ind.outcome);
  }
  const unscanned = ctx.session.listErrors ?? [];
  for (const e of unscanned) evidence.push({ probe: "scan prompts and resources", outcome: `not scanned: ${e}`, verifiedBy: "static", code: "poisoning.list-failed" });
  const extra = [prompts.length ? `${prompts.length} prompt(s)` : "", resources.length ? `${resources.length} resource(s)` : ""].filter(Boolean);
  const verdict = strong ? "fail" : weak ? "part" : "pass";
  const head = `${ctx.session.tools.length} tool definition(s)${instructions ? ", the server instructions and serverInfo" : " and serverInfo"}`;
  return {
    ...base,
    verdict,
    summary: strong
      ? `${strong} strong indicator(s) in ${[...places].join(" and ")}${weak ? `, ${weak} weak` : ""}`
      : weak
        ? `${weak} weak indicator(s) worth reading, none conclusive`
        : `scanned ${head}${extra.length ? `, ${extra.join(" and ")}` : ""}, including parameter text: nothing suspicious${unscanned.length ? ` (${unscanned.length} listing(s) failed and were not scanned)` : ""}`,
    evidence: evidence.length ? evidence : [{ probe: `scan tool${extra.length ? ", prompt and resource" : ""} names, descriptions and schema text, the server instructions and serverInfo for injection phrases and hidden characters`, outcome: "no matches", verifiedBy: "static" }],
  };
}

/** Every string a prompt exposes to the model, with the place it came from (`prompt <name> description`). */
function promptTexts(p: PromptLike): [string, string][] {
  const out: [string, string][] = [];
  const at = `prompt ${p.name}`;
  if (p.name) out.push([`${at} name`, p.name]);
  if (p.title) out.push([`${at} title`, p.title]);
  if (p.description) out.push([`${at} description`, p.description]);
  for (const a of p.arguments ?? []) {
    if (a.name) out.push([`${at} argument ${a.name} name`, a.name]);
    if (a.description) out.push([`${at} argument ${a.name} description`, a.description]);
  }
  return out;
}

function resourceTexts(r: ResourceLike): [string, string][] {
  const out: [string, string][] = [];
  const at = `resource ${r.name ?? r.uri}`;
  if (r.name) out.push([`${at} name`, r.name]);
  if (r.title) out.push([`${at} title`, r.title]);
  if (r.description) out.push([`${at} description`, r.description]);
  if (r.uri) out.push([`${at} uri`, r.uri]);
  return out;
}

type PromptLike = McpSession["prompts"][number];
type ResourceLike = McpSession["resources"][number];

/** True when `null` breaks the property's declared type, so sending it is a schema-invalid call. Untyped properties are never sent anything. */
function nullIsInvalid(p: SchemaProp | undefined): boolean {
  const declared = [p?.type].flat().filter((t): t is string => typeof t === "string");
  if (!declared.length || declared.includes("null")) return false;
  return !p?.enum?.includes(null);
}

interface Variant {
  label: string;
  args: Record<string, unknown>;
  /** A schema-valid call (a read-only tool with no arguments). Everything else is schema-invalid on purpose. */
  valid?: boolean;
}

/**
 * Per tool, schema-invalid calls only (addendum item 17): (a) required arguments missing, (b) every typed argument has
 * the wrong type, (c) every typed argument is null, (d) wrong types plus an unexpected extra argument. A tool with no
 * properties at all gets a `{}` call only when it declares `readOnlyHint: true`; otherwise it needs a `probes:` entry.
 */
export function variantsFor(t: ToolInfo, allowValid: boolean): { variants: Variant[]; needsProbes?: string } {
  const props = Object.entries(t.inputSchema?.properties ?? {});
  const required = t.inputSchema?.required ?? [];
  const variants: Variant[] = [];
  const wrong = props.flatMap(([k, p]) => {
    const w = wrongValue(p);
    return w ? [[k, w.value] as const] : [];
  });
  const nulls = props.filter(([, p]) => nullIsInvalid(p)).map(([k]) => [k, null] as const);
  if (required.length) variants.push({ label: "required arguments missing", args: {} });
  if (wrong.length) variants.push({ label: "every typed argument has the wrong type", args: Object.fromEntries(wrong) });
  if (nulls.length) variants.push({ label: "every typed argument is null", args: Object.fromEntries(nulls) });
  if (wrong.length) variants.push({ label: "wrong types plus an unexpected extra argument", args: { ...Object.fromEntries(wrong), [UNEXPECTED_ARG]: "x" } });
  // A second wrong type for strings: the first candidate for a string is a number, and a server that only checks `typeof x === "number"` passes it.
  const stringProps = props.filter(([, p]) => declaredTypes(p).includes("string") && !declaredTypes(p).includes("object") && !(Array.isArray(p.enum) && p.enum.some((e: unknown) => typeof e === "object" && e !== null)));
  if (stringProps.length) variants.push({ label: "every string argument is an object", args: Object.fromEntries(stringProps.map(([k]) => [k, { x: 1 }])) });
  // Required array-of-object parameters: the nested entity is what a store keeps, so a string in place of the array, and one item that
  // lacks a required field, are sent on their own (each is schema-invalid; the other parameters stay unset so the call can never be valid).
  const nested = props.filter(([k, p]) => required.includes(k) && isArrayOfObjects(p));
  if (nested.length) {
    variants.push({ label: "a string in place of the array of objects", args: Object.fromEntries(nested.map(([k]) => [k, "not-a-valid-value"])) });
    const lacking = nested.flatMap(([k, p]) => {
      const item = itemLackingRequired(p);
      return item ? [[k, [item]] as const] : [];
    });
    if (lacking.length) variants.push({ label: "one array item lacks a required field", args: Object.fromEntries(lacking) });
  }
  if (variants.length) return { variants };
  if (!props.length && (t as { annotations?: ToolAnnotations }).annotations?.readOnlyHint === true) {
    return allowValid ? { variants: [{ label: "no arguments (declared read-only)", args: {}, valid: true }] } : { variants: [], needsProbes: "excluded from valid calls; add a probes: entry to call it" };
  }
  return { variants: [], needsProbes: props.length ? "needs probes: to be called (no argument the harness can safely malform)" : "needs probes: to be called (no arguments, and not declared read-only)" };
}

/** Stands in for a response the canary scan does not need to keep: non-empty, so the count of captured responses is unchanged. */
const NOT_KEPT = "\u0000";

/**
 * secretEchoCheck needs the number of non-empty responses and the first one that holds a canary (its offset, length and the text
 * before it), nothing else. A server can answer every invalid call with tens of MiB, so everything else is replaced by NOT_KEPT.
 * `already` is what `seen` holds before the first call: a canary hit in there stays the first hit.
 */
function keeper(canaries: readonly string[], already: readonly string[] = []): (text: string) => string {
  const has = (t: string) => canaries.some((c) => t.includes(c));
  let found = already.some(has);
  return (text) => {
    if (!text) return "";
    if (!found && has(text)) {
      found = true;
      return text;
    }
    return NOT_KEPT;
  };
}

/** The responses of `probes:` calls, bounded the same way (see keeper). */
export const boundSeen = (texts: readonly string[], canaries: readonly string[]): string[] => texts.map(keeper(canaries));

let callEvidenceDefault = false;
/**
 * Whether robust-input records every call it makes. Off by default: a normal report shows only what went wrong, and the
 * per-call lines would grow the JSON, JUnit and SARIF output of every run. The CLI turns it on under `--verbosity verbose`,
 * where the text and markdown formats print every evidence line with its arguments. It adds evidence only; no verdict reads it.
 */
export function setCallEvidence(on: boolean): void {
  callEvidenceDefault = on;
}

async function robustnessCheck(ctx: CoreCtx): Promise<CheckResult> {
  const base = { id: "robust-input", pack: "core" as const, label: "Survives malformed tool input", critical: false, scope: "server" };
  const evidence: Evidence[] = [];
  const hangSec = ctx.hangMs / 1000;
  let crashed = false;
  let hangs = 0;
  let leaked = 0;
  let lenient = 0;
  /** Rejections that show the server consumed the invalid argument (a failed upstream request) or crashed on it (an unhandled runtime error). */
  let downstream = 0;
  let internalErrors = 0;
  let textRefusals = 0;
  let invalid = 0;
  /** Tools that received at least one schema-invalid call (the count the evidence line reports). */
  const invalidTools = new Set<string>();
  let taskOnly = 0;
  const probed = new Set<string>();
  const notCovered: CheckCoverage["notCovered"] = [];
  let validCalls = 0;
  const noValid = new Set(ctx.noValidCalls ?? []);
  const maxTools = ctx.maxTools ?? MAX_TOOLS_PROBED;
  const keep = keeper(ctx.canaries, ctx.seen);
  // Per-call lines go after the findings (the summary format shows a failing check's first evidence line) and carry no
  // `tool`, so the SARIF fingerprint, which is built from the tools named in the evidence, does not depend on verbosity.
  const callLog: Evidence[] = [];
  const logCalls = ctx.callEvidence ?? callEvidenceDefault;
  const tools = ctx.session.tools.slice(0, maxTools);
  for (const t of ctx.session.tools.slice(maxTools)) notCovered.push({ tool: t.name, reason: `beyond the first ${maxTools} tools, which are the only ones robust-input probes` });

  // Valid calls made earlier (probes:). A server can be clean on bad input and still leak internals on good input.
  for (const v of ctx.validCalls ?? []) {
    validCalls++;
    probed.add(v.tool);
    if (hasStack(v.text) || hasStack(v.rpcError ?? "")) {
      leaked++;
      evidence.push({ probe: `${v.tool}: valid call from probes:`, outcome: "valid call leaked internals: the response exposes a stack trace or internal file paths", verifiedBy: "response", tool: v.tool, args: v.args, excerpt: excerpt(v.text || v.rpcError || ""), code: "robust.valid-leak" });
    }
  }

  outer: for (const t of tools) {
    // A task-only tool answers every plain call with -32600 before it reads the arguments, so a variant would be counted as a clean
    // rejection of input the server never looked at. Not sent, and said so.
    if (requiresTask(t)) {
      taskOnly++;
      notCovered.push({ tool: t.name, reason: TASK_ONLY_REASON });
      continue;
    }
    const { variants, needsProbes } = variantsFor(t, !noValid.has(t.name));
    if (needsProbes) {
      if (!(ctx.validCalls ?? []).some((v) => v.tool === t.name)) notCovered.push({ tool: t.name, reason: needsProbes });
      continue;
    }
    for (const [i, pr] of variants.entries()) {
      const last = i === variants.length - 1;
      const res = await ctx.session.call(t.name, pr.args, ctx.hangMs);
      const kept = [keep(res.text), keep(res.rpcError ?? "")];
      ctx.seen.push(...kept);
      (ctx.calls ??= []).push({ tool: t.name, args: pr.args, texts: kept, ok: !res.isError && res.rpcError === undefined });
      // A valid call counts only when the server answered it. A refused no-argument call exercised no tool behaviour.
      const answered = !res.isError && res.rpcError === undefined && !res.timedOut && !res.closed;
      if (pr.valid) {
        if (answered) {
          validCalls++;
          probed.add(t.name);
        } else if (!res.timedOut && !res.closed) notCovered.push({ tool: t.name, reason: "its no-argument call returned an error, so no tool behaviour was exercised" });
      } else {
        invalid++;
        invalidTools.add(t.name);
      }
      const where = `${t.name}: ${pr.label}`;
      if (logCalls) {
        const what = res.timedOut ? `no answer within ${hangSec}s` : res.closed ? "server stopped answering" : res.rpcError !== undefined ? `protocol error: ${brief(res.rpcError, 100)}` : res.isError ? "isError response" : refusedInTextOnly(res) && !pr.valid ? "refused in text without isError" : "answered without isError";
        callLog.push({ probe: `${where} (${pr.valid ? "valid" : "schema-invalid"} call)`, outcome: what, verifiedBy: "protocol", args: pr.args, code: "robust.call" });
      }
      if (res.timedOut) {
        hangs++;
        evidence.push({ probe: where, outcome: `no answer within ${hangSec}s`, verifiedBy: "protocol", tool: t.name, args: pr.args, code: "robust.hang" });
        if (hangs >= MAX_HANGS) break outer;
        continue outer;
      }
      if (res.closed || ((last || res.rpcError !== undefined) && !(await ctx.session.alive()))) {
        crashed = true;
        evidence.push({ probe: where, outcome: `server process exited or stopped answering${res.rpcError ? ` (${res.rpcError.slice(0, 120)})` : ""}`, verifiedBy: "protocol", tool: t.name, args: pr.args, code: "robust.crash" });
        break outer;
      }
      if (hasStack(res.text) || hasStack(res.rpcError ?? "")) {
        leaked++;
        evidence.push({ probe: where, outcome: "error response exposes a stack trace or internal file paths", verifiedBy: "response", tool: t.name, args: pr.args, excerpt: excerpt(res.text || res.rpcError || ""), code: "robust.stack" });
      }
      if (pr.valid) continue;
      if (refusedInTextOnly(res)) {
        // The server did refuse, but a client reading isError sees a success. Counted as a rejection, and said so.
        textRefusals++;
        evidence.push({ probe: where, outcome: `refused in text without isError (clients cannot tell it from success): ${brief(res.text, 160)}`, verifiedBy: "response", tool: t.name, args: pr.args, excerpt: excerpt(res.text), code: "robust.text-refusal" });
      } else if (!res.isError) {
        lenient++;
        evidence.push({ probe: where, outcome: "call succeeded: the server accepted schema-invalid arguments", verifiedBy: "response", tool: t.name, args: pr.args, excerpt: excerpt(res.text), code: "robust.lenient" });
      } else {
        // An error is a clean rejection only when it is a validation decision. A failed upstream request or an unhandled runtime
        // error means the server consumed the invalid argument first (the verdict rests on what the reply shows, not on isError).
        const reply = res.text || res.rpcError || "";
        const kind = rejectionKind(reply, t, pr.args);
        if (kind === "downstream") {
          downstream++;
          evidence.push({ probe: where, outcome: `the server used the invalid argument (an upstream request was attempted with it) and that request failed: ${brief(reply, 160)}`, verifiedBy: "response", tool: t.name, args: pr.args, excerpt: excerpt(reply), code: "robust.lenient-downstream" });
        } else if (kind === "internal") {
          internalErrors++;
          evidence.push({ probe: where, outcome: `an unhandled runtime error, not a validation decision: ${brief(reply, 160)}`, verifiedBy: "response", tool: t.name, args: pr.args, excerpt: excerpt(reply), code: "robust.internal-error" });
        }
      }
    }
  }
  const coverage: CheckCoverage = { probed: [...probed], notCovered, validCalls };
  if (!invalid && !validCalls) {
    const summary = taskOnly && taskOnly === tools.length ? `every tool requires task-based execution, which the harness does not use (${taskOnly} not called)` : "no tool has arguments the harness can safely malform";
    return { ...base, verdict: "na", summary, evidence: [], coverage };
  }
  const hung = hangs > 0;
  const verdict = crashed || hung ? "fail" : leaked || lenient || downstream || internalErrors ? "part" : "pass";
  if (!evidence.some((e) => e.code !== "robust.text-refusal")) evidence.push({ probe: `${invalid} invalid call(s) across ${invalidTools.size} tool(s)`, outcome: "all rejected cleanly and the server stayed responsive", verifiedBy: "protocol" });
  evidence.push(...callLog);
  const found = [
    ...(leaked || lenient ? [`${leaked} internals leak(s), ${lenient} invalid call(s) accepted`] : []),
    ...(downstream ? [`${downstream} reply(ies) show the invalid argument was used downstream`] : []),
    ...(internalErrors ? [`${internalErrors} unhandled runtime error(s)`] : []),
  ];
  return {
    ...base,
    verdict,
    summary: crashed ? "server died on malformed input" : hung ? "server hung on malformed input" : found.length ? found.join(", ") : `${invalid} invalid call(s) rejected cleanly${textRefusals ? ` (${textRefusals} refused in text without isError)` : ""}`,
    evidence,
    coverage,
  };
}


const CANARY_NAMES = ["SEALMARK_CANARY", "SEALMARK_FAKE_API_KEY"];
/** How far back from a canary to look for the name it was printed under. */
const KEY_LOOKBACK = 80;

/**
 * The name a leaked value was printed under (`SEALMARK_CANARY` in `"SEALMARK_CANARY":"..."` or `SEALMARK_CANARY=...`), and
 * nothing else of the response. A report never quotes the text around a leak: with an inherited environment (--no-sandbox)
 * a server that echoes its environment puts the user's real variables right next to the canary.
 */
export function keyBefore(text: string, at: number): string | undefined {
  return /([A-Za-z_][\w.-]*)\\*["']?\s*[:=]\s*\\*["']?\s*$/.exec(text.slice(Math.max(0, at - KEY_LOOKBACK), at))?.[1];
}

/**
 * The tool and arguments of the call whose response carried the canary. Calls robust-input made are recorded as they happen. A
 * `probes:` valid call is found through its kept excerpt, where the canary is already masked as `<canary>` (the raw text only
 * reaches `seen`); the excerpt is capped, so a canary past its end leaves the call unnamed rather than guessed.
 */
function leakedBy(ctx: CoreCtx, hit: string): { tool: string; args: Record<string, unknown> } | undefined {
  const own = (ctx.calls ?? []).find((c) => c.texts.includes(hit));
  if (own) return { tool: own.tool, args: own.args };
  const valid = (ctx.validCalls ?? []).find((v) => [v.text, v.rpcError ?? ""].some((t) => t.includes("<canary>") || ctx.canaries.some((c) => t.includes(c))));
  return valid ? { tool: valid.tool, args: valid.args } : undefined;
}

function secretEchoCheck(ctx: CoreCtx, listing: string): CheckResult {
  const base = { id: "secret-echo", pack: "core" as const, label: "No environment secret echoed in responses", critical: true, scope: "server" };
  if (!ctx.canaries.length) {
    return { ...base, verdict: "na", summary: "canary injection needs a server Sealmark starts (stdio, or --start with --url)", evidence: [] };
  }
  const probe = "set SEALMARK_CANARY and SEALMARK_FAKE_API_KEY in the server env, then scan tools/list and every tool response";
  const texts = ctx.seen.filter(Boolean);
  const hit = [listing, ...texts].find((t) => ctx.canaries.some((c) => t.includes(c)));
  if (hit) {
    // Say where the canary was, not what surrounds it (see keyBefore).
    const at = Math.min(...ctx.canaries.map((c) => hit.indexOf(c)).filter((i) => i >= 0));
    const which = ctx.canaries.findIndex((c) => hit.indexOf(c) === at);
    const name = CANARY_NAMES[which] ?? "a canary";
    const key = keyBefore(hit, at);
    const shown = key ? `${key}=<canary>` : "<canary>";
    const from = hit === listing ? undefined : leakedBy(ctx, hit);
    return {
      ...base,
      verdict: "fail",
      summary: from ? `a canary secret from the server's environment appeared in a response of tool ${from.tool}` : "a canary secret from the server's environment appeared in a response",
      evidence: [
        {
          probe,
          outcome: `${name} found at offset ${at} of a ${hit.length}-character response, printed as ${shown} (the surrounding text is not quoted)`,
          verifiedBy: "response",
          ...(from ? { tool: from.tool, args: from.args } : {}),
          excerpt: shown,
          code: "secret.found",
        },
      ],
    };
  }
  if (!texts.length) {
    return { ...base, verdict: "inconclusive", summary: "no tool responses were captured to scan", evidence: [{ probe, outcome: "only tools/list was scanned; the harness made no call that returned content", verifiedBy: "response" }] };
  }
  // Most replies to a schema-invalid call are error replies, which is where a server prints the least. Say how many were successful results.
  const ok = (ctx.calls ?? []).filter((c) => c.ok && c.texts.some(Boolean)).length + (ctx.validCalls ?? []).filter((v) => !v.isError && v.rpcError === undefined && v.text).length;
  const of = `${texts.length} captured response(s), ${ok} of them successful result(s)`;
  return { ...base, verdict: "pass", summary: `canary secrets absent from tools/list and ${of}`, evidence: [{ probe, outcome: `not found. Coverage is limited to the calls the harness makes (${of}).`, verifiedBy: "response" }] };
}

// ---------------------------------------------------------------------------------------------------------
// Round 6 (design 3.7): two advisory candidates. Neither moves a letter.
// ---------------------------------------------------------------------------------------------------------

const REFUSAL_QUALITY_META = { id: "refusal-quality", label: "Refusals say what to do next", scope: "server (how it words a refusal)" };
const INSTRUCTIONS_HYGIENE_META = { id: "instructions-hygiene", label: "Server instructions name only tools that exist", scope: "server (what its instructions say)" };

/** What makes a refusal route the caller somewhere: an alternative, a tool to call, a reason it will not succeed. `checks.refusal-quality.patterns` replaces the list. */
export const DEFAULT_ROUTING_PATTERNS: readonly string[] = ["instead", "use (the )?[a-z_]+ tool", "available", "allowed", "try", "list_[a-z]+", "contact", "will not (help|succeed)", "permanent", "not retry"];

/** Evidence codes that carry a refusal the run recorded. */
const REFUSAL_CODE = /^(scope\.refused|sql-guard\.refused|net\.ssrf-refused.*|fs\.[a-z.-]*refused[a-z.-]*|probe:.*)$/;
const MAX_NON_ROUTING = 12;

function compile(list: readonly unknown[] | undefined, fallback: readonly string[]): RegExp[] {
  const src = Array.isArray(list) && list.length ? list : fallback;
  const out: RegExp[] = [];
  for (const p of src) {
    if (typeof p !== "string") continue;
    try {
      out.push(new RegExp(p, "i"));
    } catch {
      // A pattern that does not compile is ignored; the schema validates regexes, so this only guards a hand-built config.
    }
  }
  return out;
}

/** The server's own words in one evidence line: the excerpt kept with it, else what follows the first ": " of the outcome (the refusal outcomes of the packs end with the reply). */
function refusalText(e: Evidence): string | undefined {
  if (e.excerpt) return e.excerpt;
  const i = e.outcome.indexOf(": ");
  return i >= 0 ? e.outcome.slice(i + 2) : undefined;
}

/**
 * `refusal-quality` (advisory candidate, design 3.7; seam S10: run.ts pushes the result onto the run's checks after the pack loop).
 * Reads every refusal the checks recorded and says what share of them route the caller: pass at 90 % or more, part at 50 % or more,
 * fail below, n/a with no refusal. A refusal that is only "forbidden" leaves an agent retrying.
 */
export function refusalQuality(checks: readonly CheckResult[], cfg?: { checks?: Record<string, CheckConfig> }): CheckResult {
  const m = REFUSAL_QUALITY_META;
  const base = { id: m.id, pack: "core" as const, label: m.label, critical: false, advisory: true as const, scope: m.scope };
  const own = cfg?.checks?.[m.id];
  const patterns = compile(own?.patterns as unknown[] | undefined, DEFAULT_ROUTING_PATTERNS);
  const seen: { e: Evidence; text: string; routes: boolean }[] = [];
  for (const c of checks) {
    if (c.id === m.id) continue;
    for (const e of c.evidence) {
      if (!e.code || !REFUSAL_CODE.test(e.code)) continue;
      const text = refusalText(e);
      if (!text || !text.trim()) continue;
      // A probe's verdict code does not say its reply was a refusal: only a reply that reads as one is counted.
      if (e.code.startsWith("probe:") && !refusedInTextOnly({ isError: false, text }) && !/\b(refus|denied|not allowed|forbidden|not permitted|error)/i.test(text)) continue;
      seen.push({ e, text, routes: patterns.some((re) => re.test(text)) });
    }
  }
  const done = (r: Pick<CheckResult, "verdict" | "summary" | "evidence">): CheckResult => applyCheckConfig({ ...base, ...r }, own);
  if (!seen.length) return done({ verdict: "na", summary: "no refusal was recorded in this run, so there is nothing to judge", evidence: [] });
  const routing = seen.filter((s) => s.routes).length;
  const pct = (routing / seen.length) * 100;
  const verdict = pct >= 90 ? "pass" : pct >= 50 ? "part" : "fail";
  const evidence: Evidence[] = seen
    .filter((s) => !s.routes)
    .slice(0, MAX_NON_ROUTING)
    .map((s) => ({ probe: s.e.probe, outcome: `the refusal does not say what to do instead: ${brief(s.text, 160)}`, verifiedBy: "response" as const, ...(s.e.tool ? { tool: s.e.tool } : {}), excerpt: excerpt(s.text), code: "refusal.dead-end" }));
  return done({ verdict, summary: `${routing} of ${seen.length} refusal(s) say what to do instead or why retrying will not help (${Math.round(pct)} %)`, evidence });
}

const TOOL_WORD = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;
const BACKTICKED = /`([A-Za-z][A-Za-z0-9_-]{2,})(?:\(\))?`/g;

/** Names the instructions may use without naming a missing tool: tools, parameters, prompts and resources the server declares. */
function knownNames(ctx: CoreCtx): Set<string> {
  const out = new Set<string>();
  for (const t of ctx.session.tools) {
    out.add(t.name.toLowerCase());
    for (const k of Object.keys(t.inputSchema?.properties ?? {})) out.add(k.toLowerCase());
  }
  for (const p of ctx.session.prompts ?? []) out.add(p.name.toLowerCase());
  for (const r of ctx.session.resources ?? []) if (r.name) out.add(r.name.toLowerCase());
  return out;
}

/**
 * `instructions-hygiene` (advisory candidate, design 3.7). Clause 1: the instructions name something that looks like a tool (a snake_case word,
 * or a word in backticks) that the server does not list (a leftover from another server's prompt). Clause 2: a pattern from
 * `checks.instructions-hygiene.deny` matches. n/a when the server sent no instructions.
 */
export function instructionsHygiene(ctx: CoreCtx): CheckResult {
  const m = INSTRUCTIONS_HYGIENE_META;
  const base = { id: m.id, pack: "core" as const, label: m.label, critical: false, advisory: true as const, scope: m.scope };
  const cfg = ctx.checks?.[m.id];
  const done = (r: Pick<CheckResult, "verdict" | "summary" | "evidence">): CheckResult => applyCheckConfig({ ...base, ...r }, cfg);
  const text = ctx.session.instructions;
  if (!text || !text.trim()) return done({ verdict: "na", summary: "the server sent no instructions", evidence: [] });
  const known = knownNames(ctx);
  const evidence: Evidence[] = [];
  const unknown = new Set<string>();
  for (const w of text.match(TOOL_WORD) ?? []) if (!known.has(w.toLowerCase())) unknown.add(w);
  for (const hit of text.matchAll(BACKTICKED)) {
    const w = hit[1]!;
    // Upper-case words (SELECT, LIMIT) are SQL or prose, not tool names.
    if (w === w.toUpperCase() || known.has(w.toLowerCase()) || !/^[a-z]/.test(w)) continue;
    unknown.add(w);
  }
  for (const w of unknown) {
    const at = text.indexOf(w);
    evidence.push({ probe: "initialize: instructions", outcome: `the instructions name \`${w}\`, which the server does not offer as a tool (or declare as a parameter, prompt or resource)`, verifiedBy: "static", excerpt: excerpt(text.slice(Math.max(0, at - 60), at + w.length + 60)), code: "instructions.unknown-tool" });
  }
  const deny = compile(cfg?.deny as unknown[] | undefined, []);
  let denied = 0;
  for (const re of deny) {
    const hit = re.exec(text);
    if (!hit) continue;
    denied++;
    evidence.push({ probe: "initialize: instructions", outcome: `the instructions match the deny pattern /${re.source}/`, verifiedBy: "static", excerpt: excerpt(text.slice(Math.max(0, hit.index - 40), hit.index + hit[0].length + 40)), code: "instructions.deny" });
  }
  if (!evidence.length) {
    return done({ verdict: "pass", summary: `the instructions name no tool the server lacks${deny.length ? ` and match none of ${deny.length} deny pattern(s)` : ""}`, evidence: [{ probe: "initialize: instructions", outcome: `${text.length} character(s) read against ${known.size} declared name(s)`, verifiedBy: "static" }] });
  }
  const parts = [unknown.size ? `names ${unknown.size} tool(s) the server does not offer (${[...unknown].slice(0, 5).join(", ")})` : "", denied ? `matches ${denied} deny pattern(s)` : ""].filter(Boolean);
  return done({ verdict: "fail", summary: `the server instructions ${parts.join(" and ")}`, evidence });
}

/**
 * The server's tools/list reply could not be parsed as MCP. There is nothing to probe, so the
 * handshake check fails with the reason and the other checks are inconclusive.
 */
export function protocolFailure(message: string): CheckResult[] {
  const reason = "tools/list was rejected by the MCP client, so nothing could be probed";
  return [
    { id: "protocol", pack: "core", label: "Valid MCP handshake and tool schemas", critical: false, scope: "server", verdict: "fail", summary: "the server's reply is not valid MCP", evidence: [{ probe: "initialize + tools/list", outcome: message, verifiedBy: "protocol" }] },
    { id: "tool-poisoning", pack: "core", label: "No tool-poisoning indicators in tool metadata", critical: true, scope: "server (what it declares, not what it does)", verdict: "inconclusive", summary: reason, evidence: [] },
    { id: "robust-input", pack: "core", label: "Survives malformed tool input", critical: false, scope: "server", verdict: "inconclusive", summary: reason, evidence: [] },
    { id: "secret-echo", pack: "core", label: "No environment secret echoed in responses", critical: true, scope: "server", verdict: "inconclusive", summary: reason, evidence: [] },
    // The same five core checks as every other run (refusal-quality is added by the harness after the packs).
    { id: INSTRUCTIONS_HYGIENE_META.id, pack: "core", label: INSTRUCTIONS_HYGIENE_META.label, critical: false, advisory: true, scope: INSTRUCTIONS_HYGIENE_META.scope, verdict: "inconclusive", summary: reason, evidence: [] },
  ];
}

export async function runCore(ctx: CoreCtx): Promise<CheckResult[]> {
  return applyChecksConfig(await runCoreChecks(ctx), ctx.checks);
}

async function runCoreChecks(ctx: CoreCtx): Promise<CheckResult[]> {
  if (!ctx.session.tools.length) {
    const none = "the server declares no tools";
    // Instructions and serverInfo are text the model reads even with no tool next to them: they are scanned, and only a clean scan of nothing is n/a.
    const scanned = hygieneCheck(ctx);
    const hasText = (ctx.session.prompts?.length ?? 0) + (ctx.session.resources?.length ?? 0) > 0 || Boolean(ctx.session.instructions);
    const poisoning: CheckResult = hasText || scanned.verdict !== "pass" ? scanned : { id: "tool-poisoning", pack: "core", label: "No tool-poisoning indicators in tool metadata", critical: true, scope: "server (what it declares, not what it does)", verdict: "na", summary: none, evidence: [] };
    return [
      protocolCheck(ctx),
      poisoning,
      { id: "robust-input", pack: "core", label: "Survives malformed tool input", critical: false, scope: "server", verdict: "na", summary: none, evidence: [] },
      { id: "secret-echo", pack: "core", label: "No environment secret echoed in responses", critical: true, scope: "server", verdict: "na", summary: none, evidence: [] },
      instructionsHygiene(ctx),
    ];
  }
  const listing = JSON.stringify({ serverInfo: ctx.session.serverInfo, instructions: ctx.session.instructions, tools: ctx.session.tools, prompts: ctx.session.prompts ?? [], resources: ctx.session.resources ?? [] });
  const hygiene = hygieneCheck(ctx);
  // A disabled robust-input makes no calls at all: applyChecksConfig turns this stub into the "disabled by config" result.
  const robust: CheckResult = ctx.checks?.["robust-input"]?.enabled === false
    ? { id: "robust-input", pack: "core", label: "Survives malformed tool input", critical: false, scope: "server", verdict: "na", summary: "disabled by config", evidence: [] }
    : await robustnessCheck(ctx);
  const secret = secretEchoCheck(ctx, listing);
  // The handshake check reads what the session saw on the wire (stdout noise, invalid results) through every call above, so it runs last.
  const protocol = protocolCheck(ctx);
  return [protocol, hygiene, robust, secret, instructionsHygiene(ctx)];
}

export type { ToolInfo };

// ---------------------------------------------------------------------------------------------------------
// Check documentation
// ---------------------------------------------------------------------------------------------------------

const CORE_SINCE = "0.1-draft";

export function describe(): CheckDoc[] {
  const common = { pack: "core" as const, advisory: false, thresholds: {}, since: CORE_SINCE, status: "shipped" as const };
  return [
    {
      ...common,
      id: "protocol",
      label: "Valid MCP handshake and tool schemas",
      critical: false,
      scope: "server",
      verifiedBy: ["protocol"],
      probes: [
        { id: "tool-name", text: "tool names are 1-128 characters of A-Z a-z 0-9 _ . -", core: true, kind: "schema" },
        { id: "unique-names", text: "no two tools share a name", core: true, kind: "schema" },
        { id: "description", text: "every tool has a description of at least 10 characters", core: false, kind: "schema" },
        { id: "stdout-noise", text: "no line on the server's stdout that is not a JSON-RPC message (a banner, a log line, a stray print), counted over initialize, tools/list and every call the core session makes; part, protocol.stdout-noise", core: true, kind: "wire" },
        { id: "invalid-result", text: "every tools/call result the core session receives is valid MCP (the client's schema accepts it); part, protocol.invalid-result", core: true, kind: "wire" },
      ],
      falsePositive: "A short description is a style finding and only earns part; a tool name outside the allowed characters is a protocol failure in strict clients. A server that prints a banner to stdout works with a lenient client and breaks a strict one; the check says part, not fail.",
      falseNegative: "The tools/list schema is reviewed, plus what the core session saw on the wire while it ran: stdout lines that are not JSON-RPC and replies the client rejected as not valid MCP. Only the core session is measured; other packs' sessions are not. Tool results are otherwise checked by robust-input. An HTTP server has no stdout, so noise is never reported for it.",
      configKeys: ["checks.protocol.enabled", "checks.protocol.severity"],
    },
    {
      ...common,
      id: "tool-poisoning",
      label: "No tool-poisoning indicators in tool metadata",
      critical: true,
      scope: "server (what it declares, not what it does)",
      verifiedBy: ["static"],
      probes: [
        { id: "hidden-characters", text: "invisible and bidirectional control characters in any metadata string", core: true, kind: "strong" },
        { id: "ctl-strong", text: "ESC (U+001B), NUL (U+0000) or a C1 control (U+0080 to U+009F) in any metadata string", core: true, kind: "strong" },
        { id: "ctl-weak", text: "another C0 control (U+0001 to U+0008, U+000B, U+000C, U+000E to U+001A, U+001C to U+001F) or DEL (U+007F); tab, line feed and carriage return are allowed", core: false, kind: "weak" },
        ...INJECTION.map(([tier, label, re]) => ({ id: label, text: re.source, core: tier === "strong", kind: tier })),
        { id: "server-instructions", text: "the `instructions` string from initialize is scanned by every rule above (no length rule: long instructions are ordinary)", core: true, kind: "scope" },
        { id: "server-info", text: "serverInfo name, title, description and websiteUrl are scanned by every rule above", core: true, kind: "scope" },
      ],
      falsePositive: "A server that embeds ANSI colour codes in its descriptions on purpose fails by design: ESC drives a terminal that renders the text. Only phrases with no innocent reading are strong and fail the check; a careful honest description can only earn part. Documentation that names a key path is weak, an instruction to read and send it is strong.",
      falseNegative: "Static text matching. A description or instruction that carries an injection in words the patterns do not know passes. Tool names, descriptions, schema text, the server instructions (first 1 MiB), serverInfo, prompts and resources are scanned; tool output is not (see notCovered).",
      configKeys: ["checks.tool-poisoning.enabled", "checks.tool-poisoning.severity"],
    },
    {
      ...common,
      id: "robust-input",
      label: "Survives malformed tool input",
      critical: false,
      scope: "server",
      verifiedBy: ["protocol", "response"],
      probes: [
        { id: "missing-required", text: "{} when the tool has required arguments", core: true, kind: "invalid" },
        { id: "wrong-types", text: "every typed argument gets a value of the wrong JSON type", core: true, kind: "invalid" },
        { id: "nulls", text: "every typed argument is null", core: true, kind: "invalid" },
        { id: "extra-argument", text: `wrong types plus an unexpected extra argument (${UNEXPECTED_ARG})`, core: true, kind: "invalid" },
        { id: "string-as-object", text: "every string argument gets an object (a second wrong type: the first candidate is a number)", core: true, kind: "invalid" },
        { id: "nested-string", text: "a string in place of a required array-of-object parameter (one extra call per tool that has one)", core: true, kind: "invalid" },
        { id: "nested-item", text: "a required array-of-object parameter gets one item that lacks a required field, when the items declare one (one extra call per tool that has one)", core: true, kind: "invalid" },
        { id: "read-only-no-args", text: "{} for a tool with no arguments that declares readOnlyHint: true (a valid call, counted for coverage)", core: false, kind: "valid" },
        { id: "robust.lenient-downstream", text: "an error reply that reports a failed fetch (the failed-fetch vocabulary of the net pack: connection refused, DNS, timeout, TLS ...) and does not name a parameter: the server used the invalid argument before it failed; part", core: true, kind: "rule" },
        { id: "robust.internal-error", text: "an error reply that is an unhandled runtime error (TypeError, Cannot read properties, is not a function, undefined is not, AttributeError, KeyError, NoneType): an internals leak, not a validation decision; part", core: true, kind: "rule" },
      ],
      thresholds: { max_tools: { default: MAX_TOOLS_PROBED, configKey: "checks.robust-input.max_tools", standardLocked: true } },
      falsePositive: "Only schema-invalid input is sent, so a tool that rejects it cannot have run with unintended input. A plain-text refusal without isError counts as a rejection, with evidence that clients cannot tell it from success. An error is a clean rejection only when it is a validation decision: a reply that names a declared parameter and says it is invalid or required is one, a failed upstream request (robust.lenient-downstream) or an unhandled runtime error (robust.internal-error) is not.",
      falseNegative: "A tool that takes no arguments and is not declared read-only is never called (it is listed as needing a probes: entry). Valid calls are only made through probes:. A server that validates the top level and passes nested entities on unchecked is caught only through the two nested variants, and only for required array-of-object parameters; object parameters and optional ones are not descended.",
      configKeys: ["checks.robust-input.hang_ms", "checks.robust-input.max_tools", "timeout_probe_sec"],
    },
    {
      ...common,
      id: "secret-echo",
      label: "No environment secret echoed in responses",
      critical: true,
      scope: "server",
      verifiedBy: ["response"],
      probes: [{ id: "canary-env", text: "SEALMARK_CANARY and SEALMARK_FAKE_API_KEY are set in the server's environment; tools/list and every captured response are searched for them", core: true, kind: "canary" }],
      falsePositive: "The canaries are random per run, so a match is the server printing its own environment.",
      falseNegative: "Coverage is limited to the calls the harness makes: with no valid call (no probes: entry) only malformed input and tools/list are searched, which is why a core-only run is labelled hygiene only. HTTP servers cannot receive canaries (n/a).",
      configKeys: ["checks.secret-echo.enabled", "checks.secret-echo.severity"],
    },
    {
      ...common,
      id: "refusal-quality",
      label: REFUSAL_QUALITY_META.label,
      critical: false,
      advisory: true,
      scope: REFUSAL_QUALITY_META.scope,
      verifiedBy: ["response"],
      probes: [{ id: "routing", text: `every refusal the other checks recorded (codes scope.refused, sql-guard.refused, net.ssrf-refused*, fs.*refused*, and probe replies that are errors) is read; one routes when it matches a pattern: ${DEFAULT_ROUTING_PATTERNS.join(", ")}. pass at 90 % or more, part at 50 %, fail below, n/a with no refusal`, core: false, kind: "advisory" }],
      falsePositive: "A server that refuses tersely on purpose (to give an attacker nothing) reads as a dead end; the check is advisory and never moves a letter.",
      falseNegative: "Only refusals the run recorded with the server's words are read; a refusal worded with none of the patterns reads as a dead end whatever it says (checks.refusal-quality.patterns replaces the list).",
      configKeys: ["checks.refusal-quality.enabled", "checks.refusal-quality.severity", "checks.refusal-quality.patterns"],
      since: "0.3-draft",
    },
    {
      ...common,
      id: "instructions-hygiene",
      label: INSTRUCTIONS_HYGIENE_META.label,
      critical: false,
      advisory: true,
      scope: INSTRUCTIONS_HYGIENE_META.scope,
      verifiedBy: ["static"],
      probes: [
        { id: "unknown-tool", text: "a snake_case word, or a word in backticks, in the initialize instructions that is not a tool, parameter, prompt or resource the server declares (a leftover from another server's prompt)", core: false, kind: "static" },
        { id: "deny", text: "a regex from checks.instructions-hygiene.deny matches the instructions (default: none, so this clause is not run)", core: false, kind: "static" },
      ],
      falsePositive: "Instructions that mention a snake_case term that is not a tool (a column name, a setting) read as an unknown tool; the check is advisory and never moves a letter.",
      falseNegative: "Only names that look like tools are found: a tool named with one plain word is recognised in prose only inside backticks.",
      configKeys: ["checks.instructions-hygiene.enabled", "checks.instructions-hygiene.severity", "checks.instructions-hygiene.deny"],
      since: "0.3-draft",
    },
  ];
}
