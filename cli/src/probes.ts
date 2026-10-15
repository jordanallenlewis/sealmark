import { randomBytes } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { fillArgs } from "./classify.js";
import { ConfigError } from "./config.js";
import type { ProbeExpect, ProbeSpec, UpstreamReplySpec } from "./config/model.js";
import type { CallResult, McpSession, ToolInfo } from "./mcp.js";
import { variantsFor } from "./packs/core.js";
import { FAILURE_VETO, targetProblem } from "./packs/net.js";
import { head, listenerReachable, refusedInTextOnly } from "./packs/shared.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, FsDiff, FsSnapshot, Pack, PackCtx, Sandbox, ToolClassification, Verdict } from "./types.js";

/**
 * `probes:` in the configuration. One list, two uses:
 *
 *  - a probe WITH `check:` is a custom check. The `custom` pack calls the tool once with the probe's arguments and tests the
 *    response and what the harness observed (files in the sandbox, hits on the loopback listener, duration) against `expect:`.
 *  - a probe WITHOUT `check:` is a valid call for coverage. `runValidCalls` makes it once in the core session, so the
 *    secret-echo and robust-input checks see what the tool does with good input. A missed `expect:` is a warning, never a verdict.
 *
 * Probes observe only the sandbox. A literal path, URL, command or SQL string aimed at a tool the classifier knows takes that kind
 * of argument is refused: the target must be a placeholder the harness fills with something it owns.
 */

// ---------------------------------------------------------------------------------------------------------
// Placeholders
// ---------------------------------------------------------------------------------------------------------

export interface ProbeVars {
  sandbox: string;
  sandbox_home: string;
  canary: string;
  listener: string;
  sqlite_path: string;
  duckdb_path: string;
}

export function probeVars(sb: Sandbox): ProbeVars {
  const sep_ = process.platform === "win32" ? "\\" : "/";
  return { sandbox: sb.root, sandbox_home: sb.home, canary: sb.canary, listener: sb.listener.url, sqlite_path: `${sb.root}${sep_}fixture.sqlite`, duckdb_path: `${sb.root}${sep_}fixture.duckdb` };
}

const HARNESS_KEYS = "sandbox_home|sandbox|canary|dir|listener|sqlite_path|duckdb_path";
/** The harness placeholders a probe may use: the configuration's, less {token} (filled per probe) and the stub and bearer values (refused in probe args). */
export const PROBE_HARNESS_KEYS: readonly string[] = HARNESS_KEYS.split("|");
/** Placeholders that stand for a place the harness owns. Only these may start a path or URL. */
const ANCHOR = new RegExp(`^\\{(?:${HARNESS_KEYS})\\}`);
const HARNESS_PLACEHOLDER = new RegExp(`\\{(?:${HARNESS_KEYS})\\}`);
const PLACEHOLDER = () => new RegExp(`\\{(${HARNESS_KEYS}|token)\\}`, "g");
/** Database placeholders: custom probes cannot fill them (the database belongs to the db pack). */
const DB_PLACEHOLDER = /\{(?:dsn(?::[a-z_]+)?|host|port|user|password|database|role)\}/;

function expandString(s: string, vars: Partial<ProbeVars>, tok: string): string {
  return s.replace(PLACEHOLDER(), (m, key: string) => {
    if (key === "token") return tok;
    if (key === "dir") return vars.sandbox ?? m;
    return (vars as Record<string, string | undefined>)[key] ?? m;
  });
}

function expandValue(v: unknown, vars: Partial<ProbeVars>, tok: string): unknown {
  if (typeof v === "string") return expandString(v, vars, tok);
  if (Array.isArray(v)) return v.map((x) => expandValue(x, vars, tok));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandValue(x, vars, tok)]));
  return v;
}

const strings = (v: unknown, at = "args"): [string, string][] => {
  if (typeof v === "string") return [[at, v]];
  if (Array.isArray(v)) return v.flatMap((x, i) => strings(x, `${at}[${i}]`));
  if (v && typeof v === "object") return Object.entries(v).flatMap(([k, x]) => strings(x, `${at}.${k}`));
  return [];
};

const usesDbPlaceholder = (v: unknown) => strings(v).some(([, s]) => DB_PLACEHOLDER.test(s));

// ---------------------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------------------

export interface CheckMeta {
  id: string;
  label: string;
  critical: boolean;
  scope: string;
}

// -- the round 6 clauses of a probe: the types of config/model.ts -----------------------------------
// The Rules* interfaces below are the parts of the stub, the log and the identities a probe uses; the real UpstreamStub, LogObserver and
// IdentityAccess of types.ts satisfy them, and a test can hand in a small fake.

export type ProbeIdentity = NonNullable<ProbeSpec["identity"]>;
export type { UpstreamReplySpec };
export type UpstreamExpectSpec = NonNullable<ProbeExpect["upstream"]>;
export type RuleExpect = ProbeExpect;
export type RuleProbeSpec = ProbeSpec;

/** What a probe reads of a request the stub saw (a subset of `UpstreamRequest`). */
export interface RulesRequest {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: string;
  minted?: string[];
}
/** What a probe uses of the upstream stub (a subset of `UpstreamStub`). */
export interface RulesUpstream {
  mark(): number;
  requests(since?: number): RulesRequest[];
  setOverride(reply: UpstreamReplySpec | undefined): void;
}
/** What a probe uses of the log observer (a subset of `LogObserver`). */
export interface RulesLog {
  mark(): number;
  since(mark: number): string;
}
/** `IdentityAccess.openAs`. */
export type RulesOpenAs = (identity: "a" | "b" | null) => Promise<McpSession>;

export interface PlannedProbe {
  index: number;
  /** The probe's id, or `<tool>#<n>` for a probe without one; `id[k=v]` / `id#n` for a matrix cell or a case. */
  id: string;
  spec: RuleProbeSpec;
  tool: ToolInfo;
  cls?: ToolClassification;
  check?: CheckMeta;
  /** Needs --active: `active: true`, which is required for command-class tools. */
  active: boolean;
  timeoutMs: number;
  /** Problems with the arguments against the tool's schema. A probe with problems is not counted as a valid call. */
  schemaProblems: string[];
  usesDb: boolean;
}

export interface ProbePlan {
  probes: PlannedProbe[];
  /** Custom checks in order of first appearance. */
  checks: CheckMeta[];
}

export interface PlanInput {
  tools: readonly ToolInfo[];
  classification: readonly ToolClassification[];
  /** Needed to validate `files:` paths; without it a probe that has `files:` is refused. */
  sandbox?: Pick<Sandbox, "fs"> & Partial<Pick<Sandbox, "dir" | "root" | "home" | "canary" | "listener">>;
  /** Check ids that custom checks may not reuse (every built-in pack's ids). */
  reservedCheckIds?: Iterable<string>;
  /** Default `timeout_ms`. */
  defaultTimeoutMs?: number;
  /**
   * The upstream stub is declared (`upstream.kind: http`). Without it a probe may not carry `upstream.reply` or `expect.upstream`,
   * and SQL is refused as before: with a stub the stub is the only database the server has. `mintsTokens` says whether the stub is
   * scripted to mint `{upstream_token}` (config `upstream.responses` / `default_reply`); `undefined` means unknown.
   */
  upstream?: { kind?: "http"; mintsTokens?: boolean };
  /** The server's transport; `identity` is refused on stdio. Unknown (`undefined`) is not refused. */
  transport?: "stdio" | "http";
}

const PROBE_KEYS = ["id", "check", "tool", "args", "active", "timeout_ms", "expect", "identity", "matrix", "cases", "upstream"];
const CHECK_KEYS = ["id", "label", "critical", "scope"];
const UPSTREAM_EXPECT_KEYS = ["requests", "none_matching", "all_matching", "header", "token_echoed"];
const EXPECT_KEYS = ["is_error", "text", "files", "listener", "duration_ms", "upstream", "log", "response"];
const FILE_KEYS = ["unchanged", "created", "absent"];
const SM_PROGRAM = /^sm-(?:echo|canary|sleep|spew)$/;

function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

function unknownKeys(obj: Record<string, unknown>, allowed: string[], at: string, out: string[]): void {
  for (const k of Object.keys(obj)) {
    if (allowed.includes(k)) continue;
    const near = allowed.find((a) => distance(a, k) <= 2);
    out.push(`${at}: unknown key "${k}"${near ? `; did you mean "${near}"?` : ` (allowed: ${allowed.join(", ")})`}`);
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);

function typeMatches(type: string, v: unknown): boolean {
  switch (type) {
    case "string":
      return typeof v === "string";
    case "number":
      return typeof v === "number";
    case "integer":
      return Number.isInteger(v);
    case "boolean":
      return typeof v === "boolean";
    case "array":
      return Array.isArray(v);
    case "object":
      return isObject(v);
    case "null":
      return v === null;
    default:
      return true;
  }
}

/** Top-level checks only (required names, primitive types, enums); anything the checker cannot decide (anyOf, $ref) is let through. */
export function schemaProblemsOf(tool: ToolInfo, args: Record<string, unknown>): string[] {
  const schema = tool.inputSchema ?? {};
  const props = (schema.properties ?? {}) as Record<string, { type?: string | string[]; enum?: unknown[] }>;
  const out: string[] = [];
  for (const r of schema.required ?? []) if (!(r in args)) out.push(`missing required argument "${r}"`);
  for (const [k, v] of Object.entries(args)) {
    const p = props[k];
    if (!p) {
      if (Object.keys(props).length && schema.additionalProperties !== true) out.push(`"${k}" is not an argument of this tool (it takes: ${Object.keys(props).join(", ")})`);
      continue;
    }
    const types = [p.type].flat().filter((t): t is string => typeof t === "string");
    if (types.length && !types.some((t) => typeMatches(t, v))) out.push(`argument "${k}" must be ${types.join(" or ")}`);
    else if (Array.isArray(p.enum) && !(typeof v === "string" && PLACEHOLDER().test(v)) && !p.enum.includes(v))
      out.push(`argument "${k}" must be one of ${p.enum.map((x) => JSON.stringify(x)).join(", ")}`);
  }
  return out;
}

// -- literal targets ----------------------------------------------------------------------------------------

const stripScheme = (s: string) => s.replace(/^[A-Za-z][A-Za-z0-9+.-]+:\/{0,3}/, "");
const hasScheme = (s: string) => /^[A-Za-z][A-Za-z0-9+.-]+:\S/.test(s);
const anchored = (s: string) => ANCHOR.test(s) || ANCHOR.test(stripScheme(s));
/** Looks like a place on a disk: a separator, a drive, a leading ~ or dot segment. A bare file name is relative to the sandbox root and is fine. */
const looksPath = (s: string) => /[\\/]/.test(s) || /^[A-Za-z]:/.test(s) || /^~/.test(s) || /^\.\.?$/.test(s);
const looksAbsolute = (s: string) => /^(?:[A-Za-z]:[\\/]|\\\\|\/|~[\\/]?|file:)/.test(s);
const looksHost = (s: string) => /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#].*)?$/i.test(s) || /^\d{1,3}(?:\.\d{1,3}){0,3}(?::\d+)?(?:[/?#].*)?$/.test(s) || /^\[[0-9a-f:]+\]/i.test(s);
const SQL_WORDS = /\b(?:select|insert|update|delete|drop|create|alter|truncate|with|pragma|attach|vacuum|copy|explain|grant)\b/i;

/** Segments of a string at shell separators; the first token of each must be a harness program (the first segment of an argument is data). */
function foreignCommands(s: string, firstIsData: boolean): string[] {
  return s.split(/;|&&?|\|\|?|\n|`|\$\(|\)/).flatMap((seg, i) => {
    const first = seg.trim().split(/\s+/)[0] ?? "";
    if (!first || (i === 0 && firstIsData)) return [];
    return SM_PROGRAM.test(first) ? [] : [first];
  });
}

function literalProblems(cls: ToolClassification | undefined, args: Record<string, unknown>, sqlAllowed = false): string[] {
  const out: string[] = [];
  // A low-confidence tool is treated as unclassified, except for the two classes whose literals are always refused.
  const kind = cls && (cls.confidence !== "low" || cls.class === "command" || cls.class === "sql") ? cls.class : undefined;
  const pathLike = kind === "path" || kind === "git";
  const param = (role: string) => (cls?.params as Record<string, string | undefined> | undefined)?.[role];
  for (const [at, s] of strings(args)) {
    const name = at.replace(/^args\.?/, "").replace(/\[\d+\]/g, "") || at;
    const root = name.split(".")[0];
    if (kind === "command") {
      if (root === param("command")) {
        const bad = cls?.style === "spawn" || param("args") ? (SM_PROGRAM.test(s.trim()) ? [] : [s]) : foreignCommands(s, false);
        if (bad.length)
          out.push(`${at}: ${JSON.stringify(s)} would run ${bad.map((b) => JSON.stringify(b)).join(", ")}; probes may only run the harness programs sm-echo, sm-canary, sm-sleep and sm-spew`);
      } else if (root === param("args")) {
        const bad = foreignCommands(s, true);
        if (bad.length)
          out.push(
            `${at}: ${JSON.stringify(s)} contains the command ${bad.map((b) => JSON.stringify(b)).join(", ")}; after a shell separator only the harness programs sm-echo, sm-canary, sm-sleep and sm-spew are allowed`,
          );
      } else if ((looksPath(s) || hasScheme(s)) && !anchored(s) && !/^\{token\}$/.test(s))
        out.push(`${at}: ${JSON.stringify(s)} looks like a path or URL; use {sandbox}, {sandbox_home}, {canary} or {listener}`);
      continue;
    }
    if (kind === "sql") {
      // With an upstream stub declared, the stub is the only database the server has: SQL cannot reach anything the harness does not own.
      if (!sqlAllowed && root === param("sql") && !/^\{token\}$/.test(s))
        out.push(`${at}: SQL cannot be sent from probes (the db and sqlite packs own SQL against databases the harness seeds); remove the literal ${JSON.stringify(s.slice(0, 40))}`);
      continue;
    }
    if (pathLike && (looksPath(s) || looksAbsolute(s)) && !anchored(s)) {
      out.push(`${at}: ${JSON.stringify(s)} looks like a path on your disk; a probe aimed at a ${kind} tool must start with {sandbox}, {sandbox_home} or {canary} (literal targets are not allowed)`);
    } else if (kind === "url" && !/^\{token\}$/.test(s) && (hasScheme(s) || looksHost(s) || /^\/\//.test(s)) && !anchored(s) && !/^data:/i.test(s)) {
      out.push(`${at}: ${JSON.stringify(s)} looks like a URL; a probe aimed at a url tool must start with {listener} (the harness's loopback listener)`);
    } else if (!kind || kind === "text" || kind === "opaque") {
      // A tool the classifier cannot place may still be a path or URL tool in disguise: refuse anything that is plainly a place outside the sandbox.
      if ((looksAbsolute(s) || /^[a-z][a-z0-9+.-]+:\/\//i.test(s)) && !anchored(s))
        out.push(`${at}: ${JSON.stringify(s)} looks like a path or URL, but the classifier does not know that this tool takes one; use a placeholder, or set tools.overrides for the tool`);
    }
  }
  return out;
}

// -- files and paths -----------------------------------------------------------------------------------------

const fold = (p: string) => (process.platform === "win32" ? p.replace(/\\/g, "/").toLowerCase() : p.replace(/\\/g, "/")).replace(/\/+$/, "");
const inside = (p: string, dir: string) => fold(p) === fold(dir) || fold(p).startsWith(`${fold(dir)}/`);

/** The snapshot key (`canary/secret.txt`) of an absolute path inside an observed directory, or undefined. */
function keyFor(fs: Sandbox["fs"], abs: string): string | undefined {
  const full = resolve(abs);
  for (const [label, dir] of Object.entries(fs.dirs)) {
    if (!inside(full, dir)) continue;
    const rel = relative(resolve(dir), full);
    if (!rel || rel.startsWith("..") || isAbsolute(rel)) continue;
    return `${label}/${rel.split(sep).join("/")}`;
  }
  return undefined;
}

// -- where an argument really points ----------------------------------------------------------------------------

/** Placeholders that stand for a directory or file in the sandbox. */
const FS_ANCHOR = /^\{(?:sandbox_home|sandbox|canary|dir|sqlite_path|duckdb_path)\}/;
const LISTENER_ANCHOR = /^\{listener\}/;
/** Percent-encoded dot, slash, backslash or NUL: a server that decodes them reads a different path than the one that was checked. */
const PERCENT_SEPARATOR = /%(?:2e|2f|5c|00)/i;
/** A segment made only of dots (`...`, `....`): `....//` becomes `../` in a server that strips `../` once. Plain `..` is judged by where it lands. */
const DOT_SEGMENT = /(?:^|[\\/])\.{3,}[ .]*(?=[\\/]|$)/;

export interface TargetEnv {
  /** The sandbox directory as a whole: the limit for every path a probe may name. */
  sandboxDir?: string;
  /** Ports of the harness listener (IPv4 and IPv6). */
  ports: number[];
}

/**
 * Why an argument may not be sent, judged on the EXPANDED value, or undefined. A literal that starts with `{listener}` is
 * parsed as a URL and must still point at the listener (`{listener}@host/` expands to a URL whose host is `host`); one that
 * starts with a sandbox placeholder must stay inside the sandbox after percent-decoding and normalisation. This runs when the
 * probes are validated and again, with the real listener port and sandbox, just before the call.
 */
export function unsafeTarget(raw: string, expanded: string, env: TargetEnv): string | undefined {
  const bare = stripScheme(raw);
  if (LISTENER_ANCHOR.test(bare) && !LISTENER_ANCHOR.test(raw)) return "write {listener} first: it already includes http://127.0.0.1:<port>";
  if (LISTENER_ANCHOR.test(raw)) {
    const p = targetProblem(expanded, { sandboxDir: env.sandboxDir ?? "", ports: env.ports, allowDns: false });
    return p ? `it does not stay on the harness listener (${p})` : undefined;
  }
  if (FS_ANCHOR.test(bare)) {
    if (PERCENT_SEPARATOR.test(raw)) return "it contains a percent-encoded dot, slash or backslash, which a server may decode into a path outside the sandbox";
    if (DOT_SEGMENT.test(raw)) return "it contains a path segment made only of dots, which some servers turn into `..`";
    if (env.sandboxDir && !/\{[a-z_]+\}/.test(expanded)) {
      const abs = resolve(expanded.replace(/^[A-Za-z][A-Za-z0-9+.-]+:\/{0,3}(?=[A-Za-z]:|\/)/, ""));
      if (!inside(abs, env.sandboxDir)) return "it climbs out of the sandbox; custom probes observe only the sandbox";
    }
  }
  return undefined;
}

/** The listener ports a probe may target, from the sandbox when there is one, else a dummy (1) that stands for "the listener". */
const portsOf = (sb: Pick<Sandbox, "listener"> | undefined): number[] => {
  const l = sb?.listener;
  return l ? [l.port, ...(l.port6 !== undefined ? [l.port6] : [])] : [1];
};

// -- rules: the round 6 clauses ----------------------------------------------------------------------------------

const MATRIX_REF = /\{matrix\.([A-Za-z_][A-Za-z0-9_]*)\}/g;
const MAX_EXPANSION = 100;
const BEARER_REF = /\{bearer(?::[ab])?\}/;
const UPSTREAM_REF = /\{upstream\}/;
const MINT = "{upstream_token}";
const isScalar = (v: unknown): v is string | number | boolean => ["string", "number", "boolean"].includes(typeof v);

/** `{bearer}`, `{upstream}` and `{upstream_token}` have no meaning in a probe's arguments; each refusal says what to write instead. */
function refusedPlaceholders(v: unknown): string[] {
  const out: string[] = [];
  for (const [where, s] of strings(v)) {
    if (BEARER_REF.test(s)) out.push(`${where}: {bearer} cannot be used in a probe's arguments: the identity is chosen with \`identity: a | b | none\` and the harness sends its token as the header you wrote in server.headers`);
    if (UPSTREAM_REF.test(s)) out.push(`${where}: {upstream} cannot be used in a probe's arguments: the stub is the server's backend, not a probe target`);
    if (s.includes(MINT)) out.push(`${where}: {upstream_token} exists only inside the reply of \`upstream.reply\` (and of upstream.responses); it is minted by the stub, not sent by a probe`);
  }
  return out;
}

function expandMatrix(v: unknown, cell: Record<string, string | number | boolean>): unknown {
  if (typeof v === "string") {
    const whole = /^\{matrix\.([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(v);
    if (whole && whole[1]! in cell) return cell[whole[1]!];
    return v.replace(MATRIX_REF, (m, k: string) => (k in cell ? String(cell[k]) : m));
  }
  if (Array.isArray(v)) return v.map((x) => expandMatrix(x, cell));
  if (isObject(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandMatrix(x, cell)]));
  return v;
}

const NO_STUB = "set upstream.kind: http (or pass --upstream) and use {upstream} in the server config, so the harness can stand in for the server's backend";

function regexProblem(s: unknown, what: string, bad: (m: string) => void): void {
  if (typeof s !== "string") return bad(`${what} must be a string`);
  try {
    new RegExp(s, "i");
  } catch (err) {
    bad(`${what} is not a valid regular expression: ${(err as Error).message}`);
  }
}

/** Shape of an `upstream.reply`; returns whether it mints `{upstream_token}`. */
function validateReply(reply: unknown, pfx: string, at: string, mine: string[], bad: (m: string) => void): boolean {
  if (!isObject(reply)) {
    bad(`${pfx} must be a mapping with one of body, json or bytes`);
    return false;
  }
  unknownKeys(reply, ["status", "headers", "body", "json", "bytes", "delay_ms"], `${at}.${pfx}`, mine);
  if (reply.status !== undefined && !(typeof reply.status === "number" && Number.isInteger(reply.status) && reply.status >= 100 && reply.status <= 599)) bad(`${pfx}.status must be an integer from 100 to 599`);
  if (reply.headers !== undefined && !(isObject(reply.headers) && Object.values(reply.headers).every((x) => typeof x === "string"))) bad(`${pfx}.headers must be a mapping of header names to strings`);
  if (reply.body !== undefined && typeof reply.body !== "string") bad(`${pfx}.body must be a string`);
  if (reply.bytes !== undefined && !(typeof reply.bytes === "number" && Number.isInteger(reply.bytes) && reply.bytes >= 1)) bad(`${pfx}.bytes must be a positive integer (the size of the reply body)`);
  if (reply.delay_ms !== undefined && !(typeof reply.delay_ms === "number" && Number.isInteger(reply.delay_ms) && reply.delay_ms >= 0)) bad(`${pfx}.delay_ms must be an integer of 0 or more`);
  const given = (["body", "json", "bytes"] as const).filter((k) => reply[k] !== undefined);
  const ok = given.length === 1 || (given.length === 2 && given.includes("body") && given.includes("bytes"));
  if (!ok) bad(`${pfx} needs exactly one of body, json or bytes (a bytes reply may also give body as its prefix); it has ${given.length ? given.join(" and ") : "none"}`);
  return JSON.stringify([reply.body, reply.json]).includes(MINT);
}

interface ExpectCtx {
  at: string;
  bad: (m: string) => void;
  mine: string[];
  input: PlanInput;
  fsObs: Sandbox["fs"] | undefined;
  /** This probe's own `upstream.reply` carries {upstream_token}. */
  replyMints: boolean;
}

/** Shape of one `expect:` mapping (the probe's or a case's). `pfx` is how the messages name it: `expect` or `cases[1].expect`. */
function validateExpect(e: unknown, pfx: string, c: ExpectCtx): void {
  const { bad, mine, input, fsObs } = c;
  if (!isObject(e)) return bad(`"${pfx}" must be a mapping`);
  unknownKeys(e, EXPECT_KEYS, `${c.at}.${pfx}`, mine);
  if (e.is_error !== undefined && typeof e.is_error !== "boolean") bad(`${pfx}.is_error must be true or false`);
  if (e.text !== undefined) {
    if (!isObject(e.text)) bad(`${pfx}.text must be a mapping with matches and/or not_matches`);
    else {
      unknownKeys(e.text, ["matches", "not_matches"], `${c.at}.${pfx}.text`, mine);
      for (const k of ["matches", "not_matches"] as const) if (e.text[k] !== undefined) regexProblem(e.text[k], `${pfx}.text.${k}`, bad);
    }
  }
  if (e.files !== undefined) {
    if (!isObject(e.files)) bad(`${pfx}.files must be a mapping with unchanged, created and/or absent`);
    else {
      unknownKeys(e.files, FILE_KEYS, `${c.at}.${pfx}.files`, mine);
      for (const k of FILE_KEYS) {
        const list = e.files[k];
        if (list === undefined) continue;
        if (!Array.isArray(list) || list.some((x) => typeof x !== "string")) {
          bad(`${pfx}.files.${k} must be a list of paths`);
          continue;
        }
        for (const p of list as string[]) {
          if (DB_PLACEHOLDER.test(p)) {
            bad(`${pfx}.files.${k}: database placeholders have no meaning in a path (${JSON.stringify(p)})`);
            continue;
          }
          if (!fsObs) {
            bad(`${pfx}.files.${k}: ${JSON.stringify(p)} cannot be checked because there is no sandbox to observe`);
            continue;
          }
          const vars: Partial<ProbeVars> = { sandbox: input.sandbox?.root, sandbox_home: input.sandbox?.home, canary: input.sandbox?.canary };
          const abs = expandString(p, vars, "tok");
          if (!ANCHOR.test(p) || /\{[a-z_]+\}/.test(abs) || !isAbsolute(abs))
            bad(`${pfx}.files.${k}: ${JSON.stringify(p)} must start with {sandbox}, {sandbox_home} or {canary}; custom probes observe only the sandbox`);
          else if (!keyFor(fsObs, abs))
            bad(`${pfx}.files.${k}: ${JSON.stringify(p)} is outside the sandbox directories the harness observes (root, root-evil, canary, home, tmp); custom probes observe only the sandbox`);
        }
      }
    }
  }
  if (e.listener !== undefined && !["none", "hit", "any"].includes(e.listener as string)) bad(`${pfx}.listener must be "none", "hit" or "any"`);
  if (e.duration_ms !== undefined) {
    if (!isObject(e.duration_ms)) bad(`${pfx}.duration_ms must be a mapping with max`);
    else {
      unknownKeys(e.duration_ms, ["max"], `${c.at}.${pfx}.duration_ms`, mine);
      if (e.duration_ms.max !== undefined && !(typeof e.duration_ms.max === "number" && e.duration_ms.max > 0)) bad(`${pfx}.duration_ms.max must be a positive number of milliseconds`);
    }
  }
  if (e.upstream !== undefined) {
    const u = e.upstream;
    if (!input.upstream) bad(`${pfx}.upstream needs the upstream stub: ${NO_STUB}`);
    if (!isObject(u)) bad(`${pfx}.upstream must be a mapping (requests, none_matching, all_matching, header, token_echoed)`);
    else {
      unknownKeys(u, UPSTREAM_EXPECT_KEYS, `${c.at}.${pfx}.upstream`, mine);
      if (u.requests !== undefined && !["none", "any"].includes(u.requests as string)) bad(`${pfx}.upstream.requests must be "none" or "any"`);
      for (const k of ["none_matching", "all_matching"] as const) if (u[k] !== undefined) regexProblem(u[k], `${pfx}.upstream.${k}`, bad);
      if (u.header !== undefined) {
        if (!isObject(u.header)) bad(`${pfx}.upstream.header must be a mapping of header names to { equals | matches }`);
        else
          for (const [name, h] of Object.entries(u.header)) {
            if (!isObject(h) || (h.equals === undefined && h.matches === undefined)) {
              bad(`${pfx}.upstream.header.${name} must be a mapping with equals and/or matches`);
              continue;
            }
            unknownKeys(h, ["equals", "matches"], `${c.at}.${pfx}.upstream.header.${name}`, mine);
            if (h.equals !== undefined && typeof h.equals !== "string") bad(`${pfx}.upstream.header.${name}.equals must be a string`);
            if (h.matches !== undefined) regexProblem(h.matches, `${pfx}.upstream.header.${name}.matches`, bad);
          }
      }
      if (u.token_echoed !== undefined) {
        if (typeof u.token_echoed !== "boolean") bad(`${pfx}.upstream.token_echoed must be true or false`);
        else if (input.upstream?.mintsTokens === false && !c.replyMints)
          bad(`${pfx}.upstream.token_echoed needs a reply that carries {upstream_token}: add \`upstream.reply\` with it to this probe, or a reply with it to upstream.responses; otherwise the stub mints no token to look for`);
      }
    }
  }
  if (e.log !== undefined) {
    if (!isObject(e.log)) bad(`${pfx}.log must be a mapping with matches and/or not_matches`);
    else {
      unknownKeys(e.log, ["matches", "not_matches"], `${c.at}.${pfx}.log`, mine);
      for (const k of ["matches", "not_matches"] as const) if (e.log[k] !== undefined) regexProblem(e.log[k], `${pfx}.log.${k}`, bad);
    }
  }
  if (e.response !== undefined) {
    if (!isObject(e.response)) bad(`${pfx}.response must be a mapping with max_bytes`);
    else {
      unknownKeys(e.response, ["max_bytes"], `${c.at}.${pfx}.response`, mine);
      if (e.response.max_bytes !== undefined && !(typeof e.response.max_bytes === "number" && Number.isInteger(e.response.max_bytes) && e.response.max_bytes >= 1)) bad(`${pfx}.response.max_bytes must be a positive integer (bytes)`);
    }
  }
}

/** How many assertions an `expect` holds: a check probe needs at least one, or it could never fail. */
export function countClauses(e: RuleExpect | undefined): number {
  if (!e) return 0;
  let n = 0;
  if (e.is_error !== undefined) n++;
  n += (["matches", "not_matches"] as const).filter((k) => e.text?.[k] !== undefined).length;
  n += FILE_KEYS.filter((k) => ((e.files as Record<string, string[] | undefined> | undefined)?.[k]?.length ?? 0) > 0).length;
  if (e.listener !== undefined) n++;
  if (e.duration_ms?.max !== undefined) n++;
  n += UPSTREAM_EXPECT_KEYS.filter((k) => (e.upstream as Record<string, unknown> | undefined)?.[k] !== undefined).length;
  n += (["matches", "not_matches"] as const).filter((k) => e.log?.[k] !== undefined).length;
  if (e.response?.max_bytes !== undefined) n++;
  return n;
}

interface Expansion {
  id: string;
  args: Record<string, unknown>;
  expect: RuleExpect | undefined;
  expanded: boolean;
}

// -- the validator ---------------------------------------------------------------------------------------------

/**
 * Check every probe against the tools the server offers and the safety rules. Collects all problems into one ConfigError.
 * Pure: nothing is called. Placeholders are expanded only to test paths (`files:`), and a database placeholder is allowed here
 * and answered at run time with an inconclusive probe, because custom probes get no database.
 *
 * A probe with `matrix` or `cases` becomes several planned probes (ids `id[k=v]`, `id#1`); each is validated on its own arguments and
 * all share the probe's `check`, so they fold into one check result.
 */
export function validateProbes(specs: readonly ProbeSpec[], input: PlanInput): ProbePlan {
  const problems: string[] = [];
  const reserved = new Set(input.reservedCheckIds ?? []);
  const probes: PlannedProbe[] = [];
  const metas = new Map<string, { meta: CheckMeta; at: number }>();
  const ids = new Map<string, number>();
  const expandedIds = new Set<string>();
  const toolByName = new Map(input.tools.map((t) => [t.name, t]));
  const classOf = new Map(input.classification.map((c) => [c.tool, c]));
  const fsObs = input.sandbox?.fs;

  specs.forEach((raw, i) => {
    const at = `probes[${i}]`;
    if (!isObject(raw)) {
      problems.push(`${at}: must be a mapping with at least a "tool"`);
      return;
    }
    const spec = raw as unknown as RuleProbeSpec;
    const r = raw as Record<string, unknown>;
    const mine: string[] = [];
    const bad = (m: string) => mine.push(`${at}${typeof r.id === "string" ? ` (${r.id})` : ""}: ${m}`);
    unknownKeys(r, PROBE_KEYS, at, mine);

    if (r.id !== undefined) {
      if (typeof r.id !== "string" || !r.id.trim()) bad('"id" must be a non-empty string');
      else if (ids.has(r.id)) bad(`duplicate probe id "${r.id}" (also probes[${ids.get(r.id)}])`);
      else ids.set(r.id, i);
    }

    // tool
    let tool: ToolInfo | undefined;
    if (typeof r.tool !== "string" || !r.tool) bad('"tool" is required and must be a tool name');
    else {
      tool = toolByName.get(r.tool);
      if (!tool) bad(`unknown tool "${r.tool}" (the server offers: ${[...toolByName.keys()].join(", ") || "no tools"}; a tool removed by tools.include or tools.exclude is not offered either)`);
    }

    // args
    let args: Record<string, unknown> = {};
    if (r.args !== undefined) {
      if (!isObject(r.args)) bad('"args" must be a mapping of argument names to values');
      else args = r.args;
    }
    const cls = tool ? classOf.get(tool.name) : undefined;

    // active, timeout
    if (r.active !== undefined && typeof r.active !== "boolean") bad('"active" must be true or false');
    if (r.timeout_ms !== undefined && !(typeof r.timeout_ms === "number" && Number.isInteger(r.timeout_ms) && r.timeout_ms >= 1)) bad('"timeout_ms" must be a positive integer');
    const runsCommands = cls?.class === "command" && !cls.excluded;
    if (runsCommands && r.active !== true) bad(`tool "${cls!.tool}" is classified as running commands; a probe against it must say \`active: true\` and runs only with --active`);

    // identity
    if (r.identity !== undefined) {
      if (!["a", "b", "none"].includes(r.identity as string)) bad('"identity" must be "a", "b" or "none"');
      else if (input.transport === "stdio") bad('identity needs an HTTP server whose headers use {bearer}: a stdio server has no per-caller credential, so remove "identity"');
    }

    // upstream.reply
    let replyMints = false;
    if (r.upstream !== undefined) {
      if (!isObject(r.upstream)) bad('"upstream" must be a mapping with a "reply"');
      else {
        unknownKeys(r.upstream, ["reply"], `${at}.upstream`, mine);
        if (r.upstream.reply === undefined) bad('"upstream" needs a "reply" (status, headers, body, json, bytes, delay_ms)');
        else {
          if (!input.upstream) bad(`upstream.reply needs the upstream stub: ${NO_STUB}`);
          replyMints = validateReply(r.upstream.reply, "upstream.reply", at, mine, bad);
        }
      }
    }

    // check metadata
    let check: CheckMeta | undefined;
    if (r.check !== undefined) {
      const c = r.check;
      if (!isObject(c)) bad('"check" must be a mapping with id, label and scope');
      else {
        unknownKeys(c, CHECK_KEYS, `${at}.check`, mine);
        const idOk = typeof c.id === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(c.id);
        if (!idOk) bad('check.id must be letters, digits, ".", "_" or "-" and start with a letter or digit');
        if (typeof c.label !== "string" || !c.label.trim()) bad("check.label is required");
        if (typeof c.scope !== "string" || !/^(server|database|environment)\b/.test(c.scope))
          bad(`check.scope must start with "server", "database" or "environment"${typeof c.scope === "string" ? `, got ${JSON.stringify(c.scope)}` : ""}`);
        if (c.critical !== undefined && typeof c.critical !== "boolean") bad("check.critical must be true or false");
        if (typeof r.id !== "string") bad('a probe with "check" needs an "id" so its result can be matched');
        if (idOk && typeof c.label === "string" && typeof c.scope === "string") {
          const id = c.id as string;
          if (reserved.has(id)) bad(`check id "${id}" belongs to a built-in check; choose another (custom ids such as "custom-${id}" are fine)`);
          const meta: CheckMeta = { id, label: c.label, critical: c.critical === true, scope: c.scope };
          const prev = metas.get(id);
          if (!prev) {
            metas.set(id, { meta, at: i });
            check = meta;
          } else {
            check = prev.meta;
            const diff = (["label", "critical", "scope"] as const).filter((k) => prev.meta[k] !== meta[k]);
            if (diff.length)
              bad(`check "${id}" is described differently in probes[${prev.at}] and here (${diff.join(", ")}); probes that share a check id must share its label, critical flag and scope`);
          }
        }
      }
    }

    // expect (the probe's own; a case's is validated with its case)
    const ectx: ExpectCtx = { at, bad, mine, input, fsObs, replyMints };
    if (r.expect !== undefined) validateExpect(r.expect, "expect", ectx);

    // placeholders that have no meaning in arguments
    for (const m of refusedPlaceholders(r.args)) bad(m);

    // matrix and cases: the list of concrete probes this entry stands for
    const base = typeof r.id === "string" ? r.id : tool ? `${tool.name}#${i + 1}` : at;
    const parentExpect = isObject(r.expect) ? (r.expect as RuleExpect) : undefined;
    const exps: Expansion[] = [];
    if (r.matrix !== undefined && r.cases !== undefined) bad('"matrix" and "cases" cannot be used together: use matrix for a cross-product of values and cases for an explicit list');
    else if (r.matrix !== undefined) {
      const m = r.matrix;
      if (!isObject(m) || !Object.keys(m).length) bad('"matrix" must be a mapping of argument names to lists of values');
      else {
        const props = tool?.inputSchema?.properties ?? {};
        const used = new Set([...JSON.stringify(args).matchAll(MATRIX_REF)].map((x) => x[1]!));
        let size = 1;
        let shapeOk = true;
        for (const [k, vals] of Object.entries(m)) {
          if (!Array.isArray(vals) || !vals.length || !vals.every(isScalar)) {
            bad(`matrix.${k} must be a non-empty list of strings, numbers or booleans`);
            shapeOk = false;
            continue;
          }
          size *= vals.length;
          if (tool && Object.keys(props).length && !(k in props)) bad(`matrix.${k} is not an argument of "${tool.name}" (it takes: ${Object.keys(props).join(", ")})`);
          if (!used.has(k)) bad(`matrix.${k} is never used: reference it as {matrix.${k}} in args`);
        }
        for (const u of used) if (!(u in m)) bad(`args use {matrix.${u}} but matrix has no "${u}" key`);
        if (shapeOk && size > MAX_EXPANSION) bad(`matrix expands to ${size} probes; the limit is ${MAX_EXPANSION}`);
        if (shapeOk && size <= MAX_EXPANSION) {
          const keys = Object.keys(m);
          let cells: Record<string, string | number | boolean>[] = [{}];
          for (const k of keys) cells = cells.flatMap((c) => (m[k] as (string | number | boolean)[]).map((v) => ({ ...c, [k]: v })));
          for (const cell of cells) exps.push({ id: `${base}[${keys.map((k) => `${k}=${String(cell[k])}`).join(",")}]`, args: expandMatrix(args, cell) as Record<string, unknown>, expect: parentExpect, expanded: true });
        }
      }
    } else if (r.cases !== undefined) {
      if (!Array.isArray(r.cases) || !r.cases.length) bad('"cases" must be a non-empty list of { id?, args?, expect? }');
      else {
        (r.cases as unknown[]).forEach((cs, n) => {
          const pfx = `cases[${n}]`;
          if (!isObject(cs)) return bad(`${pfx} must be a mapping with id, args and/or expect`);
          unknownKeys(cs, ["id", "args", "expect"], `${at}.${pfx}`, mine);
          if (cs.id !== undefined && (typeof cs.id !== "string" || !cs.id.trim())) bad(`${pfx}.id must be a non-empty string`);
          if (cs.args !== undefined && !isObject(cs.args)) bad(`${pfx}.args must be a mapping of argument names to values`);
          if (cs.expect === undefined && r.expect === undefined) bad(`${pfx} has no expect, and neither has the probe: a case needs an expect (its own, or the probe's)`);
          if (cs.expect !== undefined) validateExpect(cs.expect, `${pfx}.expect`, ectx);
          if (cs.args !== undefined) for (const m of refusedPlaceholders(cs.args)) bad(`${pfx}.${m}`);
          exps.push({
            id: typeof cs.id === "string" && cs.id.trim() ? cs.id : `${base}#${n + 1}`,
            args: { ...args, ...(isObject(cs.args) ? cs.args : {}) },
            expect: isObject(cs.expect) || parentExpect ? ({ ...(parentExpect ?? {}), ...(isObject(cs.expect) ? (cs.expect as RuleExpect) : {}) } as RuleExpect) : undefined,
            expanded: true,
          });
        });
      }
    } else {
      if (/\{matrix\./.test(JSON.stringify(args))) bad("args use {matrix.<name>} but the probe has no matrix");
      exps.push({ id: base, args, expect: parentExpect, expanded: false });
    }

    const planned: PlannedProbe[] = [];
    for (const x of exps) {
      const badx = (m: string) => (x.expanded ? mine.push(`${at} (${x.id}): ${m}`) : bad(m));
      if (x.expanded) {
        if (expandedIds.has(x.id) || ids.has(x.id)) badx(`duplicate probe id "${x.id}"`);
        expandedIds.add(x.id);
      }
      if (r.check !== undefined && isObject(r.check) && countClauses(x.expect) === 0) {
        badx('a probe with "check" needs an "expect" with at least one clause; without one it could never fail');
      }
      // literal targets
      if (isObject(r.args) || x.expanded) {
        for (const m of literalProblems(cls, x.args, Boolean(input.upstream))) badx(m);
        // An anchored argument is judged on what it expands to, not on how it starts: `{listener}@host/` is a URL for `host`,
        // `{sandbox}/..%2f..%2f` and `{sandbox}/....//` climb out of the sandbox in a server that decodes or strips.
        const sb = input.sandbox;
        const vars: Partial<ProbeVars> = { sandbox: sb?.root, sandbox_home: sb?.home, canary: sb?.canary, listener: sb?.listener?.url ?? "http://127.0.0.1:1" };
        const env: TargetEnv = { sandboxDir: sb?.dir, ports: portsOf(sb as Pick<Sandbox, "listener"> | undefined) };
        for (const [where, str] of strings(x.args)) {
          const why = unsafeTarget(str, expandString(str, vars, "tok"), env);
          if (why) badx(`${where}: ${JSON.stringify(str)}: ${why}`);
        }
      }
      // The schema check is advisory for custom checks (a probe may send wrong types on purpose) and fatal for plain valid calls.
      const schemaProblems = tool ? schemaProblemsOf(tool, x.args) : [];
      if (!r.check && schemaProblems.length && tool) badx(`the arguments do not match the schema of "${tool.name}": ${schemaProblems.join("; ")}. A probe without "check" exists to make a valid call`);
      if (tool) {
        const { matrix: _matrix, cases: _cases, ...rest } = spec;
        const spec2: RuleProbeSpec = x.expanded ? { ...rest, id: x.id, args: x.args, ...(x.expect ? { expect: x.expect } : {}) } : spec;
        planned.push({
          index: i,
          id: x.id,
          spec: spec2,
          tool,
          cls,
          ...(check ? { check } : {}),
          active: r.active === true,
          timeoutMs: typeof r.timeout_ms === "number" ? r.timeout_ms : (input.defaultTimeoutMs ?? 10_000),
          schemaProblems,
          usesDb: usesDbPlaceholder(x.args),
        });
      }
    }
    problems.push(...mine);
    // A probe with any problem leaves nothing behind (the ConfigError below carries the messages).
    if (!mine.length) probes.push(...planned);
  });

  if (problems.length) throw new ConfigError(problems);
  return { probes, checks: [...metas.values()].map((m) => m.meta) };
}

// ---------------------------------------------------------------------------------------------------------
// Running one probe
// ---------------------------------------------------------------------------------------------------------

export interface ClauseResult {
  clause: string;
  ok: boolean;
  detail: string;
  /** The clause could not be judged (nothing reached the stub, no log observer, nothing minted): not a fail, the probe is inconclusive. */
  unjudged?: boolean;
}

export interface ProbeOutcome {
  id: string;
  index: number;
  tool: string;
  checkId?: string;
  /** The arguments as written (placeholders unexpanded). */
  args: unknown;
  verdict: Verdict;
  /** Why the probe is na or inconclusive. */
  reason?: string;
  /** false when the arguments do not match the tool's schema: the call does not count toward coverage. */
  schemaValid: boolean;
  /** The call was made (and was neither dropped nor timed out). */
  called: boolean;
  isError?: boolean;
  timedOut?: boolean;
  elapsedMs?: number;
  excerpt?: string;
  /** Full response text, for callers that scan it (secret-echo). Not serialized into reports. */
  text?: string;
  clauses: ClauseResult[];
}

/** Replaces the harness's canary secrets with `<canary>` in text that goes into a report. */
export const maskCanaries =
  (canaries: readonly string[] | undefined) =>
  (text: string): string =>
    (canaries ?? []).reduce((t, c) => (c ? t.split(c).join("<canary>") : t), text);

export interface RunEnv {
  /** Applied to the response excerpt kept for the report (the full text is for scanning only). */
  mask?: (text: string) => string;
  /** Not needed for a probe that is skipped (na, or inconclusive before any call). */
  session?: McpSession;
  sandbox?: Sandbox;
  active: boolean;
  /** False when the server runs on another host: the harness's loopback listener (and `{listener}`) mean nothing to it. Default true. */
  listenerReachable?: boolean;
  /** The harness-owned upstream stub (`PackCtx.upstream`): `expect.upstream` and `upstream.reply` need it. */
  upstream?: RulesUpstream;
  /** The server's log (`PackCtx.serverLog`): `expect.log` needs it. */
  serverLog?: RulesLog;
  /** Opens a fresh session as identity `b` or anonymously (`PackCtx.identity.openAs`): `identity: b | none` needs it. */
  openAs?: RulesOpenAs;
}

const sleep =(ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const newToken = () => `sm-${randomBytes(6).toString("hex")}`;
const EXCERPT_BYTES = 4096;

const touches = (d: FsDiff, key: string) => [d.added, d.removed, d.changed].some((l) => l.some((k) => k === key || k.startsWith(`${key}/`)));

/** Run one planned probe and test its `expect:` clauses. Never throws for a server problem; that is a verdict. */
export async function runProbe(p: PlannedProbe, env: RunEnv): Promise<ProbeOutcome> {
  const base = {
    id: p.id,
    index: p.index,
    tool: p.tool.name,
    ...(p.check ? { checkId: p.check.id } : {}),
    args: p.spec.args ?? {},
    schemaValid: p.schemaProblems.length === 0,
    called: false,
    clauses: [] as ClauseResult[],
  };
  const skip = (verdict: Verdict, reason: string): ProbeOutcome => ({ ...base, verdict, reason });
  if (p.active && !env.active) return skip("na", "this probe is active and needs --active on the command line");
  if (p.usesDb) return skip("inconclusive", "the probe uses a database placeholder ({dsn}, {host}, ...), which custom probes cannot fill: the database belongs to the db pack");
  const needsSandbox =
    strings(p.spec.args ?? {}).some(([, s]) => HARNESS_PLACEHOLDER.test(s)) || Boolean(p.spec.expect?.files) || (p.spec.expect?.listener !== undefined && p.spec.expect.listener !== "any");
  const sb = env.sandbox;
  if (needsSandbox && !sb) return skip("inconclusive", "the probe needs the sandbox (a placeholder, files or listener expectation) and none is available");

  const usesListener = (p.spec.expect?.listener !== undefined && p.spec.expect.listener !== "any") || strings(p.spec.args ?? {}).some(([, s]) => s.includes("{listener}"));
  if (usesListener && env.listenerReachable === false) return skip("inconclusive", "the probe uses the harness's loopback listener, which a server on another host cannot reach");

  const wantsUpstream = Boolean(p.spec.expect?.upstream || p.spec.upstream?.reply);
  if (wantsUpstream && !env.upstream)
    return skip("inconclusive", "the probe needs the upstream stub, which is not running: set upstream.kind: http (or --upstream) and use {upstream} in the server config");
  const identity = p.spec.identity;
  if ((identity === "b" || identity === "none") && !env.openAs)
    return skip("inconclusive", `identity: ${identity} needs per-caller identities: use an HTTP server and write {bearer} in server.headers (for example Authorization: "Bearer {bearer}")`);

  const tok = newToken();
  const vars: Partial<ProbeVars> = sb ? probeVars(sb) : {};
  const args = expandValue(p.spec.args ?? {}, vars, tok) as Record<string, unknown>;
  // The last gate before anything is sent: the same rules as validation, on the real listener port and sandbox.
  {
    const written = strings(p.spec.args ?? {});
    const expandedStrings = strings(args);
    const tenv: TargetEnv = { sandboxDir: sb?.dir, ports: portsOf(sb) };
    for (let i = 0; i < written.length; i++) {
      const why = unsafeTarget(written[i]![1], expandedStrings[i]?.[1] ?? written[i]![1], tenv);
      if (why) return skip("inconclusive", `not sent: ${written[i]![0]}: ${why}`);
    }
  }
  const expect: RuleExpect = p.spec.expect ?? {};
  const wantsFiles = Boolean(expect.files && (expect.files.unchanged?.length || expect.files.created?.length || expect.files.absent?.length));
  const before: FsSnapshot | undefined = wantsFiles && sb ? await sb.fs.snapshot() : undefined;
  const listen0 = sb ? { req: sb.listener.requests().length, conn: sb.listener.connections().length } : undefined;

  // A probe as another caller gets its own session, closed after the call; the probe's own session is never reused for it.
  let session = env.session;
  let opened: McpSession | undefined;
  if (identity === "b" || identity === "none") {
    try {
      opened = await env.openAs!(identity === "none" ? null : "b");
    } catch (e) {
      return skip("inconclusive", `could not open a session as identity ${identity}: ${(e as Error).message.slice(0, 200)}`);
    }
    session = opened;
  }
  if (!session) throw new Error("runProbe needs a session to call the tool");
  const up = env.upstream;
  const mark = up?.mark();
  const logMark = env.serverLog?.mark();
  const reply = p.spec.upstream?.reply;
  // The probe's own token fills {token} in the scripted reply; {upstream_token} is left for the stub to mint, so it can say which rows it minted.
  if (reply && up) up.setOverride(expandValue(reply, {}, tok) as UpstreamReplySpec);
  let r: CallResult;
  try {
    r = await session.call(p.tool.name, args, p.timeoutMs);
  } finally {
    if (reply && up) up.setOverride(undefined);
    await opened?.close().catch(() => {});
  }
  const excerpt = (env.mask ?? ((t: string) => t))(r.text || r.rpcError || "").slice(0, EXCERPT_BYTES);
  const common = { ...base, isError: r.isError || r.rpcError !== undefined, timedOut: r.timedOut, elapsedMs: r.elapsedMs, excerpt, text: r.text || r.rpcError || "" };
  if (r.timedOut) return { ...common, verdict: "inconclusive", reason: `no reply within ${p.timeoutMs} ms` };
  if (r.closed) return { ...common, verdict: "inconclusive", reason: `the server went away during the call${r.rpcError ? ` (${r.rpcError.slice(0, 160)})` : ""}` };

  const clauses: ClauseResult[] = [];
  const add = (clause: string, ok: boolean, detail: string) => clauses.push({ clause, ok, detail });
  const answer = [r.text, r.rpcError].filter(Boolean).join("\n");
  if (expect.is_error !== undefined) {
    const got = r.isError || r.rpcError !== undefined;
    add("is_error", got === expect.is_error, `expected is_error ${expect.is_error}, the tool reported ${got ? "an error" : "success"}`);
  }
  if (expect.text?.matches !== undefined) {
    const re = new RegExp(expandString(expect.text.matches, {}, tok), "i");
    add("text.matches", re.test(answer), `expected the response to match /${expect.text.matches}/`);
  }
  if (expect.text?.not_matches !== undefined) {
    const re = new RegExp(expandString(expect.text.not_matches, {}, tok), "i");
    add("text.not_matches", !re.test(answer), `expected the response not to match /${expect.text.not_matches}/`);
  }
  if (expect.duration_ms?.max !== undefined) add("duration_ms.max", r.elapsedMs <= expect.duration_ms.max, `took ${r.elapsedMs} ms, limit ${expect.duration_ms.max} ms`);
  const wantsLog = Boolean(expect.log);
  if ((sb && (wantsFiles || (expect.listener !== undefined && expect.listener !== "any"))) || expect.upstream || wantsLog) await sleep(150);
  if (sb && wantsFiles && before) {
    const after = await sb.fs.snapshot();
    const d = sb.fs.diff(before, after);
    const keyOf = (path: string) => keyFor(sb.fs, expandString(path, vars, tok));
    for (const path of expect.files?.unchanged ?? []) {
      const key = keyOf(path);
      if (!key) add("files.unchanged", false, `${path} is outside the observed directories`);
      else if (!before[key] && !after[key]) add("files.unchanged", false, `${path} does not exist before or after the call (a wrong path would make this expectation pass vacuously)`);
      else add("files.unchanged", !touches(d, key), touches(d, key) ? `${path} was changed, added or removed` : `${path} unchanged`);
    }
    for (const path of expect.files?.created ?? []) {
      const key = keyOf(path);
      // An earlier call (core's invalid ones) can leave an empty file behind: a file that was there and whose content this call changed is written by it too.
      const added = Boolean(key && d.added.includes(key));
      const rewritten = Boolean(key && !added && before[key] && after[key] && d.changed.includes(key));
      add("files.created", added || rewritten, added ? `${path} was created` : rewritten ? `${path} existed and this call changed its content` : `${path} was not created`);
    }
    for (const path of expect.files?.absent ?? []) {
      const key = keyOf(path);
      add("files.absent", Boolean(key && !after[key]), key && !after[key] ? `${path} does not exist` : `${path} exists`);
    }
  }
  if (sb && listen0 && expect.listener !== undefined && expect.listener !== "any") {
    const req = sb.listener.requests().length - listen0.req;
    const conn = sb.listener.connections().length - listen0.conn;
    const seen = req + conn;
    add(
      "listener",
      expect.listener === "hit" ? seen > 0 : seen === 0,
      seen ? `the loopback listener saw ${req} request(s) and ${conn} connection(s) during the call` : "the loopback listener saw nothing during the call",
    );
  }
  const unjudged = (clause: string, detail: string) => clauses.push({ clause, ok: false, detail, unjudged: true });

  // -- what the stub saw ------------------------------------------------------------------------------------------
  const ux = expect.upstream;
  if (ux && up) {
    const seen = up.requests(mark);
    const rendered = seen.map((q) => `${q.method} ${q.path}${q.query}\n${Object.entries(q.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${q.body}`);
    const noRequest = "no request reached the upstream stub during the call, so there was nothing to judge";
    if (ux.requests !== undefined)
      add("upstream.requests", ux.requests === "none" ? seen.length === 0 : seen.length > 0, ux.requests === "none" ? (seen.length ? `expected no request to reach the upstream, ${seen.length} did: ${seen.slice(0, 3).map((q) => `${q.method} ${q.path}`).join(", ")}` : "no request reached the upstream") : seen.length ? `${seen.length} request(s) reached the upstream` : "expected a request to reach the upstream, none did");
    if (ux.none_matching !== undefined) {
      const re = new RegExp(expandString(ux.none_matching, {}, tok), "i");
      const hit = rendered.findIndex((t) => re.test(t));
      add("upstream.none_matching", hit < 0, hit < 0 ? `none of the ${seen.length} request(s) matched /${ux.none_matching}/` : `a request to the upstream matched /${ux.none_matching}/: ${seen[hit]!.method} ${seen[hit]!.path}${seen[hit]!.query}`);
    }
    if (ux.all_matching !== undefined) {
      const re = new RegExp(expandString(ux.all_matching, {}, tok), "i");
      if (!seen.length) unjudged("upstream.all_matching", `${noRequest} (all_matching would hold vacuously)`);
      else {
        const miss = rendered.findIndex((t) => !re.test(t));
        add("upstream.all_matching", miss < 0, miss < 0 ? `all ${seen.length} request(s) matched /${ux.all_matching}/` : `a request to the upstream did not match /${ux.all_matching}/: ${seen[miss]!.method} ${seen[miss]!.path}${seen[miss]!.query}`);
      }
    }
    for (const [name, want] of Object.entries(ux.header ?? {})) {
      const key = name.toLowerCase();
      if (!seen.length) {
        unjudged(`upstream.header.${key}`, `${noRequest} (header ${key} would hold vacuously)`);
        continue;
      }
      const wrong = seen.find((q) => {
        const v = q.headers[key];
        if (v === undefined) return true;
        if (want.equals !== undefined && v !== want.equals) return true;
        return want.matches !== undefined && !new RegExp(expandString(want.matches, {}, tok), "i").test(v);
      });
      add(`upstream.header.${key}`, !wrong, wrong ? `a request to the upstream ${wrong.headers[key] === undefined ? `had no ${key} header` : `had a ${key} header that does not match`} (${wrong.method} ${wrong.path})` : `every request carried the expected ${key} header`);
    }
    if (ux.token_echoed !== undefined) {
      const minted = seen.flatMap((q) => q.minted ?? []);
      if (!minted.length) unjudged("upstream.token_echoed", "the stub minted no {upstream_token} into a reply during the call (the server may not have reached it, or the reply holds no {upstream_token}), so token_echoed could not be judged");
      else {
        const echoed = minted.some((t) => answer.includes(t));
        add("upstream.token_echoed", echoed === ux.token_echoed, echoed ? "a value the upstream returned was echoed in the response" : "no value the upstream returned appears in the response");
      }
    }
  }
  if (expect.log) {
    const log = env.serverLog;
    for (const k of ["matches", "not_matches"] as const) {
      const re = expect.log[k];
      if (re === undefined) continue;
      if (!log || logMark === undefined) {
        unjudged(`log.${k}`, "there is no server log to read: the log is captured only for a server Sealmark starts (server.command with server.url, or over stdio)");
        continue;
      }
      const hit = new RegExp(expandString(re, {}, tok), "i").test(log.since(logMark));
      add(`log.${k}`, k === "matches" ? hit : !hit, k === "matches" ? (hit ? `the server log matched /${re}/` : `expected the server log to match /${re}/`) : hit ? `the server log matched /${re}/ during the call` : `the server log did not match /${re}/`);
    }
  }
  if (expect.response?.max_bytes !== undefined) {
    const bytes = Buffer.byteLength(answer, "utf8") + (r.blobs ?? []).reduce((n, b) => n + b.bytes, 0);
    add("response.max_bytes", bytes <= expect.response.max_bytes, `the response was ${bytes} byte(s), limit ${expect.response.max_bytes}`);
  }

  const hard = clauses.filter((c) => !c.ok && !c.unjudged);
  const soft = clauses.filter((c) => c.unjudged);
  if (!hard.length && soft.length) return { ...common, called: true, verdict: "inconclusive", reason: soft.map((c) => c.detail).join("; "), clauses };
  return { ...common, called: true, verdict: hard.length ? "fail" : "pass", clauses };
}

// ---------------------------------------------------------------------------------------------------------
// Valid calls (probes without `check`)
// ---------------------------------------------------------------------------------------------------------

/** A reply that says the tool's own request failed, in words the transport layer uses and that the vocabulary of FAILURE_VETO does not cover. */
const FETCH_FAILED = /\bfetch failed\b|\bfailed to fetch\b/i;

/**
 * True when a call that completed with an ordinary reply (no `isError`) says that the upstream request failed or declines in plain text
 * ("Error searching ...: TypeError: fetch failed"): a client cannot tell that from success, and it exercised no tool behaviour, so
 * it must not count toward coverage. Verdict-neutral: `badgeFor` never reads coverage.
 */
export function reportsFailedUpstream(o: { isError?: boolean; text?: string }): boolean {
  if (o.isError) return false;
  const said = head(o.text ?? "");
  return FAILURE_VETO.test(said) || FETCH_FAILED.test(said) || refusedInTextOnly({ isError: false, rpcError: undefined, text: o.text ?? "" });
}

export interface ProbeCall {
  id?: string;
  tool: string;
  args: unknown;
  isError: boolean;
  elapsedMs: number;
  excerpt: string;
  /** Schema-valid arguments, and the call completed. Such a response is scanned for internals whatever it said. */
  valid: boolean;
  /** Counted toward coverage: `valid`, and the tool did not answer with an error, and every `expect:` clause held. A rejected call exercised no tool behaviour. */
  counted: boolean;
  skipped?: string;
  /** `expect:` clauses that did not hold. These are warnings, never verdicts. */
  misses: string[];
}

export interface ValidCalls {
  calls: ProbeCall[];
  /** Full response text of every call, for the secret-echo scan. */
  seen: string[];
  /** Number of calls that count toward `RunResult.coverage.validCalls`: schema-valid, answered without an error, and every expectation held. */
  validCalls: number;
  /** Number of calls made with schema-valid arguments, whether or not they count toward coverage (`calls[].valid`). */
  schemaValidCalls: number;
  /** Tools reached with a schema-valid call. */
  tools: string[];
  /** Tools reached by a call that counts toward coverage. */
  countedTools: string[];
  warnings: string[];
}

/** True when a probe declares a check: those run in the custom pack. A probe without one is a plain valid call (coverage only). */
export const isCheckProbe = (p: unknown): boolean => Boolean(p && typeof p === "object" && (p as ProbeSpec).check !== undefined);
export const hasCheckProbes = (probes: readonly unknown[] | undefined): boolean => Boolean(probes?.some(isCheckProbe));

/**
 * The robust-input check counts every valid call it is handed (it also scans each response for stack traces, an error response
 * included), so the calls that do not count toward coverage are taken back out of its numbers here. A tool stays probed when
 * a call that counts reached it or when robust-input makes a valid call of its own (`ownValid`); a tool left without either is
 * listed as not covered, with the reason. The input is not modified.
 */
export function discountUncounted(coverage: CheckCoverage, v: ValidCalls, ownValid: (tool: string) => boolean): CheckCoverage {
  const uncounted = v.calls.filter((c) => c.valid && !c.counted);
  if (!uncounted.length) return coverage;
  const counted = new Set(v.countedTools);
  const drop = [...new Set(uncounted.map((c) => c.tool))].filter((t) => !counted.has(t) && !ownValid(t));
  return {
    ...coverage,
    probed: coverage.probed.filter((t) => !drop.includes(t)),
    notCovered: [...coverage.notCovered, ...drop.map((tool) => ({ tool, reason: "its only valid call returned an error, reported a failed upstream request or missed an expectation, so no tool behaviour was exercised" }))],
    ...(coverage.validCalls !== undefined ? { validCalls: Math.max(0, coverage.validCalls - uncounted.length) } : {}),
  };
}

export interface ValidCallsInput {
  /** The core session; the calls are made on it before robust-input. */
  session: McpSession;
  probes: readonly ProbeSpec[];
  tools: readonly ToolInfo[];
  classification: readonly ToolClassification[];
  sandbox?: Sandbox;
  active: boolean;
  defaultTimeoutMs?: number;
  /** Secret strings placed in the server's environment; they are masked in the excerpts kept for the report (the `seen` texts stay raw for the scan). */
  canaries?: readonly string[];
  listenerReachable?: boolean;
  /** Round 6 (the harness passes them as `RunEnv.upstream`, `serverLog` and `openAs`, seam S3): the stub, the server log and per-caller sessions. */
  upstream?: RulesUpstream;
  serverLog?: RulesLog;
  openAs?: RulesOpenAs;
  /** What `validateProbes` is told about the stub and the transport (see `planContext`). */
  plan?: Pick<PlanInput, "upstream" | "transport">;
}

/**
 * What `validateProbes` needs to know about the run, read from the effective configuration and the stub: whether the upstream stub is
 * declared (`upstream.kind`, or a stub that is running), whether it is scripted to mint `{upstream_token}`, and the server's transport.
 * A configuration built by hand may carry the raw tree (`value`) only.
 */
export function planContext(cfg: { server?: { url?: string }; upstream?: { kind?: string | null; responses?: unknown; default_reply?: unknown }; value?: Record<string, unknown> } | undefined, stub?: unknown): Pick<PlanInput, "upstream" | "transport"> {
  const raw = (cfg?.upstream ?? cfg?.value?.upstream) as { kind?: string | null; responses?: unknown; default_reply?: unknown } | undefined;
  const declared = raw?.kind === "http" || Boolean(stub);
  const transport = cfg?.server ? (cfg.server.url ? "http" : "stdio") : undefined;
  if (!declared) return { ...(transport ? { transport } : {}) };
  const mints = JSON.stringify([raw?.responses ?? [], raw?.default_reply ?? null]).includes(MINT);
  return { upstream: { kind: "http", mintsTokens: mints }, ...(transport ? { transport } : {}) };
}

/**
 * Make every probe that has no `check` once, as a valid call. All probes are validated first, so a mistake in any of them
 * (including custom checks) surfaces here, before anything is called.
 */
export async function runValidCalls(input: ValidCallsInput): Promise<ValidCalls> {
  const plan = validateProbes(input.probes, {
    tools: input.tools,
    classification: input.classification,
    sandbox: input.sandbox,
    defaultTimeoutMs: input.defaultTimeoutMs,
    ...(input.plan ?? (input.upstream ? { upstream: { kind: "http" as const } } : {})),
  });
  const out: ValidCalls = { calls: [], seen: [], validCalls: 0, schemaValidCalls: 0, tools: [], countedTools: [], warnings: [] };
  for (const p of plan.probes.filter((x) => !x.check)) {
    const o = await runProbe(p, {
      session: input.session,
      sandbox: input.sandbox,
      active: input.active,
      mask: maskCanaries(input.canaries),
      listenerReachable: input.listenerReachable,
      ...(input.upstream ? { upstream: input.upstream } : {}),
      ...(input.serverLog ? { serverLog: input.serverLog } : {}),
      ...(input.openAs ? { openAs: input.openAs } : {}),
    });
    const valid = o.called && o.schemaValid;
    const rejected = Boolean(o.isError);
    const missed = o.clauses.some((c) => !c.ok);
    const upstream = valid && !rejected && reportsFailedUpstream(o);
    const counted = valid && !rejected && !missed && !upstream;
    out.calls.push({
      ...(typeof p.spec.id === "string" ? { id: p.spec.id } : {}),
      tool: p.tool.name,
      args: o.args,
      isError: Boolean(o.isError),
      elapsedMs: o.elapsedMs ?? 0,
      excerpt: (o.excerpt ?? "").slice(0, EXCERPT_BYTES),
      valid,
      counted,
      ...(o.called ? {} : { skipped: o.reason }),
      misses: o.clauses.filter((c) => !c.ok).map((c) => c.detail),
    });
    if (o.text) out.seen.push(o.text);
    if (valid) {
      out.schemaValidCalls++;
      if (!out.tools.includes(p.tool.name)) out.tools.push(p.tool.name);
    }
    if (counted) {
      out.validCalls++;
      if (!out.countedTools.includes(p.tool.name)) out.countedTools.push(p.tool.name);
    } else if (valid) {
      out.warnings.push(
        rejected
          ? `probe ${p.id} returned an error and does not count toward coverage`
          : upstream
            ? `probe ${p.id}: the reply reports a failed upstream request and does not count toward coverage`
            : `probe ${p.id} did not hold its expectations and does not count toward coverage`,
      );
    }
    if (!o.called) out.warnings.push(`probe ${p.id} was not run: ${o.reason}`);
    for (const c of o.clauses.filter((x) => !x.ok)) out.warnings.push(`probe ${p.id} on "${p.tool.name}": ${c.detail}`);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------------------------------------

export interface CustomProbeRecord {
  id: string;
  check?: string;
  tool: string;
  args: unknown;
  verdict: string;
  outcome: string;
  excerpt?: string;
}

/**
 * Build `RunResult.probes` and `RunResult.custom` from the valid-call records and the custom pack's checks. The custom records are
 * read back from the evidence (`code` is `probe:<id>:<verdict>`), so nothing has to be passed between the pack and the caller.
 */
export function probesReport(o: { calls?: readonly ProbeCall[]; checks?: readonly CheckResult[] }): {
  probes: { calls: ProbeCall[]; custom: CustomProbeRecord[] };
  custom: { probes: CustomProbeRecord[] };
} {
  const custom: CustomProbeRecord[] = [];
  for (const c of o.checks ?? []) {
    if (c.pack !== "custom") continue;
    for (const e of c.evidence) {
      const m = /^probe:(.*):(pass|fail|inconclusive|na)$/s.exec(e.code ?? "");
      if (!m) continue;
      custom.push({ id: m[1], check: c.id, tool: e.tool ?? "", args: e.args, verdict: m[2], outcome: e.outcome, ...(e.excerpt ? { excerpt: e.excerpt } : {}) });
    }
  }
  return { probes: { calls: [...(o.calls ?? [])], custom }, custom: { probes: custom } };
}

// ---------------------------------------------------------------------------------------------------------
// The `custom` pack
// ---------------------------------------------------------------------------------------------------------

/** Custom check ids are chosen by the author, so there is nothing static to document. */
export function describe(): CheckDoc[] {
  return [];
}

const NO_CHECK_PROBES = "no probe declares a check: probes without `check` run as plain valid calls in the core session";

function fold3(outcomes: ProbeOutcome[]): { verdict: Verdict; summary: string } {
  const ran = outcomes.filter((o) => o.verdict === "pass" || o.verdict === "fail");
  const pass = ran.filter((o) => o.verdict === "pass").length;
  const fail = ran.length - pass;
  const unjudged = outcomes.length - ran.length;
  if (outcomes.every((o) => o.verdict === "na")) return { verdict: "na", summary: outcomes[0]?.reason ?? "not applicable" };
  if (!ran.length) return { verdict: "inconclusive", summary: `no probe could be judged: ${outcomes.map((o) => `${o.id}: ${o.reason}`).join("; ")}` };
  const tail = unjudged
    ? ` (${unjudged} of ${outcomes.length} probe(s) not judged: ${outcomes
        .filter((o) => !ran.includes(o))
        .map((o) => `${o.id}: ${o.reason}`)
        .join("; ")})`
    : "";
  if (fail === 0)
    return unjudged
      ? { verdict: "inconclusive", summary: `${pass} probe(s) passed, so a pass is not claimed${tail}` }
      : { verdict: "pass", summary: `${pass} of ${outcomes.length} probe(s) held every expectation` };
  const failed = ran
    .filter((o) => o.verdict === "fail")
    .map(
      (o) =>
        `${o.id}: ${o.clauses
          .filter((c) => !c.ok)
          .map((c) => c.detail)
          .join(", ")}`,
    );
  if (pass === 0) return { verdict: "fail", summary: `${fail} of ${outcomes.length} probe(s) failed: ${failed.join("; ")}${tail}` };
  return { verdict: "part", summary: `${pass} passed, ${fail} failed: ${failed.join("; ")}${tail}` };
}

function evidenceFor(p: PlannedProbe, o: ProbeOutcome): Evidence {
  const failed = o.clauses.filter((c) => !c.ok);
  const outcome =
    o.verdict === "pass"
      ? `held ${o.clauses.length} expectation(s): ${o.clauses.map((c) => c.clause).join(", ")}`
      : o.verdict === "fail"
        ? `failed: ${failed.map((c) => c.detail).join("; ")}`
        : `${o.verdict === "na" ? "not applicable" : "inconclusive"}: ${o.reason}`;
  const pool = failed.length ? failed : o.clauses;
  // "upstream" and "log" join the VerifiedBy union with types.ts (round 6, harness package): cast until it has merged.
  const verifiedBy = (pool.some((c) => c.clause.startsWith("files"))
    ? "fs-observer"
    : pool.some((c) => c.clause === "listener")
      ? "listener"
      : pool.some((c) => c.clause.startsWith("upstream"))
        ? "upstream"
        : pool.some((c) => c.clause.startsWith("log."))
          ? "log"
          : o.verdict === "na"
            ? "static"
            : "response") as Evidence["verifiedBy"];
  return {
    probe: `[${o.id}] ${p.tool.name} ${JSON.stringify(o.args)}`,
    outcome,
    verifiedBy,
    tool: p.tool.name,
    args: o.args,
    ...(o.excerpt ? { excerpt: o.excerpt } : {}),
    code: `probe:${o.id}:${o.verdict}`,
  };
}

/** Run all custom checks. Throws ConfigError for any invalid probe, before the first call. */
export async function runCustomProbes(ctx: PackCtx): Promise<CheckResult[]> {
  // Imported here, not at the top: the registry imports this module, and a static import would be circular.
  const { describeAll } = await import("./packs/index.js");
  const sandbox = ctx.sandbox;
  const r6: { upstream?: RulesUpstream; serverLog?: RulesLog; identity?: { openAs: RulesOpenAs } } = ctx;
  const plan = validateProbes(ctx.config.probes ?? [], {
    tools: ctx.tools,
    classification: ctx.classification,
    sandbox,
    reservedCheckIds: describeAll().map((d) => d.id),
    defaultTimeoutMs: ctx.config.timeouts?.probe_ms,
    ...planContext(ctx.config, r6.upstream),
  });
  const mine = plan.probes.filter((p) => p.check);
  if (!mine.length) return [];

  let session: McpSession | undefined;
  const results: CheckResult[] = [];
  const reachable = listenerReachable(ctx.config.server, ctx.config.env).ok;
  for (const meta of plan.checks) {
    const group = mine.filter((p) => p.check!.id === meta.id);
    const outcomes: ProbeOutcome[] = [];
    const cc = ctx.config.checks?.[meta.id];
    for (const p of group) {
      if (cc?.enabled === false) break;
      if ((p.active && !ctx.active) || p.usesDb) {
        outcomes.push(await runProbe(p, { sandbox, active: ctx.active, listenerReachable: reachable }));
        continue;
      }
      if (!session || session.closed) session = await ctx.open();
      outcomes.push(
        await runProbe(p, {
          session,
          sandbox,
          active: ctx.active,
          mask: maskCanaries(ctx.canaries),
          listenerReachable: reachable,
          ...(r6.upstream ? { upstream: r6.upstream } : {}),
          ...(r6.serverLog ? { serverLog: r6.serverLog } : {}),
          ...(r6.identity ? { openAs: r6.identity.openAs } : {}),
        }),
      );
    }
    let critical = meta.critical;
    let advisory = false;
    if (cc?.severity === "advisory") [critical, advisory] = [false, true];
    else if (cc?.severity === "critical") critical = true;
    else if (cc?.severity === "scored") critical = false;
    const base = { id: meta.id, pack: "custom" as const, label: meta.label, critical, ...(advisory ? { advisory: true } : {}), scope: meta.scope };
    if (cc?.enabled === false) {
      const origin = ctx.config.origins?.[`/checks/${meta.id}/enabled`];
      results.push({ ...base, verdict: "na", summary: `disabled by config${origin ? ` (${origin.source}${origin.line ? `:${origin.line}` : ""})` : ""}`, evidence: [] });
      continue;
    }
    const { verdict, summary } = fold3(outcomes);
    // A call counts when the tool did something with it: a reply that is an error, or reports a failed upstream request, exercised nothing.
    // (A call whose expectation did not hold stays counted: the tool answered, and the failed expectation is the verdict.)
    const valid = outcomes.filter((o) => o.called && o.schemaValid && !o.isError && !reportsFailedUpstream(o));
    results.push({
      ...base,
      verdict,
      summary,
      evidence: outcomes.map((o, i) => evidenceFor(group[i], o)),
      coverage: { probed: [...new Set(valid.map((o) => o.tool))], notCovered: [], validCalls: valid.length },
    });
  }
  return results;
}

export const pack: Pack = {
  id: "custom",
  describe,
  applies(ctx: PackCtx) {
    const specs = ctx.config?.probes;
    if (!specs || !hasCheckProbes(specs)) return { ok: false, reason: NO_CHECK_PROBES };
    // Surface mistakes before any pack runs. The built-in id collision check needs the registry and happens in run().
    if (ctx.tools && ctx.classification)
      validateProbes(specs, { tools: ctx.tools, classification: ctx.classification, sandbox: ctx.sandbox, defaultTimeoutMs: ctx.config.timeouts?.probe_ms, ...planContext(ctx.config, ctx.upstream) });
    return { ok: true };
  },
  run: runCustomProbes,
};
export default pack;

// ---------------------------------------------------------------------------------------------------------
// `sealmark init --probes`: one valid call per tool
// ---------------------------------------------------------------------------------------------------------

export const PROBES_FORMAT = "sealmark.probes/1";

/** One generated probe: a valid call, no `check`. */
export interface GeneratedProbe {
  tool: string;
  args: Record<string, unknown>;
  active?: true;
}
export interface SkippedProbe {
  tool: string;
  reason: string;
  /** The entry that would have been written, so the block can carry it commented out. */
  would?: GeneratedProbe;
}
export interface GenerateInput {
  tools: readonly ToolInfo[];
  classification: readonly ToolClassification[];
  /** `upstream.kind` is set: SQL probes are written. Without a stub the harness has no database to send SQL to. */
  upstream: boolean;
  /** `scope.tools` and `scope.allow` as configured: a scoped tool gets the first exact allowed identifier. */
  scope?: { tools: readonly { tool: string; param: string }[]; allow: readonly string[]; separator?: string };
  transport?: "stdio" | "http";
}
export interface GeneratedProbes {
  probes: GeneratedProbe[];
  skipped: SkippedProbe[];
}

const TOKEN = "sm-{token}";

/**
 * Builds the valid calls the harness can make with confidence, from the tool list alone: a target it owns for each kind of argument
 * ({sandbox}/ok.txt, {listener}/t/{token}, sm-echo, the first exact `scope.allow` identifier, `SELECT 1 AS sm_{token}`). A tool it cannot
 * fill, or must not call without being told (a no-argument tool that does not declare readOnlyHint), is listed in `skipped` with the reason.
 * Pure and deterministic: the same tools and configuration give the same list (sorted by tool name; placeholders stay unexpanded).
 * Every entry is accepted by `validateProbes` (an entry it refuses is moved to `skipped` with the validator's message).
 */
export function generateValidProbes(input: GenerateInput): GeneratedProbes {
  const classOf = new Map(input.classification.map((c) => [c.tool, c]));
  const scopeOf = new Map((input.scope?.tools ?? []).map((s) => [s.tool, s.param]));
  const sep = input.scope?.separator ?? ".";
  const exactAllowed = (input.scope?.allow ?? []).find((a) => a && !a.endsWith(sep));
  const probes: GeneratedProbe[] = [];
  const skipped: SkippedProbe[] = [];
  const roles: Partial<Record<import("./types.js").ParamRole, string | string[]>> = {
    path: "{sandbox}/ok.txt",
    paths: ["{sandbox}/ok.txt"],
    content: TOKEN,
    url: "{listener}/t/{token}",
    command: "sm-echo",
    args: [],
    dest: "{sandbox}/ok-dest.txt",
    text: TOKEN,
    message: TOKEN,
    sql: "SELECT 1 AS sm_{token}",
  };
  const skip = (tool: string, reason: string, would?: GeneratedProbe) => skipped.push({ tool, reason, ...(would ? { would } : {}) });

  // Writers first, deleters last, so {sandbox}/ok.txt exists when a reader or a deleter is called; ties by name (deterministic).
  const rank = (t: ToolInfo) => (classOf.get(t.name)?.params.content !== undefined ? 0 : /delet|remov|unlink|drop|rm$/i.test(t.name) ? 2 : 1);
  for (const t of [...input.tools].sort((a, b) => rank(a) - rank(b) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    const c = classOf.get(t.name);
    if (!c) {
      skip(t.name, "the tool was not classified");
      continue;
    }
    if (c.excluded) {
      skip(t.name, "excluded by tools.include or tools.exclude");
      continue;
    }
    const kind = c.confidence !== "low" || c.class === "command" || c.class === "sql" ? c.class : "text";
    const scoped = scopeOf.get(t.name);
    const props = Object.keys(t.inputSchema?.properties ?? {});
    let args: Record<string, unknown> | undefined;
    let active = false;
    if (kind === "git") {
      skip(t.name, "cannot fill: a git tool needs a repository the harness builds only when the server config names {sandbox}/repo; write the probe by hand");
      continue;
    }
    if (!props.length) {
      // Nothing to fill; call it only when the server says it changes nothing (the same rule the core pack's own valid call follows).
      if (variantsFor(t, true).variants.some((v) => v.valid)) args = {};
      else {
        skip(t.name, "cannot fill: the tool takes no arguments and does not declare readOnlyHint, so the harness will not call it unasked; add a probes: entry by hand once you know the call is safe", { tool: t.name, args: {} });
        continue;
      }
    } else {
      args = fillArgs(t, c, roles, TOKEN);
      if (args === undefined) {
        skip(t.name, `cannot fill: required parameter(s) ${c.unfillable.join(", ")} are not plain strings, numbers, booleans or one-level objects; write the probe by hand`);
        continue;
      }
      if (scoped !== undefined) {
        if (!exactAllowed) {
          skip(t.name, `scope.allow has no exact identifier for "${scoped}" (only prefixes ending in "${sep}", or none): list one identifier the server serves, then run this again`);
          continue;
        }
        args = { ...args, [scoped]: exactAllowed };
      }
      if (kind === "sql" && !input.upstream) {
        skip(t.name, "SQL is sent only to a stub the harness owns: set upstream.kind: http (flag --upstream), use {upstream} in the server config, then run this again", { tool: t.name, args });
        continue;
      }
      if (kind === "command") active = true;
    }
    const gen: GeneratedProbe = { tool: t.name, args, ...(active ? { active: true as const } : {}) };
    try {
      validateProbes([gen as unknown as ProbeSpec], { tools: input.tools, classification: input.classification, ...(input.upstream ? { upstream: { kind: "http" as const } } : {}), ...(input.transport ? { transport: input.transport } : {}) });
      probes.push(gen);
    } catch (e) {
      skip(t.name, `the probe validator refuses the generated call: ${(e as ConfigError).message.split("\n")[0]!.slice(0, 240)}`, gen);
    }
  }
  return { probes, skipped };
}

const KEY = /^[A-Za-z_][A-Za-z0-9_-]*$/;
/** A YAML flow value (JSON-compatible: strings are JSON-quoted). Deterministic. */
function flow(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(flow).join(", ")}]`;
  if (v && typeof v === "object") {
    const e = Object.entries(v as Record<string, unknown>);
    return e.length ? `{ ${e.map(([k, x]) => `${KEY.test(k) ? k : JSON.stringify(k)}: ${flow(x)}`).join(", ")} }` : "{}";
  }
  return JSON.stringify(v);
}
const entry = (p: GeneratedProbe): string => `{ tool: ${KEY.test(p.tool) ? p.tool : JSON.stringify(p.tool)}${p.active ? ", active: true" : ""}, args: ${flow(p.args)} }`;

/**
 * The `probes:` block for sealmark.yaml: a comment, then one flow-style entry per generated probe, then each skipped tool as a comment
 * with the reason. With nothing generated there is no `probes:` key (an empty list would stop --write from ever adding one).
 */
export function renderProbesBlock(g: GeneratedProbes): string {
  const lines = ["# Valid calls generated by `sealmark init --probes`. Each makes one call so the harness can see what the tool does with good input;", "# {sandbox}, {listener} and {token} are filled in at run time."];
  if (g.probes.length) lines.push("probes:", ...g.probes.map((p) => `  - ${entry(p)}`));
  for (const s of g.skipped) {
    lines.push(`# ${s.tool}: ${s.reason}`);
    if (s.would) lines.push(`#   - ${entry(s.would)}`);
  }
  return `${lines.join("\n")}\n`;
}

/** The JSON of `sealmark init --probes --json`. */
export function probesJson(g: GeneratedProbes): { format: typeof PROBES_FORMAT; probes: GeneratedProbe[]; skipped: { tool: string; reason: string }[] } {
  return { format: PROBES_FORMAT, probes: g.probes, skipped: g.skipped.map(({ tool, reason }) => ({ tool, reason })) };
}
