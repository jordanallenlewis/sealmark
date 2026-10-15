import type { McpSession, ToolInfo } from "./mcp.js";
import type { ConfigIntegrity, EffectiveConfig } from "./config/index.js";
import type { Sandbox } from "./sandbox.js";
import type { PgTarget, Role } from "./seed.js";

export type Verdict = "pass" | "part" | "fail" | "inconclusive" | "na";

/** Built-in pack ids. `plugin:<name>` ids come from `plugins:` in the config. */
export const BUILTIN_PACKS = ["core", "db", "fs", "net", "git", "exec", "http", "effects", "custom", "sqlite", "scope", "sql-guard", "upstream"] as const;
export type BuiltinPackId = (typeof BUILTIN_PACKS)[number];
export type PackId = BuiltinPackId | `plugin:${string}`;
/** Packs outside the standard that run when their declaration exists; scored, labelled, off the badge. */
export const CANDIDATE_PACKS: readonly PackId[] = ["scope", "sql-guard", "upstream"];
export type Letter = "A" | "B" | "C" | "D" | "F";

/**
 * How a verdict was established.
 * db-state: the harness read the database. fs-observer: before/after snapshot of the sandbox directories.
 * listener: the loopback listener saw (or did not see) the probe's token. process: the server's process tree.
 * http: a raw HTTP exchange with the server endpoint. response: the tool response text. protocol: MCP framing. static: metadata.
 * upstream: what the harness-owned upstream stub received. log: what the launched server printed.
 */
export type VerifiedBy = "db-state" | "response" | "protocol" | "static" | "fs-observer" | "listener" | "process" | "http" | "upstream" | "log";

// --- observers (round 6, the design notes) ------------------------------------------

/** A request the harness-owned upstream stub received. Header names lower-cased; body bounded by upstream.max_body_kib. */
export interface UpstreamRequest {
  /** 1-based, monotonic for the run. */
  id: number;
  /** Date.now() */
  at: number;
  method: string;
  /** Pathname only. */
  path: string;
  /** "" or "?a=b". */
  query: string;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  /** What the stub answered. ruleId names the upstream.responses entry (or "default", "mode:error", "mode:slow", "probe"). */
  reply: { status: number; bytes: number; ruleId: string; delayMs: number };
  /** Tokens the stub minted into this reply ({upstream_token} occurrences), so a pack can ask whether a reply row was echoed. */
  minted: string[];
}
/** The id of the last request at mark(). */
export type UpstreamMark = number;
export type UpstreamMode = "normal" | "error" | "slow";
export interface UpstreamReply {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  json?: unknown;
  bytes?: number;
  delay_ms?: number;
}

export interface UpstreamStub {
  readonly kind: "http";
  /** http://127.0.0.1:<port> (no trailing slash); the value of {upstream}. */
  readonly url: string;
  readonly port: number;
  /** The error canary the `error` mode writes into its body (sm-upstream-err-<hex>). */
  readonly errorCanary: string;
  mark(): UpstreamMark;
  requests(since?: UpstreamMark): UpstreamRequest[];
  /** Requests since the mark whose path, query, headers or body contain `needle` (case-insensitive). */
  find(needle: string, since?: UpstreamMark): UpstreamRequest[];
  /** Mode switch for the harness's own checks; reset to normal by the harness after each use. */
  setMode(mode: UpstreamMode, opts?: { delayMs?: number }): void;
  /** A reply used for every request until cleared (a probe's `upstream.reply`). */
  setOverride(reply: UpstreamReply | undefined): void;
  waitFor(needle: string, timeoutMs: number, since?: UpstreamMark): Promise<UpstreamRequest[]>;
  close(): Promise<void>;
}

/** A position in the log capture (characters since the capture began). */
export type LogMark = number;
export interface LogObserver {
  /** Where the text comes from: "launched" (stdout+stderr of the server Sealmark started) and/or "stderr" (stdio sessions). */
  readonly sources: ("launched" | "stderr")[];
  mark(): LogMark;
  /** Bounded: the capture keeps the last 1 MiB. */
  since(mark: LogMark): string;
  all(): string;
  /** First position of `needle` after the mark, or -1. */
  find(needle: string, since?: LogMark): number;
}

export type IdentityName = "a" | "b";
/** bearer: the value {bearer:<name>} expands to. */
export interface Identity {
  name: IdentityName;
  bearer: string;
}
export interface IdentityAccess {
  /** Always a and b. */
  identities: Identity[];
  /** A fresh session with {bearer} = that identity's value; `null` = anonymous: every header whose value holds {bearer} is dropped. */
  openAs(identity: IdentityName | null): Promise<McpSession>;
}

/** What the agent surface suggests adding to the configuration (produced by doctor and run, rendered by the report). */
export interface Suggestion {
  /** Stable, e.g. "scope:describe_table". */
  id: string;
  kind: "scope" | "sql-guard" | "upstream" | "identity" | "probes" | "sandbox";
  why: string;
  /** YAML to paste into sealmark.yaml. */
  config: string;
  /** The equivalent flags. */
  flags: string[];
  tools?: string[];
}

export interface Evidence {
  /** What was sent or inspected. */
  probe: string;
  /** What came back or was observed. */
  outcome: string;
  /** How the verdict was established. db-state means the harness checked the database directly. */
  verifiedBy: VerifiedBy;
  role?: string;
  tool?: string;
  /** Who enforced the control in a database check. */
  enforcedBy?: "server" | "database" | "unknown";
  /** The arguments sent, placeholders unexpanded (addendum 5, item 23). */
  args?: unknown;
  /** A longer response excerpt for JSON output, up to 4 KiB. */
  excerpt?: string;
  /** A stable machine-readable code for the observation, for example `fs.canary-read`. */
  code?: string;
}

/** Which tools a check exercised with a valid call, and which it could not (addendum 1.1). */
export interface CheckCoverage {
  probed: string[];
  notCovered: { tool: string; reason: string }[];
  /**
   * Valid calls made by this check. Defaults to `probed.length` when absent.
   *
   * The counting rule (every pack applies it in its own counter, and run.ts backstops it): a call counts when it was schema-valid AND the
   * server processed it. A control call counts only when it succeeded; an escape or policy probe counts when the tool's control
   * succeeded (its refusal is the behaviour under test) and the reply was not a validation error (JSON-RPC -32602, or an `isError`
   * reply that names a parameter and says invalid or expected); a `failed` network outcome never counts. A call that errored before the
   * tool did anything exercised nothing, so it must not lift a run above `hygiene-only`.
   */
  validCalls?: number;
  /** Per-tool outcome for checks that split outcomes (the `pii` check records denied, masked or leaked). */
  outcome?: string;
}

export interface CheckResult {
  id: string;
  pack: PackId;
  label: string;
  critical: boolean;
  /** Reported but not part of the grade. */
  advisory?: boolean;
  /** What the check actually measures, in one line. Starts with "server", "database" or "environment". */
  scope: string;
  verdict: Verdict;
  summary: string;
  evidence: Evidence[];
  coverage?: CheckCoverage;
  enforcedBy?: "server" | "database" | "unknown";
}

export interface PackGrade {
  pack: PackId;
  points: number;
  scored: number;
  pct: number;
  raw: Letter;
  letter: Letter;
  capped: boolean;
  criticalFails: string[];
  provisional: boolean;
  /** Checks excluded from the score (inconclusive or n/a). */
  excluded: string[];
}

export interface SqlTool {
  tool: string;
  arg: string;
  /** Added by the db pack's discovery (addendum 1.1). Absent means "unknown" for explicit config entries. */
  role?: "reader" | "writer" | "unknown";
  shape?: "string" | "array";
  approvalParam?: string;
  /** Scalar values for the tool's other required parameters (round 5, seam S10: written by the sql package, read defensively until the integrator removes the casts). */
  args?: Record<string, string | number | boolean>;
}

export interface ServerSpec {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  /** With command + url: seconds to wait for url to answer after starting command (default 60). */
  start_timeout_sec?: number;
  /** Files written inside the sandbox before the server starts (`server.files`). */
  files?: { path: string; content: string }[];
  /** The server takes no root argument: the fs pack treats its working directory ({sandbox}) as the allowed root (round 5, seam S10). */
  rootless?: boolean;
}

/** The legacy single-server view that the unchanged core/db code paths consume. config/ produces it from EffectiveConfig. */
export interface SealmarkConfig {
  name: string;
  version: string;
  server: ServerSpec;
  sql_tools?: SqlTool[];
  packs?: PackId[];
}

// ---------------------------------------------------------------------------------------------------------
// Classification. Produced by classify.ts, consumed by every pack.
// ---------------------------------------------------------------------------------------------------------

export type ToolClass = "sql" | "path" | "url" | "command" | "git" | "text" | "opaque";
export type Confidence = "high" | "medium" | "low" | "explicit";

/**
 * What a tool parameter is used for. Values in `ToolClassification.params` are parameter names of the tool.
 * The first block is the frozen set from the design; the rest are the secondary roles the design lists for git and
 * for two-path tools (`dest`).
 */
export type ParamRole =
  | "sql" | "path" | "paths" | "content" | "url" | "command" | "args" | "repo" | "text"
  | "dest" | "message" | "branch_name" | "target" | "revision" | "files";

export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/** What a tool offers an agent, reduced to hashes and types (report/drift.ts compares two of these). Descriptions are never stored: they are server-controlled text. */
export interface ToolSurface {
  name: string;
  title?: string;
  /** sha256 of the exact description text. */
  descriptionHash: string;
  descriptionLength: number;
  /** sha256 of the canonical JSON (sorted keys) of the input schema. */
  inputSchemaHash: string;
  /** Required parameter names, sorted. */
  required: string[];
  /** Parameter name to JSON type ("string", "string|null", "array<string>", "object", "unknown"). */
  params: Record<string, string>;
  annotations?: ToolAnnotations;
}

export interface ToolClassification {
  tool: string;
  class: ToolClass;
  confidence: Confidence;
  /** role -> the tool's parameter name that plays it. */
  params: Partial<Record<ParamRole, string>>;
  /** Required parameters the harness cannot fill (objects, arrays of objects, untyped). A pack probes the tool only when this is empty. */
  unfillable: string[];
  annotations?: ToolAnnotations;
  /** Human-readable evidence: `param "path"`, `name matches /read|file/`, `override: tools.overrides`. */
  reasons: string[];
  /** Other classes this tool matched at medium or higher; the primary class wins by specificity. */
  secondary?: ToolClass[];
  /** role -> parameter name for each secondary class (a path-primary tool with a `uri` parameter: `{ url: { url: "uri" } }`). Read by the pack of that class. */
  secondaryParams?: Partial<Record<ToolClass, Partial<Record<ParamRole, string>>>>;
  /** Command tools: one command string (shell) or a program plus an argument list (spawn). */
  style?: "shell" | "spawn";
  /** Where the class came from. */
  source?: "heuristic" | "override" | "sql_tools";
  /** True when `tools.include`/`tools.exclude` removed the tool from every pack except the hygiene checks. Class is `opaque`. */
  excluded?: boolean;
}

// ---------------------------------------------------------------------------------------------------------
// Sandbox and observers. The implementations live in sandbox.ts and observers/* (WP A2);
// their interfaces are the source of truth and are re-exported here so packs have one place to import from.
// ---------------------------------------------------------------------------------------------------------

export type { BinName, BinProgram, DestroyResult, LinkStatus, Sandbox, SandboxOptions } from "./sandbox.js";
export type { FsDiff, FsEntry, FsObserver, FsSnapshot } from "./observers/fs.js";
export type { ConnectionRecord, Listener, RequestRecord } from "./observers/listener.js";
export type { ProcInfo, ProcessObserver } from "./observers/process.js";

// ---------------------------------------------------------------------------------------------------------
// Configuration. config/ (WP E1) owns the real types.
// ---------------------------------------------------------------------------------------------------------

export type { ConfigIntegrity, EffectiveConfig, PluginSpec, ToolOverride } from "./config/index.js";

// ---------------------------------------------------------------------------------------------------------
// Packs. Frozen.
// ---------------------------------------------------------------------------------------------------------

export interface CheckDoc {
  id: string;
  pack: PackId;
  label: string;
  critical: boolean;
  advisory: boolean;
  /** Starts with "server", "database" or "environment". */
  scope: string;
  /** Every kind of verification this check can emit. */
  verifiedBy: VerifiedBy[];
  /** The published probe corpus. */
  probes: { id: string; text: string; core?: boolean; kind?: string }[];
  thresholds: Record<string, { default: number | string | boolean; configKey: string; standardLocked: boolean }>;
  falsePositive: string;
  falseNegative: string;
  /** Schema paths that affect this check. */
  configKeys: string[];
  /** Methodology version, e.g. "0.2-draft". */
  since: string;
  status: "shipped" | "planned" | "deprecated";
  /** For example db-rowcap.replaces = ["cap-timeout"]. */
  replaces?: string[];
}

/** Everything the database packs need that other packs do not. Present for `core` and `db` only. */
export interface DbAccess {
  target: PgTarget;
  /** Opens the server under test as one of the seeded roles. */
  openAs(role: Role): Promise<McpSession>;
}

export interface PackCtx {
  pack: PackId;
  config: EffectiveConfig;
  /** Tools as the server declared them, after `tools.include`/`tools.exclude`. */
  tools: ToolInfo[];
  classification: ToolClassification[];
  /** Set by run.ts on every run. Optional so tests can build a ctx without one. */
  sandbox?: Sandbox;
  /** false under --no-sandbox: the server was not confined, so the sandbox directories prove nothing and packs that watch them are na. The listener still works. */
  sandboxEnabled?: boolean;
  /** A fresh session on the server under test, started in the sandbox (cwd, scrubbed env). The harness closes it when the pack ends. */
  open(): Promise<McpSession>;
  active: boolean;
  timeoutProbeSec: number;
  hangMs: number;
  log(s: string): void;
  /** Checks produced by the packs that ran before this one (effects reads which tools they called). */
  prior?: readonly CheckResult[];
  /** Secret strings placed in the server's environment (core's secret-echo). */
  canaries?: string[];
  /** SQL tools the db pack probes. */
  sqlTools?: SqlTool[];
  /** Only for `core`/`db`. */
  db?: DbAccess;
  /** Set by run.ts: true once a signal stopped the run. A pack that cleans up after itself must not recreate files or start a server then. */
  interrupted?: () => boolean;
  /** The harness-owned upstream stub, when `upstream.kind` is set and the server spec uses {upstream}. */
  upstream?: UpstreamStub;
  /** The server's log, when Sealmark started the server (launched HTTP) or runs it over stdio (stderr). */
  serverLog?: LogObserver;
  /** Per-caller identities, when the server is HTTP and its headers use {bearer}. */
  identity?: IdentityAccess;
  /** The harness placeholder values of this run (sandbox, listener, upstream, bearer:a, bearer:b ...). Optional so hand-built contexts keep compiling; readers use `ctx.vars ?? {}`. */
  vars?: Record<string, string>;
}

/**
 * `kind` says whose fault a refusal is: `server` (default) is a property of the server under test (the pack does not apply to it: n/a),
 * `harness` is the harness's own environment (`node:sqlite` missing): the pack could not be judged, so it is recorded inconclusive and
 * a gate that fails on inconclusive notices.
 */
export type PackApplies = { ok: true } | { ok: false; reason: string; kind?: "server" | "harness" };

export interface Pack {
  id: PackId;
  describe(): CheckDoc[];
  applies(ctx: PackCtx): PackApplies;
  run(ctx: PackCtx): Promise<CheckResult[]>;
}

// ---------------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------------

export interface SandboxInfo {
  /** Absolute path as created; the report layer rewrites it to `{sandbox}` for display. */
  dir: string | null;
  envMode: "scrubbed" | "inherited";
  listenerPort: number | null;
  cleanedUp: boolean;
  /** Processes that survived the run (name and pid). */
  leftoverProcesses: string[];
  /** What the server inherited from the harness's environment (variable names and path classes, never values). Absent in reports written before 0.2.2. */
  inherited?: string[];
  active: boolean;
  /** false under --no-sandbox. */
  enabled: boolean;
  kept: boolean;
}

export type CoverageLevel = "hygiene-only" | "low" | "covered";

export interface RunResult {
  sealmark: { version: string; methodology: string };
  server: {
    name: string;
    version: string;
    command: string;
    /** true when Sealmark started the server itself (server.command + server.url). */
    launched?: boolean;
    env: Record<string, string>;
    transport: "stdio" | "http";
    tools: string[];
    /** The tool surface this run saw, for `--fail-on drift` and `sealmark diff`. Absent in reports written before 0.2.1. */
    surface?: ToolSurface[];
    sqlTools: SqlTool[];
    /** Addendum item 15: what the package manager actually resolved. */
    resolved?: { serverInfoVersion?: string; configVersion: string; package?: { name: string; version?: string; source: "npx-cache" | "uv-cache" | "npx-cache (ambiguous)" | "uv-cache (ambiguous)" | "not found"; candidates?: string[] }; dependencies?: Record<string, string> };
  };
  db?: { mode: "embedded" | "external"; seed: string; roles: string[]; timeoutProbeSec: number };
  options: { packsRequested: PackId[]; timeoutProbeSec: number; active?: boolean; sandbox?: boolean };
  startedAt: string;
  durationMs: number;
  packs: Partial<Record<PackId, { status: "graded" | "na" | "inconclusive"; reason?: string; grade?: PackGrade }>>;
  checks: CheckResult[];
  notCovered: string[];
  /** One entry per tool, after overrides. */
  classification?: ToolClassification[];
  sandbox?: SandboxInfo;
  /** The configuration identity of this run (section 6.8). `standard: false` means the grade is custom. */
  config?: ConfigIntegrity & { path?: string; line?: number };
  /** How much of the tool surface a valid call reached (addendum 1.4). */
  coverage?: { validCalls: number; toolsCalledValid: number; toolsTotal: number; level: CoverageLevel };
  badge?: { eligible: boolean; reason?: string };
  warnings?: string[];
  /** Custom probe results (section 4); filled by the custom pack's owner. */
  custom?: { probes: unknown[] };
  probes?: { calls: unknown[]; custom: unknown[] };
  /** The upstream stub of this run (kind http only). `url` is printed as "{upstream}" under redaction. */
  upstream?: { kind: "http"; requests: number; scripted: number; url: string };
  /** Which identities the run used; names only, never values. */
  identities?: { names: IdentityName[]; source: "minted" | "config" };
  /** What to add to the configuration, re-evaluated after the run. */
  suggestions?: Suggestion[];
  /** Set only when the run failed before grading (addendum item 19). */
  status?: "ok" | "failed";
  /** True when a signal (Ctrl-C, SIGTERM, SIGHUP) arrived during the run: the report may be incomplete and the exit code is the signal's. */
  interrupted?: boolean;
}
