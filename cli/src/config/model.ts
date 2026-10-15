import type { ServerSpec, SqlTool } from "../types.js";

/** Printed in every report header and folded into the config hash. Bump with the methodology. */
export const METHODOLOGY = "0.3-draft";
/** The newest config file layout this binary understands. */
export const SCHEMA_VERSION = 1;

/** Bad configuration, flag or environment value. The CLI exits 2. `issues` has one entry per problem; `message` joins them. */
export class ConfigError extends Error {
  readonly issues: string[];
  constructor(message: string | string[]) {
    const issues = Array.isArray(message) ? message : [message];
    super(issues.join("\n"));
    this.issues = issues;
  }
}

export type LayerKind = "default" | "profile" | "user" | "project" | "local" | "env" | "flag" | "replay";

/** Where an effective value came from. `source` is display text: `sealmark.yaml`, `profile:standard`, `env SEALMARK_X`, `flag --timeout-probe`, `default`. */
export interface Origin {
  layer: LayerKind;
  source: string;
  line?: number;
}

export type Severity = "critical" | "scored" | "advisory";

export interface CheckConfig {
  enabled: boolean;
  /** null keeps the check's own severity. */
  severity: Severity | null;
  corpus?: { add: unknown[]; remove: string[] };
  row_cap?: number;
  expected_sec?: number | null;
  slow_sql?: string | null;
  hang_ms?: number | null;
  max_tools?: number;
  file_mib?: number;
  pass_mib?: number;
  /** checks.sql-guard-statements.control_sql */
  control_sql?: string | null;
  /** checks.refusal-quality.patterns (regular expressions) */
  patterns?: string[];
  /** checks.instructions-hygiene.deny (regular expressions) */
  deny?: string[];
  [key: string]: unknown;
}

export interface ToolOverride {
  class: "sql" | "path" | "url" | "command" | "git" | "text" | "opaque";
  params?: Record<string, string>;
}

export interface PluginSpec {
  module: string;
  options?: Record<string, unknown>;
}

/** A scripted reply of the upstream stub: exactly one of body, json or bytes (bytes may carry body as its prefix). Same fields as `UpstreamReply` in types.ts. */
export interface UpstreamReplySpec {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  json?: unknown;
  bytes?: number;
  delay_ms?: number;
}

/** One `upstream.responses` entry. Every given `match` part must hold; no `match` answers every request. */
export interface UpstreamResponseRule {
  id?: string;
  match?: { method?: string; path?: string; body?: string; header?: Record<string, string> };
  reply: UpstreamReplySpec;
}

/** `EffectiveConfig.upstream`: the `upstream:` section as written (snake_case keys, defaults applied). */
export interface UpstreamSettings {
  kind: "http" | null;
  responses: UpstreamResponseRule[];
  default_reply: UpstreamReplySpec;
  /** As written; the consumer lower-cases it. */
  credential_header: string;
  max_body_kib: number;
}

/** `EffectiveConfig.scope`: the `scope:` section as written. */
export interface ScopeSettings {
  tools: { tool: string; param: string }[];
  allow: string[];
  deny: string[];
  separator: string;
  case: "sensitive" | "insensitive";
}

/**
 * `EffectiveConfig.identities`: the tokens the harness sends as callers A and B. `${VAR}` references are already read from the
 * environment here, so a consumer uses the value as it is. null means "mint one for the run". Never printed: the values are secrets.
 */
export interface IdentitySettings {
  a: string | null;
  b: string | null;
}

export interface ProbeExpect {
  is_error?: boolean;
  text?: { matches?: string; not_matches?: string };
  files?: { unchanged?: string[]; created?: string[]; absent?: string[] };
  listener?: "none" | "hit" | "any";
  duration_ms?: { max?: number };
  /** Round 6: what the upstream stub saw while this probe ran. */
  upstream?: {
    requests?: "none" | "any";
    none_matching?: string;
    all_matching?: string;
    header?: Record<string, { equals?: string; matches?: string }>;
    token_echoed?: boolean;
  };
  /** Round 6: what the server printed while this probe ran. */
  log?: { matches?: string; not_matches?: string };
  /** Round 6: size of the reply. */
  response?: { max_bytes?: number };
}

export interface ProbeSpec {
  id?: string;
  check?: { id: string; label: string; critical?: boolean; scope?: string };
  tool: string;
  args?: Record<string, unknown>;
  active?: boolean;
  timeout_ms?: number;
  /** Round 6: which harness identity opens the session for this probe (default: the session's own headers). */
  identity?: "a" | "b" | "none";
  /** Round 6: cross-product expansion; every `args` value may reference `{matrix.<name>}`. Exclusive with `cases`. */
  matrix?: Record<string, (string | number | boolean)[]>;
  /** Round 6: explicit expansion; each case merges its `args` and `expect` over the probe's. Exclusive with `matrix`. */
  cases?: { id?: string; args?: Record<string, unknown>; expect?: ProbeExpect }[];
  /** Round 6: a scripted upstream reply for the duration of the probe. */
  upstream?: { reply: UpstreamReplySpec };
  expect?: ProbeExpect;
}

export interface DiffEntry {
  path: string;
  standard: unknown;
  effective: unknown;
  /** Display text of where the effective value came from. */
  origin: string;
}

/** What `RunResult.config` carries (section 6.8). `locked` is flat: dotted schema path to value, plus `packs`. */
export interface ConfigIntegrity {
  hash: string;
  profile: string;
  standard: boolean;
  standardDiff: DiffEntry[];
  methodology: string;
  schemaVersion: number;
  locked: Record<string, unknown>;
}

export interface SandboxSettings {
  enabled: boolean;
  dir: string | null;
  keep: boolean;
  scrub_env: boolean;
  keep_env: string[];
  pack_timeout_sec: number;
  max_mib: number;
}

export interface OutputSettings {
  format: "text" | "json" | "markdown" | "junit" | "sarif" | "summary" | "badge" | "shields";
  formats: string[];
  out: string | null;
  out_dir: string | null;
  verbosity: "quiet" | "normal" | "verbose";
  redact: boolean;
  template: string | null;
  baseline: string | null;
  write_baseline: string | null;
  fail_on: ("any" | "regressions" | "drift")[];
  exit_policy: {
    fail_under: "A" | "B" | "C" | "D" | "F" | null;
    regressions_only: boolean;
    soft_fail: boolean;
    treat_inconclusive_as: "pass" | "fail";
    critical_fail: number;
  };
}

export interface NamedServer {
  name: string;
  spec: ServerSpec;
}

/**
 * The one typed object everything outside config/ receives. Fully defaulted; `origins` and `integrity` attached.
 * Nothing outside config/ reads YAML or the process environment.
 */
export interface EffectiveConfig {
  schemaVersion: number;
  name: string;
  version: string;
  /** Name of the selected profile. */
  profile: string;
  /** Names along the resolved profile chain, base first. */
  profileChain: string[];
  /** First selected server (what single-server code paths use). */
  server: ServerSpec;
  /** Servers selected for this run (`run.server`), in declaration order. One entry for a plain `server:`. */
  servers: NamedServer[];
  /** Every declared server name. */
  serverNames: string[];
  sqlTools?: SqlTool[];
  packs: string[];
  /** True when a flag, env var, file or non-standard profile chose the packs rather than the defaults. */
  packsExplicit: boolean;
  /** Seconds the cap/timeout probes wait. */
  timeoutProbeSec: number;
  /** robust-input hang threshold in ms: checks.robust-input.hang_ms, else max(2000, timeoutProbeSec * 1000). */
  hangMs: number;
  checks: Record<string, CheckConfig>;
  sandbox: SandboxSettings;
  tools: { include: string[]; exclude: string[]; overrides: Record<string, ToolOverride> };
  timeouts: { connect_ms: number; call_ms: number; probe_ms: number };
  retries: { call: number };
  net: { control_url: string | null; allow_dns: boolean };
  output: OutputSettings;
  plugins: PluginSpec[];
  probes: ProbeSpec[];
  sqlite: { engine: "sqlite" | "duckdb" | null };
  db: { embedded: boolean | null; pg: string | null };
  /** Round 6: the upstream stub declaration. `kind: null` means no stub. Always set by loadEffectiveConfig; optional in the type so a hand-built config (run.ts replay, tests) keeps compiling. */
  upstream?: UpstreamSettings;
  /** Round 6: the declared scope (identifier allow list) the scope pack tests. Empty `tools` means none declared. */
  scope?: ScopeSettings;
  /** Round 6: caller A and B tokens for `{bearer:a}` / `{bearer:b}`; null = mint per run. Secrets: never print them. */
  identities?: IdentitySettings;
  notCoveredExtra: string[];
  /** Safety flags: only ever true when given on the command line. */
  active: boolean;
  yes: boolean;
  /** The complete merged tree (defaults included). Same data as the fields above, in file shape. */
  value: Record<string, unknown>;
  /** Origin of every leaf, keyed by JSON pointer (`/checks/db-rowcap/row_cap`). */
  origins: Record<string, Origin>;
  integrity: ConfigIntegrity;
  warnings: string[];
  /** Files that were read, in layer order. */
  files: string[];
  /** The environment snapshot passed to the loader, for `${VAR}` references in server specs. */
  env: Record<string, string | undefined>;
  cwd: string;
  /** Project config path actually used, if any. */
  configPath?: string;
}
