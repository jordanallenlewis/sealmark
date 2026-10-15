import { METHODOLOGY, SCHEMA_VERSION } from "./model.js";
import { deepClone, didYouMean } from "./util.js";
import {
  CONTROL_SQL_SHAPE,
  PLUGIN_SHAPE,
  PROBES_SHAPE,
  SCOPE_TOOL_SHAPE,
  SQL_TOOL_SHAPE,
  STAGED_FILES_SHAPE,
  TOOL_OVERRIDE_SHAPE,
  UPSTREAM_REPLY_SHAPE,
  UPSTREAM_RESPONSE_SHAPE,
  bool,
  corpusAddShape,
  regexList,
  shapeToJsonSchema,
  str,
  strCoerced,
  strings,
  type Problem,
  type Shape,
} from "./validators.js";

/**
 * The single schema table. Defaults, validation, env/flag typing, `config show`, the integrity model and the
 * generated JSON Schema (cli/schema/sealmark.schema.json) all derive from `SCHEMA`.
 *
 * Maintainer rules: a new setting needs a default that preserves previous behavior,
 * a `since`, and a description. A setting that affects a grade must set `standardLocked: true`. Renames go
 * through a `deprecated` alias that still works and warns for one major version.
 */

export type LeafType = "string" | "integer" | "number" | "boolean" | "enum" | "string[]" | "stringMap" | "list" | "object";

export interface Leaf {
  /** Dotted path. A `*` segment matches any key (servers.*.command). */
  path: string;
  type: LeafType;
  /** undefined means "no default: absent unless set". null is a real default. */
  default?: unknown;
  /** What the setting does when absent, for documentation only (describe, the JSON Schema). It is not a default: the key stays unset. */
  documentedDefault?: unknown;
  description: string;
  /** Methodology/CLI version that introduced the setting. */
  since: string;
  shape: Shape;
  nullable?: boolean;
  /** Affects a grade: any difference from the standard profile makes the run CUSTOM. */
  standardLocked?: boolean;
  /** List that appends and de-duplicates across layers instead of replacing. */
  mergeable?: boolean;
  /** Never printed; redacted in `config show` and reports. */
  secret?: boolean;
  /** Only the command line may set it (never files or environment). */
  flagOnly?: boolean;
  /** A renamed setting kept working for one major: its value moves to each `to` path with a warning. */
  deprecated?: { to: string[] };
  /** Not allowed inside a profile body (project-specific). */
  profileForbidden?: boolean;
  enum?: readonly string[];
}

export const S01 = "0.1-draft";
export const S02 = "0.2-draft";
export const S03 = "0.3-draft";

export const PACK_IDS = ["core", "db", "sqlite", "fs", "net", "git", "exec", "http", "effects", "custom", "scope", "sql-guard", "upstream"] as const;
/** Packs the published standard profile runs. `exec` is opt-in (adding a pack is allowed, removing one is not). `custom` runs when probes are written. */
export const STANDARD_PACKS = ["core", "db", "sqlite", "fs", "net", "git", "http", "effects"];

const LETTERS = ["A", "B", "C", "D", "F"] as const;

interface CheckDef {
  id: string;
  pack: string;
  since: string;
  corpus?: boolean;
  /**
   * Shipped advisory ahead of the standard (0.3-draft candidate). Its enabled/severity leaves are not locked and it has no corpus
   * leaves, so adding it cannot change the standard hash; integrity.ts makes disabling or scoring it CUSTOM instead.
   */
  candidate?: boolean;
}

/** Every check id the configuration can address. Packs own the behaviour; the config only needs the ids. */
export const CHECKS: CheckDef[] = [
  { id: "protocol", pack: "core", since: S01 },
  { id: "tool-poisoning", pack: "core", since: S01 },
  { id: "robust-input", pack: "core", since: S01 },
  { id: "secret-echo", pack: "core", since: S01 },
  { id: "read-only", pack: "db", since: S01 },
  { id: "write-gate", pack: "db", since: S01 },
  { id: "rls", pack: "db", since: S01 },
  { id: "mutating-sql", pack: "db", since: S01, corpus: true },
  { id: "pii", pack: "db", since: S01 },
  { id: "pii-masked", pack: "db", since: S02 },
  { id: "audit", pack: "db", since: S01 },
  { id: "db-privilege", pack: "db", since: S03, candidate: true },
  { id: "db-rowcap", pack: "db", since: S02 },
  { id: "db-timeout", pack: "db", since: S02 },
  { id: "sqlite-read-only", pack: "sqlite", since: S02 },
  { id: "sqlite-mutating-sql", pack: "sqlite", since: S02, corpus: true },
  { id: "sqlite-file-read", pack: "sqlite", since: S02, corpus: true },
  { id: "sqlite-file-write", pack: "sqlite", since: S02, corpus: true },
  { id: "sqlite-extension-load", pack: "sqlite", since: S02, corpus: true },
  { id: "sqlite-rowcap", pack: "sqlite", since: S02 },
  { id: "sqlite-timeout", pack: "sqlite", since: S02 },
  { id: "fs-read-escape", pack: "fs", since: S02, corpus: true },
  { id: "fs-write-escape", pack: "fs", since: S02, corpus: true },
  { id: "fs-link-escape", pack: "fs", since: S02, corpus: true },
  { id: "fs-size-cap", pack: "fs", since: S02 },
  { id: "net-loopback-ssrf", pack: "net", since: S02, corpus: true },
  { id: "net-scheme-allowlist", pack: "net", since: S02, corpus: true },
  { id: "net-caps", pack: "net", since: S02 },
  { id: "net-redirect", pack: "net", since: S02 },
  { id: "git-repo-scope", pack: "git", since: S02, corpus: true },
  { id: "git-arg-injection", pack: "git", since: S02, corpus: true },
  { id: "exec-injection", pack: "exec", since: S02, corpus: true },
  { id: "exec-cwd", pack: "exec", since: S02 },
  { id: "exec-timeout-cap", pack: "exec", since: S02 },
  { id: "exec-allowlist", pack: "exec", since: S02 },
  { id: "http-origin", pack: "http", since: S02 },
  { id: "http-auth", pack: "http", since: S02 },
  { id: "http-protocol-version", pack: "http", since: S02 },
  { id: "http-session", pack: "http", since: S02 },
  { id: "http-cors", pack: "http", since: S02 },
  { id: "http-bind", pack: "http", since: S02 },
  { id: "http-tls", pack: "http", since: S02 },
  { id: "annotation-honesty", pack: "effects", since: S02 },
  { id: "openworld-honesty", pack: "effects", since: S02 },
  { id: "undeclared-writes", pack: "effects", since: S02 },
  // Round 6 candidates: checks of the candidate packs scope, sql-guard and upstream, and two advisory core checks. Unlocked (see CheckDef.candidate).
  { id: "refusal-quality", pack: "core", since: S03, candidate: true },
  { id: "instructions-hygiene", pack: "core", since: S03, candidate: true },
  { id: "scope-escape", pack: "scope", since: S03, candidate: true },
  { id: "sql-guard-statements", pack: "sql-guard", since: S03, candidate: true },
  { id: "sql-guard-references", pack: "sql-guard", since: S03, candidate: true },
  { id: "sql-guard-rowcap", pack: "sql-guard", since: S03, candidate: true },
  { id: "upstream-credential", pack: "upstream", since: S03, candidate: true },
  { id: "upstream-credential-echo", pack: "upstream", since: S03, candidate: true },
  { id: "log-secret", pack: "upstream", since: S03, candidate: true },
  { id: "upstream-error-leak", pack: "upstream", since: S03, candidate: true },
  { id: "upstream-slow", pack: "upstream", since: S03, candidate: true },
];

/** Words a refusal may carry to count as routing the caller somewhere (checks.refusal-quality.patterns default; design section 3.7). */
export const REFUSAL_ROUTING_PATTERNS = ["instead", "use (the )?[a-z_]+ tool", "available", "allowed", "try", "list_[a-z]+", "contact", "will not (help|succeed)", "permanent", "not retry"];

function packsShape(): Shape {
  const known: readonly string[] = PACK_IDS;
  return {
    k: "custom",
    base: { k: "array", item: { k: "string", nonEmpty: true } },
    check: (v: unknown, path, out: Problem[]) => {
      (v as string[]).forEach((p, i) => {
        if (known.includes(p) || /^plugin:.+/.test(p)) return;
        const hint = didYouMean(p, known);
        out.push({ path: [...path, i], message: `unknown pack "${p}" (use ${known.join(", ")})${hint ? `; did you mean "${hint}"?` : ""}` });
      });
    },
  };
}

type ShapeOpts = { min?: number; max?: number; exclusiveMin?: boolean; coerce?: boolean };
type LeafOpts = Partial<Leaf> & ShapeOpts & { since?: string };

const L = (path: string, type: LeafType, dflt: unknown, description: string, o: LeafOpts = {}): Leaf => {
  const shape = o.shape ?? shapeFor(type, o);
  return { path, type, default: dflt, description, since: o.since ?? S02, shape, ...stripShapeOpts(o) };
};

function shapeFor(type: LeafType, o: LeafOpts): Shape {
  switch (type) {
    case "string":
      return { k: "string", ...(o.coerce ? { coerce: true } : {}) };
    case "integer":
      return { k: "int", min: o.min, max: o.max };
    case "number":
      return { k: "num", min: o.min, max: o.max, exclusiveMin: o.exclusiveMin };
    case "boolean":
      return bool;
    case "enum":
      return { k: "enum", values: o.enum ?? [] };
    case "string[]":
      return o.coerce ? { k: "array", item: strCoerced } : strings;
    case "stringMap":
      return { k: "map", value: strCoerced };
    default:
      return { k: "any" };
  }
}

function stripShapeOpts(o: LeafOpts): Partial<Leaf> {
  const { min: _min, max: _max, exclusiveMin: _e, coerce: _c, since: _s, shape: _sh, ...rest } = o;
  return rest;
}

const locked = { standardLocked: true } as const;
const SEVERITIES = ["critical", "scored", "advisory"] as const;
const FORMATS = ["text", "json", "markdown", "junit", "sarif", "summary", "badge", "shields"] as const;
const FAIL_ON = ["any", "regressions", "drift"] as const;

function build(): Leaf[] {
  const out: Leaf[] = [];
  const add = (...l: Leaf[]) => out.push(...l);

  add(
    L("schema_version", "integer", SCHEMA_VERSION, "Config file layout version. Required in project files (a missing field is read as 1 with a warning). `sealmark config migrate` upgrades older files.", { since: S02, min: 0 }),
    L("name", "string", "my-server", "Display name of the server under test. When not set, it is taken from the server's command (or the host of its url); `my-server` is only the fallback.", { since: S01, shape: { k: "string", coerce: true, nonEmpty: true } }),
    L("version", "string", "0.0.0", "Version of the server under test as you know it (reported next to the version the server announces).", { since: S01, coerce: true }),
    L("profile", "string", "standard", "Profile to start from: standard, quick, ci, strict, paranoid, or a name defined under `profiles`.", { shape: { k: "string", nonEmpty: true } }),
    L("profiles", "object", undefined, "User-defined profiles: a name maps to a partial config with an optional `extends`. Project-level settings such as server cannot appear inside a profile.", { shape: { k: "map", value: { k: "any" } }, profileForbidden: true }),
  );

  // --- server(s) ---
  const serverLeaves = (prefix: string, since: string): Leaf[] => [
    L(`${prefix}.command`, "string", undefined, "Program that starts the MCP server. Alone it is a stdio server; with url, Sealmark starts it, waits for url to answer, tests it and stops it.", { since, profileForbidden: true }),
    L(`${prefix}.args`, "string[]", undefined, "Arguments for command. Placeholders such as {dsn}, {sandbox} are filled by the harness. Replaces, never appends.", { since, coerce: true, profileForbidden: true }),
    L(`${prefix}.env`, "stringMap", undefined, "Environment variables for the server. Values under secret-looking names are redacted in reports.", { since, profileForbidden: true }),
    L(`${prefix}.url`, "string", undefined, "URL of a Streamable HTTP server. Alone it must already be running; with command, Sealmark starts it and waits for this URL.", { since, profileForbidden: true }),
    L(`${prefix}.start_timeout_sec`, "integer", undefined, "Seconds to wait for a server started with command + url to answer on url (default 60). A server that does not answer in time fails the run with its last output.", { since: S02, min: 1, documentedDefault: 60, profileForbidden: true }),
    L(`${prefix}.headers`, "stringMap", undefined, "HTTP headers sent to the server (url transport). Values under secret-looking names are redacted.", { since, profileForbidden: true }),
    L(`${prefix}.rootless`, "boolean", undefined, "The server takes no root argument and works in its own working directory: the fs pack treats that directory ({sandbox}) as the allowed root, so every path probe runs and a server that reads or writes any path fails the escape checks. Use it for a path server you cannot give a {sandbox} argument. Not locked: it only adds coverage, so a STANDARD run stays STANDARD.", { since: S03, documentedDefault: false, profileForbidden: true }),
    L(`${prefix}.files`, "list", undefined, "Files written inside the sandbox before the server starts, as { path, content }. path must start with {sandbox} or {sandbox_home}; content may use harness placeholders and ${VAR}, never {dsn}. File only.", { since: S02, shape: STAGED_FILES_SHAPE, profileForbidden: true }),
  ];
  add(...serverLeaves("server", S01));
  add(...serverLeaves("servers.*", S02));
  add(
    L("sql_tools", "list", undefined, "Tools that take a SQL string, as { tool, arg } (optional role: reader|writer|unknown, shape: string|array, args: { <parameter>: <string|number|boolean> } for the tool's other required parameters, which a placeholder cannot satisfy). Auto-detected when omitted. A list adds tools and corrects arguments; it never hides a detected tool (use tools.exclude for that), and a detected writer stays a writer.", {
      since: S01,
      shape: { k: "array", item: SQL_TOOL_SHAPE },
      profileForbidden: true,
    }),
    L("run.server", "string", null, "Which entry of `servers` to run: a name or `all`. Empty runs every declared server.", { nullable: true, profileForbidden: true }),
  );

  // --- run shape ---
  add(
    L("packs", "string[]", [...STANDARD_PACKS], "Packs to run. Removing a standard pack makes the run CUSTOM; adding one (exec, custom) does not. exec only runs with --active.", { since: S01, shape: packsShape() }),
    L("timeout_probe_sec", "number", 10, "Seconds the cap and timeout probes wait before a call counts as running too long (flag --timeout-probe).", { since: S01, min: 0, exclusiveMin: true, ...locked }),
  );

  // --- per-check controls ---
  for (const c of CHECKS) {
    // A candidate is not part of the standard yet: unlocked, so the pinned standard hash does not move (integrity.ts reports a change as CUSTOM).
    const lock = c.candidate ? {} : locked;
    const note = c.candidate ? ` ${c.id} is a candidate check, not part of the standard profile: changing this makes the run CUSTOM.` : "";
    add(
      L(`checks.${c.id}.enabled`, "boolean", true, `Run ${c.id}. false reports it as n/a ("disabled by config") so it stays visible.${note}`, { since: c.since, ...lock }),
      L(`checks.${c.id}.severity`, "enum", null, `Override how ${c.id} counts: critical, scored or advisory. null keeps the check's own severity. advisory removes it from the score.${note}`, { since: c.since, enum: SEVERITIES, nullable: true, ...lock }),
    );
    if (c.corpus && !c.candidate) {
      add(
        L(`checks.${c.id}.corpus.add`, "list", [], `Extra probes for ${c.id}, validated against the pack's corpus schema. Appends across layers. Any addition makes the run CUSTOM.`, { since: c.since, shape: { k: "array", item: corpusAddShape(c.id) }, mergeable: true, ...locked }),
        L(`checks.${c.id}.corpus.remove`, "string[]", [], `Probe ids or exact strings to drop from the ${c.id} corpus. Appends across layers. Any removal makes the run CUSTOM.`, { since: c.since, mergeable: true, ...locked }),
      );
    }
  }
  add(
    L("checks.db-rowcap.row_cap", "integer", 10000, "Rows a single response may return before db-rowcap fails (standard 10000).", { min: 1, ...locked }),
    L("checks.db-timeout.expected_sec", "number", null, "Seconds a runaway query may run before db-timeout fails. null uses timeout_probe_sec.", { min: 0, exclusiveMin: true, nullable: true, ...locked }),
    L("checks.db-timeout.slow_sql", "string", null, "A SELECT that runs for a long time, used instead of pg_sleep when a server refuses pg_sleep. Must be a SELECT. null keeps the built-in probe.", { nullable: true, ...locked }),
    L("checks.sqlite-rowcap.row_cap", "integer", 10000, "Rows a single response may return before sqlite-rowcap fails.", { min: 1, ...locked }),
    L("checks.sqlite-timeout.expected_sec", "number", null, "Seconds a runaway query may run before sqlite-timeout fails. null uses timeout_probe_sec.", { min: 0, exclusiveMin: true, nullable: true, ...locked }),
    L("checks.robust-input.hang_ms", "integer", null, "Milliseconds a call may hang on bad input before robust-input fails. null derives max(2000, timeout_probe_sec * 1000).", { since: S01, min: 1, nullable: true, ...locked }),
    L("checks.robust-input.max_tools", "integer", 25, "Most tools robust-input will probe.", { since: S01, min: 1, ...locked }),
    L("checks.fs-size-cap.file_mib", "integer", 64, "Size in MiB of the file fs-size-cap asks the server to read.", { min: 1, ...locked }),
    L("checks.fs-size-cap.pass_mib", "integer", 16, "Largest response in MiB that still passes fs-size-cap (standard 16).", { min: 1, ...locked }),
  );

  // Deprecated 0.1-era check id, kept working for one major. The new ids carry the thresholds.
  const dep = (leaf: string, to: string[], type: LeafType, extra: LeafOpts = {}) =>
    add(L(`checks.cap-timeout.${leaf}`, type, undefined, `Deprecated alias: cap-timeout was split into db-rowcap and db-timeout. Use ${to.join(" and ")}.`, { since: S01, deprecated: { to }, ...extra }));
  dep("enabled", ["checks.db-rowcap.enabled", "checks.db-timeout.enabled"], "boolean");
  dep("severity", ["checks.db-rowcap.severity", "checks.db-timeout.severity"], "enum", { enum: SEVERITIES });
  dep("timeout_sec", ["checks.db-timeout.expected_sec"], "number", { min: 0, exclusiveMin: true });
  dep("row_cap", ["checks.db-rowcap.row_cap"], "integer", { min: 1 });

  // --- sandbox ---
  add(
    L("sandbox.enabled", "boolean", true, "Run packs that need a harness-owned sandbox. false (--no-sandbox) inherits the environment, disables fs, git, exec and effects, and makes the run CUSTOM.", { ...locked }),
    L("sandbox.dir", "string", null, "Parent directory for the disposable sandbox. null uses the OS temp directory.", { nullable: true }),
    L("sandbox.keep", "boolean", false, "Keep the sandbox after the run (--keep-sandbox).", {}),
    L("sandbox.scrub_env", "boolean", true, "Start the server with a built-from-scratch environment instead of inheriting yours.", { ...locked }),
    L("sandbox.keep_env", "string[]", [], "Variable names copied from your environment into the scrubbed one (for example HTTP_PROXY).", { ...locked }),
    L("sandbox.pack_timeout_sec", "number", 600, "Seconds before one pack is abandoned and reported inconclusive (--pack-timeout).", { min: 0, exclusiveMin: true, ...locked }),
    L("sandbox.max_mib", "integer", 1024, "Size cap of the sandbox directory in MiB; a probe that exceeds it is aborted and fails.", { min: 1, ...locked }),
  );

  // --- tool selection ---
  add(
    L("tools.include", "string[]", ["*"], "Glob patterns of tool names to probe, evaluated before exclude. A higher layer replaces the list (it is not mergeable: a catch-all default could never be narrowed by appending).", { ...locked }),
    L("tools.exclude", "string[]", [], "Glob patterns of tool names never to probe (listed under not covered). Appends across layers.", { mergeable: true, ...locked }),
    L("tools.overrides", "object", {}, "Per-tool classifier overrides: { tool: { class, params } }. An override always wins and is printed.", {
      shape: { k: "map", value: TOOL_OVERRIDE_SHAPE },
      ...locked,
    }),
  );

  // --- timing ---
  add(
    L("timeouts.connect_ms", "integer", 60000, "Milliseconds to wait for the server to start and answer initialize (--connect-timeout, in seconds).", { min: 1 }),
    L("timeouts.call_ms", "integer", 30000, "Milliseconds before an ordinary tool call counts as timed out.", { min: 1, ...locked }),
    L("timeouts.probe_ms", "integer", 10000, "Milliseconds before a verdict probe counts as timed out.", { min: 1, ...locked }),
    L("retries.connect", "integer", undefined, "No longer used and ignored: nothing retries a server start.", { min: 0, deprecated: { to: [] } }),
    L("retries.call", "integer", undefined, "No longer used and ignored: nothing retries a control call.", { min: 0, deprecated: { to: [] } }),
    L("concurrency.servers", "integer", undefined, "No longer used and ignored: servers run one after another.", { deprecated: { to: [] } }),
    L("concurrency.packs", "integer", undefined, "No longer used and ignored: packs run one after another (they share observers).", { deprecated: { to: [] } }),
  );

  // --- network ---
  add(
    L("net.control_url", "string", null, "A URL the harness may fetch through the server as a control, so a no-hit, no-refusal result can pass instead of staying inconclusive.", { nullable: true, ...locked }),
    L("net.allow_dns", "boolean", false, "Allow probes that need DNS resolution (127.0.0.1.nip.io).", { ...locked }),
  );

  // --- engines and database ---
  add(
    L("sqlite.engine", "enum", null, "Force the embedded-database engine instead of detecting it from {sqlite_path} / {duckdb_path}. Setting it makes the run CUSTOM (it can switch the sqlite pack off).", { enum: ["sqlite", "duckdb"], nullable: true }),
    L("db.embedded", "boolean", null, "false (--no-embedded) disables the embedded Postgres. null starts it when the db pack needs it.", { since: S01, nullable: true }),
    L("db.pg", "string", null, "Superuser DSN of an existing Postgres to seed instead of the embedded one (--pg). Needs --yes. Treated as a secret.", { since: S01, nullable: true, secret: true }),
  );

  // --- round 6: upstream stub, identities, declared scope (candidate packs; every leaf unlocked, so the standard hash does not move) ---
  add(
    L("upstream.kind", "enum", null, "Kind of the harness-owned upstream stub the server's backend is pointed at through {upstream}. http starts a loopback stub that records every request the server forwards (flag --upstream). null starts none. The stub needs a server Sealmark starts, and the server must use {upstream} in command, args, env, url, headers or files.", { since: S03, enum: ["http"], nullable: true }),
    L("upstream.responses", "list", [], "Scripted replies of the upstream stub, tried in order: { id?, match?: { method?, path?, body?, header? }, reply }. match values are regular expressions (method is exact); an entry without match answers everything. reply needs exactly one of body, json or bytes, plus optional status, headers and delay_ms. {upstream_token} in a reply body becomes a fresh marker per occurrence.", { since: S03, shape: { k: "array", item: UPSTREAM_RESPONSE_SHAPE } }),
    L("upstream.default_reply", "object", { status: 200, json: {} }, "What the upstream stub answers when no `responses` entry matches.", { since: S03, shape: UPSTREAM_REPLY_SHAPE }),
    L("upstream.credential_header", "string", "authorization", "Header the upstream-credential check reads the forwarded credential from (compared case-insensitively).", { since: S03, shape: { k: "string", nonEmpty: true } }),
    L("upstream.max_body_kib", "integer", 1024, "Largest request body in KiB the upstream stub records; the rest is cut and marked truncated.", { since: S03, min: 1 }),
    L("identities.a", "string", null, "Token the harness sends as caller A wherever the server config says {bearer} or {bearer:a}. null mints one per run. Set it when the server validates tokens it did not issue. ${VAR} is read from the environment. Treated as a secret: redacted in config show and in reports (flag --identity-a).", { since: S03, nullable: true, secret: true, coerce: true }),
    L("identities.b", "string", null, "Token the harness sends as caller B ({bearer:b}). null mints one per run. Must differ from identities.a. Treated as a secret (flag --identity-b).", { since: S03, nullable: true, secret: true, coerce: true }),
    L("scope.tools", "list", [], "Tools that take an identifier the server is meant to restrict (a table, dataset, path), as { tool, param }: the scope pack sends out-of-scope forms of the identifier through each. The tool keeps its classification.", { since: S03, shape: { k: "array", item: SCOPE_TOOL_SHAPE } }),
    L("scope.allow", "string[]", [], "Identifiers the server may serve. An entry that ends with scope.separator is a prefix (sales.public.); any other entry is exact. Needed when scope.tools is not empty.", { since: S03 }),
    L("scope.deny", "string[]", [], "Identifiers the server must refuse even inside scope.allow (same syntax; deny wins).", { since: S03 }),
    L("scope.separator", "string", ".", "The one character that separates the parts of an identifier (and ends a prefix entry).", { since: S03, shape: { k: "string", pattern: /^[\s\S]$/u, patternHint: "separator must be exactly one character" } }),
    L("scope.case", "enum", "insensitive", "Whether the server compares identifiers case-insensitively (the default) or case-sensitively. An upper-case spelling of an allowed name that is refused under insensitive is noted, never failed.", { since: S03, enum: ["sensitive", "insensitive"] }),
    L("checks.sql-guard-rowcap.row_cap", "integer", 10000, "Largest LIMIT (or FETCH FIRST / TOP) the statement the server forwards may carry before sql-guard-rowcap fails. A candidate setting: unlocked.", { since: S03, min: 1 }),
    L("checks.sql-guard-statements.control_sql", "string", null, "A SELECT or WITH statement the harness sends as the control for sql-guard-statements; it must reach the upstream stub. null builds one (SELECT 1 AS sm_<token>, or a read of the first exact scope.allow entry).", { since: S03, shape: CONTROL_SQL_SHAPE, nullable: true }),
    L("checks.upstream-slow.expected_sec", "number", null, "Seconds the server may take to answer when the upstream is slow before upstream-slow fails (a little slack is added). null uses timeout_probe_sec.", { since: S03, min: 0, exclusiveMin: true, nullable: true }),
    L("checks.refusal-quality.patterns", "string[]", [...REFUSAL_ROUTING_PATTERNS], "Regular expressions that mark a refusal as routing the caller (naming what is available, what to use instead, that retrying will not help). Replaces the default list.", { since: S03, shape: regexList }),
    L("checks.instructions-hygiene.deny", "string[]", [], "Regular expressions the server's instructions must not match (a leftover prompt, a product name). Appends across layers.", { since: S03, shape: regexList, mergeable: true }),
  );

  // --- output ---
  add(
    L("output.format", "enum", "text", "Report format printed to stdout or --out.", { since: S01, enum: FORMATS }),
    L("output.formats", "string[]", [], "Several formats at once (written under output.out_dir). Empty means just output.format.", { shape: { k: "array", item: { k: "enum", values: FORMATS } } }),
    L("output.out", "string", null, "Write the report to this file instead of stdout (--out).", { since: S01, nullable: true }),
    L("output.out_dir", "string", null, "Directory for multi-format output.", { nullable: true }),
    L("output.verbosity", "enum", "normal", "quiet, normal, or verbose (every evidence line and probe argument).", { enum: ["quiet", "normal", "verbose"] }),
    L("output.redact", "boolean", true, "Redact secret-looking values in reports. false (--no-redact) is for local debugging only.", {}),
    L("output.template", "string", null, "Path of a report template. Templates never change the result data.", { nullable: true }),
    L("output.baseline", "string", null, "Prior JSON report to compare against (--baseline).", { nullable: true }),
    L("output.write_baseline", "string", null, "Write the current JSON report here for later --baseline runs (--write-baseline).", { nullable: true }),
    L("output.fail_on", "string[]", ["any"], "With a baseline, what decides the exit code: any (the gate and regressions, the default), regressions (regressions only), drift (breaking or notable tool-surface drift). A list: fail_on: [regressions, drift].", {
      enum: FAIL_ON,
      shape: { k: "array", item: { k: "enum", values: FAIL_ON }, scalar: true },
    }),
    L("output.interactive", "boolean", undefined, "No longer used and ignored: whether a prompt appears depends on a terminal being attached and on --yes.", { deprecated: { to: [] } }),
    L("output.exit_policy.fail_under", "enum", "A", "Exit 1 when a graded pack is below this letter (--fail-under). Default A: anything below an A fails. Use B, C, D or F to relax it, or null (--fail-under none) to turn the gate off.", { since: S01, enum: LETTERS, nullable: true }),
    L("output.exit_policy.soft_fail", "boolean", false, "A grade below fail_under (or a baseline regression) prints a warning and exits 0. Config errors, nothing graded and server failures still fail (--soft-fail).", {}),
    L("output.exit_policy.regressions_only", "boolean", false, "Exit non-zero only for regressions against the baseline.", {}),
    L("output.exit_policy.treat_inconclusive_as", "enum", "pass", "How --fail-under treats an inconclusive pack.", { enum: ["pass", "fail"] }),
    L("output.exit_policy.critical_fail", "integer", 0, "Exit code used when a critical check fails (0 keeps the 0.1 behaviour).", { min: 0, max: 4 }),
  );

  // --- extension points ---
  add(
    L("plugins", "list", [], "Plugin packs: { module, options }. Plugins run in-process with your privileges and always make the run CUSTOM. Appends across layers.", {
      shape: { k: "array", item: PLUGIN_SHAPE },
      mergeable: true,
    }),
    L("probes", "list", [], "Probes: valid calls for coverage, and custom checks when an entry has `check`. Entries with `check` make the run CUSTOM.", { shape: PROBES_SHAPE }),
    L("notCovered.extra", "string[]", [], "Extra lines for the report's 'not covered' section. Appends across layers.", { mergeable: true }),
  );

  // --- safety flags: command line only ---
  add(
    L("active", "boolean", false, "Allow the exec pack and active custom probes to run harness-owned programs. Only the --active flag can set it; files and environment cannot.", { flagOnly: true, profileForbidden: true }),
    L("yes", "boolean", false, "Confirm that --pg may drop and recreate the seed database. Only the --yes flag can set it.", { flagOnly: true, profileForbidden: true }),
  );
  return out;
}

export const SCHEMA: readonly Leaf[] = build();

// ---- schema tree ----

export interface SchemaNode {
  children: Map<string, SchemaNode>;
  wildcard?: SchemaNode;
  leaf?: Leaf;
}

function buildTree(leaves: readonly Leaf[]): SchemaNode {
  const root: SchemaNode = { children: new Map() };
  for (const leaf of leaves) {
    let node = root;
    for (const seg of leaf.path.split(".")) {
      if (seg === "*") node = node.wildcard ??= { children: new Map() };
      else {
        let next = node.children.get(seg);
        if (!next) node.children.set(seg, (next = { children: new Map() }));
        node = next;
      }
    }
    if (node.leaf || node.children.size) throw new Error(`schema path ${leaf.path} collides with another entry`);
    node.leaf = leaf;
  }
  return root;
}

export const TREE: SchemaNode = buildTree(SCHEMA);

/** Top-level keys that make no sense inside a profile (they describe one project, not a way of running). */
export const PROFILE_FORBIDDEN_TOP = new Set(["profile", "profiles", "schema_version", "server", "servers", "sql_tools", "run", "name", "version", "active", "yes"]);

/** Resolves a concrete path (["servers", "fs", "command"]) to its leaf, honouring `*` segments. */
export function findLeaf(path: readonly string[]): Leaf | undefined {
  let node: SchemaNode | undefined = TREE;
  for (const seg of path) {
    node = node.children.get(seg) ?? node.wildcard;
    if (!node) return undefined;
  }
  return node.leaf;
}

const byPath = new Map(SCHEMA.map((l) => [l.path, l]));
export const leafByPath = (p: string): Leaf | undefined => byPath.get(p);

/** Paths (no wildcards) of lists that append across layers. */
export const MERGEABLE_PATHS: ReadonlySet<string> = new Set(SCHEMA.filter((l) => l.mergeable).map((l) => l.path));

/** Locked leaves: every grade-affecting setting. `packs` is locked separately as a pack list (adding a pack is allowed). */
export const LOCKED_LEAVES: readonly Leaf[] = SCHEMA.filter((l) => l.standardLocked && !l.path.includes("*"));

/** The defaults tree (file shape). Deprecated aliases and wildcard entries have none. */
export function defaults(): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  for (const l of SCHEMA) {
    if (l.default === undefined || l.path.includes("*")) continue;
    const segs = l.path.split(".");
    let cur = root;
    for (const s of segs.slice(0, -1)) cur = (cur[s] ??= {}) as Record<string, unknown>;
    cur[segs[segs.length - 1]] = deepClone(l.default);
  }
  return root;
}

// ---- JSON Schema ----

function nodeToJson(node: SchemaNode, forbid: ReadonlySet<string> = new Set(), top = false): Record<string, unknown> {
  if (node.leaf) {
    const l = node.leaf;
    const base = shapeToJsonSchema(l.shape);
    const schema: Record<string, unknown> = { ...base, description: l.description };
    if (l.default !== undefined) schema.default = l.default;
    else if (l.documentedDefault !== undefined) schema.default = l.documentedDefault;
    if (l.nullable) {
      if (Array.isArray(base.enum)) schema.enum = [...(base.enum as unknown[]), null];
      else if (base.type) schema.type = [...(Array.isArray(base.type) ? (base.type as string[]) : [base.type as string]), "null"];
    }
    if (l.deprecated) schema.deprecated = true;
    schema["x-sealmark"] = { since: l.since, standardLocked: Boolean(l.standardLocked), mergeable: Boolean(l.mergeable), secret: Boolean(l.secret), flagOnly: Boolean(l.flagOnly) };
    return schema;
  }
  const properties: Record<string, unknown> = {};
  for (const [k, child] of [...node.children].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (top && forbid.has(k)) continue;
    properties[k] = nodeToJson(child);
  }
  const res: Record<string, unknown> = { type: "object", properties };
  if (node.wildcard) res.additionalProperties = nodeToJson(node.wildcard);
  else res.additionalProperties = false;
  return res;
}

/** The JSON Schema published as cli/schema/sealmark.schema.json. Deterministic. */
export function buildJsonSchema(): Record<string, unknown> {
  const root = nodeToJson(TREE);
  const profile = nodeToJson(TREE, PROFILE_FORBIDDEN_TOP, true) as { properties: Record<string, unknown> };
  profile.properties.extends = { type: "string", description: "Name of the profile this one builds on (default: standard)." };
  profile.properties.description = { type: "string", description: "What the profile is for." };
  const props = root.properties as Record<string, Record<string, unknown>>;
  props.profiles = {
    type: "object",
    description: (props.profiles.description as string) ?? "User-defined profiles.",
    additionalProperties: { $ref: "#/definitions/profile" },
    "x-sealmark": props.profiles["x-sealmark"],
  };
  return {
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "Sealmark configuration",
    description: `Configuration for the sealmark CLI (methodology ${METHODOLOGY}, config schema_version ${SCHEMA_VERSION}). Generated from cli/src/config/schema.ts; do not edit by hand.`,
    ...root,
    definitions: { profile },
  };
}
