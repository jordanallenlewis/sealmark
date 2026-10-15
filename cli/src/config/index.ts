import { homedir } from "node:os";
import { dirname, join, posix, resolve, win32 } from "node:path";
import { envToLayer } from "./env.js";
import { flagsToLayer, HEADER_NAME, type FlagValues } from "./flags.js";
import { checkReplay, evaluateIntegrity, replayNotes } from "./integrity.js";
import { mergeLayers, originText, type Layer } from "./layers.js";
import { loadFile, validateLeaf, type LoadedFile, type VCtx } from "./loader.js";
import {
  ConfigError,
  type CheckConfig,
  type DiffEntry,
  type EffectiveConfig,
  type IdentitySettings,
  type NamedServer,
  type Origin,
  type OutputSettings,
  type PluginSpec,
  type ProbeSpec,
  type SandboxSettings,
  type ScopeSettings,
  type ToolOverride,
  type UpstreamSettings,
} from "./model.js";
import { allPlaceholders, expandEnvRefs, realPaths, ROLE_NAMES, specParts, stripUserinfo, unknownPlaceholders, unknownPlaceholderWarning, unsetEnvRefs } from "./placeholders.js";
import { isShipped, mergeChain, resolveChain, shippedProfile, standardMerged, SHIPPED_PROFILES, userRecord, type ProfileRecord } from "./profiles.js";
import { LOCKED_LEAVES, SCHEMA, leafByPath, type Leaf } from "./schema.js";
import { deleteIn, deepClone, deepEqual, didYouMean, getIn, isPlainObject, pointer, setIn } from "./util.js";
import type { PackId, SealmarkConfig, ServerSpec, SqlTool } from "../types.js";

export * from "./model.js";
export { FLAG_DEFS, flagsToLayer, parseArgsOptions, type FlagDef, type FlagValues } from "./flags.js";
export { CANDIDATE_CHECKS, checkReplay, computeHash, evaluateIntegrity, extractLocked, replayNotes, standardHash } from "./integrity.js";
export { migrateFile, migrateText, MIGRATIONS } from "./migrations.js";
export { displaySpec, expand, expandEnvRefs, placeholdersUsed, usesPlaceholders, type TemplateCtx } from "./placeholders.js";
export { SHIPPED_PROFILES } from "./profiles.js";
export { buildJsonSchema, CHECKS, PACK_IDS, SCHEMA, STANDARD_PACKS, type Leaf } from "./schema.js";
export { redactedValue, renderShow } from "./show.js";

export interface LoadOptions {
  /** Directory the project file is looked up in and relative paths resolve against. */
  cwd: string;
  /** Parsed command-line values, as util.parseArgs reports them (see FLAG_DEFS). */
  flags?: FlagValues;
  /** The environment to read SEALMARK_* and %APPDATA% / XDG_CONFIG_HOME from. Pass process.env; nothing else in sealmark reads it. */
  env?: Record<string, string | undefined>;
  platform?: NodeJS.Platform;
  homedir?: string;
  /** Do not read the user-level file. */
  isolated?: boolean;
  /** A prior report's `config` block: its locked leaves replace the loaded ones, after the hash is verified. */
  replay?: { hash?: unknown; locked?: unknown; methodology?: unknown };
}

/** Where the user-level file lives, or undefined when disabled (`SEALMARK_USER_CONFIG=none`). */
export function userConfigPath(env: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform, home: string = homedir()): string | undefined {
  const override = env.SEALMARK_USER_CONFIG;
  if (override !== undefined && override !== "") return override.toLowerCase() === "none" ? undefined : override;
  if (platform === "win32") return win32.join(env.APPDATA || win32.join(env.USERPROFILE || home, "AppData", "Roaming"), "sealmark", "config.yaml");
  return posix.join(env.XDG_CONFIG_HOME || posix.join(env.HOME || home, ".config"), "sealmark", "config.yaml");
}

interface Sources {
  layers: { user?: LoadedFile; project?: LoadedFile; local?: LoadedFile };
  projectPath: string;
  projectMissing: boolean;
  userProfiles: Map<string, ProfileRecord>;
  files: string[];
  warnings: string[];
}

function readFiles(opts: LoadOptions, cwd: string, issues: string[]): Sources {
  const env = opts.env ?? {};
  const flagConfig = opts.flags?.config;
  const explicit = typeof flagConfig === "string" && flagConfig !== "";
  const projectPath = resolve(cwd, explicit ? (flagConfig as string) : "sealmark.yaml");
  const userPath = opts.isolated ? undefined : userConfigPath(env, opts.platform, opts.homedir);
  const user = userPath ? loadFile(userPath, "user", { cwd, optional: true, issues }) : undefined;
  const project = loadFile(projectPath, "project", { cwd, optional: !explicit, issues });
  const local = loadFile(join(dirname(projectPath), "sealmark.local.yaml"), "local", { cwd, optional: true, issues });
  const files: string[] = [];
  const warnings: string[] = [];
  const userProfiles = new Map<string, ProfileRecord>();
  for (const [f, p] of [[user, userPath], [project, projectPath], [local, join(dirname(projectPath), "sealmark.local.yaml")]] as const) {
    if (!f) continue;
    files.push(p as string);
    warnings.push(...f.warnings);
    for (const def of f.profiles) {
      if (isShipped(def.name)) issues.push(`${f.display}: profile "${def.name}" is a shipped profile and cannot be redefined; pick another name`);
      else userProfiles.set(def.name, userRecord(def));
    }
  }
  return { layers: { user, project, local }, projectPath, projectMissing: !project && !explicit, userProfiles, files, warnings };
}

const DEPRECATED = SCHEMA.filter((l) => l.deprecated);

/** Moves values set through a deprecated name to their replacements and warns. The old name keeps working for one major. */
function applyDeprecations(layer: Layer, warnings: string[]): void {
  for (const leaf of DEPRECATED) {
    const segs = leaf.path.split(".");
    const v = getIn(layer.data, segs);
    if (v === undefined) continue;
    deleteIn(layer.data, segs);
    const parent = getIn(layer.data, segs.slice(0, -1));
    if (isPlainObject(parent) && !Object.keys(parent).length) deleteIn(layer.data, segs.slice(0, -1));
    const line = layer.lines.get(pointer(segs));
    for (const to of leaf.deprecated?.to ?? []) {
      const t = to.split(".");
      if (getIn(layer.data, t) === undefined) {
        setIn(layer.data, t, deepClone(v));
        if (line !== undefined) layer.lines.set(pointer(t), line);
        const src = layer.sources.get(pointer(segs));
        if (src) layer.sources.set(pointer(t), src);
      }
    }
    const where = layer.sources.get(pointer(segs)) ?? (line !== undefined ? `${layer.source}:${line}` : layer.source);
    const to = leaf.deprecated?.to ?? [];
    warnings.push(to.length ? `${where}: ${leaf.path} is deprecated; use ${to.join(" and ")}` : `${where}: ${leaf.path} is no longer used and is ignored`);
  }
}

/** GitLab CI, GitHub Actions, CircleCI and most others set CI=true. */
export const inCi = (env: Record<string, string | undefined> | undefined): boolean => /^(true|1)$/i.test(env?.CI ?? "");

/** An explicit profile (flag, env or file) always wins; otherwise a CI job gets the `ci` profile and a laptop gets `standard`. */
function selectedProfile(layers: readonly Layer[], ci: boolean): string {
  for (const l of [...layers].reverse()) {
    const p = l.data.profile;
    if (typeof p === "string" && p) return p;
  }
  return ci ? "ci" : "standard";
}

const str = (v: unknown): Record<string, string> => Object.fromEntries(Object.entries((v as Record<string, unknown> | undefined) ?? {}).map(([k, x]) => [k, String(x)]));

/** A server is started from a clean sandbox folder, so "./dist/server.js" would not be found there: anchor leading ./ and ../ paths to the config file's folder. */
const RELATIVE_PATH = /^\.{1,2}[\\/]/;
const anchorPath = (v: string, baseDir: string): string => (RELATIVE_PATH.test(v) ? resolve(baseDir, v).split("\\").join("/") : v);

/** Programs that run a script or package: the thing worth naming is their first real argument. */
const RUNNERS = new Set(["node", "nodejs", "npx", "bunx", "bun", "deno", "tsx", "ts-node", "python", "python3", "py", "uv", "uvx", "pipx", "java", "dotnet", "sh", "bash", "zsh", "env", "docker", "npm", "pnpm", "yarn"]);
const SUBCOMMANDS = new Set(["run", "exec", "dlx", "x", "tool", "start", "dev"]);

/** A readable report name from the server's command (`my-server --port 8000` -> `my-server`; `npx -y @scope/pkg@1.2` -> `pkg`) or the host of its url. */
function deriveName(spec: ServerSpec, env: Record<string, string | undefined>): string | undefined {
  const tidy = (x: string): string =>
    x.replace(/\\/g, "/").split("/").filter(Boolean).pop()?.replace(/@[^@/]+$/, "").replace(/\.(?:[cm]?[jt]s|py|exe|cmd|bat)$/i, "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "") ?? "";
  if (spec.command) {
    const base = tidy(spec.command);
    if (!RUNNERS.has(base.toLowerCase())) return base || undefined;
    const args = spec.args ?? [];
    // `node -e "<code>"` and friends: the argument is a program text, not a name
    const i = args.findIndex((a) => !/^-|^\{|^\$\{|^\d+$/.test(a) && !SUBCOMMANDS.has(a));
    const arg = i >= 0 && !/^(?:-e|-c|-p|--eval|--print)$/.test(args[i - 1] ?? "") && !/[\s'"();=]/.test(args[i]) ? args[i] : undefined;
    return (arg !== undefined ? tidy(arg) : "") || base || undefined;
  }
  if (spec.url) {
    try {
      return new URL(expandEnvRefs(spec.url, env)).hostname.replace(/[^A-Za-z0-9._-]+/g, "-") || undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** The flags that only add to a server, and so mean nothing without --url or --start. */
const NEEDS_SERVER: Record<string, string> = { headers: "--header or --bearer", start_timeout_sec: "--start-timeout" };

/** The error when no server is configured anywhere: lead with what is wrong, then what to type. `given` names server settings that were set without a server. */
function noServerHelp(given: readonly string[]): string {
  const extras = [...new Set(given.map((k) => NEEDS_SERVER[k]).filter(Boolean))];
  return (
    `No server is configured${extras.length ? ` (${extras.join(" and ")} only add to a server; name one with --url or --start)` : ""}. Name it on the command line, no file needed:\n` +
    `  sealmark run --url http://localhost:8000/mcp                          (a server that is already running)\n` +
    `  sealmark run --start "my-server --port 8000" --url http://localhost:8000/mcp   (start it, wait, test, stop)\n` +
    `  sealmark run --start "npx -y some-mcp-server"                          (a stdio server)\n` +
    `or run "sealmark init" to write a sealmark.yaml.`
  );
}

/** Layers lowest to highest, for deciding which of two headers that differ only by case wins. */
const LAYER_RANK: Record<string, number> = { default: 0, profile: 1, user: 2, project: 3, local: 4, env: 5, flag: 6, replay: 7 };

/** What toSpec needs from the merge: the environment, where a value came from, and a place to put warnings. */
interface SpecCtx {
  env: Record<string, string | undefined>;
  warnings: string[];
  /** Origin of a setting under this server (`headers`, `Authorization`), looked up the way `at` does. */
  originOf(path: string[]): Origin | undefined;
  where(path: string[]): string;
  /** Unset ${VAR} problems, kept apart: with several servers only the ones that will run must have their variables. */
  unset: string[];
}

/** Characters Node's fetch refuses in a header value: control characters other than tab, and anything beyond Latin-1. */
const BAD_HEADER_VALUE = /[\u0000-\u0008\u000A-\u001F\u007F]|[^\u0000-\u00FF]/;

/**
 * Header names are case-insensitive. Two that differ only by case would both be sent, joined into one value, so the
 * credential a CI variable was meant to replace would still go out. The higher layer wins (flags over env over files);
 * two in the same layer cannot be ordered, so that is an error.
 */
function dedupeHeaders(headers: Record<string, string>, label: string, c: SpecCtx, issues: string[]): Record<string, string> {
  const groups = new Map<string, string[]>();
  for (const k of Object.keys(headers)) groups.set(k.toLowerCase(), [...(groups.get(k.toLowerCase()) ?? []), k]);
  const out: Record<string, string> = {};
  for (const keys of groups.values()) {
    if (keys.length === 1) {
      out[keys[0]] = headers[keys[0]];
      continue;
    }
    const ranked = keys.map((k) => ({ k, o: c.originOf(["headers", k]) })).map((x) => ({ ...x, rank: LAYER_RANK[x.o?.layer ?? "default"] ?? 0 }));
    const top = Math.max(...ranked.map((x) => x.rank));
    const winners = ranked.filter((x) => x.rank === top);
    if (winners.length > 1) {
      issues.push(`${c.where(["headers", winners[1].k])}: ${label}.headers has ${winners.map((w) => `"${w.k}"`).join(" and ")}, the same header in different case. Header names are not case-sensitive; keep one.`);
      continue;
    }
    const win = winners[0];
    // an environment variable name is upper-cased (SEALMARK_SERVER__HEADERS__AUTHORIZATION): keep the spelling the lower layer used
    const spelled = win.o?.layer === "env" ? (ranked.find((x) => x !== win && x.rank < top)?.k ?? win.k) : win.k;
    out[spelled] = headers[win.k];
  }
  return out;
}

function toSpec(raw: Record<string, unknown>, label: string, at: string, issues: string[], baseDir: string, c: SpecCtx): ServerSpec | undefined {
  const command = raw.command ? anchorPath(String(raw.command), baseDir) : undefined;
  const url = raw.url as string | undefined;
  if (url && !/^(https?:\/\/|\$\{|\{)/i.test(url)) {
    issues.push(`${at}: ${label}.url must start with http:// or https:// (got "${stripUserinfo(url)}").`);
    return undefined;
  }
  if (!command && !url) {
    issues.push(`${at}: ${label} needs "command" (stdio) or "url" (HTTP).`);
    return undefined;
  }

  // A ${VAR} that is not set would expand to nothing: a missing CI secret would run the test without credentials.
  const strs = (v: unknown): Record<string, string> => Object.fromEntries(Object.entries((v as Record<string, unknown> | undefined) ?? {}).map(([k, x]) => [k, String(x)]));
  const files = ((raw.files as { path: string; content: string }[] | undefined) ?? []).map((f) => ({ path: String(f.path), content: String(f.content) }));
  const valuesAt: [string[], string][] = [
    ...(command ? ([[["command"], String(raw.command)]] as [string[], string][]) : []),
    ...(url ? ([[["url"], url]] as [string[], string][]) : []),
    ...((raw.args as unknown[] | undefined) ?? []).map((a, i): [string[], string] => [["args", String(i)], String(a)]),
    ...Object.entries(strs(raw.env)).map(([k, v]): [string[], string] => [["env", k], v]),
    ...Object.entries(strs(raw.headers)).map(([k, v]): [string[], string] => [["headers", k], v]),
    ...files.flatMap((f, i): [string[], string][] => [[["files", String(i), "path"], f.path], [["files", String(i), "content"], f.content]]),
  ];
  let unset = false;
  for (const [path, value] of valuesAt) {
    for (const name of unsetEnvRefs(value, c.env)) {
      unset = true;
      const used = path[0] === "args" ? `${label}.args` : `${label}.${path.join(".")}`;
      c.unset.push(`${c.where(path)}: \${${name}} is not set (used in ${used}). Set it as a CI variable, or give a default: \${${name}:-fallback}`);
    }
  }

  // The URL after ${VAR} is filled in: it must be a real http(s) URL with a host, so a typo is a config error and not a harness failure.
  if (url && !unset) {
    const expanded = expandEnvRefs(url, c.env);
    if (!/\{[a-z_:]+\}/i.test(expanded)) {
      let ok = false;
      try {
        const u = new URL(expanded);
        ok = (u.protocol === "http:" || u.protocol === "https:") && u.hostname !== "";
      } catch {
        ok = false;
      }
      if (!ok) {
        issues.push(`${at}: ${label}.url is not a valid URL (got "${stripUserinfo(url.includes("${") ? url : expanded)}"); it needs a scheme and a host, for example http://localhost:8000/mcp`);
        return undefined;
      }
    }
  }

  let headers = raw.headers ? strs(raw.headers) : undefined;
  if (headers) {
    for (const [name, value] of Object.entries(headers)) {
      // only the header NAME is ever printed: the value may be a credential
      if (!HEADER_NAME.test(name)) issues.push(`${c.where(["headers", name])}: ${label}.headers: "${name}" is not a valid HTTP header name (letters, digits and - only; no spaces)`);
      else if (!unset && BAD_HEADER_VALUE.test(expandEnvRefs(value, c.env))) {
        issues.push(`${c.where(["headers", name])}: ${label}.headers.${name}: the value contains a character HTTP does not allow (a newline, a control character or a non-Latin-1 character). Check the variable it is built from.`);
      }
    }
    headers = dedupeHeaders(headers, label, c, issues);
  }
  if (!url && (headers || raw.start_timeout_sec !== undefined)) {
    const which = [headers ? "headers" : "", raw.start_timeout_sec !== undefined ? "start_timeout_sec" : ""].filter(Boolean).map((k) => `${label}.${k}`).join(" and ");
    c.warnings.push(`${at}: ${which} only apply to an HTTP server (url), and ${label} is a stdio server: ${headers ? "the headers are" : "start_timeout_sec is"} ignored. Add a url (with command, Sealmark starts it and waits for the url).`);
  }

  const spec: ServerSpec = {
    ...(command ? { command } : {}),
    ...(url ? { url } : {}),
    args: ((raw.args as unknown[] | undefined) ?? []).map((a) => anchorPath(String(a), baseDir)),
    env: str(raw.env),
    ...(headers ? { headers } : {}),
    ...(typeof raw.start_timeout_sec === "number" ? { start_timeout_sec: raw.start_timeout_sec } : {}),
    ...(files.length ? { files } : {}),
    // The key is unlocked and read by the fs pack (ServerSpec carries it as `rootless`); only a literal true is passed on.
    ...(raw.rootless === true ? { rootless: true } : {}),
  };
  const parts = [command ?? "", url ?? "", ...(spec.args ?? []), ...Object.values(spec.env ?? {}), ...Object.values(spec.headers ?? {}), ...files.flatMap((f) => [f.path, f.content])];
  const keys = new Set<string>();
  for (const part of parts) for (const m of part.matchAll(allPlaceholders())) keys.add(m[1]);
  for (const k of keys) {
    if (k.startsWith("dsn:") && !ROLE_NAMES.includes(k.slice(4))) issues.push(`${at}: unknown role in {${k}} (use ${ROLE_NAMES.join(", ")}).`);
  }
  if (keys.has("canary")) issues.push(`${at}: {canary} cannot be used in the server configuration; the canary path is never given to the server (use it in probes).`);
  if (keys.has("token")) issues.push(`${at}: {token} cannot be used in the server configuration; it is a per-probe value (use it in probes).`);
  if (keys.has("sqlite_path") && keys.has("duckdb_path")) issues.push(`${at}: {sqlite_path} and {duckdb_path} cannot both be used; one engine per server config (or set sqlite.engine).`);
  return spec;
}

/**
 * The only way the rest of sealmark gets configuration. Merges, lowest to highest: defaults, the selected profile
 * (and what it extends), the user-level file, the project file plus sealmark.local.yaml, SEALMARK_* environment
 * variables, command-line flags. Every problem found is collected and thrown together as one ConfigError.
 */
export function loadEffectiveConfig(opts: LoadOptions): EffectiveConfig {
  const cwd = resolve(opts.cwd);
  const env = opts.env ?? {};
  const issues: string[] = [];

  const flagLayer = flagsToLayer(opts.flags ?? {}, issues);
  const envLayer = envToLayer(env, issues);
  const src = readFiles(opts, cwd, issues);
  const fileLayers = [src.layers.user, src.layers.project, src.layers.local].flatMap((f) => (f ? [f.layer] : []));
  const upper = [...fileLayers, envLayer, flagLayer];

  // Someone who asked for a specific output (--out, --format, --out-dir) has not asked for the CI defaults. A gate flag (--fail-under, --soft-fail)
  // does not change the output, so it keeps the log summary and the report files.
  const outputFlag = ["out", "format", "out-dir"].some((k) => opts.flags?.[k] !== undefined);
  const profileName = selectedProfile(upper, inCi(opts.env) && !outputFlag);
  const chain = resolveChain(profileName, src.userProfiles, issues);
  if (issues.length) throw new ConfigError(issues);

  const warnings = [...src.warnings];
  // Mirrors the transform in flags.ts: a lowercase letter is read as the capital, and the first time says so.
  const failUnder = opts.flags?.["fail-under"];
  if (typeof failUnder === "string" && /^[a-df]$/.test(failUnder.trim())) warnings.push(`--fail-under ${failUnder.trim()} read as ${failUnder.trim().toUpperCase()}`);
  const layers = [...chain.map((c) => c.layer), ...upper];
  for (const l of layers) applyDeprecations(l, warnings);
  const merged = mergeLayers(layers);
  const { value, origins } = merged;
  // The profile in effect is the one `config show` prints, also when CI=true chose it rather than a file, flag or default.
  if (value.profile !== profileName) {
    value.profile = profileName;
    // the layer stays "default" on purpose: cli.ts reads it to print the "CI detected" line
    origins.set("/profile", { layer: "default", source: `env CI=${env.CI ?? "true"}` });
  }

  if (opts.replay) {
    const problem = checkReplay(opts.replay);
    if (problem) throw new ConfigError(`--replay: ${problem}`);
    // Replay is a config layer like any other: every value goes through the same leaf validation as a file, flag-only and
    // unknown settings are refused, and nothing outside the locked leaves and `packs` can be set from a report.
    const replayIssues: string[] = [];
    const rctx: VCtx = { kind: "replay", where: () => "--replay", showPath: true, issues: replayIssues, lines: new Map() };
    const allowed = new Map<string, Leaf>(LOCKED_LEAVES.map((l) => [l.path, l]));
    const packsLeaf = leafByPath("packs");
    if (packsLeaf) allowed.set("packs", packsLeaf);
    warnings.push(...replayNotes(opts.replay));
    for (const [path, v] of Object.entries(opts.replay.locked as Record<string, unknown>)) {
      // The record of a CUSTOM run's checks and plugins is not a setting: it only feeds the hash and the warning above.
      if (path === "custom_checks" || path === "plugins") continue;
      const leaf = allowed.get(path);
      if (!leaf) {
        replayIssues.push(`--replay: config.locked carries "${path}", which a report may not set`);
        continue;
      }
      if (v === undefined) continue;
      // extractLocked writes every locked leaf into every report, so these must stay replayable (checkReplay accepts them), but a
      // report may not change where or how the server runs or what it is made to fetch: the local setting stays and one warning says so.
      if (path.startsWith("sandbox.") || path === "net.control_url") {
        const mine = getIn(value, path.split("."));
        const same = deepEqual(v, mine);
        if (!same) warnings.push(`--replay: ${path} is not replayed (a report may not change where or how the server runs); the local setting ${JSON.stringify(mine)} stays`);
        continue;
      }
      const cleaned = v === null && leaf.nullable ? null : validateLeaf(leaf, v, path.split("."), rctx);
      if (cleaned === undefined) continue;
      setIn(value, path.split("."), deepClone(cleaned));
      origins.set(pointer(path.split(".")), { layer: "replay", source: "replay" });
    }
    if (replayIssues.length) throw new ConfigError(replayIssues);
  }

  const originAt = (path: string[]): Origin | undefined => {
    for (let n = path.length; n > 0; n--) {
      const o = origins.get(pointer(path.slice(0, n)));
      if (o) return o;
    }
    return undefined;
  };
  const at = (path: string[], fallback = src.layers.project?.display ?? src.projectPath): string => {
    const o = originAt(path);
    return o ? originText(o) : fallback;
  };
  const specCtx = (base: string[]): SpecCtx => ({
    env,
    warnings,
    originOf: (p) => originAt([...base, ...p]),
    where: (p) => at([...base, ...p], at(base)),
    unset: [],
  });

  // ---- cross-field checks on the merged result ----
  const post: string[] = [];
  const server = value.server as Record<string, unknown> | undefined;
  const servers = value.servers as Record<string, Record<string, unknown>> | undefined;
  const declared: NamedServer[] = [];
  const unsetBy = new Map<string, string[]>();
  const hasServers = isPlainObject(servers) && Object.keys(servers).length > 0;
  /**
   * command + url means "start the command and test the URL" (launch). Because layers merge key by key, a url from the
   * environment or another file could silently turn a plain stdio server into an unsandboxed launch. So the two must be
   * set in the same place (one file, the environment, or the flags: --start and --url together).
   */
  const sameLayer = (base: string[], label: string, raw: Record<string, unknown>): boolean => {
    if (!raw.command || !raw.url) return true;
    const c = origins.get(pointer([...base, "command"]));
    const u = origins.get(pointer([...base, "url"]));
    if (!c || !u || c.layer === u.layer) return true;
    post.push(
      `${at([...base, "url"])}: ${label}.command (from ${originText(c)}) and ${label}.url (from ${originText(u)}) are set in different places. ` +
        `Sealmark would start the command and then test whatever answers at the URL, without the stdio sandbox. ` +
        `Set both in the same place (for example --start and --url together, or both in sealmark.yaml), or remove one.`,
    );
    return false;
  };
  /** A relative command typed on the command line is relative to where it was typed, not to the config file. */
  const baseDirFor = (base: string[]): string => (origins.get(pointer([...base, "command"]))?.layer === "flag" ? cwd : dirname(src.projectPath));
  if (server && hasServers) {
    // `server` can come from flags or SEALMARK_SERVER__*; blaming the file for it sends the reader to the wrong place.
    // a map such as headers has an origin per entry, so look at everything under the key
    const originsOf = (k: string): Origin[] => [...origins].filter(([ptr]) => ptr === pointer(["server", k]) || ptr.startsWith(`${pointer(["server", k])}/`)).map(([, o]) => o);
    const elsewhere = Object.keys(server).flatMap((k) => originsOf(k).filter((o) => !["user", "project", "local"].includes(o.layer)));
    if (!elsewhere.length) post.push(`${at(["servers"])}: set either server or servers, not both.`);
    else {
      const who = [...new Set(elsewhere.map((o) => originText(o)))].join(", ");
      post.push(
        `${who} set "server", but ${at(["servers"])} defines "servers" (${Object.keys(servers!).join(", ")}). They cannot be combined. ` +
          `To test one of the file's servers, drop the server flags and use --server <name>; to test the server from the command line, remove "servers" from the file.`,
      );
    }
  }
  else if (hasServers) {
    for (const [name, raw] of Object.entries(servers!)) {
      if (!sameLayer(["servers", name], `servers.${name}`, raw)) continue;
      const sc = specCtx(["servers", name]);
      const spec = toSpec(raw, `servers.${name}`, at(["servers", name, "command"], at(["servers", name])), post, baseDirFor(["servers", name]), sc);
      unsetBy.set(name, sc.unset);
      if (spec) declared.push({ name, spec });
    }
  } else if (server && isPlainObject(server)) {
    const ok = sameLayer(["server"], "server", server);
    // Only --header, --bearer or --start-timeout were given: they add to a server, they do not name one.
    const named = Boolean(server.command || server.url);
    if (ok && !named && src.projectMissing) post.push(noServerHelp(Object.keys(server)));
    const sc = specCtx(["server"]);
    const spec = ok && (named || !src.projectMissing) ? toSpec(server, "server", at(["server", "command"], at(["server", "url"], at(["server"]))), post, baseDirFor(["server"]), sc) : undefined;
    unsetBy.set(String(value.name), sc.unset);
    if (spec) declared.push({ name: String(value.name), spec });
  } else if (src.projectMissing) post.push(noServerHelp([]));
  else post.push(`${src.layers.project?.display ?? src.projectPath}: "server" is required (command + args, or url).`);

  const run = (value.run as { server?: string | null } | undefined)?.server;
  let selected = [...declared];
  if (declared.length && typeof run === "string" && run !== "all" && run !== "") {
    selected = declared.filter((s) => s.name === run);
    if (!selected.length) {
      const hint = didYouMean(run, declared.map((d) => d.name));
      post.push(`${at(["run", "server"])}: no server named "${run}" is configured (configured: ${declared.map((d) => d.name).join(", ")})${hint ? `; did you mean "${hint}"?` : ""}`);
    }
  }
  for (const sel of selected) post.push(...(unsetBy.get(sel.name) ?? []));
  if (post.length) throw new ConfigError(post);

  // `my-server` is only the fallback: with no name given, a report should say what was tested.
  if (origins.get("/name")?.layer === "default" && selected.length === 1 && !hasServers) {
    const sp = selected[0].spec;
    const derived = deriveName(sp, env);
    if (derived) {
      value.name = derived;
      origins.set("/name", { layer: "default", source: `default (from ${sp.command ? "server.command" : "server.url"})` });
      selected[0] = { ...selected[0], name: derived };
      declared[0] = selected[0];
    }
  }

  const packsOrigin = origins.get("/packs");
  const timeoutProbeSec = value.timeout_probe_sec as number;
  const checks = value.checks as Record<string, CheckConfig>;
  const robust = checks["robust-input"];
  const active = Boolean(value.active);
  const packs = value.packs as string[];
  if (packs.includes("exec") && !active) {
    // Only `--pack exec` typed on the command line without --active is a usage error (run.ts says what to type). A profile, file or
    // environment that merely lists exec just does not get it: exec is not a STANDARD_PACK, so the hash and the diff are unaffected.
    if (packsOrigin?.layer === "flag") warnings.push(`the exec pack is listed (${originText(packsOrigin)}) but runs only with --active`);
    else {
      // value (and so the report's config.locked) drops it; the returned `packs` keeps it so doctor can still say why exec does not run.
      value.packs = packs.filter((p) => p !== "exec");
      warnings.push(`the exec pack is listed${packsOrigin ? ` (${originText(packsOrigin)})` : ""} but runs only with --active; it was left out of this run (add --active to run it)`);
    }
  }

  // The README promises that valid-looking arguments go only to targets the harness owns: say so when a config names a real file or directory.
  for (const sel of selected) {
    const label = hasServers ? `servers.${sel.name}` : "server";
    const spec = sel.spec;
    // A misspelled placeholder would reach the server as literal text, and the run would look as if it had used the harness's file.
    for (const u of unknownPlaceholders(spec, label)) warnings.push(unknownPlaceholderWarning(u));
    for (const r of realPaths({ command: spec.command, args: spec.args, env: spec.env })) {
      const what = r.field === "env" ? `${label}.env ${r.key}` : `${label}.args[${r.key}]`;
      warnings.push(`${what} points at a real path on this machine; valid calls may read or write it. Use {sandbox}/<name> to keep the run inside the harness's directory.`);
    }
  }

  const plugins = value.plugins as PluginSpec[];
  const probes = value.probes as ProbeSpec[];

  // ---- round 6: upstream stub, identities, declared scope ----
  const upstream = value.upstream as UpstreamSettings;
  const scope = value.scope as ScopeSettings;
  const rawIdentities = value.identities as { a: string | null; b: string | null };
  const round6: string[] = [];
  const identityValue = (name: "a" | "b"): string | null => {
    const raw = rawIdentities[name];
    if (raw === null || raw === undefined) return null;
    const unset = unsetEnvRefs(raw, env);
    if (unset.length) {
      round6.push(`${at(["identities", name])}: \${${unset[0]}} is not set (used in identities.${name}). Set it as a CI variable, or give a default: \${${unset[0]}:-fallback}`);
      return null;
    }
    return expandEnvRefs(raw, env);
  };
  const identities: IdentitySettings = { a: identityValue("a"), b: identityValue("b") };
  if (identities.a !== null && identities.a === identities.b) {
    round6.push(`${at(["identities", "b"])}: identities.a and identities.b must differ, or passthrough cannot be told from a shared credential`);
  }
  if (scope.tools.length && !scope.allow.length) {
    round6.push(`${at(["scope", "allow"], at(["scope", "tools"]))}: scope.allow is empty: list at least one identifier the server may serve (an entry ending in "." is a prefix)`);
  }
  if (upstream.kind) {
    const usesUpstream = (spec: ServerSpec): boolean =>
      [...specParts(spec), ...(spec.files ?? []).flatMap((f) => [f.path, f.content])].some((p) => p.includes("{upstream}"));
    for (const sel of selected) {
      const label = hasServers ? `servers.${sel.name}` : "server";
      if (sel.spec.url && !sel.spec.command) {
        round6.push(`${at(["upstream", "kind"])}: the upstream stub needs a server Sealmark starts (server.command + server.url, or a stdio command); ${label} is a url-only server that is already running`);
      } else if (!usesUpstream(sel.spec)) {
        round6.push(`${at(["upstream", "kind"])}: upstream.kind is set but ${label}.command/args/env/url/headers never use {upstream}: the server would not talk to the stub`);
      }
    }
  }
  const stdioSelected = selected.some((s) => !s.spec.url);
  const mentionsUpstream = (p: ProbeSpec): string[] => {
    const out: string[] = [];
    const stub = (e: ProbeSpec["expect"] | undefined) => e?.upstream !== undefined;
    if (p.upstream?.reply !== undefined) out.push("upstream.reply");
    if (stub(p.expect) || (p.cases ?? []).some((c) => stub(c.expect))) out.push("expect.upstream");
    return out;
  };
  const rulesCanEcho = (): boolean => JSON.stringify([upstream.responses, upstream.default_reply]).includes("{upstream_token}");
  probes.forEach((p, i) => {
    const who = `probes[${i}]${p.id ? ` (${p.id})` : ""}`;
    if (p.identity !== undefined && stdioSelected) round6.push(`${at(["probes"])}: ${who}: identity needs an HTTP server whose headers use {bearer}`);
    const need = mentionsUpstream(p);
    if (need.length && !upstream.kind) round6.push(`${at(["probes"])}: ${who}: ${need.join(" and ")} needs upstream.kind; set upstream.kind: http (or pass --upstream)`);
    const echoes = [p.expect, ...(p.cases ?? []).map((c) => c.expect)].some((e) => e?.upstream?.token_echoed !== undefined);
    if (echoes && !JSON.stringify(p.upstream?.reply ?? null).includes("{upstream_token}") && !rulesCanEcho()) {
      round6.push(`${at(["probes"])}: ${who}: expect.upstream.token_echoed needs an upstream.reply with {upstream_token} (on the probe, or in upstream.responses)`);
    }
  });
  if (round6.length) throw new ConfigError(round6);

  const integrity = evaluateIntegrity({ value, origins, profile: profileName, chain: chain.map((c) => c.name), plugins, probes });

  return {
    schemaVersion: value.schema_version as number,
    name: String(value.name),
    version: String(value.version),
    profile: profileName,
    profileChain: chain.map((c) => c.name),
    server: selected[0].spec,
    servers: selected,
    serverNames: declared.map((d) => d.name),
    ...(Array.isArray(value.sql_tools) ? { sqlTools: value.sql_tools as SqlTool[] } : {}),
    // A replayed report's pack list is the report's own record of what ran, not a list the user chose: it must not stop the custom pack from
    // being added again when the user's own probes with a check are declared (run.ts). exec cannot be replayed without --active.
    packs: packsOrigin?.layer === "replay" ? (value.packs as string[]) : packs,
    packsExplicit: Boolean(packsOrigin && packsOrigin.layer !== "default" && packsOrigin.layer !== "replay" && packsOrigin.source !== "profile:standard"),
    timeoutProbeSec,
    hangMs: robust.hang_ms ?? Math.max(2000, timeoutProbeSec * 1000),
    checks,
    sandbox: value.sandbox as SandboxSettings,
    tools: value.tools as { include: string[]; exclude: string[]; overrides: Record<string, ToolOverride> },
    timeouts: value.timeouts as { connect_ms: number; call_ms: number; probe_ms: number },
    // retries.call is retired (deprecated and ignored); the field stays so run.ts is untouched.
    retries: { call: 0 },
    net: value.net as { control_url: string | null; allow_dns: boolean },
    output: value.output as OutputSettings,
    plugins,
    probes,
    sqlite: value.sqlite as { engine: "sqlite" | "duckdb" | null },
    db: value.db as { embedded: boolean | null; pg: string | null },
    upstream,
    scope,
    identities,
    notCoveredExtra: (value.notCovered as { extra: string[] }).extra,
    active,
    yes: Boolean(value.yes),
    value,
    origins: Object.fromEntries(origins) as Record<string, Origin>,
    integrity,
    warnings,
    files: src.files,
    env,
    cwd,
    ...(src.layers.project ? { configPath: src.projectPath } : {}),
  };
}

/** The shipped 0.1 view of the configuration (name, version, one server, sql_tools, explicit packs) for code that predates EffectiveConfig. */
export function toSealmarkConfig(cfg: EffectiveConfig): SealmarkConfig {
  return {
    name: cfg.name,
    version: cfg.version,
    server: cfg.server,
    ...(cfg.sqlTools ? { sql_tools: cfg.sqlTools } : {}),
    ...(cfg.packsExplicit ? { packs: cfg.packs as PackId[] } : {}),
  };
}

// ---- profiles listing ----

export interface ProfileSummary {
  name: string;
  shipped: boolean;
  extends?: string;
  description?: string;
  /** Would a run with just this profile be STANDARD? */
  standard: boolean;
  /** Why not (locked-leaf differences, dropped packs, profile rule). */
  reasons: DiffEntry[];
  /** Every setting that differs from the standard profile. */
  diff: { path: string; standard: unknown; profile: unknown }[];
}

/** Shipped profiles and the user's own, each with its difference from `standard`. */
export function describeProfiles(userProfiles: ReadonlyMap<string, ProfileRecord> = new Map()): ProfileSummary[] {
  const std = standardMerged();
  const names = [...SHIPPED_PROFILES, ...userProfiles.keys()];
  return names.map((name) => {
    const issues: string[] = [];
    const chain = resolveChain(name, userProfiles, issues);
    if (issues.length) throw new ConfigError(issues);
    const m = mergeChain(chain);
    const rec = userProfiles.get(name) ?? shippedProfile(name);
    const diff = SCHEMA.filter((l) => l.default !== undefined && !l.path.includes("*") && !l.deprecated)
      .map((l) => ({ path: l.path, standard: getIn(std.value, l.path.split(".")), profile: getIn(m.value, l.path.split(".")) }))
      .filter((d) => JSON.stringify(d.standard) !== JSON.stringify(d.profile));
    const integ = evaluateIntegrity({ value: m.value, origins: m.origins, profile: name, chain: chain.map((c) => c.name), plugins: [], probes: [] });
    return { name, shipped: rec.shipped, extends: rec.extends, description: rec.description, standard: integ.standard, reasons: integ.standardDiff, diff };
  });
}

/** User-defined profiles visible from `opts` (user file, project file, local file). */
export function loadUserProfiles(opts: LoadOptions): Map<string, ProfileRecord> {
  const issues: string[] = [];
  const src = readFiles(opts, resolve(opts.cwd), issues);
  if (issues.length) throw new ConfigError(issues);
  return src.userProfiles;
}
