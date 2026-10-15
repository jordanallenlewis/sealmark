import { existsSync, statSync } from "node:fs";
import type { ServerSpec } from "../types.js";
import { didYouMean } from "./util.js";

/** Database placeholders: filled per role when the db pack runs. */
const DB_KEYS = new Set(["host", "port", "user", "password", "database", "role"]);
/**
 * Harness-owned targets (sandbox, listener, fixtures, the upstream stub, caller identities). `{dir}` is an alias of `{sandbox}`;
 * `{bearer}` is `{bearer:a}`. `{upstream_token}` is not listed: it exists only inside an upstream reply body.
 */
export const HARNESS_KEYS = ["sandbox_home", "sandbox", "canary", "listener", "token", "sqlite_path", "duckdb_path", "dir", "upstream", "bearer:a", "bearer:b", "bearer"];

const ALL_SOURCE = `\\{(dsn(?::[a-z_]+)?|host|port|user|password|database|role|${HARNESS_KEYS.join("|")})\\}`;
const DB_SOURCE = "\\{(dsn(?::[a-z_]+)?|host|port|user|password|database|role)\\}";

/** Fresh global regexes (a shared /g regex keeps lastIndex state). */
export const allPlaceholders = () => new RegExp(ALL_SOURCE, "g");
export const dbPlaceholders = () => new RegExp(DB_SOURCE, "g");

export const ROLE_NAMES = ["analyst", "support", "admin"];

export interface TemplateCtx {
  /** Values for {dsn}, {host}, {port}, {user}, {password}, {database}, {role} for the role being tested, and for the harness placeholders {sandbox}, {sandbox_home}, {canary}, {listener}, {token}, {sqlite_path}, {duckdb_path}, {dir}, {upstream}, {bearer}, {bearer:a}, {bearer:b}. */
  vars: Record<string, string>;
  /** Per-role DSNs for {dsn:analyst}, {dsn:support}, {dsn:admin}. */
  dsns: Record<string, string>;
  /** When given, `${VAR}` and `${VAR:-default}` references are filled from it. */
  env?: Record<string, string | undefined>;
}

/** Looks a variable up the way Windows does: exact name first, then case-insensitive. */
function envLookup(env: Record<string, string | undefined>, name: string): string | undefined {
  if (env[name] !== undefined) return env[name];
  const key = Object.keys(env).find((k) => k.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : env[key];
}

const ENV_REF = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;

export function expandEnvRefs(s: string, env: Record<string, string | undefined>): string {
  return s.replace(ENV_REF, (_m, name: string, dflt: string | undefined) => envLookup(env, name) ?? dflt ?? "");
}

/** Names of the `${VAR}` references in `s` that are not set and have no `:-default`. `${VAR:-}` is the explicit way to allow empty. */
export function unsetEnvRefs(s: string, env: Record<string, string | undefined>): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(ENV_REF)) if (m[2] === undefined && envLookup(env, m[1]) === undefined && !out.includes(m[1])) out.push(m[1]);
  return out;
}

/**
 * Fills placeholders. The database ones keep the shipped behaviour (unknown becomes empty). A harness
 * placeholder the caller did not supply is left as written so a missing sandbox is visible instead of becoming "".
 */
export function expand(s: string, ctx: TemplateCtx): string {
  const out = s.replace(allPlaceholders(), (m, key: string) => {
    if (key.startsWith("dsn:")) return ctx.dsns[key.slice(4)] ?? "";
    if (key === "dsn" || DB_KEYS.has(key)) return ctx.vars[key] ?? "";
    return ctx.vars[key] ?? (key === "dir" ? ctx.vars.sandbox : key === "bearer" ? ctx.vars["bearer:a"] : undefined) ?? m;
  });
  return ctx.env ? expandEnvRefs(out, ctx.env) : out;
}

export function specParts(spec: ServerSpec): string[] {
  return [spec.command ?? "", spec.url ?? "", ...(spec.args ?? []), ...Object.values(spec.env ?? {}), ...Object.values(spec.headers ?? {})];
}

/** True when the spec uses a database placeholder. This is the gate for starting Postgres, so harness placeholders do not count. */
export function usesPlaceholders(spec: ServerSpec): boolean {
  return specParts(spec).some((p) => dbPlaceholders().test(p));
}

/** Every placeholder key used in the spec (`dsn`, `dsn:analyst`, `sandbox`, ...). */
export function placeholdersUsed(spec: ServerSpec): Set<string> {
  const keys = new Set<string>();
  for (const part of specParts(spec)) for (const m of part.matchAll(allPlaceholders())) keys.add(m[1]);
  return keys;
}

const SECRET_NAME = /key|token|secret|passw|auth|credential|cookie|bearer|dsn|private|conn(?:ection)?[_-]?(?:str|string|url|uri)|(?:^|[^a-z])(?:pat|pwd|sas)(?:[^a-z]|$)/i;
export const looksSecret = (name: string) => SECRET_NAME.test(name);
const hasPlaceholder = (v: string) => allPlaceholders().test(v) || /\$\{[A-Za-z_]/.test(v);

/**
 * Well-known credential shapes, recognised by value so a secret under an innocent name (MY_PAT, DATABASE_URL) is still
 * hidden: GitHub, npm, GitLab, Slack, AWS, Google and OpenAI-style keys, JWTs, `password=...` pairs inside a connection
 * string, and long unbroken blobs of hex or base64 that mix letters and digits.
 */
const SECRET_SHAPES: readonly RegExp[] = [
  /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{16,})/,
  /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/,
  /(?:^|[\s;&?,])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|sslpassword)\s*=\s*[^\s;&,]+/i,
  /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_+=-]{32,}$/,
];
/** True when the value itself looks like a credential, whatever it is called. */
export const secretShaped = (value: string): boolean => SECRET_SHAPES.some((re) => re.test(value));

/**
 * What is shown for a configured value. URL credentials (`user:password@`) are dropped from any value, whatever the name;
 * a value under a secret-looking name, or shaped like a credential, is hidden unless it is only a placeholder or an
 * environment reference.
 */
export const redactValue = (name: string, value: string): string => {
  const shown = stripUserinfo(value);
  if (hasPlaceholder(shown)) return shown;
  return looksSecret(name) || secretShaped(shown) ? "<redacted>" : shown;
};

/** Query parameters that carry a credential even though looksSecret does not match the name (a signed URL's `sig`). */
const SECRET_QUERY_NAME = /^(?:sig|signature)$/i;

/** Replaces the value of a secret-looking query parameter (`?token=...&api_key=...`) with <redacted>. A placeholder or `${VAR}` value stays. */
const maskQuerySecrets = (url: string): string =>
  url.replace(/([?&])([^=&#\s]+)=([^&#\s]*)/g, (m, sep: string, name: string, value: string) => {
    if (!value || hasPlaceholder(value) || !(looksSecret(name) || SECRET_QUERY_NAME.test(name))) return m;
    return `${sep}${name}=<redacted>`;
  });

/** Drops user:password@ from a URL and hides the value of secret-looking query parameters; the rest is shown as written. */
export const stripUserinfo = (url: string): string => maskQuerySecrets(url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]*@/i, "$1"));

/** An argument that would not survive being pasted into a shell as one word is quoted, so the shown command line is unambiguous. */
const quoteArg = (a: string | undefined): string => (a !== undefined && /[\s<>"'|&;]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : String(a));

/**
 * The exact configuration, safe to print: placeholders stay unexpanded. A literal value under a
 * secret-looking name (an API key typed straight into the file) is replaced by <redacted> so a
 * shared report never carries it. HTTP headers are listed under "header:<Name>" in env.
 */
export function displaySpec(spec: ServerSpec): { command: string; env: Record<string, string> } {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(spec.env ?? {})) env[k] = redactValue(k, v);
  for (const [k, v] of Object.entries(spec.headers ?? {})) env[`header:${k}`] = redactValue(k, v);
  const command = spec.url ? stripUserinfo(spec.url) : [spec.command, ...(spec.args ?? [])].map(quoteArg).join(" ");
  return { command, env };
}

// ---------------------------------------------------------------------------------------------------------
// Real paths: values that name a file or directory of this machine (shared by `init` and the config warnings)
// ---------------------------------------------------------------------------------------------------------

/** An absolute POSIX or Windows path. */
export const ABS_PATH = /^(?:[A-Za-z]:[\\/]|\/)/;
/** Environment variables that name directories the program needs for itself, not data it serves. */
export const SYSTEM_ENV = /^(PATH|PATHEXT|HOME|USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|TMPDIR|NODE_PATH|PYTHONPATH|PYTHONHOME|VIRTUAL_ENV|JAVA_HOME|GOPATH|CARGO_HOME|XDG_.*|SYSTEMROOT|WINDIR|PROGRAMFILES.*)$/i;
/** Launcher options whose value is where the launcher itself runs, not what the server serves. */
export const LAUNCHER_DIR_FLAGS = new Set(["--directory", "--project", "--cwd", "-C", "--prefix", "--from", "--with-requirements", "--python"]);
/** A program the launcher runs (the server's own entry point), not data it serves. */
const PROGRAM_FILE = /\.(?:[cm]?[jt]s|py|rb|jar|exe|cmd|bat|sh|dll|php|pl)$/i;
/** Credential and certificate files belong to the machine; the harness cannot own a replacement. */
export const CREDENTIAL_ENV = /(CERT|SSL|TLS|CA_?BUNDLE|CREDENTIAL|KEY_?FILE|SECRET|TOKEN)/i;

/** Splits `--db=/x/y.db` into its flag prefix (`--db=`) and value. */
export function splitFlag(v: string): [string, string] {
  const m = /^(--?[\w.-]+=)(.*)$/s.exec(v);
  return m ? [m[1], m[2]] : ["", v];
}

export interface RealPath {
  /** `args[2]` or `env.MEMORY_FILE_PATH`. */
  id: string;
  field: "args" | "env";
  /** The env variable name, or the argument index as text. */
  key: string;
  path: string;
}

/** Interpreters that take the program they run as their first argument: that argument is the server's own entry point, not data it serves. */
const LAUNCHER = /^(?:node|nodejs|python[\d.]*|py|pypy[\d.]*|deno|bun|ruby|perl|php|tsx|ts-node)(?:\.exe)?$/i;
const commandName = (command: string | undefined): string => (command ?? "").replace(/\\/g, "/").split("/").pop() ?? "";

/** True for a file the user could run (an extensionless launcher or binary): a program is not data. Never true on Windows, where the extension says so (PROGRAM_FILE). */
export function isExecutableFile(p: string): boolean {
  if (process.platform === "win32") return false;
  try {
    return existsSync(p) && statSync(p).isFile() && (statSync(p).mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

/**
 * Absolute paths in a server's arguments and environment that the harness does not own: not a launcher directory flag's value,
 * not a system variable, not the program being run (an executable file, or the first argument of a `node`/`python` launcher),
 * and nothing that already holds a placeholder (`{sandbox}/x`, `${HOME}/x`).
 */
export function realPaths(spec: { command?: string; args?: readonly string[]; env?: Readonly<Record<string, string>> }, isExecutable: (p: string) => boolean = isExecutableFile): RealPath[] {
  const out: RealPath[] = [];
  const holdsPlaceholder = (v: string) => /\$?\{[^}]*\}/.test(v);
  const args = spec.args ?? [];
  // The program a launcher runs is the first argument that is not an option.
  const program = LAUNCHER.test(commandName(spec.command)) ? args.findIndex((a) => !a.startsWith("-")) : -1;
  args.forEach((a, i) => {
    if (holdsPlaceholder(a)) return;
    const [flag, path] = splitFlag(a);
    if (!ABS_PATH.test(path) || PROGRAM_FILE.test(path)) return;
    if (!flag && i === program) return;
    if (flag && LAUNCHER_DIR_FLAGS.has(flag.slice(0, -1))) return;
    if (!flag && i > 0 && LAUNCHER_DIR_FLAGS.has(args[i - 1])) return;
    if (isExecutable(path)) return;
    out.push({ id: `args[${i}]`, field: "args", key: String(i), path });
  });
  for (const [k, v] of Object.entries(spec.env ?? {})) {
    if (SYSTEM_ENV.test(k) || holdsPlaceholder(v) || !ABS_PATH.test(v) || PROGRAM_FILE.test(v) || isExecutable(v)) continue;
    out.push({ id: `env.${k}`, field: "env", key: k, path: v });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// Misspelled placeholders
// ---------------------------------------------------------------------------------------------------------

/** A `{word}` or `{dsn:role}` that is not preceded by `$` (a `${VAR}` reference is the environment's, not the harness's). */
const BRACE_WORD = /(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z0-9_]+)?)\}/g;
/** Every spelling the harness fills, for the did-you-mean: the database keys, `dsn`, the per-role DSNs and the harness keys. */
const KNOWN_PLACEHOLDERS = [...DB_KEYS, "dsn", ...ROLE_NAMES.map((r) => `dsn:${r}`), ...HARNESS_KEYS];

export interface UnknownPlaceholder {
  /** `server.args[2]`, `server.env KEY`, `server.command`, `server.url` or `server.headers NAME`. */
  where: string;
  word: string;
  /** The closest known placeholder, when one is within two edits. */
  suggestion?: string;
}

/** `{word}` texts that are not a placeholder the harness fills (a misspelled `{sqlite_pth}`), in `command`, `args`, `env`, `url` and `headers`. */
export function unknownPlaceholders(spec: Pick<ServerSpec, "command" | "args" | "env" | "url" | "headers">, label = "server"): UnknownPlaceholder[] {
  const out: UnknownPlaceholder[] = [];
  const scan = (value: string, where: string): void => {
    for (const m of value.matchAll(BRACE_WORD)) {
      const word = m[1];
      if (KNOWN_PLACEHOLDERS.includes(word)) continue;
      const suggestion = didYouMean(word, KNOWN_PLACEHOLDERS);
      out.push({ where, word, ...(suggestion ? { suggestion } : {}) });
    }
  };
  if (spec.command) scan(spec.command, `${label}.command`);
  if (spec.url) scan(spec.url, `${label}.url`);
  (spec.args ?? []).forEach((a, i) => scan(a, `${label}.args[${i}]`));
  for (const [k, v] of Object.entries(spec.env ?? {})) scan(v, `${label}.env ${k}`);
  for (const [k, v] of Object.entries(spec.headers ?? {})) scan(v, `${label}.headers ${k}`);
  return out;
}

/** The warning text for one unknown placeholder: a warning, not an error, because a server may take braces of its own. */
export const unknownPlaceholderWarning = (u: UnknownPlaceholder): string =>
  `unknown placeholder {${u.word}} in ${u.where}${u.suggestion ? `; did you mean {${u.suggestion}}?` : ""} the server will receive the literal text`;
