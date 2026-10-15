import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { dirname, isAbsolute, join } from "node:path";
import { stringify } from "yaml";
import { SCHEMA_HINT, SCHEMA_MODELINE, initTemplate } from "../config.js";
import { SCHEMA_VERSION } from "./model.js";
import {
  CLIENT_LABELS,
  describeServer,
  fullSpec,
  importManual,
  scanClients,
  selectServers,
  uniqueNames,
  type ClientId,
  type ImportEnv,
  type ImportedServer,
  type LocalOverrides,
  type ScanResult,
} from "./import.js";
import { ABS_PATH, CREDENTIAL_ENV, LAUNCHER_DIR_FLAGS, realPaths, SYSTEM_ENV, splitFlag, stripUserinfo } from "./placeholders.js";

/**
 * `sealmark init`: pick servers from the MCP clients on this machine (or a one-liner), offer to point them at
 * harness-owned targets, and write sealmark.yaml, sealmark.local.yaml (secrets, machine paths) and .gitignore.
 *
 * Everything that decides something is a pure function (suggestReplacements, applySuggestions, planInit,
 * ensureGitignore, splitCommandLine) and tests call them without a terminal. `runInit` is the thin driver that
 * asks questions through a WizardIO; cli.ts supplies `readlineIO()` on a TTY and nothing on `--yes`.
 */

export class InitError extends Error {}

// ---------------------------------------------------------------------------------------------------------
// Suggested replacements: let the harness own the target
// ---------------------------------------------------------------------------------------------------------

export type SuggestionKind = "sandbox" | "sandbox-file" | "dsn" | "sqlite" | "duckdb";

export interface Suggestion {
  /** Unique within a server: `args[2]`, `env.DATABASE_URL`. */
  id: string;
  serverId: string;
  kind: SuggestionKind;
  target: { field: "arg"; index: number } | { field: "env"; key: string };
  /** What is there now, safe to print (credentials removed). */
  shown: string;
  /** The placeholder that replaces it, for display. */
  placeholder: string;
  /** The complete new value (`--db={sqlite_path}`). */
  value: string;
  reason: string;
}

export interface SuggestOptions {
  /** Is this path an existing directory? Defaults to the file system. */
  isDir?: (path: string) => boolean;
  /** Is this path an existing file? Defaults to the file system. */
  isFile?: (path: string) => boolean;
}

const nodeIsDir = (p: string) => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};

const DSN = /^(--?[\w.-]+=)?(postgres(?:ql)?:\/\/\S+)$/i;
const SQLITE_EXT = /\.(?:sqlite3?|db3?|s3db)$/i;
const DUCKDB_EXT = /\.(?:duckdb|ddb)$/i;

/** The flag whose value is a database file: `--db-path x`, `--database=x`, `--db x`. */
const DB_FLAG = /^--?(?:db|database|(?:db|database|sqlite)[-_]?(?:path|file)|sqlite)$/i;
/** A data file by extension: the harness gives the server its own copy to read and write. */
const DATA_FILE = /\.(?:jsonl?|ndjson|yaml|yml|toml|csv|txt|log|md|sqlite3?|db3?)$/i;
/** Environment variables that name a file or store the server reads or writes. */
const DATA_ENV = /(FILE|PATH|STORE|DATA|DB)/i;
/** The flag whose value is a git repository: `--repository x`, `--repo=x`. */
const REPO_FLAG = /^--?(?:repository|repo)$/i;
const baseOf = (p: string) => p.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";

/**
 * Looks for values that point the server at something real: a Postgres connection string, a SQLite or DuckDB
 * file, a directory. For each it offers the placeholder under which the harness supplies a target it owns.
 * Looks at the full configuration (secrets included) but only ever returns redacted text for display.
 */
export function suggestReplacements(s: ImportedServer, o: SuggestOptions = {}): Suggestion[] {
  const isDir = o.isDir ?? nodeIsDir;
  const isFile = o.isFile ?? ((p: string) => existsSync(p) && !nodeIsDir(p));
  const spec = fullSpec(s);
  const out: Suggestion[] = [];
  const consider = (value: string, target: Suggestion["target"], id: string, prevArg: string | undefined) => {
    const dsn = DSN.exec(value);
    if (dsn) {
      out.push({
        id,
        serverId: s.id,
        kind: "dsn",
        target,
        shown: stripUserinfo(dsn[2]),
        placeholder: "{dsn}",
        value: `${dsn[1] ?? ""}{dsn}`,
        reason: "the db pack seeds its own Postgres and fills {dsn} for each test role; a real connection string would point the server at your database",
      });
      return;
    }
    const [flag, path] = splitFlag(value);
    // A git server's repository: the git pack builds a repository at {sandbox}/repo, so that is what the argument becomes (a bare {sandbox} is not a repository).
    if (REPO_FLAG.test(flag ? flag.slice(0, -1) : (prevArg ?? "")) && path !== "" && !path.includes("{") && !/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
      out.push({
        id,
        serverId: s.id,
        kind: "sandbox",
        target,
        shown: path,
        placeholder: "{sandbox}/repo",
        value: `${flag}{sandbox}/repo`,
        reason: "the git pack builds its own repository at {sandbox}/repo and the server is run against that one; your real repository is never touched",
      });
      return;
    }
    const dbFlag = DB_FLAG.test(flag ? flag.slice(0, -1) : (prevArg ?? ""));
    const isUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(path) || path.startsWith(":");
    const sqliteLike = SQLITE_EXT.test(path) || DUCKDB_EXT.test(path);
    // The engine test comes first: a relative `--db-path ./test.db` is as much a real store as an absolute one.
    const dbPath = !sqliteLike && dbFlag && !isUrl && (ABS_PATH.test(path) || /[\\/]/.test(path));
    if (sqliteLike || dbPath) {
      const duck = DUCKDB_EXT.test(path);
      out.push({
        id,
        serverId: s.id,
        kind: duck ? "duckdb" : "sqlite",
        target,
        shown: path,
        placeholder: duck ? "{duckdb_path}" : "{sqlite_path}",
        value: `${flag}${duck ? "{duckdb_path}" : "{sqlite_path}"}`,
        reason: `the sqlite pack generates a seeded ${duck ? "DuckDB" : "SQLite"} file inside the sandbox and fills this placeholder with its path${isFile(path) ? "; your own file is left alone" : ""}`,
      });
      return;
    }
    if (!ABS_PATH.test(path)) return;
    if (!flag && prevArg !== undefined && LAUNCHER_DIR_FLAGS.has(prevArg)) return;
    if (flag && LAUNCHER_DIR_FLAGS.has(flag.slice(0, -1))) return;
    if (isDir(path)) {
      out.push({
        id,
        serverId: s.id,
        kind: "sandbox",
        target,
        shown: path,
        placeholder: "{sandbox}",
        value: `${flag}{sandbox}`,
        reason: "{sandbox} is a disposable directory the harness owns; the fs, git and effects packs run only when the server is confined to it, and your real directory is never touched",
      });
      return;
    }
    // A file the server reads or writes (an existing file, a data-file extension, or a variable that names one).
    const name = baseOf(path);
    const envKey = target.field === "env" ? target.key : undefined;
    const dataByKey = envKey !== undefined && DATA_ENV.test(envKey) && !SYSTEM_ENV.test(envKey);
    if (name && !(envKey !== undefined && CREDENTIAL_ENV.test(envKey)) && (isFile(path) || DATA_FILE.test(path) || dataByKey)) {
      out.push({
        id,
        serverId: s.id,
        kind: "sandbox-file",
        target,
        shown: path,
        placeholder: `{sandbox}/${name}`,
        value: `${flag}{sandbox}/${name}`,
        reason: "a file the server reads or writes: inside the sandbox the harness owns it and your real file is never touched",
      });
    }
  };
  (spec.args ?? []).forEach((a, i) => consider(a, { field: "arg", index: i }, `args[${i}]`, i > 0 ? spec.args![i - 1] : undefined));
  for (const [k, v] of Object.entries(spec.env ?? {})) if (!SYSTEM_ENV.test(k)) consider(v, { field: "env", key: k }, `env.${k}`, undefined);
  // The config allows one engine per server: keep the first sqlite/duckdb suggestion only.
  let engine: SuggestionKind | undefined;
  return out.filter((x) => {
    if (x.kind !== "sqlite" && x.kind !== "duckdb") return true;
    if (engine && engine !== x.kind) return false;
    engine = x.kind;
    return true;
  });
}

/** Package names that mean "talks to a database": `postgres`, `pg`, `mysql`, `...-db`, `...-sql`. SQLite and DuckDB take a file, not a connection string. */
const DB_PACKAGE = /postgres|pg|mysql|db|sql/i;
const FILE_DB_PACKAGE = /sqlite|duckdb/i;

/**
 * For `init --from "<command>"`: a database server whose command carries no connection string and no `{dsn}` yet. Returns what to
 * add, or undefined when the command is not recognisably a database server or already has a DSN, a `{dsn}` or a SQLite path.
 */
export function dsnHint(s: ImportedServer): string | undefined {
  const command = s.spec.command;
  if (!command) return undefined;
  const spec = fullSpec(s);
  const parts = [...(spec.args ?? []), ...Object.values(spec.env ?? {})];
  if (parts.some((p) => DSN.test(p) || /\{(?:dsn(?::[a-z_]+)?|sqlite_path|duckdb_path)\}/.test(p))) return undefined;
  const pkg = (spec.args ?? []).find((a) => !a.startsWith("-")) ?? command;
  if (!DB_PACKAGE.test(pkg) || FILE_DB_PACKAGE.test(pkg)) return undefined;
  return "this looks like a database server and no connection string was given: add --dsn {dsn} (or the env variable it reads) under server.args or server.env; the db pack fills {dsn} for each test role with a Postgres it owns";
}

/** Returns a copy of the server with the accepted suggestions applied. A replaced secret leaves no trace in the local overrides. */
export function applySuggestions(s: ImportedServer, accepted: readonly Suggestion[]): ImportedServer {
  const spec = structuredClone(s.spec);
  const local: LocalOverrides = structuredClone(s.local);
  let routed = [...s.routed];
  for (const a of accepted) {
    if (a.serverId !== s.id) continue;
    if (a.target.field === "arg") {
      const i = a.target.index;
      if (spec.args) spec.args[i] = a.value;
      if (local.args) local.args[i] = a.value;
      routed = routed.filter((r) => r !== `args[${i}]`);
    } else {
      const k = a.target.key;
      if (spec.env) spec.env[k] = a.value;
      if (local.env) delete local.env[k];
      routed = routed.filter((r) => r !== `env.${k}`);
    }
  }
  if (local.args && !routed.some((r) => r.startsWith("args["))) delete local.args;
  if (local.env && !Object.keys(local.env).length) delete local.env;
  return { ...s, spec, local, routed };
}

// ---------------------------------------------------------------------------------------------------------
// Command line splitting for `init --from`
// ---------------------------------------------------------------------------------------------------------

/**
 * Splits a one-line command into words. Single and double quotes group words; a backslash is literal except for
 * `\"` inside double quotes, so Windows paths such as C:\Program Files\nodejs survive when quoted.
 */
export function splitCommandLine(line: string): string[] {
  const words: string[] = [];
  let cur = "";
  let started = false;
  let quote: '"' | "'" | undefined;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = undefined;
      else if (quote === '"' && c === "\\" && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      started = true;
    } else if (/\s/.test(c)) {
      if (started || cur) words.push(cur);
      cur = "";
      started = false;
    } else cur += c;
  }
  if (quote) throw new InitError(`unterminated ${quote} in: ${line}`);
  if (started || cur) words.push(cur);
  return words;
}

/** File names that say nothing about the server: the name comes from the package (or, failing that, its directory). */
const GENERIC_ENTRY = /^(?:index|main|cli|app|mod)(?:\.[cm]?[jt]s|\.py)?$/i;
/** Directory names that only hold build output or sources. */
const OUTPUT_DIR = /^(?:dist|build|out|src|lib|bin|esm|cjs|esm5|esm2015|\.)$/i;

const tidyName = (last: string): string => {
  const bare = last.replace(/@[^@/]+$/, "").replace(/\.[cm]?[jt]s$|\.py$/i, "").replace(/^(?:mcp-)?server-|^mcp-|-mcp(?:-server)?$|-server$/i, "");
  return bare.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "server";
};

/**
 * A readable server name from a launcher line: `npx -y @modelcontextprotocol/server-filesystem` becomes `filesystem`. A program file with a
 * generic name (`dist/index.js`) is named after its package (`pkgName` reads the nearest package.json) or, without one, its directory.
 */
export function guessName(command: string, args: readonly string[], pkgName?: (file: string) => string | undefined): string {
  const pick = args.find((a) => !a.startsWith("-") && !/^\{/.test(a)) ?? command;
  const parts = pick.replace(/\\/g, "/").split("/").filter(Boolean);
  const last = parts.pop() ?? command;
  if (GENERIC_ENTRY.test(last)) {
    const fromPackage = pkgName?.(pick);
    if (fromPackage) return tidyName(fromPackage.split("/").pop() ?? fromPackage);
    const dir = [...parts].reverse().find((d) => !OUTPUT_DIR.test(d) && !/^[A-Za-z]:$/.test(d));
    if (dir) return tidyName(dir);
  }
  return tidyName(last);
}

/** The `name` of the nearest package.json at or above the directory of `file` (up to four levels), through `read`; a scoped name keeps only the part after the slash. */
export function packageNameNear(file: string, read: (path: string) => string | undefined): string | undefined {
  let dir = dirname(file);
  for (let i = 0; i < 4; i++) {
    const text = read(join(dir, "package.json"));
    if (text !== undefined) {
      try {
        const name = (JSON.parse(text) as { name?: unknown }).name;
        if (typeof name === "string" && name) return name;
      } catch {
        /* not JSON: keep looking upward */
      }
    }
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------
// Rendering and the plan
// ---------------------------------------------------------------------------------------------------------

export interface PlannedFile {
  path: string;
  content: string;
  kind: "config" | "local" | "gitignore";
  action: "create" | "overwrite" | "append" | "unchanged";
  /** POSIX file mode; the local file is 0600. */
  mode?: number;
}

export interface InitPlan {
  files: PlannedFile[];
  /** Names of the servers written, in order. */
  serverNames: string[];
  /** Per server, what was moved to the local file (names only). */
  routed: { server: string; items: string[] }[];
  warnings: string[];
}

export interface PlanInput {
  servers: readonly ImportedServer[];
  /** Where sealmark.yaml goes. The local file and .gitignore sit beside it. */
  configPath: string;
  /** Existing .gitignore text, if there is one. */
  gitignore?: string;
  /** Text of the config being replaced, to report `overwrite` instead of `create`. */
  existingConfig?: boolean;
  /** Where the servers came from, for the header comment. */
  source?: string;
  /** Write the `yaml-language-server` $schema modeline. Default true; `runInit` turns it off where the path would not resolve. */
  schemaLine?: boolean;
  /** Comment on each absolute path left in the servers (set by `runInit`, after the replacements were offered). */
  realPathNotes?: boolean;
}

/**
 * The modeline points at `./node_modules/sealmark/schema/sealmark.schema.json`. It is written only when that file exists next to the
 * config being written; anywhere else (npx, a global install, a project that has not installed sealmark yet) the line would be an
 * unresolved reference, so `init` writes the SCHEMA_HINT comment instead. How sealmark was launched (`npm_command`) no longer matters, only
 * whether the file is there.
 */
export function schemaLineWanted(schemaFileInstalled: boolean): boolean {
  return schemaFileInstalled;
}


const specToYaml = (spec: ImportedServer["spec"]) => ({
  ...(spec.command ? { command: spec.command } : {}),
  ...(spec.command ? { args: spec.args ?? [] } : {}),
  ...(spec.url ? { url: spec.url } : {}),
  ...(spec.env && Object.keys(spec.env).length ? { env: spec.env } : {}),
  ...(spec.headers && Object.keys(spec.headers).length ? { headers: spec.headers } : {}),
});

const dump = (v: unknown) => stringify(v, { lineWidth: 0 });

/** Text of sealmark.yaml. Secrets are environment references; machine paths use forward slashes. */
export function renderConfigYaml(servers: readonly ImportedServer[], names: ReadonlyMap<string, string>, o: { source?: string; schemaLine?: boolean; realPathNotes?: boolean } = {}): string {
  const head = [o.schemaLine === false ? SCHEMA_HINT : SCHEMA_MODELINE,`# sealmark.yaml${o.source ? `: written by \`sealmark init\` from ${o.source}` : ""}`, "# Run:  sealmark run     Inspect:  sealmark config show --effective --origins"];
  const notes: string[] = [];
  for (const s of servers) {
    const n = names.get(s.id) ?? s.name;
    for (const w of s.warnings) notes.push(`# note (${n}): ${w}`);
    if (s.routed.length) notes.push(`# note (${n}): values moved to sealmark.local.yaml and replaced here by \${...} references: ${s.routed.join(", ")}`);
    // After the replacements were offered, what is still an absolute path is the user's choice: say what it means.
    for (const r of o.realPathNotes ? realPaths(fullSpec(s)) : []) {
      notes.push(`# note (${n}): ${r.field === "env" ? `server.env ${r.key}` : `server.${r.id}`} points at a real path on this machine; valid calls may read or write it. Use {sandbox}/<name> to keep the run inside the harness's directory`);
    }
    if (s.machineSpecific) notes.push(`# note (${n}): contains an absolute path of this machine; replace it with {sandbox} or a path that exists for your team`);
  }
  const body: Record<string, unknown> = { schema_version: SCHEMA_VERSION };
  if (servers.length === 1) {
    body.name = names.get(servers[0].id) ?? servers[0].name;
    body.server = specToYaml(servers[0].spec);
  } else {
    body.servers = Object.fromEntries(servers.map((s) => [names.get(s.id) ?? s.name, specToYaml(s.spec)]));
  }
  return `${[...head, ...notes].join("\n")}\n\n${dump(body)}`;
}

/** Text of sealmark.local.yaml, or undefined when no server has anything to put there. */
export function renderLocalYaml(servers: readonly ImportedServer[], names: ReadonlyMap<string, string>): string | undefined {
  const has = (l: LocalOverrides) => Boolean(l.args || l.url || (l.env && Object.keys(l.env).length) || (l.headers && Object.keys(l.headers).length));
  const withLocal = servers.filter((s) => has(s.local));
  if (!withLocal.length) return undefined;
  const one = (l: LocalOverrides) => ({ ...(l.url ? { url: l.url } : {}), ...(l.args ? { args: l.args } : {}), ...(l.env ? { env: l.env } : {}), ...(l.headers ? { headers: l.headers } : {}) });
  const body: Record<string, unknown> = { schema_version: SCHEMA_VERSION };
  if (servers.length === 1) body.server = one(withLocal[0].local);
  else body.servers = Object.fromEntries(withLocal.map((s) => [names.get(s.id) ?? s.name, one(s.local)]));
  return [
    "# sealmark.local.yaml: secrets and machine-specific values for sealmark.yaml.",
    "# Written by `sealmark init`, which also adds it to .gitignore. Never commit it or paste it into a report.",
    "# Lists replace across files: an `args` list here replaces the whole list in sealmark.yaml, so edit both when you change arguments.",
    "",
    dump(body),
  ].join("\n");
}

/** Adds entries to .gitignore text without duplicating them or changing its line endings. */
export function ensureGitignore(text: string | undefined, entries: readonly string[]): { text: string; added: string[] } {
  const original = text ?? "";
  const eol = original.includes("\r\n") ? "\r\n" : "\n";
  const lines = original.split(/\r?\n/).map((l) => l.trim());
  const covers = (entry: string) => lines.some((l) => !l.startsWith("#") && !l.startsWith("!") && (l === entry || l === `/${entry}` || l === "*.local.yaml" || l === "sealmark.local.*" || l === "*.local.*"));
  const added = entries.filter((e) => !covers(e));
  if (!added.length) return { text: original, added: [] };
  const prefix = original === "" || original.endsWith("\n") ? "" : eol;
  return { text: `${original}${prefix}${original === "" ? "" : eol}# sealmark: machine-specific values and secrets${eol}${added.join(eol)}${eol}`, added };
}

/** Builds the files `init` would write. Pure: nothing is read or written here. */
export function planInit(input: PlanInput): InitPlan {
  const names = uniqueNames(input.servers);
  const dir = dirname(input.configPath);
  const localPath = join(dir, "sealmark.local.yaml");
  const gitignorePath = join(dir, ".gitignore");
  const files: PlannedFile[] = [];
  const warnings: string[] = [];
  if (!input.servers.length) throw new InitError("no server selected");
  for (const s of input.servers) for (const w of s.warnings) warnings.push(`${names.get(s.id)}: ${w}`);
  files.push({ path: input.configPath, content: renderConfigYaml(input.servers, names, { source: input.source, schemaLine: input.schemaLine, realPathNotes: input.realPathNotes }), kind: "config", action: input.existingConfig ? "overwrite" : "create" });
  const local = renderLocalYaml(input.servers, names);
  if (local) files.push({ path: localPath, content: local, kind: "local", action: "create", mode: 0o600 });
  // The local file is where secrets go later too, so it is ignored whether or not this run wrote one.
  const g = ensureGitignore(input.gitignore, ["sealmark.local.yaml"]);
  files.push({ path: gitignorePath, content: g.text, kind: "gitignore", action: g.added.length ? (input.gitignore === undefined ? "create" : "append") : "unchanged" });
  return {
    files,
    serverNames: input.servers.map((s) => names.get(s.id) ?? s.name),
    routed: input.servers.filter((s) => s.routed.length).map((s) => ({ server: names.get(s.id) ?? s.name, items: s.routed })),
    warnings,
  };
}

export interface FileSink {
  write(path: string, content: string, mode?: number): void;
}

export const nodeSink: FileSink = {
  write(path, content, mode) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, mode === undefined ? {} : { mode });
  },
};

/** Writes the plan. Returns the paths that changed. */
export function writePlan(plan: InitPlan, sink: FileSink = nodeSink): string[] {
  const done: string[] = [];
  for (const f of plan.files) {
    if (f.action === "unchanged") continue;
    sink.write(f.path, f.content, f.mode);
    done.push(f.path);
  }
  return done;
}

// ---------------------------------------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------------------------------------

export interface WizardIO {
  ask(question: string, dflt?: string): Promise<string>;
  /** For `${input:...}` values marked as passwords. Falls back to `ask`. */
  askSecret?(question: string): Promise<string>;
  write(text: string): void;
}

/** Questions on stderr, answers from stdin (node:readline). Call `close()` when done. */
export function readlineIO(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stderr): WizardIO & { close(): void } {
  // Everything readline echoes goes through `echo`, which askSecret switches off while the answer is typed.
  let muted = false;
  const echo = new Writable({
    write(chunk, _enc, cb) {
      if (!muted) output.write(chunk);
      cb();
    },
  });
  const rl = createInterface({ input, output: echo, terminal: Boolean((input as { isTTY?: boolean }).isTTY) });
  // Lines are queued as they arrive: pasted or piped input delivers several at once, before the next question is asked.
  const queue: string[] = [];
  const waiting: ((line: string | undefined) => void)[] = [];
  let ended = false;
  rl.on("line", (l) => {
    const w = waiting.shift();
    if (w) w(l);
    else queue.push(l);
  });
  rl.on("close", () => {
    ended = true;
    for (const w of waiting.splice(0)) w(undefined);
  });
  const line = async (prompt: string): Promise<string> => {
    rl.setPrompt(prompt);
    rl.prompt();
    const l = queue.length ? queue.shift() : ended ? undefined : await new Promise<string | undefined>((res) => waiting.push(res));
    if (l === undefined) throw new InitError("the input ended before every question was answered");
    return l.trim();
  };
  return {
    async ask(q, dflt) {
      const a = await line(`${q}${dflt !== undefined ? ` [${dflt}]` : ""} `);
      return a === "" && dflt !== undefined ? dflt : a;
    },
    async askSecret(q) {
      output.write(`${q} (input is hidden) `);
      muted = true;
      try {
        return await line("");
      } finally {
        muted = false;
        output.write("\n");
      }
    },
    write: (t) => void output.write(t),
    close: () => rl.close(),
  };
}

export interface InitOptions {
  env: ImportEnv;
  configPath: string;
  clients?: readonly ClientId[];
  /** Interactive questions. Absent means non-interactive: the `--yes` path. */
  io?: WizardIO;
  /** Server ids, `client/name` or names to import (`all` for every one). Required non-interactively when several are found. */
  select?: readonly string[];
  /** `init --from "<command line>"` and `--from-url`. */
  fromCommand?: string;
  fromUrl?: string;
  /** Answers for `${input:id}` variables. */
  inputs?: Record<string, string>;
  force?: boolean;
  /** Plan only: write nothing. */
  dryRun?: boolean;
  suggest?: SuggestOptions;
  /** Read and write hooks for tests. */
  readText?: (path: string) => string | undefined;
  sink?: FileSink;
}

export interface InitOutcome {
  plan?: InitPlan;
  written: string[];
  selected: ImportedServer[];
  /** Replacements that were applied, for the summary. */
  applied: Suggestion[];
  /** Nothing to import: sealmark.yaml is the commented template. */
  template: boolean;
  scan?: ScanResult;
  /** Lines for stderr. */
  messages: string[];
}

const yes = (a: string) => /^(y|yes|j|ja|1|true)$/i.test(a.trim());
const nodeRead = (p: string) => {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return undefined;
  }
};

/**
 * Runs `init`. With `io` it asks (which servers, which replacements, `${input:...}` values); without it, it takes the
 * defaults: one server when only one exists, every suggested replacement accepted (all of them point at targets the
 * harness owns), unanswered inputs left as environment references.
 */
export async function runInit(o: InitOptions): Promise<InitOutcome> {
  const read = o.readText ?? nodeRead;
  const sink = o.sink ?? nodeSink;
  const messages: string[] = [];
  const say = (s: string) => {
    messages.push(s);
    o.io?.write(`${s}\n`);
  };
  const exists = read(o.configPath) !== undefined;
  if (exists && !o.force) throw new InitError(`${o.configPath} already exists. Use --force to overwrite it.`);
  const localPath = join(dirname(o.configPath), "sealmark.local.yaml");
  const schemaLine = schemaLineWanted(read(join(dirname(o.configPath), "node_modules", "sealmark", "schema", "sealmark.schema.json")) !== undefined);
  const inputs: Record<string, string> = { ...o.inputs };

  let selected: ImportedServer[] = [];
  let scan: ScanResult | undefined;
  let source: string;
  const manual = o.fromCommand !== undefined || o.fromUrl !== undefined;

  if (o.fromCommand !== undefined && o.fromUrl !== undefined) throw new InitError("use either --from or --from-url, not both");
  if (o.fromCommand !== undefined) {
    const words = splitCommandLine(o.fromCommand);
    if (!words.length) throw new InitError("--from needs a command, for example --from \"npx -y @modelcontextprotocol/server-filesystem {sandbox}\"");
    selected = [importManual({ name: guessName(words[0], words.slice(1), (file) => (isAbsolute(file) ? packageNameNear(file, read) : undefined)), command: words[0], args: words.slice(1) }, o.env, inputs)];
    source = "the command line";
  } else if (o.fromUrl !== undefined) {
    let host = "server";
    try {
      host = new URL(o.fromUrl).hostname.replace(/^www\./, "") || "server";
    } catch {
      throw new InitError(`--from-url needs a full URL such as https://example.com/mcp, got "${o.fromUrl}"`);
    }
    selected = [importManual({ name: host, url: o.fromUrl }, o.env, inputs)];
    source = "the command line";
  } else {
    scan = scanClients(o.env, { clients: o.clients, inputs });
    for (const f of scan.files) if (f.error) say(`skipped ${f.path}: ${f.error}`);
    const found = scan.servers;
    if (!found.length) {
      const where = scan.files.filter((f) => f.found).map((f) => f.path);
      say(where.length ? `no usable MCP server in ${where.join(", ")}; writing the template` : "no MCP client configuration found; writing the template");
      const files: PlannedFile[] = [{ path: o.configPath, content: initTemplate(schemaLine), kind: "config", action: exists ? "overwrite" : "create" }];
      const written = o.dryRun ? [] : writePlan({ files, serverNames: [], routed: [], warnings: [] }, sink);
      return { plan: { files, serverNames: [], routed: [], warnings: [] }, written, selected: [], applied: [], template: true, scan, messages };
    }
    if (o.select?.length) {
      const r = selectServers(found, o.select);
      if (r.problems.length) throw new InitError(`${r.problems.join("; ")}. Servers found: ${found.map((s) => s.id).join(", ")}`);
      selected = r.chosen;
    } else if (found.length === 1) selected = [found[0]];
    else if (o.io) {
      say("MCP servers found:");
      found.forEach((s, i) => say(`  ${String(i + 1).padStart(2)}. ${describeServer(s)}`));
      const a = await o.io.ask("Which should sealmark grade? Numbers separated by commas, or \"all\":", found.length ? "1" : "all");
      const picks = a.trim().toLowerCase() === "all" ? found : a.split(/[\s,]+/).filter(Boolean).map((n) => found[Number(n) - 1]);
      if (!picks.length || picks.some((p) => !p)) throw new InitError(`"${a}" is not a valid choice`);
      selected = [...new Set(picks)];
    } else {
      // No terminal, or --yes: take the defaults, which for several servers is all of them (the `servers:` map holds many). Say so.
      selected = found;
      say(`${found.length} MCP servers found (${found.map((s) => s.id).join(", ")}); no terminal to ask, so all of them are taken. Choose some with --server <name> (comma separated).`);
    }
    source = [...new Set(selected.map((s) => CLIENT_LABELS[s.client]))].join(" and ");

    // Variables the client asks for at start-up: ask once, then translate again with the answers.
    const need = [...new Map(selected.flatMap((s) => s.inputs).map((d) => [d.id, d])).values()].filter((d) => inputs[d.id] === undefined);
    if (need.length && o.io) {
      for (const d of need) {
        const q = `Value for ${d.id}${d.description ? ` (${d.description})` : ""}; it goes to sealmark.local.yaml:`;
        inputs[d.id] = d.password && o.io.askSecret ? await o.io.askSecret(q) : await o.io.ask(q);
      }
      const again = scanClients(o.env, { clients: o.clients, inputs });
      selected = selected.map((s) => again.servers.find((x) => x.id === s.id) ?? s);
    }
  }

  // Offer harness-owned targets for real directories, databases and connection strings.
  const applied: Suggestion[] = [];
  // `--from` and `--from-url` get the same pass as a client import: with --yes (no questions) every suggestion is taken, as it is for an import.
  selected = await Promise.all(
    selected.map(async (s) => {
      const sugg = suggestReplacements(s, o.suggest);
      const take: Suggestion[] = [];
      for (const x of sugg) {
        let ok = true;
        if (o.io) ok = yes(await o.io.ask(`${s.name}: replace ${x.shown} with ${x.placeholder}? (${x.reason}) [Y/n]`, "y"));
        if (ok) take.push(x);
      }
      applied.push(...take);
      return applySuggestions(s, take);
    }),
  );
  for (const x of applied) say(`${x.serverId}: ${x.id} ${x.shown} -> ${x.placeholder}`);

  // `init --from "<command>"` for a database server: say how to let the db pack grade it (asked, never added silently: the flag name is the server's).
  if (manual) {
    selected = await Promise.all(
      selected.map(async (s) => {
        const hint = dsnHint(s);
        if (!hint) return s;
        say(`${s.name}: ${hint}`);
        if (o.io && yes(await o.io.ask(`${s.name}: add "--dsn {dsn}" to its arguments? [y/N]`, "n"))) {
          return { ...s, spec: { ...s.spec, args: [...(s.spec.args ?? []), "--dsn", "{dsn}"] } };
        }
        return s;
      }),
    );
  }

  const plan = planInit({
    servers: selected,
    configPath: o.configPath,
    gitignore: read(join(dirname(o.configPath), ".gitignore")),
    existingConfig: exists,
    source,
    schemaLine,
    realPathNotes: true,
  });
  const localExists = read(localPath) !== undefined;
  const localFile = plan.files.find((f) => f.kind === "local");
  if (localFile && localExists && !o.force) throw new InitError(`${localPath} already exists. Use --force to overwrite it.`);
  if (localFile && localExists) localFile.action = "overwrite";
  const written = o.dryRun ? [] : writePlan(plan, sink);
  for (const f of plan.files) if (f.action !== "unchanged") say(`${o.dryRun ? "would write" : "wrote"} ${f.path}`);
  for (const r of plan.routed) say(`${r.server}: kept out of ${o.configPath}: ${r.items.join(", ")} (see sealmark.local.yaml; it is in .gitignore)`);
  for (const w of plan.warnings) say(`warning: ${w}`);
  say(`Next: sealmark doctor (it lists what to add to the config)   then   sealmark init --probes --write --yes   then   sealmark run`);
  return { plan, written, selected, applied, template: false, scan, messages };
}
