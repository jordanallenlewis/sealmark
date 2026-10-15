import { randomBytes } from "node:crypto";
import { statSync } from "node:fs";
import { userInfo } from "node:os";
import { posix, win32 } from "node:path";
import { classificationBlock, classifyTools, packsFor, secondaryUrlParam } from "./classify.js";
import { TEMPLATE_COMMAND, displaySpec, expand, usesPlaceholders, type TemplateCtx } from "./config.js";
import { CONNECT_TIMEOUT_ADVICE, isConnectTimeout, launchServer, stopOnSignals, type LaunchedServer } from "./launch.js";
import { listSegments, type IpcsRow } from "./embedded.js";
import type { EffectiveConfig, NamedServer } from "./config/index.js";
import { McpSession, ProtocolViolation, SessionError, discoverSqlTools, driftHint, resolvePackage, type OpenOptions, type ToolInfo } from "./mcp.js";
import { effectsGateReason } from "./packs/effects.js";
import { ensureGitFixture } from "./packs/git.js";
import { RUN_ORDER, getPack } from "./packs/index.js";
import { NO_SCOPE_TOOL, NO_UPSTREAM_STUB, NO_VALID_CALL, listenerReachable } from "./packs/shared.js";
import { hasCheckProbes, isCheckProbe } from "./probes.js";
import { MAX_REPORT_FIELD, inert, inertLines } from "./report/sanitize.js";
import { createSandbox } from "./sandbox.js";
import { ensureSqliteFixture } from "./sqlite-fixtures.js";
import { CANDIDATE_PACKS, type PackCtx, type PackId, type Sandbox, type Suggestion, type ToolClassification } from "./types.js";

/**
 * `sealmark doctor [--server name]`: answers "why does my server not grade?" before a run costs minutes.
 * It checks the tools a launcher needs, resolves the command, starts the server the way `run` would (sandbox working
 * directory, scrubbed environment) for a short time, runs initialize and tools/list, prints the classification and, for
 * every pack, whether it would run and why not. It also tests the harness's own pieces: the loopback listener and link creation.
 *
 * Everything returns data (`DoctorReport`); `renderDoctor` turns it into text. Exit code: 0, or 4 when any step failed.
 * Nothing is graded and nothing is written outside the sandbox, which is deleted at the end.
 */

export type DoctorStatus = "ok" | "warn" | "fail" | "info";

export interface DoctorItem {
  id: string;
  status: DoctorStatus;
  title: string;
  detail?: string;
}

export interface DoctorPack {
  pack: PackId;
  /** The pack is in the configured pack list. */
  requested: boolean;
  /** The pack would run for this server and configuration. */
  applies: boolean;
  reason: string;
}

export interface DoctorServer {
  name: string;
  transport: "stdio" | "http";
  /** The command line or URL as `run` would show it: placeholders unexpanded, secrets redacted. */
  display: string;
  items: DoctorItem[];
  /** What the server wrote to stderr during start-up, bounded. */
  stderr: string;
  startup?: { elapsedMs: number; serverName?: string; serverVersion?: string; capabilities: string[]; tools: number; prompts: number; resources: number };
  classification?: ToolClassification[];
  /** Lines of the `Classification:` block, ready to print. */
  classificationText?: string[];
  packs: DoctorPack[];
}

export interface DoctorReport {
  /** No step failed. */
  ok: boolean;
  /** 0, or 4 when a step failed. */
  exitCode: 0 | 4;
  environment: DoctorItem[];
  servers: DoctorServer[];
  summary: { failures: number; warnings: number };
  /**
   * What to add to sealmark.yaml (or pass as flags) to cover more of the server: each carries the YAML to paste and the equivalent flags
   * Stable ids; an agent reads these and `packs` and writes the config with no further reading.
   * `runDoctor` always sets it; optional in the type so a hand-built report (a test, a renderer) need not.
   */
  suggestions?: Suggestion[];
}

/** One thing to add to the configuration (types.ts; doctor --json and the run report carry the same objects). */
export type { Suggestion };

/** What `sealmark init --probes` takes from a doctor run: the tools exactly as the harness saw them. */
export interface DoctorCapture {
  server: string;
  transport: "stdio" | "http";
  tools: ToolInfo[];
  classification: ToolClassification[];
  /** The server's `instructions`, when it sent any. */
  instructions?: string;
}

export interface DoctorOptions {
  cfg: EffectiveConfig;
  /** Only this entry of `servers:`. Default: every server the configuration selects. */
  server?: string;
  /** How long to wait for the server to start (initialize and each tools/list page). Default 10 000 ms. */
  startupTimeoutMs?: number;
  log?: (s: string) => void;
  /** Install SIGINT handling that deletes the sandbox. Default true; tests turn it off. */
  handleSignals?: boolean;
  /** Test hook: resolve a command on a PATH string. */
  which?: (name: string, path: string) => string | undefined;
  /** Test hook: the sandbox factory. */
  makeSandbox?: typeof createSandbox;
  /** Test hook: the shared-memory segments `ipcs -m` lists (default: run it; undefined where there is no ipcs). */
  segments?: () => Promise<IpcsRow[] | undefined>;
  /** Test hook: whether a process id is alive (default: signal 0). */
  pidAlive?: (pid: number) => boolean;
  /** Test hook: the current user's name, as `ipcs` prints an owner. */
  user?: string;
  /** Test hook: looks a launcher's package up in the on-disk caches. */
  resolve?: typeof resolvePackage;
  clientVersion?: string;
  /** Internal: runDoctor collects every server Sealmark launched so a signal or an error can stop them all. */
  onLaunched?: (server: LaunchedServer) => void;
  /** Called once per server that started, with its tools and classification (`init --probes` uses it; nothing is added to the report). */
  capture?: (c: DoctorCapture) => void;
  /** Internal: checkServer reports the suggestions it derived for a server. */
  onSuggestions?: (s: Suggestion[]) => void;
}

// ---------------------------------------------------------------------------------------------------------
// Finding programs without a shell
// ---------------------------------------------------------------------------------------------------------

const isFile = (p: string): boolean => {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
};

export interface WhichOptions {
  platform?: NodeJS.Platform;
  pathext?: string;
  cwd?: string;
  exists?: (path: string) => boolean;
}

/**
 * Resolves a command the way the operating system would, but without spawning anything: a path (absolute, or containing
 * a separator) is checked as is; a bare name is looked up in each directory of `path`. On Windows a name without an extension
 * is tried with each PATHEXT entry, so `npx` finds `npx.cmd`. A spawn that fails with ENOENT must never be read as "missing"
 * without this check, because `spawn("npx")` without a shell cannot find a .cmd file but cross-spawn-style launchers can.
 */
export function findOnPath(name: string, path: string, o: WhichOptions = {}): string | undefined {
  const platform = o.platform ?? process.platform;
  const win = platform === "win32";
  const exists = o.exists ?? isFile;
  const pathext = (o.pathext ?? process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const hasExt = win && pathext.some((e) => name.toLowerCase().endsWith(e.toLowerCase()));
  const variants = (base: string): string[] => (win ? (hasExt ? [base] : [...pathext.map((e) => base + e), base]) : [base]);
  // The rules of the platform being asked about, not of the host: tests check the Windows and POSIX answers on any machine.
  const P = win ? win32 : posix;
  if (/[\\/]/.test(name) || P.isAbsolute(name)) {
    return variants(P.resolve(o.cwd ?? process.cwd(), name)).find(exists);
  }
  for (const dir of path.split(win ? ";" : ":").filter(Boolean)) {
    const hit = variants(P.join(dir.replace(/^"|"$/g, ""), name)).find(exists);
    if (hit) return hit;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------
// Explaining a start-up failure
// ---------------------------------------------------------------------------------------------------------

/** The first `Error: ...` line of a click-style usage message (one that also prints `Usage: ...`), or undefined when stderr is not one. */
export function usageError(stderr: string): string | undefined {
  if (!/^\s*Usage:/m.test(stderr)) return undefined;
  const line = /^\s*Error:\s*(.+)$/m.exec(stderr)?.[1]?.trim();
  return line ? line.slice(0, 200) : undefined;
}

/** What the server printed while it was still downloading or installing itself (npx, uvx): the cache is cold, and a longer wait helps. */
export const DOWNLOAD_PROGRESS = /\bdownloading\b|\bdownloaded\b|\binstalling\b|\bresolved \d+ packages\b|\badded \d+ packages\b|\binstalled \d+ packages?\b|npm (?:warn|notice) exec|\bneed to install\b/i;

/** A plain-language next step for a server that did not start, from the error and what it wrote to stderr. */
export function diagnoseStartup(error: string, stderr: string, o: { command?: string; timeoutMs: number; usesDsn?: boolean }): string[] {
  const text = `${error}\n${stderr}`;
  const out: string[] = [];
  const drift = driftHint(text);
  if (drift) out.push(`${drift}.`);
  if (/ENOENT|not recognized as an internal or external command|command not found|No such file or directory/i.test(text) && !/ModuleNotFound|Cannot find module/i.test(text)) {
    out.push(`the launcher${o.command ? ` "${o.command}"` : ""} or a file it needs was not found. The server starts with a short PATH (the system PATH plus the sandbox bin directory), so a program that is only on your shell's PATH is not visible; use its full path in server.command.`);
  }
  if (/timed? ?out|did not answer|Request timed out/i.test(error)) {
    out.push(`it did not answer within ${Math.round(o.timeoutMs / 1000)} s (--connect-timeout). ${CONNECT_TIMEOUT_ADVICE}`);
  }
  if (/not a valid git repository/i.test(text)) {
    out.push("a git server needs `--repository {sandbox}/repo` (or its environment variable set to it): the harness builds that repository inside the sandbox before the server starts.");
  }
  // A command-line tool's usage error ("Usage: ...", "Error: Missing option '--x'") is about a flag, not about the environment.
  const usage = usageError(stderr);
  if (usage) {
    out.push(`the server printed a usage error (${usage}); it probably needs a command-line flag or argument it was not given: add it to server.args.`);
  } else if (/api[_ -]?key|token|credential|secret|not set|is required|missing.*(variable|env)|environment variable/i.test(stderr)) {
    out.push("it looks as if the server wanted a setting from its environment. It sees only a short environment, not yours; put it under server.env (in sealmark.local.yaml if it is a secret) or reference your own with ${NAME}.");
  }
  if (!o.usesDsn && /database url|connection string|DATABASE_URL|No database/i.test(stderr)) {
    out.push("the server may need a database connection string: add --dsn {dsn} (or the env it reads) under server.args or server.env; the db pack fills it.");
  }
  if (/EADDRINUSE|address already in use/i.test(text)) out.push("a port the server wants is already in use; stop the other process or configure another port.");
  if (/connection closed|exited|ECONNRESET|EPIPE/i.test(error) && !out.length) out.push("the server exited while starting; the stderr above says why.");
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// Orphaned shared-memory segments
// ---------------------------------------------------------------------------------------------------------

const pidIsAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};

/**
 * Segments an interrupted embedded-Postgres run can leave behind: owned by this user, nothing attached, created by a process that is gone,
 * and tiny (Postgres's interlock segment is a few dozen bytes; a program's real shared memory is not under 1 KiB). A listing without the
 * creator pid cannot show that the creator is dead, so such a segment is never listed.
 */
export function orphanedSegments(rows: readonly IpcsRow[], o: { user: string; alive?: (pid: number) => boolean }): IpcsRow[] {
  const alive = o.alive ?? pidIsAlive;
  return rows.filter((r) => r.owner === o.user && r.nattch === 0 && r.cpid !== undefined && !alive(r.cpid) && r.size !== undefined && r.size < 1024);
}

/** The doctor line for the segments `orphanedSegments` found; it names the command and removes nothing. */
export function segmentItem(orphans: readonly IpcsRow[]): DoctorItem | undefined {
  if (!orphans.length) return undefined;
  return {
    id: "shm-orphans",
    status: "warn",
    title: `${orphans.length} possibly orphaned shared-memory segment${orphans.length === 1 ? "" : "s"} (id ${orphans.map((r) => r.id).join(", ")})`,
    detail: "an embedded Postgres that was killed leaves one behind, and about 30 of them stop every later embedded start; list them with `ipcs -m`, and remove one you recognise with `ipcrm -m <id>`. doctor removes nothing.",
  };
}

// ---------------------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------------------

/** The same minimum as `engines.node` in package.json (node:sqlite, used by the sqlite pack, needs 22.13); a test keeps them equal. */
export const NODE_MIN = [22, 13];
const baseName = (command: string) => command.replace(/\\/g, "/").split("/").pop()!.replace(/\.(cmd|exe|bat|com)$/i, "").toLowerCase();

export function nodeItem(version = process.version): DoctorItem {
  const m = /^v(\d+)\.(\d+)/.exec(version);
  const ok = !m || Number(m[1]) > NODE_MIN[0] || (Number(m[1]) === NODE_MIN[0] && Number(m[2]) >= NODE_MIN[1]);
  return { id: "node", status: ok ? "ok" : "fail", title: `node ${version}`, detail: ok ? process.execPath : `sealmark needs Node ${NODE_MIN.join(".")} or newer` };
}

function toolItem(id: "npx" | "uvx" | "git", path: string, needed: boolean, which: NonNullable<DoctorOptions["which"]>): DoctorItem {
  const hit = which(id, path);
  if (hit) return { id, status: "ok", title: id, detail: hit };
  const why: Record<string, string> = {
    npx: needed ? "the server is started with npx" : "only servers started with npx need it",
    uvx: needed ? "the server is started with uvx" : "only servers started with uvx need it",
    git: needed ? "the server is started with git" : "the git pack needs it and is not applicable without it",
  };
  return { id, status: needed ? "fail" : "warn", title: `${id}: not found on PATH`, detail: why[id] };
}

async function sandboxItems(sb: Sandbox, timeoutMs: number): Promise<DoctorItem[]> {
  const items: DoctorItem[] = [];
  items.push({ id: "sandbox", status: "ok", title: "sandbox created", detail: `${sb.dir} (deleted at the end of the check)` });
  const dir = sb.links.dir;
  items.push(
    dir.ok
      ? { id: "link-dir", status: "ok", title: `directory link created (${dir.kind})` }
      : { id: "link-dir", status: "warn", title: "directory link could not be created", detail: `${dir.reason ?? "unknown reason"}; the fs link-escape check will be n/a` },
  );
  const file = sb.links.file;
  items.push(
    file.ok
      ? { id: "link-file", status: "ok", title: `file symlink created (${file.kind})` }
      : { id: "link-file", status: "warn", title: "file symlink could not be created", detail: `${file.reason ?? "unknown reason"}; on Windows turn on Developer Mode or run from an elevated shell. The symlink probes will be n/a; the junction probe still runs.` },
  );
  // The listener must answer a request that carries a token, and record it against that token.
  const token = randomBytes(6).toString("hex");
  try {
    const res = await fetch(`${sb.listener.url}/t/${token}`, { signal: AbortSignal.timeout(timeoutMs) });
    const body = await res.text();
    const hits = sb.listener.hitsFor(token);
    if (body === `sm-listener-${token}` && hits.length === 1) {
      items.push({ id: "listener", status: "ok", title: `loopback listener answered on ${sb.listener.url}`, detail: sb.listener.url6 ? `also on ${sb.listener.url6}` : "IPv6 loopback is not available here; the [::1] probe will be skipped" });
    } else {
      items.push({ id: "listener", status: "fail", title: "the loopback listener answered with something unexpected", detail: `status ${res.status}, ${hits.length} recorded hit(s); the net pack cannot be trusted here` });
    }
  } catch (e) {
    items.push({ id: "listener", status: "fail", title: "the loopback listener did not answer", detail: `${(e as Error).message}. A firewall or security product may block loopback connections; the net pack needs them.` });
  } finally {
    sb.listener.reset();
  }
  return items;
}

/** Placeholders that need the seeded database. Doctor fills them with a dummy loopback address so the server can start. */
/** The address doctor gives database placeholders: nothing listens on port 1, so no database is ever contacted. */
export const DOCTOR_DUMMY_DSN = "postgres://sm_admin:unused@127.0.0.1:1/sealmark_seed";
export const DOCTOR_DUMMY_UPSTREAM = "http://127.0.0.1:1";
export const DOCTOR_DUMMY_BEARER = { a: "sm-bearer-a-000000000000", b: "sm-bearer-b-000000000000" };
const DUMMY_DB = { host: "127.0.0.1", port: "1", user: "sm_admin", password: "unused", database: "sealmark_seed", role: "admin" };

interface GateInput {
  startedOk: boolean;
  transport: "stdio" | "http";
  sandboxOn: boolean;
  active: boolean;
  classification: ToolClassification[];
  probes: number;
  /** Probes that declare a check: only these make the custom pack run. */
  checkProbes: number;
  sqlTools: number;
  dbPlaceholders: boolean;
  hasSqlClass: boolean;
  /** Set when the server runs on another host, so it cannot reach the harness's loopback listener. */
  remoteHost?: string;
  /** An HTTP server Sealmark starts itself (server.command with server.url): started inside the sandbox like a stdio server (round 6). */
  selfStarted?: boolean;
  /** `upstream.kind` is set (the stub is declared). */
  upstreamKind?: string | null;
  /** `scope.tools` entries, and the tools the server declares. */
  scopeTools?: readonly { tool: string; param: string }[];
  toolNames?: readonly string[];
  /** Probes without a check (valid calls). */
  validProbes?: number;
}

export const NO_UPSTREAM = NO_UPSTREAM_STUB;

/**
 * Why a pack would not run for this server. This mirrors the gate in run.ts (which is not exported); the wording is the same so
 * a pack's reason reads identically here and in the report. Returns undefined when no gate stops the pack.
 */
function gate(id: PackId, g: GateInput): string | undefined {
  if (!g.startedOk) return "the server's tool list could not be read";
  if (id === "exec" && !g.active) return "the exec pack runs only with --active";
  const needsSandbox = new Set<PackId>(["fs", "git", "exec", "effects", "sqlite"]);
  if (needsSandbox.has(id) && !g.sandboxOn) return g.transport === "http" && !g.selfStarted ? "the server is already running (HTTP), so it cannot be started inside the sandbox" : "the sandbox is off (--no-sandbox)";
  const id_ = id as string;
  if (id_ === "scope" && !(g.scopeTools ?? []).some((s) => (g.toolNames ?? []).includes(s.tool))) return NO_SCOPE_TOOL;
  if (id_ === "sql-guard" || id_ === "upstream") {
    if (id_ === "sql-guard" && !(g.sqlTools || g.hasSqlClass)) return "no tool takes a SQL string";
    if (!g.upstreamKind) return NO_UPSTREAM;
    if (g.transport === "http" && !g.selfStarted) return "the upstream stub needs a server Sealmark starts (server.command + server.url, or a stdio command): this server is already running";
    if (id_ === "upstream" && !g.validProbes) return NO_VALID_CALL;
  }
  if (id === "http" && g.transport !== "http") return "the server is started over stdio; the http pack needs server.url";
  if (id === "net" && g.remoteHost) return `the server runs on ${g.remoteHost}, so it cannot reach the harness's loopback listener; the net pack is only meaningful for stdio servers or an HTTP server on this machine`;
  if (id === "custom" && !g.probes) return "no probes: are declared in the config";
  const take = (want: PackId) => g.classification.some((c) => packsFor(c, { active: g.active, sandboxEnabled: g.sandboxOn }).includes(want));
  if (id === "fs" && !take("fs")) return "no tool is classified as taking a file path with medium confidence or higher";
  if (id === "net" && !take("net")) return "no tool is classified as taking a URL with medium confidence or higher";
  if (id === "git" && !take("git")) return "no tool is classified as taking a git repository path with medium confidence or higher";
  if (id === "exec" && !take("exec")) return "no tool is classified as running a command with high confidence";
  if (id === "effects") return effectsGateReason(g.classification, { active: g.active, sandboxEnabled: g.sandboxOn });
  if (id === "sqlite" && !g.hasSqlClass) return "no tool takes a SQL string";
  return undefined;
}

async function checkServer(named: NamedServer, cfg: EffectiveConfig, sb: Sandbox, o: Required<Pick<DoctorOptions, "startupTimeoutMs">> & DoctorOptions & { limitIsDefault?: boolean }, which: NonNullable<DoctorOptions["which"]>): Promise<DoctorServer> {
  const spec = named.spec;
  const transport = spec.url ? "http" : "stdio";
  const shown = displaySpec(spec);
  const items: DoctorItem[] = [];
  const out: DoctorServer = { name: named.name, transport, display: shown.command, items, stderr: "", packs: [] };
  // A launched HTTP server (server.command with server.url) is started by the harness, so it runs inside the sandbox like a stdio one (round 6).
  const selfStarted = transport === "http" && Boolean(spec.command);
  const sandboxOn = cfg.sandbox.enabled && (transport === "stdio" || selfStarted);
  const log = o.log ?? (() => {});

  // ---- the launcher ----
  const sbEnv = sandboxOn && cfg.sandbox.scrub_env ? sb.env() : undefined;
  const searchPath = sbEnv ? (Object.entries(sbEnv).find(([k]) => k.toUpperCase() === "PATH")?.[1] ?? "") : (process.env.PATH ?? process.env.Path ?? "");
  if (spec.command === TEMPLATE_COMMAND) {
    items.push({
      id: "command",
      status: "fail",
      title: `server.command is still the placeholder "${TEMPLATE_COMMAND}" from sealmark init`,
      detail: "Replace it with the command that starts the MCP server you want to grade (and its arguments), then run sealmark doctor again. Nothing was started.",
    });
    return out;
  }
  if (spec.command) {
    const hit = which(spec.command, searchPath);
    items.push(
      hit
        ? { id: "command", status: "ok", title: `command "${spec.command}" resolves`, detail: hit }
        : {
            id: "command",
            status: "fail",
            title: `command "${spec.command}" was not found`,
            detail: `${sbEnv ? "The server starts with a short PATH (the system PATH plus the sandbox bin directory). " : ""}Install it, or give the full path in server.command.`,
          },
    );
  }
  const bin = spec.command ? baseName(spec.command) : "";
  if (["npx", "uvx"].includes(bin) && spec.command && items[0]?.status === "ok") {
    items.push({ id: "launcher-cache", status: "info", title: `${bin} downloads the server on first use`, detail: "a slow first start is normal; later starts use the cache. Pin the version (pkg@x.y.z) so a grade is reproducible." });
  }
  const usesDb = usesPlaceholders(spec);
  if (usesDb) {
    items.push({ id: "placeholders", status: "info", title: "the configuration uses database placeholders ({dsn} and friends)", detail: "doctor does not start Postgres; they are filled with an unused loopback address (127.0.0.1:1) so the server can start. A server that connects eagerly may fail here although `sealmark run` works." });
  }

  // ---- start the server, as run would ----
  const sep = process.platform === "win32" ? "\\" : "/";
  const vars: Record<string, string> = {
    sandbox: sb.root,
    sandbox_home: sb.home,
    listener: sb.listener.url,
    sqlite_path: `${sb.root}${sep}fixture.sqlite`,
    duckdb_path: `${sb.root}${sep}fixture.duckdb`,
    // Round 6: doctor starts no stub and mints no real identity; a server that names {upstream} or {bearer} gets values that are well formed
    // and point nowhere (like the unused DSN), so it can start. A server that checks its backend or its token at start-up fails here
    // although `sealmark run` works, and the advice below says so.
    upstream: DOCTOR_DUMMY_UPSTREAM,
    bearer: DOCTOR_DUMMY_BEARER.a,
    "bearer:a": DOCTOR_DUMMY_BEARER.a,
    "bearer:b": DOCTOR_DUMMY_BEARER.b,
    ...(usesDb ? { ...DUMMY_DB, dsn: DOCTOR_DUMMY_DSN } : {}),
  };
  const ctx: TemplateCtx = { vars, dsns: usesDb ? { analyst: vars.dsn, support: vars.dsn, admin: vars.dsn } : {}, env: cfg.env };
  const where: OpenOptions =
    transport === "http" ? {} : sandboxOn ? (cfg.sandbox.scrub_env ? { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed" } : { cwd: sb.root, envMode: "inherit" }) : { cleanCwd: true, envMode: "inherit" };
  const failedLauncher = items.some((i) => i.status === "fail");
  // The same fixtures run.ts builds before its first open(): a server given {sandbox}/repo or {sqlite_path} checks them at startup.
  if (sandboxOn && transport === "stdio" && !failedLauncher) {
    const specText = JSON.stringify(spec);
    if (/\{(?:sandbox|dir)\}(?:\\\\|\/)+repo/.test(specText)) {
      try {
        await ensureGitFixture(sb);
      } catch (e) {
        items.push({ id: "fixture-git", status: "warn", title: "the git fixtures could not be built", detail: (e as Error).message });
      }
    }
    if (specText.includes("{sqlite_path}")) {
      try {
        ensureSqliteFixture(vars.sqlite_path!);
      } catch (e) {
        items.push({ id: "fixture-sqlite", status: "warn", title: "the sqlite fixture could not be built", detail: (e as Error).message });
      }
    }
  }
  let session: McpSession | undefined;
  let startedOk = false;
  const t0 = Date.now();
  let launched: LaunchedServer | undefined;
  let launchFailed = false;
  if (!failedLauncher && transport === "http" && spec.command) {
    try {
      launched = await launchServer({
        command: expand(spec.command, ctx),
        args: (spec.args ?? []).map((a) => expand(a, ctx)),
        env: Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expand(v, ctx)])),
        url: expand(spec.url!, ctx),
        timeoutMs: (spec.start_timeout_sec ?? 60) * 1000,
        // Inside the sandbox, as run starts it: the sandbox root as cwd and, unless sandbox.scrub_env is off, the scrubbed environment.
        ...(sandboxOn ? { cwd: sb.root, ...(cfg.sandbox.scrub_env ? { baseEnv: sb.env(Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expand(v, ctx)]))) } : {}) } : {}),
        onProgress: log,
        onStarted: (h) => {
          launched = h;
          o.onLaunched?.(h);
        },
      });
    } catch (e) {
      launchFailed = true;
      items.push({ id: "launch", status: "fail", title: "the server did not start", detail: (e as Error).message });
    }
  }
  if (!failedLauncher && !launchFailed) {
    // The default 10 s cannot cover a first download: when the package is not in the launcher's cache, wait 60 s and say why (an explicit --connect-timeout is never changed).
    let limitMs = o.startupTimeoutMs;
    let cold = "";
    if (o.limitIsDefault && ["npx", "uvx"].includes(bin) && spec.command) {
      const pkg = (o.resolve ?? resolvePackage)(spec.command, spec.args ?? []);
      if (pkg && pkg.source === "not found") {
        limitMs = Math.max(limitMs, 60_000);
        cold = `; ${pkg.name} is not in the ${bin} cache yet, so the first start downloads it`;
      }
    }
    log(`starting "${named.name}" (limit ${Math.round(limitMs / 1000)} s${cold})`);
    const openOnce = (ms: number) => McpSession.open(spec, ctx, { clientVersion: o.clientVersion, connectTimeoutMs: ms, onProgress: log, ...where });
    try {
      try {
        session = await openOnce(limitMs);
      } catch (first) {
        // The default 10 s cannot cover a download that is still running: when stderr shows one, wait once more, longer (an explicit limit is never changed).
        const f = first as SessionError;
        if (!(o.limitIsDefault && limitMs < 60_000 && (isConnectTimeout(f.message ?? "") || /did not answer/i.test(f.message ?? "")) && DOWNLOAD_PROGRESS.test(f.stderr ?? ""))) throw first;
        limitMs = 60_000;
        log(`the server was still downloading itself: starting "${named.name}" again with a limit of 60 s`);
        session = await openOnce(limitMs);
      }
      startedOk = true;
    } catch (e) {
      const err = e as SessionError;
      const stderr = err.stderr ?? "";
      out.stderr = boundKeepingError(stderr);
      const protocol = e instanceof ProtocolViolation;
      items.push({
        id: "start",
        status: "fail",
        title: protocol ? "the server answered, but not with valid MCP" : "the server did not start or did not answer initialize and tools/list",
        detail: err.message,
      });
      for (const step of diagnoseStartup(err.message, stderr, { command: spec.command, timeoutMs: limitMs, usesDsn: usesDb })) items.push({ id: "advice", status: "info", title: step });
      const text = JSON.stringify(spec);
      if (/\{bearer(?::[ab])?\}/.test(text) && /\b40[13]\b|unauthori[sz]ed|forbidden/i.test(`${err.message} ${stderr}`))
        items.push({
          id: "advice",
          status: "info",
          title: "the server refused the token doctor sent for {bearer}: it validates tokens it did not issue",
          detail: "set identities.a (and identities.b) to real tokens, for example identities: { a: \"${TOKEN_A}\" } or --identity-a <token>; doctor does not use them, but a run does",
        });
      if (/\{upstream\}/.test(text) && !/\b40[13]\b/.test(err.message))
        items.push({ id: "advice", status: "info", title: "the server config names {upstream}; doctor starts no stub and gives it an address that points nowhere (127.0.0.1:1)", detail: "a server that connects to its backend at start-up fails here although `sealmark run` (which starts the stub) works" });
    }
  } else if (!launchFailed) {
    items.push({ id: "start", status: "info", title: "not started: the command was not found" });
  }

  let classification: ToolClassification[] = [];
  let visible = session?.tools ?? [];
  let sqlCount = 0;
  if (session) {
    const elapsedMs = Date.now() - t0;
    out.stderr = bound(session.stderrFull());
    const caps = Object.keys(session.capabilities);
    out.startup = {
      elapsedMs,
      serverName: session.serverInfo.name,
      serverVersion: session.serverInfo.version,
      capabilities: caps,
      tools: session.tools.length,
      prompts: session.prompts.length,
      resources: session.resources.length,
    };
    items.push({
      id: "start",
      status: "ok",
      title: `started: initialize and tools/list answered in ${elapsedMs} ms`,
      detail: `${session.serverInfo.name ?? "(no name)"} ${session.serverInfo.version ?? ""}`.trim() + `; ${session.tools.length} tool(s); capabilities: ${caps.join(", ") || "none"}`,
    });
    if (!session.tools.length) items.push({ id: "tools", status: "warn", title: "the server declares no tools", detail: "only the protocol checks can run" });
    for (const e of session.listErrors) items.push({ id: "list", status: "warn", title: e });
    if (out.stderr) items.push({ id: "stderr", status: "info", title: `the server wrote to stderr while starting (${out.stderr.split("\n").length} line(s), shown below)` });
    const classified = classifyTools({ tools: session.tools, sqlTools: cfg.sqlTools, overrides: cfg.tools.overrides, include: cfg.tools.include, exclude: cfg.tools.exclude });
    classification = classified.classification;
    for (const w of classified.warnings) items.push({ id: "classify", status: "warn", title: w });
    if (sandboxOn && !spec.rootless && classified.classification.some((c) => c.class === "path" && !c.excluded && c.confidence !== "low") && !/\{(?:sandbox|dir|sandbox_home)\}/.test(JSON.stringify(spec))) {
      items.push({
        id: "sandbox-placeholder",
        status: "info",
        title: "the server config has no {sandbox} placeholder, so the fs pack cannot tell which directory the server may use",
        detail: 'pass {sandbox} as its directory argument or in server.env (for example ROOT_DIR: "{sandbox}"); a server that takes no root argument can set server.rootless: true, and the fs pack then treats its working directory as the allowed root',
      });
    }
    const excluded = new Set(classification.filter((c) => c.excluded).map((c) => c.tool));
    visible = session.tools.filter((t) => !excluded.has(t.name));
    sqlCount = discoverSqlTools(session.tools, cfg.sqlTools).tools.filter((t) => !excluded.has(t.tool)).length;
    out.classification = classification;
    o.capture?.({ server: named.name, transport, tools: [...session.tools], classification, ...(session.instructions ? { instructions: session.instructions } : {}) });
    const applied =([...RUN_ORDER] as PackId[]).filter((id) => classification.some((c) => packsFor(c, { active: cfg.active, sandboxEnabled: sandboxOn }).includes(id)));
    out.classificationText = classificationBlock(classification, applied);
  } else if (!out.stderr) {
    out.stderr = "";
  }

  // ---- every pack: would it run? ----
  const reach = listenerReachable(spec, cfg.env);
  const rules = rulesOf(cfg);
  const gin: GateInput = {
    startedOk,
    transport,
    sandboxOn,
    active: cfg.active,
    classification,
    probes: cfg.probes.length,
    checkProbes: cfg.probes.filter((p) => isCheckProbe(p)).length,
    sqlTools: sqlCount,
    dbPlaceholders: usesDb,
    hasSqlClass: classification.some((c) => c.class === "sql" && c.confidence !== "low"),
    ...(reach.ok ? {} : { remoteHost: reach.host }),
    selfStarted,
    upstreamKind: rules.upstreamKind,
    scopeTools: rules.scopeTools,
    toolNames: visible.map((t) => t.name),
    validProbes: cfg.probes.filter((p) => !isCheckProbe(p)).length,
  };
  // The same rule run.ts applies: a declaration puts its pack in the pack list (custom for a probe with a check; scope, sql-guard and
  // upstream in round 6), so doctor says "would run" only when run does.
  const auto = autoAddedPacks(cfg, { hasSqlTool: gin.hasSqlClass || sqlCount > 0 });
  const requested = new Set<PackId>([...(cfg.packs as PackId[]), ...auto.packs]);
  for (const note of auto.notes) out.items.push({ id: "pack-auto", status: "info", title: note });
  for (const note of auto.skipped) out.items.push({ id: "pack-skipped", status: "warn", title: note });
  o.onSuggestions?.(
    suggestionsFor({ tools: visible, classification, spec, transport, selfStarted, sandboxEnabled: cfg.sandbox.enabled, probes: cfg.probes.length, usesDsn: usesDb, sqlTools: cfg.sqlTools ?? [], rules }),
  );
  const packCtx = (pack: PackId): PackCtx => ({
    pack,
    config: cfg,
    tools: visible,
    classification,
    sandbox: sb,
    sandboxEnabled: sandboxOn,
    open: () => {
      throw new Error("doctor does not run packs");
    },
    active: cfg.active,
    timeoutProbeSec: cfg.timeoutProbeSec,
    hangMs: cfg.hangMs,
    log: () => {},
    prior: [],
    canaries: [],
    sqlTools: discoverSqlTools(visible, cfg.sqlTools).tools,
  });
  // The candidate packs are listed even before the registry has them (the harness package adds them to RUN_ORDER).
  for (const id of ["core", "db", ...new Set([...RUN_ORDER, ...CANDIDATE_PACKS])] as PackId[]) {
    const isReq = requested.has(id);
    let applies = true;
    let reason = "";
    if (id === "core") {
      applies = startedOk;
      reason = startedOk ? "always applies" : "the server's tool list could not be read";
    } else if (id === "db") {
      if (!startedOk) [applies, reason] = [false, "the server's tool list could not be read"];
      else if (!usesDb) [applies, reason] = [false, "server config has no {dsn}/{host}/... placeholder, so the harness cannot start the server once per role (add {dsn} to grade it)"];
      else if (!sqlCount) [applies, reason] = [false, `no tool takes a SQL string (checked ${visible.length} tool(s)); set sql_tools`];
      else reason = `${sqlCount} SQL tool(s) and a database placeholder; the harness seeds its own Postgres`;
    } else {
      const stop = gate(id, gin);
      if (stop) [applies, reason] = [false, stop];
      else {
        const pack = getPack(id);
        if (!pack) [applies, reason] = [false, "pack not installed"];
        else {
          try {
            const a = pack.applies(packCtx(id));
            if (a.ok) reason = describeApplies(id, classification, gin);
            else [applies, reason] = [false, a.reason];
          } catch (e) {
            [applies, reason] = [false, `applies() threw: ${(e as Error).message}`];
          }
        }
      }
    }
    out.packs.push({ pack: id, requested: isReq, applies, reason });
  }
  // The same line a run prints: the packs that would take part (asked for and applicable), not the ones the tool classes could in principle feed.
  if (out.classification) {
    // Core included, as the run's line has it: it applies whenever the tool list could be read.
    const taking = out.packs.filter((p) => p.requested && p.applies).map((p) => p.pack);
    out.classificationText = classificationBlock(out.classification, taking);
  }
  if (cfg.plugins.length) out.packs.push({ pack: "plugin:*" as PackId, requested: true, applies: true, reason: `${cfg.plugins.length} plugin pack(s) declared; doctor does not load them` });

  await session?.close();
  await launched?.stop();
  return out;
}

function describeApplies(id: PackId, classification: ToolClassification[], g: GateInput): string {
  const tools = (cls: string) => classification.filter((c) => c.class === cls && !c.excluded && c.confidence !== "low").map((c) => c.tool);
  switch (id as string) {
    case "fs":
      return `path tools: ${tools("path").join(", ")}`;
    case "net": {
      // A path or git tool that also takes a URL is probed through that parameter: named, so the list is not read as missing it.
      const side = classification.filter((c) => secondaryUrlParam(c) !== undefined).map((c) => `${c.tool} (via secondary url)`);
      return `URL tools: ${[...tools("url"), ...side].join(", ")}`;
    }
    case "git":
      return `git tools: ${tools("git").join(", ")}`;
    case "exec":
      return `command tools: ${tools("command").join(", ")} (--active is on)`;
    case "sqlite":
      return `SQL tools: ${tools("sql").join(", ")}`;
    case "http":
      return "server.url is set";
    case "effects":
      return "a tool with annotations takes a harness-owned target; it grades only what a benign call can show";
    case "custom":
      return `${g.probes} probe(s) declared, ${g.checkProbes} with a check`;
    case "scope":
      return `scope.tools: ${(g.scopeTools ?? []).filter((s) => (g.toolNames ?? []).includes(s.tool)).map((s) => s.tool).join(", ")}`;
    case "sql-guard":
      return `SQL tools: ${tools("sql").join(", ")}; the upstream stub is declared`;
    case "upstream":
      return `the upstream stub is declared; ${g.validProbes} valid-call probe(s)`;
    default:
      return "applies";
  }
}

// ---------------------------------------------------------------------------------------------------------
// Round 6: the declarations that add packs, and what to suggest
// ---------------------------------------------------------------------------------------------------------

export interface RuleSettings {
  /** `upstream.kind`, or null when no stub is declared. */
  upstreamKind: string | null;
  scopeTools: { tool: string; param: string }[];
  scopeAllow: string[];
}

/**
 * The round 6 settings of a configuration: the typed `EffectiveConfig` fields, or the raw merged tree (`cfg.value`) for a configuration built by hand.
 */
export function rulesOf(cfg: EffectiveConfig): RuleSettings {
  // A hand-built configuration (a test, a library caller) may carry the raw tree only.
  const tree = (cfg.value ?? {}) as { upstream?: { kind?: string | null }; scope?: { tools?: unknown; allow?: unknown } };
  const up: { kind?: string | null } | undefined = cfg.upstream ?? tree.upstream;
  const sc: { tools?: unknown; allow?: unknown } | undefined = cfg.scope ?? tree.scope;
  const tools = Array.isArray(sc?.tools) ? (sc.tools as unknown[]).filter((t): t is { tool: string; param: string } => Boolean(t) && typeof (t as { tool?: unknown }).tool === "string" && typeof (t as { param?: unknown }).param === "string") : [];
  return { upstreamKind: typeof up?.kind === "string" ? up.kind : null, scopeTools: tools, scopeAllow: Array.isArray(sc?.allow) ? (sc.allow as unknown[]).filter((a): a is string => typeof a === "string") : [] };
}

export interface AutoAdded {
  /** Packs a declaration adds to the list nobody chose. */
  packs: PackId[];
  /** One line per pack added (printed by `run` as `note: ...`). */
  notes: string[];
  /** A declaration whose pack is not in a list the user chose: the pack is skipped, and this says so. */
  skipped: string[];
}

/**
 * The auto-add rule, one function so `run` and `doctor` cannot drift (seam S11): a declaration puts its pack in the pack list when the
 * list was not chosen by the user (the shipped default or a profile), and is reported as skipped when it was:
 * `custom` for a probe with a check; `scope` when `scope.tools` is not empty; `upstream` when `upstream.kind` is set; `sql-guard` when it
 * is set and a SQL tool exists. The text of `notes` and `skipped` is what the run prints.
 */
export function autoAddedPacks(cfg: EffectiveConfig, o: { hasSqlTool: boolean }): AutoAdded {
  const rules = rulesOf(cfg);
  const layer = cfg.origins?.["/packs"]?.layer;
  const shipped = cfg.packsExplicit ? (layer === undefined ? false : layer === "default" || layer === "profile") : true;
  const listed = new Set<string>(cfg.packs);
  const declared: { id: PackId; note: string }[] = [];
  if (hasCheckProbes(cfg.probes)) declared.push({ id: "custom", note: "probes with a check were declared, so the custom pack is included" });
  if (rules.scopeTools.length) declared.push({ id: "scope" as PackId, note: "scope was declared in the config, so the pack is included" });
  if (rules.upstreamKind && o.hasSqlTool) declared.push({ id: "sql-guard" as PackId, note: "sql-guard was declared in the config, so the pack is included" });
  if (rules.upstreamKind) declared.push({ id: "upstream" as PackId, note: "upstream was declared in the config, so the pack is included" });
  const out: AutoAdded = { packs: [], notes: [], skipped: [] };
  for (const d of declared) {
    if (listed.has(d.id)) continue;
    if (shipped) {
      out.packs.push(d.id);
      out.notes.push(d.note);
    } else out.skipped.push(`${d.id === "custom" ? "probes with a check were declared" : `${d.id} was declared in the config`} but the pack list omits ${d.id}, so ${d.id === "custom" ? "they were" : "it was"} skipped (add ${d.id} to --pack or packs:)`);
  }
  return out;
}

const SCOPE_PARAM = /(table|dataset|path|resource|identifier|object|space|schema|collection|index|bucket|topic|name)/i;
const SCOPE_WORDS = /\b(allow(?:ed|list)?|scoped?|permitted|catalog)\b/i;

export interface SuggestInput {
  tools: readonly ToolInfo[];
  classification: readonly ToolClassification[];
  spec: { command?: string; url?: string; args?: readonly string[]; env?: Record<string, string>; headers?: Record<string, string> };
  transport: "stdio" | "http";
  selfStarted: boolean;
  sandboxEnabled: boolean;
  /** Number of `probes:` entries. */
  probes: number;
  usesDsn: boolean;
  sqlTools: readonly { tool: string }[];
  rules: RuleSettings;
}

/**
 * What to add to the configuration to cover more of this server. Pure: it reads the tool list, the
 * classification and the configuration; nothing is started. Every item carries the YAML to paste and the equivalent flags; a literal
 * credential in the configuration is never repeated in a suggestion.
 */
export function suggestionsFor(i: SuggestInput): Suggestion[] {
  const out: Suggestion[] = [];
  const classOf = new Map(i.classification.map((c) => [c.tool, c]));
  const scoped = new Set(i.rules.scopeTools.map((s) => s.tool));
  for (const t of [...i.tools].sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (scoped.has(t.name)) continue;
    const c = classOf.get(t.name);
    // A tool another pack already holds to account for its target (a file path, a URL, a command, a repository) is not a scoped identifier.
    if (c && !c.excluded && c.confidence !== "low" && ["path", "git", "url", "command"].includes(c.class)) continue;
    const props = Object.entries(t.inputSchema?.properties ?? {}).filter(([, p]) => [p.type].flat().includes("string"));
    const hit = props.find(([name, p]) => SCOPE_PARAM.test(name) && SCOPE_WORDS.test(`${t.description ?? ""} ${typeof p.description === "string" ? p.description : ""}`));
    if (!hit) continue;
    out.push({
      id: `scope:${t.name}`,
      kind: "scope",
      why: `tool "${t.name}" takes the string parameter "${hit[0]}" and its description speaks of what is allowed: declare the identifiers it may serve, so the scope pack can check that names outside them are refused`,
      config: `scope:\n  tools:\n    - { tool: ${t.name}, param: ${hit[0]} }\n  allow: []   # fill in: identifiers the server may serve; an entry ending in "." is a prefix, for example "sales.public."\n`,
      flags: [`--scope-tool ${t.name}=${hit[0]}`, "--scope-allow <identifier>"],
      tools: [t.name],
    });
  }
  const sqlTools = i.tools.filter((t) => i.sqlTools.some((s) => s.tool === t.name) || (classOf.get(t.name)?.class === "sql" && classOf.get(t.name)?.confidence !== "low" && !classOf.get(t.name)?.excluded)).map((t) => t.name);
  const spec = JSON.stringify(i.spec);
  if (sqlTools.length && !i.rules.upstreamKind && !i.usesDsn && !/\{(?:sqlite_path|duckdb_path)\}/.test(spec)) {
    out.push({
      id: "upstream:http",
      kind: "upstream",
      why: `${sqlTools.map((t) => `"${t}"`).join(", ")} takes a SQL string and no database or upstream stub is configured: the harness has no backend to watch, so the SQL packs cannot run. Start the server against a harness-owned stub instead of a real backend`,
      config: `upstream:\n  kind: http\n# and point the server's backend at the stub, for example in server.args: ["--backend", "{upstream}"] (or an env var or the url)\n`,
      flags: ["--upstream"],
      tools: sqlTools,
    });
    out.push({
      id: `sql-guard:${sqlTools[0]}`,
      kind: "sql-guard",
      why: "with the stub declared, the sql-guard pack runs by itself: it sends statements that must not be forwarded and out-of-scope references, and reads what reached the stub",
      config: i.sqlTools.some((s) => s.tool === sqlTools[0]) ? "# nothing more to add: the tool is already listed under sql_tools\n" : `# only if the tool is not recognised as a SQL tool by itself:\nsql_tools:\n  - { tool: ${sqlTools[0]}, arg: <the SQL argument> }\n`,
      flags: [],
      tools: sqlTools,
    });
  }
  const auth = Object.entries(i.spec.headers ?? {}).find(([k, v]) => k.toLowerCase() === "authorization" && !/\{bearer(?::[ab])?\}/.test(String(v)));
  if (i.transport === "http" && auth) {
    out.push({
      id: "identity:authorization",
      kind: "identity",
      why: "server.headers holds a fixed Authorization value: every caller shares one credential, so per-caller passthrough cannot be tested. Write {bearer}; the harness mints two identities and the upstream pack checks whose token reaches the backend",
      config: `server:\n  headers:\n    Authorization: "Bearer {bearer}"\n# only if the server validates tokens it did not issue, give it two real ones (not in the file):\n# identities:\n#   a: "\${TOKEN_A}"\n#   b: "\${TOKEN_B}"\n`,
      flags: ['--header "Authorization: Bearer {bearer}"', "--identity-a <token>", "--identity-b <token>"],
    });
  }
  if (i.probes === 0) {
    out.push({
      id: "probes:none",
      kind: "probes",
      why: "no probes: are declared, so no tool is called with valid input and the checks that need a working call stay inconclusive; generate one valid call per tool",
      config: "# run: sealmark init --probes --write --yes\n",
      flags: ["sealmark init --probes --write --yes"],
    });
  }
  if (i.selfStarted && !i.sandboxEnabled) {
    out.push({
      id: "sandbox:enable",
      kind: "sandbox",
      why: "the server is started by Sealmark but the sandbox is off, so it runs with your full environment and the fs, git, exec, effects and sqlite packs are disabled",
      config: "sandbox:\n  enabled: true\n",
      flags: ["(drop --no-sandbox)"],
    });
  }
  return out;
}

/**
 * Suggestions drawn from the checks of a finished run, for the `suggestions` of the JSON report: a check that could not be judged says
 * which key to change. Pure; `checks` is `RunResult.checks`.
 */
export function suggestionsAfterRun(checks: readonly { id: string; verdict: string; summary: string; pack?: string }[]): Suggestion[] {
  const out: Suggestion[] = [];
  const inconclusive = (id: string) => checks.find((c) => c.id === id && c.verdict === "inconclusive");
  const cred = inconclusive("upstream-credential");
  if (cred && /refus|reject|401|403|unauthori[sz]ed/i.test(cred.summary))
    out.push({
      id: "identity:tokens",
      kind: "identity",
      why: `upstream-credential is inconclusive: ${cred.summary} The server rejects the tokens the harness minted: set identities.a and identities.b to real tokens (from the environment, never the file)`,
      config: 'identities:\n  a: "${TOKEN_A}"\n  b: "${TOKEN_B}"\n',
      flags: ["--identity-a <token>", "--identity-b <token>"],
    });
  const scope = inconclusive("scope-escape");
  if (scope)
    out.push({
      id: "scope:control",
      kind: "scope",
      why: `scope-escape is inconclusive: ${scope.summary} The allow entries may be misspelled: compare them with the identifiers the server lists (for example through a list tool)`,
      config: "scope:\n  allow: [] # fill in: identifiers the server serves, spelled exactly as it returns them\n",
      flags: ["--scope-allow <identifier>"],
    });
  const sql = inconclusive("sql-guard-statements") ?? inconclusive("sql-guard-references");
  if (sql)
    out.push({
      id: "sql-guard:control",
      kind: "sql-guard",
      why: `${sql.id} is inconclusive: ${sql.summary} The control statement did not reach the upstream stub: give a statement the server accepts`,
      config: 'checks:\n  sql-guard-statements:\n    control_sql: "SELECT * FROM <an identifier in scope.allow> WHERE \'sm-{token}\' = \'sm-{token}\'"\n',
      flags: [],
    });
  if (checks.some((c) => c.verdict === "inconclusive" && /no valid call/i.test(c.summary)))
    out.push({
      id: "probes:none",
      kind: "probes",
      why: "a check was inconclusive because no valid call was made: declare one valid call per tool",
      config: "# run: sealmark init --probes --write --yes\n",
      flags: ["sealmark init --probes --write --yes"],
    });
  return out;
}

const bound = (s: string, max = 4000): string => {
  const t = s.replace(/\r\n/g, "\n").trimEnd();
  return t.length > max ? `...${t.slice(-max)}` : t;
};

/** `bound`, but a usage error keeps the `Error: ...` line that says what is wrong even when the usage text pushes it out of the tail. */
const boundKeepingError = (s: string, max = 4000): string => {
  const t = bound(s, max);
  const line = usageError(s);
  return line && !t.includes(line) ? `Error: ${line}\n${t}` : t;
};

/** Runs every check. Never throws for a problem it can report; throws only for programmer errors. */
export async function runDoctor(opts: DoctorOptions): Promise<DoctorReport> {
  const cfg = opts.cfg;
  const log = opts.log ?? (() => {});
  const timeoutMs = opts.startupTimeoutMs ?? 10_000;
  const which = opts.which ?? ((name: string, path: string) => findOnPath(name, path));
  const make = opts.makeSandbox ?? createSandbox;
  let servers: NamedServer[] = cfg.servers;
  if (opts.server) {
    servers = cfg.servers.filter((s) => s.name === opts.server);
    if (!servers.length) {
      throw new Error(`no server named "${opts.server}" is selected (selected: ${cfg.servers.map((s) => s.name).join(", ")})`);
    }
  }

  const environment: DoctorItem[] = [nodeItem()];
  const sysPath = process.env.PATH ?? process.env.Path ?? "";
  const commands = servers.map((s) => (s.spec.command ? baseName(s.spec.command) : ""));
  for (const id of ["npx", "uvx", "git"] as const) environment.push(toolItem(id, sysPath, commands.includes(id), which));
  // Listed while the servers start (it only runs `ipcs`), and added to the environment lines at the end.
  const segments = (async (): Promise<DoctorItem | undefined> => {
    try {
      const rows = await (opts.segments ?? listSegments)();
      return rows ? segmentItem(orphanedSegments(rows, { user: opts.user ?? userInfo().username, alive: opts.pidAlive })) : undefined;
    } catch {
      return undefined; // no ipcs here: nothing to say
    }
  })();
  if (!cfg.sandbox.enabled) environment.push({ id: "sandbox-off", status: "warn", title: "the sandbox is off (--no-sandbox)", detail: "the server would inherit your environment; fs, git, exec, effects and sqlite packs are disabled and the run is CUSTOM" });

  let sb: Sandbox | undefined;
  let cleaned: Promise<void> | undefined;
  const launchedServers: LaunchedServer[] = [];
  // One shared promise: a signal that arrives during the normal end-of-run cleanup waits for it instead of skipping it.
  const cleanup = () =>
    (cleaned ??= (async () => {
      for (const h of launchedServers) await h.stop().catch(() => {});
      await sb?.destroy().catch(() => {});
    })());
  // SIGHUP too (a closed terminal): a launched server is in its own process group and would be orphaned.
  const unhook = opts.handleSignals !== false ? stopOnSignals(() => cleanup()) : () => {};
  const reports: DoctorServer[] = [];
  const suggestions: Suggestion[] = [];
  try {
    try {
      sb = await make({ ...(cfg.sandbox.dir ? { dir: cfg.sandbox.dir } : {}), maxBytes: cfg.sandbox.max_mib * 1024 * 1024, timeoutProbeSec: cfg.timeoutProbeSec, keepEnv: cfg.sandbox.keep_env, log });
    } catch (e) {
      environment.push({ id: "sandbox", status: "fail", title: "the sandbox could not be created", detail: `${(e as Error).message}${cfg.sandbox.dir ? ` (sandbox.dir is ${cfg.sandbox.dir})` : ""}` });
    }
    if (sb) environment.push(...(await sandboxItems(sb, 3000)));
    if (sb) for (const s of servers) reports.push(await checkServer(s, cfg, sb, { ...opts, startupTimeoutMs: timeoutMs, limitIsDefault: opts.startupTimeoutMs === undefined, onLaunched: (h) => launchedServers.push(h), onSuggestions: (list) => suggestions.push(...list.filter((x) => !suggestions.some((y) => y.id === x.id))) }, which));
  } finally {
    try {
      await cleanup();
    } finally {
      unhook();
    }
  }
  const orphans = await segments;
  if (orphans) environment.push(orphans);
  const all = [...environment, ...reports.flatMap((r) => r.items)];
  const failures = all.filter((i) => i.status === "fail").length;
  const warnings = all.filter((i) => i.status === "warn").length;
  return { ok: failures === 0, exitCode: failures === 0 ? 0 : 4, environment, servers: reports, summary: { failures, warnings }, suggestions };
}

// ---------------------------------------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------------------------------------

const MARK: Record<DoctorStatus, string> = { ok: "ok  ", warn: "warn", fail: "FAIL", info: "    " };

// Titles, details, names and stderr come from the server (or from what the harness saw of it): made inert here, in the text
// only. The DoctorReport itself, and so --json, keeps the raw values, like the JSON run report.
function lines(items: readonly DoctorItem[], indent = "  "): string[] {
  return items.flatMap((i) => [`${indent}${MARK[i.status]}  ${inert(i.title, MAX_REPORT_FIELD)}`, ...(i.detail ? [`${indent}      ${inert(i.detail, MAX_REPORT_FIELD)}`] : [])]);
}

/** A pre-formatted table row made inert segment by segment, so the runs of spaces that align its columns survive. */
const safeRow = (l: string): string => l.split(/( {2,})/).map((p, i) => (i % 2 ? p : inert(p, MAX_REPORT_FIELD))).join("");

/** The report as text for the terminal. */
export function renderDoctor(r: DoctorReport): string {
  const out: string[] = ["sealmark doctor", "", "Environment", ...lines(r.environment)];
  for (const s of r.servers) {
    out.push("", `Server "${inert(s.name, 200)}" (${s.transport}): ${inert(s.display, MAX_REPORT_FIELD)}`, ...lines(s.items));
    if (s.stderr) out.push("", "  server stderr:", ...inertLines(s.stderr).split("\n").map((l) => `    | ${l}`));
    if (s.classificationText) out.push("", ...s.classificationText.map(safeRow));
    if (s.packs.length) {
      out.push("", "Packs");
      // The candidate packs (round 6) are listed apart, so the columns of the standard rows keep their width and the label says what they are.
      const isCandidate = (p: DoctorPack) => CANDIDATE_PACKS.includes(p.pack);
      const row = (p: DoctorPack, w: number) => `  ${p.pack.padEnd(w)}  ${p.applies ? (p.pack === "effects" ? "may run  " : "would run") : "n/a      "}  ${p.requested || isCandidate(p) ? "" : "[not in packs: list] "}${inert(p.reason, MAX_REPORT_FIELD)}`;
      const std = s.packs.filter((p) => !isCandidate(p));
      const cand = s.packs.filter(isCandidate);
      const w = Math.max(...std.map((p) => p.pack.length));
      for (const p of std) out.push(row(p, w));
      if (cand.length) {
        out.push("  candidate packs (not part of the standard profile; each runs when its declaration exists in the config):");
        const wc = Math.max(...cand.map((p) => p.pack.length));
        for (const p of cand) out.push(row(p, wc));
      }
    }
  }
  if (r.suggestions?.length) {
    out.push("", "Suggestions (each one: why, the YAML to paste into sealmark.yaml, the equivalent flags)");
    for (const s of r.suggestions) {
      out.push(`  - ${inert(s.id, 200)}: ${inert(s.why, MAX_REPORT_FIELD)}`, ...s.config.trimEnd().split("\n").map((l) => `      ${inert(l, MAX_REPORT_FIELD)}`));
      if (s.flags.length) out.push(`      flags: ${s.flags.map((f) => inert(f, 200)).join("  ")}`);
    }
  }
  out.push("", r.ok ? `No problems found${r.summary.warnings ? ` (${r.summary.warnings} warning${r.summary.warnings === 1 ? "" : "s"})` : ""}. Next: sealmark run` : `${r.summary.failures} problem${r.summary.failures === 1 ? "" : "s"} found${r.summary.warnings ? `, ${r.summary.warnings} warning${r.summary.warnings === 1 ? "" : "s"}` : ""}. Fix the lines marked FAIL, then run: sealmark doctor`);
  return `${out.join("\n")}\n`;
}
