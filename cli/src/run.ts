import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { classifyTools, coreOnlyNotes, packsFor } from "./classify.js";
import { ConfigError, TEMPLATE_COMMAND, displaySpec, usesPlaceholders, type TemplateCtx } from "./config.js";
import type { IdentitySettings, ScopeSettings, UpstreamSettings } from "./config/model.js";
import { connectTimeoutMessage, isConnectTimeout, launchServer, LaunchError, stopOnSignals, wasInterrupted, type LaunchedServer } from "./launch.js";
import { leftoverDirs, pendingPids, startEmbedded, stopAll, type EmbeddedHandle } from "./embedded.js";
import { createLogObserver } from "./observers/log.js";
import { createProcessObserver, terminatePids } from "./observers/process.js";
import { startUpstream } from "./observers/upstream.js";
import { normVersion, versionWarnings } from "./resolve.js";
import { gradePack } from "./grade.js";
import { McpSession, ProtocolViolation, SessionError, discoverSqlTools, expandHarness, resolvePackage, usesBearer, type OpenOptions } from "./mcp.js";
import { MAX_TOOLS_PROBED, applyChecksConfig, boundSeen, protocolFailure, refusalQuality, runCore, variantsFor } from "./packs/core.js";
import { runDb } from "./packs/db.js";
import { effectsGateReason } from "./packs/effects.js";
import { ensureGitFixture } from "./packs/git.js";
import { RUN_ORDER, describeAll, getPack } from "./packs/index.js";
import { NO_SCOPE_TOOL, NO_UPSTREAM_STUB, NO_VALID_CALL, coverageNotes, listenerReachable } from "./packs/shared.js";
import { autoAddedPacks, rulesOf, suggestionsAfterRun, suggestionsFor } from "./doctor.js";
import { loadPlugins } from "./plugins.js";
import { discountUncounted, planContext, probesReport, runValidCalls, validateProbes, type ValidCalls } from "./probes.js";
import { SANDBOX_NON_GUARANTEE, createSandbox } from "./sandbox.js";
import { ROLES, ROLE_PASSWORD, SEED_DB, SEED_VERSION, deprovision, parseDsn, provision, roleDsn, terminateBackends, type PgTarget, type Role } from "./seed.js";
import { ensureSqliteFixture } from "./sqlite-fixtures.js";
import { stageFiles } from "./staged-files.js";
import { captureSurface } from "./surface.js";
import { CANDIDATE_PACKS, type CheckResult, type ConfigIntegrity, type DestroyResult, type EffectiveConfig, type IdentityAccess, type IdentityName, type Pack, type PackCtx, type PackId, type RunResult, type Sandbox, type SandboxInfo, type SealmarkConfig, type SqlTool, type Suggestion, type ToolClassification, type UpstreamStub } from "./types.js";

export interface RunOptions {
  /** The single-server view of the configuration. Used to build an EffectiveConfig when `effective` is absent (tests, library callers). */
  config: SealmarkConfig;
  /**
   * The merged, validated configuration from config/. When present it is the only source of settings; `config` is ignored.
   * When absent, run.ts builds a default-profile one from `config` and the options below and does NOT claim a config identity
   * (`RunResult.config` stays undefined), because nothing proved the run followed the standard profile.
   */
  effective?: EffectiveConfig;
  packs: PackId[];
  /** True when the user asked for these packs (flag or config) rather than getting the defaults. */
  packsExplicit: boolean;
  /** DSN of a superuser on an existing Postgres. Requires `yes`. */
  pg?: string;
  /** false disables the embedded Postgres. Default true. */
  embedded?: boolean;
  yes?: boolean;
  /** --active. Only the command line sets it; files and environment cannot. */
  active?: boolean;
  timeoutProbeSec: number;
  log: (s: string) => void;
}

/** The harness itself failed (server would not start, database unavailable). The CLI exits 4. */
export class HarnessError extends Error {
  /** Short advice for the user, for example a pin hint when the server's dependencies drifted. */
  hint?: string;
  /** Bounded copy of the server's stderr, for `<out>.stderr.log`. */
  stderr?: string;
  constructor(message: string, extra: { hint?: string; stderr?: string } = {}) {
    super(message);
    this.hint = extra.hint;
    this.stderr = extra.stderr;
  }
}

const LEGACY_METHODOLOGY = "0.1-draft";
const CANARY_ENV = ["SEALMARK_CANARY", "SEALMARK_FAKE_API_KEY"] as const;

function version(): string {
  try {
    return String((JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: string }).version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

export const UNAUTHORIZED_HINT = "the server answered 401: pass a token with --bearer or --header";

/**
 * The MCP SDK's error does not carry the HTTP status, so a server that needs a token and was given none would only say
 * "Error POSTing to endpoint". When no Authorization header is configured, ask the URL once more; a 401 gets a hint that says what to type.
 */
async function unauthorizedHint(spec: { url?: string; headers?: Record<string, string> }, ctx: TemplateCtx): Promise<string | undefined> {
  if (!spec.url || Object.keys(spec.headers ?? {}).some((k) => k.toLowerCase() === "authorization")) return undefined;
  try {
    const r = await fetch(expandHarness(spec.url, ctx), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k, expandHarness(v, ctx)])) },
      body: "{}",
      signal: AbortSignal.timeout(3_000),
    });
    await r.body?.cancel().catch(() => {});
    return r.status === 401 ? UNAUTHORIZED_HINT : undefined;
  } catch {
    return undefined;
  }
}

const EMPTY_CTX: TemplateCtx = { vars: {}, dsns: {} };

/** Packs whose probes read or write the sandbox directories: they mean nothing when the server is not confined to it. */
const NEEDS_SANDBOX = new Set<PackId>(["fs", "git", "exec", "effects", "sqlite"]);
/** Packs that need the harness to have started the server (stdio, or `server.command` with `server.url`), so an already-running HTTP server cannot be graded by them. */
const NEEDS_HARNESS_START = new Set<PackId>(["fs", "git", "exec", "effects", "sqlite"]);

// Round 6 settings: optional in the EffectiveConfig type so a hand-built config keeps compiling; loadEffectiveConfig always sets them.
const upstreamSettings = (eff: EffectiveConfig): Partial<UpstreamSettings> => eff.upstream ?? {};
const scopeSettings = (eff: EffectiveConfig): Partial<ScopeSettings> => eff.scope ?? {};
const identitySettings = (eff: EffectiveConfig): Partial<IdentitySettings> => eff.identities ?? {};
const BEARER_USED = /\{bearer(?::[ab])?\}/;

/** Addendum 1.4: no valid call at all is hygiene-only; fewer than half the tools reached is low. */
export function coverageLevel(validCalls: number, toolsCalledValid: number, toolsTotal: number): "hygiene-only" | "low" | "covered" {
  if (validCalls === 0) return "hygiene-only";
  return toolsCalledValid < Math.ceil(toolsTotal / 2) ? "low" : "covered";
}

/**
 * A badge needs the published standard profile and at least one graded pack besides core, and no grade that rests on a check
 * nobody could measure: a provisional grade, or a critical check that came back inconclusive (`checks`, when the caller has them),
 * withholds it. A plain grade of any letter stays eligible: the badge shows the per-pack letters, so a low one is honest.
 * `integrity` is undefined when the run did not load a configuration (library callers): nothing proves it followed the standard profile.
 */
export function badgeFor(integrity: ConfigIntegrity | undefined, packs: RunResult["packs"], checks: readonly CheckResult[] = []): { eligible: boolean; reason?: string } {
  if (!integrity) return { eligible: false, reason: "the run did not load a configuration, so it cannot be shown to follow the standard profile" };
  if (!integrity.standard) return { eligible: false, reason: "custom run: the configuration differs from the published standard profile" };
  // The candidate packs (scope, sql-guard, upstream) are scored but sit outside the standard, so they never make a run badge-eligible.
  if (!Object.entries(packs).some(([id, p]) => id !== "core" && !CANDIDATE_PACKS.includes(id as PackId) && p?.status === "graded")) return { eligible: false, reason: "core-only run: no capability pack was graded" };
  if (Object.entries(packs).some(([id, p]) => !CANDIDATE_PACKS.includes(id as PackId) && p?.status === "graded" && p.grade?.provisional)) return { eligible: false, reason: "a pack is provisional: a critical check was inconclusive" };
  if (checks.some((c) => !CANDIDATE_PACKS.includes(c.pack) && c.critical && !c.advisory && c.verdict === "inconclusive")) return { eligible: false, reason: "a pack has an inconclusive critical check" };
  return { eligible: true };
}

// ---------------------------------------------------------------------------------------------------------
// Legacy adapter
// ---------------------------------------------------------------------------------------------------------

/** What `loadEffectiveConfig` would return for a plain run with nothing but a server block: default sandbox, no overrides. */
export function legacyEffectiveConfig(o: { config: SealmarkConfig; packs: PackId[]; packsExplicit: boolean; timeoutProbeSec: number; active?: boolean; yes?: boolean; pg?: string; embedded?: boolean }): EffectiveConfig {
  const { config } = o;
  return {
    schemaVersion: 1,
    name: config.name,
    version: config.version,
    profile: "legacy",
    profileChain: [],
    server: config.server,
    servers: [{ name: config.name, spec: config.server }],
    serverNames: [config.name],
    sqlTools: config.sql_tools,
    packs: o.packs,
    packsExplicit: o.packsExplicit,
    timeoutProbeSec: o.timeoutProbeSec,
    hangMs: Math.max(2000, o.timeoutProbeSec * 1000),
    checks: {},
    sandbox: { enabled: true, dir: null, keep: false, scrub_env: true, keep_env: [], pack_timeout_sec: 600, max_mib: 1024 },
    tools: { include: ["*"], exclude: [], overrides: {} },
    timeouts: { connect_ms: 60_000, call_ms: 30_000, probe_ms: 10_000 },
    retries: { call: 0 },
    net: { control_url: null, allow_dns: false },
    output: {
      format: "text",
      formats: ["text"],
      out: null,
      out_dir: null,
      verbosity: "normal",
      redact: true,
      template: null,
      baseline: null,
      write_baseline: null,
      fail_on: ["any"],
      exit_policy: { fail_under: null, regressions_only: false, soft_fail: false, treat_inconclusive_as: "fail", critical_fail: 0 },
    },
    plugins: [],
    probes: [],
    sqlite: { engine: null },
    db: { embedded: o.embedded ?? null, pg: o.pg ?? null },
    notCoveredExtra: [],
    active: Boolean(o.active),
    yes: Boolean(o.yes),
    value: {},
    origins: {},
    // Not a claim of any kind: run.ts leaves RunResult.config undefined for a legacy run.
    integrity: { hash: "", profile: "legacy", standard: false, standardDiff: [], methodology: LEGACY_METHODOLOGY, schemaVersion: 1, locked: {} },
    warnings: [],
    files: [],
    env: {},
    cwd: process.cwd(),
  };
}

// ---------------------------------------------------------------------------------------------------------

/** One pack that did not produce checks: why, and whether that is "not applicable" or "could not be judged". */
interface Skip {
  status: "na" | "inconclusive";
  reason: string;
}

/**
 * The pack line for a pack that ran. Inconclusive dominates not-applicable: when every check that applied was
 * inconclusive (a failed control, an unreadable fixture), the pack is inconclusive and says why, even if other checks
 * were not applicable. "Not applicable" is only for a pack in which nothing applied at all.
 */
export function packStatus(pack: PackId, checks: CheckResult[], isBase = false): RunResult["packs"][PackId] & object {
  const mine = checks.filter((c) => c.pack === pack && !c.advisory);
  const grade = gradePack(pack, checks);
  if (grade) return { status: "graded", grade };
  if (!isBase && !checks.some((c) => c.pack === pack)) return { status: "na", reason: "the pack produced no checks" };
  const live = mine.filter((c) => c.verdict !== "na");
  if (live.length && live.every((c) => c.verdict === "inconclusive")) return { status: "inconclusive", reason: live[0]!.summary };
  return { status: "na", reason: mine.find((c) => c.verdict === "na")?.summary ?? "no check produced a scored verdict" };
}

/**
 * The last sweep of an interrupted run: the processes the sandbox owns, then every direct child of this process with its tree.
 * A server still starting when the signal came is in no list of ours, and where the platform cannot tell a process's working
 * directory (macOS) the sandbox cannot find it either; it is still our child. Best effort: the process exits right after.
 */
async function reapChildren(sb: Sandbox | undefined, keep: ReadonlySet<number> = new Set()): Promise<void> {
  // No sandbox yet (a signal while the database was starting): the observer is only used to list our own children.
  const none = join(tmpdir(), "sealmark-no-sandbox");
  const proc = sb?.proc ?? createProcessObserver({ sandboxDir: none, bin: join(none, "bin") });
  try {
    // One listing, one kill: every `ps` costs seconds on a loaded machine, and the signal handler has 15 s in all.
    const all = await proc.list();
    const kids = new Map<number, number[]>();
    for (const p of all) kids.set(p.ppid, [...(kids.get(p.ppid) ?? []), p.pid]);
    const tree = (root: number, into: Set<number>): Set<number> => {
      for (let stack = [root]; stack.length; ) {
        const pid = stack.pop()!;
        if (into.has(pid)) continue;
        into.add(pid);
        stack.push(...(kids.get(pid) ?? []));
      }
      return into;
    };
    const victims = new Set<number>();
    for (const p of sb ? await sb.proc.strays(all) : []) tree(p.pid, victims);
    // Our direct children (the listing command itself is one of them and is already gone by now).
    for (const p of all) if (p.ppid === process.pid && !keep.has(p.pid) && !/^ps(\.exe)?$/i.test(p.name)) tree(p.pid, victims);
    victims.delete(process.pid);
    // The embedded Postgres processes the registry knows are shut down politely afterwards (their shared-memory segment is released only then).
    for (const k of keep) for (const t of tree(k, new Set())) victims.delete(t);
    if (victims.size) await terminatePids([...victims].reverse());
  } catch {
    /* listing is best effort */
  }
}

/** At most this many per-tool gap lines are printed; the rest are counted. */
export const MAX_GAP_LINES = 12;

/**
 * What the capability packs (fs, git, net, sqlite, effects) said they could not exercise, once per tool (the first reason wins), skipping the
 * tools already named in `said` (which the harness lists itself), bounded at MAX_GAP_LINES lines plus a count of the rest.
 */
export function capabilityGaps(checks: readonly CheckResult[], said: Set<string> = new Set()): string[] {
  const lines: string[] = [];
  for (const p of ["fs", "git", "net", "sqlite", "effects"]) {
    for (const line of coverageNotes(checks, p)) {
      const tool = /^tool "([^"]+)"/.exec(line)?.[1];
      if (tool !== undefined) {
        if (said.has(tool)) continue;
        said.add(tool);
      }
      lines.push(line);
    }
  }
  if (lines.length <= MAX_GAP_LINES) return lines;
  return [...lines.slice(0, MAX_GAP_LINES), `${lines.length - MAX_GAP_LINES} more tool gaps in the capability packs are listed in each check's coverage in the JSON report`];
}

/** The line in the configuration file where the selected server's command (or url) is set, for the SARIF and JUnit locations; undefined when it did not come from a file. */
function serverLine(eff: EffectiveConfig): number | undefined {
  for (const base of ["/server", `/servers/${eff.name}`]) {
    for (const leaf of ["command", "url"]) {
      const o = eff.origins[`${base}/${leaf}`];
      if (o?.line !== undefined) return o.line;
    }
  }
  return undefined;
}

/** Waits for `p`, but never longer than `ms`; a rejection counts as settled. */
async function within<T>(p: Promise<T> | undefined, ms: number): Promise<T | undefined> {
  if (!p) return undefined;
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p.catch(() => undefined), new Promise<undefined>((res) => (timer = setTimeout(() => res(undefined), ms)))]);
  } finally {
    clearTimeout(timer);
  }
}

export async function runHarness(opts: RunOptions): Promise<RunResult> {
  // A signal already stopped an earlier server of this invocation: nothing new is started for the next one.
  if (wasInterrupted()) throw new HarnessError("the run was interrupted, so no further server was started");
  const t0 = Date.now();
  const startedAt = new Date().toISOString();
  const legacy = !opts.effective;
  const eff = opts.effective ?? legacyEffectiveConfig(opts);
  const { log } = opts;
  const spec = eff.server;
  const transport = spec.url ? "http" : "stdio";
  if (spec.command === TEMPLATE_COMMAND) {
    throw new ConfigError(`server.command is still "${TEMPLATE_COMMAND}", the placeholder sealmark init writes when it finds no MCP client configuration. Replace it with the command that starts the MCP server you want to grade (or use init --from "<command>" / --from-url <url>).`);
  }
  const active = opts.active ?? eff.active;
  const yes = opts.yes ?? eff.yes;
  const timeoutProbeSec = opts.timeoutProbeSec;
  // exec runs only with --active. A profile, file or the environment that lists it was already warned (loadEffectiveConfig): it just does
  // not run. Typed as --pack exec on the command line (or with no origin to say otherwise) it is a usage error, below.
  const execNeedsActive = opts.packs.includes("exec") && !active;
  const packsLayer = eff.origins["/packs"]?.layer;
  const execFromConfig = execNeedsActive && opts.packsExplicit && packsLayer !== undefined && packsLayer !== "flag";
  const configuredPacks = execFromConfig ? opts.packs.filter((p) => p !== "exec") : opts.packs;
  // A probe with a check is a check the user asked for. The default pack list has no `custom`, so without this it would never run
  // and a failing check could not reach the gate. The run stays CUSTOM either way (a check probe differs from the standard profile).
  // Only a list nobody chose is extended: a list typed with --pack or written in a file is respected, and the skipped probes are said so.
  // The rule is doctor's `autoAddedPacks`, so `doctor` and `run` cannot disagree; the candidate packs it
  // adds (scope, sql-guard, upstream) are applied after discovery, when it is known whether a SQL tool exists.
  const packView: EffectiveConfig = { ...eff, packs: configuredPacks, packsExplicit: opts.packsExplicit };
  const isCandidate = (id: PackId) => CANDIDATE_PACKS.includes(id);
  const early = autoAddedPacks(packView, { hasSqlTool: false });
  const addCustom = early.packs.includes("custom");
  const packList: PackId[] = addCustom ? [...configuredPacks, "custom" as PackId] : [...configuredPacks];
  const requested = new Set<PackId>(packList);
  const packNotes: string[] = [];
  for (const note of [...early.notes.filter((_, i) => early.packs[i] === "custom"), ...early.skipped.filter((t) => t.startsWith("probes with a check"))]) {
    packNotes.push(note);
    log(`note: ${note}`);
  }
  const wantCore = requested.has("core");
  const wantDb = requested.has("db");
  const placeholders = usesPlaceholders(spec);
  const pgDsn = opts.pg ?? eff.db.pg ?? undefined;
  const embeddedOn = opts.embedded ?? eff.db.embedded ?? undefined;
  // The server cannot even start without a connection string when the config uses placeholders,
  // so a database is started for any pack (not only db) as long as a source for one exists.
  const needDb = placeholders && Boolean(pgDsn || embeddedOn !== false);
  if (needDb && pgDsn && !yes) {
    throw new ConfigError(`--pg drops and recreates the database ${SEED_DB} and creates roles sm_analyst, sm_support and sm_admin on that server. Add --yes to allow it.`);
  }
  if (execNeedsActive && opts.packsExplicit && !execFromConfig) {
    throw new ConfigError("the exec pack asks a command-running tool to run harness-owned programs and needs --active on the command line (it cannot be switched on from a file or the environment). Only use it on servers you trust or inside a throwaway VM.");
  }

  const methodology = legacy ? LEGACY_METHODOLOGY : eff.integrity.methodology;
  const clientVersion = version();
  // Plugins load first: a bad module, a version mismatch or a colliding check id is a config error and must not cost a server start.
  const pluginPacks = await loadPlugins(eff.plugins, {
    sealmarkVersion: clientVersion,
    baseDir: eff.configPath ? dirname(eff.configPath) : eff.cwd,
    reservedCheckIds: describeAll().map((d) => d.id),
  });

  const sessions: McpSession[] = [];
  let embedded: EmbeddedHandle | undefined;
  let target: PgTarget | undefined;
  let external = false;
  let seeded = false;
  let sandbox: Sandbox | undefined;
  /** A server Sealmark started itself (server.command + server.url). Stopped after the sessions close. */
  let launched: LaunchedServer | undefined;
  /** The upstream stub (round 6), closed right after the sessions and the launched server. */
  let upstreamStub: UpstreamStub | undefined;
  let destroyed: DestroyResult | undefined;
  let cleaned: Promise<void> | undefined;
  // Work that was abandoned (a pack past its timeout) can still be starting a server when the run ends; such a session is closed on arrival.
  let finished = false;
  let interrupted = false;
  /** The work that is running right now (the pack, the db pack, the core run): an interrupted cleanup waits for it, briefly, before it deletes what it uses. */
  let inflight: Promise<void> | undefined;
  const track = <T>(p: Promise<T>): Promise<T> => {
    inflight = p.then(
      () => undefined,
      () => undefined,
    );
    return p;
  };
  /** The sandbox while it is being created: a signal in that window finds `sandbox` unset. */
  let creating: Promise<Sandbox> | undefined;
  const destroySandbox = async (): Promise<void> => {
    if (!sandbox) return;
    try {
      destroyed = await sandbox.destroy({ keep: eff.sandbox.keep });
    } catch (e) {
      destroyed = { cleanedUp: false, leftover: [`${(e as Error).message}`], path: sandbox.dir };
    }
  };
  const cleanup = () =>
    (cleaned ??= (async () => {
      finished = true;
      // The waits that can hang under interrupt (the running work, the seed database, the embedded Postgres) share one budget; the signal
      // handler's own bail is at 15 s.
      const budget = Date.now() + 12_000;
      const room = (cap: number): number => Math.max(300, Math.min(cap, budget - Date.now()));
      // Together: each close waits for its server's process tree to go, and the signal handler has 15 s in all.
      await Promise.all(sessions.map((s) => s.close()));
      if (launched) await launched.stop();
      if (upstreamStub) await within(upstreamStub.close(), 3000);
      if (interrupted) {
        // A server a session was still starting is in no list above: sweep our children, then give the work that was running a moment to see
        // its sessions closed and unwind, before its files go. Every embedded Postgres the registry knows is left alone here: it is shut
        // down politely below (a SIGKILL would leave its shared-memory segment behind).
        await reapChildren(sandbox, new Set(pendingPids()));
        if (!sandbox && creating) sandbox = await within(creating, 3000);
        await within(inflight, room(3000));
      }
      await destroySandbox();
      if (target && seeded) {
        try {
          if (interrupted) await within(terminateBackends(target), room(3000));
          else await terminateBackends(target);
        } catch {
          /* the database may already be gone */
        }
        if (external) {
          try {
            await deprovision(target);
          } catch {
            /* best effort */
          }
        }
      }
      let leftPg: string[] = [];
      // Under interrupt the registry decides, not this function's variables: a start that has no handle yet (its data directory and password file
      // exist), a server whose handle is on its way here, and a live one are all stopped politely, bounded, and their segment is released.
      if (interrupted) leftPg = await stopAll({ deadlineMs: room(6000) }).catch(() => leftoverDirs());
      else if (embedded) await embedded.stop().catch(() => {});
      if (!interrupted) return;
      // Last, and inside this promise: the process exits when it settles. Whatever the dying processes recreated goes in a second pass.
      await reapChildren(sandbox);
      if (sandbox && !eff.sandbox.keep && existsSync(sandbox.dir)) await destroySandbox();
      const left = [...(sandbox && !eff.sandbox.keep && existsSync(sandbox.dir) ? [sandbox.dir] : []), ...leftPg];
      if (left.length) log(`cleanup did not finish: ${left.join(", ")} (remove ${left.length === 1 ? "it" : "them"} by hand)`);
      // A kept sandbox is not "cleaned up": the last line names where it is.
      if (sandbox && eff.sandbox.keep) log(`kept sandbox: ${sandbox.dir}`);
      else if (!left.length) log("cleaned up");
    })());
  // SIGHUP too: the server is in its own process group, so a closed terminal would not reach it.
  const unhook = stopOnSignals(
    () => {
      // No pack is scheduled from here on, and cleanup ends with a sweep for a server that was still starting.
      finished = true;
      interrupted = true;
      return cleanup();
    },
    () => log("interrupted: cleaning up (press Ctrl+C again to force quit)"),
    { leftovers: () => (sandbox && !eff.sandbox.keep && existsSync(sandbox.dir) ? [sandbox.dir] : []) },
  );

  let result: RunResult;
  try {
    // ---- database (embedded or external) ----
    if (needDb) {
      if (pgDsn) {
        try {
          target = parseDsn(pgDsn);
        } catch {
          throw new ConfigError("--pg must be a postgres:// URL for a superuser, for example postgres://postgres:secret@localhost:5432/postgres");
        }
        external = true;
      } else {
        try {
          const port = await freePort();
          log(`starting an embedded Postgres on port ${port}`);
          embedded = await startEmbedded(port, true, { cancelled: () => interrupted });
          // The signal can fall between the server becoming ready and this line: the registry already has it, but nothing else may go on with it.
          if (interrupted) {
            await stopAll({ deadlineMs: 6000 }).catch(() => []);
            throw new Error("the run was interrupted, so the embedded Postgres was not used");
          }
          target = embedded.target;
        } catch (e) {
          throw new HarnessError((e as Error).message);
        }
      }
      try {
        log(external ? `provisioning ${SEED_DB} on ${target.host}:${target.port}` : `provisioning ${SEED_DB}`);
        await track(provision(target, log));
        seeded = true;
      } catch (e) {
        throw new HarnessError(`could not set up the seed database: ${(e as Error).message}`);
      }
    }
    const db = target;

    // ---- sandbox (also provides the loopback listener when the server itself is not confined) ----
    // A server Sealmark starts itself (server.command + server.url) runs inside the sandbox like a stdio server: its cwd is the sandbox
    // root and its environment is the scrubbed one. A server that is already running cannot be confined.
    const selfStarted = transport === "http" && Boolean(spec.command);
    const sandboxOn = eff.sandbox.enabled && (transport === "stdio" || selfStarted);
    if (interrupted) throw new HarnessError("the run was interrupted");
    try {
      creating = createSandbox({
        ...(eff.sandbox.dir ? { dir: eff.sandbox.dir } : {}),
        maxBytes: eff.sandbox.max_mib * 1024 * 1024,
        timeoutProbeSec,
        keepEnv: eff.sandbox.keep_env,
        log,
      });
      sandbox = await creating;
    } catch (e) {
      throw new HarnessError(`could not create the sandbox: ${(e as Error).message}`);
    }
    const sb = sandbox;
    const envMode: SandboxInfo["envMode"] = sandboxOn && eff.sandbox.scrub_env ? "scrubbed" : "inherited";
    if (!eff.sandbox.enabled) log("the sandbox is off (--no-sandbox): the server inherits your environment and the fs, git, exec and effects packs are disabled");

    // ---- upstream stub (round 6): the server's backend, when the config asks for one and the server uses {upstream} ----
    const up = upstreamSettings(eff);
    const specJson = JSON.stringify(spec);
    if (up.kind === "http" && specJson.includes("{upstream}")) {
      const reachable = listenerReachable(spec, eff.env);
      if (reachable.ok === false) {
        throw new ConfigError(`the server runs on ${reachable.host}, which cannot reach the harness's upstream stub (it listens on this machine's loopback only). Run the server on this machine, or remove upstream.kind.`);
      }
      try {
        upstreamStub = await startUpstream({
          responses: up.responses ?? [],
          defaultReply: up.default_reply ?? { status: 200, json: {} },
          maxBodyBytes: (up.max_body_kib ?? 1024) * 1024,
          slowHoldMs: (timeoutProbeSec + 30) * 1000,
          ...(up.credential_header ? { credentialHeader: up.credential_header } : {}),
          log,
        });
      } catch (e) {
        throw new HarnessError(`could not start the upstream stub: ${(e as Error).message}`);
      }
      log(`the upstream stub is listening on ${upstreamStub.url}`);
    }
    // ---- identities (round 6): two caller identities for {bearer:a} / {bearer:b}; `identities.*` overrides the minted values ----
    const idCfg = identitySettings(eff);
    const bearers: Record<IdentityName, string> = {
      a: idCfg.a || `sm-bearer-a-${randomBytes(6).toString("hex")}`,
      b: idCfg.b || `sm-bearer-b-${randomBytes(6).toString("hex")}`,
    };
    const bearerUsed = BEARER_USED.test(specJson);
    // ---- the server's log: what a launched server prints, and the stderr of stdio sessions ----
    const logObs = transport === "stdio" || selfStarted ? createLogObserver() : undefined;
    logObs?.push("", transport === "stdio" ? "stderr" : "launched");

    const sqlitePath = `${sb.root}${process.platform === "win32" ? "\\" : "/"}fixture.sqlite`;
    const harnessVars = (): Record<string, string> => ({
      sandbox: sb.root,
      sandbox_home: sb.home,
      listener: sb.listener.url,
      sqlite_path: sqlitePath,
      duckdb_path: `${sb.root}${process.platform === "win32" ? "\\" : "/"}fixture.duckdb`,
      ...(upstreamStub ? { upstream: upstreamStub.url } : {}),
      bearer: bearers.a,
      "bearer:a": bearers.a,
      "bearer:b": bearers.b,
    });
    // Real servers open their repository or database file at startup, and the discovery session starts before any pack does,
    // so the fixtures a config refers to must exist before the first open().
    if (sandboxOn) {
      const specText = JSON.stringify(spec);
      if (/\{(?:sandbox|dir)\}(?:\\\\|\/)+repo/.test(specText)) {
        try {
          await ensureGitFixture(sb);
        } catch (e) {
          log(`could not build the git fixtures: ${(e as Error).message}`);
        }
      }
      if (specText.includes("{sqlite_path}")) {
        try {
          ensureSqliteFixture(sqlitePath);
        } catch (e) {
          log(`could not build the sqlite fixture: ${(e as Error).message}`);
        }
      }
    }
    const withEnv = (c: TemplateCtx): TemplateCtx => (legacy ? c : ({ ...c, env: eff.env } as TemplateCtx));
    const roleCtx = (role: Role): TemplateCtx => {
      if (!db) return withEnv({ vars: harnessVars(), dsns: {} });
      const dsns = Object.fromEntries(ROLES.map((r) => [r, roleDsn(db, r)]));
      return withEnv({ vars: { ...harnessVars(), dsn: dsns[role], host: db.host, port: String(db.port), user: `sm_${role}`, password: ROLE_PASSWORD, database: SEED_DB, role }, dsns });
    };
    const baseCtx = (): TemplateCtx => withEnv({ vars: harnessVars(), dsns: {} });
    // server.files: written once, before the discovery session opens (after the fixtures above, which a file may point at). A server Sealmark
    // does not start cannot see the sandbox, and without the sandbox there is nowhere to write.
    if (spec.files?.length) {
      if (transport === "http" && !spec.command) throw new ConfigError("staged files need a server Sealmark starts; a server that is already running cannot see the sandbox");
      if (!eff.sandbox.enabled) throw new ConfigError("staged files (server.files) need the sandbox: remove --no-sandbox");
      stageFiles(spec.files, baseCtx(), { sandbox: sb.root, home: sb.home }, log);
    }
    // server.command + server.url: Sealmark starts the server itself. Canary secrets are injected for it, as for a stdio server.
    const canaries = transport === "stdio" || selfStarted ? [`sm-canary-${randomBytes(8).toString("hex")}`, `sk-sealmark-fake-${randomBytes(12).toString("hex")}`] : [];
    const extraEnv = Object.fromEntries(canaries.map((c, i) => [CANARY_ENV[i], c]));
    // What the secret-echo scan looks for: the canaries, and the two bearer values when the server is configured with {bearer} (an echoed credential is a leak).
    // Only where canaries exist: an already-running HTTP server keeps its "secret-echo was not run" line.
    const scanSecrets = canaries.length && bearerUsed ? [...canaries, bearers.a, bearers.b] : canaries;
    // Start the server, wait until the URL answers, and keep it up for every pack.
    if (selfStarted) {
      if (placeholders) {
        throw new ConfigError("database placeholders ({dsn}, {host}, {password}, ...) cannot be used when Sealmark starts the server with --start and --url: the server is started once, outside the database roles. Use a stdio server (no --url) for the db pack, or remove the placeholders.");
      }
      const lctx = baseCtx();
      const launchEnv = { ...Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expandHarness(v, lctx)])), ...extraEnv };
      try {
        // `launched` is set as soon as the process exists (onStarted), so a Ctrl+C or SIGTERM while still waiting can stop it.
        await launchServer({
          command: expandHarness(spec.command!, lctx),
          args: (spec.args ?? []).map((a) => expandHarness(a, lctx)),
          env: launchEnv,
          // Inside the sandbox like a stdio server: its working directory is the sandbox root and, unless sandbox.scrub_env is off, its
          // environment is the scrubbed one.
          ...(sandboxOn ? { cwd: sb.root, ...(eff.sandbox.scrub_env ? { baseEnv: sb.env(launchEnv) } : {}) } : {}),
          ...(logObs ? { onOutput: (chunk: string) => logObs.push(chunk, "launched") } : {}),
          url: expandHarness(spec.url!, lctx),
          timeoutMs: (spec.start_timeout_sec ?? 60) * 1000,
          onProgress: log,
          onStarted: (h) => {
            launched = h;
          },
        });
      } catch (e) {
        throw new HarnessError(e instanceof LaunchError ? e.message : `could not start the server: ${(e as Error).message}`);
      }
    }
    /** Where and how the server process starts: the sandbox root with a scrubbed environment, or a throwaway cwd with everything inherited. */
    const where = (): OpenOptions =>
      transport === "http"
        ? {}
        : sandboxOn
          ? eff.sandbox.scrub_env
            ? { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed" }
            : { cwd: sb.root, envMode: "inherit" }
          : { cleanCwd: true, envMode: "inherit" };
    const open = async (ctx: TemplateCtx, extra: OpenOptions = {}): Promise<McpSession> => {
      // After a signal nothing starts again: a server spawned now would be in no list the cleanup sweeps, and would hold the sandbox open.
      if (finished) throw new SessionError("the run was interrupted, so the server was not started again");
      const s = await McpSession.open(spec, ctx, {
        clientVersion,
        connectTimeoutMs: eff.timeouts.connect_ms,
        onProgress: log,
        ...(logObs && transport === "stdio" ? { onStderr: (chunk: string) => logObs.push(chunk, "stderr") } : {}),
        ...where(),
        ...extra,
      });
      if (finished) {
        await s.close();
        throw new SessionError("the run has already finished, so the server was stopped again");
      }
      sessions.push(s);
      return s;
    };

    /** Per-caller sessions for one pack: `{bearer}` is that identity's value, or (null) every header that holds `{bearer}` is dropped. */
    const identityFor = (mine: McpSession[], over: () => boolean): IdentityAccess => ({
      identities: [
        { name: "a", bearer: bearers.a },
        { name: "b", bearer: bearers.b },
      ],
      openAs: async (who) => {
        const s = await open(withEnv({ vars: { ...harnessVars(), ...(who ? { bearer: bearers[who] } : {}) }, dsns: {} }), who === null ? { anonymous: true } : {});
        if (over()) {
          await s.close();
          throw new SessionError("the pack was already stopped, so the server was stopped again");
        }
        mine.push(s);
        return s;
      },
    });

    // ---- the server, once, for the core pack and for discovering its tools ----
    log("starting the server under test");
    let session: McpSession | undefined;
    let protocolChecks: CheckResult[] | undefined;
    try {
      session = await open(db ? roleCtx("admin") : baseCtx(), { extraEnv });
    } catch (e) {
      if (e instanceof ProtocolViolation) protocolChecks = protocolFailure(e.message);
      else if (e instanceof SessionError) {
        const hint = placeholders && !db ? " The config uses {dsn}-style placeholders but no database was started (--no-embedded without --pg), so they were empty." : "";
        const auth = transport === "http" ? await unauthorizedHint(spec, baseCtx()) : undefined;
        // The SDK's bare "MCP error -32001: Request timed out" names neither the limit nor the flag that raises it.
        const what = isConnectTimeout(e.message) ? connectTimeoutMessage(eff.timeouts.connect_ms) : `could not start or talk to the server: ${e.message}.`;
        throw new HarnessError(`${what}${hint}`, { hint: [auth, e.hint].filter(Boolean).join(" ") || undefined, stderr: e.stderr });
      } else throw e;
    }

    const tools = session?.tools ?? [];
    const warnings: string[] = [...eff.warnings, ...packNotes];
    const notCovered: string[] = [];
    let sqlTools: SqlTool[] = [];
    let sqlSkipped: { tool: string; reason: string }[] = [];
    let classification: ToolClassification[] = [];
    if (session) {
      const found = discoverSqlTools(tools, eff.sqlTools);
      sqlTools = found.tools;
      sqlSkipped = found.skipped;
      if (eff.sqlTools?.length) {
        for (const t of sqlTools) {
          const declared = tools.find((x) => x.name === t.tool);
          if (!declared) {
            throw new ConfigError(`sql_tools lists "${t.tool}" but the server declares no such tool (it declares: ${tools.map((x) => x.name).join(", ") || "none"}).`);
          }
          // A misspelled arg would make every control read fail and read as a connection problem.
          const props = declared.inputSchema?.properties ?? {};
          const p = props[t.arg];
          // An undeclared type (anyOf, $ref) is given the benefit of the doubt; a missing property or a type that is neither
          // a string nor an array of strings (the batch shape) is not.
          const types = p ? [p.type].flat() : [];
          const arrayOfStrings = types.includes("array") && [(p as { items?: { type?: string | string[] } } | undefined)?.items?.type].flat().includes("string");
          if (!p || (p.type !== undefined && !types.includes("string") && !arrayOfStrings)) {
            const strings = Object.keys(props).filter((k) => [props[k]?.type].flat().includes("string"));
            throw new ConfigError(`sql_tools: tool "${t.tool}" has no string argument named "${t.arg}" (its string arguments: ${strings.join(", ") || "none"}).`);
          }
        }
      }
      if (!tools.length) notCovered.push("the server declares no tools, so no tool behavior was probed");
      if (tools.length > MAX_TOOLS_PROBED) notCovered.push(`malformed-input probes cover the first ${MAX_TOOLS_PROBED} of ${tools.length} tools`);
      const classified = classifyTools({ tools, sqlTools: eff.sqlTools, overrides: eff.tools.overrides, include: eff.tools.include, exclude: eff.tools.exclude });
      classification = classified.classification;
      warnings.push(...classified.warnings);
      // Excluded tools are not given to the db pack either.
      const excluded = new Set(classification.filter((c) => c.excluded).map((c) => c.tool));
      // So is a tool that `tools.overrides` gives another class: the override says what the tool is, over the name-based SQL detection.
      const overridden = new Set(classification.filter((c) => c.source === "override" && c.class !== "sql").map((c) => c.tool));
      sqlTools = sqlTools.filter((t) => !excluded.has(t.tool) && !overridden.has(t.tool));
    }
    const visibleTools = tools.filter((t) => !classification.find((c) => c.tool === t.name)?.excluded);
    const excludedTools = classification.filter((c) => c.excluded).map((c) => c.tool);
    // What the probes read besides the session: the stub, the server log, and what validation is told about them.
    const rulesEnv = {
      ...(upstreamStub ? { upstream: upstreamStub } : {}),
      ...(logObs ? { serverLog: logObs } : {}),
    };
    const plan = planContext(eff, upstreamStub);
    // A mistake in any probe is a config error, and it must surface before the first tool call, whichever packs run.
    if (session && eff.probes.length) {
      validateProbes(eff.probes, {
        tools: visibleTools,
        classification,
        sandbox: sb,
        reservedCheckIds: describeAll().map((d) => d.id),
        defaultTimeoutMs: eff.timeouts.probe_ms,
        ...plan,
      });
    }

    const checks: CheckResult[] = [];
    let valid: ValidCalls | undefined;
    if (wantCore) {
      if (session) {
        log("core pack");
        // Probes without a check are valid calls: made once here, before robust-input, so they count toward coverage,
        // feed the secret-echo scan and are scanned for stack traces.
        if (eff.probes.length) {
          // A valid call with `identity:` opens its own session as that caller; those sessions are closed with the core phase.
          const coreMine: McpSession[] = [];
          const coreIdentity = transport === "http" && bearerUsed ? identityFor(coreMine, () => false) : undefined;
          try {
            valid = await track(runValidCalls({ session, probes: eff.probes, tools: visibleTools, classification, sandbox: sb, active, defaultTimeoutMs: eff.timeouts.probe_ms, canaries: scanSecrets, listenerReachable: listenerReachable(spec, eff.env).ok, ...rulesEnv, ...(coreIdentity ? { openAs: coreIdentity.openAs } : {}), plan }));
          } finally {
            for (const s of coreMine) await s.close();
            upstreamStub?.setOverride(undefined);
          }
          warnings.push(...valid.warnings);
        }
        const robust = eff.checks["robust-input"];
        const coreChecks = await track(runCore({
          session,
          canaries: scanSecrets,
          seen: boundSeen(valid?.seen ?? [], scanSecrets),
          checks: eff.checks,
          hangMs: eff.hangMs,
          ...(valid
            ? {
                validCalls: valid.calls
                  .filter((c) => c.valid)
                  .map((c) => ({ tool: c.tool, args: (c.args ?? {}) as Record<string, unknown>, text: c.excerpt, isError: c.isError })),
              }
            : {}),
          noValidCalls: excludedTools,
          ...(typeof robust?.max_tools === "number" ? { maxTools: robust.max_tools } : {}),
        }));
        // Every valid call is handed to robust-input (it scans each response for internals), but a call that was rejected, or missed
        // its expectations, exercised no tool behaviour and must not raise the coverage.
        const noValid = new Set(excludedTools);
        const ownValid = (tool: string) => {
          const t = tools.find((x) => x.name === tool);
          return Boolean(t && !noValid.has(tool) && variantsFor(t, true).variants.some((v) => v.valid));
        };
        checks.push(...coreChecks.map((c) => (valid && c.id === "robust-input" && c.coverage ? { ...c, coverage: discountUncounted(c.coverage, valid, ownValid) } : c)));
      } else if (protocolChecks) checks.push(...applyChecksConfig(protocolChecks, eff.checks));
    }
    const serverInfoVersion = session?.serverInfo.version;
    await session?.close();

    // ---- db pack ----
    let dbReason: string | undefined;
    if (!wantDb) dbReason = "pack not requested";
    else if (!placeholders) dbReason = "server config has no {dsn}/{host}/... placeholder, so the harness cannot start the server once per role";
    else if (!session) dbReason = "the server's tool list could not be read, so its SQL tools could not be found";
    else if (!sqlTools.length) dbReason = `no tool takes a SQL string (checked ${tools.length} tool(s)); set sql_tools`;
    else if (!db) dbReason = "--embedded disabled and no --pg";
    if (!dbReason && db) {
      log("db pack");
      checks.push(
        ...(await track(
          runDb({
            target: db,
            sqlTools,
            timeoutSec: timeoutProbeSec,
            log,
            open: (role) => open(roleCtx(role)),
            checks: eff.checks,
            ...(typeof eff.checks["db-rowcap"]?.row_cap === "number" ? { rowCap: eff.checks["db-rowcap"].row_cap } : {}),
            ...(typeof eff.checks["db-timeout"]?.expected_sec === "number" ? { expectedSec: eff.checks["db-timeout"].expected_sec } : {}),
            ...(typeof eff.checks["db-timeout"]?.slow_sql === "string" ? { slowSql: eff.checks["db-timeout"].slow_sql } : {}),
          }),
        )),
      );
    }
    // Skipped-tool lines only matter when the db pack looked at the tools.
    if (wantDb && !dbReason) for (const s of sqlSkipped) notCovered.push(`tool "${s.tool}" was not probed as a SQL tool: ${s.reason}`);

    // ---- the other packs, each with fresh sessions and reset observers ----
    // A candidate pack runs when its declaration exists, like `custom` does for check probes: only a pack list nobody chose is extended.
    const hasSqlTool = sqlTools.length > 0 || classification.some((c) => c.class === "sql" && c.confidence !== "low" && !c.excluded);
    const late = autoAddedPacks(packView, { hasSqlTool });
    late.packs.forEach((id, i) => {
      if (!isCandidate(id) || requested.has(id)) return;
      requested.add(id);
      packList.push(id);
      warnings.push(late.notes[i]!);
      log(`note: ${late.notes[i]}`);
    });
    for (const note of late.skipped.filter((t) => !t.startsWith("probes with a check"))) {
      warnings.push(note);
      log(`note: ${note}`);
    }
    const skipped = new Map<PackId, Skip>();
    /** Per pack: tools/call requests its sessions made, and how many reached a tool (the backstop for the coverage rule). */
    const callStats = new Map<PackId, { calls: number; processed: number }>();
    const runOrder: Pack[] = [];
    for (const id of RUN_ORDER) {
      if (!requested.has(id)) continue;
      const p = getPack(id);
      if (p) runOrder.push(p);
    }
    // Declared plugins run unless the user named a pack list that leaves them out.
    for (const p of pluginPacks) if (!opts.packsExplicit || requested.has(p.id)) runOrder.push(p);

    const reach = listenerReachable(spec, eff.env);
    const gate = (id: PackId): string | undefined => {
      if (!session) return "the server's tool list could not be read";
      if (id === "exec" && !active) return "the exec pack runs only with --active";
      if (NEEDS_SANDBOX.has(id) && !sandboxOn) return transport === "http" && !selfStarted ? "the server is already running (HTTP), so it cannot be started inside the sandbox" : "the sandbox is off (--no-sandbox)";
      if (NEEDS_HARNESS_START.has(id) && transport !== "stdio" && !selfStarted) return "the server is already running (HTTP), so the harness cannot start it with sandbox placeholders";
      if (id === "http" && transport !== "http") return "the server is started over stdio; the http pack needs server.url";
      if (id === "custom" && !eff.probes.length) return "no probes: are declared in the config";
      const take = (want: PackId) => classification.some((c) => packsFor(c, { active, sandboxEnabled: sandboxOn }).includes(want));
      if (id === "fs" && !take("fs")) return "no tool is classified as taking a file path with medium confidence or higher";
      if (id === "net" && reach.ok === false) return `the server runs on ${reach.host}, so it cannot reach the harness's loopback listener; the net pack is only meaningful for stdio servers or an HTTP server on this machine`;
      if (id === "net" && !take("net")) return "no tool is classified as taking a URL with medium confidence or higher";
      if (id === "git" && !take("git")) return "no tool is classified as taking a git repository path with medium confidence or higher";
      if (id === "exec" && !take("exec")) return "no tool is classified as running a command with high confidence";
      if (id === "effects") return effectsGateReason(classification, { active, sandboxEnabled: sandboxOn });
      if (id === "sqlite" && !classification.some((c) => c.class === "sql" && c.confidence !== "low")) return "no tool takes a SQL string";
      if (id === "scope" && !visibleTools.some((t) => scopeSettings(eff).tools?.some((s) => s.tool === t.name))) return NO_SCOPE_TOOL;
      if (id === "sql-guard") {
        if (!sqlTools.length && !classification.some((c) => c.class === "sql" && c.confidence !== "low" && !c.excluded)) return "no tool takes a SQL string";
        if (!upstreamStub) return NO_UPSTREAM_STUB;
      }
      if (id === "upstream") {
        if (!upstreamStub) return NO_UPSTREAM_STUB;
        if (!eff.probes.some((p) => !p.check)) return NO_VALID_CALL;
      }
      return undefined;
    };

    /**
     * What the exec pack left running in the sandbox. A server Sealmark launched lives in the sandbox for the whole run (its cwd is the
     * sandbox root), so its process tree is not a stray and stays.
     */
    const killStrays = async (): Promise<void> => {
      const pid = launched?.pid;
      if (pid === undefined) {
        await sb.proc.killStrays();
        return;
      }
      const all = await sb.proc.list();
      const mine = new Set<number>([pid]);
      for (let grew = true; grew; ) {
        grew = false;
        for (const p of all) if (!mine.has(p.pid) && mine.has(p.ppid)) (mine.add(p.pid), (grew = true));
      }
      for (const p of (await sb.proc.strays(all)).filter((x) => !mine.has(x.pid))) await sb.proc.killTree(p.pid).catch(() => {});
    };

    const packTimeoutMs = eff.sandbox.pack_timeout_sec * 1000;
    for (const [at, pack] of runOrder.entries()) {
      // After a signal nothing new is started: the packs still waiting are recorded as stopped, not run.
      if (finished) {
        for (const rest of runOrder.slice(at)) skipped.set(rest.id, { status: "inconclusive", reason: "the run was interrupted before this pack started" });
        break;
      }
      const why = gate(pack.id);
      if (why) {
        skipped.set(pack.id, { status: "na", reason: why });
        continue;
      }
      const mine: McpSession[] = [];
      let packOver = false;
      const ctx: PackCtx = {
        pack: pack.id,
        config: eff,
        tools: visibleTools,
        classification,
        sandbox: sb,
        sandboxEnabled: sandboxOn,
        open: async () => {
          // The admin role's connection strings, as the discovery session has them: a server that cannot start without {dsn} must be startable by every pack.
          const s = await open(db ? roleCtx("admin") : baseCtx());
          if (packOver) {
            await s.close();
            throw new SessionError("the pack was already stopped, so the server was stopped again");
          }
          mine.push(s);
          return s;
        },
        active,
        timeoutProbeSec,
        hangMs: eff.hangMs,
        log,
        prior: [...checks],
        canaries,
        sqlTools,
        interrupted: () => interrupted,
        vars: harnessVars(),
        ...(upstreamStub ? { upstream: upstreamStub } : {}),
        ...(logObs ? { serverLog: logObs } : {}),
        ...(transport === "http" && bearerUsed ? { identity: identityFor(mine, () => packOver) } : {}),
      };
      const applies = pack.applies(ctx);
      if (!applies.ok) {
        // A pack the harness's own environment cannot run (no node:sqlite) was not judged: inconclusive, so a gate that fails on that notices.
        skipped.set(pack.id, { status: applies.kind === "harness" ? "inconclusive" : "na", reason: applies.reason });
        continue;
      }
      log(`${pack.id} pack`);
      sb.listener.reset();
      const work = pack.run(ctx);
      work.catch(() => {});
      track(work);
      let timer: NodeJS.Timeout | undefined;
      try {
        const outcome = await Promise.race([
          work.then((value) => ({ value })),
          new Promise<{ timedOut: true }>((res) => {
            timer = setTimeout(() => res({ timedOut: true }), packTimeoutMs);
          }),
        ]);
        if ("timedOut" in outcome) {
          skipped.set(pack.id, { status: "inconclusive", reason: `the pack did not finish within sandbox.pack_timeout_sec (${eff.sandbox.pack_timeout_sec} s), so it was stopped` });
        } else {
          for (const c of outcome.value) {
            if (c.pack !== pack.id) throw new Error(`pack "${pack.id}" returned check "${c.id}" labelled for pack "${String(c.pack)}"`);
          }
          checks.push(...outcome.value);
        }
      } catch (e) {
        if (e instanceof ConfigError) throw e;
        if (e instanceof SessionError) {
          // The config uses {dsn}-style placeholders and no database was started: the server could not have started, and the user is told what to type.
          const hint = placeholders && !db ? " The config uses {dsn}-style placeholders but no database was started (--no-embedded without --pg), so they were empty." : "";
          skipped.set(pack.id, { status: "inconclusive", reason: `could not start or talk to the server: ${e.message}${hint ? `.${hint}` : ""}` });
        }
        else {
          skipped.set(pack.id, { status: "inconclusive", reason: `the pack stopped with an error: ${(e as Error).message}` });
          warnings.push(`pack ${pack.id} failed: ${(e as Error).stack ?? (e as Error).message}`);
        }
      } finally {
        clearTimeout(timer);
        packOver = true;
        // The stub goes back to its normal answers for the next pack; the recorded requests stay (packs read them by mark).
        upstreamStub?.setMode("normal");
        upstreamStub?.setOverride(undefined);
        callStats.set(pack.id, { calls: mine.reduce((n, s) => n + s.calls, 0), processed: mine.reduce((n, s) => n + s.processed, 0) });
        for (const s of mine) await s.close();
        if (pack.id === "exec") await killStrays().catch(() => {});
      }
    }

    // ---- refusal quality (core, advisory): read from the evidence the packs above recorded, so it is computed after them ----
    if (wantCore && (session || protocolChecks)) {
      try {
        checks.push(refusalQuality(checks, eff));
      } catch (e) {
        warnings.push(`refusal-quality could not be computed: ${(e as Error).message}`);
      }
    }

    // ---- grades ----
    const packs: RunResult["packs"] = {};
    for (const pack of ["core", "db", ...runOrder.map((p) => p.id)] as PackId[]) {
      const isBase = pack === "core" || pack === "db";
      if (isBase && !requested.has(pack)) {
        packs[pack] = { status: "na", reason: "pack not requested" };
        continue;
      }
      if (pack === "db" && dbReason) {
        packs[pack] = { status: "na", reason: dbReason };
        continue;
      }
      const skip = skipped.get(pack);
      if (skip) {
        packs[pack] = skip;
        continue;
      }
      packs[pack] = packStatus(pack, checks, isBase);
    }

    // ---- what was not covered, stated ----
    // SQL tools no engine pack looked at. The line must hold: it is said only when neither the db nor the sqlite pack produced checks.
    if (sqlTools.length && !checks.some((c) => c.pack === "db" || c.pack === "sqlite" || c.pack === "sql-guard") && !(wantDb && !dbReason)) {
      const specText = JSON.stringify(spec);
      const sqliteReason = specText.includes("{sqlite_path}") ? (packs.sqlite && "reason" in packs.sqlite ? packs.sqlite.reason : undefined) ?? "the pack was not requested" : undefined;
      const DUCKDB = "SQL engines such as DuckDB can read and write arbitrary files; no pack tests this";
      if (specText.includes("{duckdb_path}") && !sqliteReason) for (const t of sqlTools) notCovered.push(`SQL tool "${t.tool}" detected; DuckDB placeholder present but DuckDB grading is not built in this release`);
      else if (sqliteReason) for (const t of sqlTools) notCovered.push(`SQL tool "${t.tool}" detected; the sqlite pack did not run (${sqliteReason}) and no database placeholder was given for the db pack`);
      else for (const t of sqlTools) notCovered.push(`SQL tool "${t.tool}" detected; no engine pack ran${placeholders ? ` (the db pack: ${dbReason ?? "it did not run"})` : " (no {dsn} or {sqlite_path} placeholder)"}. ${DUCKDB}`);
    }
    // A classified tool that no capability pack probed, with the reason its pack gave. Command tools have their own line below.
    const probedByPack = new Set(checks.filter((c) => c.pack !== "core" && c.pack !== "db").flatMap((c) => c.coverage?.probed ?? []));
    const PRIMARY: Partial<Record<string, PackId>> = { path: "fs", git: "git", url: "net" };
    const said = new Set<string>();
    for (const c of classification) {
      const id = PRIMARY[c.class];
      if (!id || c.excluded || c.confidence === "low" || probedByPack.has(c.tool)) continue;
      const own = packs[id];
      if (own?.status === "graded") continue; // the pack ran; what it skipped inside is in its own checks
      const why = own && "reason" in own && own.reason ? own.reason : "the pack was not requested";
      notCovered.push(`tool "${c.tool}" (${c.class}) was not probed by the ${id} pack: ${why}`);
      said.add(c.tool);
    }
    // A tool that also looks like another kind of tool is probed as its primary class only, unless the pack of the secondary class took it too.
    const SECONDARY_PACK: Partial<Record<string, PackId[]>> = { path: ["fs"], git: ["git"], url: ["net"], command: ["exec"], sql: ["db", "sqlite"] };
    for (const c of classification) {
      if (c.excluded || c.confidence === "low" || !c.secondary?.length) continue;
      for (const s of c.secondary) {
        const packsOf = SECONDARY_PACK[s] ?? [];
        if (packsOf.some((p) => checks.some((k) => k.pack === p && k.coverage?.probed.includes(c.tool)))) continue;
        // A pack that made calls on the tool has attempted it: saying "only its primary class was probed" would contradict its own checks.
        const attempted = packsOf.find((p) => checks.some((k) => k.pack === p && k.evidence.some((e) => e.tool === c.tool)));
        notCovered.push(attempted ? `tool "${c.tool}" also looks like a ${s} tool (secondary class); it was attempted by the ${attempted} pack but every call failed` : `tool "${c.tool}" also looks like a ${s} tool (secondary class); only its primary class (${c.class}) was probed`);
      }
    }
    notCovered.push(...capabilityGaps(checks, said));
    if (tools.length) notCovered.push("tools that a server lists only for clients that declare roots, sampling or elicitation capabilities are not seen: the harness declares none");
    if (transport === "http" && !selfStarted) notCovered.push("secret-echo: canary secrets cannot be injected into an HTTP server that is already running, so that check was not run");
    if (selfStarted && !sandboxOn) notCovered.push("the server was started by Sealmark with your full environment and no sandbox (the fs, git, exec and effects packs did not run)");
    else if (selfStarted && !eff.sandbox.scrub_env) notCovered.push("the server was started by Sealmark inside the sandbox directory but with your full environment (sandbox.scrub_env is off)");
    // Tools a candidate pack (scope, sql-guard, upstream) just probed are not told "core only".
    const probedByCandidates = checks.filter((c) => CANDIDATE_PACKS.includes(c.pack)).flatMap((c) => c.coverage?.probed ?? []);
    const byCandidate = new Set(probedByCandidates);
    notCovered.push(...coreOnlyNotes(classification.filter((c) => !byCandidate.has(c.tool)), probedByCandidates), ...coverageNotes(checks, "core"), ...coverageNotes(checks, "db"));
    const runners = classification.filter((c) => c.class === "command" && !c.excluded && c.confidence !== "low");
    if (runners.length && !packs.exec?.grade) {
      for (const c of runners) notCovered.push(`tool "${c.tool}" looks like a command runner; the exec pack did not run (${packs.exec?.reason ?? "it needs --active"})`);
    }
    if (reach.ok === false && classification.some((c) => c.class === "url" && !c.excluded && c.confidence !== "low")) {
      notCovered.push(`SSRF: the server runs on ${reach.host}, not on this machine, so the harness's loopback listener is unreachable for it and the net pack did not run`);
    }
    if (classification.some((c) => c.class === "url" && !c.excluded && c.confidence !== "low")) {
      notCovered.push("SSRF: link-local and private-range addresses are never contacted; redirects from a public host to loopback and DNS rebinding are not tested (the harness contacts only its own loopback listener)");
    }
    if (!eff.sandbox.enabled) notCovered.push("the sandbox is off (--no-sandbox): the fs, git, exec and effects packs did not run, and the server saw your real environment");
    else if (sandboxOn) notCovered.push(SANDBOX_NON_GUARANTEE);
    // The http pack grades whether a credential is required and whether the URL uses TLS, so claiming "authentication and transport security" is not covered would contradict its own checks.
    const authTransport = transport === "http" && packs.http?.grade
      ? "authorization semantics and token handling (the http pack only checks that the configured credential is required, and whether the URL uses TLS)"
      : "authentication and transport security";
    notCovered.push("prompt injection carried in tool output (only tool metadata is scanned)", authTransport, "audit logging (not measured by these packs; only the db pack has an advisory audit check)");
    notCovered.push(...eff.notCoveredExtra);

    // ---- coverage and badge eligibility (addendum 1.4) ----
    // The rule is on CheckCoverage.validCalls: a call counts when it was schema-valid and the server processed it. Each pack counts in its
    // own way; this is the backstop that holds whatever a pack reported. A pack whose checks are all inconclusive or n/a judged nothing, and a pack
    // whose every call was rejected before it ran (a JSON-RPC error, a validation error) exercised no tool, so neither lifts the run above hygiene-only.
    const exercised = (pack: PackId): boolean => {
      if (!checks.some((c) => c.pack === pack && c.verdict !== "inconclusive" && c.verdict !== "na")) return false;
      const s = callStats.get(pack);
      return !(s && s.calls > 0 && s.processed === 0);
    };
    const notExercised = new Set<PackId>();
    const probedTools = new Set<string>();
    const callsByPack = new Map<PackId, number>();
    for (const c of checks) {
      if (!c.coverage) continue;
      if (!exercised(c.pack)) {
        if (c.coverage.probed.length || c.coverage.validCalls) notExercised.add(c.pack);
        continue;
      }
      for (const t of c.coverage.probed) probedTools.add(t);
      callsByPack.set(c.pack, Math.max(callsByPack.get(c.pack) ?? 0, c.coverage.validCalls ?? c.coverage.probed.length));
    }
    for (const p of notExercised) notCovered.push(`the ${p} pack's calls do not count toward coverage: every check of the pack was inconclusive or n/a, or the server rejected every call before running it`);
    const validCalls = [...callsByPack.values()].reduce((a, b) => a + b, 0);
    const coverage = { validCalls, toolsCalledValid: probedTools.size, toolsTotal: tools.length, level: coverageLevel(validCalls, probedTools.size, tools.length) };
    const badge = badgeFor(legacy ? undefined : eff.integrity, packs, checks);
    // What to add to the configuration: doctor's suggestions for this server, then what the finished checks say.
    const suggestions: Suggestion[] = [];
    if (session) {
      const before = suggestionsFor({ tools: visibleTools, classification, spec, transport, selfStarted, sandboxEnabled: eff.sandbox.enabled, probes: eff.probes.length, usesDsn: placeholders, sqlTools: eff.sqlTools ?? [], rules: rulesOf(eff) });
      for (const s of [...before, ...suggestionsAfterRun(checks)]) if (!suggestions.some((x) => x.id === s.id)) suggestions.push(s);
    }

    // ---- what the package manager actually ran (addendum item 15) ----
    let resolved: RunResult["server"]["resolved"];
    let headerVersion = eff.version === "0.0.0" && serverInfoVersion?.trim() ? serverInfoVersion : eff.version;
    if (transport === "stdio" && spec.command) {
      let pkg: ReturnType<typeof resolvePackage>;
      try {
        pkg = resolvePackage(spec.command, spec.args ?? []);
        // Several versions in the cache and nothing in the spec says which ran. The server's own announcement settles it only when it names
        // one of them; otherwise no version is claimed (the newest entry is merely the one unpacked last).
        const announced = serverInfoVersion ? normVersion(serverInfoVersion) : undefined;
        const match = pkg?.candidates?.find((v) => normVersion(v) === announced);
        if (pkg?.candidates && match) pkg = resolvePackage(spec.command, spec.args ?? [], { pick: match }) ?? pkg;
      } catch {
        pkg = undefined;
      }
      resolved = {
        serverInfoVersion,
        configVersion: eff.version,
        ...(pkg
          ? {
              package: { name: pkg.name, ...(pkg.version ? { version: pkg.version } : {}), source: pkg.source, ...(pkg.candidates ? { candidates: pkg.candidates } : {}) },
              ...(pkg.dependencies ? { dependencies: pkg.dependencies } : {}),
            }
          : {}),
      };
      const v = versionWarnings({ pkg, serverInfoVersion, configVersion: eff.version });
      warnings.push(...v.warnings);
      headerVersion = v.headerVersion;
      if (v.note) warnings.push(v.note);
    }

    const died = launched?.exited();
    if (died) warnings.push(`the server ${died} during the run, so results after that point may be unreliable`);
    const shown = displaySpec(spec);
    result = {
      sealmark: { version: clientVersion, methodology },
      server: {
        name: eff.name,
        // The config default "0.0.0" means "not set": prefer the version the server announced, then the resolved package's, over printing 0.0.0.
        version: headerVersion,
        command: shown.command,
        ...(selfStarted ? { launched: true } : {}),
        env: { ...shown.env, ...(transport === "stdio" || selfStarted ? Object.fromEntries(CANARY_ENV.map((k) => [k, "<canary>"])) : {}) },
        transport,
        tools: tools.map((t) => t.name),
        surface: captureSurface(tools, classification),
        sqlTools,
        ...(resolved ? { resolved } : {}),
      },
      db: db ? { mode: external ? "external" : "embedded", seed: `${SEED_DB} (seed ${SEED_VERSION})`, roles: [...ROLES], timeoutProbeSec } : undefined,
      options: { packsRequested: packList, timeoutProbeSec, active, sandbox: sandboxOn },
      startedAt,
      durationMs: Date.now() - t0,
      packs,
      checks,
      notCovered,
      classification,
      coverage,
      ...(eff.probes.length ? probesReport({ calls: valid?.calls, checks }) : {}),
      badge,
      warnings,
      ...(upstreamStub
        ? (() => {
            const seen = upstreamStub.requests();
            return { upstream: { kind: "http" as const, requests: seen.length, scripted: seen.filter((r) => r.reply.ruleId !== "default").length, url: upstreamStub.url } };
          })()
        : {}),
      ...(suggestions.length ? { suggestions } : {}),
      ...(bearerUsed ? { identities: { names: ["a", "b"] as IdentityName[], source: idCfg.a || idCfg.b ? ("config" as const) : ("minted" as const) } } : {}),
      ...(legacy ? {} : { config: { ...eff.integrity, ...(eff.configPath ? { path: eff.configPath } : {}), ...(serverLine(eff) !== undefined ? { line: serverLine(eff) } : {}) } }),
    };
  } finally {
    // The handlers stay installed while cleanup runs, so a second signal cannot kill us before the server is stopped.
    try {
      await cleanup();
    } finally {
      unhook();
    }
  }

  const sbx = sandbox as Sandbox | undefined;
  const gone = destroyed as DestroyResult | undefined;
  if (sbx) {
    const leftover = (gone?.leftover ?? []).filter((l) => l.startsWith("process "));
    result.sandbox = {
      dir: sbx.dir,
      envMode: result.options.sandbox && eff.sandbox.scrub_env ? "scrubbed" : "inherited",
      listenerPort: sbx.listener.port,
      inherited: [...sbx.inherited],
      // A kept sandbox is on disk on purpose: it is `kept`, not `cleanedUp`.
      cleanedUp: Boolean(gone?.cleanedUp),
      leftoverProcesses: leftover,
      active,
      enabled: Boolean(result.options.sandbox),
      kept: Boolean(gone?.kept),
    };
    if (gone && !gone.cleanedUp && !gone.kept) {
      result.warnings = [...(result.warnings ?? []), `the sandbox ${gone.path} could not be fully deleted (${gone.leftover.join("; ") || "locked files"}); remove it by hand`];
    }
    if (gone?.kept) result.warnings = [...(result.warnings ?? []), `the sandbox was kept at ${gone.path} (--keep-sandbox)`];
    result.durationMs = Date.now() - t0;
  }
  // A signal that landed while the last pack was finishing leaves a complete-looking report and the exit code of the signal: say so in the report.
  if (interrupted) {
    result.interrupted = true;
    result.warnings = [...(result.warnings ?? []), "the run was interrupted; the report may be incomplete"];
  }
  return result;
}
