import { execFile, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { constants as osConstants, setPriority } from "node:os";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PgTarget } from "./seed.js";

export interface EmbeddedHandle {
  target: PgTarget;
  stop: () => Promise<void>;
  /** The postmaster's pid while it runs, so an interrupted run's sweep of child processes leaves it for `stop()` to shut down cleanly. */
  pid?: () => number | undefined;
}

interface EmbeddedPg {
  initialise(): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  /** The postmaster, once start() has created it. */
  process?: ChildProcess;
}

type EmbeddedCtor = new (o: Record<string, unknown>) => EmbeddedPg;

export interface EmbeddedOptions {
  /**
   * How long the server may take to say it is ready (default 60 s). embedded-postgres' start() settles only when the log says
   * so or when the postmaster's stdio pipes all close, and a postmaster that dies during start-up can leave worker processes
   * holding those pipes, so start() would otherwise never settle at all.
   */
  startTimeoutMs?: number;
  /** Attempts, each on a fresh port after the first (default 3). */
  attempts?: number;
  /** Replaces the optional "embedded-postgres" package (tests). */
  create?: EmbeddedCtor;
  /** True once the run was interrupted: no attempt starts after that, and one that is running does not go on to start the server. */
  cancelled?: () => boolean;
  /** Test hook: awaited after the server reported ready and before the handle is taken (the window a signal could fall into). */
  afterStart?: () => void | Promise<void>;
}

/** A SysV shared-memory segment as `postmaster.pid` names it (line 7: `<key> <id>`) and as `ipcs -m` lists it. */
export interface Segment {
  key: number;
  id: number;
}

/**
 * One embedded Postgres from the moment its data directory exists until `stop()` has finished: `pending` while no handle has been
 * returned (the package also writes `pg-password-<id>` into the temp directory during `initialise()`), `live` once it has. A signal can
 * arrive in either state, so `stopAll()` and `abandonPending()` find every start here, whatever the run's own variables hold.
 */
interface Entry {
  dir: string;
  /** The password this attempt gave the package: it is written, in plain text, into the `pg-password-*` file, which is how that file is recognised. */
  password: string;
  registeredAt: number;
  state: "pending" | "live";
  abandoned: boolean;
  pid: () => number | undefined;
  child: () => ChildProcess | undefined;
  /** The interlock segment the postmaster created, read from its own `postmaster.pid` while the file exists (the package deletes it on stop). */
  segment?: Segment;
  /** Live entries only: stops the server politely within `ms`, then with the kill ladder; idempotent. */
  stopWith?: (ms: number) => Promise<void>;
}
const registry = new Map<string, Entry>();

/** Every registered postmaster that has a pid: an interrupted run's sweep of child processes leaves these for `stopAll()` to shut down politely. */
export function pendingPids(): number[] {
  return [...registry.values()].map((e) => e.pid()).filter((p): p is number => p !== undefined);
}

/** The data directories of every registered start that still exist: what an interrupted run has to name when it could not remove them. */
export function leftoverDirs(): string[] {
  return [...registry.values()].map((e) => e.dir).filter((d) => existsSync(d));
}

/** Waits for a promise, but never longer than `ms`; a rejection counts as settled. */
async function bounded(p: Promise<unknown>, ms: number): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([p.catch(() => {}), new Promise<void>((res) => (timer = setTimeout(res, ms)))]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Stops every registered start, politely and bounded: a live server gets `stop()` (fast shutdown, then the kill ladder), one that has
 * no handle yet is abandoned (postmaster stopped, data directory and password file removed). Returns the data directories that are
 * still there when it is done or when `deadlineMs` (default 8 s) has passed. Safe to call at any time, any number of times.
 */
export async function stopAll(o: { deadlineMs?: number } = {}): Promise<string[]> {
  const work = [...registry.values()].map((e) => (e.state === "live" && e.stopWith ? e.stopWith(5_000) : abandonEntry(e)).catch(() => {}));
  await bounded(Promise.all(work), o.deadlineMs ?? 8_000);
  return leftoverDirs();
}

/**
 * Stops every start that has not returned yet: kills its postmaster, removes its data directory and the `pg-password-*` file the
 * package left in the temp directory (found by the password it holds, so another run's file is never touched). A start that already
 * returned its handle is left to its `stop()` (see `stopAll`). Safe to call at any time.
 */
export async function abandonPending(): Promise<string[]> {
  const left: string[] = [];
  for (const e of [...registry.values()].filter((x) => x.state === "pending")) {
    await abandonEntry(e).catch(() => {});
    if (existsSync(e.dir)) left.push(e.dir);
  }
  return left;
}

async function abandonEntry(e: Entry): Promise<void> {
  e.abandoned = true;
  noteSegment(e);
  await killPostmaster(e.pid(), e.child());
  await releaseEntrySegment(e);
  removeDir(e.dir);
  removePasswordFiles(e);
  if (!existsSync(e.dir)) registry.delete(e.dir);
}

function removeDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    /* best effort */
  }
}

/** `pg-password-*` files in the temp directory that hold this attempt's password and were written after it registered. */
function removePasswordFiles(p: Pick<Entry, "password" | "registeredAt">): void {
  let names: string[];
  try {
    names = readdirSync(tmpdir()).filter((n) => n.startsWith("pg-password-"));
  } catch {
    return;
  }
  for (const n of names) {
    const f = join(tmpdir(), n);
    try {
      if (statSync(f).mtimeMs < p.registeredAt - 1000) continue;
      if (readFileSync(f, "utf8").trim() === p.password) rmSync(f, { force: true });
    } catch {
      /* gone already, or not ours to read */
    }
  }
}

// ---------------------------------------------------------------------------------------------------------
// The SysV shared-memory segment
// ---------------------------------------------------------------------------------------------------------
//
// Postgres creates one tiny SysV segment as an interlock and names it on line 7 of `postmaster.pid` (`<key> <id>`). A postmaster that is
// stopped politely (SIGINT or SIGQUIT) releases it on its way out; one that is SIGKILLed cannot, and the segment stays with nattch 0.
// macOS allows 32 segments by default, so about thirty such runs make every later start fail with "could not create shared memory
// segment". Only an id read from a data directory this process created is ever removed.

/** Line 7 of `<dir>/postmaster.pid`: `<key> <id>`. Undefined while the file is missing or the line is not written yet. */
export function readSegment(dir: string): Segment | undefined {
  try {
    const m = /^\s*(\d+)\s+(\d+)\s*$/.exec(readFileSync(join(dir, "postmaster.pid"), "utf8").split(/\r?\n/)[6] ?? "");
    if (!m) return undefined;
    const [key, id] = [Number(m[1]), Number(m[2])];
    return Number.isSafeInteger(key) && Number.isSafeInteger(id) ? { key, id } : undefined;
  } catch {
    return undefined;
  }
}

const noteSegment = (e: Entry): void => {
  e.segment ??= readSegment(e.dir);
};

export interface IpcsRow {
  id: number;
  /** The key as a 32-bit number; absent in a listing that has no key column (`ipcs -m -p` on Linux). */
  key?: number;
  owner?: string;
  nattch?: number;
  size?: number;
  cpid?: number;
}

/**
 * Parses `ipcs -m` output (macOS `-a`: `T ID KEY MODE OWNER GROUP CREATOR CGROUP NATTCH SEGSZ CPID ...`; Linux: `key shmid owner perms
 * bytes nattch status`, or `-p`: `shmid owner cpid lpid`) by its header row, so either layout works. Rows that do not parse are skipped.
 */
export function parseIpcs(text: string): IpcsRow[] {
  let cols: string[] | undefined;
  const rows: IpcsRow[] = [];
  for (const line of text.split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    if (!cols) {
      const lower = tokens.map((t) => t.toLowerCase());
      if (lower.includes("id") || lower.includes("shmid")) cols = lower;
      continue;
    }
    const at = (...names: string[]): string | undefined => {
      const i = cols!.findIndex((c) => names.includes(c));
      return i >= 0 ? tokens[i] : undefined;
    };
    const num = (v: string | undefined): number | undefined => (v !== undefined && /^\d+$/.test(v) ? Number(v) : undefined);
    const id = num(at("id", "shmid"));
    if (id === undefined) continue;
    const keyText = at("key");
    const key = keyText !== undefined && /^(?:0x)?[0-9a-f]+$/i.test(keyText) ? Number(BigInt(keyText.toLowerCase().startsWith("0x") ? keyText : `0x${keyText}`) & 0xffffffffn) : undefined;
    const owner = at("owner");
    const [nattch, size, cpid] = [num(at("nattch")), num(at("segsz", "bytes")), num(at("cpid"))];
    rows.push({ id, ...(key !== undefined ? { key } : {}), ...(owner !== undefined ? { owner } : {}), ...(nattch !== undefined ? { nattch } : {}), ...(size !== undefined ? { size } : {}), ...(cpid !== undefined ? { cpid } : {}) });
  }
  return rows;
}

/** Runs a helper and returns its standard output; undefined when it is missing, fails or times out. */
const capture = (cmd: string, args: string[], ms = 5_000): Promise<string | undefined> =>
  new Promise((resolve) => {
    try {
      execFile(cmd, args, { windowsHide: true, timeout: ms, maxBuffer: 1 << 20 }, (err, stdout) => resolve(err ? undefined : String(stdout)));
    } catch {
      resolve(undefined);
    }
  });

/** `ipcs -m` parsed (with the creator pids merged in where the platform lists them separately); undefined where there is no ipcs (Windows, a minimal container). */
export async function listSegments(): Promise<IpcsRow[] | undefined> {
  if (process.platform === "win32") return undefined;
  const plain = (await capture("ipcs", ["-m", "-a"])) ?? (await capture("ipcs", ["-m"]));
  if (plain === undefined) return undefined;
  const rows = parseIpcs(plain);
  if (rows.some((r) => r.cpid !== undefined) || !rows.length) return rows;
  const creators = parseIpcs((await capture("ipcs", ["-m", "-p"])) ?? "");
  return rows.map((r) => {
    const c = creators.find((x) => x.id === r.id);
    return c?.cpid !== undefined ? { ...r, cpid: c.cpid } : r;
  });
}

/**
 * Removes the segment `postmaster.pid` named, when it still exists: `ipcs -m` must list it under that id AND that key (an id can be
 * reused by another program once the segment is gone), then `ipcrm -m <id>`. POSIX only; a missing `ipcs` or `ipcrm`, or a segment that
 * is already gone, is not an error. Returns true when `ipcrm` was run and succeeded. Call it only after the postmaster has exited.
 */
export async function releaseSegment(seg: Segment): Promise<boolean> {
  if (process.platform === "win32" || !Number.isInteger(seg.id) || seg.id < 0) return false;
  const rows = await listSegments();
  const key = Number(BigInt(seg.key) & 0xffffffffn);
  if (!rows?.some((r) => r.id === seg.id && r.key === key)) return false;
  return (await capture("ipcrm", ["-m", String(seg.id)])) !== undefined;
}

const releaseEntrySegment = async (e: Entry): Promise<void> => {
  noteSegment(e);
  if (e.segment) await releaseSegment(e.segment).catch(() => false);
};

export const START_TIMEOUT_MS = 60_000;

/** The error says what to do when the start failed because of orphaned segments (the log tail names them). */
const SHM_FAILURE = /could not create shared memory segment|No space left on device/i;
export const SHM_HINT = "orphaned shared-memory segments from earlier interrupted runs are the usual cause: list them with `ipcs -m` and remove yours with `ipcrm -m <id>`; `sealmark doctor` lists them";

/** Wait for a promise, but never longer than ms: embedded-postgres' stop() never settles when the server has already exited. */
const within = bounded;

function pickPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });
}

/** Run a helper command; `low` lowers its priority so that it cannot slow down whatever else is running (test timeouts are tight). */
const run = (cmd: string, args: string[], low = false, ms = 15_000): Promise<void> =>
  new Promise((resolve) => {
    const child = execFile(cmd, args, { windowsHide: true, timeout: ms }, () => resolve());
    try {
      if (low && child.pid) setPriority(child.pid, osConstants.priority.PRIORITY_LOW);
    } catch {
      /* best effort */
    }
  });

/** Close our end of a child's stdio and stop waiting for it, so an orphaned worker holding the other end cannot keep this process alive. */
export function releaseStdio(child: ChildProcess | undefined): void {
  if (!child) return;
  for (const s of [child.stdin, child.stdout, child.stderr]) s?.destroy();
  child.unref();
}

const exited = (child: ChildProcess | undefined): boolean => child !== undefined && (child.exitCode !== null || child.signalCode !== null);

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};

/** Sends `signal` and waits up to `ms` for the process to be gone. */
async function signalAndWait(pid: number, child: ChildProcess | undefined, signal: NodeJS.Signals, ms: number): Promise<boolean> {
  try {
    process.kill(pid, signal);
  } catch {
    return true; // already gone
  }
  const t0 = Date.now();
  for (;;) {
    if (exited(child) || (child === undefined && !alive(pid))) return true;
    if (Date.now() - t0 >= ms) return false;
    await new Promise((r) => setTimeout(r, 25));
  }
}

/**
 * Stop a postmaster and everything it started. POSIX: SIGINT (fast shutdown) and up to 2 s, SIGQUIT (immediate shutdown, which still
 * releases the shared-memory segment) and up to 1 s, SIGKILL last; the workers are swept after it is gone. After a failed start the
 * postmaster may already be gone while its workers (io_worker, checkpointer, ...) live on, so they are found by its pid: only
 * processes named like the embedded server whose parent is the pid of the server THIS call started are touched.
 */
export async function killPostmaster(pid: number | undefined, child?: ChildProcess, low = false): Promise<void> {
  if (!pid || !Number.isInteger(pid) || pid <= 0) return;
  // A pid whose process has exited may belong to something else by now: only its leftover children are looked for then.
  const gone = exited(child);
  if (process.platform === "win32") {
    if (!gone) await run("taskkill", ["/pid", String(pid), "/f", "/t"], low);
    await run("powershell.exe", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Get-CimInstance Win32_Process -Filter "Name='postgres.exe' AND ParentProcessId=${pid} AND CommandLine LIKE '%embedded-postgres%'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`,
    ], low);
  } else {
    if (!gone && !(await signalAndWait(pid, child, "SIGINT", 2_000)) && !(await signalAndWait(pid, child, "SIGQUIT", 1_000))) {
      // Last resort: the workers first (they would hold the segment attached), then the postmaster itself.
      await run("pkill", ["-KILL", "-P", String(pid), "-f", "embedded-postgres"], low);
      await signalAndWait(pid, child, "SIGKILL", 1_000);
    }
    await run("pkill", ["-KILL", "-P", String(pid), "-f", "embedded-postgres"], low);
  }
}

/**
 * Start a throwaway real Postgres (no Docker). Requires the optional "embedded-postgres" package. A port that was free a moment
 * ago can be taken by the time the server binds it (several runs start at once), so a failed start is retried on a fresh port.
 */
export async function startEmbedded(port: number, quiet = true, opts: EmbeddedOptions = {}): Promise<EmbeddedHandle> {
  let last: unknown;
  for (let attempt = 0; attempt < (opts.attempts ?? 3); attempt++) {
    if (opts.cancelled?.()) throw new Error("the run was interrupted, so the embedded Postgres was not started");
    try {
      return await startEmbeddedOnce(attempt === 0 ? port : await pickPort(), quiet, opts);
    } catch (e) {
      last = e;
      // Not worth retrying: the package is missing.
      if (/could not be loaded/.test((e as Error).message) || opts.cancelled?.()) break;
    }
  }
  throw last;
}

/**
 * `pgx.start()` bounded three ways: it resolves when the server is ready, it rejects when the postmaster exits (watched on
 * the child itself, which fires even while a worker holds the pipes open), and it rejects at the deadline.
 */
async function startBounded(pgx: EmbeddedPg, ms: number, pidOut: { pid?: number; child?: ChildProcess }, tick?: () => void): Promise<void> {
  const child = () => (pgx as unknown as { process?: ChildProcess }).process;
  let watching: ChildProcess | undefined;
  let poll: NodeJS.Timeout | undefined;
  let timer: NodeJS.Timeout | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      let over = false;
      const end = (err?: Error) => {
        if (over) return;
        over = true;
        if (err) reject(err);
        else resolve();
      };
      timer = setTimeout(() => end(new Error(`the server did not report ready within ${Math.round(ms / 1000)} s`)), ms);
      // start() creates the child asynchronously, so look for it until it exists.
      poll = setInterval(() => {
        tick?.();
        const c = child();
        if (!c || c === watching) return;
        watching = c;
        pidOut.pid = c.pid;
        pidOut.child = c;
        c.once("exit", (code, signal) => end(new Error(`the server exited during startup (code ${code ?? "null"}, signal ${signal ?? "null"})`)));
      }, 25);
      pgx.start().then(
        () => end(),
        (e: unknown) => end(e instanceof Error ? e : new Error("the server exited during startup")),
      );
    });
  } finally {
    clearInterval(poll);
    clearTimeout(timer);
    // The postmaster may have died before the first poll tick: take its pid now so its workers can still be found.
    pidOut.pid ??= child()?.pid;
    pidOut.child ??= child();
    tick?.();
    // A later 'exit' of a healthy server must not reject anything: the promise above is settled, so the listener is inert.
  }
}

const EXIT_SIGNALS = ["SIGHUP", "SIGINT", "SIGTERM", "SIGBREAK"] as const;

/**
 * Imports the optional package. Importing it registers `async-exit-hook`, which listens for SIGHUP, SIGINT and SIGTERM, stops every
 * instance and then calls `process.exit` on its own: a signal during a run would end the process while the harness is still deleting the
 * sandbox, and would stop a start that has not finished (whose stop() may never settle). The harness owns signal handling (launch.ts
 * `stopOnSignals`), so the listeners the import added are removed again. Its `exit` and `beforeExit` hooks stay as a safety net.
 */
async function loadPackage(): Promise<EmbeddedCtor> {
  const before = new Map(EXIT_SIGNALS.map((s) => [s, new Set<unknown>(process.rawListeners(s))]));
  const mod = (await import("embedded-postgres")) as unknown as { default: EmbeddedCtor };
  for (const s of EXIT_SIGNALS) {
    for (const l of process.rawListeners(s)) if (!before.get(s)!.has(l)) process.removeListener(s, l as (...a: unknown[]) => void);
  }
  return mod.default;
}

const INTERRUPTED = "the run was interrupted, so the embedded Postgres was not started";

async function startEmbeddedOnce(port: number, quiet: boolean, opts: EmbeddedOptions): Promise<EmbeddedHandle> {
  let Ctor: EmbeddedCtor;
  if (opts.create) Ctor = opts.create;
  else {
    try {
      Ctor = await loadPackage();
    } catch (e) {
      throw new Error(`The embedded Postgres could not be loaded (${(e as Error).message}). It needs the optional dependency "embedded-postgres" (npm i embedded-postgres) and a build for this platform; or pass --pg <dsn> to use your own Postgres.`);
    }
  }
  // Nothing between this check and the registration below yields, so a signal cannot slip in: either no directory is made, or it is registered.
  if (opts.cancelled?.()) throw new Error(INTERRUPTED);
  const dir = mkdtempSync(join(tmpdir(), "sealmark-pg-"));
  const password = "sealmark-admin-" + Math.random().toString(36).slice(2, 10);
  const started: { pid?: number; child?: ChildProcess } = {};
  let pgx: EmbeddedPg | undefined;
  const entry: Entry = {
    dir,
    password,
    registeredAt: Date.now(),
    state: "pending",
    abandoned: false,
    pid: () => started.pid ?? (pgx as unknown as { process?: ChildProcess } | undefined)?.process?.pid,
    child: () => started.child ?? (pgx as unknown as { process?: ChildProcess } | undefined)?.process,
  };
  registry.set(dir, entry);
  // embedded-postgres rejects start() with no value when the server exits early, so keep the tail of its log for the error.
  const tail: string[] = [];
  const keep = (m: unknown) => {
    tail.push(String(m).trim());
    if (tail.length > 20) tail.shift();
    if (!quiet) process.stderr.write(String(m));
  };
  const made = new Ctor({ databaseDir: dir, user: "postgres", password, port, persistent: false, onLog: keep, onError: keep });
  pgx = made;
  try {
    await made.initialise();
    // A signal that arrived while initdb ran has already removed the directory: the server is not started on top of that.
    if (entry.abandoned || opts.cancelled?.()) throw new Error(INTERRUPTED);
    await startBounded(made, opts.startTimeoutMs ?? START_TIMEOUT_MS, started, () => noteSegment(entry));
    await opts.afterStart?.();
    // From here on the entry is live in the registry: a signal finds it there even before the caller has the handle.
    if (entry.abandoned) throw new Error(INTERRUPTED);
    if (opts.cancelled?.()) {
      await abandonEntry(entry);
      throw new Error(INTERRUPTED);
    }
  } catch (e) {
    // Kill what is left (the postmaster and any worker holding its pipes) instead of asking it to stop politely: a stop() on a
    // server that has already exited never settles. A server that was told to stop politely is already gone, so this is quick.
    noteSegment(entry);
    await killPostmaster(entry.pid(), entry.child());
    // Workers that outlived the postmaster hold its stdio pipes; those pipes keep THIS process from ever exiting (npm test hung
    // for that reason). Let go of them whether or not the workers could be killed.
    releaseStdio(started.child);
    await releaseEntrySegment(entry);
    removeDir(dir);
    removePasswordFiles(entry);
    if (!existsSync(dir)) registry.delete(dir);
    const why = e instanceof Error ? e.message : "the server exited during startup";
    if (why === INTERRUPTED) throw e;
    const log = tail.length ? ` | ${tail.slice(-5).join(" | ")}` : "";
    throw new Error(`The embedded Postgres failed to start on port ${port}: ${why}${log}${SHM_FAILURE.test(`${why}\n${tail.join("\n")}`) ? `. ${SHM_HINT}` : ""}`);
  }
  let stopping: Promise<void> | undefined;
  const stopWith = (ms: number): Promise<void> =>
    (stopping ??= (async () => {
      // The package deletes postmaster.pid when it stops the server, so the segment is read first.
      noteSegment(entry);
      try {
        // embedded-postgres' stop() waits for an 'exit' event that never comes when the postmaster has already exited.
        if (!exited(started.child)) await within(made.stop(), ms);
        if (!exited(started.child)) await killPostmaster(started.pid, started.child, true);
        // taskkill /t leaves io_workers behind on some builds; they keep our end of the pipes open (and the data directory locked).
        // Not awaited: the sweep runs at low priority and may take a while on a busy machine; the pipes are released below.
        else void killPostmaster(started.pid, started.child, true);
        await releaseEntrySegment(entry);
      } finally {
        releaseStdio(started.child);
        removeDir(dir);
        removePasswordFiles(entry);
        if (!existsSync(dir)) registry.delete(dir);
      }
    })());
  entry.state = "live";
  entry.stopWith = stopWith;
  return {
    target: { host: "127.0.0.1", port, adminUser: "postgres", adminPassword: password },
    pid: () => started.pid ?? made.process?.pid,
    stop: () => stopWith(30_000),
  };
}
