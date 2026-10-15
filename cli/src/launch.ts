import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { writeSync } from "node:fs";
import { leftoverDirs } from "./embedded.js";
import { killPidsNow, killTrackedFirstOnWindows, snapshotTracked } from "./observers/process.js";

/**
 * `server.command` together with `server.url` means "start this server, then talk to it at that URL".
 * The harness starts the process, waits until the URL answers HTTP, keeps it for the whole run, and stops it at the end.
 * It replaces the background process, wait loop and cleanup every CI job used to hand-write around an HTTP server.
 *
 * Safety rules (see docs/ci-design.md):
 *  - the process is registered the moment it is spawned, so a Ctrl+C or SIGTERM while still waiting can stop it;
 *  - something already answering on the URL before the start is an error (a leftover server would be graded instead);
 *  - "ready" means the URL gave a real answer: not 404 and not a 5xx (a wrong path or a half-started server);
 *  - errors that cannot get better by waiting (bad URL, certificate, unknown host) fail at once;
 *  - a process that dies right after answering, or later in the run, is reported, never ignored.
 */
export interface LaunchedServer {
  /** Stops the process and everything it started, and resolves when they are gone. Safe to call twice and at any time. */
  stop(): Promise<void>;
  /** Why the process is no longer running ("exited with code 1"), or undefined while it is. */
  exited(): string | undefined;
  /** Process id of the launched process (the leader of its own process group on POSIX), or undefined when it could not be spawned. */
  readonly pid: number | undefined;
}

export interface LaunchOptions {
  command: string;
  args: string[];
  /** Extra environment for the process, on top of the harness's own environment. Already placeholder-expanded. */
  env: Record<string, string>;
  /** Working directory of the process. Default: the harness's own (the sandbox root when the harness confines the server). */
  cwd?: string;
  /** The complete environment, replacing the harness's own (`sandbox.env()`); `env` is merged on top. Omitted: the harness's environment. */
  baseEnv?: Record<string, string>;
  /** Called with every chunk the process writes, as it arrives (feeds the log observer). */
  onOutput?: (chunk: string, stream: "stdout" | "stderr") => void;
  /** The URL the server will answer on. */
  url: string;
  timeoutMs: number;
  onProgress?: (line: string) => void;
  /** Called right after the process is spawned, before waiting, so the caller can stop it if the run is cancelled meanwhile. */
  onStarted?: (server: LaunchedServer) => void;
}

export class LaunchError extends Error {}

/** The advice after a server that did not answer `initialize` in time; `run` and `doctor` say it in the same words. */
export const CONNECT_TIMEOUT_ADVICE = "The first start of an npx or uvx server downloads it: run the command once by hand, pin the version, or raise the limit.";

/** True for the SDK's request timeout (JSON-RPC code -32001, "Request timed out"). */
export const isConnectTimeout = (message: string): boolean => /-32001|Request timed out/i.test(message);

/** `the server did not answer initialize within 60 s (--connect-timeout). The first start of ...` */
export const connectTimeoutMessage = (connectMs: number): string => `the server did not answer initialize within ${Math.round(connectMs / 1000)} s (--connect-timeout). ${CONNECT_TIMEOUT_ADVICE}`;

const TAIL_BYTES = 8 * 1024;
const WIN = process.platform === "win32";

/** Every process this module started and has not stopped: a last-resort synchronous kill when sealmark itself exits. */
const live = new Map<number, ChildProcess>();
let exitHookInstalled = false;

function killNow(pid: number): void {
  try {
    if (WIN) spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    else process.kill(-pid, "SIGKILL");
  } catch {
    /* already gone */
  }
}

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const pid of live.keys()) killNow(pid);
  });
}

const SIGNAL_EXIT: Record<string, number> = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };

/** The exit code of the signal that interrupted this process (128 + its number), or undefined while none has. Set by the first signal `stopOnSignals` handles. */
let interruptedWith: number | undefined;
export const wasInterrupted = (): boolean => interruptedWith !== undefined;
export const interruptCode = (): number | undefined => interruptedWith;

/** Synchronous, so the last line before `process.exit` is never dropped (a piped stderr is asynchronous on some platforms). */
function stderrNow(line: string): void {
  try {
    writeSync(2, `${line}\n`);
  } catch {
    /* nowhere to say it */
  }
}

export interface StopOnSignalsOptions {
  /** More paths than the embedded Postgres's data directories that the bail line names when it fires (the sandbox, for the run). */
  leftovers?: () => string[];
  /** How long the cleanup may take before the process exits anyway (default 15 s). */
  bailMs?: number;
}

/**
 * Stops everything on Ctrl+C, SIGTERM and SIGHUP (a closed terminal or a dropped SSH session; a launched server is in its own
 * process group, so the terminal's hangup never reaches it). The first signal runs `cleanup` and then exits with 128 + the
 * signal number. The handlers stay installed until the returned function is called, so a second signal while cleanup is still
 * waiting is not the default "die now": it exits at once with 130, and the synchronous 'exit' hook above kills every launched
 * process group on the way out.
 *
 * `onFirst` announces an interactive interrupt, so it runs for Ctrl+C only; for any other signal ("press Ctrl+C again" would be
 * wrong for a kill that came from outside) this prints the neutral "stopping: cleaning up" instead. The process exits only
 * after `cleanup` has finished, then after every server process a session had started but not yet registered (a server that is
 * still starting, which `cleanup` cannot see) has been stopped, tree and all. The exit code is the signal's, whatever the
 * interrupted run was about to report.
 */
export function stopOnSignals(cleanup: (signal: NodeJS.Signals) => Promise<void>, onFirst?: (signal: NodeJS.Signals) => void, opts: StopOnSignalsOptions = {}): () => void {
  installExitHook();
  let fired = false;
  const handler = (signal: NodeJS.Signals): void => {
    if (fired) process.exit(130);
    fired = true;
    const code = SIGNAL_EXIT[signal] ?? 130;
    interruptedWith = code;
    let cleanupDone = false;
    // Stopping the server under test makes the interrupted run fail fast; if it reaches its own process.exit first, the signal's code must still win.
    process.on("exit", () => {
      process.exitCode = code;
    });
    if (onFirst) {
      if (signal === "SIGINT") onFirst(signal);
      else process.stderr.write("stopping: cleaning up\n");
    }
    // The cleanup did not finish in time: say what it leaves, synchronously, before the process goes (the line is never missing).
    const bail = setTimeout(() => {
      const left = [...new Set([...leftoverDirs(), ...(opts.leftovers?.() ?? [])])];
      if (left.length) stderrNow(`cleanup did not finish: ${left.join(", ")} (remove ${left.length === 1 ? "it" : "them"} by hand)`);
      else if (!cleanupDone) stderrNow(`cleanup did not finish within ${Math.round((opts.bailMs ?? 15_000) / 1000)} s: something may still be running`);
      process.exit(code);
    }, opts.bailMs ?? 15_000);
    bail.unref();
    void (async () => {
      try {
        // Windows cannot delete a directory a live process is working in, so the servers go before the sandbox is removed there.
        killTrackedFirstOnWindows();
        await cleanup(signal);
        cleanupDone = true;
      } catch {
        /* nothing more to do: the exit code below is what counts */
      }
      try {
        // POSIX: the trees are listed and killed in one synchronous step, so the interrupted run cannot unwind in between.
        killPidsNow(await snapshotTracked());
      } catch {
        /* the 'exit' hook kills the roots */
      }
      // One turn of the event loop first: a run whose last pack had finished when the signal landed unwinds in microtasks and prints its report
      // and its exit line synchronously, so they are out before the process goes (the exit line then says "interrupted", never the gate's verdict).
      await new Promise<void>((r) => setImmediate(r));
      process.exit(code);
    })();
  };
  const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
  for (const sig of signals) process.on(sig, handler);
  return () => {
    for (const sig of signals) process.off(sig, handler);
  };
}

/** Windows cannot run npx.cmd and friends without a shell (Node refuses .cmd files since 22.x), so quote and let the shell find them. */
const quoteWin = (a: string): string => (/[\s"&|<>^%]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);

/** Keeps the last few KiB of the server's output so a failed start can say why. */
function tailOf(child: ChildProcess): () => string {
  let buf = "";
  const take = (b: Buffer) => {
    buf = (buf + b.toString("utf8")).slice(-TAIL_BYTES);
  };
  child.stdout?.on("data", take);
  child.stderr?.on("data", take);
  return () => buf.trim();
}

type Probe = { state: "ready" | "answered-badly" | "not-yet" | "fatal"; detail: string };

/** Codes that waiting will not fix: the URL itself or the certificate is wrong. */
const FATAL_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "ERR_INVALID_URL", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "CERT_HAS_EXPIRED", "ERR_TLS_CERT_ALTNAME_INVALID", "ERR_SSL_WRONG_VERSION_NUMBER"]);

async function probe(url: string, limitMs = 2_000): Promise<Probe> {
  // "localhost:8000/mcp" parses as a URL whose scheme is "localhost:"; waiting for it would never end.
  if (!/^https?:\/\//i.test(url)) return { state: "fatal", detail: `${url} is not a valid URL: it must start with http:// or https://` };
  try {
    const r = await fetch(url, {
      method: "POST",
      // The Accept header an MCP client sends, so a strict server answers with its own 401/400 instead of 406.
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: "{}",
      // Never wait past the caller's own limit: --start-timeout 1 must not take 3 s.
      signal: AbortSignal.timeout(Math.max(1, Math.min(2_000, limitMs))),
    });
    await r.body?.cancel().catch(() => {});
    // 404 means the path is wrong (or another service holds the port); 5xx means the server is not ready yet.
    if (r.status === 404 || r.status >= 500) return { state: "answered-badly", detail: `HTTP ${r.status}` };
    return { state: "ready", detail: `HTTP ${r.status}` };
  } catch (e) {
    const err = e as { name?: string; code?: string; message?: string; cause?: { code?: string; message?: string } };
    const code = err.cause?.code ?? err.code ?? "";
    if (err.name === "TypeError" && /invalid url/i.test(err.message ?? "")) return { state: "fatal", detail: `${url} is not a valid URL` };
    if (FATAL_CODES.has(code)) return { state: "fatal", detail: `${code}: ${err.cause?.message ?? err.message ?? ""}`.trim() };
    return { state: "not-yet", detail: code || err.name || "no answer" };
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function launchServer(o: LaunchOptions): Promise<LaunchedServer> {
  installExitHook();
  // Something already answering means a stale server (or the wrong port) would be graded instead of the one we start.
  const before = await probe(o.url);
  if (before.state === "fatal") throw new LaunchError(`cannot use ${o.url}: ${before.detail}`);
  if (before.state === "ready" || before.state === "answered-badly") {
    throw new LaunchError(`something is already answering at ${o.url} (${before.detail}) before the server was started, so it would be graded instead of yours. Stop it or use another port.`);
  }

  const child = spawn(WIN ? quoteWin(o.command) : o.command, WIN ? o.args.map(quoteWin) : o.args, {
    env: { ...(o.baseEnv ?? process.env), ...o.env },
    ...(o.cwd ? { cwd: o.cwd } : {}),
    stdio: ["ignore", "pipe", "pipe"],
    // Own process group on POSIX so stopping also reaches a launcher's children (npx, uvx, a shell wrapper).
    detached: !WIN,
    shell: WIN,
    windowsHide: true,
  });
  const pid = child.pid;
  if (pid !== undefined) live.set(pid, child);
  const tail = tailOf(child);
  if (o.onOutput) {
    // Decoded per stream so a multi-byte character split across chunks is not mangled.
    for (const stream of ["stdout", "stderr"] as const) {
      const out = child[stream];
      out?.setEncoding("utf8");
      out?.on("data", (chunk: string) => {
        try {
          o.onOutput!(chunk, stream);
        } catch {
          /* an observer must never take the server down */
        }
      });
    }
  }
  let exited: { code: number | null; signal: NodeJS.Signals | null; at: number } | undefined;
  let spawnError: Error | undefined;
  child.once("exit", (code, signal) => (exited = { code, signal, at: Date.now() }));
  child.once("error", (e) => (spawnError = e));

  const groupAlive = (): boolean => {
    if (pid === undefined) return false;
    if (WIN) return !exited;
    try {
      process.kill(-pid, 0);
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "EPERM";
    }
  };
  const signalGroup = (sig: NodeJS.Signals): void => {
    if (pid === undefined) return;
    try {
      if (WIN) spawnSync("taskkill", ["/PID", String(pid), "/T", ...(sig === "SIGKILL" ? ["/F"] : [])], { stdio: "ignore", windowsHide: true });
      else process.kill(-pid, sig);
    } catch {
      /* already gone */
    }
  };

  let stopping: Promise<void> | undefined;
  const stop = (): Promise<void> =>
    (stopping ??= (async () => {
      if (pid === undefined) return;
      // The wrapper may have exited while its children still run, so signal the whole group, not just the leader.
      // (A leader that exited long ago may have had its pid reused: leave that group alone.)
      const longGone = exited !== undefined && Date.now() - exited.at > 30_000;
      if (!longGone) {
        signalGroup("SIGTERM");
        for (let i = 0; i < 60 && groupAlive(); i++) await sleep(50);
        if (groupAlive()) {
          signalGroup("SIGKILL");
          for (let i = 0; i < 40 && groupAlive(); i++) await sleep(50);
        }
      }
      live.delete(pid);
    })());

  const handle: LaunchedServer = {
    stop,
    pid,
    exited: () => (exited ? (exited.signal ? `was killed by ${exited.signal}` : `exited with code ${exited.code}`) : undefined),
  };
  o.onStarted?.(handle);

  const started = Date.now();
  o.onProgress?.(`starting the server (${o.command}) and waiting for ${o.url} (limit ${Math.round(o.timeoutMs / 1000)} s)`);
  let last = "no answer yet";
  const fail = async (message: string): Promise<never> => {
    await stop();
    throw new LaunchError(`${message}${tail() ? `. Its last output:\n${tail()}` : "."}`);
  };
  while (Date.now() - started < o.timeoutMs) {
    if (spawnError) return fail(`could not start "${o.command}": ${spawnError.message}`);
    if (exited) return fail(`the server ${handle.exited()} before ${o.url} answered`);
    const p = await probe(o.url, o.timeoutMs - (Date.now() - started));
    if (p.state === "fatal") return fail(`cannot use ${o.url}: ${p.detail}`);
    if (p.state === "ready") {
      // A different process could be the one that answered (it won the port); give ours a moment to fail on its own.
      await sleep(300);
      if (exited) return fail(`the server ${handle.exited()} right after ${o.url} answered, so another process probably holds that port`);
      o.onProgress?.(`the server answered (${p.detail}) after ${((Date.now() - started) / 1000).toFixed(1)} s`);
      return handle;
    }
    last = p.state === "answered-badly" ? `the last answer was ${p.detail}, which is not a working MCP endpoint (check the URL path)` : `the last attempt: ${p.detail}`;
    await sleep(Math.max(0, Math.min(500, o.timeoutMs - (Date.now() - started))));
  }
  return fail(`${o.url} did not answer within ${Math.round(o.timeoutMs / 1000)} s (${last}; raise --start-timeout, or server.start_timeout_sec in sealmark.yaml, if the server is slow to start)`);
}
