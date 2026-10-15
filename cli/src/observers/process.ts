// Process observer: list processes, find the ones that belong to a sandbox, kill them.
// Windows uses Get-CimInstance (one PowerShell start, about 1-2 s per call); POSIX uses ps and /proc.
//
// Ownership rule (stated, approximate): a process belongs to the sandbox when its executable is under
// <sandbox>/bin, or its working directory is under the sandbox (POSIX only: Windows does not expose a
// process's cwd to CIM), or its command line mentions the sandbox directory. The harness's own process
// and its ancestors are never matched.
//
// The tree helpers below the observer (terminateTree, trackRoot, ...) stop a server process and everything a launcher
// started under it, and are awaited, so nothing is left running behind a failed start or a signal.
import { execFile, spawnSync } from "node:child_process";
import { readlinkSync } from "node:fs";

export interface ProcInfo {
  pid: number;
  ppid: number;
  name: string;
  exe?: string;
  cmd?: string;
  cwd?: string;
}

export interface ProcessObserver {
  list(): Promise<ProcInfo[]>;
  /** Processes that belong to the sandbox by the rule above. */
  strays(all?: ProcInfo[]): Promise<ProcInfo[]>;
  /** Kill every stray (trees included). Returns what was found and targeted. */
  killStrays(): Promise<ProcInfo[]>;
  /** Kill a process and everything below it, and wait until they are gone. */
  killTree(pid: number): Promise<void>;
  isAlive(pid: number): boolean;
}

const norm = (p: string): string => p.replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
const under = (p: string | undefined, dir: string): boolean => {
  if (!p) return false;
  const a = norm(p);
  const b = norm(dir);
  return a === b || a.startsWith(`${b}/`);
};

function run(file: string, args: string[], timeoutMs = 30_000): Promise<{ stdout: string; code: number }> {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs, encoding: "utf8" }, (err, stdout) => {
      const code = err ? Number((err as { code?: unknown }).code) || 1 : 0;
      resolve({ stdout: String(stdout ?? ""), code });
    });
  });
}

const PS_LIST =
  "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; " +
  "@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine) | ConvertTo-Json -Compress -Depth 2";

async function listWindows(): Promise<ProcInfo[]> {
  const { stdout } = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_LIST]);
  const text = stdout.trim();
  if (!text) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  const rows = Array.isArray(parsed) ? parsed : [parsed];
  return (rows as Record<string, unknown>[])
    .filter((r) => typeof r.ProcessId === "number")
    .map((r) => ({
      pid: r.ProcessId as number,
      ppid: Number(r.ParentProcessId ?? 0),
      name: String(r.Name ?? ""),
      exe: typeof r.ExecutablePath === "string" ? r.ExecutablePath : undefined,
      cmd: typeof r.CommandLine === "string" ? r.CommandLine : undefined,
    }));
}

async function listPosix(): Promise<ProcInfo[]> {
  const { stdout } = await run("ps", ["-eo", "pid=,ppid=,comm=,args="]);
  const out: ProcInfo[] = [];
  for (const line of stdout.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({ pid: Number(m[1]), ppid: Number(m[2]), name: m[3]!, cmd: m[4] || undefined });
  }
  return out;
}

function fillProc(p: ProcInfo): ProcInfo {
  if (process.platform === "linux") {
    try {
      p.cwd = readlinkSync(`/proc/${p.pid}/cwd`);
    } catch {
      /* not ours to read, or gone */
    }
    try {
      p.exe = readlinkSync(`/proc/${p.pid}/exe`);
    } catch {
      /* ignore */
    }
  }
  return p;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** `rootPid` and everything below it (children, grandchildren...), deepest first, so a parent is never killed before its children. */
function treeOf(rootPid: number, all: ProcInfo[]): ProcInfo[] {
  const kids = new Map<number, ProcInfo[]>();
  for (const p of all) kids.set(p.ppid, [...(kids.get(p.ppid) ?? []), p]);
  const byPid = new Map(all.map((p) => [p.pid, p]));
  const out: ProcInfo[] = [];
  const seen = new Set<number>();
  const stack = [rootPid];
  while (stack.length) {
    const pid = stack.pop()!;
    if (seen.has(pid)) continue;
    seen.add(pid);
    const self = byPid.get(pid);
    if (self) out.push(self);
    for (const k of kids.get(pid) ?? []) stack.push(k.pid);
  }
  return out.reverse();
}

export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function signalPid(pid: number, sig: NodeJS.Signals): void {
  try {
    process.kill(pid, sig);
  } catch {
    /* already gone */
  }
}

/** Waits until none of `pids` is alive or `withinMs` has passed; returns the ones that still are. */
async function waitGone(pids: Iterable<number>, withinMs: number): Promise<number[]> {
  const all = [...pids];
  const until = Date.now() + withinMs;
  for (;;) {
    const up = all.filter(pidAlive);
    if (up.length === 0 || Date.now() >= until) return up;
    await sleep(25);
  }
}

/** `pid` and its descendants right now, deepest first (POSIX: one `ps`; Windows: just `pid`, because taskkill /T walks the tree itself). */
export async function snapshotTree(pid: number): Promise<number[]> {
  if (process.platform === "win32") return [pid];
  const tree = treeOf(pid, await listPosix()).map((p) => p.pid);
  return tree.includes(pid) ? tree : [...tree, pid];
}

/**
 * `pid` and its descendants right now with their command lines, deepest first. POSIX only (Windows: empty, because taskkill /T
 * walks the tree itself and a stale pid cannot be checked against its old command line there).
 */
export async function snapshotTreeInfo(pid: number): Promise<ProcInfo[]> {
  if (process.platform === "win32") return [];
  return treeOf(pid, await listPosix());
}

/**
 * Stops the processes of an earlier `snapshotTreeInfo` that are still running as the same program: a pid that now belongs to
 * something else (the number was reused) has a different command line and is left alone. This is how descendants of a launcher
 * that has already exited are reached: nothing links them to it any more. Returns the pids it signalled.
 */
export async function terminateRemembered(remembered: ProcInfo[], o: { graceMs?: number } = {}): Promise<number[]> {
  if (process.platform === "win32" || remembered.length === 0) return [];
  const now = new Map((await listPosix()).map((p) => [p.pid, p]));
  const same = remembered.filter((r) => r.pid !== process.pid && r.cmd !== undefined && now.get(r.pid)?.cmd === r.cmd).map((r) => r.pid);
  if (same.length) await terminatePids(same, o);
  return same;
}

/**
 * Stops the given processes and waits until they are gone: SIGTERM, then after `graceMs` SIGKILL (graceMs 0 goes straight to
 * SIGKILL), looking the tree up again before the SIGKILL so a child started during the grace period is caught too. Windows:
 * `taskkill /T /F` per pid. Bounded: returns the pids that would not go (a zombie nobody reaps, or a process we may not signal).
 */
export async function terminatePids(pids: number[], o: { graceMs?: number } = {}): Promise<number[]> {
  const graceMs = o.graceMs ?? 0;
  if (process.platform === "win32") {
    for (const pid of pids) await run("taskkill", ["/PID", String(pid), "/T", "/F"], 15_000);
    return waitGone(pids, 2000);
  }
  const set = new Set(pids);
  if (graceMs > 0) {
    for (const pid of pids) if (pidAlive(pid)) signalPid(pid, "SIGTERM");
    if ((await waitGone(set, graceMs)).length === 0) return [];
  }
  // Whatever is still alive, and anything those processes started in the meantime.
  const now = await listPosix();
  for (const pid of [...set]) if (pidAlive(pid)) for (const p of treeOf(pid, now)) set.add(p.pid);
  for (const pid of [...set].reverse()) if (pidAlive(pid)) signalPid(pid, "SIGKILL");
  return waitGone(set, 2000);
}

/** Stops `pid` and everything it started, and waits until they are gone. */
export async function terminateTree(pid: number, o: { graceMs?: number } = {}): Promise<number[]> {
  return terminatePids(await snapshotTree(pid), o);
}

// ---- server processes a session has started and not yet closed -------------------------------------------------------
// The SDK starts a stdio server in the harness's own process group, not its own, so the group cannot be signalled and a
// launcher's children are found only by walking parent links. The roots are remembered here so a signal that arrives while a
// server is still starting, or an exit that skips a close, can still stop every tree.
const tracked = new Set<number>();
let exitHook = false;

/** Windows: taskkill /T takes each tree. POSIX: one `ps`, then SIGKILL, deepest first. Synchronous, for where nothing can be awaited. */
export function killTrackedSync(): void {
  if (tracked.size === 0) return;
  if (process.platform === "win32") {
    for (const pid of tracked) spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    return;
  }
  const all: ProcInfo[] = [];
  try {
    const r = spawnSync("ps", ["-eo", "pid=,ppid=,comm="], { encoding: "utf8", timeout: 5000 });
    for (const line of String(r.stdout ?? "").split("\n")) {
      const m = /^\s*(\d+)\s+(\d+)\s+(\S+)/.exec(line);
      if (m) all.push({ pid: Number(m[1]), ppid: Number(m[2]), name: m[3]! });
    }
  } catch {
    /* no ps: kill the roots */
  }
  const set = new Set<number>(tracked);
  for (const pid of tracked) for (const p of treeOf(pid, all)) set.add(p.pid);
  for (const pid of [...set].reverse()) signalPid(pid, "SIGKILL");
}

export function trackRoot(pid: number): void {
  tracked.add(pid);
  if (!exitHook) {
    exitHook = true;
    process.on("exit", killTrackedSync);
  }
}

export function untrackRoot(pid: number): void {
  tracked.delete(pid);
}

/** Every tracked root and its descendants, deepest first. Pair with killPidsNow. */
export async function snapshotTracked(): Promise<number[]> {
  const out = new Set<number>();
  for (const pid of [...tracked]) for (const p of await snapshotTree(pid)) out.add(p);
  return [...out];
}

/** SIGKILL (Windows: taskkill /T /F) without waiting: for the moment right before process.exit. */
export function killPidsNow(pids: number[]): void {
  for (const pid of pids) {
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    else signalPid(pid, "SIGKILL");
  }
}

/** Windows only: a live working directory cannot be deleted there, so the tracked trees go before the sandbox is removed. */
export function killTrackedFirstOnWindows(): void {
  if (process.platform === "win32") killTrackedSync();
}

export function createProcessObserver(o: { sandboxDir: string; bin: string }): ProcessObserver {
  const win = process.platform === "win32";
  const list = () => (win ? listWindows() : listPosix());

  const protectedPids = (all: ProcInfo[]): Set<number> => {
    const byPid = new Map(all.map((p) => [p.pid, p]));
    const s = new Set<number>([process.pid]);
    for (let pid = process.ppid, n = 0; pid && n < 64 && !s.has(pid); n++) {
      s.add(pid);
      pid = byPid.get(pid)?.ppid ?? 0;
    }
    return s;
  };

  const strays = async (given?: ProcInfo[]): Promise<ProcInfo[]> => {
    const all = given ?? (await list());
    const skip = protectedPids(all);
    const dirN = norm(o.sandboxDir);
    return all.filter((p) => {
      if (skip.has(p.pid)) return false;
      if (!win) fillProc(p);
      if (under(p.exe, o.bin)) return true;
      if (p.cwd && under(p.cwd, o.sandboxDir)) return true;
      return Boolean(p.cmd && norm(p.cmd).includes(dirN));
    });
  };

  // The whole tree (a launcher's children included), SIGKILLed deepest first, looked up again once in case it forked meanwhile, and awaited.
  const killTree = async (pid: number): Promise<void> => {
    if (win) {
      await run("taskkill", ["/PID", String(pid), "/T", "/F"], 15_000);
      return;
    }
    await terminateTree(pid);
  };

  return {
    list,
    strays,
    async killStrays() {
      const found = await strays();
      const done = new Set<number>();
      // A stray's children are strays too on POSIX; on Windows taskkill /T takes the tree. Skip pids already covered.
      for (const p of found) {
        if (done.has(p.pid)) continue;
        await killTree(p.pid);
        done.add(p.pid);
        if (!win) for (const k of treeOf(p.pid, found)) done.add(k.pid);
      }
      return found;
    },
    killTree,
    isAlive: pidAlive,
  };
}
