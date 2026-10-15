// Disposable sandbox the harness owns: <base>/sealmark-<rand>/{root, root-evil, canary, home, tmp, bin}.
//
// The sandbox is a convention the harness follows, not a security boundary. A malicious server runs with
// the user's privileges, sees the real file system and network, and can ignore cwd, HOME and PATH.
// Run untrusted servers in a throwaway VM or container.
import { randomBytes } from "node:crypto";
import { createWriteStream, existsSync, lstatSync, mkdirSync, realpathSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { lstat, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, join, parse, resolve } from "node:path";
import { DEFAULT_INHERITED_ENV_VARS } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createFsObserver, type FsObserver } from "./observers/fs.js";
import { startListener, type Listener } from "./observers/listener.js";
import { createProcessObserver, type ProcessObserver } from "./observers/process.js";

export const SANDBOX_NON_GUARANTEE =
  "The sandbox is a convention the harness follows, not a security boundary. A malicious server runs with your user's privileges, sees the real file system and network, and can ignore cwd, HOME and PATH. Run untrusted servers in a throwaway VM or container.";

/** Fixed names of the programs in <sandbox>/bin (package D relies on them). */
export const BIN_NAMES = ["sm-canary", "sm-echo", "sm-sleep", "sm-spew"] as const;
export type BinName = (typeof BIN_NAMES)[number];

export interface LinkStatus {
  ok: boolean;
  kind: "junction" | "symlink" | "na";
  /** Why the link could not be made (for example: needs Developer Mode or an elevated shell). */
  reason?: string;
  path: string;
}

export interface BinProgram {
  /** Node script that does the work (.cjs so a surrounding "type": "module" cannot break it). */
  script: string;
  /** What a shell finds when it resolves the bare name: sm-x.cmd on Windows, an executable sh wrapper elsewhere. */
  launcher: string;
  /** Spawn-style invocation that works on every platform without a shell: `process.execPath` plus the script. */
  program: string;
  args: string[];
}

export interface SandboxOptions {
  /** Parent directory. Default os.tmpdir(). */
  dir?: string;
  /** Sandbox size cap in bytes. Default 1 GiB. */
  maxBytes?: number;
  /** Size poll interval in ms. Default 2000. */
  pollMs?: number;
  /** Used for the /slow hold: timeoutProbeSec + 30 s. Default 10. */
  timeoutProbeSec?: number;
  /** Overrides the /slow hold (tests). */
  slowHoldMs?: number;
  /** Names copied from the real environment into env() (the `keep_env` setting). */
  keepEnv?: string[];
  /**
   * Point npm, uv and uv-managed Python at the real cache directories so a launcher does not re-download
   * the server on every session. Default true. These paths are inherited and listed in `inherited`.
   */
  sharedCaches?: boolean;
  /** destroy(): retries and delay between them. Defaults 5 and 1000 ms (5 retries over 5 s). */
  destroyRetries?: number;
  destroyRetryDelayMs?: number;
  log?: (s: string) => void;
}

export interface DestroyResult {
  cleanedUp: boolean;
  /** Paths and processes that are still there. Empty when cleanedUp (or when kept on request). */
  leftover: string[];
  /** The sandbox path, for the report when cleanedUp is false. */
  path: string;
  kept?: boolean;
}

export interface Sandbox {
  /** The sandbox directory `S`. */
  readonly dir: string;
  /** `S/root`: allowed root, server cwd, value of {sandbox}. */
  readonly root: string;
  /** `S/root-evil`: sibling whose name has the root as a prefix. */
  readonly rootEvil: string;
  /** `S/canary`: never given to the server through config. */
  readonly canary: string;
  /** `S/home`: value of {sandbox_home}. */
  readonly home: string;
  readonly tmp: string;
  readonly bin: string;
  /** `linkDangling`: a symbolic link in the root to a file in the canary directory that does not exist (a write through it creates the file there). */
  readonly files: { canary: string; evil: string; ok: string; linkDir: string; linkFile: string; linkDangling: string; big: string };
  readonly tokens: { canary: string; evil: string; control: string };
  /** `dangling` is absent in a hand-built sandbox that predates the dangling link. */
  readonly links: { dir: LinkStatus; file: LinkStatus; dangling?: LinkStatus };
  readonly bins: Record<BinName, BinProgram>;
  readonly listener: Listener;
  readonly fs: FsObserver;
  readonly proc: ProcessObserver;
  /** Aborts when the sandbox grows past the size cap (the probe in flight should be treated as a fail). */
  readonly sizeExceeded: AbortSignal;
  /** Names of environment items taken from the real environment, for the report. */
  readonly inherited: string[];
  /** The scrubbed environment for a stdio server. `extra` (server.env, canaries) is applied last. */
  env(extra?: Record<string, string>, opts?: { keepEnv?: string[] }): Record<string, string>;
  /** Create S/root/big.bin (default 64 MiB) on first use and return its path. */
  bigFile(mib?: number): Promise<string>;
  sizeBytes(): Promise<number>;
  destroy(opts?: { keep?: boolean }): Promise<DestroyResult>;
}

const rand = (n = 6) => randomBytes(n).toString("hex");
const WIN = process.platform === "win32";
const SDK_KEYS = new Set<string>(DEFAULT_INHERITED_ENV_VARS);

/** Sum of file sizes under dir, not following links. Stops early once the sum passes `stopAbove`. */
async function dirBytes(dir: string, stopAbove = Infinity): Promise<number> {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop()!;
    let names: string[];
    try {
      names = await readdir(d);
    } catch {
      continue;
    }
    for (const n of names) {
      const p = join(d, n);
      try {
        const st = await lstat(p);
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) stack.push(p);
        else total += st.size;
      } catch {
        /* vanished */
      }
      if (total > stopAbove) return total;
    }
  }
  return total;
}

function makeLink(target: string, path: string, wantDir: boolean): LinkStatus {
  const attempts: ("junction" | "dir" | "file")[] = wantDir ? (WIN ? ["junction", "dir"] : ["dir"]) : ["file"];
  let reason = "";
  for (const type of attempts) {
    try {
      symlinkSync(target, path, type);
      return { ok: true, kind: type === "junction" ? "junction" : "symlink", path };
    } catch (e) {
      reason = (e as NodeJS.ErrnoException).code === "EPERM" || (e as NodeJS.ErrnoException).code === "EACCES" ? "needs Developer Mode or an elevated shell to create symbolic links" : String((e as Error).message);
    }
  }
  return { ok: false, kind: "na", reason, path };
}

function removeLinkSync(p: string): void {
  try {
    if (!lstatSync(p).isSymbolicLink()) return;
  } catch {
    return;
  }
  try {
    unlinkSync(p);
  } catch {
    try {
      rmdirSync(p);
    } catch {
      /* the recursive delete below will report it */
    }
  }
}

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

function binScripts(root: string, canary: string): Record<BinName, string> {
  const j = JSON.stringify;
  const head = "'use strict';\nconst fs = require('node:fs');\nconst path = require('node:path');\n";
  return {
    "sm-canary":
      head +
      `// Harness canary: if a server runs this, its argument handling reached a shell.\nconst dir = ${j(canary)};\nfs.mkdirSync(dir, { recursive: true });\n` +
      `fs.writeFileSync(path.join(dir, 'executed-' + process.pid + '.txt'), 'sm-executed argv=' + JSON.stringify(process.argv.slice(2)) + ' cwd=' + process.cwd() + '\\n');\nconsole.log('sm-canary ran');\n`,
    "sm-echo":
      head +
      `// Records argv and cwd under the sandbox root, prints argv.\nconst dir = ${j(root)};\nconst argv = process.argv.slice(2);\n` +
      `fs.writeFileSync(path.join(dir, 'argv-' + process.pid + '-' + Date.now().toString(36) + '.txt'), JSON.stringify({ argv, cwd: process.cwd(), pid: process.pid }) + '\\n');\nconsole.log('sm-echo ' + argv.join(' '));\n`,
    "sm-sleep":
      head +
      `// Sleeps for <seconds> (default 30), then exits.\nconst s = Number(process.argv[2] ?? 30);\nconsole.log('sm-sleep pid=' + process.pid);\nsetTimeout(() => process.exit(0), Math.max(0, s) * 1000);\n`,
    "sm-spew":
      head +
      `// Writes <MiB> (default 64) of 'x' to stdout, honouring backpressure.\nlet left = Number(process.argv[2] ?? 64) * 1024 * 1024;\nconst chunk = Buffer.alloc(64 * 1024, 0x78);\n` +
      `process.stdout.on('error', () => process.exit(0));\nfunction pump() {\n  while (left > 0) {\n    const part = left >= chunk.length ? chunk : chunk.subarray(0, left);\n    left -= part.length;\n    if (!process.stdout.write(part)) { process.stdout.once('drain', pump); return; }\n  }\n  process.exit(0);\n}\npump();\n`,
  };
}

function writeBins(bin: string, root: string, canary: string): Record<BinName, BinProgram> {
  const out = {} as Record<BinName, BinProgram>;
  const scripts = binScripts(root, canary);
  for (const name of BIN_NAMES) {
    const script = join(bin, `${name}.cjs`);
    writeFileSync(script, scripts[name]);
    let launcher: string;
    if (WIN) {
      launcher = join(bin, `${name}.cmd`);
      writeFileSync(launcher, `@echo off\r\n"${process.execPath}" "%~dp0${name}.cjs" %*\r\n`);
    } else {
      launcher = join(bin, name);
      writeFileSync(launcher, `#!/bin/sh\nexec ${shq(process.execPath)} ${shq(script)} "$@"\n`, { mode: 0o755 });
    }
    out[name] = { script, launcher, program: process.execPath, args: [script] };
  }
  return out;
}

/** What the harness builds inside a sandbox directory, without the listener, observers or watcher. */
export interface Layout {
  dir: string;
  root: string;
  rootEvil: string;
  canary: string;
  home: string;
  tmp: string;
  bin: string;
  files: Sandbox["files"];
  tokens: Sandbox["tokens"];
  links: Sandbox["links"];
  bins: Record<BinName, BinProgram>;
}

/**
 * Builds the directory layout and its files with fresh random tokens: the marker, root, root-evil, canary, home, tmp, bin,
 * ok.txt, the two secret files, the two links and the four sm-* programs. `dir` must exist and be empty. Shared by
 * createSandbox and `sealmark run --fixture fs`.
 */
export function createLayout(dir: string, log: (s: string) => void = () => {}): Layout {
  writeFileSync(join(dir, ".sealmark-sandbox"), "created by sealmark; safe to delete\n");
  // Private on POSIX (Windows ignores the mode): the canary and the home must not be readable by other local users under a 022 umask.
  const mk = (n: string, mode?: number) => {
    const p = join(dir, n);
    mkdirSync(p, mode === undefined ? undefined : { mode });
    return p;
  };
  const root = mk("root");
  const rootEvil = mk("root-evil");
  const canary = mk("canary");
  const home = mk("home", 0o700);
  const tmp = mk("tmp", 0o700);
  const bin = mk("bin");

  const tokens = { canary: `sm-fscanary-${rand(8)}`, evil: `sm-fscanary-${rand(8)}`, control: `sm-control-${rand(8)}` };
  const files = {
    canary: join(canary, "secret.txt"),
    evil: join(rootEvil, "secret.txt"),
    ok: join(root, "ok.txt"),
    linkDir: join(root, "link-dir"),
    linkFile: join(root, "link.txt"),
    linkDangling: join(root, "link-dangling.txt"),
    big: join(root, "big.bin"),
  };
  writeFileSync(files.canary, tokens.canary);
  writeFileSync(files.evil, tokens.evil);
  writeFileSync(files.ok, tokens.control);
  // The dangling link points at a file that is not there: a server that resolves links with realpath finds nothing to resolve, and a write lands at the target.
  const links = { dir: makeLink(canary, files.linkDir, true), file: makeLink(files.canary, files.linkFile, false), dangling: makeLink(join(canary, `dangling-${rand(6)}.txt`), files.linkDangling, false) };
  if (!links.file.ok) log(`sandbox: file symlink not created (${links.file.reason}); the file-link probes will be reported as not applicable`);
  if (!links.dir.ok) log(`sandbox: directory link not created (${links.dir.reason})`);
  const bins = writeBins(bin, root, canary);
  return { dir, root, rootEvil, canary, home, tmp, bin, files, tokens, links, bins };
}

export async function createSandbox(opts: SandboxOptions = {}): Promise<Sandbox> {
  const log = opts.log ?? (() => {});
  const wanted = resolve(opts.dir ?? tmpdir());
  mkdirSync(wanted, { recursive: true });
  const parent = realpathSync.native(wanted);
  const dir = join(parent, `sealmark-${rand(5)}`);
  mkdirSync(dir, { mode: 0o700 });
  const { root, rootEvil, canary, home, tmp, bin, files, tokens, links, bins } = createLayout(dir, log);

  const listener = await startListener({ slowHoldMs: opts.slowHoldMs ?? ((opts.timeoutProbeSec ?? 10) + 30) * 1000 });
  const fsObs = createFsObserver({ root, "root-evil": rootEvil, canary, home, tmp });
  const proc = createProcessObserver({ sandboxDir: dir, bin });

  // ---- size cap watcher ----
  const maxBytes = opts.maxBytes ?? 1024 * 1024 * 1024;
  const abort = new AbortController();
  let polling = false;
  const watcher = setInterval(() => {
    if (polling || abort.signal.aborted) return;
    polling = true;
    dirBytes(dir, maxBytes)
      .then((n) => {
        if (n > maxBytes && !abort.signal.aborted) {
          abort.abort(new Error(`sandbox grew past ${Math.round(maxBytes / 1024 / 1024)} MiB`));
          log(`sandbox: size cap of ${Math.round(maxBytes / 1024 / 1024)} MiB exceeded; stopping the processes that belong to it`);
          void proc.killStrays().catch(() => {});
          clearInterval(watcher);
        }
      })
      .catch(() => {})
      .finally(() => {
        polling = false;
      });
  }, opts.pollMs ?? 2000);
  watcher.unref();

  // ---- environment ----
  const real = (k: string): string | undefined => process.env[k];
  const sharedEnv = (): Record<string, string> => {
    if (opts.sharedCaches === false) return {};
    const e: Record<string, string> = {};
    const local = real("LOCALAPPDATA");
    const roaming = real("APPDATA");
    const xdgCache = real("XDG_CACHE_HOME") ?? join(homedir(), ".cache");
    const xdgData = real("XDG_DATA_HOME") ?? join(homedir(), ".local", "share");
    const npm = real("npm_config_cache") ?? (WIN ? (local ? join(local, "npm-cache") : undefined) : join(homedir(), ".npm"));
    const uv = real("UV_CACHE_DIR") ?? (WIN ? (local ? join(local, "uv", "cache") : undefined) : join(xdgCache, "uv"));
    const py = real("UV_PYTHON_INSTALL_DIR") ?? (WIN ? (roaming ? join(roaming, "uv", "python") : undefined) : join(xdgData, "uv", "python"));
    if (npm && existsSync(npm)) e.npm_config_cache = npm;
    if (uv && existsSync(uv)) e.UV_CACHE_DIR = uv;
    if (py && existsSync(py)) e.UV_PYTHON_INSTALL_DIR = py;
    return e;
  };
  const shared = sharedEnv();
  const inherited = ["PATH (system part)", "LANG", ...(WIN ? ["SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "PROGRAMFILES", "PROCESSOR_ARCHITECTURE"] : []), ...Object.keys(shared), ...(opts.keepEnv ?? [])];

  const env = (extra: Record<string, string> = {}, o: { keepEnv?: string[] } = {}): Record<string, string> => {
    const e: Record<string, string> = {};
    e.PATH = `${bin}${delimiter}${real("PATH") ?? ""}`;
    e.TEMP = tmp;
    e.TMP = tmp;
    e.TMPDIR = tmp;
    e.LANG = real("LANG") ?? "C.UTF-8";
    if (WIN) {
      const p = parse(home);
      e.HOME = home;
      e.USERPROFILE = home;
      e.HOMEDRIVE = p.root.replace(/[\\/]+$/, "") || "C:";
      e.HOMEPATH = home.slice(p.root.replace(/[\\/]+$/, "").length) || "\\";
      e.APPDATA = home;
      e.LOCALAPPDATA = home;
      e.USERNAME = "sealmark";
      e.USERDOMAIN = "SEALMARK";
      e.LOGONSERVER = "\\\\SEALMARK";
      for (const k of ["SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "PROGRAMFILES", "PROCESSOR_ARCHITECTURE"]) {
        const v = real(k);
        if (v !== undefined) e[k] = v;
      }
    } else {
      e.HOME = home;
      e.USER = "sealmark";
      e.LOGNAME = "sealmark";
      e.SHELL = "/bin/sh";
      e.TERM = "dumb";
    }
    Object.assign(e, shared);
    for (const k of [...(opts.keepEnv ?? []), ...(o.keepEnv ?? [])]) {
      const v = real(k);
      if (v !== undefined) e[k] = v;
    }
    Object.assign(e, extra);
    if (!WIN) return e;
    // Windows names are case-insensitive: keep one spelling per name (the last wins) and use the SDK's spelling for
    // the names it would otherwise add from the real environment, so its merge overrides instead of duplicating.
    const out: Record<string, string> = {};
    const at = new Map<string, string>();
    for (const [k, v] of Object.entries(e)) {
      const up = k.toUpperCase();
      const prev = at.get(up);
      if (prev !== undefined) delete out[prev];
      const name = SDK_KEYS.has(up) ? up : k;
      at.set(up, name);
      out[name] = v;
    }
    return out;
  };

  // ---- teardown ----
  let result: DestroyResult | undefined;
  let inflight: Promise<DestroyResult> | undefined;
  const retries = opts.destroyRetries ?? 5;
  const delay = opts.destroyRetryDelayMs ?? 1000;

  const doDestroy = async (o: { keep?: boolean }): Promise<DestroyResult> => {
    clearInterval(watcher);
    try {
      await proc.killStrays();
    } catch (e) {
      log(`sandbox: could not stop sandbox processes: ${(e as Error).message}`);
    }
    await listener.close().catch(() => {});
    if (o.keep) return { cleanedUp: false, leftover: [], path: dir, kept: true };
    // Guard: only ever delete the directory this module made (the marker file can be gone after a partial delete, so the name is the check).
    if (!basename(dir).startsWith("sealmark-") || dirname(dir) !== parent) {
      return { cleanedUp: false, leftover: [dir], path: dir };
    }
    // Links first, so a delete can never walk into the canary directory or anything a server linked to.
    for (const l of [files.linkDir, files.linkFile, files.linkDangling]) removeLinkSync(l);
    try {
      await rm(dir, { recursive: true, force: true, maxRetries: retries, retryDelay: delay });
    } catch (e) {
      log(`sandbox: could not delete ${dir}: ${(e as Error).message}`);
    }
    if (!existsSync(dir)) return { cleanedUp: true, leftover: [], path: dir };
    const leftover = [dir];
    try {
      for (const p of await proc.strays()) leftover.push(`process ${p.pid} ${p.name}`);
    } catch {
      /* listing is best effort */
    }
    return { cleanedUp: false, leftover, path: dir };
  };

  return {
    dir,
    root,
    rootEvil,
    canary,
    home,
    tmp,
    bin,
    files,
    tokens,
    links,
    bins,
    listener,
    fs: fsObs,
    proc,
    sizeExceeded: abort.signal,
    inherited,
    env,
    async bigFile(mib = 64) {
      if (!existsSync(files.big)) {
        await mkdir(root, { recursive: true });
        const chunk = Buffer.alloc(1024 * 1024, 0x62);
        await new Promise<void>((res, rej) => {
          const w = createWriteStream(files.big);
          let i = 0;
          const next = () => {
            while (i < mib) {
              i++;
              if (!w.write(chunk)) {
                w.once("drain", next);
                return;
              }
            }
            w.end();
          };
          w.on("error", rej);
          w.on("finish", () => res());
          next();
        });
      }
      return files.big;
    },
    sizeBytes: () => dirBytes(dir),
    destroy(o = {}) {
      if (result?.cleanedUp) return Promise.resolve(result);
      return (inflight ??= doDestroy(o)
        .then((r) => {
          if (r.cleanedUp) result = r;
          return r;
        })
        .finally(() => {
          inflight = undefined;
        }));
    },
  };
}

/**
 * A fresh empty directory under os.tmpdir() for a server started with --no-sandbox, so a stray .env or config
 * in the project directory is never loaded (addendum item 28).
 */
export async function createTempCwd(): Promise<{ dir: string; remove(): Promise<void> }> {
  const dir = join(realpathSync.native(tmpdir()), `sealmark-cwd-${rand(5)}`);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, ".sealmark-cwd"), "created by sealmark; safe to delete\n");
  return {
    dir,
    async remove() {
      if (!existsSync(join(dir, ".sealmark-cwd"))) return;
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 }).catch(() => {});
    },
  };
}
