import { randomBytes } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { ConfigError } from "./config.js";
import type { CheckDoc, CheckResult, Evidence, FsDiff, FsSnapshot, IdentityAccess, LogObserver, Pack, PackApplies, PackCtx, PackId, PluginSpec, RequestRecord, UpstreamStub, Verdict } from "./types.js";

/**
 * Plugin packs. A plugin is an ES module whose default export has the shape of `Pack` plus a
 * version and the sealmark range it was written for. It runs in-process with the same trust as the config file that
 * declares it. Observer helpers are passed in on `ctx.helpers`, never imported, so a plugin cannot reach past them
 * by accident. A plugin cannot change another pack's results or the grading formula, and a run with any plugin is custom.
 */

export interface PluginHelpers {
  /** A fresh random token to embed in a probe so an observation maps back to one probe. */
  token(): string;
  /** Snapshot the sandbox directories by label (root, root-evil, canary, home, tmp; default all). Throws a clear error under --no-sandbox. */
  snapshot(labels?: string[]): Promise<FsSnapshot>;
  /** What changed since `before` (against a fresh snapshot, or `after` when given). */
  diff(before: FsSnapshot, after?: FsSnapshot): Promise<FsDiff>;
  listener: {
    /** The loopback URL a probe may point a tool at; `path` includes the leading slash. */
    url(path?: string): string;
    /** HTTP requests that carried this token. */
    expect(token: string): RequestRecord[];
  };
  /** What the harness-owned upstream stub received; undefined when the run has none (`upstream.kind` unset). */
  upstream?: Pick<UpstreamStub, "mark" | "requests" | "find" | "waitFor" | "url">;
  /** What the launched (or stdio) server printed; undefined when the harness does not see its output. */
  serverLog?: Pick<LogObserver, "mark" | "since" | "find">;
  /** A fresh session as a given identity (`{bearer}` = that identity's value), or anonymous for `null`; undefined when the run has no identities. */
  openAs?: IdentityAccess["openAs"];
  /** True when the path is inside the sandbox directory (lexical, case-insensitive on Windows). */
  inSandbox(path: string): boolean;
  /** Build a CheckResult for this plugin: pack, label prefix and metadata are filled in. */
  done(meta: { id: string; label: string; critical: boolean; scope: string; advisory?: boolean }, verdict: Verdict, summary: string, evidence: Evidence[]): CheckResult;
}

export interface PluginCtx extends PackCtx {
  helpers: PluginHelpers;
  /** `options:` from the plugin's entry under `plugins:`. */
  options: Record<string, unknown>;
}

/** What a plugin module default-exports. */
export interface PluginModule {
  id: `plugin:${string}`;
  version: string;
  /** Semver range of sealmark versions this plugin supports: `>=0.2 <0.3`, `^0.2`, `~0.2.1`, `0.2.x`. Space means AND, `||` means OR. */
  sealmark: string;
  describe(): CheckDoc[];
  applies(ctx: PluginCtx): PackApplies;
  run(ctx: PluginCtx): Promise<CheckResult[]>;
}

// ---- semver ranges (no dependency; only the forms the design documents) ---------------------------------

type V = [number, number, number];

interface Partial3 {
  v: V;
  /** How many of major, minor, patch were written (0 for `*`). */
  n: number;
}

function parsePartial(s: string): Partial3 {
  const t = s.trim().replace(/^v/i, "");
  if (t === "" || t === "*" || /^x$/i.test(t)) return { v: [0, 0, 0], n: 0 };
  const m = /^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:[-+][0-9A-Za-z.+-]*)?$/.exec(t);
  if (!m) throw new Error(`"${s}" is not a version`);
  const parts: number[] = [];
  for (const g of [m[1], m[2], m[3]]) {
    if (g === undefined || /^[xX*]$/.test(g)) break;
    parts.push(Number(g));
  }
  return { v: [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0], n: parts.length };
}

const cmp = (a: V, b: V) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/** The smallest version above everything the partial covers: bump(0.2) = 0.3.0, bump(1) = 2.0.0. */
function bump(p: Partial3, at = p.n - 1): V {
  const v: V = [...p.v];
  if (p.n === 0) return [Infinity, 0, 0];
  v[at] += 1;
  for (let i = at + 1; i < 3; i++) v[i] = 0;
  return v;
}

function comparator(token: string, version: V): boolean {
  const m = /^(>=|<=|>|<|=|\^|~)?\s*(.*)$/.exec(token)!;
  const op = m[1] ?? "=";
  const p = parsePartial(m[2]);
  switch (op) {
    case ">=":
      return cmp(version, p.v) >= 0;
    case ">":
      return p.n === 3 ? cmp(version, p.v) > 0 : cmp(version, bump(p)) >= 0;
    case "<=":
      return p.n === 3 ? cmp(version, p.v) <= 0 : cmp(version, bump(p)) < 0;
    case "<":
      return cmp(version, p.v) < 0;
    case "^": {
      // The first non-zero written part is the one that may not change; all zeros bump the last written part.
      const at = [0, 1, 2].slice(0, Math.max(p.n, 1)).findIndex((i) => p.v[i] !== 0);
      return cmp(version, p.v) >= 0 && cmp(version, bump(p, at === -1 ? Math.max(p.n, 1) - 1 : at)) < 0;
    }
    case "~":
      return cmp(version, p.v) >= 0 && cmp(version, bump(p, p.n >= 2 ? 1 : 0)) < 0;
    default:
      return p.n === 0 || (cmp(version, p.v) >= 0 && cmp(version, bump(p)) < 0);
  }
}

/** True when `version` satisfies `range`. Throws an Error with the offending token for a range it cannot read. */
export function satisfies(version: string, range: string): boolean {
  const v = parsePartial(version);
  if (v.n === 0) throw new Error(`"${version}" is not a version`);
  const alternatives = range.split("||");
  return alternatives.some((alt) => {
    // "> = 0.2" is not supported; operators are glued to their version, as in npm.
    const tokens = alt.trim().split(/\s+/).filter(Boolean);
    return tokens.every((t) => comparator(t, v.v));
  });
}

// ---- helpers -------------------------------------------------------------------------------------------

const labelled = (id: string, label: string) => (label.startsWith(`[${id}]`) ? label : `[${id}] ${label}`);

export function makeHelpers(id: PackId, ctx: PackCtx): PluginHelpers {
  const sandbox = () => {
    const s = ctx.sandbox;
    if (!s || ctx.sandboxEnabled === false) throw new Error("the sandbox is not available (--no-sandbox), so file observation helpers cannot be used; return a check with verdict na instead");
    return s;
  };
  return {
    token: () => `sm-${randomBytes(6).toString("hex")}`,
    snapshot: async (labels) => sandbox().fs.snapshot(labels),
    diff: async (before, after) => {
      const fs = sandbox().fs;
      return after ? fs.diff(before, after) : fs.diffSince(before);
    },
    listener: {
      url: (path) => {
        if (!ctx.sandbox) throw new Error("the loopback listener is not available");
        return `${ctx.sandbox.listener.url}${path ?? ""}`;
      },
      expect: (token) => ctx.sandbox?.listener.expect(token) ?? [],
    },
    // Narrowed views: a plugin can read what the stub and the log saw, never switch the stub's mode or close anything.
    ...(ctx.upstream
      ? (() => {
          const u = ctx.upstream;
          return { upstream: { url: u.url, mark: () => u.mark(), requests: (since?: number) => u.requests(since), find: (needle: string, since?: number) => u.find(needle, since), waitFor: (needle: string, timeoutMs: number, since?: number) => u.waitFor(needle, timeoutMs, since) } };
        })()
      : {}),
    ...(ctx.serverLog
      ? (() => {
          const l = ctx.serverLog;
          return { serverLog: { mark: () => l.mark(), since: (mark: number) => l.since(mark), find: (needle: string, since?: number) => l.find(needle, since) } };
        })()
      : {}),
    ...(ctx.identity ? { openAs: (who: Parameters<IdentityAccess["openAs"]>[0]) => ctx.identity!.openAs(who) } : {}),
    inSandbox(path) {
      const s = ctx.sandbox;
      if (!s || ctx.sandboxEnabled === false) return false;
      const fold = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
      const rel = relative(fold(resolve(s.dir)), fold(resolve(path)));
      return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel) && !rel.split(sep).includes(".."));
    },
    done: (meta, verdict, summary, evidence) => ({ ...meta, pack: id, label: labelled(id, meta.label), verdict, summary, evidence }),
  };
}

// ---- loader --------------------------------------------------------------------------------------------

const ID = /^plugin:[A-Za-z0-9][A-Za-z0-9._-]*$/;
const isPath = (m: string) => m.startsWith(".") || isAbsolute(m) || /^[A-Za-z]:[\\/]/.test(m) || m.startsWith("file:");

export interface LoadOptions {
  /** The running sealmark version, checked against each plugin's `sealmark` range. */
  sealmarkVersion: string;
  /** Directory that relative module paths resolve against: the config file's directory (default: the working directory). */
  baseDir?: string;
  /** Check ids that plugins may not reuse (every built-in pack's ids). */
  reservedCheckIds: Iterable<string>;
}

function validate(mod: unknown, source: string): PluginModule {
  const bad = (why: string) => new ConfigError(`plugin "${source}": ${why}`);
  if (!mod || typeof mod !== "object") throw bad("the module has no default export that is an object");
  const m = mod as Partial<PluginModule>;
  if (typeof m.id !== "string" || !ID.test(m.id)) throw bad(`id must look like "plugin:name" (letters, digits, . _ -), got ${JSON.stringify(m.id)}`);
  if (typeof m.version !== "string" || !m.version) throw bad(`"${m.id}" must export a version string`);
  if (typeof m.sealmark !== "string" || !m.sealmark.trim()) throw bad(`"${m.id}" must export a sealmark version range such as ">=0.2 <0.3"`);
  for (const fn of ["describe", "applies", "run"] as const) if (typeof m[fn] !== "function") throw bad(`"${m.id}" must export ${fn}()`);
  return m as PluginModule;
}

/** Wrap a validated module as an ordinary Pack: labels, id checks and helpers are applied here, not trusted to the plugin. */
export function wrapPlugin(mod: PluginModule, options: Record<string, unknown>, reserved: ReadonlySet<string>): Pack {
  const id = mod.id;
  const plug = (ctx: PackCtx): PluginCtx => ({ ...ctx, pack: id, helpers: makeHelpers(id, ctx), options });
  return {
    id,
    describe: () => mod.describe().map((d) => ({ ...d, pack: id, label: labelled(id, d.label) })),
    applies: (ctx) => mod.applies(plug(ctx)),
    async run(ctx) {
      const results = await mod.run(plug(ctx));
      if (!Array.isArray(results)) throw new Error(`${id} returned ${typeof results} instead of a list of checks`);
      const seen = new Set<string>();
      return results.map((c) => {
        if (c.pack !== id) throw new Error(`${id} returned check "${c.id}" for pack "${String(c.pack)}"; a plugin may only report its own pack`);
        if (reserved.has(c.id)) throw new Error(`${id} returned check id "${c.id}", which belongs to a built-in pack`);
        if (seen.has(c.id)) throw new Error(`${id} returned check id "${c.id}" twice`);
        seen.add(c.id);
        return { ...c, label: labelled(id, c.label) };
      });
    },
  };
}

/**
 * Import every declared plugin. Discovery is explicit only. Anything wrong (module missing, wrong shape, version range not
 * satisfied, check ids that collide with built-ins) is a ConfigError, so the run exits 2 before touching the server.
 */
export async function loadPlugins(decls: PluginSpec[], o: LoadOptions): Promise<Pack[]> {
  const reserved = new Set(o.reservedCheckIds);
  const packs: Pack[] = [];
  const ids = new Set<string>();
  for (const decl of decls) {
    let imported: { default?: unknown };
    try {
      const spec = isPath(decl.module) ? (decl.module.startsWith("file:") ? decl.module : pathToFileURL(resolve(o.baseDir ?? process.cwd(), decl.module)).href) : decl.module;
      imported = (await import(spec)) as { default?: unknown };
    } catch (e) {
      throw new ConfigError(`plugin "${decl.module}" could not be loaded: ${(e as Error).message}`);
    }
    const mod = validate(imported.default, decl.module);
    let ok: boolean;
    try {
      ok = satisfies(o.sealmarkVersion, mod.sealmark);
    } catch (e) {
      throw new ConfigError(`plugin "${mod.id}": cannot read its sealmark range ${JSON.stringify(mod.sealmark)} (${(e as Error).message})`);
    }
    if (!ok) throw new ConfigError(`plugin "${mod.id}" ${mod.version} requires sealmark ${mod.sealmark}, but this is sealmark ${o.sealmarkVersion}.`);
    if (ids.has(mod.id)) throw new ConfigError(`plugin id "${mod.id}" is declared twice.`);
    ids.add(mod.id);
    for (const d of mod.describe()) {
      if (reserved.has(d.id)) throw new ConfigError(`plugin "${mod.id}" declares check id "${d.id}", which belongs to a built-in pack.`);
    }
    packs.push(wrapPlugin(mod, decl.options ?? {}, reserved));
  }
  return packs;
}
