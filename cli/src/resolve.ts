// Which package version did the launcher actually run? File reads only: this never spawns a process,
// never touches the network, and never writes anything. It looks into the npx and uv caches.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";

export interface ResolvedPackage {
  name: string;
  version?: string;
  /** `... (ambiguous)`: the cache holds several versions of the package and nothing says which one ran; `version` is then absent. */
  source: "npx-cache" | "uv-cache" | "npx-cache (ambiguous)" | "uv-cache (ambiguous)" | "not found";
  /** Every distinct version the cache holds (sorted, oldest first), set only when it is ambiguous. */
  candidates?: string[];
  /** The spec named one exact version, so that version is what the launcher ran: nothing about it is a guess. */
  pinned?: true;
  /** Resolved dependency versions (npx: declared dependencies with the version found beside the package; uv: every *.dist-info). */
  dependencies?: Record<string, string>;
  /** Requires-Dist lines of the package (uv only). */
  requires?: string[];
}

export interface ResolveOptions {
  /** Directories to scan instead of the real caches (tests). */
  roots?: { npx?: string[]; uv?: string[] };
  platform?: NodeJS.Platform;
  env?: Record<string, string | undefined>;
  /** Take this version among several candidates (the run knows which one the server announced). */
  pick?: string;
}

/** `v1.2.3` and `1.2.3` are one version; the comparison is case-insensitive. */
export const normVersion =(v: string): string => v.trim().replace(/^v(?=\d)/i, "").toLowerCase();

/** A `serverInfo.version` that looks like a package version (`1.2`, `v0.9.1`, `2.0.0-rc1`), not a date, a hash or a word. */
export const PACKAGE_VERSION = /^v?\d+(\.\d+)+/;

/**
 * True when the version a server announced is the one of the MCP SDK it was built on (a server that never sets its own version announces
 * the SDK's), which says nothing about which build of the package ran.
 */
export function isSdkVersion(pkg: Pick<ResolvedPackage, "dependencies">, announced: string): boolean {
  const SDK = new Set(["@modelcontextprotocol/sdk", "mcp", "fastmcp", "modelcontextprotocol"]);
  return Object.entries(pkg.dependencies ?? {}).some(([name, v]) => SDK.has(normName(name)) && normVersion(v) === normVersion(announced));
}

export interface VersionFacts {
  pkg?: ResolvedPackage;
  /** What the server announced in initialize (may be empty or absent). */
  serverInfoVersion?: string;
  /** The configured version label; "0.0.0" means "not set". */
  configVersion: string;
}

/**
 * The version warnings of a run, and the version the report header shows. Pure: the facts come from the run.
 *  - several versions in the cache and none named: the one case where "pin the version" is advice that helps;
 *  - one cached version that the server's own announcement differs from: the two say different things (a server that never sets its own
 *    version announces its SDK's), which is not a reason to pin anything;
 *  - serverInfo.version against the configured version: not said when the resolved package version IS the configured one;
 *  - no configured version and an empty announcement: the header shows the resolved package version, with a note.
 */
export function versionWarnings(f: VersionFacts): { warnings: string[]; headerVersion: string; note?: string } {
  const { pkg, configVersion } = f;
  const announced = f.serverInfoVersion?.trim() ? f.serverInfoVersion : undefined;
  const warnings: string[] = [];
  if (pkg?.candidates && !pkg.version) {
    const cache = pkg.source.startsWith("uv") ? "uv" : "npx";
    warnings.push(`resolved package ${pkg.name} unknown (several versions in the ${cache} cache: ${pkg.candidates.join(", ")}; ${announced ? `the server announced ${announced}` : "the server announced no version"}; pin the version)`);
  } else if (pkg?.version && !pkg.pinned && announced && PACKAGE_VERSION.test(announced) && normVersion(announced) !== normVersion(pkg.version) && !isSdkVersion(pkg, announced)) {
    warnings.push(`the cache holds one version (${pkg.version}); the server announces its own version string (${announced})`);
  }
  const resolvedIsConfigured = pkg?.version !== undefined && normVersion(pkg.version) === normVersion(configVersion);
  if (announced && configVersion !== "0.0.0" && announced !== configVersion && !resolvedIsConfigured) {
    warnings.push(`serverInfo.version ${announced} differs from config version ${configVersion}${pkg?.version ? ` (resolved package: ${pkg.name} ${pkg.version})` : ""}`);
  }
  if (configVersion !== "0.0.0") return { warnings, headerVersion: configVersion };
  if (announced) return { warnings, headerVersion: announced };
  if (pkg?.version) return { warnings, headerVersion: pkg.version, note: `the server announced no version, so the resolved package version (${pkg.version}) is shown` };
  return { warnings, headerVersion: configVersion };
}

/** Oldest first; numeric segments compare as numbers, the rest as text. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/);
  const pb = b.split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "";
    const y = pb[i] ?? "";
    if (x === y) continue;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) - Number(y);
    return x < y ? -1 : 1;
  }
  return 0;
}

/** The cache entries narrowed to the one version the caller wants (`pick`) or the one an exact pin names. */
function narrow<T extends { version?: string }>(found: T[], pin: string | undefined, pick: string | undefined): T[] {
  const want = pick ?? pin;
  if (want === undefined) return found;
  return found.filter((f) => f.version !== undefined && normVersion(f.version) === normVersion(want));
}

const distinctVersions = (found: { version?: string }[]): string[] =>
  [...new Set(found.map((f) => f.version).filter((v): v is string => v !== undefined))].sort(compareVersions);

const readText = (p: string): string | undefined => {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return undefined;
  }
};
const readJson = (p: string): Record<string, unknown> | undefined => {
  const t = readText(p);
  if (t === undefined) return undefined;
  try {
    return JSON.parse(t) as Record<string, unknown>;
  } catch {
    return undefined;
  }
};
const list = (p: string): string[] => {
  try {
    return readdirSync(p);
  } catch {
    return [];
  }
};
const mtime = (p: string): number => {
  try {
    return statSync(p).mtimeMs;
  } catch {
    return 0;
  }
};

const stripExe = (c: string): string => basename(c.replace(/\\/g, "/")).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, "");
const normName = (n: string): string => n.toLowerCase().replace(/[-_.]+/g, "-");

type Launch = { kind: "npx" | "uvx"; pkg: string; spec?: string };

/** npx flags that take a value in the next argument. */
const NPX_VALUE_FLAGS = new Set(["-p", "--package", "-c", "--call", "--cache", "--prefix", "--registry", "--userconfig", "--node-options"]);
const UVX_VALUE_FLAGS = new Set(["--from", "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index", "--default-index", "--index-url", "--extra-index-url", "--find-links", "--constraints", "--override", "--env-file", "--directory", "--project", "--config-file", "--cache-dir", "--resolution", "--prerelease", "--index-strategy", "--exclude-newer", "--refresh-package", "--reinstall-package", "--upgrade-package", "--with-requirements"]);

/** `pkg@1.2.3`, `@scope/pkg@latest` -> name and spec. */
function splitNpmSpec(s: string): { name: string; spec?: string } {
  const at = s.lastIndexOf("@");
  if (at > 0) return { name: s.slice(0, at), spec: s.slice(at + 1) };
  return { name: s };
}

function parseLaunch(command: string, args: string[]): Launch | undefined {
  let cmd = stripExe(command);
  let a = args;
  // cmd /c npx ... and powershell wrappers
  if ((cmd === "cmd" || cmd === "cmd.exe") && /^\/[ck]$/i.test(a[0] ?? "") && a[1]) {
    cmd = stripExe(a[1]);
    a = a.slice(2);
  }
  if (cmd === "uv" && a[0] === "tool" && a[1] === "run") {
    cmd = "uvx";
    a = a.slice(2);
  }
  if (cmd === "npx") {
    let pkg: string | undefined;
    for (let i = 0; i < a.length; i++) {
      const x = a[i]!;
      if (x === "--") {
        pkg ??= a[i + 1];
        break;
      }
      if (x.startsWith("--package=")) {
        pkg ??= x.slice("--package=".length);
        continue;
      }
      if (x === "-p" || x === "--package") {
        pkg ??= a[i + 1];
        i++;
        continue;
      }
      if (NPX_VALUE_FLAGS.has(x)) {
        i++;
        continue;
      }
      if (x.startsWith("-")) continue;
      pkg ??= x;
      break;
    }
    if (!pkg) return undefined;
    const { name, spec } = splitNpmSpec(pkg);
    return { kind: "npx", pkg: name, spec };
  }
  if (cmd === "uvx") {
    let from: string | undefined;
    let first: string | undefined;
    for (let i = 0; i < a.length; i++) {
      const x = a[i]!;
      if (x.startsWith("--from=")) {
        from = x.slice("--from=".length);
        continue;
      }
      if (x === "--from") {
        from = a[i + 1];
        i++;
        continue;
      }
      if (UVX_VALUE_FLAGS.has(x)) {
        i++;
        continue;
      }
      if (x.startsWith("-")) continue;
      first = x;
      break;
    }
    const raw = from ?? first;
    if (!raw) return undefined;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(raw);
    if (!m) return undefined;
    return { kind: "uvx", pkg: m[1]!, spec: m[2] || undefined };
  }
  return undefined;
}

function npxCaches(o: ResolveOptions): string[] {
  if (o.roots?.npx) return o.roots.npx;
  const env = o.env ?? process.env;
  const win = (o.platform ?? process.platform) === "win32";
  const base = env.npm_config_cache ?? (win ? (env.LOCALAPPDATA ? join(env.LOCALAPPDATA, "npm-cache") : undefined) : join(homedir(), ".npm"));
  return base ? [join(base, "_npx")] : [];
}

function uvCaches(o: ResolveOptions): string[] {
  if (o.roots?.uv) return o.roots.uv;
  const env = o.env ?? process.env;
  const win = (o.platform ?? process.platform) === "win32";
  const base = env.UV_CACHE_DIR ?? (win ? (env.LOCALAPPDATA ? join(env.LOCALAPPDATA, "uv", "cache") : undefined) : join(env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "uv"));
  // environments-v2 holds the environments uvx built; the current uv names them by hash and keeps the unpacked wheels
  // (the package's dist-info among them) in archive-v0/<hash>/. Both are searched.
  return base ? [join(base, "environments-v2"), join(base, "archive-v0")] : [];
}

function resolveNpx(l: Launch, o: ResolveOptions): ResolvedPackage {
  const found: { dir: string; nm: string; mtime: number; version?: string }[] = [];
  for (const root of npxCaches(o)) {
    for (const h of list(root)) {
      const nm = join(root, h, "node_modules");
      const dir = join(nm, ...l.pkg.split("/"));
      const pj = readJson(join(dir, "package.json"));
      if (!pj) continue;
      found.push({ dir, nm, mtime: mtime(join(dir, "package.json")), version: typeof pj.version === "string" ? pj.version : undefined });
    }
  }
  if (!found.length) return { name: l.pkg, source: "not found" };
  // An exact version in the spec narrows the choice. Without one, the newest entry is NOT taken to be the one that ran (it is only the
  // one unpacked last): one distinct version is that version, several are reported as candidates and no version is named.
  const pin = l.spec && /^\d+\.\d+\.\d+/.test(l.spec) ? l.spec : undefined;
  const pool = narrow(found, pin, o.pick);
  if (!pool.length) return { name: l.pkg, source: "not found" };
  const candidates = distinctVersions(pool);
  if (candidates.length > 1) return { name: l.pkg, source: "npx-cache (ambiguous)", candidates };
  pool.sort((a, b) => b.mtime - a.mtime);
  const best = pool[0]!;
  const pj = readJson(join(best.dir, "package.json"))!;
  const nm = best.nm;
  const dependencies: Record<string, string> = {};
  for (const dep of Object.keys((pj.dependencies as Record<string, string> | undefined) ?? {}).slice(0, 200)) {
    const v = readJson(join(nm, ...dep.split("/"), "package.json"))?.version;
    if (typeof v === "string") dependencies[dep] = v;
  }
  return { name: l.pkg, version: best.version, source: "npx-cache", ...(pin ? { pinned: true } : {}), ...(Object.keys(dependencies).length ? { dependencies } : {}) };
}

/** Every place under one hash-named uv cache directory where an installed distribution's `*.dist-info` can sit. */
function uvSites(dir: string): string[] {
  const sites = [dir, join(dir, "Lib", "site-packages")];
  for (const d of list(join(dir, "lib"))) if (d.startsWith("python")) sites.push(join(dir, "lib", d, "site-packages"));
  return sites;
}

/** `pkg==1.2.3` and `pkg@1.2.3` pin one version; a range or `latest` does not narrow anything. */
function uvPinned(spec: string | undefined): string | undefined {
  const m = spec ? /^(?:==\s*|@)(\d[^\s,;]*)$/.exec(spec.trim()) : undefined;
  return m?.[1];
}

function resolveUv(l: Launch, o: ResolveOptions): ResolvedPackage {
  const want = normName(l.pkg);
  const found: { site: string; dist: string; mtime: number; env: boolean }[] = [];
  // Every hash-named directory is a candidate: the name says nothing about the package. readdir and stat follow the
  // symlink an environment may hold into archive-v0, so a linked distribution is found the same way as a copied one.
  for (const [i, root] of uvCaches(o).entries()) {
    for (const entry of list(root)) {
      for (const site of uvSites(join(root, entry))) {
        const dist = list(site).find((d) => d.endsWith(".dist-info") && normName(d.replace(/-[^-]*\.dist-info$/, "")) === want);
        if (dist) found.push({ site, dist, mtime: mtime(join(site, dist)), env: i === 0 });
      }
    }
  }
  if (!found.length) return { name: l.pkg, source: "not found" };
  const versionOf = (f: { site: string; dist: string }) => /^Version:\s*(\S+)/m.exec(readText(join(f.site, f.dist, "METADATA")) ?? "")?.[1];
  // A pinned version narrows the choice, as for npx; without one several versions are candidates and none is named (the newest entry
  // is only the one unpacked last). Among entries of one version, an environment (which carries the whole dependency set) wins a tie
  // with a bare unpacked wheel.
  const pool = narrow(found.map((f) => ({ ...f, version: versionOf(f) })), uvPinned(l.spec), o.pick);
  if (!pool.length) return { name: l.pkg, source: "not found" };
  const candidates = distinctVersions(pool);
  if (candidates.length > 1) return { name: l.pkg, source: "uv-cache (ambiguous)", candidates };
  pool.sort((a, b) => b.mtime - a.mtime || Number(b.env) - Number(a.env));
  const best = pool[0]!;
  const meta = readText(join(best.site, best.dist, "METADATA")) ?? "";
  const version = /^Version:\s*(\S+)/m.exec(meta)?.[1];
  const requires = [...meta.matchAll(/^Requires-Dist:\s*(.+)$/gm)].map((m) => m[1]!.trim());
  const dependencies: Record<string, string> = {};
  for (const d of list(best.site)) {
    const m = /^(.+)-([^-]+)\.dist-info$/.exec(d);
    if (m) dependencies[m[1]!] = m[2]!;
  }
  return { name: l.pkg, version, source: "uv-cache", ...(uvPinned(l.spec) ? { pinned: true } : {}), dependencies, ...(requires.length ? { requires } : {}) };
}

/**
 * Resolve the package a launcher command runs, from the on-disk caches. Returns undefined when the command is
 * not `npx <pkg>` or `uvx <pkg>` (a direct `node server.js` has no package to look up).
 */
export function resolvePackage(command: string, args: string[], opts: ResolveOptions = {}): ResolvedPackage | undefined {
  const l = parseLaunch(command, args);
  if (!l) return undefined;
  return l.kind === "npx" ? resolveNpx(l, opts) : resolveUv(l, opts);
}
