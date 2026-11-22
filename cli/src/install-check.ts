/**
 * `sealmark install-check <server>`: before installing an MCP server, read the grade sealmark.dev's public fleet gave it and the
 * client config that starts the version it graded. Reads the public results data (https://sealmark.dev/data/v1/lookup.json,
 * then /data/v1/servers/<id>.json for each server the name matches); starts nothing, grades nothing, writes nothing, and sends
 * nothing but those GETs.
 *
 * The rules come from the site so both give one answer (sealmark-site web/lib/lookup.mjs, web/lib/install-config.mjs, and the
 * coverage and re-test sentences of web/lib/results-copy.mjs and web/lib/retest.mjs):
 * - Lookup keys: `npm:<name>`, `pypi:<name>`, `github:<owner>/<repo>`, `id:<id>`, normalised the same way.
 * - Install config: only for a stdio server whose tested start command is a plain npx or uvx line that pins the graded version,
 *   with run placeholders turned into values the reader replaces. The site withholds the start command while a security finding
 *   is reported privately (`launch: null`), so there is no config then either. This command is stricter in one way: a word with a
 *   character outside printable ASCII gives no config, so nothing copied from a terminal can hide a character.
 *
 * Everything the data says is server-influenced text (names, reasons, start commands) and goes through `inert` before it is
 * printed. Unreachable or unreadable data is a failure (exit 4) with no grade shown: never a guess.
 */
import { SITE_ORIGIN } from "./badge-snippet.js";
import { inert, inertDeep, MAX_REPORT_FIELD } from "./report/sanitize.js";

export const INSTALL_CHECK_FORMAT = "sealmark.install-check/1";
export const DATA_URL = `${SITE_ORIGIN}/data/v1`;
export const TIMEOUT_MS = 10_000;
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_LISTED = 10;

// ---------------------------------------------------------------------------------------------------------
// lookup keys (same rules as sealmark-site web/lib/lookup.mjs)
// ---------------------------------------------------------------------------------------------------------

const NPM = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i;
const OWNER = /^[a-z0-9](?:[a-z0-9-]{0,38})$/i;
const REPO = /^[a-z0-9._-]{1,100}$/i;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** `npm:<name>`: the scope stays, a version or tag after the name is dropped, lowercased. */
export function npmKey(input: string): string | null {
  const m = input.trim().match(/^(@[^/@\s]+\/[^/@\s]+|[^/@\s]+)(?:@[^\s]*)?$/);
  if (!m) return null;
  const name = m[1]!.toLowerCase();
  return name.length <= 214 && NPM.test(name) ? `npm:${name}` : null;
}

/** `pypi:<name>`: PEP 503 (lowercase, runs of `-`, `_` and `.` as one `-`), extras and version specifiers dropped. */
export function pypiKey(input: string): string | null {
  const name = input.trim().split(/[\s[;=<>!~@]/)[0];
  return name && PYPI.test(name) ? `pypi:${name.replace(/[-_.]+/g, "-").toLowerCase()}` : null;
}

/** `github:<owner>/<repo>`, lowercased, from `owner/repo` or a common GitHub URL form (https, git+https, ssh, git@github.com:). */
export function githubKey(input: string): string | null {
  const s = input.trim().replace(/^git\+/i, "");
  const m = s.match(/^(?:(?:https?|ssh|git):\/\/)?(?:git@)?(?:www\.)?github\.com[/:]([^/\s]+)\/([^/\s#?]+)/i) ?? s.match(/^([^/\s:@]+)\/([^/\s#?:@]+)$/);
  if (!m) return null;
  const owner = m[1]!;
  const repo = m[2]!.replace(/\.git$/i, "");
  if (!OWNER.test(owner) || !REPO.test(repo) || repo === "." || repo === "..") return null;
  return `github:${owner.toLowerCase()}/${repo.toLowerCase()}`;
}

/** `id:<id>`, the last part of the results page address, as it is. */
export function idKey(input: string): string | null {
  return ID.test(input.trim()) ? `id:${input.trim()}` : null;
}

/**
 * The keys to try for what someone typed, most specific first: a sealmark.dev results URL, a prefixed key, an npmjs.com, pypi.org
 * or GitHub URL, a scoped npm name, `owner/repo`, or a bare name (an npm name, a PyPI name or an id). The results URL is this
 * command's addition; the rest is the site's order.
 */
export function lookupKeys(input: string): string[] {
  const s = input.trim();
  if (!s) return [];
  const page = s.match(/^(?:https?:\/\/)?(?:www\.)?sealmark\.dev\/results\/([^/?#\s]+)\/?(?:[?#].*)?$/i);
  if (page) return [idKey(page[1]!)].filter((k): k is string => k !== null);
  const pre = s.match(/^(npm|pypi|github|id):(.*)$/i);
  if (pre) {
    const kind = pre[1]!.toLowerCase();
    const k = kind === "npm" ? npmKey(pre[2]!) : kind === "pypi" ? pypiKey(pre[2]!) : kind === "github" ? githubKey(pre[2]!) : idKey(pre[2]!);
    return k ? [k] : [];
  }
  const keep = (ks: (string | null)[]) => ks.filter((k): k is string => k !== null);
  const npmUrl = s.match(/^(?:https?:\/\/)?(?:www\.)?npmjs\.(?:com|org)\/package\/(@[^/?#\s]+\/[^/?#\s]+|[^/?#@\s]+)/i);
  if (npmUrl) {
    let name = npmUrl[1]!;
    try {
      name = decodeURIComponent(name);
    } catch {
      return [];
    }
    return keep([npmKey(name)]);
  }
  const pypiUrl = s.match(/^(?:https?:\/\/)?(?:www\.)?pypi\.org\/project\/([^/?#\s]+)/i);
  if (pypiUrl) return keep([pypiKey(pypiUrl[1]!)]);
  if (/github\.com/i.test(s) || /^[^@][^/\s]*\/[^/\s]+$/.test(s)) return keep([githubKey(s)]);
  if (s.startsWith("@")) return keep([npmKey(s)]);
  return keep([npmKey(s), pypiKey(s), idKey(s)]);
}

/** The ids the first matching key names, and that key (none: not in the public results under that name). */
export function resolveLookup(index: LookupIndex, keys: readonly string[]): { key: string | null; ids: string[] } {
  for (const k of keys) {
    const ids = index.keys.get(k);
    if (ids && ids.length) return { key: k, ids };
  }
  return { key: null, ids: [] };
}

// ---------------------------------------------------------------------------------------------------------
// install config (same rules as sealmark-site web/lib/install-config.mjs)
// ---------------------------------------------------------------------------------------------------------

/** What each run placeholder becomes in a reader's config, and what to put there (the results page's words). */
export const FILL: Record<string, { value: string; words: string }> = {
  "{dsn}": { value: "postgresql://USER:PASSWORD@HOST:5432/DATABASE", words: "your Postgres connection string" },
  "{sandbox}": { value: "/path/to/folder", words: "a folder the server may use" },
  "{dir}": { value: "/path/to/folder", words: "a folder the server may use" },
  "{sandbox_home}": { value: "/path/to/home", words: "a home folder for the server" },
  "{sqlite_path}": { value: "/path/to/database.sqlite", words: "your SQLite database file" },
  "{host}": { value: "HOST", words: "your database host" },
  "{port}": { value: "5432", words: "your database port" },
  "{user}": { value: "USER", words: "your database user" },
  "{password}": { value: "PASSWORD", words: "your database password" },
  "{database}": { value: "DATABASE", words: "your database name" },
  "{upstream}": { value: "UPSTREAM_URL", words: "the URL of the service the server talks to" },
};

const RUNNERS = new Set(["npx", "uvx"]);
const KEY = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const PLAIN = /^[A-Za-z0-9_\-.,/:=+]+$/;
const PRINTABLE = /^[\x20-\x7e]*$/;

/** Split a start command into words like a POSIX shell, or null when it holds anything a JSON args list cannot say. */
export function splitLaunch(s: string): string[] | null {
  const out: string[] = [];
  let cur = "";
  let has = false;
  let q = "";
  for (const ch of s) {
    if (q) {
      if (ch === q) q = "";
      else if (q === '"' && /[$`\\!]/.test(ch)) return null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      q = ch;
      has = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (has) out.push(cur);
      cur = "";
      has = false;
      continue;
    }
    if (/[$`\\|&;<>()*?~#!]/.test(ch)) return null;
    cur += ch;
    has = true;
  }
  if (q) return null;
  if (has) out.push(cur);
  return out;
}

/** A shell word for the `claude mcp add` line (the site's shellArg). */
function shellArg(s: string): string {
  if (!/["$`\\!]/.test(s)) return `"${s}"`;
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export interface InstallConfig {
  /** An `mcpServers` JSON document for a client that reads one. */
  json: string;
  /** The `claude mcp add` command. */
  claude: string;
  /** The placeholder values in it the reader replaces. */
  fill: { placeholder: string; value: string; words: string }[];
}

/** The install config for one server, or null when the site would show none (or a word is not printable ASCII). */
export function installConfig(x: { id: string; transport?: string | null; launch: string | null; versionTested: string }): InstallConfig | null {
  if (x.launch === null || x.transport !== "stdio" || !KEY.test(x.id)) return null;
  const words = splitLaunch(x.launch);
  if (!words || words.length < 2 || !RUNNERS.has(words[0]!)) return null;
  if (!x.versionTested || !words.some((w) => w.endsWith(`@${x.versionTested}`) || w.endsWith(`==${x.versionTested}`))) return null;
  const fill = new Map<string, InstallConfig["fill"][number]>();
  const args: string[] = [];
  for (const w of words) {
    if (!PRINTABLE.test(w)) return null;
    let bad = false;
    const v = w.replace(/\{[a-z_]+(?::[a-z]+)?\}/g, (p) => {
      const f = FILL[p];
      if (!f) {
        bad = true;
        return p;
      }
      fill.set(p, { placeholder: p, ...f });
      return f.value;
    });
    if (bad || /[{}]/.test(v)) return null;
    args.push(v);
  }
  const [command, ...rest] = args;
  const json = JSON.stringify({ mcpServers: { [x.id]: { command, args: rest } } }, null, 2);
  const claude = `claude mcp add ${x.id} -- ${args.map((a) => (PLAIN.test(a) ? a : shellArg(a))).join(" ")}`;
  return { json, claude, fill: [...fill.values()] };
}

// ---------------------------------------------------------------------------------------------------------
// the data
// ---------------------------------------------------------------------------------------------------------

export interface LookupIndex {
  updated: string | null;
  count: number | null;
  /** A Map, so a key such as `__proto__` from the data is only ever a key. */
  keys: Map<string, string[]>;
}

export interface ServerDoc {
  id: string;
  name: string;
  ecosystem: string | null;
  versionTested: string;
  testedAt: string;
  grade: string | null;
  provisional: boolean;
  areas: { id: string; letter: string; provisional: boolean }[];
  transport: string | null;
  launch: string | null;
  page: string;
  sealmark: { version: string | null; methodology: string | null };
  standard: boolean | null;
  noGradeReason: string | null;
  lastGrade: { grade: string | null; testedAt: string | null; version: string | null; failingSince: string | null } | null;
  /** How much of the server the grade covers, in the results page's words. */
  coverage: { kind: "no-tools" | "hygiene" | "low" | "covered" | "unknown"; text: string };
  /** The page's sentence for a failed re-test on or after the graded run, or null. */
  retest: string | null;
}

/** The data could not be read: offline, an HTTP error, or a shape this version does not know. No grade is shown. */
export class DataError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const DATE = /^\d{4}-\d{2}-\d{2}$/;

const originOf = (u: string): string | null => {
  try {
    return new URL(u).origin;
  } catch {
    return null;
  }
};
const count = (n: number, one: string, other: string) => `${n} ${n === 1 ? one : other}`;

/** The site's coverageNote (web/lib/results-copy.mjs): `deepGraded` is whether a test area other than core was graded. */
export function coverageNote(toolCount: number | null, cov: { level: string; toolsCalledValid: number; toolsTotal: number } | null, deepGraded: boolean): ServerDoc["coverage"] {
  const tools = toolCount ?? -1;
  const total = cov ? cov.toolsTotal : tools;
  if (total === 0 && tools === 0) {
    return { kind: "no-tools", text: "The server declared no tools under default settings. It probably needs configuration first, such as an API key or a setting, so there was nothing to call and this is not a grade for what the server does." };
  }
  if (!cov) return { kind: "unknown", text: "This result has no record of how many tools were called." };
  const n = cov.toolsCalledValid;
  const reached = n === 0 ? `None of the ${count(total, "tool", "tools")} could be called` : `Only ${n} of ${count(total, "tool", "tools")} could be called`;
  if (cov.level !== "covered" && !deepGraded) return { kind: "hygiene", text: `${reached} with default settings, so this grade covers the handshake and tool metadata only.` };
  if (cov.level !== "covered" && n === 0) return { kind: "low", text: `${reached} with default settings, so no test area saw a tool do its real work.` };
  if (cov.level !== "covered") return { kind: "low", text: `${reached} with default settings, so the deeper test areas cover only ${n === 1 ? "that tool" : "those tools"}.` };
  return { kind: "covered", text: `Tools reached with a valid call: ${n} of ${total}.` };
}

const RETEST: Record<string, string> = {
  "start-fail": "could not start the server",
  timeout: "timed out",
  "sealmark-crash": "stopped on a Sealmark error",
};
const START: Record<string, string> = {
  "needs-credentials": "could not start the server (it looks like it needs a credential)",
  "missing-runtime": "could not start the server (a runtime it needs is missing)",
  "dependency-resolution": "could not start the server (a dependency could not be installed)",
  "bad-launch": "could not start the server (the launch command did not work)",
  "initialize-timeout": "could not start the server (it did not answer in time)",
};
const own = (o: Record<string, string>, k: unknown): k is string => typeof k === "string" && Object.prototype.hasOwnProperty.call(o, k);

/** The site's retestNote (web/lib/retest.mjs): only a failed attempt on or after the graded run's date counts. */
export function retestNote(testedAt: string, a: Record<string, unknown> | null): string | null {
  if (!a || a.status !== "failed" || typeof a.date !== "string" || !DATE.test(a.date) || a.date < testedAt) return null;
  const what = a.kind === "start-fail" && own(START, a.startKind) ? START[a.startKind] : own(RETEST, a.kind) ? RETEST[a.kind] : "failed";
  return `The latest re-test, on ${a.date}, ${what}, so this grade is still the one from ${testedAt}.`;
}

export function parseLookup(v: unknown): LookupIndex {
  if (!isObj(v) || !isObj(v.keys)) throw new DataError("the lookup index has no keys");
  const keys = new Map<string, string[]>();
  for (const [k, ids] of Object.entries(v.keys)) {
    if (Array.isArray(ids)) keys.set(k, ids.filter((id): id is string => typeof id === "string" && ID.test(id)));
  }
  return { updated: str(v.updated), count: typeof v.count === "number" ? v.count : null, keys };
}

/** The page link is trusted only on sealmark.dev or the data's own origin; anything else is rebuilt from the id. */
function trustedPage(page: string | null, id: string, base: string): string {
  const ok = page !== null && /^https:\/\//.test(page) && [SITE_ORIGIN, originOf(base)].includes(originOf(page));
  return ok ? page : `${SITE_ORIGIN}/results/${encodeURIComponent(id)}/`;
}

export function parseServer(v: unknown, id: string, base: string = DATA_URL): ServerDoc {
  if (!isObj(v) || v.id !== id) throw new DataError(`the file for ${id} does not describe ${id}`);
  const versionTested = str(v.versionTested);
  const testedAt = str(v.testedAt);
  if (versionTested === null || testedAt === null || !DATE.test(testedAt)) throw new DataError(`the file for ${id} has no tested version or date`);
  if (v.grade !== null && typeof v.grade !== "string") throw new DataError(`the file for ${id} has a grade this version cannot read`);
  const areas = (Array.isArray(v.packDetails) ? v.packDetails : [])
    .filter((p): p is Record<string, unknown> => isObj(p) && p.status === "graded" && typeof p.id === "string" && typeof p.letter === "string")
    .map((p) => ({ id: p.id as string, letter: p.letter as string, provisional: p.provisional === true }));
  const sm = isObj(v.sealmark) ? v.sealmark : {};
  const ng = isObj(v.noGradeReason) ? str(v.noGradeReason.text) : null;
  const lg = isObj(v.lastGrade) ? v.lastGrade : null;
  const la = isObj(v.lastAttempt) ? v.lastAttempt : null;
  const page = str(v.page);
  const c = isObj(v.coverage) ? v.coverage : null;
  const cov = c && typeof c.level === "string" && typeof c.toolsCalledValid === "number" && typeof c.toolsTotal === "number" ? { level: c.level, toolsCalledValid: c.toolsCalledValid, toolsTotal: c.toolsTotal } : null;
  const toolCount = typeof v.toolCount === "number" ? v.toolCount : null;
  return {
    id,
    name: str(v.name) ?? id,
    ecosystem: str(v.ecosystem),
    versionTested,
    testedAt,
    grade: v.grade as string | null,
    provisional: v.provisional === true,
    areas,
    transport: str(v.transport),
    launch: str(v.launch),
    page: trustedPage(page, id, base),
    sealmark: { version: str(sm.version), methodology: str(sm.methodology) },
    standard: typeof v.standard === "boolean" ? v.standard : null,
    noGradeReason: ng,
    lastGrade: lg ? { grade: str(lg.grade), testedAt: str(lg.testedAt), version: str(lg.version), failingSince: str(lg.failingSince) } : null,
    coverage: coverageNote(toolCount, cov, areas.some((a) => a.id !== "core")),
    retest: retestNote(testedAt, la),
  };
}

/** One line of `<base>/servers.json`, the fields `sealmark mcp`'s find_server passes on. Every string is still unsanitised data. */
export interface ServerListing {
  id: string;
  name: string;
  ecosystem: string | null;
  versionTested: string | null;
  testedAt: string | null;
  grade: string | null;
  provisional: boolean;
  packs: Record<string, string>;
  page: string;
}

const MAX_LISTING_PACKS = 40;

/**
 * `<base>/servers.json`: the index of every graded server. Defensive like parseServer: a non-object or a missing `servers` array is
 * a DataError; an entry whose id is not a sealmark.dev id is skipped; only string fields are kept; the page link is trusted only on
 * sealmark.dev or the data's own origin, else rebuilt from the id; a repeated id keeps its first entry.
 */
export function parseServers(v: unknown, base: string = DATA_URL): { updated: string | null; count: number | null; servers: ServerListing[] } {
  if (!isObj(v) || !Array.isArray(v.servers)) throw new DataError("the server list has a shape this version does not know");
  const servers: ServerListing[] = [];
  const seen = new Set<string>();
  for (const e of v.servers) {
    if (!isObj(e) || typeof e.id !== "string" || !ID.test(e.id) || seen.has(e.id)) continue;
    seen.add(e.id);
    const page = str(e.page);
    const packs = isObj(e.packs) ? Object.entries(e.packs).filter((kv): kv is [string, string] => typeof kv[1] === "string").slice(0, MAX_LISTING_PACKS) : [];
    servers.push({
      id: e.id,
      name: str(e.name) ?? e.id,
      ecosystem: str(e.ecosystem),
      versionTested: str(e.versionTested),
      testedAt: str(e.testedAt),
      grade: str(e.grade),
      provisional: e.provisional === true,
      // fromEntries defines own properties, so a pack named `__proto__` is only ever a key.
      packs: Object.fromEntries(packs),
      page: trustedPage(page, e.id, base),
    });
  }
  return { updated: str(v.updated), count: typeof v.count === "number" ? v.count : null, servers };
}

export type Fetcher = (url: string, init: { signal: AbortSignal; headers: Record<string, string> }) => Promise<Response>;

export async function getJson(url: string, fetcher: Fetcher, timeoutMs: number): Promise<unknown> {
  const tooBig = () => new DataError(`${url} is larger than ${MAX_BYTES / 1024 / 1024} MiB`);
  let res: Response;
  try {
    res = await fetcher(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
  } catch (e) {
    const err = e as Error & { cause?: { code?: string; message?: string } };
    const why = err.name === "TimeoutError" ? `no answer in ${Math.round(timeoutMs / 1000)} s` : (err.cause?.code ?? err.cause?.message ?? err.message);
    throw new DataError(`could not reach ${url} (${why})`);
  }
  // A redirect to another origin would present someone else's data as this source's.
  if (res.url && originOf(res.url) !== originOf(url)) throw new DataError(`${url} redirected to another site (${originOf(res.url) ?? "unreadable address"})`);
  if (!res.ok) throw new DataError(`${url} answered HTTP ${res.status}`);
  if (Number(res.headers.get("content-length") ?? "0") > MAX_BYTES) throw tooBig();
  // Read at most MAX_BYTES, whatever the headers say (a chunked or compressed body has no length).
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    const reader = res.body?.getReader();
    for (;;) {
      if (!reader) break;
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) {
        await reader.cancel().catch(() => {});
        throw tooBig();
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof DataError) throw e;
    throw new DataError(`could not read ${url} (${(e as Error).name === "TimeoutError" ? `no answer in ${Math.round(timeoutMs / 1000)} s` : (e as Error).message})`);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new DataError(`${url} is not JSON`);
  }
}

/** `--data-url`: an http(s) base, without a trailing slash. */
export function dataBase(value: string | undefined): string {
  if (value === undefined) return DATA_URL;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new Error(`--data-url: "${inert(value, 200)}" is not a URL`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error(`--data-url takes an http or https URL, not ${inert(u.protocol, 20)}`);
  if (u.username || u.password) throw new Error("--data-url takes an address with no user name or password (a base URL, not credentials)");
  if (u.search || u.hash) throw new Error("--data-url takes a base address with no ? or # part");
  return u.href.replace(/\/+$/, "");
}

export interface InstallCheckResult {
  query: string;
  keys: string[];
  matchedKey: string | null;
  source: string;
  index: { updated: string | null; count: number | null };
  servers: (ServerDoc & { install: InstallConfig | null })[];
  /** More ids than were read (a key naming more than MAX_LISTED servers). */
  more: number;
}

/** Looks the input up and reads each server it names. Throws DataError when the data cannot be read. */
export async function installCheck(query: string, o: { base?: string; fetcher?: Fetcher; timeoutMs?: number } = {}): Promise<InstallCheckResult> {
  const base = o.base ?? DATA_URL;
  const fetcher = o.fetcher ?? (fetch as Fetcher);
  const timeoutMs = o.timeoutMs ?? TIMEOUT_MS;
  const keys = lookupKeys(query);
  const index = parseLookup(await getJson(`${base}/lookup.json`, fetcher, timeoutMs));
  const { key, ids } = resolveLookup(index, keys);
  const servers: InstallCheckResult["servers"] = [];
  for (const id of ids.slice(0, MAX_LISTED)) {
    const doc = parseServer(await getJson(`${base}/servers/${encodeURIComponent(id)}.json`, fetcher, timeoutMs), id, base);
    servers.push({ ...doc, install: installConfig(doc) });
  }
  return { query, keys, matchedKey: key, source: base, index: { updated: index.updated, count: index.count }, servers, more: Math.max(0, ids.length - MAX_LISTED) };
}

// ---------------------------------------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------------------------------------

const t = (v: unknown, max = 300) => inert(v, max);
const DAY = 86_400_000;

/** "today", "1 day ago", "12 days ago" (UTC dates), or "" for a date in the future or unreadable. */
export function age(date: string, now: number): string {
  const d = Math.floor((Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), new Date(now).getUTCDate()) - Date.parse(`${date}T00:00:00Z`)) / DAY);
  if (!Number.isFinite(d) || d < 0) return "";
  return d === 0 ? "today" : d === 1 ? "1 day ago" : `${d} days ago`;
}

function gradeLines(x: ServerDoc): string[] {
  const areas = x.areas.map((a) => `${t(a.id, 40)} ${t(a.letter, 4)}${a.provisional ? " (provisional)" : ""}`).join(", ");
  const out: string[] = [];
  if (x.lastGrade) {
    const lg = x.lastGrade;
    out.push(`Grade: none now. Re-tests have kept failing${lg.failingSince ? ` since ${t(lg.failingSince, 40)}` : ""}, so the last grade is withdrawn${lg.grade ? ` (it was ${t(lg.grade, 4)} for version ${t(lg.version ?? "?", 80)} on ${t(lg.testedAt ?? "?", 40)})` : ""}.`);
    if (x.noGradeReason) out.push(t(x.noGradeReason, 600));
    return out;
  }
  if (x.grade !== null) out.push(`Grade: ${t(x.grade, 4)}${x.provisional ? " (provisional)" : ""}, the lowest test-area grade`);
  else out.push(`Grade: none. ${x.noGradeReason ? t(x.noGradeReason, 600) : "No test area was graded."}`);
  if (areas) out.push(`Test areas: ${areas}`);
  // The no-tools sentence is the no-grade reason itself; every other coverage sentence qualifies the grade.
  if (!(x.coverage.kind === "no-tools" && x.grade === null && x.noGradeReason)) out.push(`Coverage: ${x.coverage.text}`);
  if (x.retest) out.push(x.retest);
  return out;
}

function testedLine(x: ServerDoc, now: number): string {
  const when = age(x.testedAt, now);
  const with_ = x.sealmark.version ? ` with Sealmark ${t(x.sealmark.version, 40)}${x.sealmark.methodology ? ` (methodology ${t(x.sealmark.methodology, 40)})` : ""}` : "";
  const settings = x.standard === null ? "" : x.standard ? ", standard settings" : ", custom settings";
  return `Tested: version ${t(x.versionTested, 80)} on ${x.testedAt}${when ? ` (${when})` : ""}${with_}${settings}`;
}

function installLines(x: ServerDoc & { install: InstallConfig | null }): string[] {
  const i = x.install;
  const which = x.lastGrade ? "the last version graded; re-tests of newer versions keep failing" : "the version graded";
  if (!i) return ["", "No install config: sealmark.dev gives one only for a stdio server whose tested start command is a plain npx or uvx line that pins the graded version. The results page has the details."];
  const out = ["", `Add it to an MCP client (this starts version ${t(x.versionTested, 80)}, ${which}):`, "", "  For a client that reads an mcpServers JSON file:", ...i.json.split("\n").map((l) => `    ${l}`), "", "  Claude Code:", `    ${i.claude}`];
  if (i.fill.length) {
    out.push("", "  The test run gave the server a throwaway database or folder. Replace these values with your own:");
    const seen = new Set<string>();
    for (const f of i.fill) {
      if (seen.has(f.value)) continue;
      seen.add(f.value);
      out.push(`    ${f.value}: ${f.words}`);
    }
  }
  out.push("", "  The test run used no API keys or other secrets. If the server needs some, its own documentation says how to pass them.");
  return out;
}

/** The text output. `now` is a clock for the "N days ago" note. */
export function renderInstallCheck(r: InstallCheckResult, now: number = Date.now()): string {
  if (!r.servers.length) {
    const where = r.index.count !== null ? ` (${r.index.count} graded servers${r.index.updated ? `, updated ${t(r.index.updated, 40)}` : ""})` : "";
    return [
      `"${t(r.query, 200)}" is not in sealmark.dev's public results${where}. Looked up: ${r.keys.map((k) => t(k, 240)).join(", ")}.`,
      "Not being listed does not prove a server was never graded: a repository is listed only where its results page links it, so also try the npm or PyPI package name.",
      "To grade it yourself: sealmark run --start \"<the command that starts it>\"",
      "",
    ].join("\n");
  }
  if (r.servers.length === 1 && r.more === 0) {
    const x = r.servers[0]!;
    return [`${t(x.name, 200)} (sealmark.dev id ${t(x.id, 128)}, matched as ${t(r.matchedKey ?? "", 240)})`, ...gradeLines(x), testedLine(x, now), `Results: ${t(x.page, 400)}`, ...installLines(x), ""].join("\n");
  }
  const out = [`"${t(r.query, 200)}" (matched as ${t(r.matchedKey ?? "", 240)}) names ${r.servers.length + r.more} graded servers:`];
  for (const x of r.servers) {
    const g = x.lastGrade ? "grade withdrawn" : x.grade !== null ? `grade ${t(x.grade, 4)}${x.provisional ? " (provisional)" : ""}${x.coverage.kind === "hygiene" ? " (handshake and tool metadata only)" : ""}` : "no grade";
    out.push("", `  ${t(x.name, 200)} (id ${t(x.id, 128)}): ${g}, version ${t(x.versionTested, 80)} tested ${x.testedAt}`, `    ${t(x.page, 400)}`);
  }
  if (r.more) out.push("", `  ...and ${r.more} more.`);
  out.push("", `For one server's install config: sealmark install-check id:<id>`, "");
  return out.join("\n");
}

/** The `--json` output: one `sealmark.install-check/1` object, every string made inert. */
export function installCheckJson(r: InstallCheckResult): string {
  // The install snippets are built only from printable-ASCII words (installConfig), so they keep their line breaks; the rest is data.
  const servers = r.servers.map(({ install, ...x }) => ({ ...inertDeep(x, MAX_REPORT_FIELD), install }));
  const { servers: _servers, ...rest } = r;
  return `${JSON.stringify({ format: INSTALL_CHECK_FORMAT, found: r.servers.length > 0, ...inertDeep(rest, MAX_REPORT_FIELD), servers }, null, 2)}\n`;
}
