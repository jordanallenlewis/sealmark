import { isAbsolute, relative, sep } from "node:path";
import type { RunResult } from "../types.js";

/**
 * Path and secret redaction for everything a report prints (addendum item 26, packs-design 6.7).
 *
 * Sandbox paths are rewritten to stable names so two runs of the same server produce the same report:
 * `<dir>\root\x` becomes `{sandbox}/x`, `<dir>\canary\x` becomes `{canary}/x`, `<dir>\home` becomes `{sandbox_home}`,
 * and whatever is left of `<dir>` becomes `{sandbox_dir}`. Servers on Windows echo both `\` and `/` forms, doubled
 * backslashes included, so all of them are matched, and so is the percent-encoded form a URL query value carries
 * (`…%2Fsealmark-<id>%2Fcanary%2Fsecret.txt` becomes `…%2F{canary}%2Fsecret.txt`). Secret literals (values under secret-looking names, anything read
 * from sealmark.local.yaml, a --pg password) become `<redacted>`. The harness listener's ephemeral port becomes
 * `{listener_port}` after any host spelling and the per-run random tokens (`sm-<hex>` and its relatives, `sm-who-<hex>`) become stable names such as `{token}`,
 * so two runs of the same server render the same verdicts and evidence; timestamps and durations still differ.
 *
 * With `--no-redact` (or when the sandbox was kept, so the user can find it) nothing is rewritten.
 */

export interface RedactOptions {
  /** false skips every rewrite. */
  redact?: boolean;
  /** Literal strings to scrub (4 characters or longer). */
  secrets?: readonly string[];
}

const SUBDIRS: { dir: string; name: string }[] = [
  { dir: "root-evil", name: "{sandbox_evil}" },
  { dir: "root", name: "{sandbox}" },
  { dir: "canary", name: "{canary}" },
  { dir: "home", name: "{sandbox_home}" },
  { dir: "tmp", name: "{sandbox_tmp}" },
  { dir: "bin", name: "{sandbox_bin}" },
];

const SEP = "[\\\\/]+";
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** A directory path as a regex that accepts either separator, doubled separators, and a `\\?\` prefix on Windows. */
function dirPattern(dir: string): string {
  const plain = dir.replace(/^[\\/]{2}\?[\\/]/, "");
  const parts = plain.split(/[\\/]+/).filter((p) => p !== "");
  const body = parts.map(escapeRe).join(SEP);
  if (/^[\\/]/.test(plain)) return `${SEP}${body}`;
  return `(?:[\\\\/]{2}\\?[\\\\/])?${body}`;
}
/** Characters that end a path token in prose or JSON. */
const TAIL = "(?:[\\\\/]+[^\\s\"'`<>|,;()\\[\\]{}]*)?";

/** An encoded separator (`%2F` or `%5C`, either case), repeated. */
const ESEP = "(?:%2[fF]|%5[cC])+";
/** The tail of an encoded path: it stays encoded, and an `&` ends it (the next query parameter). */
const ETAIL = `(?:${ESEP}[^\\s"'\`<>|,;()\\[\\]{}&]*)?`;
/** What may precede an encoded directory: not a path character, or an encoded separator, so `file%3A%2F%2F%2F<dir>` and `to=<dir>` match but `x<dir>` does not. */
const EBEFORE = "(?:(?<![A-Za-z0-9._~%-])|(?<=%2[fF])|(?<=%5[cC]))";

/** The directory with each part percent-encoded (encodeURIComponent) and the separators encoded too, as a regex; undefined for a root-only path. */
function encodedDirPattern(dir: string): string | undefined {
  const plain = dir.replace(/^[\\/]{2}\?[\\/]/, "");
  const parts = plain.split(/[\\/]+/).filter((p) => p !== "");
  if (!parts.length) return undefined;
  return parts.map((p) => escapeRe(encodeURIComponent(p))).join(ESEP);
}

/**
 * The parent directory, the harness prefix of the sandbox's own name (`sealmark-`) and any leading part of its random characters (an excerpt
 * cut inside the name), as a plain and a percent-encoded regex. Only a leading part of THIS directory's own characters matches, so another
 * directory with the same prefix and different letters is left alone. Undefined when the directory has no parent or its name has no `-` prefix.
 */
function cutPattern(dir: string): { plain: string; encoded?: string } | undefined {
  const plain = dir.replace(/^[\\/]{2}\?[\\/]/, "");
  const parts = plain.split(/[\\/]+/).filter((p) => p !== "");
  const name = parts.pop();
  const dash = name?.indexOf("-") ?? -1;
  if (!name || dash < 1 || !parts.length) return undefined;
  const prefix = name.slice(0, dash + 1);
  const rest = [...name.slice(dash + 1)];
  // `(?:a(?:b(?:c)?)?)?`: every leading part of the random characters, longest first.
  const leading = (esc: (c: string) => string) => rest.reduceRight((acc, c) => `(?:${esc(c)}${acc})?`, "");
  const lead = /^[\\/]/.test(plain) ? SEP : "(?:[\\\\/]{2}\\?[\\\\/])?";
  const body = parts.map(escapeRe).join(SEP);
  return {
    plain: `${lead}${body}${SEP}${escapeRe(prefix)}${leading(escapeRe)}`,
    encoded: `${parts.map((p) => escapeRe(encodeURIComponent(p))).join(ESEP)}${ESEP}${escapeRe(encodeURIComponent(prefix))}${leading((c) => escapeRe(encodeURIComponent(c)))}`,
  };
}

/** `makePathRewriter` for one spelling of the directory; `withEncoded` adds the percent-encoded rules (only once, for the spelling the harness created). */
function plainRewriter(dir: string, withEncoded: boolean): (s: string) => string {
  const flags = process.platform === "win32" ? "gi" : "g";
  const base = dirPattern(dir);
  const rules = SUBDIRS.map(({ dir: sub, name }) => ({ re: new RegExp(`${base}${SEP}${sub}(?![\\w-])(${TAIL})`, flags), name }));
  const rest = new RegExp(`${base}(?![\\w-])(${TAIL})`, flags);
  const tail = (t: string) => t.replace(/[\\/]+/g, "/");
  // The percent-encoded form is built once from the same directory. It has no leading separator of its own, so
  // `file%3A%2F%2F%2F<dir>%2Fcanary%2Fx` keeps its scheme slashes and reads `file%3A%2F%2F%2F{canary}%2Fx`.
  // (encodeURI of a path is the plain form unless a part has a space or a non-ASCII character; that part is encoded here too.)
  const enc = withEncoded ? encodedDirPattern(dir) : undefined;
  const encRules = enc
    ? [
        ...SUBDIRS.map(({ dir: sub, name }) => ({ re: new RegExp(`${EBEFORE}${enc}${ESEP}${sub}(?![\\w-])(${ETAIL})`, "gi"), name })),
        { re: new RegExp(`${EBEFORE}${enc}(?![\\w-])(${ETAIL})`, "gi"), name: "{sandbox_dir}" },
      ]
    : [];
  const encTail = (t: string) => t.replace(/(?:%2[fF]|%5[cC])+/g, "%2F");
  // A truncated echo: an excerpt cut inside the random part of the directory name (`<parent>/sealmark-ab`) still carries the user's
  // directory and the harness prefix. What is left of the name is only a few characters of the random suffix, so it is dropped.
  const cut = cutPattern(dir);
  const cutRule = cut ? new RegExp(`${cut.plain}(?![\\w-])(${TAIL})`, flags) : undefined;
  const cutEnc = withEncoded && cut?.encoded ? new RegExp(`${EBEFORE}${cut.encoded}(?![\\w-])(${ETAIL})`, "gi") : undefined;
  return (s) => {
    let out = s;
    for (const r of rules) out = out.replace(r.re, (_m, t: string) => `${r.name}${tail(t ?? "")}`);
    out = out.replace(rest, (_m, t: string) => `{sandbox_dir}${tail(t ?? "")}`);
    for (const r of encRules) out = out.replace(r.re, (_m, t: string) => `${r.name}${encTail(t ?? "")}`);
    if (cutRule) out = out.replace(cutRule, (_m, t: string) => `{sandbox_dir}${tail(t ?? "")}`);
    if (cutEnc) out = out.replace(cutEnc, (_m, t: string) => `{sandbox_dir}${encTail(t ?? "")}`);
    return out;
  };
}

export function makePathRewriter(dir: string | null | undefined): (s: string) => string {
  if (!dir) return (s) => s;
  const plain = plainRewriter(dir, true);
  // encodeURI keeps `/` but encodes the other characters (a space, a non-ASCII letter): the plain separators around encoded parts.
  const uri = encodeURI(dir) !== dir ? plainRewriter(encodeURI(dir), false) : undefined;
  return uri ? (s) => uri(plain(s)) : plain;
}

/**
 * The per-run random tokens the packs put in their probes, most specific shape first (`ann-sm-<hex>` before `sm-<hex>`).
 * Only the exact shapes the harness generates match, and never inside a longer word, so a program called `sm-canary` or a
 * server's own `sm-` prefix is left alone. A `sm-` token may follow `_` or `-` (a gopher path `_sm-<hex>`, a doubled
 * `sm-sm-<hex>`) or a percent-encoded separator (`%2Fsm-<hex>`), but never a letter or a digit.
 */
const AFTER = "(?![\\w-])";
/**
 * What may follow a token in a name the harness builds: the style suffix of a control file (`-abs`, `-rel`) or the index of a probe file
 * (`-3`), then an extension or any other non-word character (`w-ctl-sm-<hex>-abs.txt`, `w-sm-<hex>-3.txt`). Never a longer word.
 */
const AFTER_NAME = "(?:(?=-(?:abs|rel|\\d+)(?![\\w-]))|(?![\\w-]))";
const SM_BEFORE = "(?:(?<![A-Za-z0-9])|(?<=%[0-9A-Fa-f]{2}))";
const smRule = (body: string, to: string): [RegExp, string] => [new RegExp(`${SM_BEFORE}${body}${AFTER_NAME}`, "g"), to];
const TOKEN_RULES: [RegExp, string][] = [
  smRule("ann-sm-[0-9a-f]{12}", "ann-{token}"),
  smRule("sm-sm-[0-9a-f]{12}", "{token}"),
  smRule("sm-ctl-[0-9a-f]{8,12}", "{ctl}"),
  smRule("sm-who-[0-9a-f]{8}", "{who}"),
  smRule("sm-control-[0-9a-f]{16}", "{control}"),
  smRule("sm-(root|canary|evil|forged|fscanary|prefix)-[0-9a-f]{12,16}", "{token:$1}"),
  [/(?<![\w-])sm_s_[0-9a-f]{6}(?![\w-])/g, "{alias}"],
  [new RegExp(`(?<![\\w-])pwned-[0-9a-f]{12,16}${AFTER_NAME}`, "g"), "pwned-{token}"],
  [/(?<![\w-])(vac|att)-[0-9a-f]{6}(?![\w-])/g, "$1-{token}"],
  // The file a write through the dangling link creates in the canary directory (`dangling-<12 hex>.txt`) is named per run.
  [new RegExp(`(?<![\\w-])dangling-[0-9a-f]{12}${AFTER_NAME}`, "g"), "dangling-{token}"],
  smRule("sm-[0-9a-f]{12}", "{token}"),
  // Round 6: the identities and markers the harness mints for the upstream stub (a minted bearer is `sm-bearer-<a|b>-<12 hex>`).
  smRule("sm-bearer-a-[0-9a-f]{12}", "{bearer:a}"),
  smRule("sm-bearer-b-[0-9a-f]{12}", "{bearer:b}"),
  smRule("sm-row-[0-9a-f]{8}", "{row}"),
  smRule("sm-upstream-err-[0-9a-f]{8,16}", "{upstream_error}"),
  // Round 6 corpus names. sql-guard marks each statement with `sm_<8 hex>` (identifier), `'sm-<8 hex>'` (literal), `sm_ctl_<8 hex>` and
  // `outside_sm_<8 hex>`; the scope corpus builds `sm_control_<6 hex>` and names ending `_sm<6 hex>` (upper-cased by the case family).
  [/(?<![0-9A-Za-z])(sm_control_)[0-9a-f]{6}(?![0-9A-Za-z])/gi, "$1{token}"],
  [/(?<=_)(sm)[0-9a-f]{6}(?![0-9A-Za-z])/gi, "$1{token}"],
  [/(?<![0-9A-Za-z])(sm[-_](?:ctl_)?)[0-9a-f]{8}(?![0-9A-Za-z])/gi, "$1{token}"],
  // A commit id (40 hex digits) and an abbreviated range (`abc1234..def5678`) change with every fixture the harness builds.
  [/(?<![0-9A-Za-z])[0-9a-f]{7}\.\.[0-9a-f]{7}(?![0-9A-Za-z])/g, "{sha}..{sha}"],
  [/(?<![0-9A-Za-z])[0-9a-f]{40}(?![0-9A-Za-z])/g, "{sha}"],
  // A timestamp a server printed about a file or a call the harness made (a stat reply's `mtime`) is the time of this run. The run's own
  // `startedAt` is never passed through here (redactResult leaves it as it is).
  [/(?<![0-9])\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})(?![0-9A-Za-z])/g, "{time}"],
];

/**
 * Rewrites the listener port (when it is this run's) and the per-run tokens to stable names. The port follows a host in
 * any spelling the corpus uses (`127.0.0.1`, `127.1`, `0x7f000001`, `2130706433`, `0.0.0.0`, `[::1]`, `[::ffff:127.0.0.1]`,
 * `[::ffff:7f00:1]`, `localhost`, a name that resolves there): it is the run's own ephemeral number, so any `<host>:<port>`
 * is rewritten, and so is the percent-encoded `<host>%3A<port>` of a URL passed as a query value.
 */
export function makeRunNormaliser(ports: number | null | undefined | { listenerPort?: number | null; upstreamPort?: number | null }): (s: string) => string {
  const { listenerPort, upstreamPort } = typeof ports === "object" && ports !== null ? ports : { listenerPort: ports, upstreamPort: undefined };
  const portRule = (n: number | null | undefined, to: string): [RegExp, string][] =>
    n ? [[new RegExp(`(?<=[\\w\\]]):${n}(?!\\d)`, "g"), `:${to}`], [new RegExp(`(?<=[\\w\\]])(%3[aA])${n}(?!\\d)`, "g"), `$1${to}`]] : [];
  // The second ephemeral port of a run is the upstream stub's (round 6).
  const portRules = [...portRule(listenerPort, "{listener_port}"), ...portRule(upstreamPort, "{upstream_port}")];
  return (s) => {
    let out = s;
    for (const [re, to] of portRules) out = out.replace(re, to);
    for (const [re, to] of TOKEN_RULES) out = out.replace(re, to);
    return out;
  };
}

/** `127.0.0.1:<port>` as a markdown report prints it: the real port with `--no-redact` or a kept sandbox, `{listener_port}` otherwise. */
export function listenerLabel(r: RunResult, o: RedactOptions = {}): string | undefined {
  const port = r.sandbox?.listenerPort;
  if (!port) return undefined;
  return `127.0.0.1:${o.redact === false || r.sandbox?.kept ? port : "{listener_port}"}`;
}

/**
 * Words a secret-named variable may carry as its value (`AUTH_REQUIRED=true`, `TOKEN_MODE=none`). They are settings, not secrets, and
 * rewriting them would mangle every ordinary use of the word in a report (a check label, a scope, a verdict sentence).
 */
export const MODE_WORDS: ReadonlySet<string> = new Set(["true", "false", "yes", "no", "on", "off", "none", "null", "required", "optional", "enabled", "disabled", "auto", "default", "strict", "lax"]);
export const isModeWord = (v: string): boolean => MODE_WORDS.has(v.trim().toLowerCase());

export function makeSecretScrubber(secrets: readonly string[] | undefined): (s: string) => string {
  const list = [...new Set((secrets ?? []).filter((x) => x.length >= 4 && !isModeWord(x)))].sort((a, b) => b.length - a.length);
  if (!list.length) return (s) => s;
  return (s) => {
    let out = s;
    for (const lit of list) if (out.includes(lit)) out = out.split(lit).join("<redacted>");
    return out;
  };
}

/** The sentence run.ts writes when --keep-sandbox is used; it carries the real path on purpose. */
const KEPT = /^the sandbox was kept at /;

/** A deep copy of `value` with every string rewritten. `skip` names the object keys whose values are copied as they are. */
export function redactDeep<T>(value: T, rewrite: (s: string) => string, skip?: (key: string, parent: object) => boolean): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return rewrite(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      return Object.fromEntries(Object.entries(obj).map(([k, x]) => [k, skip?.(k, obj) ? x : walk(x)]));
    }
    return v;
  };
  return walk(value) as T;
}

/** The fields of a check that name it: harness constants, so a secret value or a path never has a reason to be rewritten inside them. */
const CHECK_NAME_FIELDS = new Set(["id", "label", "scope", "pack"]);

/** `config.path` as the working directory sees it, so a report carries no user directory (JUnit and SARIF write the file name only). */
function relativeConfigPath(p: string): string {
  if (!isAbsolute(p)) return p.split(sep).join("/");
  const rel = relative(process.cwd(), p);
  return (rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : (p.split(/[\\/]/).pop() ?? p)).split(sep).join("/");
}

/** What the renderers print: `r` with sandbox paths and secrets rewritten, unless redaction is off or the sandbox was kept. */
export function redactResult(r: RunResult, o: RedactOptions = {}): RunResult {
  if (o.redact === false) return r;
  const scrub = makeSecretScrubber(o.secrets);
  // A kept sandbox is one the reader will open, so its paths and the tokens in its file names stay as they were.
  const kept = Boolean(r.sandbox?.kept);
  const paths = kept ? (s: string) => s : makePathRewriter(r.sandbox?.dir);
  const upstream = (r as { upstream?: { url?: unknown } }).upstream;
  const upstreamPort = typeof upstream?.url === "string" ? Number(/:(\d+)\/?$/.exec(upstream.url)?.[1]) || null : null;
  const run = kept ? (s: string) => s : makeRunNormaliser({ listenerPort: r.sandbox?.listenerPort, upstreamPort });
  const checks = new Set<object>(Array.isArray(r.checks) ? r.checks : []);
  const out = redactDeep(r, (s) => (KEPT.test(s) ? s : scrub(run(paths(s)))), (k, parent) => (CHECK_NAME_FIELDS.has(k) && checks.has(parent)) || (k === "startedAt" && parent === r));
  const finished = out.config?.path ? { ...out, config: { ...out.config, path: relativeConfigPath(out.config.path) } } : out;
  // The stub's address names this run's ephemeral port: the report carries the placeholder (the sentence in types.ts: `url` printed as "{upstream}").
  const shown = (finished as { upstream?: { url?: unknown } }).upstream;
  if (!kept && shown && typeof shown.url === "string") return { ...finished, upstream: { ...shown, url: "{upstream}" } } as RunResult;
  return finished;
}

/**
 * A sandbox directory the harness created, in any spelling, when the failure carries no record of which one it was: the name is
 * `sealmark-` and ten hex digits (`sealmark-cwd-` for the working-directory one), so the parent is whatever path precedes it.
 * Found by the name first (one linear scan), then the parent is read backwards a bounded distance: a pattern that began with the
 * parent would be quadratic on a long run of path-like text.
 */
const SANDBOX_NAME = /sealmark-(?:cwd-)?[0-9a-f]{10}(?![\w-])/g;
const PATH_CHAR = /[^\s"'`<>|,;()[\]{}]/;
const TAIL_AT = new RegExp(TAIL, "y");
/** Most characters of parent path read before the name: longer than any real temporary directory. */
const MAX_PARENT = 1024;

/** The harness's own sandbox paths and per-run tokens rewritten in a message that has no run result to take the directory from. */
function rewriteFailureText(s: string): string {
  let out = "";
  let last = 0;
  if (s.includes("sealmark-")) {
    for (const m of s.matchAll(SANDBOX_NAME)) {
      const at = m.index!;
      if (at < last || !/[\\/]/.test(s[at - 1] ?? "")) continue; // a name that is not the last part of a path is not a sandbox directory
      let start = at;
      while (start > last && at - start < MAX_PARENT && PATH_CHAR.test(s[start - 1]!)) start--;
      const end = at + m[0].length;
      TAIL_AT.lastIndex = end;
      const rawTail = TAIL_AT.exec(s)![0];
      const tail = rawTail.replace(/[\\/]+/g, "/");
      const sub = SUBDIRS.find(({ dir }) => tail === `/${dir}` || tail.startsWith(`/${dir}/`));
      out += s.slice(last, start) + (sub ? `${sub.name}${tail.slice(sub.dir.length + 1)}` : `{sandbox_dir}${tail}`);
      last = end + rawTail.length;
    }
  }
  return makeRunNormaliser(null)(out + s.slice(last));
}

/** A run that failed before it produced a result: its message can carry the server's own output, secrets and the sandbox path included. */
export function redactFailed<T extends { error: string; hint?: string }>(f: T, o: RedactOptions = {}): T {
  if (o.redact === false) return f;
  const scrub = makeSecretScrubber(o.secrets);
  const clean = (t: string) => scrub(rewriteFailureText(t));
  return { ...f, error: clean(f.error), ...(f.hint ? { hint: clean(f.hint) } : {}) };
}
