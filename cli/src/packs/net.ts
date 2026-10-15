// The net pack: does a URL-fetching tool refuse loopback targets and non-http schemes,
// and does it cap what it reads? Every target is the harness's own loopback listener or a canary file in the sandbox.
// Link-local, private-range and public addresses are never sent to the server under test.
import { randomBytes } from "node:crypto";
import { isAbsolute, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { fillArgs, packsFor, secondaryUrlParam } from "../classify.js";
import type { BlobBlock, CallResult, McpSession, ToolInfo } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence, Pack, PackCtx, ToolClassification, Verdict } from "../types.js";
import { describeRedirect, redirectCheck } from "./net-redirect.js";
import { head, refused as declined } from "./shared.js";

const SINCE = "0.2-draft";
const MIB = 1024 * 1024;

/**
 * What a refusal of a target looks like (round 4 design A1, round 5 design G1). A refusal is a declined reply that ties itself to the
 * TARGET or to the RULE that refused it. A reply that reports a failed fetch, or names the mechanism that failed (proxy, socket,
 * DNS, timeout, a refused connection), is a failure whatever adjectives it uses, because a tool that fetches nothing says exactly
 * that. `refusalTier` applies the tiers in this order:
 *   1. a timeout or a closed transport: a failure (not declined: unanswered);
 *   2. the reply with every spelling of the probe URL and of the listener's host:port removed (`stripUrl`): what the server said;
 *   3. a RULE_PHRASE (ssrf, unsafe destination, resolves to a private address, only public hosts, egress policy, failed validation,
 *      the scheme phrases): a refusal that names the rule. Tested before the failure veto on purpose: "Request to a private address
 *      failed validation" carries a failure phrase and is a refusal;
 *   4. a CLASS_NOUN (loopback, link-local, private address, internal host, local network, public hosts, ...): a refusal that names the
 *      address class, unless the reply is also a failure report (FAILURE_VETO) and the clause holding the noun carries no refusal
 *      word once the failure phrases are cut out ("Failed to connect to loopback interface: ECONNREFUSED" is a failure; "connections
 *      to a private address are not allowed" is a refusal);
 *   5. a failure phrase (FAILURE_VETO): a failure;
 *   6. a generic refusal word (REFUSAL_WORD) together with a noun that names the target (TARGET_NOUN) in the first 300 characters;
 *   7. a declined reply that names the loopback address itself: a JSON-RPC invalid-params error (-32602) does; an isError reply
 *      does when it also carries a refusal word, or says invalid or bad request (too generic to count without the address).
 * The word lists decide only among replies the harness already saw come back from a call; where a refusal needs more than words,
 * net-loopback-ssrf compares the tool's reply to a URL with no host (the hostless twin) and the listener's own record.
 */
/** The rule half of the vocabulary: the reply names the rule that refused the target (or the scheme). */
export const RULE_PHRASE = new RegExp(
  [
    "\\bssrf\\b",
    "\\bunsafe (?:destination|host|target|url|address)",
    "\\bresolves to (?:\\d{1,3}(?:\\.\\d{1,3}){3}\\b|\\[?(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*\\]?)",
    "\\bresolves to [^.]{0,30}(?:private|internal|loopback|reserved|non-public|not public)",
    "(?:only|just) [^.\\n]{0,40}(?:allowed|permitted|supported|accepted|may be fetched)",
    "(?:only|just) [^.\\n]{0,20}(?:public|external|internet)",
    "\\begress (?:policy|rule|filter)",
    "(?:failed|fails) validation",
    "validation (?:failed|error)",
    // The scheme phrases (net-scheme-allowlist): the refusal names the scheme, or says only http(s) is accepted.
    "(?:invalid|unknown|unsupported|disallowed|forbidden) (?:url |uri )?(?:scheme|protocol)",
    "scheme [^.\\n]{0,30}(?:not|un)",
    "\\bsupported schemes are\\b",
    "\\bonly https?\\b|\\bhttps?(?:\\(s\\))? only\\b",
  ].join("|"),
  "i",
);

/** The class half: the reply names the class of address it refused. Weaker than a rule phrase: a failure report that uses the noun does not count. */
export const CLASS_NOUN = new RegExp(
  [
    "loopback",
    "\\blink-local\\b",
    "\\bprivate (?:address|ip|range|network|host|subnet)",
    "\\binternal (?:address|ip|host|network|url|resource|target|service(?! (?:error|unavailable|failure|timeout)))",
    "\\breserved (?:address|ip|range)",
    "\\b(?:non|not)[- ]routable|\\bunroutable\\b",
    "\\bnot (?:a )?public\\b",
    "\\bnon-public\\b",
    "\\blocal (?:network|address|host|resource)",
    "\\bpublic (?:hosts?|addresses|urls?|ips?|domains?)",
    "\\bmetadata (?:endpoint|service)",
  ].join("|"),
  "i",
);

/** A reply that reports a failed fetch: the transport, the resolver, a proxy or a timeout. Never a refusal unless a RULE_PHRASE, or a CLASS_NOUN in a clause that also refuses, matches. */
export const FAILURE_VETO =
  /\bECONN\w+|\bENET\w+|\bEHOSTUNREACH|\bETIMEDOUT|\bEAI_AGAIN|\bENOTFOUND|connection (?:refused|reset|closed|failed|error|aborted|blocked)|(?:network|host) (?:is )?unreachable|\bunreachable\b|timed? ?out|\bproxy\b|\bsocket\b|\bdns\b|name resolution|getaddrinfo|certificate|\btls\b|\bssl\b|\bfailed to (?:fetch|connect|load|download|resolve|reach|open)\b|\b(?:request|fetch|download|connection)\b(?:[^.\n]|\.\S){0,40}\bfailed\b|\brefused to connect\b|\bcould not (?:connect|resolve|reach)\b/i;
const FAILURE_SPANS = new RegExp(FAILURE_VETO.source, "gi");

/** A word servers use to decline. It counts next to a TARGET_NOUN; or, with VALIDATION_WORD, next to the loopback address itself. */
const REFUSAL_WORD = /\b(?:blocked|not allowed|not permitted|forbidden|disallowed|prohibited|denied|rejected|refused|restricted|unsafe)\b|\bcan(?:not|['\u2019]t) (?:access|reach|fetch|connect to)\b|\bwon['\u2019]t (?:fetch|connect)\b/i;
const VALIDATION_WORD = /\b(?:invalid|bad request)\b/i;
/** What a refusal is about. "host" is a whole word, so "localhost" alone does not count: that spelling is the address rule's (tier 7). */
const TARGET_NOUN = /\b(?:hosts?|hostnames?|address|destination|target|url|domain|ip|origin|site)\b/i;

/** An address the probes can resolve to: what a refusal names when it explains itself by the address instead of by a rule. */
const LOOPBACK_ADDRESS = /\b127(?:\.\d{1,3}){3}\b|\b0\.0\.0\.0\b|\[?::1\]?(?![0-9a-f:])|\blocalhost\b|::ffff:(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|7f[0-9a-f]{2}:[0-9a-f]{1,4})\b/i;

/** A refusal that is about the scheme: it names the scheme, the protocol or the URL type (or says only http(s) is accepted). */
const SCHEME_WORDS = /\bschemes?\b|\bprotocols?\b|\burl type\b|\bonly (?:http|https)\b|\b(?:http|https)(?:\(s\))? only\b/i;
/** What McpSession prints for an embedded resource whose content is a blob: its uri only. A text resource prints its text. */
const EMBEDDED_RESOURCE = /\[resource\b/; // "[resource_link ...]" is a pointer, not content, and has no word boundary after "resource"

const article = (kind: string): string => `${/^[aeiou]/.test(kind) ? "an" : "a"} ${kind}`;

/** True when the result carries the data of at least one non-text block. */
const hasBlobData = (r: CallResult): boolean => (r.blobs ?? []).some((b) => b.base64 !== undefined);

/** The first non-text block whose decoded bytes (UTF-8 or Latin-1) contain `needle`, an echo of the probe URL not counted. */
function blobWith(r: CallResult, needle: string, url: string): BlobBlock | undefined {
  return (r.blobs ?? []).find((b) => {
    if (b.base64 === undefined) return false;
    const raw = Buffer.from(b.base64, "base64");
    return [raw.toString("utf8"), raw.toString("latin1")].some((t) => stripUrl(t, url).includes(needle));
  });
}

/**
 * The text with every URL-shaped run removed (`https?://...`, and any run holding a percent-escape): an echo of the probe inside a URL
 * or a slug built from it (a search path, a query string) is not a decoded data: URL.
 */
export function outsideUrls(text: string): string {
  return text.replace(/https?:\/\/\S+/gi, " ").replace(/\S*%[0-9A-Fa-f]{2}\S*/g, " ");
}

/** How one probe call came out. Only "refused" is positive evidence that the target was declined on purpose. */
export type CallOutcome = "refused" | "failed" | "answered";

/** The loopback host spellings of the corpora: a reply that echoes one of them with the listener's port echoes the probe, not a refusal. */
const HOST_SPELLINGS = ["127.0.0.1", "localhost", "[::1]", "::1", "127.1", "0x7f000001", "2130706433", "0.0.0.0", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "127.0.0.1.nip.io"];

/**
 * Remove from a response every spelling of the probe URL (as sent, `encodeURI`, `encodeURIComponent`) and every `<host>:<port>` form
 * of the listener (each corpus host spelling and the probe URL's own parsed host, bracketed and percent-encoded, followed by one of
 * `ports`, the listener's ports of this run), so that an echo of what the harness sent cannot count as evidence. Bare host names
 * without the port are not removed: "cannot access localhost" names the address, and the failure veto is what tells a refusal from
 * an echo in a failure report.
 */
export function stripUrl(text: string, url: string, ports: readonly number[] = []): string {
  let t = text;
  for (const form of new Set([url, encodeURI(url), encodeURIComponent(url)])) t = t.split(form).join(" ");
  const hosts = new Set(HOST_SPELLINGS);
  const own = (() => {
    try {
      const u = new URL(url);
      return u.hostname ? { host: u.hostname, port: u.port } : undefined;
    } catch {
      return undefined;
    }
  })();
  const allPorts = new Set(ports.map(String));
  if (own) {
    hosts.add(own.host);
    if (own.port) allPorts.add(own.port);
  }
  if (!allPorts.size) return t;
  const forms = new Set<string>();
  for (const h of hosts) {
    for (const port of allPorts) {
      for (const f of [`${h}:${port}`, `${h.replace(/^\[|\]$/g, "")}:${port}`]) forms.add(f).add(encodeURIComponent(f)).add(encodeURI(f));
    }
  }
  const escaped = [...forms].sort((a, b) => b.length - a.length).map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return t.replace(new RegExp(escaped.join("|"), "gi"), " ");
}

/** Which tier of the refusal model made a reply a refusal; the report names it so that a vocabulary miss can be argued from the evidence. */
export type RefusalTier = "names the rule" | "names the address class" | "refusal tied to the host" | "validation error naming the address";

/** True when a clause of `said` names an address class and refuses it; under a failure veto the clause must carry a refusal word of its own once the failure phrases are cut out. */
function classNounRefusal(said: string, veto: boolean): boolean {
  for (const clause of said.split(/[;\n]|\.(?=\s|$)/)) {
    if (!CLASS_NOUN.test(clause)) continue;
    if (!veto || REFUSAL_WORD.test(clause.replace(FAILURE_SPANS, " "))) return true;
  }
  return false;
}

/**
 * Classify a probe call and, for a refusal, say why it is one. `failed` = errored or declined without saying the target was refused;
 * `answered` = neither. `ports` are the listener's ports of this run (their host:port spellings are removed from the reply first).
 */
export function refusalTier(r: CallResult, url: string, ports: readonly number[] = []): { outcome: CallOutcome; tier?: RefusalTier } {
  if (r.timedOut || r.closed) return { outcome: "failed" };
  if (!declined(r)) return { outcome: "answered" };
  const said = stripUrl(`${head(r.text ?? "")}\n${r.rpcError ?? ""}`, url, ports);
  const veto = FAILURE_VETO.test(said);
  if (RULE_PHRASE.test(said)) return { outcome: "refused", tier: "names the rule" };
  if (classNounRefusal(said, veto)) return { outcome: "refused", tier: "names the address class" };
  if (veto) return { outcome: "failed" };
  const first = said.slice(0, 300);
  if (REFUSAL_WORD.test(first) && TARGET_NOUN.test(first)) return { outcome: "refused", tier: "refusal tied to the host" };
  // A server that validates the argument says so as JSON-RPC INVALID_PARAMS (-32602, carried in the SDK's "MCP error -32602: ..." text),
  // or, in the Python SDK's family, as an isError reply: when the message names the loopback address the URL resolves to, it is a
  // refusal of the target, not a malformed call. The protocol error needs no word (it is a validation by definition); the isError
  // reply does. A failure report that names the address ("connect to 127.0.0.1 failed") never gets here: the veto has returned.
  if (LOOPBACK_ADDRESS.test(said)) {
    if (/-32602\b/.test(r.rpcError ?? "")) return { outcome: "refused", tier: "validation error naming the address" };
    if (r.isError && (REFUSAL_WORD.test(first) || VALIDATION_WORD.test(first))) return { outcome: "refused", tier: "validation error naming the address" };
  }
  return { outcome: "failed" };
}

/** Classify a probe call (see refusalTier). */
export function outcomeOf(r: CallResult, url: string, ports: readonly number[] = []): CallOutcome {
  return refusalTier(r, url, ports).outcome;
}

/** The phrase that goes into a probe's evidence line for an outcome: it names the tier of a refusal. */
const outcomeText = (o: { outcome: CallOutcome; tier?: RefusalTier }): string => (o.outcome === "refused" ? `explicitly refused (${o.tier})` : o.outcome === "failed" ? "failed without saying the target was refused" : "answered");
const declinedCall = (r: CallResult): boolean => r.timedOut || r.closed || declined(r);

/** Fixed thresholds of net-caps (published in describe(); not configurable). */
export const NET_CAPS = { passMib: 16, bigMib: 64, slowMarginSec: 8, maxToolsProbed: 6 } as const;

// ---------------------------------------------------------------------------------------------------------
// Corpora. `template` placeholders: {port} (listener, IPv4), {port6} (listener, IPv6), {token}, {listener}, {canary}
// ---------------------------------------------------------------------------------------------------------

export interface CorpusEntry {
  id: string;
  template: string;
  /** Needs the IPv6 loopback listener, or DNS (net.allow_dns). */
  needs?: "ipv6" | "dns";
  text: string;
}

export const SSRF_CORPUS: CorpusEntry[] = [
  { id: "loopback", template: "http://127.0.0.1:{port}/t/{token}", text: "127.0.0.1" },
  { id: "localhost", template: "http://localhost:{port}/t/{token}", text: "localhost" },
  { id: "ipv6", template: "http://[::1]:{port6}/t/{token}", needs: "ipv6", text: "[::1]" },
  { id: "short", template: "http://127.1:{port}/t/{token}", text: "127.1 (short form)" },
  { id: "hex", template: "http://0x7f000001:{port}/t/{token}", text: "0x7f000001 (hex)" },
  { id: "decimal", template: "http://2130706433:{port}/t/{token}", text: "2130706433 (decimal)" },
  { id: "unspecified", template: "http://0.0.0.0:{port}/t/{token}", text: "0.0.0.0" },
  // The IPv4-mapped IPv6 spelling: it reaches the IPv4 listener through the kernel's dual-stack mapping, so it uses {port} and needs no IPv6 listener.
  { id: "ipv4-mapped", template: "http://[::ffff:127.0.0.1]:{port}/t/{token}", text: "[::ffff:127.0.0.1] (IPv4-mapped IPv6)" },
  { id: "redirect", template: "http://127.0.0.1:{port}/redir/{token}", text: "loopback URL that answers 302 to another loopback URL" },
  { id: "dns", template: "http://127.0.0.1.nip.io:{port}/t/{token}", needs: "dns", text: "127.0.0.1.nip.io (only with net.allow_dns: true)" },
];

export const SCHEME_CORPUS: CorpusEntry[] = [
  { id: "file", template: "{file_url}", text: "file:/// URL of the sandbox canary file" },
  { id: "file-localhost", template: "{file_url_localhost}", text: "file://localhost/ URL of the sandbox canary file" },
  { id: "ftp", template: "ftp://127.0.0.1:{port}/", text: "ftp:// to the listener (raw TCP)" },
  // {token} already starts with "sm-", which is what the report's redaction normalises: no second prefix.
  { id: "gopher", template: "gopher://127.0.0.1:{port}/_{token}", text: "gopher:// to the listener (raw TCP)" },
  { id: "dict", template: "dict://127.0.0.1:{port}/d:{token}", text: "dict:// to the listener (raw TCP)" },
  { id: "data", template: "data:text/plain,{token}", text: "data: URL carrying a token" },
  { id: "javascript", template: "javascript:1", text: "javascript:1 (recorded, never scored)" },
];

interface Vars {
  port: number;
  port6?: number;
  token: string;
  canaryDir: string;
  canaryFile: string;
}

export function expandTemplate(t: string, v: Vars): string {
  const fileUrl = pathToFileURL(v.canaryFile);
  return t.replace(/\{(port6|port|token|listener|canary|file_url_localhost|file_url)\}/g, (_m, key: string) => {
    switch (key) {
      case "port":
        return String(v.port);
      case "port6":
        return String(v.port6 ?? "");
      case "token":
        return v.token;
      case "listener":
        return `http://127.0.0.1:${v.port}`;
      case "canary":
        return v.canaryDir.replace(/\\/g, "/").replace(/^\//, "");
      case "file_url":
        return fileUrl.href;
      default:
        return `file://localhost${fileUrl.pathname}`;
    }
  });
}

// ---------------------------------------------------------------------------------------------------------
// Target safety: the last gate before anything is sent to the server under test.
// ---------------------------------------------------------------------------------------------------------

const QUAD = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isLoopbackHost(host: string, allowDns: boolean): boolean {
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const q = QUAD.exec(host);
  if (q) {
    const n = q.slice(1).map(Number);
    if (n.some((x) => x > 255)) return false;
    return n[0] === 127 || n.every((x) => x === 0);
  }
  if (host === "::1" || host === "::") return true;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) return parseInt(mapped[1]!, 16) >> 8 === 127;
  if (allowDns) {
    const dns = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.nip\.io$/.exec(host);
    if (dns) return isLoopbackHost(dns[1]!, false);
  }
  return false;
}

function insideDir(dir: string, path: string): boolean {
  const fold = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
  const rel = relative(fold(dir), fold(path));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel) && !rel.split(sep).includes(".."));
}

/**
 * Why a probe URL may not be sent, or undefined when it may. A URL with a host must be a loopback spelling AND carry the
 * port of the harness listener (so a typo in a corpus addition can never reach another service on this machine); a file:
 * URL must point inside the sandbox; data: and javascript: touch nothing. Link-local and RFC1918 addresses fail the first rule.
 */
export function targetProblem(raw: string, o: { sandboxDir: string; ports: number[]; allowDns: boolean }): string | undefined {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return "not a valid URL after placeholder expansion";
  }
  if (u.protocol === "data:" || u.protocol === "javascript:") return undefined;
  if (u.protocol === "file:") {
    let p: string;
    try {
      p = fileURLToPath(u);
    } catch {
      return "file: URL with a host other than localhost";
    }
    return insideDir(o.sandboxDir, p) ? undefined : "file: URL outside the sandbox";
  }
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return "no host";
  if (!isLoopbackHost(host, o.allowDns)) return `host ${host} is not a loopback address (link-local, private and public addresses are never contacted)`;
  if (!o.ports.includes(Number(u.port))) return `port ${u.port || "(default)"} is not the harness listener's`;
  return undefined;
}

/** Why a host may not be the net.control_url's, or undefined when it may: loopback, unspecified, link-local, private, CGNAT and unique-local addresses and `localhost` names are all refused (the control fetch is sent through the tool under test). */
export function controlHostProblem(hostRaw: string): string | undefined {
  const h = hostRaw.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return "it is a localhost name";
  const v4 = (q: [number, number, number, number]): string | undefined => {
    const [a, b] = q;
    if (a === 127) return "it is a loopback address";
    if (a === 0) return "it is an unspecified address";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "it is a private address";
    if (a === 169 && b === 254) return "it is a link-local address";
    if (a === 100 && b >= 64 && b <= 127) return "it is a shared (carrier-grade NAT) address";
    return undefined;
  };
  const q = QUAD.exec(h);
  if (q) return v4(q.slice(1).map(Number) as [number, number, number, number]);
  if (h === "::1") return "it is a loopback address";
  if (h === "::") return "it is an unspecified address";
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1]!, 16);
    const lo = parseInt(mappedHex[2]!, 16);
    return v4([hi >> 8, hi & 255, lo >> 8, lo & 255]) ? "it is an IPv4-mapped private or loopback address" : undefined;
  }
  const mappedDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (mappedDotted) {
    const m = QUAD.exec(mappedDotted[1]!);
    return m && v4(m.slice(1).map(Number) as [number, number, number, number]) ? "it is an IPv4-mapped private or loopback address" : undefined;
  }
  if (/^f[cd]/.test(h) && h.includes(":")) return "it is a unique-local address";
  if (/^fe[89ab]/.test(h) && h.includes(":")) return "it is a link-local address";
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------

export const newToken = () => `sm-${randomBytes(6).toString("hex")}`;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function excerpt(s: string, n = 140): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n)}...` : t;
}

/** One session at a time; a fresh one when the last died (a dropped transport, a crashed server). */
export class Caller {
  private session?: McpSession;
  constructor(private open: () => Promise<McpSession>) {}
  /** Open the session now when there is none, so that starting a server does not count against a timed call. */
  async ensure(): Promise<void> {
    if (!this.session || this.session.closed) this.session = await this.open();
  }
  async call(tool: string, args: Record<string, unknown>, timeoutMs: number): Promise<CallResult> {
    await this.ensure();
    return this.session!.call(tool, args, timeoutMs);
  }
  /** Forget the session (it may be in an unknown state after a dropped message); the next call opens a fresh one. */
  async drop(): Promise<void> {
    const s = this.session;
    this.session = undefined;
    await s?.close().catch(() => {});
  }
}

export interface Target {
  tool: ToolInfo;
  cls: ToolClassification;
  urlParam: string;
}

function pickTargets(ctx: PackCtx): { targets: Target[]; notCovered: { tool: string; reason: string }[] } {
  const targets: Target[] = [];
  const notCovered: { tool: string; reason: string }[] = [];
  const sandboxEnabled = ctx.sandboxEnabled !== false;
  for (const own of ctx.classification ?? []) {
    // A path tool that also takes a URL is probed through that parameter: it is aimed as a url tool, and every other required parameter gets a filler.
    const via = own.class === "url" ? undefined : secondaryUrlParam(own);
    if ((own.class !== "url" && via === undefined) || !packsFor(own, { active: Boolean(ctx.active), sandboxEnabled }).includes("net")) continue;
    const cls: ToolClassification = via === undefined ? own : { ...own, class: "url", params: { ...own.params, url: via } };
    const tool = (ctx.tools ?? []).find((t) => t.name === cls.tool);
    if (!tool) continue;
    const urlParam = cls.params.url;
    if (!urlParam) {
      notCovered.push({ tool: cls.tool, reason: "no URL parameter identified; set it under tools.overrides" });
      continue;
    }
    if (cls.unfillable.length) {
      notCovered.push({ tool: cls.tool, reason: `requires ${cls.unfillable.join(", ")}, which the harness cannot fill in` });
      continue;
    }
    if (targets.length >= NET_CAPS.maxToolsProbed) {
      notCovered.push({ tool: cls.tool, reason: `only the first ${NET_CAPS.maxToolsProbed} URL tools are probed` });
      continue;
    }
    targets.push({ tool, cls, urlParam });
  }
  return { targets, notCovered };
}

export function checkSettings(ctx: PackCtx, id: string): { disabled?: string; advisory?: boolean; critical?: boolean; remove: string[]; add: string[] } {
  const c = ctx.config?.checks?.[id];
  const origin = ctx.config?.origins?.[`/checks/${id}/enabled`]?.source ?? "config";
  const sev = c?.severity ?? null;
  return {
    disabled: c && c.enabled === false ? `disabled by config (${origin})` : undefined,
    // scored and critical say "counts": false, not unset, so an advisory-by-default check (net-redirect) can be made to score.
    advisory: sev === "advisory" ? true : sev === "scored" || sev === "critical" ? false : undefined,
    critical: sev === "critical" ? true : sev === "scored" ? false : undefined,
    remove: c?.corpus?.remove ?? [],
    add: ((c?.corpus?.add ?? []) as unknown[]).filter((x): x is string => typeof x === "string"),
  };
}

export function makeResult(ctx: PackCtx, doc: CheckDoc, verdict: Verdict, summary: string, evidence: Evidence[], coverage?: CheckResult["coverage"]): CheckResult {
  const s = checkSettings(ctx, doc.id);
  const base: CheckResult = {
    id: doc.id,
    pack: "net",
    label: doc.label,
    critical: s.critical ?? doc.critical,
    ...(s.advisory ?? doc.advisory ? { advisory: true } : {}),
    scope: doc.scope,
    verdict,
    summary,
    evidence,
    ...(coverage ? { coverage } : {}),
  };
  if (s.disabled) return { ...base, verdict: "na", summary: s.disabled, evidence: [], coverage: undefined };
  return base;
}

// ---------------------------------------------------------------------------------------------------------
// Check docs
// ---------------------------------------------------------------------------------------------------------

const DOCS: CheckDoc[] = [
  {
    id: "net-loopback-ssrf",
    pack: "net",
    label: "Refuses loopback targets (SSRF)",
    critical: true,
    advisory: false,
    scope: "server (does a URL tool refuse loopback addresses? tested against a harness-owned loopback listener)",
    verifiedBy: ["listener", "response"],
    probes: [
      ...SSRF_CORPUS.map((e) => ({ id: e.id, text: e.text, kind: e.needs ?? "loopback" })),
      // The hostless twin: sent only when the pass would rest on the words of the refusals alone.
      { id: "twin", text: "a data: URL with no host (sent only when every loopback probe was refused and no control URL shows the tool fetches); its reply must differ from the loopback refusals", kind: "control" },
    ],
    thresholds: {
      allow_dns: { default: false, configKey: "net.allow_dns", standardLocked: true },
      control_url: { default: "none", configKey: "net.control_url", standardLocked: true },
    },
    falsePositive: "A server that is meant to fetch local services (a developer tool) fails by design; it should say so and be run with the target outside the loopback range. A response counts as a refusal only when it ties the refusal to the target or names the rule, and the listener saw nothing. Two phrase families count. The rule: it names the rule that refused (SSRF, unsafe destination, resolves to a private or loopback address, only public hosts or only http(s) allowed, egress policy, failed validation, an unsupported scheme). The address class: it names the class of address (loopback, link-local, private, internal or reserved address, local network, public hosts, non-routable, not public), unless the reply is also a failure report and the clause with the noun does not refuse. Beyond those, a refusal word (blocked, not allowed, forbidden, denied, rejected, restricted, cannot access) next to a word for the target (host, address, URL, destination, domain, ip), or a validation error that names the loopback address (JSON-RPC -32602, or an isError reply that says invalid, bad request or a refusal word). A message that merely echoes the URL, or the host and the listener's port, does not count. The evidence line names the tier that decided.",
    falseNegative: "Spellings outside the corpus (the corpus has one entry per normalisation family: dotted, name, IPv6, short, hex, decimal, unspecified and IPv4-mapped IPv6; octal and the rest of 127/8 are not tried), DNS names that resolve to loopback (unless net.allow_dns), DNS rebinding, redirects from a public host to loopback, link-local and private ranges (never sent). A tool that fails for an unrelated reason is not read as refusing: a reply that only reports a failed fetch (refused to connect, connection blocked by a proxy, a socket or DNS error, a timeout, ENETUNREACH, a certificate error) is a failure whatever address words it uses, and so is a bare \"blocked\" or \"restricted\" with no word for the target. Words alone cannot show that a tool fetches anything, so when every loopback probe was refused and no control URL shows the tool fetches, the harness sends one more call, a data: URL with no host (the twin): a tool that gives it the same reply word for word, or that refuses it in wording about an address, refuses everything and is inconclusive; a refuse-everything tool whose reply to the hostless URL differs from its loopback refusals passes on text, with the evidence line saying that no fetch of any URL was shown to work, and net.control_url (a URL the tool can reach) is the way to show it fetches. Unless a reply ties its refusal to the target, the check is inconclusive until net.control_url shows the tool can fetch (the only target the harness owns is the one a guarded tool refuses, so only the tool's own words, or a control URL you supply, can tell a refusal from a failure). The server must be able to reach this machine's loopback listener (stdio, or an HTTP server on this machine).",
    configKeys: ["net.allow_dns", "net.control_url", "checks.net-loopback-ssrf.corpus.add", "checks.net-loopback-ssrf.corpus.remove", "checks.net-loopback-ssrf.enabled", "checks.net-loopback-ssrf.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "net-scheme-allowlist",
    pack: "net",
    label: "Only http(s) schemes accepted",
    critical: true,
    advisory: false,
    scope: "server (does a URL tool accept file:, ftp:, gopher:, dict: or data: URLs?)",
    verifiedBy: ["response", "listener"],
    probes: SCHEME_CORPUS.map((e) => ({ id: e.id, text: e.text, kind: "scheme" })),
    thresholds: {},
    falsePositive: "A tool documented to read local files through file: URLs fails by design.",
    falseNegative: "A scheme that is unsupported by the server's HTTP library passes trivially (recorded, not a defence). A pass needs at least one probe refused for its scheme or a tool shown to fetch: a refusal by a host guard says nothing about the scheme, so a tool with only those refusals is inconclusive. Schemes outside the corpus are not tried. A data: URL counts as accepted when the decoded token comes back in the reply outside any URL-shaped text (an echo of the probe inside a URL or a percent-encoded slug is not a decode), when the reply is an embedded resource (a blob the harness cannot read as text), or when a tool already shown to fetch answers it without refusing; a server that decodes it and replies with a summary that says nothing of the content is not seen.",
    configKeys: ["checks.net-scheme-allowlist.corpus.add", "checks.net-scheme-allowlist.corpus.remove", "checks.net-scheme-allowlist.enabled", "checks.net-scheme-allowlist.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "net-caps",
    pack: "net",
    label: "Response size and time are capped",
    critical: false,
    advisory: false,
    scope: "server (size and time limits on a fetched response; measurable only when the server already reached the harness listener)",
    verifiedBy: ["response", "listener"],
    probes: [
      { id: "big", text: `/big on the listener: a ${NET_CAPS.bigMib} MiB body`, kind: "size" },
      { id: "slow", text: "/slow on the listener: a response held for timeout_probe_sec + 30 s", kind: "time" },
    ],
    thresholds: {
      pass_mib: { default: NET_CAPS.passMib, configKey: "(fixed)", standardLocked: true },
      slow_margin_sec: { default: NET_CAPS.slowMarginSec, configKey: "(fixed; added to timeout_probe_sec)", standardLocked: true },
    },
    falsePositive: "A server that streams large bodies on purpose, or reads a whole body to count it or save it, fails the size half. The size half is judged by bytes: the listener records how much of the 64 MiB body it sent and whether the server hung up early, and a server that consumed the whole body fails whatever it returned afterwards (evidence: 'the listener sent 64 of 64 MiB'). A server that hung up early passes when its reply is small. A server whose own fetch timeout is longer than timeout_probe_sec + 8 s fails the time half although it does cap: set --timeout-probe to the server's value, as for db-timeout.",
    falseNegative: "Only runs when a loopback probe was allowed, so a server that blocks loopback is never measured; a cap that applies only to some content types is not seen.",
    configKeys: ["timeout_probe_sec", "checks.net-caps.enabled", "checks.net-caps.severity"],
    since: SINCE,
    status: "shipped",
  },
  ...describeRedirect(),
];

export function describe(): CheckDoc[] {
  return DOCS;
}
const doc = (id: string): CheckDoc => DOCS.find((d) => d.id === id)!;

// ---------------------------------------------------------------------------------------------------------
// Probe construction (exported so a test can audit every target)
// ---------------------------------------------------------------------------------------------------------

export interface BuiltProbe {
  id: string;
  template: string;
  token: string;
  url: string;
  /** Why the probe was not sent (unsafe target, no IPv6, ...). */
  skipped?: string;
}

export function buildProbes(
  corpus: CorpusEntry[],
  o: { port: number; port6?: number; canaryDir: string; canaryFile: string; sandboxDir: string; allowDns: boolean; remove: string[]; add: string[] },
): BuiltProbe[] {
  const entries: CorpusEntry[] = corpus.filter((e) => !o.remove.includes(e.id) && !o.remove.includes(e.template));
  o.add.forEach((t, i) => entries.push({ id: `added-${i + 1}`, template: t, text: t }));
  const ports = [o.port, ...(o.port6 !== undefined ? [o.port6] : [])];
  const out: BuiltProbe[] = [];
  for (const e of entries) {
    const token = newToken();
    const url = expandTemplate(e.template, { port: o.port, port6: o.port6, token, canaryDir: o.canaryDir, canaryFile: o.canaryFile });
    const base: BuiltProbe = { id: e.id, template: e.template, token, url };
    if (e.needs === "dns" && !o.allowDns) continue;
    if (e.needs === "ipv6" && o.port6 === undefined) {
      out.push({ ...base, skipped: "this host has no IPv6 loopback listener" });
      continue;
    }
    const problem = targetProblem(url, { sandboxDir: o.sandboxDir, ports, allowDns: o.allowDns });
    out.push(problem ? { ...base, skipped: `not sent: ${problem}` } : base);
  }
  return out;
}

export function listenerPorts(ctx: PackCtx) {
  const l = ctx.sandbox!.listener;
  return { port: l.port, port6: l.port6 };
}

// ---------------------------------------------------------------------------------------------------------
// net-loopback-ssrf
// ---------------------------------------------------------------------------------------------------------

/**
 * A fetch of net.control_url through the same tool: the one piece of positive evidence that the tool can fetch at all, so
 * that "the listener saw nothing" can be read as "blocked" and not "cannot fetch". Run at most once per pack run.
 */
class Control {
  private done?: { ok: boolean; evidence: Evidence[]; calls: number };
  constructor(
    private ctx: PackCtx,
    private caller: Caller,
    private targets: Target[],
  ) {}
  async run(): Promise<{ ok: boolean; evidence: Evidence[]; calls: number }> {
    if (this.done) return this.done;
    const out: { ok: boolean; evidence: Evidence[]; calls: number } = { ok: false, evidence: [], calls: 0 };
    this.done = out;
    const url = this.ctx.config?.net?.control_url;
    if (!url) return out;
    let host = "";
    try {
      host = new URL(url).hostname;
    } catch {
      /* reported below */
    }
    const problem = host ? controlHostProblem(host) : "it is not a URL with a host";
    if (problem) {
      out.evidence.push({ probe: "net.control_url", outcome: `not used: ${problem} (it must name a host the harness does not own: no loopback, link-local or private address)`, verifiedBy: "static" });
      return out;
    }
    const t = this.targets[0];
    if (!t) return out;
    const args = fillArgs(t.tool, t.cls, { url }, newToken());
    if (!args) return out;
    const r = await this.caller.call(t.tool.name, args, 20_000);
    const okFetch = !declinedCall(r) && r.text.trim().length > 0;
    // A control that errored did not exercise the tool: it is not a valid call.
    if (okFetch) out.calls++;
    out.ok = okFetch;
    out.evidence.push({ probe: `${t.tool.name} control fetch (net.control_url)`, outcome: okFetch ? `the tool answered the control URL: ${excerpt(r.text)}` : `failed: ${excerpt(r.text || r.rpcError || "")}`, verifiedBy: "response", tool: t.tool.name });
    return out;
  }
}

export interface SsrfOutcome {
  result: CheckResult;
  /** The first probe the server followed, so net-caps can reuse the spelling that works. */
  allowed?: { target: Target; template: string };
  /** Corpus entries the server explicitly refused (first occurrence per corpus id), so net-redirect can send a redirect to a spelling it refused directly. */
  refused: { id: string; template: string }[];
}

/** The hostless twin (round 5, G1): a URL with no host. A refusal that describes the target cannot be the reply to it. */
const twinUrlFor = (token: string): string => `data:text/plain,${token}`;

/**
 * A reply reduced to what it says apart from what the harness put in it: the probe URL and the listener's host:port spellings
 * removed (stripUrl), every run token, the probe URL's own host, whitespace collapsed, case folded. Two replies that normalise to the
 * same text are one sentence. The full reply is compared, never an excerpt.
 */
export function normaliseReply(r: Pick<CallResult, "text" | "rpcError">, url: string, token: string, ports: readonly number[] = []): string {
  let t = stripUrl(`${r.text ?? ""}\n${r.rpcError ?? ""}`, url, ports);
  t = t.split(token).join(" ").replace(/\bsm-[0-9a-f]{12}\b/gi, " ");
  const raw = /^[a-z][a-z0-9+.-]*:\/\/(?:[^/@?#]*@)?(\[[^\]]*\]|[^/:?#]*)/i.exec(url)?.[1];
  const hosts = new Set<string>();
  try {
    const parsed = new URL(url).hostname;
    if (parsed) hosts.add(parsed).add(parsed.replace(/^\[|\]$/g, ""));
  } catch {
    /* no parsed host */
  }
  if (raw) hosts.add(raw).add(raw.replace(/^\[|\]$/g, ""));
  for (const h of [...hosts].filter(Boolean).sort((a, b) => b.length - a.length)) t = t.replace(new RegExp(h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), " ");
  return t.replace(/\s+/g, " ").trim().toLowerCase();
}

async function ssrfCheck(ctx: PackCtx, caller: Caller, targets: Target[], notCovered: { tool: string; reason: string }[], control: Control): Promise<SsrfOutcome> {
  const d = doc("net-loopback-ssrf");
  const sb = ctx.sandbox!;
  const l = sb.listener;
  const s = checkSettings(ctx, d.id);
  if (s.disabled) return { result: makeResult(ctx, d, "na", "", []), refused: [] };
  const lp = listenerPorts(ctx);
  const ports = [lp.port, ...(lp.port6 !== undefined ? [lp.port6] : [])];
  const probesFor = () =>
    buildProbes(SSRF_CORPUS, {
      ...lp,
      canaryDir: sb.canary,
      canaryFile: sb.files.canary,
      sandboxDir: sb.dir,
      allowDns: Boolean(ctx.config?.net?.allow_dns),
      remove: s.remove,
      add: s.add,
    });
  const evidence: Evidence[] = [];
  const hitsBy: { target: Target; probe: BuiltProbe; how: string }[] = [];
  const results: { target: Target; probe: BuiltProbe; refused: boolean; hit: boolean; outcome: CallOutcome; reqsBefore: number; norm: string }[] = [];
  let generic = 0;
  const calledTools = new Set<string>();
  let validCalls = 0;

  for (const probe of probesFor()) {
    if (probe.skipped) evidence.push({ probe: `corpus entry "${probe.id}"`, outcome: probe.skipped, verifiedBy: "static" });
  }
  for (const target of targets) {
    // One token per (tool, probe) pair: a later tool never inherits an earlier tool's listener hits.
    for (const probe of probesFor()) {
      if (probe.skipped) continue;
      const args = fillArgs(target.tool, target.cls, { url: probe.url }, probe.token);
      if (!args) continue;
      const connsBefore = l.connections().length;
      const reqsBefore = l.requests().length;
      const r = await caller.call(target.tool.name, args, 15_000);
      const judged = refusalTier(r, probe.url, ports);
      const outcome = judged.outcome;
      const isRefused = outcome === "refused";
      if (outcome === "failed") generic++;
      // Only requests that arrived during this call count.
      const sinceCall = <T extends { id: number }>(hs: T[]): T[] => {
        const ids = new Set(l.requests().slice(reqsBefore).map((x) => x.id));
        return hs.filter((h) => ids.has(h.id));
      };
      const hits = sinceCall(declinedCall(r) ? l.hitsFor(probe.token) : await l.waitForHit(probe.token, 400));
      const newConns = l.connections().slice(connsBefore);
      const hit = hits.length > 0 || newConns.length > 0;
      // A call counts as one that exercised the tool when it was answered or refused, or when the listener saw it; a failed call does not.
      if (outcome !== "failed" || hit) {
        validCalls++;
        calledTools.add(target.tool.name);
      }
      const base = { tool: target.tool.name, args: { ...args, [target.urlParam]: probe.url } };
      if (hit) {
        // A hit without the probe's token is a connection (or a request for another path): say what the listener recorded, so the line can be checked by hand.
        const seen = l.requests().slice(reqsBefore).map((x) => `${x.method} ${x.path}`);
        const how = hits.length
          ? `${hits[0]!.method} ${hits[0]!.path} (token seen)`
          : `a connection from the server (${newConns[0]!.family}, no request token; ${seen.length ? `requests recorded: ${seen.slice(0, 3).join(", ")}` : `no HTTP request line recorded, first bytes: ${JSON.stringify(newConns[0]!.firstBytes || "none")}`})`;
        hitsBy.push({ target, probe, how });
        evidence.push({ ...base, probe: `${target.tool.name} ${probe.id}: ${probe.url}`, outcome: `the loopback listener received ${how}`, verifiedBy: "listener", code: "net.ssrf-hit", excerpt: excerpt(r.text || r.rpcError || "", 400) });
      } else {
        evidence.push({ ...base, probe: `${target.tool.name} ${probe.id}: ${probe.url}`, outcome: r.timedOut ? "no answer before the timeout; listener saw nothing" : `${outcomeText(judged)} and the listener saw nothing: ${excerpt(r.text || r.rpcError || "")}`, verifiedBy: "response", code: isRefused ? "net.ssrf-refused" : "net.ssrf-unreached" });
      }
      results.push({ target, probe, refused: isRefused, hit, outcome, reqsBefore, norm: normaliseReply(r, probe.url, probe.token, ports) });
    }
  }
  // A server may fetch after it has already replied.
  if (results.length) {
    await sleep(500);
    for (const x of results) {
      if (x.hit) continue;
      const since = new Set(l.requests().slice(x.reqsBefore).map((q) => q.id));
      const late = l.hitsFor(x.probe.token).filter((h) => since.has(h.id));
      if (late.length) {
        x.hit = true;
        hitsBy.push({ target: x.target, probe: x.probe, how: `${late[0]!.method} ${late[0]!.path} (after the server had replied)` });
        evidence.push({ probe: `${x.target.tool.name} ${x.probe.id}: ${x.probe.url}`, outcome: `the loopback listener received ${late[0]!.method} ${late[0]!.path} after the server had replied`, verifiedBy: "listener", tool: x.target.tool.name, code: "net.ssrf-hit" });
      }
    }
  }

  const coverage = { probed: [...calledTools], notCovered, validCalls };
  const refused: SsrfOutcome["refused"] = [];
  for (const x of results.filter((r) => r.refused)) if (!refused.some((r) => r.id === x.probe.id)) refused.push({ id: x.probe.id, template: x.probe.template });
  if (!results.length) {
    return { result: makeResult(ctx, d, "inconclusive", "no probe could be sent (no usable URL tool or every corpus entry was removed)", evidence, coverage), refused };
  }
  if (hitsBy.length) {
    const forms = [...new Set(hitsBy.map((h) => h.probe.id))];
    const tools = [...new Set(hitsBy.map((h) => h.target.tool.name))];
    const first = hitsBy.find((h) => h.probe.id !== "redirect") ?? hitsBy[0]!;
    return {
      result: makeResult(ctx, d, "fail", `${tools.join(", ")} contacted a loopback listener the harness owns (${forms.join(", ")}): ${hitsBy.length} of ${results.length} probes reached it`, evidence, coverage),
      allowed: { target: first.target, template: first.probe.template },
      refused,
    };
  }
  if (results.every((x) => x.refused)) {
    // Every probe was refused in words and the listener saw nothing. A control fetch shows the tool fetches at all; without one the
    // pass rests on the words alone, and the hostless twin asks whether those words describe the target.
    const ctl = await control.run();
    evidence.push(...ctl.evidence);
    const lead = `all ${results.length} loopback probes were explicitly refused (the response said so) and the listener saw no request or connection`;
    if (ctl.ok) return { result: makeResult(ctx, d, "pass", `${lead}; a control fetch through the same tool succeeded`, evidence, { ...coverage, validCalls: validCalls + ctl.calls }), refused };
    const sametext: string[] = [];
    const incoherent: string[] = [];
    for (const target of targets) {
      const mine = results.filter((x) => x.target === target);
      if (!mine.length) continue;
      const token = newToken();
      const url = twinUrlFor(token);
      const args = fillArgs(target.tool, target.cls, { url }, token);
      if (!args) continue;
      const r = await caller.call(target.tool.name, args, 15_000);
      const judged = refusalTier(r, url, ports);
      const norm = normaliseReply(r, url, token, ports);
      const common = { tool: target.tool.name, args: { ...args, [target.urlParam]: url }, verifiedBy: "response" as const };
      const label = `${target.tool.name} twin: ${url}`;
      if (mine.every((x) => x.norm === norm)) {
        sametext.push(target.tool.name);
        evidence.push({ ...common, probe: label, outcome: `a data: URL with no host got the same reply as every refused loopback probe, word for word: ${excerpt(r.text || r.rpcError || "")}`, code: "net.ssrf-sametext" });
      } else if (judged.outcome === "refused" && judged.tier !== "names the rule") {
        incoherent.push(target.tool.name);
        evidence.push({ ...common, probe: label, outcome: `a data: URL with no host was refused in wording about an address (${outcomeText(judged)}): ${excerpt(r.text || r.rpcError || "")}`, code: "net.ssrf-incoherent" });
      } else {
        evidence.push({ ...common, probe: label, outcome: `a data: URL with no host got a different reply (${outcomeText(judged)}): ${excerpt(r.text || r.rpcError || "")}`, code: "net.ssrf-text-only" });
      }
    }
    const hint = "set net.control_url to a URL it can reach";
    if (sametext.length) {
      return {
        result: makeResult(ctx, d, "inconclusive", `every loopback probe was refused, but a data: URL with no host got the same reply word for word${targets.length > 1 ? ` (${sametext.join(", ")})` : ""}, so the refusal does not describe the target (the tool may refuse every URL; ${hint})`, evidence, coverage),
        refused,
      };
    }
    if (incoherent.length) {
      return {
        result: makeResult(ctx, d, "inconclusive", `every loopback probe was refused, but a data: URL with no host was refused in wording about an address too${targets.length > 1 ? ` (${incoherent.join(", ")})` : ""}, so the wording does not describe the target (${hint})`, evidence, coverage),
        refused,
      };
    }
    return {
      result: makeResult(ctx, d, "pass", `${lead}, and a hostless URL got a different reply; no fetch of any URL was shown to work (set net.control_url to confirm the tool fetches)`, evidence, coverage),
      refused,
    };
  }
  // No hit, and some probes were not explicitly refused: only a control can tell "blocked" from "cannot fetch anything".
  const ctl = await control.run();
  evidence.push(...ctl.evidence);
  if (ctl.ok) return { result: makeResult(ctx, d, "pass", "the listener saw no request, and a control fetch through the same tool succeeded, so the loopback probes were blocked rather than unreachable", evidence, { ...coverage, validCalls: validCalls + ctl.calls }), refused };
  const unrefused = results.filter((x) => !x.refused);
  // Every unexplained reply an ordinary answer: the tool may look hosts up in a table instead of fetching them.
  const lookup = unrefused.every((x) => x.outcome === "answered") ? "; the tool may be a lookup rather than a fetcher, settle it with tools.overrides" : "";
  return {
    result: makeResult(ctx, d, "inconclusive", `the listener saw nothing, but ${unrefused.length} of ${results.length} probes were not explicitly refused (${generic} failed without saying the target was refused), so a refusal cannot be told from a tool that cannot fetch at all (a reply that only reports a failed fetch (proxy, socket, DNS) is not read as a refusal; set net.control_url to a URL the tool can reach${lookup})`, evidence, coverage),
    refused,
  };
}

// ---------------------------------------------------------------------------------------------------------
// net-scheme-allowlist
// ---------------------------------------------------------------------------------------------------------

async function schemeCheck(ctx: PackCtx, caller: Caller, targets: Target[], notCovered: { tool: string; reason: string }[], control: Control, toolFetches: boolean): Promise<CheckResult> {
  const d = doc("net-scheme-allowlist");
  const sb = ctx.sandbox!;
  const l = sb.listener;
  const s = checkSettings(ctx, d.id);
  if (s.disabled) return makeResult(ctx, d, "na", "", []);
  const lp = listenerPorts(ctx);
  const ports = [lp.port, ...(lp.port6 !== undefined ? [lp.port6] : [])];
  const probesFor = () =>
    buildProbes(SCHEME_CORPUS, {
      ...lp,
      canaryDir: sb.canary,
      canaryFile: sb.files.canary,
      sandboxDir: sb.dir,
      allowDns: Boolean(ctx.config?.net?.allow_dns),
      remove: s.remove,
      add: s.add,
    });
  const evidence: Evidence[] = [];
  const calledTools = new Set<string>();
  let validCalls = 0;
  let ran = 0;
  let scored = 0;
  const fails: string[] = [];
  const parts: string[] = [];
  let unexplained = 0;
  /** Probes refused in words about the scheme (or the protocol, or "only http(s)"): the only refusals that say anything about this check. */
  let schemeRefused = 0;
  for (const probe of probesFor()) if (probe.skipped) evidence.push({ probe: `corpus entry "${probe.id}"`, outcome: probe.skipped, verifiedBy: "static" });

  for (const target of targets) {
    // One token per (tool, probe) pair, as in net-loopback-ssrf.
    for (const probe of probesFor()) {
      if (probe.skipped) continue;
      const args = fillArgs(target.tool, target.cls, { url: probe.url }, probe.token);
      if (!args) continue;
      const connsBefore = l.connections().length;
      const r = await caller.call(target.tool.name, args, 15_000);
      ran++;
      const outcome = outcomeOf(r, probe.url, ports);
      const isRefused = outcome === "refused";
      if (!declinedCall(r)) await l.waitForHit(probe.token, 300);
      const newConns = l.connections().slice(connsBefore);
      // Counts as a call that exercised the tool when it was answered or refused, or when the server connected to the listener; a failed call does not.
      if (outcome !== "failed" || newConns.length > 0) {
        validCalls++;
        calledTools.add(target.tool.name);
      }
      const raw = newConns.filter((c) => c.httpRequests === 0);
      const scheme = (() => {
        try {
          return new URL(probe.url).protocol;
        } catch {
          return "";
        }
      })();
      if (scheme !== "javascript:") scored++;
      const label = `${target.tool.name} ${probe.id}: ${probe.url}`;
      const common = { tool: target.tool.name, args: { ...args, [target.urlParam]: probe.url } };
      const read = r.text.includes(sb.tokens.canary);
      if (read) {
        fails.push(`${probe.id}`);
        evidence.push({ ...common, probe: label, outcome: "the canary file's content came back in the response", verifiedBy: "response", code: "net.scheme-file-read" });
      } else if (scheme !== "http:" && scheme !== "https:" && scheme !== "data:" && scheme !== "javascript:" && scheme !== "file:" && newConns.length > 0) {
        fails.push(`${probe.id}`);
        evidence.push({ ...common, probe: label, outcome: `the server opened ${raw.length ? "a raw TCP connection" : "a connection"} to the listener (first bytes: ${JSON.stringify(newConns[0]!.firstBytes || "none")})`, verifiedBy: "listener", code: "net.scheme-raw-tcp" });
      } else if (scheme === "data:" && !declinedCall(r) && outsideUrls(stripUrl(r.text, probe.url, ports)).includes(probe.token)) {
        parts.push(probe.id);
        evidence.push({ ...common, probe: label, outcome: "the server decoded the data: URL and returned its content", verifiedBy: "response", code: "net.scheme-data" });
      } else if (scheme === "data:" && !declinedCall(r) && blobWith(r, probe.token, probe.url)) {
        // The decoded content came back in a resource, image or audio block: the blob's bytes carry the token the harness put in the URL.
        parts.push(probe.id);
        evidence.push({ ...common, probe: label, outcome: `the server decoded the data: URL and returned its content as ${article(blobWith(r, probe.token, probe.url)!.kind)} block`, verifiedBy: "response", code: "net.scheme-data" });
      } else if (scheme === "data:" && !declinedCall(r) && !hasBlobData(r) && EMBEDDED_RESOURCE.test(stripUrl(r.text, probe.url))) {
        // A blob whose data was not carried (over the size cap): the client text shows "[resource <uri>]", never the bytes, so the token cannot be compared.
        parts.push(probe.id);
        evidence.push({ ...common, probe: label, outcome: `the server answered the data: URL with an embedded resource (its blob is not readable as text, so the decoded content was not compared): ${excerpt(r.text)}`, verifiedBy: "response", code: "net.scheme-data" });
      } else if (scheme === "data:" && toolFetches && outcome === "answered" && r.text.trim()) {
        // A tool that is known to fetch (it reached the listener) and did not refuse the data: URL accepted it, even if the reply does not show what it did with it.
        parts.push(probe.id);
        evidence.push({ ...common, probe: label, outcome: `the server did not refuse the data: URL (the reply does not show whether the content was decoded): ${excerpt(r.text)}`, verifiedBy: "response", code: "net.scheme-data" });
      } else {
        if (!isRefused && scheme !== "javascript:") unexplained++; // javascript:1 is recorded, never scored
        // A refusal that names no scheme, protocol or URL type (a loopback guard that fires on the host) says nothing about the scheme check.
        const forScheme = isRefused && SCHEME_WORDS.test(stripUrl(`${head(r.text ?? "")}\n${r.rpcError ?? ""}`, probe.url, ports));
        if (forScheme && scheme !== "javascript:") schemeRefused++;
        const why = isRefused && !forScheme ? "refused for another reason (host guard, not the scheme)" : "explicitly refused";
        evidence.push({ ...common, probe: label, outcome: `${isRefused ? why : outcome === "failed" ? "failed without saying the URL was refused" : "no effect observed"}: ${excerpt(r.text || r.rpcError || "")}`, verifiedBy: "response" });      }
    }
  }
  const coverage = { probed: [...calledTools], notCovered, validCalls };
  if (!ran) return makeResult(ctx, d, "inconclusive", "no probe could be sent (no usable URL tool or every corpus entry was removed)", evidence, coverage);
  if (fails.length) return makeResult(ctx, d, "fail", `the server accepted non-http schemes with an observable effect (${[...new Set(fails)].join(", ")})`, evidence, coverage);
  if (parts.length) return makeResult(ctx, d, "part", `the server accepts data: URLs (${[...new Set(parts)].join(", ")}); no file read and no raw connection was seen`, evidence, coverage);
  // No effect seen. That is a pass only with positive evidence that the tool can fetch (it reached the listener, or a control
  // fetch worked) or that every probe was explicitly refused; otherwise a tool that fetches nothing would pass.
  // A refusal "for another reason" (a host guard that fires on 127.0.0.1) says nothing about the scheme: a pass needs one probe refused
  // for its scheme, or a tool shown to fetch.
  if (!toolFetches && (unexplained > 0 || schemeRefused === 0)) {
    const ctl = await control.run();
    evidence.push(...ctl.evidence);
    if (!ctl.ok) {
      const why =
        unexplained > 0
          ? `${unexplained} of ${scored} scored probes were not explicitly refused, so a refusal cannot be told from a tool that cannot fetch at all (a reply that only reports a failed fetch (proxy, socket, DNS) is not read as a refusal`
          : `no probe was refused for its scheme (the refusals were for another reason, a host guard says nothing about the scheme) and no fetch was shown to work (a tool that fetches nothing would pass`;
      return makeResult(ctx, d, "inconclusive", `no scheme had an observable effect, but ${why}; set net.control_url to a URL the tool can reach)`, evidence, { ...coverage, validCalls: validCalls + ctl.calls });
    }
  }
  const trivial = schemeRefused === 0 ? " (a scheme the HTTP library does not support passes trivially)" : ` (${schemeRefused} explicitly refused for the scheme)`;
  return makeResult(ctx, d, "pass", `${scored} scored probes (javascript: is recorded, not scored) with file:, ftp:, gopher:, dict: and data: URLs had no observable effect${trivial}`, evidence, coverage);
}

// ---------------------------------------------------------------------------------------------------------
// net-caps
// ---------------------------------------------------------------------------------------------------------

type Half = { v: "pass" | "part" | "fail" | "unknown"; line: string };

/** Why net-caps has no URL to measure with: the server refused loopback, the loopback check could not tell, or it never ran. */
function noFetchableUrl(ssrf: SsrfOutcome, ssrfRan: boolean): string {
  const tail = "response size and time caps were not measured";
  if (!ssrfRan) return `net-loopback-ssrf did not run, so no loopback URL is known to be fetchable; ${tail}`;
  if (ssrf.result.verdict === "pass") {
    return ssrf.refused.length
      ? `the server refused loopback targets (net-loopback-ssrf passed), so there is no harness-owned URL it will fetch; ${tail}`
      : `the server never reached the loopback listener (net-loopback-ssrf passed on a control fetch), so there is no harness-owned URL it will fetch; ${tail}`;
  }
  return `net-loopback-ssrf was ${ssrf.result.verdict}: the server never reached the loopback listener, so no loopback URL is known to be fetchable; ${tail}`;
}

async function capsCheck(ctx: PackCtx, caller: Caller, ssrf: SsrfOutcome, ssrfRan: boolean): Promise<CheckResult> {
  const d = doc("net-caps");
  const s = checkSettings(ctx, d.id);
  if (s.disabled) return makeResult(ctx, d, "na", "", []);
  const allowed = ssrf.allowed;
  if (!allowed) return makeResult(ctx, d, "na", noFetchableUrl(ssrf, ssrfRan), []);
  const sb = ctx.sandbox!;
  const l = sb.listener;
  const { port, port6 } = listenerPorts(ctx);
  const base = expandTemplate(allowed.template, { port, port6, token: "", canaryDir: sb.canary, canaryFile: sb.files.canary }).replace(/\/(?:t|redir)\/.*$/, "");
  const ports = [port, ...(port6 !== undefined ? [port6] : [])];
  const bigUrl = `${base}/big`;
  const slowUrl = `${base}/slow`;
  const problem = targetProblem(bigUrl, { sandboxDir: sb.dir, ports, allowDns: Boolean(ctx.config?.net?.allow_dns) }) ?? targetProblem(slowUrl, { sandboxDir: sb.dir, ports, allowDns: Boolean(ctx.config?.net?.allow_dns) });
  if (problem) return makeResult(ctx, d, "inconclusive", `could not derive a safe size/time probe from the URL form the server followed (${problem})`, []);
  const { tool, cls } = allowed.target;
  const evidence: Evidence[] = [];
  const timeoutSec = ctx.timeoutProbeSec;
  const windowMs = (timeoutSec + NET_CAPS.slowMarginSec) * 1000;

  // ---- size ----
  const big: Half = await (async () => {
    const args = fillArgs(tool, cls, { url: bigUrl }, newToken());
    if (!args) return { v: "unknown", line: "arguments could not be built" } as Half;
    const seenBefore = l.requests().filter((r) => r.route === "big").length;
    const pending = caller.call(tool.name, args, 60_000);
    // A response that never arrives (the transport drops a message past its 64 MiB limit) is detected from the listener: once it has sent everything, give the reply 5 s.
    let stop = false;
    const watcher = (async () => {
      const t0 = Date.now();
      let doneAt = 0;
      while (!stop && Date.now() - t0 < 60_000) {
        const rec = l.requests().filter((r) => r.route === "big")[seenBefore];
        if (rec?.done && !doneAt) doneAt = Date.now();
        if (doneAt && Date.now() - doneAt > 5000) return "dropped" as const;
        await sleep(100);
      }
      // Out of time without the listener having sent the whole body: nothing was dropped, the call simply has no reply yet.
      return "idle" as const;
    })();
    const first = await Promise.race([pending, watcher]);
    const r = first === "idle" ? await pending : first;
    stop = true;
    const rec = l.requests().filter((x) => x.route === "big")[seenBefore];
    // A reply lost to the transport's message cap (the session reports the transport error, read defensively: a field on the result, or
    // the "[transport: ...]" suffix of the error text) is the same finding as one the watcher saw never arrive.
    const lostToCap = r !== "dropped" && /maximum size|exceeded/i.test((r as { transportError?: string }).transportError ?? /\[transport: ([^\]]*)\]/.exec(r.rpcError ?? "")?.[1] ?? "");
    if (r === "dropped" || lostToCap) {
      void pending.catch(() => {});
      if (lostToCap) for (let i = 0; i < 30 && rec && !rec.done; i++) await sleep(50);
      await caller.drop();
      // "Dropped by the transport" is a claim about what the listener sent: it needs the listener's record of a finished body.
      if (rec?.done) {
        evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: `the listener sent ${(rec.bytesSent / MIB).toFixed(0)} MiB and the reply never arrived (the full body was passed along and the transport dropped it)`, verifiedBy: "listener", tool: tool.name, code: "net.caps-dropped" });
        return { v: "fail", line: "the 64 MiB body was passed through uncapped (the reply was dropped by the transport)" };
      }
      evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: "the reply was lost to the transport, but the listener has no record of a finished body, so what the server read cannot be told", verifiedBy: "listener", tool: tool.name });
      return { v: "unknown", line: "the reply was lost to the transport and the listener has no record of a finished body" };
    }
    if (!rec) {
      evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: "the listener never saw a /big request", verifiedBy: "listener", tool: tool.name });
      return { v: "unknown", line: "the listener never saw the /big request" };
    }
    if (r.timedOut) {
      evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: "the call timed out before any reply; the cap could not be measured", verifiedBy: "listener", tool: tool.name });
      return { v: "unknown", line: "the call timed out before any reply; the cap could not be measured" };
    }
    if (r.rpcError !== undefined && !r.closed) {
      evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: `the call ended with a protocol error and no reply (${excerpt(r.rpcError)}); the cap could not be measured`, verifiedBy: "listener", tool: tool.name });
      return { v: "unknown", line: "the call ended with a protocol error and no reply; the cap could not be measured" };
    }
    const bytes = r.text.length;
    const mib = bytes / MIB;
    // The listener's record, not the reply, says how much of the body the server pulled: the response "close" event can land just after the reply does.
    for (let i = 0; i < 30 && !rec.done; i++) await sleep(50);
    // Bytes, not the reply: a server that pulled the whole body into memory has no read cap, whatever it returned afterwards.
    const consumed = rec.bytesSent >= l.bigBytes && !rec.aborted;
    const exactMib = (b: number) => (b / MIB).toFixed(b % MIB === 0 ? 0 : 1);
    // How far the client read before it hung up differs per run (3 MiB in one run, 6 in the next, under load): a server that did not
    // consume the body is reported as "under N MiB" with N the next power of two from 8 up, so two runs print the same figure.
    const sentMib = (b: number) => {
      if (consumed || b >= l.bigBytes) return exactMib(b);
      let bound = 8;
      while (bound * MIB <= b) bound *= 2;
      return `under ${bound}`;
    };
    evidence.push({ probe: `${tool.name} ${bigUrl}`, outcome: `${r.isError ? "error reply" : "reply"} of ${mib.toFixed(2)} MiB; the listener sent ${sentMib(rec.bytesSent)} of ${exactMib(l.bigBytes)} MiB${rec.aborted ? " and was cut off by the client" : consumed ? ", the whole body, and the server consumed all of it" : ""}`, verifiedBy: "listener", tool: tool.name, code: "net.caps-size" });
    if (r.closed && !r.text) return { v: "fail", line: "the server went away while reading the body" };
    // What this half measures: the bytes the server consumed from the body (it hung up early, or it read everything), and only then the length of what it returned.
    if (consumed) {
      if (mib <= NET_CAPS.bigMib * 0.98) return { v: "fail", line: `the server read the whole ${exactMib(l.bigBytes)} MiB body (the listener sent ${sentMib(rec.bytesSent)} of ${exactMib(l.bigBytes)} MiB) and returned ${mib.toFixed(2)} MiB: it capped its reply, not what it reads` };
      return { v: "fail", line: `the full ${NET_CAPS.bigMib} MiB body came back` };
    }
    if (mib <= NET_CAPS.passMib) return { v: "pass", line: `the reply was ${mib.toFixed(2)} MiB (limit ${NET_CAPS.passMib} MiB)` };
    if (mib < NET_CAPS.bigMib * 0.98) return { v: "part", line: `the reply was ${mib.toFixed(1)} MiB, over ${NET_CAPS.passMib} MiB but cut short` };
    return { v: "fail", line: `the full ${NET_CAPS.bigMib} MiB body came back` };
  })();
  if (big.v === "fail") await caller.drop();

  // ---- time ----
  const slow: Half = await (async () => {
    const args = fillArgs(tool, cls, { url: slowUrl }, newToken());
    if (!args) return { v: "unknown", line: "arguments could not be built" } as Half;
    const seenBefore = l.requests().filter((r) => r.route === "slow").length;
    // A fresh session (the size half may have dropped the last one) starts before the clock: spawning the server under load is not the server's time.
    await caller.ensure();
    const t0 = Date.now();
    const r = await caller.call(tool.name, args, windowMs);
    const elapsed = Date.now() - t0;
    const rec = l.requests().filter((x) => x.route === "slow")[seenBefore];
    if (!rec) {
      evidence.push({ probe: `${tool.name} ${slowUrl}`, outcome: "the listener never saw a /slow request", verifiedBy: "listener", tool: tool.name });
      return { v: "unknown", line: "the listener never saw the /slow request" };
    }
    if (r.timedOut || elapsed >= windowMs - 250) {
      evidence.push({ probe: `${tool.name} ${slowUrl}`, outcome: `no reply within ${windowMs / 1000} s while the listener held the response`, verifiedBy: "listener", tool: tool.name, code: "net.caps-slow" });
      return { v: "fail", line: `no reply within ${windowMs / 1000} s (timeout_probe_sec ${timeoutSec} + ${NET_CAPS.slowMarginSec} s; a server whose own fetch timeout is longer fails this half although it caps: set --timeout-probe to its value)` };
    }
    evidence.push({ probe: `${tool.name} ${slowUrl}`, outcome: `replied after ${(elapsed / 1000).toFixed(1)} s while the listener was still holding the response${rec.aborted ? " (the server hung up)" : ""}: ${excerpt(r.text || r.rpcError || "")}`, verifiedBy: "listener", tool: tool.name, code: "net.caps-slow" });
    return { v: "pass", line: `replied after ${(elapsed / 1000).toFixed(1)} s, inside the ${windowMs / 1000} s window` };
  })();

  const known = [big, slow].filter((h) => h.v !== "unknown");
  // A half the listener never saw (arguments not built, no request recorded) is not a call that exercised the tool.
  const coverage = { probed: known.length ? [tool.name] : [], notCovered: [], validCalls: known.length };
  if (!known.length) return makeResult(ctx, d, "inconclusive", `the listener did not see the size and time probes (${big.line}; ${slow.line})`, evidence, coverage);
  const points = known.reduce((n, h) => n + (h.v === "pass" ? 1 : h.v === "part" ? 0.5 : 0), 0);
  const verdict: Verdict = points === known.length ? "pass" : points === 0 ? "fail" : "part";
  return makeResult(ctx, d, verdict, `size: ${big.line}; time: ${slow.line}`, evidence, coverage);
}

// ---------------------------------------------------------------------------------------------------------
// The pack
// ---------------------------------------------------------------------------------------------------------

export const pack: Pack = {
  id: "net",
  describe,
  applies(ctx: PackCtx) {
    if (!ctx.sandbox?.listener) return { ok: false, reason: "no loopback listener is available" };
    const { targets } = pickTargets(ctx);
    if (!targets.length) return { ok: false, reason: "no tool is classified as taking a URL with medium confidence or higher (and a fillable argument list)" };
    return { ok: true };
  },
  async run(ctx: PackCtx) {
    const { targets, notCovered } = pickTargets(ctx);
    const caller = new Caller(() => ctx.open());
    try {
      const control = new Control(ctx, caller, targets);
      const ssrf = await ssrfCheck(ctx, caller, targets, notCovered, control);
      const scheme = await schemeCheck(ctx, caller, targets, notCovered, control, ssrf.allowed !== undefined);
      const ssrfRan = ssrf.result.verdict !== "na";
      // net-redirect runs before net-caps: caps may drop the session after a 64 MiB body. The result order keeps net-caps third.
      const redirect = await redirectCheck(ctx, caller, ssrf, ssrfRan);
      const caps = await capsCheck(ctx, caller, ssrf, ssrfRan);
      return [ssrf.result, scheme, caps, redirect];
    } finally {
      await caller.drop();
    }
  },
};

export default pack;
