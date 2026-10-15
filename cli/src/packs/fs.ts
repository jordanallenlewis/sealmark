import { randomBytes } from "node:crypto";
import { lstatSync, mkdirSync, readlinkSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { fillArgs, packsFor } from "../classify.js";
import { placeholdersUsed } from "../config.js";
import { settleMsFor, settledDiff } from "../observers/fs.js";
import type { BlobBlock, CallResult, McpSession, ToolInfo } from "../mcp.js";
import type { CheckCoverage, CheckDoc, CheckResult, Evidence, FsDiff, Pack, PackApplies, PackCtx, ParamRole, Sandbox, ToolClassification, Verdict, VerifiedBy } from "../types.js";

/**
 * The `fs` pack. The harness starts the server with `{sandbox}` as its allowed root and asks
 * file tools for files that live next to it: a canary directory, a sibling whose name has the root as a prefix, and links
 * that point out. A verdict is established by what the server returned (a random canary string) or by what the file-system
 * observer saw change. Every target is inside the sandbox directory; the harness never reads or writes anywhere else.
 *
 * This file also exports the helpers that the `git` and `effects` packs share (packs/shared.ts belongs to another package).
 */

const SINCE = "0.2-draft";
const WIN = process.platform === "win32";
const SEP = WIN ? "\\" : "/";
const KIB = 1024;
const MIB = 1024 * 1024;

// ---------------------------------------------------------------------------------------------------------
// Helpers shared with git.ts and effects.ts
// ---------------------------------------------------------------------------------------------------------

export const token = (prefix = "sm"): string => `${prefix}-${randomBytes(6).toString("hex")}`;

/** Join with the platform separator and no normalisation, so `..` segments stay in the string the server receives. */
export const rawJoin = (...parts: string[]): string =>
  parts
    .map((p, i) => (i === 0 ? p.replace(/[\\/]+$/, "") : p.replace(/^[\\/]+|[\\/]+$/g, "")))
    .filter((p, i) => i === 0 || p !== "")
    .join(SEP);
export const fwd = (p: string): string => p.replace(/\\/g, "/");
const fold = (s: string): string => (WIN ? s.toLowerCase() : s);

/**
 * A reply that says no. Anchored on the first 300 characters so a data row that merely contains the word "error" never counts.
 */
export const REFUSAL =
  /^\s*(?:\[?(?:error|err)\]?\s*[:-]|error\b|refused|rejected|denied|blocked|forbidden|disallowed|access denied|not (?:allowed|permitted|supported)|only [^.\n]{0,60}(?:allowed|permitted|supported)|invalid\b|validation\b|unsafe\b|cannot\b|can't\b|unable to\b)/i;
export function refused(r: CallResult): boolean {
  return r.isError || r.rpcError !== undefined || REFUSAL.test(r.text.slice(0, 300));
}
/** Text that says a path or object was not found or not reachable, even when the server forgot `isError`. */
export const NOT_REACHED = /\b(denied|outside|not allowed|not permitted|forbidden|enoent|no such file|not found|does not exist|invalid|unreachable|access)\b/i;

export const excerpt = (s: string, n = 300): string => (s.length > n ? `${s.slice(0, n)}...` : s);
export const oneLine = (s: string, n = 120): string => excerpt(s.replace(/\s+/g, " ").trim(), n);

const B64_RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const B64_MAX = 4 * MIB;

/**
 * The reply text plus whatever its base64 runs decode to, so a read tool that hands back file bytes as base64 (a JSON
 * `data` field, a data URI, a bare encoded body) is matched against the canary tokens like any other read. Only text the
 * harness already holds is looked at; the bytes of a resource, image or audio block are searched separately (CallResult.blobs).
 */
export function withDecodedBase64(text: string): string {
  if (text.length < 16 || text.length > B64_MAX) return text;
  const runs = new Set<string>();
  const squashed = text.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/_=-]{16,}$/.test(squashed)) runs.add(squashed);
  for (const m of text.match(B64_RUN) ?? []) runs.add(m);
  const out = [text];
  for (const run of [...runs].slice(0, 50)) {
    const decoded = Buffer.from(run, "base64").toString("utf8");
    if (decoded) out.push(decoded);
  }
  return out.join("\n");
}

/** What mcp.ts writes in the reply text for a resource, resource link, image or audio block. The data itself is in `CallResult.blobs` when it was carried. */
const BINARY_PLACEHOLDER = /^\s*\[(?:resource|resource_link|image|audio)\b/;

/** True when some block of the result has data the harness holds (a blob over the size cap carries only its length). */
const carriesBlobData = (r: CallResult): boolean => (r.blobs ?? []).some((b) => b.base64 !== undefined);

/** The first resource, image or audio block whose decoded bytes (as UTF-8 or as Latin-1) contain one of `needles`. */
function blobHolding(r: CallResult, needles: string[]): BlobBlock | undefined {
  return (r.blobs ?? []).find((b) => {
    if (b.base64 === undefined) return false;
    const raw = Buffer.from(b.base64, "base64");
    return [raw.toString("utf8"), raw.toString("latin1")].some((t) => needles.some((n) => t.includes(n)));
  });
}

const toolNamed = (ctx: PackCtx, name: string): ToolInfo | undefined => ctx.tools.find((t) => t.name === name);

/** Every path a pack ever touches must lie inside the sandbox directory. Lexical, case-insensitive on Windows; resolves `..`. */
export function insideSandbox(sb: Sandbox, target: string): boolean {
  let p = target.replace(/^file:\/\//i, "").replace(/^\\\\\?\\/, "");
  if (/^\/[A-Za-z]:[\\/]/.test(p)) p = p.slice(1);
  const abs = isAbsolute(p) ? p : resolve(sb.root, p);
  const rel = relative(fold(resolve(sb.dir)), fold(resolve(abs)));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** Replace sandbox locations in a string with the placeholders a reader of the report can follow. */
export function unexpand(sb: Sandbox, value: unknown): unknown {
  if (typeof value === "string") {
    const pairs: [string, string][] = [
      [sb.rootEvil, "{root_evil}"],
      [sb.canary, "{canary}"],
      [sb.home, "{sandbox_home}"],
      [sb.tmp, "{sandbox_tmp}"],
      [sb.root, "{sandbox}"],
      [sb.dir, "{sandbox_dir}"],
    ];
    let out = value;
    const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    for (const [dir, ph] of pairs) for (const form of new Set([dir, fwd(dir)])) out = out.replace(new RegExp(esc(form), WIN ? "gi" : "g"), ph);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => unexpand(sb, v));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, unexpand(sb, v)]));
  return value;
}

export interface Meta {
  id: string;
  label: string;
  critical: boolean;
  advisory?: boolean;
  scope: string;
}

/** Applies `checks.<id>.severity` and `checks.<id>.enabled` from the configuration to a check's built-in metadata. */
export function metaFor(ctx: PackCtx, base: Meta): Meta & { disabled?: string } {
  const cfg = ctx.config.checks?.[base.id];
  let { critical, advisory } = { critical: base.critical, advisory: Boolean(base.advisory) };
  if (cfg?.severity === "critical") [critical, advisory] = [true, false];
  else if (cfg?.severity === "scored") [critical, advisory] = [false, false];
  else if (cfg?.severity === "advisory") [critical, advisory] = [false, true];
  const origin = ctx.config.origins?.[`/checks/${base.id}/enabled`]?.source ?? `checks.${base.id}.enabled`;
  return { ...base, critical, advisory, ...(cfg?.enabled === false ? { disabled: `disabled by config (${origin})` } : {}) };
}

export function result(m: Meta & { disabled?: string }, pack: CheckResult["pack"], verdict: Verdict, summary: string, evidence: Evidence[], coverage?: CheckCoverage): CheckResult {
  if (m.disabled) return { id: m.id, pack, label: m.label, critical: m.critical, ...(m.advisory ? { advisory: true } : {}), scope: m.scope, verdict: "na", summary: m.disabled, evidence: [] };
  return { id: m.id, pack, label: m.label, critical: m.critical, ...(m.advisory ? { advisory: true } : {}), scope: m.scope, verdict, summary, evidence, ...(coverage ? { coverage } : {}) };
}

/** One long-lived session per run, reopened when the server dies. The harness closes whatever `ctx.open` returned when the pack ends. */
export class Sessions {
  private cur?: McpSession;
  constructor(private readonly ctx: PackCtx) {}
  async get(): Promise<McpSession> {
    if (!this.cur || this.cur.closed) this.cur = await this.ctx.open();
    return this.cur;
  }
  async call(tool: string, args: Record<string, unknown>, ms: number): Promise<CallResult> {
    const r = await (await this.get()).call(tool, args, ms);
    if (r.closed) this.cur = undefined;
    return r;
  }
  /** Close early (a response that drops the transport leaves nothing trustworthy behind it). */
  async drop(): Promise<void> {
    const s = this.cur;
    this.cur = undefined;
    await s?.close();
  }
}

/** Counts the calls and the tools a check used, for CheckResult.coverage. */
export class Tally {
  calls = 0;
  tools = new Set<string>();
  notCovered: { tool: string; reason: string }[] = [];
  /**
   * One call. `ok` says the call exercised the tool: a control that worked, or a probe the server answered (a refusal of the path
   * included) and did not turn away as a malformed request. A call that did not is not a valid call and does not put its tool in `probed`.
   */
  note(tool: string, ok = true): void {
    if (!ok) return;
    this.calls++;
    this.tools.add(tool);
  }
  skip(tool: string, reason: string): void {
    if (!this.notCovered.some((n) => n.tool === tool && n.reason === reason)) this.notCovered.push({ tool, reason });
  }
  coverage(): CheckCoverage {
    return { probed: [...this.tools], notCovered: this.notCovered, validCalls: this.calls };
  }
}

/** Free-form `name words`: `readTextFile` and `read_text_file` both become `read text file`. */
export const words = (s: string): string => s.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-./:]+/g, " ").toLowerCase();

// ---------------------------------------------------------------------------------------------------------
// What a path tool does
// ---------------------------------------------------------------------------------------------------------

export type FsKind = "read" | "list" | "stat" | "write" | "mkdir" | "copy" | "delete" | "edit" | "other";

const VERBS: [FsKind, RegExp][] = [
  ["delete", /\b(delete|remove|unlink|rmdir|rm|trash|erase|truncate|wipe|purge|chmod|chown)\b/],
  ["copy", /\b(move|mv|rename|copy|cp|duplicate)\b/],
  ["mkdir", /\b(mkdir|create dir\w*|make dir\w*|create folder|new dir\w*|new folder)\b/],
  // An edit changes part of a file that is already there; it has its own control (a write control creates a file, an edit needs one).
  ["edit", /\b(edits?|patch(?:es)?|modify|str replace|replace in|apply diff|apply patch)\b/],
  ["write", /\b(write|create|save|put|overwrite|append|touch|replace|update|store|export|dump)\b/],
  ["list", /\b(list|ls|tree|glob|find|search|walk|scan|browse)\b/],
  ["stat", /\b(stat|info|metadata|exists|size|attributes|lstat)\b/],
  ["read", /\b(read|get|cat|open|view|load|import|head|tail|show|fetch|download|retrieve|text|contents?)\b/],
];

/** A name that sets state ("set_default_directory", "configure", "chdir") and says nothing else about files: it changes the session, it does not read a file. */
const SETTER = /\b(set|configure|default|cwd|chdir)\b/;

/** Parenthesised text in a description lists examples and side notes ("(used by read and list)"); it is not what the tool does. */
const withoutParens = (s: string): string => s.replace(/\([^)]*\)/g, " ");

/**
 * What a classified path tool does, from its name first and the start of its description second. Only the harness's own
 * files are ever sent, but a tool that deletes or does something we cannot name is not called with escape probes at all:
 * a delete probe belongs in a custom probe, where the author says so.
 */
export function pathKind(tool: ToolInfo, c: ToolClassification): FsKind {
  const pick = (text: string): FsKind | undefined => VERBS.find(([, re]) => re.test(text))?.[0];
  const w = words(`${tool.name} ${tool.title ?? ""}`);
  let kind = pick(w);
  // The name decides first; a name that only sets state is not a reader whatever its description says.
  if (!kind && SETTER.test(w)) return "other";
  kind ??= pick(words(withoutParens(tool.description ?? "")).slice(0, 120));
  // An "edit" tool that takes a whole new content is a write; one whose replacement the harness can build stays an edit.
  if (kind === "edit") {
    if (c.params.content && !editArgsFor(tool, {}, "a", "b")) kind = "write";
  } else if (c.params.content && kind !== "delete") kind = "write";
  if (kind === "write" && !c.params.content) kind = "mkdir";
  if (kind === "copy" && !c.params.dest) kind = "other";
  if (!kind) kind = c.annotations?.readOnlyHint ? "read" : "other";
  return kind;
}

const normName = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const OLD_TEXT_NAMES = new Set(["oldstr", "oldstring", "oldtext", "oldcontent", "oldvalue", "old", "search", "searchtext", "searchstring", "find", "findtext", "from", "match", "pattern", "original", "originaltext", "before"]);
const NEW_TEXT_NAMES = new Set(["newstr", "newstring", "newtext", "newcontent", "newvalue", "new", "replace", "replacement", "replacetext", "replacewith", "substitution", "to", "after"]);
const typeOfProp = (p: unknown): string => (p && typeof p === "object" && typeof (p as { type?: unknown }).type === "string" ? (p as { type: string }).type : "");

/**
 * Fills the replacement of an edit tool: the pair of strings that say what to find and what to put there, as two string parameters
 * (`old_str`/`new_str`, `search`/`replace`, `old_text`/`new_text`) or as the first array-of-object parameter whose items hold such a pair
 * (`edits: [{oldText, newText}]`). Built here from the tool's own schema, so it does not depend on the classifier's filler. Returns
 * undefined when the tool has no replacement of a shape it knows (then it is not called: write a probes: entry).
 */
export function editArgsFor(tool: ToolInfo, base: Record<string, unknown>, oldText: string, newText: string): Record<string, unknown> | undefined {
  const props = ((tool.inputSchema as { properties?: Record<string, unknown> } | undefined)?.properties ?? {}) as Record<string, unknown>;
  const names = Object.keys(props);
  const oldName = names.find((n) => OLD_TEXT_NAMES.has(normName(n)) && typeOfProp(props[n]) === "string");
  const newName = names.find((n) => NEW_TEXT_NAMES.has(normName(n)) && typeOfProp(props[n]) === "string");
  if (oldName && newName) return { ...base, [oldName]: oldText, [newName]: newText };
  for (const n of names) {
    if (typeOfProp(props[n]) !== "array") continue;
    const item = ((props[n] as { items?: unknown }).items ?? {}) as { properties?: Record<string, unknown>; required?: string[] };
    const ip = item.properties ?? {};
    const o = Object.keys(ip).find((k) => OLD_TEXT_NAMES.has(normName(k)) && typeOfProp(ip[k]) === "string");
    const w = Object.keys(ip).find((k) => NEW_TEXT_NAMES.has(normName(k)) && typeOfProp(ip[k]) === "string");
    if (!o || !w) continue;
    const entry: Record<string, unknown> = {};
    // The other required members of an item get the plainest value of their type.
    for (const k of item.required ?? []) {
      const t = typeOfProp(ip[k]);
      const en = (ip[k] as { enum?: unknown[] } | undefined)?.enum;
      entry[k] = Array.isArray(en) ? en[0] : t === "boolean" ? false : t === "number" || t === "integer" ? 1 : "sm-edit";
    }
    entry[o] = oldText;
    entry[w] = newText;
    return { ...base, [n]: [entry] };
  }
  return undefined;
}

/** A required parameter that carries a hash of the file's current content (optimistic locking): the harness has none to give. */
const hashParam = (tool: ToolInfo): string | undefined => ((tool.inputSchema as { required?: string[] } | undefined)?.required ?? []).find((n) => /hash|etag|checksum|digest|sha\d*|revision|version/i.test(n));

/** A reply that turned the call away as a malformed request: the tool's behaviour was never reached, so the call exercised nothing. */
const VALIDATION_REJECT = /(invalid|required|must be|expected)[^.\n]{0,40}(argument|parameter|param|field|input)/i;
export function validationReject(r: Pick<CallResult, "isError" | "text" | "rpcError">): boolean {
  return /-32602|invalid params/i.test(r.rpcError ?? "") || (r.isError && VALIDATION_REJECT.test(r.text.slice(0, 400)));
}

export interface PathTool {
  tool: ToolInfo;
  c: ToolClassification;
  kind: FsKind;
}

/** Tools the fs pack may call: class path at medium confidence or higher (packsFor). */
export function pathTools(ctx: PackCtx): PathTool[] {
  const out: PathTool[] = [];
  for (const c of ctx.classification) {
    if (!packsFor(c, { active: ctx.active, sandboxEnabled: ctx.sandboxEnabled !== false }).includes("fs")) continue;
    const tool = toolNamed(ctx, c.tool);
    if (tool) out.push({ tool, c, kind: pathKind(tool, c) });
  }
  return out;
}

const READ_KINDS: FsKind[] = ["read", "list", "stat"];

/** The tool has an array path parameter (`paths`), so the array probe, with the escape in the second slot, applies to it. */
const hasArrayParam = (t: PathTool): boolean => t.c.params.paths !== undefined && t.kind !== "copy" && t.kind !== "edit";

/**
 * True when `server.rootless` says the server has no root argument: it works in its working directory, which the harness sets to
 * `{sandbox}`. Read defensively: the key is validated by the configuration layer, this pack only reads it.
 */
export const isRootless = (ctx: PackCtx): boolean => ctx.config.server.rootless === true;

/** True when the server config hands the sandbox to the server (`{sandbox}` or its alias `{dir}`), or is declared rootless (its working directory is the root). */
export function configUsesSandbox(ctx: PackCtx): boolean {
  const used = placeholdersUsed(ctx.config.server);
  return used.has("sandbox") || used.has("dir") || isRootless(ctx);
}

// ---------------------------------------------------------------------------------------------------------
// Probe corpus
// ---------------------------------------------------------------------------------------------------------

interface Env {
  R: string;
  S: string;
  C: string;
  E: string;
  home: string;
  /** The path form the tool's control used first (set by plan()); the array probe builds its escape in that form. */
  style?: "abs" | "rel";
}

interface PathProbe {
  id: string;
  /** The published form, with placeholders. */
  text: string;
  kind: string;
  windowsOnly?: boolean;
  /** Only meaningful when the server resolves relative paths against its root; sent to every tool whose root-relative control worked. */
  relativeOnly?: boolean;
  /** Sent only to a tool with an array path parameter: [control path, escape], the escape in the second slot. */
  arrayOnly?: boolean;
  /** The text is what is sent, backslashes included, on every platform (on POSIX a backslash is an ordinary character of a file name). */
  literal?: boolean;
  build(e: Env, leaf: string): string;
}

/** `{sandbox}\..\canary\<leaf>` with real backslashes: on POSIX one file name inside the sandbox directory, on Windows the same string as `dotdot`. */
const bsAbs = (e: Env, l: string): string => (WIN ? rawJoin(e.R, "..", "canary", l) : `${e.R}\\..\\canary${l ? `\\${l}` : ""}`);
const bsRel = (l: string): string => ["..", "canary", l].filter(Boolean).join("\\");
/** The escape of the array probe, in the path form the tool's control took. */
const arraySecond = (e: Env, l: string): string => (e.style === "rel" ? ["..", "canary", l].filter(Boolean).join("/") : rawJoin(e.R, "..", "canary", l));

/** `file://` plus the absolute path with forward slashes (a drive letter gets the leading slash a file URL needs). */
const fileUrl = (abs: string): string => `file://${WIN ? "/" : ""}${fwd(abs)}`;

const READ_PROBES: PathProbe[] = [
  { id: "dotdot", text: "{sandbox}\\..\\canary\\secret.txt", kind: "traversal", build: (e, l) => rawJoin(e.R, "..", "canary", l) },
  { id: "absolute", text: "{canary}\\secret.txt", kind: "absolute", build: (e, l) => rawJoin(e.C, l) },
  { id: "forward-slash", text: "{sandbox}/../canary/secret.txt", kind: "traversal", build: (e, l) => `${fwd(e.R)}/../canary/${l}` },
  { id: "dot-slash", text: "{sandbox}\\.\\..\\canary\\secret.txt", kind: "traversal", build: (e, l) => rawJoin(e.R, ".", "..", "canary", l) },
  { id: "pct-encoded", text: "{sandbox}/%2e%2e/canary/secret.txt", kind: "encoding", build: (e, l) => `${fwd(e.R)}/%2e%2e/canary/${l}` },
  { id: "extended-length", text: "\\\\?\\{canary}\\secret.txt", kind: "windows", windowsOnly: true, build: (e, l) => `\\\\?\\${rawJoin(e.C, l)}` },
  { id: "evil-dotdot", text: "{sandbox}\\..\\root-evil\\secret.txt", kind: "prefix", build: (e, l) => rawJoin(e.R, "..", "root-evil", l) },
  { id: "evil-absolute", text: "{root_evil}\\secret.txt", kind: "prefix", build: (e, l) => rawJoin(e.E, l) },
  { id: "case-variant", text: "{CANARY}\\SECRET.TXT (upper case)", kind: "windows", windowsOnly: true, build: (e, l) => rawJoin(e.C, l).toUpperCase() },
  { id: "file-url", text: "file:///{canary}/secret.txt", kind: "encoding", build: (e, l) => fileUrl(rawJoin(e.C, l)) },
  { id: "rel-dotdot", text: "..\\canary\\secret.txt", kind: "traversal", relativeOnly: true, build: (_e, l) => ["..", "canary", l].filter(Boolean).join(SEP) },
  { id: "rel-dotdot-fwd", text: "../canary/secret.txt", kind: "traversal", relativeOnly: true, build: (_e, l) => `../canary/${l}` },
  { id: "rel-evil", text: "../root-evil/secret.txt", kind: "prefix", relativeOnly: true, build: (_e, l) => `../root-evil/${l}` },
  { id: "backslash", text: "{sandbox}\\..\\canary\\secret.txt", kind: "traversal", literal: true, build: bsAbs },
  { id: "rel-backslash", text: "..\\canary\\secret.txt", kind: "traversal", relativeOnly: true, literal: true, build: (_e, l) => bsRel(l) },
  { id: "array-second", text: "[{sandbox}/ok.txt, {sandbox}/../canary/secret.txt] (the escape in the second slot of a path array)", kind: "array", arrayOnly: true, build: arraySecond },
];

/**
 * The write corpus mirrors the read corpus wherever a write can carry the same path form (every read probe except the list-only
 * ones): a server decodes or strips a prefix the same way for a write as for a read, and a lexical root check that runs before the
 * decoding lets the encoded form through.
 */
const WRITE_PROBES: PathProbe[] = [
  { id: "dotdot", text: "{sandbox}\\..\\canary\\w-<t>.txt", kind: "traversal", build: (e, l) => rawJoin(e.R, "..", "canary", l) },
  { id: "absolute", text: "{canary}\\w-<t>.txt", kind: "absolute", build: (e, l) => rawJoin(e.C, l) },
  { id: "forward-slash", text: "{sandbox}/../canary/w-<t>.txt", kind: "traversal", build: (e, l) => `${fwd(e.R)}/../canary/${l}` },
  { id: "dot-slash", text: "{sandbox}\\.\\..\\canary\\w-<t>.txt", kind: "traversal", build: (e, l) => rawJoin(e.R, ".", "..", "canary", l) },
  { id: "pct-encoded", text: "{sandbox}/%2e%2e/canary/w-<t>.txt", kind: "encoding", build: (e, l) => `${fwd(e.R)}/%2e%2e/canary/${l}` },
  { id: "extended-length", text: "\\\\?\\{canary}\\w-<t>.txt", kind: "windows", windowsOnly: true, build: (e, l) => `\\\\?\\${rawJoin(e.C, l)}` },
  { id: "evil-dotdot", text: "{sandbox}\\..\\root-evil\\w-<t>.txt", kind: "prefix", build: (e, l) => rawJoin(e.R, "..", "root-evil", l) },
  { id: "evil-absolute", text: "{root_evil}\\w-<t>.txt", kind: "prefix", build: (e, l) => rawJoin(e.E, l) },
  { id: "case-variant", text: "{CANARY}\\W-<T>.TXT (upper case)", kind: "windows", windowsOnly: true, build: (e, l) => rawJoin(e.C, l).toUpperCase() },
  { id: "file-url", text: "file:///{canary}/w-<t>.txt", kind: "encoding", build: (e, l) => fileUrl(rawJoin(e.C, l)) },
  { id: "rel-dotdot", text: "..\\canary\\w-<t>.txt", kind: "traversal", relativeOnly: true, build: (_e, l) => ["..", "canary", l].filter(Boolean).join(SEP) },
  { id: "rel-dotdot-fwd", text: "../canary/w-<t>.txt", kind: "traversal", relativeOnly: true, build: (_e, l) => `../canary/${l}` },
  { id: "rel-evil", text: "../root-evil/w-<t>.txt", kind: "prefix", relativeOnly: true, build: (_e, l) => `../root-evil/${l}` },
  { id: "backslash", text: "{sandbox}\\..\\canary\\w-<t>.txt", kind: "traversal", literal: true, build: bsAbs },
  { id: "rel-backslash", text: "..\\canary\\w-<t>.txt", kind: "traversal", relativeOnly: true, literal: true, build: (_e, l) => bsRel(l) },
  { id: "array-second", text: "[{sandbox}/w-ctl-<t>.txt, {sandbox}/../canary/w-<t>.txt] (the escape in the second slot of a path array)", kind: "array", arrayOnly: true, build: arraySecond },
];

/**
 * Move and copy tools take two paths, so the destination is not the only slot a server can forget to check. The first
 * probe aims the destination out of the root (the source is a harness file inside it); the others leave the destination
 * inside the root and aim the source at a file that is not.
 */
const MOVE_PROBES = [
  { id: "move-copy", text: "move or copy a harness-created file in {sandbox} to {canary}/moved-<t> (destination outside the root)", kind: "move" },
  { id: "move-src-canary", text: "move or copy {canary}/secret.txt to {sandbox}/mv-<t> (source outside the root)", kind: "move" },
  { id: "move-src-evil", text: "move or copy {root_evil}/secret.txt to {sandbox}/mv-<t> (source in the sibling root)", kind: "move" },
  { id: "move-src-rel", text: "move or copy ../canary/secret.txt to mv-<t> (relative source)", kind: "move", relativeOnly: true },
  { id: "move-dest-pct", text: "move or copy a harness-created file in {sandbox} to {sandbox}/%2e%2e/canary/moved-<t> (percent-encoded destination)", kind: "move" },
  { id: "move-dest-fileurl", text: "move or copy a harness-created file in {sandbox} to file:///{canary}/moved-<t> (file:// destination)", kind: "move" },
];

/** What the directory link is called in a report: a junction on Windows, a symbolic link to a directory elsewhere. */
const DIR_LINK = WIN ? "junction" : "symbolic link to directory";

const LINK_READ_PROBES = [
  { id: "link-dir", text: `{sandbox}/link-dir/secret.txt (${DIR_LINK} to {canary})` },
  { id: "link-file", text: "{sandbox}/link.txt (symbolic link to {canary}/secret.txt)" },
];
const LINK_WRITE_PROBE = { id: "link-dir-write", text: `{sandbox}/link-dir/lw-<t>.txt (write through the ${DIR_LINK})` };
/** Writes through the other two links: a link to an existing file, and a link whose target does not exist yet. Judged by what appears or changes in the canary directory. */
const LINK_FILE_WRITE_PROBE = { id: "link-file-write", text: "{sandbox}/link.txt (write through the symbolic link to {canary}/secret.txt)" };
const DANGLING_WRITE_PROBE = { id: "dangling-link-write", text: "{sandbox}/link-dangling.txt (write through a symbolic link to {canary}/dangling-<t>.txt, which does not exist)" };
/** Move and copy tools through links: the destination under the directory link lands in the canary directory; a copied or moved link source that turns up as a file holding the canary token is exfiltration (a moved link is not). */
const MOVE_LINK_PROBES = [
  { id: "move-dest-link", text: `move or copy a harness-created file in {sandbox} to {sandbox}/link-dir/moved-<t> (destination through the ${DIR_LINK})`, kind: "move" },
  { id: "move-src-link", text: "move or copy {sandbox}/link.txt (symbolic link to {canary}/secret.txt) to {sandbox}/mv-<t> (source is a link that leads out)", kind: "move" },
];

/**
 * A probe's text as this platform sends it. The published forms are written with backslashes; on POSIX the separator is a forward
 * slash, so `dotdot` and `forward-slash` are one string there. Windows-only probes keep their Windows spelling, and so do the
 * backslash probes, which send their backslashes as they are.
 */
const shownText = (p: { text: string; windowsOnly?: boolean; literal?: boolean }): string => (WIN || p.windowsOnly || p.literal ? p.text : p.text.replace(/\\/g, "/"));

/** True when `corpus.remove` names the probe by id, by its published text or by the text `explain` shows on this platform. */
const removedBy = (remove: string[], p: { id: string; text: string; windowsOnly?: boolean; literal?: boolean }): boolean => remove.includes(p.id) || (!p.literal && remove.includes(p.text)) || remove.includes(shownText(p));

/** `corpus.remove` drops built-in probes by id or exact text; `corpus.add` appends harness-relative path templates. */
function corpusOf(ctx: PackCtx, id: string): { remove: string[]; add: string[] } {
  const c = ctx.config.checks?.[id]?.corpus;
  return { remove: (c?.remove ?? []).map(String), add: (c?.add ?? []).filter((x): x is string => typeof x === "string") };
}

function expandTemplate(e: Env, tok: string, s: string): string {
  return s
    .replace(/\{(?:sandbox|dir)\}/g, e.R)
    .replace(/\{canary\}/g, e.C)
    .replace(/\{sandbox_home\}/g, e.home)
    .replace(/\{root_evil\}/g, e.E)
    .replace(/\{token\}/g, tok);
}

function envOf(sb: Sandbox, style?: "abs" | "rel"): Env {
  return { R: sb.root, S: sb.dir, C: sb.canary, E: sb.rootEvil, home: sb.home, ...(style ? { style } : {}) };
}

interface Planned {
  id: string;
  text: string;
  path: string;
  /** A root-relative form: a move or copy tool takes its source in the same form. */
  rel?: boolean;
  /** The path goes in the second slot of a path array, after a harness file that is inside the root. */
  array?: boolean;
  /** The probe's kind (`prefix` aims at the sibling root, everything else at the canary directory). */
  kind?: string;
  /** Set when the target would leave the sandbox, which must never be sent. */
  refusedReason?: string;
}

/** What a list tool is sent for a file probe: the directory, so its text names the directory and not the file the file tools get. */
const dirText = (s: string): string => s.replace(/[\\/]+(?:secret\.txt|SECRET\.TXT)\b/, "");

/**
 * The absolute-form probes always run; the root-relative ones run as well for a tool whose root-relative control worked
 * (`o.rel`), and the array probe runs for a tool with an array path parameter (`o.array`). Two probes that build the same string
 * (on POSIX `dotdot` and `forward-slash` do) are sent once.
 */
function plan(ctx: PackCtx, checkId: string, builtin: PathProbe[], leaf: string | ((i: number) => string), o: { rel: boolean; tok: string; dirForm?: boolean; style?: "abs" | "rel"; array?: boolean }): Planned[] {
  const sb = ctx.sandbox!;
  const env = envOf(sb, o.style);
  const cfg = corpusOf(ctx, checkId);
  const out: Planned[] = [];
  const leafAt = (i: number) => (typeof leaf === "function" ? leaf(i) : leaf);
  const built = new Set<string>();
  for (const p of builtin) {
    if (p.windowsOnly && !WIN) continue;
    if (p.relativeOnly && !o.rel) continue;
    if (p.arrayOnly && !o.array) continue;
    if (removedBy(cfg.remove, p)) continue;
    // Two spellings that build the same string (on POSIX `dotdot` and `forward-slash` do) are sent once, whatever the leaf is called.
    const form = `${p.arrayOnly ? "array:" : ""}${p.build(env, o.dirForm ? "" : "\0")}`;
    if (built.has(form)) continue;
    built.add(form);
    const path = p.build(env, o.dirForm ? "" : leafAt(out.length));
    out.push({ id: p.id, text: o.dirForm ? dirText(shownText(p)) : shownText(p), path, kind: p.kind === "prefix" ? "prefix" : "canary", ...(p.relativeOnly ? { rel: true } : {}), ...(p.arrayOnly ? { array: true } : {}) });
  }
  cfg.add.forEach((entry, i) => {
    if (cfg.remove.includes(entry)) return;
    let path = expandTemplate(env, o.tok, entry);
    if (o.dirForm) path = path.replace(/[\\/][^\\/]*$/, "") || path;
    out.push({ id: `custom-${i + 1}`, text: entry, path });
  });
  for (const p of out) if (!insideSandbox(sb, p.path)) p.refusedReason = "the target is outside the sandbox directory, so the harness did not send it";
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------------------

const SCOPE_PATHS = "server (path validation, with a harness-owned root)";

export const FS_META: Record<string, Meta> = {
  "fs-read-escape": { id: "fs-read-escape", label: "Reads stay inside the allowed root", critical: true, scope: SCOPE_PATHS },
  "fs-write-escape": { id: "fs-write-escape", label: "Writes stay inside the allowed root", critical: true, scope: SCOPE_PATHS },
  "fs-link-escape": { id: "fs-link-escape", label: "Links cannot lead out of the allowed root", critical: true, scope: "server (does it resolve links before checking the path?)" },
  "fs-size-cap": { id: "fs-size-cap", label: "Large file reads are capped", critical: false, scope: "server (response size limit)" },
};

interface Ctl {
  t: PathTool;
  /** The form the tool's control call used first: absolute when it takes absolute paths, root-relative otherwise. */
  style: "abs" | "rel";
  /** The tool also took a root-relative path in its control call, so the root-relative probes are meaningful for it. */
  rel: boolean;
  /** Value for the other required string parameters (a search pattern, for example), as decided by the control call that worked. */
  filler?: string;
}

/**
 * What happened to the escape probes of one check. A probe is *sent* when the harness built its arguments, called the tool and the
 * server answered (a reply of any kind, an error or a refusal included). A call that timed out, or found the connection closed,
 * was attempted and not sent: nothing says what the server would have done. A check with no probe sent proves nothing.
 */
class ProbeStats {
  attempted = 0;
  sent = 0;
  timedOut = 0;
  closed = 0;
  /** Probes the harness could not build arguments for. */
  unbuilt = 0;
  /** Probes not tried because the tool had already timed out twice. */
  stalled = 0;
  /** Probes the configuration removed (`corpus.remove`). */
  removed = 0;
  /** Probes the harness did not send because the target was outside the sandbox. */
  refused = 0;
  /** Per tool: calls attempted and answered. */
  byTool = new Map<string, { attempted: number; sent: number }>();

  /** Record one call; returns true when the server answered. */
  call(tool: string, r: CallResult | undefined): boolean {
    const t = this.byTool.get(tool) ?? { attempted: 0, sent: 0 };
    this.byTool.set(tool, t);
    this.attempted++;
    t.attempted++;
    if (!r || r.timedOut) this.timedOut++;
    else if (r.closed) this.closed++;
    else {
      this.sent++;
      t.sent++;
      return true;
    }
    return false;
  }

  get unanswered(): number {
    return this.timedOut + this.closed;
  }

  /** Appended to a verdict that stands: "55 of 56 variants answered; 1 timed out". Empty when every probe was answered. */
  suffix(): string {
    if (!this.unanswered) return "";
    return ` (${this.sent} of ${this.attempted} variants answered; ${[this.timedOut ? `${this.timedOut} timed out` : "", this.closed ? `${this.closed} closed the connection` : ""].filter(Boolean).join("; ")})`;
  }

  /** The summary and evidence of a check that sent nothing. */
  none(tools: string): { summary: string; evidence: Evidence[] } {
    const lines: { n: number; text: string; by: VerifiedBy; code: string }[] = [
      { n: this.timedOut, text: "timed out: the server never answered the escape probe", by: "response", code: "fs.escape.timed-out" },
      { n: this.closed, text: "closed the connection", by: "response", code: "fs.escape.closed" },
      { n: this.stalled, text: "not tried: the tool had already timed out twice", by: "response", code: "fs.escape.stalled" },
      { n: this.unbuilt, text: "could not be built: the tool's required parameters cannot be filled by the harness", by: "static", code: "fs.escape.unbuilt" },
      { n: this.removed, text: "removed by config (corpus.remove)", by: "static", code: "fs.escape.removed" },
      { n: this.refused, text: "not sent: the target is outside the sandbox directory", by: "static", code: "fs.escape.refused" },
    ];
    const extra = [this.closed ? `${this.closed} closed the connection` : "", this.stalled ? `${this.stalled} not tried after repeated timeouts` : "", this.refused ? `${this.refused} outside the sandbox` : ""].filter(Boolean);
    return {
      summary: `no escape probe was answered on ${tools}: ${this.timedOut} timed out, ${this.unbuilt} could not be built, ${this.removed} removed by config${extra.length ? `, ${extra.join(", ")}` : ""}`,
      evidence: lines.filter((l) => l.n > 0).map((l) => ({ probe: "escape probes", outcome: `${l.n} ${l.text}`, verifiedBy: l.by, code: l.code })),
    };
  }
}

/** How many probes of `builtin` (and `corpus.add` entries) the configuration removed, for the tools whose probes apply. */
function removedByConfig(ctx: PackCtx, checkId: string, builtin: PathProbe[], rel: boolean, array = false): number {
  const cfg = corpusOf(ctx, checkId);
  let n = cfg.add.filter((e) => cfg.remove.includes(e)).length;
  for (const p of builtin) {
    if (p.windowsOnly && !WIN) continue;
    if (p.relativeOnly && !rel) continue;
    if (p.arrayOnly && !array) continue;
    if (removedBy(cfg.remove, p)) n++;
  }
  return n;
}

/** Patterns a search or listing tool is asked for in its control: nothing, a substring or regex, a glob, a bare wildcard, an extension glob. Each one matches both ok.txt and secret.txt. */
const SEARCH_FILLERS: (string | undefined)[] = [undefined, "txt", "*txt*", "*", "*.txt"];
/** A control that failed because the pattern did not parse as a regular expression. */
const REGEX_REJECTED = /\b(regex|regexp|regular expression|nothing to repeat|repetition[- ]operator|quantifier|unterminated (?:group|character class)|unmatched|dangling meta|invalid pattern|parse error)\b/i;
/** A control that failed because a program the server runs is not installed. */
const DEPENDENCY_MISSING = /command not found|not found in PATH|executable (?:file )?not found|spawn \S+ ENOENT|exit(?:ed)?(?: with)?(?: code| status)?:? ?127\b/i;

const PROBE_MS_FLOOR = 5000;
const SIZE_CALL_MS = 120_000;

/** Verdict for one oversized read: dropped or complete is a fail, up to `passMib` passes, in between is a part. */
export function sizeVerdict(o: { bytes: number; dropped: boolean; refused: boolean; passMib: number; fileMib: number; cause?: "limit" | "exited" | "timeout" }): { verdict: Verdict; why: string } {
  if (o.dropped) {
    // Say what the harness saw: the transport's own message when it reported one, the server's exit, a timeout. Without a cause the old wording stands.
    const why =
      o.cause === "limit"
        ? "the reply exceeded the harness's 64 MiB message limit (the server sent no cap)"
        : o.cause === "exited"
          ? "the server exited"
          : o.cause === "timeout"
            ? "the call did not finish within its time limit"
            : "the connection dropped or the call timed out (the response was too large for the transport)";
    return { verdict: "fail", why };
  }
  if (o.refused) return { verdict: "pass", why: "the server refused the read" };
  const mib = (o.bytes / MIB).toFixed(1);
  if (o.bytes <= o.passMib * MIB) return { verdict: "pass", why: `returned ${mib} MiB, within the ${o.passMib} MiB limit` };
  if (o.bytes < o.fileMib * MIB) return { verdict: "part", why: `returned ${mib} MiB, over the ${o.passMib} MiB limit but not the whole ${o.fileMib} MiB file` };
  return { verdict: "fail", why: `returned the whole ${o.fileMib} MiB file` };
}

const worst = (vs: Verdict[]): Verdict => (vs.includes("fail") ? "fail" : vs.includes("part") ? "part" : "pass");

class FsRun {
  readonly sb: Sandbox;
  readonly keeper: Sessions;
  readonly probeMs: number;
  readers: Ctl[] = [];
  writers: Ctl[] = [];
  /** Why the read controls could not be established (used by the link check). */
  readControlFailed = false;
  /** A control call was made (the read or write check had a tool to try), so the link check can tell "nothing to test" from "controls failed". */
  controlsAttempted = false;
  /** High-confidence read tools whose control call failed: their escape probes were never judged. */
  private readSkipped: { tool: string; why: string }[] = [];
  /** Content readers (kind read) of any confidence whose control call failed, and why, for the size cap. */
  private readFailed: { tool: string; why: string }[] = [];
  /** A control failed because a program the server runs is not installed (command not found, exit 127). */
  private depMissing = false;
  /** What the read controls said when every one failed, for the size cap (the tally is reset between checks). */
  private readControlSaid = "";
  private timeouts = new Map<string, number>();
  private tally = new Tally();

  constructor(private readonly ctx: PackCtx, readonly tools: PathTool[]) {
    this.sb = ctx.sandbox!;
    this.keeper = new Sessions(ctx);
    this.probeMs = Math.max(PROBE_MS_FLOOR, ctx.config.timeouts?.probe_ms ?? 10_000);
  }

  private begin(): void {
    this.tally = new Tally();
  }

  private stalled(tool: string): boolean {
    return (this.timeouts.get(tool) ?? 0) >= 2;
  }

  /**
   * One call. A control is noted by its caller, once it knows the control worked (`control`); any other call is a probe, which counts
   * toward coverage when the server answered and did not turn the request away as malformed (a refusal of the path is an answer).
   */
  private async call(t: PathTool, args: Record<string, unknown>, ms = this.probeMs, control = false): Promise<CallResult> {
    const r = await this.keeper.call(t.tool.name, args, ms);
    if (r.timedOut) this.timeouts.set(t.tool.name, (this.timeouts.get(t.tool.name) ?? 0) + 1);
    if (!control) this.tally.note(t.tool.name, !r.timedOut && !r.closed && !validationReject(r));
    return r;
  }

  private args(t: PathTool, values: Partial<Record<ParamRole, string | string[]>>, filler?: string): Record<string, unknown> | undefined {
    return fillArgs(t.tool, t.c, values, filler ?? token("sm"));
  }

  private ev(t: PathTool, probe: string, outcome: string, by: VerifiedBy, o: { args?: Record<string, unknown>; r?: CallResult; code: string }): Evidence {
    return {
      probe,
      outcome,
      verifiedBy: by,
      tool: t.tool.name,
      ...(o.args ? { args: unexpand(this.sb, o.args) } : {}),
      ...(o.r?.text ? { excerpt: excerpt(String(unexpand(this.sb, o.r.text)), 400) } : {}),
      code: o.code,
    };
  }

  /** What a failed control call said, shortened for a reason line. The sandbox locations become placeholders first: cutting the text first would leave a path no redaction can match. */
  private said(last: { r: CallResult } | undefined, n: number): string {
    return oneLine(String(unexpand(this.sb, last ? last.r.text || last.r.rpcError || "no reply" : "no reply")), n);
  }

  private skipUnfillable(t: PathTool): void {
    this.tally.skip(t.tool.name, `required parameters (${t.c.unfillable.join(", ") || "unknown"}) cannot be filled by the harness`);
  }

  /**
   * The arguments of an edit call that replaces `oldText` with `newText` in `target`. The path is filled by the classifier's roles and the
   * replacement by this file's own filler, so a tool the classifier calls unfillable only because of its `edits` array is still called.
   */
  private editArgs(t: PathTool, target: string, oldText: string, newText: string): Record<string, unknown> | undefined {
    const base = fillArgs(t.tool, { ...t.c, unfillable: [] }, { path: target, paths: [target] }, token("sm"));
    return base ? editArgsFor(t.tool, base, oldText, newText) : undefined;
  }

  /** Writes the harness's own files back: a probe that wrote through a link, edited a secret or moved one must not leave the next check without it. */
  private restoreHarnessFiles(): void {
    const sb = this.sb;
    for (const [file, content] of [[sb.files.canary, sb.tokens.canary], [sb.files.evil, sb.tokens.evil], [sb.files.ok, sb.tokens.control]] as const) {
      try {
        mkdirSync(resolve(file, ".."), { recursive: true });
        writeFileSync(file, content);
      } catch {
        /* the sandbox is going away */
      }
    }
    this.restoreLinks();
  }

  /** Puts the file links back when a server replaced one with a file or moved it away; a link that is already a link is left alone. */
  private restoreLinks(): void {
    const sb = this.sb;
    const again = (path: string, target: string | undefined): void => {
      if (target === undefined) return;
      try {
        if (lstatSync(path).isSymbolicLink()) return;
        rmSync(path, { force: true });
      } catch {
        /* missing: make it */
      }
      try {
        symlinkSync(target, path, "file");
      } catch {
        /* the link could not be made again; the check says so when it needs it */
      }
    };
    if (sb.links.file.ok) again(sb.files.linkFile, sb.files.canary);
    if (sb.links.dangling?.ok && sb.files.linkDangling) again(sb.files.linkDangling, this.danglingTarget);
  }

  /** A write through the dangling link creates its target in the canary directory: remove it, so the next tool's probe finds the link still dangling. */
  private cleanDanglingTarget(): void {
    const target = this.danglingTarget;
    // Only a file the harness's own link points at, inside the canary directory.
    if (target === undefined || !insideSandbox(this.sb, target) || !fold(resolve(target)).startsWith(fold(resolve(this.sb.canary)))) return;
    try {
      rmSync(target, { force: true });
    } catch {
      /* nothing there */
    }
  }

  /** Where the dangling link points, read from the link itself the first time it is needed. */
  private get danglingTarget(): string | undefined {
    if (this.dTarget === undefined && this.sb.files.linkDangling) {
      try {
        this.dTarget = readlinkSync(this.sb.files.linkDangling);
      } catch {
        /* no link */
      }
    }
    return this.dTarget;
  }
  private dTarget?: string;

  // ---- read controls and probes -------------------------------------------------------------------------

  /** The reply a control read must have: the control token (decoded when it came back as base64), a listing that shows ok.txt, or metadata for it. */
  private controlGood(kind: FsKind, r: CallResult): boolean {
    const sb = this.sb;
    if (kind === "read") return !r.isError && (withDecodedBase64(r.text).includes(sb.tokens.control) || blobHolding(r, [sb.tokens.control]) !== undefined);
    if (kind === "list") return !r.isError && /\bok\.txt\b/.test(r.text);
    return !refused(r) && (/ok\.txt/.test(r.text) || new RegExp(`size\\W{0,4}${Buffer.byteLength(sb.tokens.control)}\\b`, "i").test(r.text));
  }

  /**
   * Establishes that a read-type tool works at all on a harness file, and which path forms it takes. Both forms are tried:
   * a server that takes absolute paths may also resolve relative ones against its root, and then the relative probes apply.
   */
  private async controlRead(t: PathTool, evidence: Evidence[]): Promise<Ctl | undefined> {
    const sb = this.sb;
    const attempts: { style: "abs" | "rel"; p: string }[] =
      t.kind === "list" ? [{ style: "abs", p: sb.root }, { style: "rel", p: "." }] : [{ style: "abs", p: sb.files.ok }, { style: "rel", p: "ok.txt" }];
    let last: { args: Record<string, unknown>; r: CallResult } | undefined;
    const failed: CallResult[] = [];
    const tried = new Set<string>();
    let gone = false;
    // A search or listing tool may need a pattern. The pattern has to match ok.txt and secret.txt both, or a listing of the canary directory
    // would show nothing whatever the server did: the fillers are tried in order (a substring or regex, a glob, a bare wildcard, an extension glob).
    const fillers: (string | undefined)[] = t.kind === "list" ? SEARCH_FILLERS : [undefined];
    for (const filler of fillers) {
      const worked: ("abs" | "rel")[] = [];
      for (const a of attempts) {
        const args = this.args(t, { path: a.p, paths: [a.p] }, filler);
        if (!args) {
          this.skipUnfillable(t);
          return undefined;
        }
        // A tool with no pattern parameter gets the same arguments whatever the filler, so they are not sent again.
        const sig = `${a.style}:${JSON.stringify(args)}`;
        if (tried.has(sig)) continue;
        tried.add(sig);
        const r = await this.call(t, args, this.probeMs, true);
        last = { args, r };
        if (!this.controlGood(t.kind, r)) {
          failed.push(r);
          if (r.timedOut || r.closed) gone = true;
        } else {
          worked.push(a.style);
          this.tally.note(t.tool.name);
          evidence.push(this.ev(t, `control: ${t.tool.name} on ${t.kind === "list" ? "{sandbox}" : "{sandbox}/ok.txt"}${a.style === "rel" ? " (root-relative)" : ""}`, t.kind === "read" ? "the tool read the harness's control file" : t.kind === "list" ? "the tool listed the harness's root and showed ok.txt" : "the tool reported on the harness's control file", "response", { args, r, code: "fs.control.read" }));
        }
      }
      if (worked.length) return { t, style: worked[0], rel: worked.includes("rel"), ...(filler ? { filler } : {}) };
      // A tool that does not answer is not asked again with another pattern.
      if (gone) break;
    }
    // Only a block whose data was not carried (over the size cap, or a link) is skipped for that reason; a block that was read and does not hold the token is an ordinary failed control.
    const binary = last && !last.r.isError && BINARY_PLACEHOLDER.test(last.r.text) && !carriesBlobData(last.r);
    const said = this.said(last, 80);
    const silent = last !== undefined && !last.r.isError && !last.r.timedOut && !last.r.closed && !refused(last.r) && !binary;
    const regexOnly = t.kind === "list" && failed.length > 0 && failed.every((r) => r.isError && REGEX_REJECTED.test(r.text));
    const missing = failed.some((r) => DEPENDENCY_MISSING.test(`${r.text} ${r.rpcError ?? ""}`));
    if (missing) this.depMissing = true;
    const why = binary
      ? "the tool returned a resource, image or audio block, whose data the harness does not read, so its escape probes were not judged"
      : missing
        ? `the control call on {sandbox}/ok.txt failed because a dependency of the server is missing (${said})`
        : regexOnly
          ? `the control pattern was rejected as a regex (${said})`
          : silent
            ? "the control call on {sandbox}/ok.txt succeeded without showing the control file (the tool ignores its path argument)"
            : `the control call on {sandbox}/ok.txt failed (${said})`;
    this.tally.skip(t.tool.name, why);
    if (t.kind === "read") this.readFailed.push({ tool: t.tool.name, why });
    if (t.kind === "read" && t.c.confidence === "high") this.readSkipped.push({ tool: t.tool.name, why });
    if (last) evidence.push(this.ev(t, `control: ${t.tool.name} on {sandbox}/ok.txt`, silent ? "the control call succeeded without showing the control file, so this tool's escape probes were not judged" : "the control call failed, so this tool's escape probes were not judged", "response", { args: last.args, r: last.r, code: "fs.control.failed" }));
    return undefined;
  }

  private leakedBy(kind: FsKind, r: CallResult): string | undefined {
    const sb = this.sb;
    if (kind === "read") {
      const toks = [sb.tokens.canary, sb.tokens.evil];
      if (toks.some((tok) => r.text.includes(tok))) return "the response contains the canary string";
      const block = blobHolding(r, toks);
      if (block) return `the response contains the canary string (in a ${block.kind} block)`;
      return toks.some((tok) => withDecodedBase64(r.text).includes(tok)) ? "the response contains the canary string (base64 encoded)" : undefined;
    }
    if (kind === "list") return !refused(r) && /secret\.txt/.test(r.text) ? "the listing shows secret.txt" : undefined;
    // stat: succeeded for a file that is outside the root and says something about it.
    const sizes = [sb.tokens.canary, sb.tokens.evil].map((x) => Buffer.byteLength(x));
    const about = /secret\.txt/.test(r.text) || sizes.some((n) => new RegExp(`size\\W{0,4}${n}\\b`, "i").test(r.text));
    return !refused(r) && !NOT_REACHED.test(r.text.slice(0, 200)) && about ? "the tool reported metadata for the file" : undefined;
  }

  /** The pack line for a rootless server: the working directory the harness set is the allowed root. */
  private rootlessEvidence(): Evidence {
    return { probe: "root", outcome: "the server's working directory ({sandbox}) is the allowed root (server.rootless): every probe runs, and a server that reads or writes outside it fails", verifiedBy: "static", code: "fs.rootless" };
  }

  /** A note for the summary of a check whose controls all failed, when the sandbox path contains "~": a server that expands it as a home directory rejects every path the harness sends. */
  private tildeNote(): string {
    return this.sb.root.includes("~") ? `; the sandbox path contains "~", which a server may expand as a home directory and then reject (set sandbox.dir to a path without it)` : "";
  }

  /** Tools the classifier left opaque because a required parameter cannot be filled, whose name says they read files (the read check would have used them). */
  private unfillableReaders(): { tool: string; params: string[] }[] {
    const out: { tool: string; params: string[] }[] = [];
    for (const c of this.ctx.classification) {
      if (c.class !== "opaque" || c.excluded || !c.unfillable.length || !c.secondary?.includes("path")) continue;
      const tool = toolNamed(this.ctx, c.tool);
      if (!tool || !READ_KINDS.includes(pathKind(tool, c))) continue;
      const props = ((tool.inputSchema as { properties?: Record<string, unknown> } | undefined)?.properties ?? {}) as Record<string, unknown>;
      out.push({ tool: c.tool, params: c.unfillable.map((n) => (typeOfProp(props[n]) === "array" ? `${n}[]` : n)) });
    }
    return out;
  }

  async readEscape(): Promise<CheckResult> {
    const m = metaFor(this.ctx, FS_META["fs-read-escape"]);
    if (m.disabled) return result(m, "fs", "na", "", []);
    this.begin();
    const evidence: Evidence[] = [];
    const readers = this.tools.filter((t) => READ_KINDS.includes(t.kind));
    for (const t of this.tools) {
      if (t.kind === "delete") this.tally.skip(t.tool.name, "a delete tool is never called by the standard probes; add a custom probe to test it");
      else if (t.kind === "other") {
        // A tool the classifier rated a path tool with high confidence and the pack cannot place says so in one line.
        this.tally.skip(t.tool.name, t.c.confidence === "high" ? "the classifier rated this a path tool with high confidence, but its name and description do not say whether it reads, writes or lists, so it was not called" : "the harness could not tell what this tool does from its name and description, so it was not called");
      }
    }
    if (isRootless(this.ctx)) evidence.push(this.rootlessEvidence());
    // A reader the classifier could not fill is a reader that exists: "no tool reads" would be untrue, and the check could not be run.
    const unfillable = this.unfillableReaders();
    for (const u of unfillable) this.tally.skip(u.tool, `required parameter${u.params.length > 1 ? "s" : ""} ${u.params.join(", ")} cannot be filled by the harness; write a probes: entry to call it`);
    if (!readers.length) {
      if (unfillable.length) {
        this.readControlFailed = true;
        this.controlsAttempted = true;
        const what = unfillable.map((u) => `${u.tool} (${u.params.join(", ")})`).join(", ");
        this.readControlSaid = ` (${what}: required parameters the harness cannot fill)`;
        return result(m, "fs", "inconclusive", `a tool that reads files exists (${what}), but its required parameters cannot be filled by the harness, so no read could be tried; write a probes: entry to call it`, evidence, this.tally.coverage());
      }
      return result(m, "fs", "na", "no tool reads, lists or inspects files, so there was nothing to read outside the root", evidence, this.tally.coverage());
    }

    this.readers = [];
    this.readSkipped = [];
    this.readFailed = [];
    this.depMissing = false;
    this.controlsAttempted = true;
    for (const t of readers) {
      const ctl = await this.controlRead(t, evidence);
      if (ctl) this.readers.push(ctl);
    }
    if (!this.readers.length) {
      this.readControlFailed = true;
      const said = this.tally.notCovered.slice(0, 2).map((n) => `${n.tool}: ${n.reason}`).join("; ");
      const dep = this.depMissing ? "; a dependency of the server is missing" : "";
      this.readControlSaid = `${said ? ` (${said})` : ""}${dep}`;
      return result(m, "fs", "inconclusive", `no read tool could read the harness's control file {sandbox}/ok.txt, so escape attempts could not be judged (is the server's root {sandbox}?)${said ? `; ${said}` : ""}${dep}${this.tildeNote()}`, evidence, this.tally.coverage());
    }

    const leaks: string[] = [];
    const st = new ProbeStats();
    for (const ctl of this.readers) {
      const t = ctl.t;
      const blocked: string[] = [];
      const array = hasArrayParam(t);
      st.removed += removedByConfig(this.ctx, "fs-read-escape", READ_PROBES, ctl.rel, array);
      const planned = plan(this.ctx, "fs-read-escape", READ_PROBES, "secret.txt", { rel: ctl.rel, tok: token(), dirForm: t.kind === "list", style: ctl.style, array });
      // The first slot of an array probe: a harness file the tool can read, in the form its control took.
      const first = ctl.style === "abs" ? (t.kind === "list" ? this.sb.root : this.sb.files.ok) : t.kind === "list" ? "." : "ok.txt";
      for (const [i, p] of planned.entries()) {
        if (p.refusedReason) {
          st.refused++;
          evidence.push(this.ev(t, p.text, p.refusedReason, "static", { code: "fs.skipped" }));
          continue;
        }
        const rest = planned.slice(i).filter((x) => !x.refusedReason).length;
        if (this.stalled(t.tool.name)) {
          st.stalled += rest;
          break;
        }
        const args = this.args(t, p.array ? { path: first, paths: [first, p.path] } : { path: p.path, paths: [p.path] }, ctl.filler);
        if (!args) {
          st.unbuilt += rest;
          break;
        }
        const r = await this.call(t, args);
        if (!st.call(t.tool.name, r)) {
          evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, r.timedOut ? "no reply before the timeout, so this probe says nothing about the server" : "the connection closed during the call, so this probe says nothing about the server", "response", { args, code: "fs.read-unanswered" }));
          continue;
        }
        const why = this.leakedBy(t.kind, r);
        if (why) {
          leaks.push(`${t.tool.name} via ${p.id}`);
          evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, `escaped: ${why}`, "response", { args, r, code: "fs.read-escape" }));
        } else blocked.push(p.id);
      }
      if (blocked.length) evidence.push({ probe: `${t.tool.name}: ${blocked.length} variant(s)`, outcome: `no canary returned for: ${blocked.join(", ")}`, verifiedBy: "response", tool: t.tool.name, code: "fs.read-blocked" });
    }
    const names = this.readers.map((c) => c.t.tool.name).join(", ");
    if (!leaks.length && st.sent === 0) {
      // Nothing was answered, so "refused or returned nothing" would be a claim without a probe behind it.
      const none = st.none(names);
      return result(m, "fs", "inconclusive", none.summary, [...evidence, ...none.evidence], this.tally.coverage());
    }
    if (!leaks.length && this.readSkipped.length) {
      // A clean pass would say the whole read surface was probed; a read tool the control could not reach was not.
      const skipped = this.readSkipped.map((s) => `${s.tool} (${s.why})`).join("; ");
      return result(m, "fs", "part", `${st.sent} path variants aimed outside the root were refused or returned nothing, on ${names}${st.suffix()}, but ${skipped}`, evidence, this.tally.coverage());
    }
    return result(
      m,
      "fs",
      leaks.length ? "fail" : "pass",
      leaks.length ? `a file outside the allowed root was readable: ${leaks.slice(0, 5).join("; ")}${leaks.length > 5 ? ` (+${leaks.length - 5} more)` : ""}` : `${st.sent} path variants aimed outside the root were refused or returned nothing, on ${names}${st.suffix()}`,
      evidence,
      this.tally.coverage(),
    );
  }

  // ---- write controls and probes ------------------------------------------------------------------------

  private async controlWrite(t: PathTool, evidence: Evidence[]): Promise<Ctl | undefined> {
    const sb = this.sb;
    const tok = token();
    const base = t.kind === "mkdir" ? `mk-ctl-${tok}` : t.kind === "copy" ? `cp-ctl-${tok}` : `w-ctl-${tok}`;
    const ext = t.kind === "mkdir" ? "" : ".txt";
    let last: { args: Record<string, unknown>; r: CallResult } | undefined;
    // Both forms are tried, each with its own file name: a server that takes absolute paths may resolve relative ones too.
    const worked: ("abs" | "rel")[] = [];
    for (const style of ["abs", "rel"] as const) {
      const name = `${base}-${style}${ext}`;
      const target = style === "abs" ? rawJoin(sb.root, name) : name;
      let values: Partial<Record<ParamRole, string | string[]>> = { path: target, paths: [target], content: tok };
      if (t.kind === "copy") {
        const srcName = `cp-src-${tok}-${style}.txt`;
        await writeFile(rawJoin(sb.root, srcName), tok);
        values = { path: style === "abs" ? rawJoin(sb.root, srcName) : srcName, dest: target };
      }
      const args = this.args(t, values);
      if (!args) {
        this.skipUnfillable(t);
        return undefined;
      }
      const before = await sb.fs.snapshot(["root"]);
      const r = await this.call(t, args, this.probeMs, true);
      const d = await settledDiff(sb.fs, before, ["root"], settleMsFor(this.ctx.timeoutProbeSec), (x) => x.added.some((k) => k.endsWith(`/${name}`)));
      last = { args, r };
      if (d.added.some((k) => k.endsWith(`/${name}`))) {
        this.tally.note(t.tool.name);
        worked.push(style);
        evidence.push(this.ev(t, `control: ${t.tool.name} creates {sandbox}/${name}${style === "rel" ? " (root-relative)" : ""}`, "the harness saw the file appear inside the root", "fs-observer", { args, code: "fs.control.write" }));
      }
    }
    if (worked.length) return { t, style: worked[0], rel: worked.includes("rel") };
    this.tally.skip(t.tool.name, `the control write inside {sandbox} did not create a file (${this.said(last, 80)})`);
    if (last) evidence.push(this.ev(t, `control: ${t.tool.name} creates a file inside {sandbox}`, "no file appeared, so this tool's escape probes were not judged", "fs-observer", { args: last.args, r: last.r, code: "fs.control.failed" }));
    return undefined;
  }

  /**
   * The control of an edit tool: replace the control token in the harness's {sandbox}/ok.txt with a new token and see the file change.
   * An edit needs a file that is there, so it has its own control (a write control creates a file). ok.txt is written back afterwards.
   */
  private async controlEdit(t: PathTool, evidence: Evidence[]): Promise<Ctl | undefined> {
    const sb = this.sb;
    let last: { args: Record<string, unknown>; r: CallResult } | undefined;
    const worked: ("abs" | "rel")[] = [];
    try {
      for (const style of ["abs", "rel"] as const) {
        const target = style === "abs" ? sb.files.ok : "ok.txt";
        const args = this.editArgs(t, target, sb.tokens.control, `sm-edited-${token("e")}`);
        if (!args) {
          this.tally.skip(t.tool.name, "the harness cannot build this edit tool's replacement (it takes no pair of old and new text it knows); write a probes: entry to call it");
          return undefined;
        }
        const before = await sb.fs.snapshot(["root"]);
        const r = await this.call(t, args, this.probeMs, true);
        const d = await settledDiff(sb.fs, before, ["root"], settleMsFor(this.ctx.timeoutProbeSec), (x) => x.changed.some((k) => k === "root/ok.txt"));
        last = { args, r };
        // Back to the control token, so the second form (and the checks that follow) find the file as it was.
        this.restoreHarnessFiles();
        if (d.changed.some((k) => k === "root/ok.txt")) {
          this.tally.note(t.tool.name);
          worked.push(style);
          evidence.push(this.ev(t, `control: ${t.tool.name} edits {sandbox}/ok.txt${style === "rel" ? " (root-relative)" : ""}`, "the harness saw the file change inside the root", "fs-observer", { args, code: "fs.control.edit" }));
        }
      }
    } finally {
      this.restoreHarnessFiles();
    }
    if (worked.length) return { t, style: worked[0], rel: worked.includes("rel") };
    const hash = hashParam(t.tool);
    this.tally.skip(t.tool.name, hash ? `the control edit of {sandbox}/ok.txt did not change the file: the tool requires an existing file and a content hash (parameter "${hash}"), which the harness cannot supply (${this.said(last, 60)})` : `the control edit of {sandbox}/ok.txt did not change the file (${this.said(last, 80)})`);
    if (last) evidence.push(this.ev(t, `control: ${t.tool.name} edits {sandbox}/ok.txt`, "the file did not change, so this tool's escape probes were not judged", "fs-observer", { args: last.args, r: last.r, code: "fs.control.failed" }));
    return undefined;
  }

  private escaped(d: FsDiff): string[] {
    return [...d.added, ...d.changed, ...d.removed];
  }

  /** The source slot of a move or copy: a harness file inside the root, in the path form the probe uses. */
  private async inRootSource(tok: string, style: "abs" | "rel"): Promise<string> {
    const srcName = `cp-src-${tok}${style === "rel" ? "-rel" : ""}.txt`;
    await writeFile(rawJoin(this.sb.root, srcName), tok);
    return style === "abs" ? rawJoin(this.sb.root, srcName) : srcName;
  }

  /**
   * One write aimed at `target`; returns what the observer saw change in the canary directory and the sibling root. An edit tool is sent
   * the same path with a replacement of `o.old` (the planted token of the file the path names) by a new token; an array probe puts the
   * path in the second slot, after a fresh file inside the root (`o.first`).
   */
  private async writeAt(ctl: Ctl, target: string, tok: string, form: "abs" | "rel" = ctl.style, o: { old?: string; first?: string } = {}): Promise<{ args?: Record<string, unknown>; r?: CallResult; changed: string[] }> {
    const t = ctl.t;
    let args: Record<string, unknown> | undefined;
    if (t.kind === "edit") args = this.editArgs(t, target, o.old ?? this.sb.tokens.canary, `sm-edited-${tok}`);
    else {
      let values: Partial<Record<ParamRole, string | string[]>> = { path: target, paths: [target], content: tok };
      if (o.first !== undefined) values = { path: o.first, paths: [o.first, target], content: tok };
      if (t.kind === "copy") values = { path: await this.inRootSource(tok, form), dest: target };
      args = this.args(t, values);
    }
    if (!args) return { changed: [] };
    const before = await this.sb.fs.snapshot(["canary", "root-evil"]);
    const r = await this.call(t, args);
    const d = await settledDiff(this.sb.fs, before, ["canary", "root-evil"], settleMsFor(this.ctx.timeoutProbeSec), (x) => this.escaped(x).length > 0);
    // An edit that went through rewrote a planted secret: put it back for the probes and the checks that follow.
    if (t.kind === "edit") this.restoreHarnessFiles();
    return { args, r, changed: this.escaped(d) };
  }

  /**
   * One move or copy of a file that is not the harness's own into the root. The source is a secret outside the root and the
   * destination is a fresh name inside it, so the call can only succeed when the server skipped the check on its source.
   * Judged by the observer: the secret disappearing from where it lived, or its token turning up at the destination.
   * Both secrets are written back afterwards, because the link and read checks that follow still need them.
   */
  private async moveSourceAt(ctl: Ctl, src: string, tok: string, leaf: string, form: "abs" | "rel"): Promise<{ args?: Record<string, unknown>; r?: CallResult; changed: string[]; landed: boolean }> {
    const sb = this.sb;
    const dest = form === "abs" ? rawJoin(sb.root, leaf) : leaf;
    const args = this.args(ctl.t, { path: src, dest });
    if (!args) return { changed: [], landed: false };
    const before = await sb.fs.snapshot(["canary", "root-evil", "root"]);
    let landed = false;
    let changed: string[] = [];
    let r: CallResult | undefined;
    try {
      r = await this.call(ctl.t, args);
      const d = await settledDiff(sb.fs, before, ["canary", "root-evil", "root"], settleMsFor(this.ctx.timeoutProbeSec), (x) => x.removed.length + x.changed.length + x.added.filter((k) => k.includes(`/${leaf}`)).length > 0);
      changed = [...d.removed, ...d.changed].filter((k) => !k.startsWith("root/"));
      for (const key of d.added.filter((k) => k.startsWith("root/") && k.endsWith(`/${leaf}`))) {
        try {
          // A moved link is a link, not the secret: readFile would follow it to the canary and call that exfiltration. Only a regular file counts.
          if (!(await lstat(sb.fs.resolve(key))).isFile()) continue;
          const body = (await readFile(sb.fs.resolve(key))).toString("utf8");
          if ([sb.tokens.canary, sb.tokens.evil].some((x) => body.includes(x))) {
            landed = true;
            changed.push(key);
          }
        } catch {
          /* removed again already: the observer's removal of the source is the signal */
        }
      }
    } finally {
      try {
        rmSync(rawJoin(sb.root, leaf), { force: true });
      } catch {
        /* nothing to remove */
      }
      // The secrets go back, and so do the file links: a move of the link itself takes it out of the root.
      this.restoreHarnessFiles();
    }
    return { args, r, changed, landed };
  }

  async writeEscape(): Promise<CheckResult> {
    const m = metaFor(this.ctx, FS_META["fs-write-escape"]);
    if (m.disabled) return result(m, "fs", "na", "", []);
    this.begin();
    const evidence: Evidence[] = [];
    const writers = this.tools.filter((t) => t.kind === "write" || t.kind === "mkdir" || t.kind === "copy" || t.kind === "edit");
    if (!writers.length) return result(m, "fs", "na", "no tool takes file content, creates files or edits them, so there was nothing to write outside the root", evidence, this.tally.coverage());
    if (isRootless(this.ctx)) evidence.push(this.rootlessEvidence());
    this.writers = [];
    this.controlsAttempted = true;
    for (const t of writers) {
      const ctl = t.kind === "edit" ? await this.controlEdit(t, evidence) : await this.controlWrite(t, evidence);
      if (ctl) this.writers.push(ctl);
    }
    if (!this.writers.length) {
      const said = this.tally.notCovered.slice(0, 2).map((n) => `${n.tool}: ${n.reason}`).join("; ");
      return result(m, "fs", "inconclusive", `no write tool could ${writers.every((t) => t.kind === "edit") ? "edit the harness's file {sandbox}/ok.txt" : "create a file inside {sandbox}"}, so escape attempts could not be judged${said ? `; ${said}` : ""}${this.tildeNote()}`, evidence, this.tally.coverage());
    }

    const leaks: string[] = [];
    const st = new ProbeStats();
    for (const ctl of this.writers) {
      const t = ctl.t;
      const tok = token();
      // An edit needs a file that exists: it is aimed at the planted secrets, so its leaf is secret.txt.
      const leaf = (i: number) => (t.kind === "edit" ? "secret.txt" : t.kind === "mkdir" ? `mk-${tok}-${i}` : `w-${tok}-${i}.txt`);
      const blocked: string[] = [];
      const array = hasArrayParam(t);
      st.removed += removedByConfig(this.ctx, "fs-write-escape", WRITE_PROBES, ctl.rel, array);
      const planned = plan(this.ctx, "fs-write-escape", WRITE_PROBES, leaf, { rel: ctl.rel, tok, style: ctl.style, array });
      // The first slot of an array probe: a fresh file inside the root, in the form the tool's control took.
      const first = ctl.style === "abs" ? rawJoin(this.sb.root, `w-first-${tok}.txt`) : `w-first-${tok}.txt`;
      for (const [i, p] of planned.entries()) {
        if (p.refusedReason) {
          st.refused++;
          evidence.push(this.ev(t, p.text, p.refusedReason, "static", { code: "fs.skipped" }));
          continue;
        }
        if (this.sb.sizeExceeded.aborted) break;
        const rest = planned.slice(i).filter((x) => !x.refusedReason).length;
        if (this.stalled(t.tool.name)) {
          st.stalled += rest;
          break;
        }
        const w = await this.writeAt(ctl, p.path, tok, p.rel ? "rel" : ctl.style, { old: p.kind === "prefix" ? this.sb.tokens.evil : this.sb.tokens.canary, ...(p.array ? { first } : {}) });
        if (!w.args) {
          st.unbuilt += rest;
          break;
        }
        // A write that lands after the timeout is still a write: what the observer saw counts whether or not the server answered.
        if (!st.call(t.tool.name, w.r)) {
          evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, w.r?.timedOut ? "no reply before the timeout, so this probe says nothing about the server" : "the connection closed during the call, so this probe says nothing about the server", "response", { args: w.args, code: "fs.write-unanswered" }));
        }
        if (w.changed.length) {
          leaks.push(`${t.tool.name} via ${p.id}`);
          evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, `escaped: the harness saw ${w.changed.slice(0, 3).join(", ")} change outside the root`, "fs-observer", { args: w.args, r: w.r, code: "fs.write-escape" }));
        } else if (w.r && !w.r.timedOut && !w.r.closed) blocked.push(p.id);
      }
      if (t.kind === "copy") await this.moveProbes(ctl, tok, leaks, blocked, evidence, st);
      if (blocked.length) evidence.push({ probe: `${t.tool.name}: ${blocked.length} variant(s)`, outcome: `nothing appeared in the canary directory or the sibling root for: ${blocked.join(", ")}`, verifiedBy: "fs-observer", tool: t.tool.name, code: "fs.write-blocked" });
    }
    if (this.sb.sizeExceeded.aborted) {
      return result(m, "fs", "fail", "the sandbox grew past its size cap while writing, so the probes were stopped", evidence, this.tally.coverage());
    }
    if (!leaks.length && st.sent === 0) {
      const none = st.none(this.writers.map((c) => c.t.tool.name).join(", "));
      return result(m, "fs", "inconclusive", none.summary, [...evidence, ...none.evidence], this.tally.coverage());
    }
    return result(
      m,
      "fs",
      leaks.length ? "fail" : "pass",
      leaks.length ? `a write landed outside the allowed root: ${leaks.slice(0, 5).join("; ")}` : `${st.sent} write attempts aimed outside the root left the canary directory and the sibling root unchanged${st.suffix()}`,
      evidence,
      this.tally.coverage(),
    );
  }

  /** The move and copy probes of MOVE_PROBES for one tool; what happened to them is recorded in `st`. */
  private async moveProbes(ctl: Ctl, tok: string, leaks: string[], blocked: string[], evidence: Evidence[], st: ProbeStats): Promise<void> {
    const sb = this.sb;
    const t = ctl.t;
    const cfg = corpusOf(this.ctx, "fs-write-escape");
    const dst = (i: number) => `mv-${tok}-${i}.txt`;
    for (const [i, p] of MOVE_PROBES.entries()) {
      if (cfg.remove.includes(p.id) || cfg.remove.includes(p.text)) {
        if (!("relativeOnly" in p) || ctl.rel) st.removed++;
        continue;
      }
      if ("relativeOnly" in p && !ctl.rel) continue;
      if (sb.sizeExceeded.aborted) break;
      if (this.stalled(t.tool.name)) {
        st.stalled++;
        continue;
      }
      const form = "relativeOnly" in p ? "rel" : ctl.style;
      let src: string;
      // The destination slot: the harness's own file is moved or copied to a spelling of a path in the canary directory.
      const dest =
        p.id === "move-copy" ? rawJoin(sb.canary, `moved-${tok}`) : p.id === "move-dest-pct" ? `${fwd(sb.root)}/%2e%2e/canary/moved-${tok}` : p.id === "move-dest-fileurl" ? fileUrl(rawJoin(sb.canary, `moved-${tok}`)) : undefined;
      if (dest !== undefined) {
        if (!insideSandbox(sb, dest)) {
          st.refused++;
          continue;
        }
        const w = await this.writeAt(ctl, dest, tok, ctl.style);
        if (!w.args) {
          st.unbuilt++;
          break;
        }
        st.call(t.tool.name, w.r);
        if (w.changed.length) {
          leaks.push(`${t.tool.name} via ${p.id}`);
          evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, `escaped: the harness saw ${w.changed.slice(0, 3).join(", ")} change outside the root`, "fs-observer", { args: w.args, r: w.r, code: "fs.write-escape" }));
        } else if (w.r && !w.r.timedOut && !w.r.closed) blocked.push(p.id);
        continue;
      }
      if (p.id === "move-src-canary") src = form === "abs" ? sb.files.canary : "../canary/secret.txt";
      else if (p.id === "move-src-evil") src = form === "abs" ? sb.files.evil : "../root-evil/secret.txt";
      else src = "../canary/secret.txt";
      if (form === "abs" && !insideSandbox(sb, src)) {
        st.refused++;
        continue;
      }
      const w = await this.moveSourceAt(ctl, src, tok, dst(i), form);
      if (!w.args) {
        st.unbuilt++;
        break;
      }
      st.call(t.tool.name, w.r);
      if (w.changed.length) {
        leaks.push(`${t.tool.name} via ${p.id}`);
        const left = w.changed.some((k) => !k.startsWith("root/"));
        const how = left && w.landed ? "the secret file was moved into the root" : left ? "the secret file left its directory" : "the secret file's content turned up inside the root";
        evidence.push(this.ev(t, `${t.tool.name}(${p.id}: ${p.text})`, `escaped: ${how} (the harness saw ${w.changed.slice(0, 3).join(", ")} change)`, "fs-observer", { args: w.args, r: w.r, code: "fs.write-escape" }));
      } else if (w.r && !w.r.timedOut && !w.r.closed) blocked.push(p.id);
    }
  }

  // ---- links --------------------------------------------------------------------------------------------

  /**
   * A link that stays inside the root: `link-in` points at the subdirectory `link-ok`, which holds a copy of the control file.
   * A tool that reads or writes through it proves the link path works, so a refusal of the links that lead out is about
   * where they lead. Returns undefined when the link could not be made; `cleanup` removes both again.
   */
  private makeInnerLink(): { dir: string; cleanup(): void } | undefined {
    const sb = this.sb;
    const real = rawJoin(sb.root, "link-ok");
    const link = rawJoin(sb.root, "link-in");
    try {
      mkdirSync(real, { recursive: true });
      writeFileSync(rawJoin(real, "ok.txt"), sb.tokens.control);
      symlinkSync(real, link, WIN ? "junction" : "dir");
    } catch {
      rmSync(real, { recursive: true, force: true });
      return undefined;
    }
    return {
      dir: link,
      cleanup: () => {
        try {
          if (lstatSync(link).isSymbolicLink()) {
            try {
              unlinkSync(link);
            } catch {
              rmdirSync(link);
            }
          }
        } catch {
          /* already gone */
        }
        rmSync(real, { recursive: true, force: true });
      },
    };
  }

  /** The control for one tool: the same kind of call as the link probes, through a link that stays inside the root. */
  private async linkControl(ctl: Ctl, inner: { dir: string }, evidence: Evidence[]): Promise<boolean> {
    const sb = this.sb;
    const t = ctl.t;
    const form = (p: string) => (ctl.style === "abs" ? p : relative(sb.root, p) || ".");
    if (t.kind === "edit") {
      // The copy of the control file that lives behind the inside link: replace its token and see it change.
      const real = rawJoin(sb.root, "link-ok", "ok.txt");
      const target = form(rawJoin(inner.dir, "ok.txt"));
      const args = this.editArgs(t, target, sb.tokens.control, `sm-edited-${token("e")}`);
      if (!args) return false;
      const before = await sb.fs.snapshot(["root"]);
      const r = await this.call(t, args, this.probeMs, true);
      const d = await settledDiff(sb.fs, before, ["root"], settleMsFor(this.ctx.timeoutProbeSec), (x) => x.changed.some((k) => k.endsWith("/link-ok/ok.txt")));
      const ok = d.changed.some((k) => k.endsWith("/link-ok/ok.txt"));
      try {
        writeFileSync(real, sb.tokens.control);
      } catch {
        /* the link directory is gone */
      }
      if (ok) this.tally.note(t.tool.name);
      evidence.push(this.ev(t, `control: ${t.tool.name} edits {sandbox}/link-in/ok.txt (a link that stays inside the root)`, ok ? "the harness saw the file change inside the root, so an edit through a link works" : "the file did not change, so a refusal of the links that lead out proves little for this tool", "fs-observer", { args, r, code: ok ? "fs.link.control" : "fs.link.control-failed" }));
      return ok;
    }
    if (t.kind === "write" || t.kind === "mkdir" || t.kind === "copy") {
      const tok = token();
      const leaf = t.kind === "mkdir" ? `lw-ctl-${tok}` : `lw-ctl-${tok}.txt`;
      const target = form(rawJoin(inner.dir, leaf));
      const args = this.args(t, t.kind === "mkdir" ? { path: target } : t.kind === "copy" ? { path: await this.inRootSource(tok, ctl.style), dest: target } : { path: target, paths: [target], content: tok });
      if (!args) return false;
      const before = await sb.fs.snapshot(["root"]);
      const r = await this.call(t, args, this.probeMs, true);
      const d = await settledDiff(sb.fs, before, ["root"], settleMsFor(this.ctx.timeoutProbeSec), (x) => x.added.some((k) => k.endsWith(`/${leaf}`)));
      const ok = d.added.some((k) => k.endsWith(`/${leaf}`));
      if (ok) this.tally.note(t.tool.name);
      evidence.push(this.ev(t, `control: ${t.tool.name} creates {sandbox}/link-in/${leaf} (a link that stays inside the root)`, ok ? "the harness saw the file appear inside the root, so a write through a link works" : "no file appeared, so a refusal of the links that lead out proves little for this tool", "fs-observer", { args, r, code: ok ? "fs.link.control" : "fs.link.control-failed" }));
      return ok;
    }
    const path = form(t.kind === "list" ? inner.dir : rawJoin(inner.dir, "ok.txt"));
    const args = this.args(t, { path, paths: [path] }, ctl.filler);
    if (!args) return false;
    const r = await this.call(t, args, this.probeMs, true);
    const ok = this.controlGood(t.kind, r);
    if (ok) this.tally.note(t.tool.name);
    evidence.push(this.ev(t, `control: ${t.tool.name} on {sandbox}/link-in${t.kind === "list" ? "" : "/ok.txt"} (a link that stays inside the root)`, ok ? "the tool read the control file through a link that stays inside the root, so the link path works" : "the control file was not reached through the inside link, so a refusal of the links that lead out proves little for this tool", "response", { args, r, code: ok ? "fs.link.control" : "fs.link.control-failed" }));
    return ok;
  }

  /** What a link probe leaves behind when nothing escaped: the server's own words, so a pass shows what was exercised. */
  private refusalEvidence(t: PathTool, probe: string, args: Record<string, unknown>, r: CallResult, by: VerifiedBy = "response"): Evidence {
    const said = oneLine(String(unexpand(this.sb, r.text || r.rpcError || "")), 100);
    const reply = refused(r) ? `the server refused: ${said || "(an error with no text)"}` : `the server answered without anything from outside the root${said ? `: ${said}` : ""}`;
    return this.ev(t, probe, by === "fs-observer" ? `nothing appeared outside the root; ${reply}` : reply, by, { args, r, code: "fs.link-refused" });
  }

  async linkEscape(): Promise<CheckResult> {
    const m = metaFor(this.ctx, FS_META["fs-link-escape"]);
    if (m.disabled) return result(m, "fs", "na", "", []);
    this.begin();
    const sb = this.sb;
    const evidence: Evidence[] = [];
    const dirOk = sb.links.dir.ok;
    const fileOk = sb.links.file.ok;
    // The dangling link is absent from a hand-built sandbox that predates it; every write probe that needs it is skipped then.
    const danglingOk = Boolean(sb.links.dangling?.ok) && Boolean(sb.files.linkDangling);
    // Where the link points is read now, before any probe can replace it.
    if (danglingOk) void this.danglingTarget;
    if (!dirOk && !fileOk) {
      return result(m, "fs", "na", `the harness could not create a link in the sandbox (${sb.links.dir.reason ?? sb.links.file.reason ?? "unknown reason"}), so links were not tested`, evidence);
    }
    if (!fileOk) evidence.push({ probe: "file symbolic link", outcome: `not run: ${sb.links.file.reason ?? "the link could not be created"}`, verifiedBy: "static", code: "fs.link.symlink-na" });
    if (!dirOk) evidence.push({ probe: "directory link", outcome: `not run: ${sb.links.dir.reason ?? "the link could not be created"}`, verifiedBy: "static", code: "fs.link.dir-na" });
    if (!this.readers.length && !this.writers.length) {
      if (this.controlsAttempted) return result(m, "fs", "inconclusive", "no file tool passed its control call, so links could not be judged", evidence, this.tally.coverage());
      const any = this.tools.some((t) => READ_KINDS.includes(t.kind) || t.kind === "write" || t.kind === "mkdir" || t.kind === "copy" || t.kind === "edit");
      return result(m, "fs", "na", any ? "no control call was made (the read and write checks are disabled), so links could not be judged" : "no tool reads or writes files, so there was nothing to send through a link", evidence, this.tally.coverage());
    }

    const leaks: string[] = [];
    const parts: string[] = [];
    let sent = 0;
    const linkKind = sb.links.dir.kind === "junction" ? "junction" : "symbolic link to directory";
    const inner = this.makeInnerLink();
    if (!inner) evidence.push({ probe: "control: a link that stays inside the root", outcome: "not run: the harness could not create one, so a refusal of the links that lead out is not shown to be about where they lead", verifiedBy: "static", code: "fs.link.control-na" });
    // Per tool: did the inside link work, and did every answer to a link that leads out read as a refusal of the link?
    const proof = new Map<string, { controlled: boolean; policy: boolean; n: number }>();
    const note = (tool: string, r: CallResult): void => {
      const p = proof.get(tool);
      if (p) p.n++;
      // A missing file or a bare transport error is not the server saying no to a link.
      if (p && !(refused(r) && !/\b(enoent|no such file|not found|does not exist)\b/i.test(r.text.slice(0, 300)))) p.policy = false;
    };
    try {
      for (const ctl of this.readers) {
        const t = ctl.t;
        proof.set(t.tool.name, { controlled: inner ? await this.linkControl(ctl, inner, evidence) : false, policy: true, n: 0 });
        const targets: { id: string; text: string; path: string }[] = [];
        if (dirOk) targets.push({ ...LINK_READ_PROBES[0], ...(t.kind === "list" ? { text: `{sandbox}/link-dir (${DIR_LINK} to {canary})` } : {}), path: t.kind === "list" ? sb.files.linkDir : rawJoin(sb.files.linkDir, "secret.txt") });
        if (fileOk && t.kind !== "list") targets.push({ ...LINK_READ_PROBES[1], path: sb.files.linkFile });
        for (const extra of corpusOf(this.ctx, "fs-link-escape").add) targets.push({ id: `custom-${targets.length}`, text: extra, path: expandTemplate(envOf(sb), token(), extra) });
        for (const p of targets) {
          if (!insideSandbox(sb, p.path)) continue;
          if (this.stalled(t.tool.name)) break;
          const rel = ctl.style === "rel" ? relative(sb.root, p.path) || "." : p.path;
          const args = this.args(t, { path: rel, paths: [rel] }, ctl.filler);
          if (!args) break;
          const r = await this.call(t, args);
          sent++;
          note(t.tool.name, r);
          if (t.kind === "stat") {
            // A tool that follows the link and tells the caller where it ended up is leaking structure, not content: a part.
            const exposes = !refused(r) && fold(fwd(r.text)).includes(fold(fwd(sb.canary)));
            if (exposes) {
              parts.push(`${t.tool.name} on ${p.id}`);
              evidence.push(this.ev(t, `${t.tool.name}(${p.text})`, "the response names the link target", "response", { args, r, code: "fs.link.stat-target" }));
            } else if (!this.leakedBy(t.kind, r)) evidence.push(this.refusalEvidence(t, `${t.tool.name}(${p.text})`, args, r));
            continue;
          }
          const why = this.leakedBy(t.kind, r);
          if (why) {
            leaks.push(`${t.tool.name} via ${p.id}`);
            evidence.push(this.ev(t, `${t.tool.name}(${p.text})`, `escaped through a ${p.id === "link-dir" ? linkKind : "link"}: ${why}`, "response", { args, r, code: "fs.link-escape" }));
          } else evidence.push(this.refusalEvidence(t, `${t.tool.name}(${p.text})`, args, r));
        }
      }
      for (const ctl of this.writers) {
        const t = ctl.t;
        if (!dirOk && !fileOk && !danglingOk) break;
        const form = (p: string) => (ctl.style === "abs" ? p : relative(sb.root, p) || ".");
        const tok = token();
        // What a link can be asked to do for this kind of tool. Each probe is judged by the file observer: a change in the canary directory is the escape.
        const probes: { id: string; text: string; via: string; run(): Promise<{ args?: Record<string, unknown>; r?: CallResult; changed: string[] }> }[] = [];
        if (t.kind === "write" || t.kind === "mkdir") {
          const leaf = t.kind === "mkdir" ? `lw-${tok}` : `lw-${tok}.txt`;
          if (dirOk) probes.push({ ...LINK_WRITE_PROBE, via: linkKind, run: () => this.writeAt(ctl, form(rawJoin(sb.files.linkDir, leaf)), tok) });
        }
        if (t.kind === "write") {
          if (fileOk) probes.push({ ...LINK_FILE_WRITE_PROBE, via: "symbolic link to a file", run: async () => ({ ...(await this.writeAt(ctl, form(sb.files.linkFile), tok)) }) });
          if (danglingOk) probes.push({ ...DANGLING_WRITE_PROBE, via: "symbolic link to a file that does not exist yet", run: () => this.writeAt(ctl, form(sb.files.linkDangling), tok) });
        }
        if (t.kind === "edit") {
          if (dirOk) probes.push({ id: "link-dir-edit", text: `{sandbox}/link-dir/secret.txt (edit through the ${DIR_LINK})`, via: linkKind, run: () => this.writeAt(ctl, form(rawJoin(sb.files.linkDir, "secret.txt")), tok, ctl.style, { old: sb.tokens.canary }) });
          if (fileOk) probes.push({ id: "link-file-edit", text: "{sandbox}/link.txt (edit through the symbolic link to {canary}/secret.txt)", via: "symbolic link to a file", run: () => this.writeAt(ctl, form(sb.files.linkFile), tok, ctl.style, { old: sb.tokens.canary }) });
        }
        if (t.kind === "copy") {
          if (dirOk) probes.push({ ...MOVE_LINK_PROBES[0], via: linkKind, run: () => this.writeAt(ctl, form(rawJoin(sb.files.linkDir, `moved-${tok}.txt`)), tok, ctl.style) });
          if (fileOk) {
            probes.push({
              ...MOVE_LINK_PROBES[1],
              via: "symbolic link to a file",
              run: async () => {
                const w = await this.moveSourceAt(ctl, form(sb.files.linkFile), tok, `mv-${tok}-link.txt`, ctl.style);
                return w;
              },
            });
          }
        }
        if (!probes.length) {
          this.tally.skip(t.tool.name, "no link of a kind this tool can be sent through could be created");
          continue;
        }
        proof.set(t.tool.name, { controlled: inner ? await this.linkControl(ctl, inner, evidence) : false, policy: true, n: 0 });
        for (const pr of probes) {
          if (this.stalled(t.tool.name)) break;
          let w: { args?: Record<string, unknown>; r?: CallResult; changed: string[] };
          try {
            w = await pr.run();
          } finally {
            // A write through the file links changes the secret or creates the dangling target; the links and files go back as they were.
            this.cleanDanglingTarget();
            this.restoreHarnessFiles();
          }
          if (!w.args || !w.r) continue;
          sent++;
          note(t.tool.name, w.r);
          if (w.changed.length) {
            leaks.push(`${t.tool.name} via ${pr.id}`);
            evidence.push(this.ev(t, `${t.tool.name}(${pr.text})`, `escaped through a ${pr.via}: the harness saw ${w.changed.slice(0, 3).join(", ")} ${pr.id === "move-src-link" ? "turn up in" : "change in"} ${pr.id === "move-src-link" ? "the root" : "the canary directory or the sibling root"}`, "fs-observer", { args: w.args, r: w.r, code: "fs.link-escape" }));
          } else evidence.push(this.refusalEvidence(t, `${t.tool.name}(${pr.text})`, w.args, w.r, "fs-observer"));
        }
      }
    } finally {
      this.cleanDanglingTarget();
      this.restoreHarnessFiles();
      inner?.cleanup();
    }
    const notRun = !fileOk ? ` (the file symlink was not created: ${sb.links.file.reason ?? "unknown reason"}; only the ${linkKind} was tested)` : !dirOk ? ` (the directory link was not created: ${sb.links.dir.reason ?? "unknown reason"}; only the file symlink was tested)` : "";
    if (this.readControlFailed && !this.readers.length && !leaks.length) {
      return result(m, "fs", "inconclusive", `the read controls failed, so links could not be judged${notRun}`, evidence, this.tally.coverage());
    }
    if (leaks.length) return result(m, "fs", "fail", `a link inside the root led to a file outside it: ${leaks.slice(0, 4).join("; ")}${notRun}`, evidence, this.tally.coverage());
    if (parts.length) return result(m, "fs", "part", `no content escaped, but the server reveals where a link points: ${parts.join("; ")}${notRun}`, evidence, this.tally.coverage());
    if (!sent) return result(m, "fs", "na", `no tool could be sent a link${notRun}`, evidence, this.tally.coverage());
    // A refusal only counts as the server's answer to the link when the same kind of call works through a link that stays inside,
    // or when every answer is plainly a refusal (a server that refuses every link is safe, and says so).
    const unproved = [...proof].filter(([, p]) => !p.controlled && !p.policy).map(([tool]) => tool);
    if (unproved.length) {
      const proved = proof.size - unproved.length;
      const why = `${unproved.join(", ")} could not use a link that stays inside the root, and its answers to the links that lead out are not clear refusals, so a refusal cannot be told from an unrelated error`;
      return result(m, "fs", proved ? "part" : "inconclusive", `no content escaped, but ${why}${notRun}`, evidence, this.tally.coverage());
    }
    const blanket = [...proof].filter(([, p]) => !p.controlled && p.n > 0).map(([tool]) => tool);
    const also = blanket.length ? `; ${blanket.join(", ")} also refused a link that stays inside the root, so it may refuse every link` : "";
    return result(m, "fs", "pass", `${sent} reads, writes, edits and moves through a ${dirOk ? linkKind : "symbolic link"} that points out of the root were refused${also}${notRun}`, evidence, this.tally.coverage());
  }

  // ---- size cap -----------------------------------------------------------------------------------------

  async sizeCap(): Promise<CheckResult> {
    const m = metaFor(this.ctx, FS_META["fs-size-cap"]);
    if (m.disabled) return result(m, "fs", "na", "", []);
    this.begin();
    const evidence: Evidence[] = [];
    const cfg = this.ctx.config.checks?.["fs-size-cap"];
    const fileMib = Math.max(1, Number(cfg?.file_mib ?? 64));
    const passMib = Math.max(1, Number(cfg?.pass_mib ?? 16));
    const readers = this.readers.filter((c) => c.t.kind === "read");
    if (!readers.length) {
      if (this.readControlFailed) {
        return result(m, "fs", "inconclusive", `no read tool passed its control call, so a large read was not attempted${this.readControlSaid}`, evidence, this.tally.coverage());
      }
      // A content reader whose control failed while a list or stat tool's passed, at any confidence: "no tool returns file contents" would be untrue.
      if (this.readFailed.length) {
        const names = this.readFailed.map((s) => s.tool).join(", ");
        return result(m, "fs", "inconclusive", `the control call of ${names} failed, so a large read was not attempted (${this.readFailed[0].why})`, evidence, this.tally.coverage());
      }
      return result(m, "fs", "na", "no tool returns file contents, so there is no read to size", evidence, this.tally.coverage());
    }
    let big: string;
    try {
      big = await this.sb.bigFile(fileMib);
    } catch (e) {
      return result(m, "fs", "inconclusive", `the harness could not create the ${fileMib} MiB test file: ${(e as Error).message}`, evidence);
    }
    const verdicts: Verdict[] = [];
    const lines: string[] = [];
    for (const ctl of readers) {
      const t = ctl.t;
      const p = ctl.style === "abs" ? big : "big.bin";
      const args = this.args(t, { path: p, paths: [p] });
      if (!args) continue;
      const r = await this.call(t, args, SIZE_CALL_MS);
      const dropped = r.closed || r.timedOut || /ReadBuffer exceeded|connection closed|timed out/i.test(r.rpcError ?? "");
      // What the transport says, when it says (CallResult.transportError, seam S4); without it the old wording stands for a drop.
      const transport = (r as { transportError?: string }).transportError ?? r.rpcError ?? "";
      const cause = !dropped ? undefined : /exceeded|too large|message size|ReadBuffer/i.test(transport) ? "limit" : r.closed ? "exited" : r.timedOut ? "timeout" : undefined;
      const v = sizeVerdict({ bytes: Buffer.byteLength(r.text), dropped, refused: !dropped && refused(r) && Buffer.byteLength(r.text) < 64 * KIB, passMib, fileMib, ...(cause ? { cause } : {}) });
      verdicts.push(v.verdict);
      lines.push(`${t.tool.name}: ${v.why}`);
      evidence.push(this.ev(t, `${t.tool.name}({sandbox}/big.bin, ${fileMib} MiB)`, v.why, "response", { args, r: { ...r, text: dropped ? "" : r.text.slice(0, 200) }, code: "fs.size-cap" }));
      if (dropped) await this.keeper.drop();
    }
    if (!verdicts.length) return result(m, "fs", "inconclusive", "no read call could be built for the large file", evidence, this.tally.coverage());
    const v = worst(verdicts);
    return result(m, "fs", v, lines.join("; "), evidence, this.tally.coverage());
  }
}

// ---------------------------------------------------------------------------------------------------------
// describe(), applies(), run()
// ---------------------------------------------------------------------------------------------------------

function doc(m: Meta, o: Omit<CheckDoc, "id" | "pack" | "label" | "critical" | "advisory" | "scope" | "since" | "status">): CheckDoc {
  return { id: m.id, pack: "fs", label: m.label, critical: m.critical, advisory: Boolean(m.advisory), scope: m.scope, since: SINCE, status: "shipped", ...o };
}

const CORPUS_KEYS = (id: string) => [`checks.${id}.enabled`, `checks.${id}.severity`, `checks.${id}.corpus.add`, `checks.${id}.corpus.remove`, "sandbox.enabled", "tools.overrides"];

export function describe(): CheckDoc[] {
  // What the run sends on this platform: this platform's separator, Windows-only entries marked, and one entry where two spellings are the same string.
  const probes = (list: PathProbe[]) => {
    const seen = new Set<string>();
    const out: { id: string; text: string; kind: string }[] = [];
    for (const p of list) {
      const text = shownText(p);
      if (!p.windowsOnly && seen.has(text)) continue;
      seen.add(text);
      out.push({ id: p.id, text: p.windowsOnly ? `${text} (Windows only)` : text, kind: p.kind });
    }
    return out;
  };
  return [
    doc(FS_META["fs-read-escape"], {
      verifiedBy: ["response", "static"],
      probes: [{ id: "control", text: "{sandbox}/ok.txt must be readable first, as an absolute path and as a root-relative one (base64 in the reply is decoded, and so are resource, image and audio blocks); otherwise the check is inconclusive, and so it is when a tool that reads files exists but cannot be called (a required parameter the harness cannot fill). A search or listing tool is asked with a pattern that matches both ok.txt and secret.txt: none, txt, *txt*, *, *.txt, the first that lists ok.txt. The root-relative probes run for every tool whose root-relative control worked, and the array probe for a tool with an array path parameter. A high-confidence read tool whose control failed makes the check a part, never a pass. A check in which no escape probe was answered (every call timed out, could not be built or was removed by config) is inconclusive, never a pass", kind: "control" }, ...probes(READ_PROBES)],
      thresholds: {},
      falsePositive: "A server deliberately configured to allow more than {sandbox} (a whole drive, the home directory) reads the canary legitimately; the pack requires {sandbox} in the server config (or server.rootless: true, for a server that works in its working directory) and is not applicable otherwise.",
      falseNegative: "Encodings and path forms outside the corpus (8.3 short names, device paths, unicode normalisation); tools the classifier did not treat as file tools. List tools count only when the listing shows secret.txt.",
      configKeys: CORPUS_KEYS("fs-read-escape"),
    }),
    doc(FS_META["fs-write-escape"], {
      verifiedBy: ["fs-observer", "static"],
      probes: [
        { id: "control", text: "a write to {sandbox}/w-ctl-<t>.txt must create the file, as an absolute path and as a root-relative one; otherwise the check is inconclusive. An edit tool has its own control: it must replace the control token in {sandbox}/ok.txt (a tool that needs a content hash cannot, and is listed as not covered). A check in which no escape probe was answered is inconclusive too. The write probes mirror the read corpus (dot-dot, evil-dot-dot, forward-slash, dot-slash, percent-encoded, file:// and backslash spellings, the array probe, and the Windows-only forms), so a server that decodes or strips a prefix after its root check is caught on a write as on a read. An edit tool is sent the same paths aimed at the planted secret files and replaces the planted token; the changed secret is the escape", kind: "control" },
        ...probes(WRITE_PROBES),
        ...MOVE_PROBES.map((p) => ({ id: p.id, text: `${p.text} (tools with a destination parameter)`, kind: p.kind })),
        // These run in fs-link-escape, where the link controls are; they are listed here too because they are writes (a move, a copy, a write through a link).
        ...[...MOVE_LINK_PROBES, LINK_FILE_WRITE_PROBE, DANGLING_WRITE_PROBE].map((p) => ({ id: p.id, text: `${p.text} (judged by fs-link-escape)`, kind: "link" })),
      ],
      thresholds: {},
      falsePositive: "A server configured with a wider root writes outside {sandbox} legitimately (the pack requires {sandbox} in the server config, or server.rootless: true).",
      falseNegative: "Writes outside the observed directories (the sandbox home and temp directory are observed, the real home is not). Delete tools are never probed by default; use a custom probe. Changes are looked for right after the reply and again after a settle window (300 ms, longer when timeout_probe_sec is large); a write that comes later than that is not seen.",
      configKeys: CORPUS_KEYS("fs-write-escape"),
    }),
    doc(FS_META["fs-link-escape"], {
      verifiedBy: ["response", "fs-observer", "static"],
      probes: [
        { id: "control", text: "the same read, write, move or edit through a link that stays inside {sandbox} must work; otherwise a refusal is only trusted when it is plainly a refusal", kind: "control" },
        ...LINK_READ_PROBES.map((p) => ({ ...p, kind: "link" })),
        { ...LINK_WRITE_PROBE, kind: "link" },
        { ...LINK_FILE_WRITE_PROBE, kind: "link" },
        { ...DANGLING_WRITE_PROBE, kind: "link" },
        ...MOVE_LINK_PROBES,
        { id: "stat-link", text: "stat on the link: a response that names the target is a part", kind: "link" },
      ],
      thresholds: {},
      falsePositive: "A server configured on purpose to follow links will fail; the check measures whether links are resolved before the root check.",
      falseNegative: "The directory link always runs. The file symlinks (and the dangling one) need Developer Mode or an elevated shell on Windows and are reported as not applicable (with the reason) when they cannot be created. Hard links and mounts are not tested.",
      configKeys: CORPUS_KEYS("fs-link-escape"),
    }),
    doc(FS_META["fs-size-cap"], {
      verifiedBy: ["response"],
      probes: [{ id: "big-file", text: "read {sandbox}/big.bin (64 MiB) with a 120 s timeout", kind: "size" }],
      thresholds: {
        file_mib: { default: 64, configKey: "checks.fs-size-cap.file_mib", standardLocked: true },
        pass_mib: { default: 16, configKey: "checks.fs-size-cap.pass_mib", standardLocked: true },
      },
      falsePositive: "A server meant to return whole large files is graded against a limit it never promised.",
      falseNegative: "Measures the size of the response only, not memory use. A dropped connection or a timeout counts as a fail. Low stakes; not a memory-safety test.",
      configKeys: [...CORPUS_KEYS("fs-size-cap").slice(0, 2), "checks.fs-size-cap.file_mib", "checks.fs-size-cap.pass_mib", "sandbox.max_mib"],
    }),
  ];
}

function applies(ctx: PackCtx): PackApplies {
  if (!ctx.sandbox || ctx.sandboxEnabled === false) return { ok: false, reason: "the sandbox is off (--no-sandbox), so the file probes would prove nothing" };
  if (ctx.config.server.url && !ctx.config.server.command) return { ok: false, reason: "the server is already running (HTTP), so it cannot be started with a sandbox root" };
  if (!pathTools(ctx).length) return { ok: false, reason: "no tool is classified as taking a file path with medium confidence or higher" };
  if (!configUsesSandbox(ctx)) {
    return { ok: false, reason: "the server config has no {sandbox} placeholder, so the harness cannot tell which directory the server is allowed to use (a server with a wider root would read the canary legitimately); pass {sandbox} as its directory argument, or, if the server has no root argument and works in its working directory, set server.rootless: true" };
  }
  return { ok: true };
}

async function guarded(m: Meta, ctx: PackCtx, f: () => Promise<CheckResult>): Promise<CheckResult> {
  try {
    return await f();
  } catch (e) {
    const meta = metaFor(ctx, m);
    return result(meta, "fs", "inconclusive", `the check stopped: ${(e as Error).message}`, []);
  }
}

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const runner = new FsRun(ctx, pathTools(ctx));
  const out: CheckResult[] = [];
  out.push(await guarded(FS_META["fs-read-escape"], ctx, () => runner.readEscape()));
  out.push(await guarded(FS_META["fs-write-escape"], ctx, () => runner.writeEscape()));
  out.push(await guarded(FS_META["fs-link-escape"], ctx, () => runner.linkEscape()));
  // Last: a response that exceeds the transport limit closes the session.
  out.push(await guarded(FS_META["fs-size-cap"], ctx, () => runner.sizeCap()));
  return out;
}

export const pack: Pack = { id: "fs", describe, applies, run };
export default pack;
