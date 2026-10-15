import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { DEFAULT_INHERITED_ENV_VARS, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { expand, type TemplateCtx } from "./config.js";
import { snapshotTree, snapshotTreeInfo, terminatePids, terminateRemembered, trackRoot, untrackRoot, type ProcInfo } from "./observers/process.js";
import { createTempCwd } from "./sandbox.js";
import type { ServerSpec, SqlTool } from "./types.js";

export { resolvePackage, type ResolvedPackage } from "./resolve.js";

export interface ToolInfo {
  name: string;
  title?: string;
  description?: string;
  inputSchema: { type?: string; properties?: Record<string, { type?: string | string[]; description?: string; [k: string]: unknown }>; required?: string[]; [k: string]: unknown };
}

export interface CallResult {
  isError: boolean;
  text: string;
  elapsedMs: number;
  /** The harness gave up waiting. A server error that mentions a timeout is not this. */
  timedOut: boolean;
  /** JSON-RPC level failure (protocol error), if any. Full text: callers scan it for secrets and truncate only what they display. */
  rpcError?: string;
  /** True when the server process or connection went away during the call. */
  closed: boolean;
  /**
   * Non-text content blocks (an embedded resource with a blob, an image, audio). `text` still shows them as `[resource uri]` or
   * `[image]`; this carries what is inside. `base64` is kept while the blocks of one result total under 8 MiB, beyond that only `bytes`.
   */
  blobs?: BlobBlock[];
  /**
   * The transport error that arrived while this call was in flight and says a message was lost to the size cap ("exceeded maximum size").
   * The net and fs packs read it to tell a reply the harness dropped from one the server never sent.
   */
  transportError?: string;
}

export interface BlobBlock {
  kind: "resource" | "image" | "audio";
  uri?: string;
  mime?: string;
  /** Decoded size. */
  bytes: number;
  base64?: string;
}

const VALIDATION_WORDS = /\b(invalid|expected|required|must be|missing|not valid|validation|unexpected|unrecognized|unknown (?:argument|parameter|property))\b/i;
const PARAM_WORDS = /\b(arguments?|params?|parameters?|input|propert(?:y|ies)|fields?|schema)\b/i;

/**
 * True when the call never reached the tool's behaviour: the protocol failed (JSON-RPC error, timeout, closed connection) or the reply is
 * a validation error (an `isError` text that says invalid, expected or required and names a parameter, or one of the keys that was sent).
 * Such a call exercised nothing, so it is not a valid call for coverage (the rule on `CheckCoverage.validCalls`).
 */
export function rejectedBeforeRunning(r: Pick<CallResult, "isError" | "text" | "rpcError" | "timedOut" | "closed">, args: Record<string, unknown> = {}): boolean {
  if (r.rpcError !== undefined || r.timedOut || r.closed) return true;
  if (!r.isError || !VALIDATION_WORDS.test(r.text)) return false;
  if (PARAM_WORDS.test(r.text)) return true;
  return Object.keys(args).some((k) => k.length > 1 && new RegExp(`\\b${k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(r.text));
}

export class SessionError extends Error {
  /** Set when the server's stderr looks like dependency drift (see driftHint). */
  hint?: string;
  /** Bounded copy of the server's stderr at the time of failure (for `<out>.stderr.log`). */
  stderr?: string;
}

/** The server answered, but not with something a valid MCP client can parse (reported as a protocol failure, not a harness failure). */
export class ProtocolViolation extends SessionError {}

const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;
const MAX_LIST_PAGES = 50;
/** tools/list is bounded in total, not only per page: no server legitimately lists more, and a harness that keeps them all would be the target of a flood. */
const MAX_LIST_TOOLS = 5000;
const MAX_LIST_BYTES = 32 * 1024 * 1024;
const MAX_BLOB_KEEP_BYTES = 8 * 1024 * 1024;
const MAX_STDERR_BYTES = 1024 * 1024;
const DRIFT = /ModuleNotFoundError|AttributeError|ImportError|Cannot find module|ERR_MODULE_NOT_FOUND/;

/** Server stderr that shows an import or module failure usually means a dependency moved under an unpinned launcher. */
export function driftHint(stderr: string): string | undefined {
  return DRIFT.test(stderr) ? "the server's dependencies may have drifted; pin them (uvx --with 'pkg<N', npx pkg@x.y.z)" : undefined;
}

export interface OpenOptions {
  extraEnv?: Record<string, string>;
  /** Startup budget for initialize and each tools/list page. Default 60 000 ms (`timeouts.connect_ms`). */
  connectTimeoutMs?: number;
  clientVersion?: string;
  /** Working directory of the server process (stdio). Default: the harness's cwd. */
  cwd?: string;
  /** Complete environment for the server (from sandbox.env()). With it, the SDK's inherited variables cannot leak in. */
  baseEnv?: Record<string, string>;
  /** "scrubbed" needs baseEnv. "inherit" passes the whole real environment. Omitted: the original behaviour. */
  envMode?: "scrubbed" | "inherit";
  /** Start the server in a fresh empty temp directory (removed on close) when no cwd is given. */
  cleanCwd?: boolean;
  /** Called every `progressEveryMs` while the server is still starting: "still starting the server (45s)…". */
  onProgress?: (message: string) => void;
  progressEveryMs?: number;
  /** List prompts and resources when the server advertises them. Default true. */
  listExtras?: boolean;
  /** Called with every chunk the stdio server writes to stderr (feeds the log observer). */
  onStderr?: (chunk: string) => void;
  /** HTTP: send no credential. Every header whose configured value holds a {bearer} placeholder is dropped. */
  anonymous?: boolean;
}

/**
 * `expand` plus the round 6 harness placeholders ({upstream}, {bearer}, {bearer:a}, {bearer:b}), filled from `ctx.vars` when the
 * caller supplied them. The config layer's own list names the same keys; until both agree this keeps them working in the files the
 * harness owns, and afterwards it is a no-op (nothing is left to fill).
 */
export function expandHarness(s: string, ctx: TemplateCtx): string {
  const filled = s.replace(/\{(upstream|bearer(?::[ab])?)\}/g, (m, key: string) => ctx.vars[key] ?? m);
  return expand(filled, ctx);
}

/** True when a header value holds a {bearer} placeholder (any identity). */
export const usesBearer = (value: string): boolean => /\{bearer(?::[ab])?\}/.test(value);

export interface PromptInfo {
  name: string;
  title?: string;
  description?: string;
  arguments?: { name: string; description?: string; required?: boolean }[];
}

export interface ResourceInfo {
  uri: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

/** Windows names are case-insensitive: one spelling per name, last layer wins, SDK spelling for the names the SDK adds. */
function mergeEnv(...layers: Record<string, string>[]): Record<string, string> {
  if (process.platform !== "win32") return Object.assign({}, ...layers);
  const sdk = new Set<string>(DEFAULT_INHERITED_ENV_VARS);
  const out: Record<string, string> = {};
  const at = new Map<string, string>();
  for (const layer of layers) {
    for (const [k, v] of Object.entries(layer)) {
      const up = k.toUpperCase();
      const prev = at.get(up);
      if (prev !== undefined) delete out[prev];
      const name = sdk.has(up) ? up : k;
      at.set(up, name);
      out[name] = v;
    }
  }
  return out;
}

/** The SDK merges its own allow-list from the real environment under whatever env it is given. Pre-empty every name we did not set. */
function fillSdkDefaults(env: Record<string, string>): Record<string, string> {
  const have = new Set(Object.keys(env).map((k) => (process.platform === "win32" ? k.toUpperCase() : k)));
  const out = { ...env };
  for (const k of DEFAULT_INHERITED_ENV_VARS) if (!have.has(k) && process.env[k] !== undefined) out[k] = "";
  return out;
}

function realEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith("=")) out[k] = v;
  return out;
}

async function listAll<T>(page: (cursor?: string) => Promise<{ items: T[]; next?: string }>): Promise<T[]> {
  const all: T[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let i = 0; i < MAX_LIST_PAGES; i++) {
    const r = await page(cursor);
    all.push(...r.items);
    cursor = r.next;
    if (!cursor) return all;
    if (seen.has(cursor)) throw new Error("pagination repeats a cursor and never ends");
    seen.add(cursor);
  }
  throw new Error(`more than ${MAX_LIST_PAGES} pages`);
}

const isSchemaError = (e: unknown): boolean => Array.isArray((e as { issues?: unknown } | null)?.issues);

/** zod 4 messages are long JSON; keep the first issue. */
function describeSchemaError(e: unknown): string {
  const issue = (e as { issues: { path?: unknown[]; message?: string }[] }).issues[0];
  const where = issue?.path?.length ? issue.path.join(".") : "response";
  return `${where}: ${issue?.message ?? "does not match the MCP schema"}`;
}

function textOf(content: unknown): string {
  const parts = Array.isArray(content) ? (content as Array<Record<string, unknown>>) : [];
  return parts
    .map((c) => {
      if (c.type === "text") return String(c.text ?? "");
      if (c.type === "resource") {
        const r = (c.resource ?? {}) as { uri?: string; text?: string };
        return r.text ?? `[resource ${r.uri ?? ""}]`;
      }
      if (c.type === "resource_link") return `[resource_link ${String(c.uri ?? "")}]`;
      return `[${String(c.type)}]`;
    })
    .join("\n");
}

/** The non-text blocks of a result, with their data while the running total stays under 8 MiB. */
function blobsOf(content: unknown): BlobBlock[] | undefined {
  const parts = Array.isArray(content) ? (content as Array<Record<string, unknown>>) : [];
  const out: BlobBlock[] = [];
  let kept = 0;
  const add = (kind: BlobBlock["kind"], data: unknown, uri?: unknown, mime?: unknown): void => {
    if (typeof data !== "string") return;
    const bytes = Buffer.byteLength(data, "base64");
    const keep = kept + bytes <= MAX_BLOB_KEEP_BYTES;
    if (keep) kept += bytes;
    out.push({ kind, ...(typeof uri === "string" ? { uri } : {}), ...(typeof mime === "string" ? { mime } : {}), bytes, ...(keep ? { base64: data } : {}) });
  };
  for (const c of parts) {
    if (c.type === "resource") {
      const r = (c.resource ?? {}) as { uri?: unknown; mimeType?: unknown; blob?: unknown };
      add("resource", r.blob, r.uri, r.mimeType);
    } else if (c.type === "image" || c.type === "audio") add(c.type, c.data, undefined, c.mimeType);
  }
  return out.length ? out : undefined;
}

/** The server's `Implementation` from `initialize`: every string in it is model-visible text, so the core pack scans it. */
export interface ServerInfo {
  name?: string;
  version?: string;
  title?: string;
  description?: string;
  websiteUrl?: string;
}

/** The instructions are kept to 1 MiB: nothing legitimate is longer, and the scan must stay bounded for a server that sends tens of MiB. */
const MAX_INSTRUCTIONS_CHARS = 1024 * 1024;

/** One line of a server's output as a report may show it: control characters replaced, bounded. */
function tidy(s: string, max = 120): string {
  const flat = s.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

/** What the SDK's stdio transport reports for a line on stdout that is not a JSON-RPC message: a JSON syntax error, or JSON that is not a message. */
function stdoutNoiseOf(e: unknown): string | undefined {
  if (e instanceof SyntaxError) return tidy(e.message);
  if (isSchemaError(e)) return `not a JSON-RPC message (${tidy(describeSchemaError(e), 100)})`;
  return undefined;
}

export class McpSession {
  tools: ToolInfo[] = [];
  serverInfo: ServerInfo = {};
  /** The `instructions` string from `initialize` (server-level guidance a client hands the model), or undefined when the server sent none. */
  instructions?: string;
  /**
   * Lines the server wrote to stdout that are not JSON-RPC (a banner, a log line, a stray print): how many arrived since the session
   * opened, and the first one. Strict stdio clients break on such a line. Always zero for an HTTP server.
   */
  stdoutNoise = { count: 0, first: "" };
  /** Replies the SDK rejected as not valid MCP (a tools/call result that does not match the schema): the total, and the first few as `tool: reason`. */
  invalidResults = { count: 0, samples: [] as string[] };
  /** Capabilities from `initialize`. */
  capabilities: Record<string, unknown> = {};
  /** Filled when the server advertises prompts / resources (addendum 16). */
  prompts: PromptInfo[] = [];
  resources: ResourceInfo[] = [];
  /** prompts/list or resources/list failed although advertised. Not a startup failure; the core pack may report it. */
  listErrors: string[] = [];
  closed = false;
  /** tools/call requests this session made, and how many of them reached the tool (see `rejectedBeforeRunning`). The harness reads both per pack. */
  calls = 0;
  processed = 0;
  private stderrBuf = "";
  private stderrAll = "";
  private transportError = "";
  /** A "maximum size" / "exceeded" transport error seen while a call was in flight; taken by callOnce. */
  private sizeCapError = "";
  private inFlight = 0;
  private _pid: number | null = null;
  /** The server's process tree as it was just after connecting, with command lines: what close() can still reach once a launcher has exited. */
  private tree: ProcInfo[] = [];
  private tempCwd?: { dir: string; remove(): Promise<void> };

  private constructor(private client: Client, private transport: StdioClientTransport | StreamableHTTPClientTransport) {}

  /** Process id of the stdio server (null for HTTP or before it started). */
  get pid(): number | null {
    return this._pid;
  }

  static async open(spec: ServerSpec, ctx: TemplateCtx, opts: OpenOptions = {}): Promise<McpSession> {
    const timeout = opts.connectTimeoutMs ?? 60_000;
    if (opts.envMode === "scrubbed" && !opts.baseEnv) throw new SessionError('envMode "scrubbed" needs baseEnv (build it with sandbox.env())');
    let tempCwd: McpSession["tempCwd"];
    let transport: StdioClientTransport | StreamableHTTPClientTransport;
    if (spec.url) {
      const headers = Object.fromEntries(
        Object.entries(spec.headers ?? {})
          .filter(([, v]) => !(opts.anonymous && usesBearer(v)))
          .map(([k, v]) => [k, expandHarness(v, ctx)]),
      );
      transport = new StreamableHTTPClientTransport(new URL(expandHarness(spec.url, ctx)), { requestInit: { headers } });
    } else {
      // The SDK's Windows allow-list has PATH but not PATHEXT or COMSPEC, so a launcher that has to find another
      // executable by bare name (uvx -> git) fails inside the harness while working from the user's shell.
      const specEnv = Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expandHarness(v, ctx)]));
      let env: Record<string, string>;
      if (opts.envMode === "inherit") env = mergeEnv(realEnv(), specEnv, opts.extraEnv ?? {});
      else if (opts.baseEnv) env = mergeEnv(fillSdkDefaults(opts.baseEnv), specEnv, opts.extraEnv ?? {});
      else {
        const winExec: Record<string, string> = {};
        if (process.platform === "win32") for (const k of ["PATHEXT", "COMSPEC"]) if (process.env[k] !== undefined) winExec[k] = process.env[k]!;
        env = { ...winExec, ...specEnv, ...(opts.extraEnv ?? {}) };
      }
      let cwd = opts.cwd;
      if (!cwd && opts.cleanCwd) {
        tempCwd = await createTempCwd();
        cwd = tempCwd.dir;
      }
      transport = new StdioClientTransport({
        command: expandHarness(spec.command!, ctx),
        args: (spec.args ?? []).map((a) => expandHarness(a, ctx)),
        env,
        ...(cwd ? { cwd } : {}),
        stderr: "pipe",
        // The default is 10 MB. A server that answers with 200k rows is a finding, not a transport failure.
        maxBufferSize: MAX_MESSAGE_BYTES,
      });
    }
    const client = new Client({ name: "sealmark", version: opts.clientVersion ?? "0.1.0" }, { capabilities: {} });
    const s = new McpSession(client, transport);
    s.tempCwd = tempCwd;
    if (transport instanceof StdioClientTransport) {
      transport.stderr?.on("data", (d: Buffer) => {
        const text = d.toString();
        s.stderrBuf = (s.stderrBuf + text).slice(-4000);
        s.stderrAll = (s.stderrAll + text).slice(-MAX_STDERR_BYTES);
        try {
          opts.onStderr?.(text);
        } catch {
          /* an observer must never take the session down */
        }
      });
    }
    if (transport instanceof StdioClientTransport) {
      // Take the pid the moment the process exists. Waiting for connect() to finish is too late: when initialize fails, the
      // client calls transport.close() before rethrowing, which forgets the process, and `transport.pid` is null by the
      // time the catch block below runs.
      const start = transport.start.bind(transport);
      transport.start = async () => {
        await start();
        const pid = (transport as StdioClientTransport).pid;
        if (pid !== null) {
          s._pid = pid;
          trackRoot(pid);
        }
      };
    }
    transport.onclose = () => {
      s.closed = true;
      if (s._pid !== null) untrackRoot(s._pid);
    };
    transport.onerror = (e: Error) => {
      // A line that is not JSON-RPC is the server's noise, counted for the protocol check; it is not why a later failure happened.
      const noise = transport instanceof StdioClientTransport ? stdoutNoiseOf(e) : undefined;
      if (noise !== undefined) {
        s.stdoutNoise.count++;
        s.stdoutNoise.first ||= noise;
        return;
      }
      s.transportError ||= e.message; // the first error is the cause; later ones are fallout
      if (s.inFlight > 0 && /maximum size|exceeded/i.test(e.message)) s.sizeCapError ||= e.message;
    };
    const started = Date.now();
    const ticker = opts.onProgress
      ? setInterval(() => opts.onProgress!(`still starting the server (${Math.round((Date.now() - started) / 1000)}s)…`), opts.progressEveryMs ?? 15_000)
      : undefined;
    ticker?.unref();
    try {
      await client.connect(transport, { timeout });
      s._pid = transport instanceof StdioClientTransport ? transport.pid : null;
      // A launcher (npx, uvx, a shell wrapper) may exit and leave the real server running with nothing linking it to the launcher's
      // pid any more. Remember the tree now, while the links are there, with each command line (the guard against pid reuse).
      if (s._pid !== null && !s.closed) s.tree = await snapshotTreeInfo(s._pid).catch(() => []);
      const tools: ToolInfo[] = [];
      let cursor: string | undefined;
      let listedBytes = 0;
      const seen = new Set<string>();
      for (let page = 0; page < MAX_LIST_PAGES; page++) {
        const listed = await client.listTools(cursor ? { cursor } : undefined, { timeout });
        tools.push(...(listed.tools as ToolInfo[]));
        listedBytes += JSON.stringify(listed).length;
        if (tools.length > MAX_LIST_TOOLS || listedBytes > MAX_LIST_BYTES) throw new ProtocolViolation(`tools/list returned more than ${MAX_LIST_TOOLS} tools (or ${MAX_LIST_BYTES / (1024 * 1024)} MiB)`);
        cursor = listed.nextCursor;
        if (!cursor) break;
        if (seen.has(cursor)) throw new ProtocolViolation("tools/list pagination repeats a cursor and never ends");
        seen.add(cursor);
        if (page === MAX_LIST_PAGES - 1) throw new ProtocolViolation(`tools/list returned more than ${MAX_LIST_PAGES} pages`);
      }
      s.tools = tools;
      const v = client.getServerVersion();
      s.serverInfo = { name: v?.name, version: v?.version, ...(v?.title ? { title: v.title } : {}), ...(v?.description ? { description: v.description } : {}), ...(v?.websiteUrl ? { websiteUrl: v.websiteUrl } : {}) };
      const instructions = client.getInstructions();
      if (typeof instructions === "string" && instructions) s.instructions = instructions.slice(0, MAX_INSTRUCTIONS_CHARS);
      s.capabilities = (client.getServerCapabilities() ?? {}) as Record<string, unknown>;
      if (opts.listExtras !== false) await s.listExtras(timeout);
    } catch (e) {
      if (transport instanceof StdioClientTransport) s._pid ??= transport.pid;
      const tail = s.stderrBuf.trim().split("\n").slice(-4).join(" | ");
      const full = s.stderrAll;
      await s.close();
      const suffix = tail ? ` (server stderr: ${tail})` : "";
      let err: SessionError;
      if (e instanceof SessionError) err = e instanceof ProtocolViolation ? new ProtocolViolation(e.message + suffix) : e;
      else if (isSchemaError(e)) err = new ProtocolViolation(`the server's reply is not valid MCP (${describeSchemaError(e)})${suffix}`);
      else err = new SessionError(`${(e as Error).message}${suffix}`);
      err.stderr ??= full;
      err.hint ??= driftHint(full);
      throw err;
    } finally {
      if (ticker) clearInterval(ticker);
    }
    return s;
  }

  /** Everything the server wrote to stderr, last 1 MiB. */
  stderrFull(): string {
    return this.stderrAll;
  }

  /** Hint text when the stderr so far looks like dependency drift. */
  driftHint(): string | undefined {
    return driftHint(this.stderrAll);
  }

  private async listExtras(timeout: number): Promise<void> {
    if (this.capabilities.prompts) {
      try {
        this.prompts = await listAll<PromptInfo>(async (cursor) => {
          const r = await this.client.listPrompts(cursor ? { cursor } : undefined, { timeout });
          return { items: r.prompts as PromptInfo[], next: r.nextCursor };
        });
      } catch (e) {
        this.listErrors.push(`prompts/list failed: ${isSchemaError(e) ? describeSchemaError(e) : (e as Error).message}`);
      }
    }
    if (this.capabilities.resources) {
      try {
        this.resources = await listAll<ResourceInfo>(async (cursor) => {
          const r = await this.client.listResources(cursor ? { cursor } : undefined, { timeout });
          return { items: r.resources as ResourceInfo[], next: r.nextCursor };
        });
      } catch (e) {
        this.listErrors.push(`resources/list failed: ${isSchemaError(e) ? describeSchemaError(e) : (e as Error).message}`);
      }
    }
  }

  async call(name: string, args: Record<string, unknown>, timeoutMs = 30_000): Promise<CallResult> {
    const r = await this.callOnce(name, args, timeoutMs);
    this.calls++;
    if (!rejectedBeforeRunning(r, args)) this.processed++;
    return r;
  }

  private async callOnce(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<CallResult> {
    this.inFlight++;
    this.sizeCapError = "";
    try {
      const r = await this.callRaw(name, args, timeoutMs);
      return this.sizeCapError ? { ...r, transportError: this.sizeCapError } : r;
    } finally {
      this.inFlight--;
    }
  }

  private async callRaw(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<CallResult> {
    const t0 = Date.now();
    try {
      const res = await this.client.callTool({ name, arguments: args }, undefined, { timeout: timeoutMs });
      const structured = res.structuredContent ? `\n${JSON.stringify(res.structuredContent)}` : "";
      const blobs = blobsOf(res.content);
      return { isError: Boolean(res.isError), text: textOf(res.content) + structured, elapsedMs: Date.now() - t0, timedOut: false, closed: this.closed, ...(blobs ? { blobs } : {}) };
    } catch (e) {
      const mcp = e instanceof McpError ? e : undefined;
      const closed = mcp?.code === ErrorCode.ConnectionClosed || this.closed;
      let msg = isSchemaError(e) ? `result is not valid MCP (${describeSchemaError(e)})` : ((e as Error).message ?? String(e));
      if (isSchemaError(e)) {
        this.invalidResults.count++;
        if (this.invalidResults.samples.length < 3) this.invalidResults.samples.push(`${name}: ${tidy(describeSchemaError(e), 100)}`);
      }
      if (closed && this.transportError) msg += ` [transport: ${this.transportError}]`;
      return { isError: true, text: "", elapsedMs: Date.now() - t0, timedOut: mcp?.code === ErrorCode.RequestTimeout && Date.now() - t0 >= timeoutMs - 250, rpcError: msg, closed };
    }
  }

  /** Cheap liveness probe: tools/list still answers. */
  async alive(timeoutMs = 10_000): Promise<boolean> {
    if (this.closed) return false;
    try {
      await this.client.listTools(undefined, { timeout: timeoutMs });
      return true;
    } catch {
      return false;
    }
  }

  /** Windows: the SDK kills only the direct child, so an npx wrapper would leave the real server running. */
  private killTree(): void {
    // Skip when the transport already saw the process exit: its pid may have been reused.
    if (process.platform === "win32" && this._pid && !this.closed) {
      try {
        spawnSync("taskkill", ["/PID", String(this._pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      } catch {
        /* already gone */
      }
    }
  }

  /**
   * Stops the server and, on POSIX, everything a launcher (npx, uvx, a shell wrapper) started under it, and waits until they are
   * gone. The SDK's own close() only closes stdin, then escalates to SIGTERM and SIGKILL on timers: after a failed start it
   * has already forgotten the process, and the timers do not survive process.exit. So the tree is listed first (once the
   * wrapper exits its children are no longer reachable by parent links), the SDK is given its graceful close, and whatever is
   * still running is then terminated explicitly: SIGTERM, then SIGKILL.
   */
  async close(): Promise<void> {
    this.killTree();
    const pid = this._pid;
    let tree: number[] = [];
    // Skip when the transport already saw the process exit: its pid may have been reused.
    if (process.platform !== "win32" && pid !== null && !this.closed) {
      const live = await snapshotTreeInfo(pid).catch(() => undefined);
      if (live?.length) {
        // The root is alive: refresh what is remembered with anything started since connecting.
        const now = new Set(live.map((p) => p.pid));
        this.tree = [...this.tree.filter((p) => !now.has(p.pid)), ...live];
      }
      tree = live?.length ? live.map((p) => p.pid) : await snapshotTree(pid).catch(() => [pid]);
    }
    try {
      await this.client.close();
    } catch {
      /* ignore */
    }
    if (tree.length) await terminatePids(tree, { graceMs: 2000 }).catch(() => []);
    // The root may have exited long ago (a launcher that hands over and leaves): its children are reparented and no parent link
    // reaches them. Stop the remembered ones that still run as the same program.
    const remembered = this.tree;
    this.tree = [];
    if (remembered.length) await terminateRemembered(remembered, { graceMs: 2000 }).catch(() => []);
    if (pid !== null) untrackRoot(pid);
    const t = this.tempCwd;
    this.tempCwd = undefined;
    await t?.remove();
  }
}

/** SQL tool discovery lives in packs/shared.ts (addendum 1.1); re-exported so existing imports keep working. */
export { discoverSqlTools } from "./packs/shared.js";
