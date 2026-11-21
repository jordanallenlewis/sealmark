import { createInterface } from "node:readline";
import { TEMPLATE_COMMAND, displaySpec, expand, placeholdersUsed, usesPlaceholders, type TemplateCtx } from "./config.js";
import type { EffectiveConfig, NamedServer } from "./config/index.js";
import { launchServer, stopOnSignals, type LaunchedServer } from "./launch.js";
import { McpSession, type CallResult, type OpenOptions, type ToolInfo } from "./mcp.js";
import { oauthSettings } from "./oauth.js";
import { settleMsFor, type FsDiff, type FsSnapshot } from "./observers/fs.js";
import { settledDiff } from "./observers/fs.js";
import type { ProcInfo } from "./observers/process.js";
import type { RequestRecord } from "./observers/listener.js";
import { MAX_REPORT_FIELD, inert, inertLines } from "./report/sanitize.js";
import { createSandbox, type Sandbox } from "./sandbox.js";

/**
 * `sealmark inspect`: start one server the way `run` and `doctor` start it (the sandbox as working directory and a scrubbed environment),
 * list its tools, call one with arguments you type, and print the reply together with what the harness's observers saw while it ran.
 * Nothing is graded and no check runs; the call is exactly the one you made, so the output is a way to look at a server, never a verdict.
 *
 * What is observed is stated in every report (`observed.scope`) and what is not is stated next to it: an empty list means "nothing seen
 * by these observers", never "the server did nothing".
 */

/** Bad request to inspect (exit 2). cli.ts maps it to its UsageError. */
export class InspectUsageError extends Error {}
/** The server could not be started or inspected (exit 4). */
export class InspectFailure extends Error {}

export const INSPECT_FORMAT = "sealmark.inspect/1";

/** Written next to every observation: what the observers cannot see. */
export const NOT_OBSERVED_DB = "database effects (no database is started; a SQLite file under the sandbox shows as a file change)";
export const NOT_OBSERVED_NET = "requests to anywhere except the harness's own loopback listener";

export interface Observed {
  /** What the observers watch in this run, in words. */
  scope: string;
  /** False when the server runs outside the sandbox (HTTP to a running server, or --no-sandbox): nothing below was observed. */
  watching: boolean;
  files: { added: string[]; removed: string[]; changed: string[]; touched: string[] };
  requests: { method: string; path: string; status?: number }[];
  processes: { pid: number; name: string; cmd?: string }[];
  stderr: string[];
  notObserved: string[];
}

export interface InspectCall {
  tool: string;
  args: Record<string, unknown>;
  result: { isError: boolean; text: string; elapsedMs: number; timedOut: boolean; closed: boolean; rpcError?: string };
  observed: Observed;
}

export interface ToolListing {
  name: string;
  description?: string;
  required: string[];
  params: string[];
}

export type InspectEvent =
  | { event: "tools"; server: string; tools: ToolListing[] }
  | ({ event: "call"; server: string } & InspectCall)
  | { event: "error"; message: string };

export interface InspectOptions {
  cfg: EffectiveConfig;
  server?: string;
  /** One call, then exit (--call). Without it the tools are listed and commands are read from `input`. */
  call?: { tool: string; args: Record<string, unknown> };
  json: boolean;
  /** Command lines (`tools`, `call <tool> [json]`, `help`, `quit`); undefined: read none. */
  input?: AsyncIterable<string>;
  /** stdin is a terminal: a prompt is written and `help` is offered at the start. */
  interactive?: boolean;
  startupTimeoutMs?: number;
  clientVersion?: string;
  log: (s: string) => void;
  /** Where a rendered event goes (stdout). */
  out: (s: string) => void;
  handleSignals?: boolean;
}

export interface InspectResult {
  exitCode: number;
  /** Every event printed, in order (tests read this instead of parsing stdout). */
  events: InspectEvent[];
}

const HELP = ["tools                    list the tools again", "call <tool> [json]       call a tool; json is its arguments, an object (default {})", "help                     this text", "quit                     stop the server and leave (so does the end of input)"].join("\n");

export const listTools = (tools: readonly ToolInfo[]): ToolListing[] =>
  tools.map((t) => ({ name: t.name, ...(t.description ? { description: t.description } : {}), required: t.inputSchema.required ?? [], params: Object.keys(t.inputSchema.properties ?? {}) }));

/** `call <tool> [json]` or `tools` / `help` / `quit`; anything else is reported, never guessed at. */
export function parseCommand(line: string): { cmd: "tools" | "help" | "quit" } | { cmd: "call"; tool: string; args: Record<string, unknown> } | { cmd: "empty" } | { cmd: "bad"; message: string } {
  const text = line.trim();
  if (!text) return { cmd: "empty" };
  const word = text.split(/\s+/, 1)[0]!;
  const rest = text.slice(word.length).trim();
  if (word === "tools" || word === "list") return { cmd: "tools" };
  if (word === "help" || word === "?") return { cmd: "help" };
  if (word === "quit" || word === "exit") return { cmd: "quit" };
  if (word !== "call") return { cmd: "bad", message: `unknown command "${inert(word, 40)}" (tools, call <tool> [json], help, quit)` };
  if (!rest) return { cmd: "bad", message: "call needs a tool name: call <tool> [json]" };
  const tool = rest.split(/\s+/, 1)[0]!;
  const raw = rest.slice(tool.length).trim();
  const args = parseArgsJson(raw);
  return typeof args === "string" ? { cmd: "bad", message: args } : { cmd: "call", tool, args };
}

/** The arguments text of --args or of a `call` line: empty is {}; anything but a JSON object is a message. */
export function parseArgsJson(raw: string): Record<string, unknown> | string {
  if (!raw.trim()) return {};
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch (e) {
    return `the arguments are not valid JSON (${(e as Error).message}); give an object such as {"path": "a.txt"}`;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return `the arguments must be a JSON object such as {"path": "a.txt"}, not ${Array.isArray(v) ? "an array" : v === null ? "null" : typeof v}`;
  return v as Record<string, unknown>;
}

function selectServer(cfg: EffectiveConfig, name: string | undefined): NamedServer {
  const wanted = name && name !== "all" ? cfg.servers.filter((s) => s.name === name) : cfg.servers;
  if (name && name !== "all" && !wanted.length) throw new InspectUsageError(`no server named "${name}" is selected (selected: ${cfg.servers.map((s) => s.name).join(", ")})`);
  if (wanted.length !== 1) throw new InspectUsageError(`inspect looks at one server at a time; pass --server <name> (selected: ${wanted.map((s) => s.name).join(", ")})`);
  return wanted[0]!;
}

const emptyFiles = (): Observed["files"] => ({ added: [], removed: [], changed: [], touched: [] });
const filesOf = (d: FsDiff): Observed["files"] => ({ added: d.added, removed: d.removed, changed: d.changed, touched: d.touched });

const MAX_STDERR_LINES = 500;
const SCOPE_SANDBOX = "files under the sandbox directories (root, home, tmp, canary), requests that reached the harness's loopback listener, and processes started under the sandbox";

/** Renders one event as text. Everything the server said goes through `inert`: a reply can carry control characters. */
export function renderEvent(e: InspectEvent): string {
  if (e.event === "error") return `error: ${inert(e.message, MAX_REPORT_FIELD)}\n`;
  if (e.event === "tools") {
    const lines = [`${e.server}: ${e.tools.length} tool${e.tools.length === 1 ? "" : "s"}`];
    for (const t of e.tools) {
      const params = t.params.map((p) => (t.required.includes(p) ? p : `${p}?`)).join(", ");
      lines.push(`  ${inert(t.name, 120)}(${inert(params, 300)})${t.description ? `  ${inert(t.description.split("\n")[0], 100)}` : ""}`);
    }
    return `${lines.join("\n")}\n`;
  }
  const r = e.result;
  const how = r.timedOut ? "timed out" : r.rpcError !== undefined ? "protocol error" : r.closed ? "the server went away" : r.isError ? "error reply" : "ok";
  const lines = [`${inert(e.tool, 120)}  ${how}, ${r.elapsedMs} ms`, `  arguments: ${inert(JSON.stringify(e.args), 500)}`];
  if (r.rpcError !== undefined) lines.push(`  rpc error: ${inert(r.rpcError, MAX_REPORT_FIELD)}`);
  lines.push("  reply:", ...inertLines(r.text || "(empty)").split("\n").map((l) => `    ${l}`));
  const o = e.observed;
  lines.push("  observed:");
  if (!o.watching) lines.push(`    nothing: ${o.scope}`);
  else {
    const f = o.files;
    const any = f.added.length + f.removed.length + f.changed.length + f.touched.length;
    if (!any) lines.push("    files: no change seen");
    for (const [label, list] of [["added", f.added], ["removed", f.removed], ["changed", f.changed], ["touched (same content)", f.touched]] as const) {
      if (list.length) lines.push(`    files ${label}: ${list.slice(0, 20).map((p) => inert(p, 200)).join(", ")}${list.length > 20 ? `, and ${list.length - 20} more` : ""}`);
    }
    lines.push(o.requests.length ? `    requests to the harness listener: ${o.requests.map((q) => `${inert(q.method, 10)} ${inert(q.path, 120)}${q.status ? ` -> ${q.status}` : ""}`).join("; ")}` : "    requests to the harness listener: none");
    lines.push(o.processes.length ? `    processes started: ${o.processes.map((p) => `${p.pid} ${inert(p.cmd ?? p.name, 120)}`).join("; ")}` : "    processes started: none seen");
    if (o.stderr.length) lines.push("    server stderr:", ...o.stderr.slice(0, 20).map((l) => `      ${inert(l, 300)}`));
  }
  if (o.notObserved.length) lines.push(`    not observed: ${o.notObserved.join("; ")}`);
  return `${lines.join("\n")}\n`;
}

/** JSON.stringify escapes only C0 controls: a terminal also acts on C1 controls (8-bit CSI), bidi overrides and zero-width characters. */
// eslint-disable-next-line no-control-regex
const RAW_IN_JSON = /[\u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
export const jsonLine = (v: unknown): string => `${JSON.stringify(v).replace(RAW_IN_JSON, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)}\n`;
const render = (e: InspectEvent, json: boolean): string => (json ? jsonLine({ format: INSPECT_FORMAT, ...e }) : renderEvent(e));

/** Starts the server, answers `o.call` or the commands in `o.input`, and stops everything. Throws InspectUsageError / InspectFailure. */
export async function runInspect(o: InspectOptions): Promise<InspectResult> {
  const cfg = o.cfg;
  const named = selectServer(cfg, o.server);
  const spec = named.spec;
  const transport = spec.url ? "http" : "stdio";
  const events: InspectEvent[] = [];
  let failed = false;
  if (spec.command === TEMPLATE_COMMAND) throw new InspectUsageError(`server.command is still "${TEMPLATE_COMMAND}", the placeholder sealmark init writes. Replace it with the command that starts the MCP server, then run inspect again. Nothing was started.`);
  if (usesPlaceholders(spec)) throw new InspectUsageError("this server's configuration uses database placeholders ({dsn} and friends): inspect starts no database. Use sealmark run, or point the server at a database you started yourself.");
  const used = placeholdersUsed(spec);
  const needsHarness = ["upstream", "bearer", "bearer:a", "bearer:b"].filter((k) => used.has(k));
  if (needsHarness.length) throw new InspectUsageError(`this server's configuration uses ${needsHarness.map((k) => `{${k}}`).join(", ")}, which run fills from a stub upstream and identity tokens; inspect starts neither, and a made-up value would make the replies mislead. Use sealmark run, or put the real address and token in the configuration.`);
  const oauth = oauthSettings(cfg);
  if (oauth.issuer === "stub") throw new InspectUsageError("oauth.issuer: stub makes sealmark start a stub token issuer for the server; inspect does not (it would sign tokens you did not ask for). Use sealmark doctor or run for this server.");

  const selfStarted = transport === "http" && Boolean(spec.command);
  const sandboxOn = cfg.sandbox.enabled && (transport === "stdio" || selfStarted);
  if (!sandboxOn) o.log(transport === "http" && !selfStarted ? "note: this server is already running, outside the sandbox: its effects are not observed" : "note: the sandbox is off (--no-sandbox): the server runs with your environment and its effects are not observed");

  let sb: Sandbox | undefined;
  let session: McpSession | undefined;
  let launched: LaunchedServer | undefined;
  let cleaned: Promise<void> | undefined;
  const stderrLines: string[] = [];
  const pushStderr = (chunk: string): void => {
    for (const l of chunk.split(/\r?\n/)) if (l && stderrLines.length < MAX_STDERR_LINES) stderrLines.push(l.length > 2000 ? `${l.slice(0, 2000)}...` : l);
  };
  const cleanup = () =>
    (cleaned ??= (async () => {
      await session?.close().catch(() => {});
      await launched?.stop().catch(() => {});
      await sb?.destroy().catch(() => {});
    })());
  const unhook = o.handleSignals !== false ? stopOnSignals(() => cleanup()) : () => {};
  try {
    // Created even with --no-sandbox (as run and doctor do): {sandbox}, {sandbox_home} and {listener} must expand to real directories, never to "".
    {
      try {
        sb = await createSandbox({ ...(cfg.sandbox.dir ? { dir: cfg.sandbox.dir } : {}), maxBytes: cfg.sandbox.max_mib * 1024 * 1024, timeoutProbeSec: cfg.timeoutProbeSec, keepEnv: cfg.sandbox.keep_env, log: o.log });
      } catch (e) {
        throw new InspectFailure(`the sandbox could not be created: ${(e as Error).message}`);
      }
    }
    const sep = process.platform === "win32" ? "\\" : "/";
    const vars: Record<string, string> = {
      sandbox: sb!.root,
      sandbox_home: sb!.home,
      listener: sb!.listener.url,
      sqlite_path: `${sb!.root}${sep}fixture.sqlite`,
      duckdb_path: `${sb!.root}${sep}fixture.duckdb`,
    };
    const ctx: TemplateCtx = { vars, dsns: {}, env: cfg.env };
    const where: OpenOptions = transport === "http" ? {} : sandboxOn ? (cfg.sandbox.scrub_env ? { cwd: sb!.root, baseEnv: sb!.env(), envMode: "scrubbed" } : { cwd: sb!.root, envMode: "inherit" }) : { cleanCwd: true, envMode: "inherit" };
    if (sandboxOn && sb && transport === "stdio") {
      const specText = JSON.stringify(spec);
      if (/\{(?:sandbox|dir)\}(?:\\\\|\/)+repo/.test(specText)) {
        const { ensureGitFixture } = await import("./packs/git.js");
        await ensureGitFixture(sb).catch((e: Error) => o.log(`warning: the git fixtures could not be built: ${e.message}`));
      }
      if (specText.includes("{sqlite_path}")) {
        const { ensureSqliteFixture } = await import("./sqlite-fixtures.js");
        try {
          ensureSqliteFixture(vars.sqlite_path!);
        } catch (e) {
          o.log(`warning: the sqlite fixture could not be built: ${(e as Error).message}`);
        }
      }
    }
    const limitMs = o.startupTimeoutMs ?? cfg.timeouts.connect_ms;
    try {
      if (selfStarted) {
        launched = await launchServer({
          command: expand(spec.command!, ctx),
          args: (spec.args ?? []).map((a) => expand(a, ctx)),
          env: Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expand(v, ctx)])),
          url: expand(spec.url!, ctx),
          ...(spec.transport === "sse" ? { transport: "sse" as const } : {}),
          timeoutMs: (spec.start_timeout_sec ?? 60) * 1000,
          ...(sandboxOn && sb ? { cwd: sb.root, ...(cfg.sandbox.scrub_env ? { baseEnv: sb.env(Object.fromEntries(Object.entries(spec.env ?? {}).map(([k, v]) => [k, expand(v, ctx)]))) } : {}) } : {}),
          onProgress: o.log,
          onOutput: (chunk, stream) => {
            if (stream === "stderr") pushStderr(chunk);
          },
          onStarted: (h) => {
            launched = h;
          },
        });
      }
      o.log(`starting "${named.name}" (${displaySpec(spec).command}, limit ${Math.round(limitMs / 1000)} s)`);
      session = await McpSession.open(spec, ctx, { clientVersion: o.clientVersion, connectTimeoutMs: limitMs, onProgress: o.log, onStderr: pushStderr, ...where });
    } catch (e) {
      const m = e as Error & { stderr?: string };
      const tail = (m.stderr ?? "").trim().split(/\r?\n/).slice(-5).join("\n");
      throw new InspectFailure(`the server did not start or did not answer initialize and tools/list: ${m.message}${tail ? `\n${tail}` : ""}\nsealmark doctor says why a server does not start`);
    }
    const live = session;
    const emit = (e: InspectEvent): void => {
      events.push(e);
      o.out(render(e, o.json));
    };
    const showTools = (): void => emit({ event: "tools", server: named.name, tools: listTools(live.tools) });

    const doCall = async (tool: string, args: Record<string, unknown>): Promise<void> => {
      if (!live.tools.some((t) => t.name === tool)) {
        emit({ event: "error", message: `the server has no tool named "${tool}" (tools: ${live.tools.map((t) => t.name).join(", ") || "none"})` });
        return;
      }
      const watching = sandboxOn && Boolean(sb);
      const labels = sb ? Object.keys(sb.fs.dirs) : undefined;
      let before: FsSnapshot | undefined;
      let procsBefore: Set<number> | undefined;
      let requestsBefore = 0;
      const stderrBefore = stderrLines.length;
      if (watching && sb) {
        // The server may still be writing its start-up files: let that settle so the diff is this call's.
        await new Promise<void>((r) => setTimeout(r, 150));
        before = await sb.fs.snapshot(labels);
        procsBefore = new Set((await sb.proc.strays().catch(() => [] as ProcInfo[])).map((p) => p.pid));
        requestsBefore = sb.listener.requests().length;
      }
      const res: CallResult = await live.call(tool, args, cfg.timeouts.call_ms);
      let files = emptyFiles();
      let requests: Observed["requests"] = [];
      let processes: Observed["processes"] = [];
      if (watching && sb && before && procsBefore) {
        files = filesOf(await settledDiff(sb.fs, before, labels, settleMsFor(cfg.timeoutProbeSec)));
        requests = sb.listener.requests().slice(requestsBefore).map((q: RequestRecord) => ({ method: q.method, path: q.path, ...(q.status !== undefined ? { status: q.status } : {}) }));
        processes = (await sb.proc.strays().catch(() => [] as ProcInfo[])).filter((p) => !procsBefore!.has(p.pid)).map((p) => ({ pid: p.pid, name: p.name, ...(p.cmd ? { cmd: p.cmd } : {}) }));
      }
      const observed: Observed = {
        scope: watching ? SCOPE_SANDBOX : transport === "http" && !selfStarted ? "the server runs outside the sandbox" : "the sandbox is off",
        watching,
        files,
        requests,
        processes,
        stderr: stderrLines.slice(stderrBefore),
        notObserved: watching ? [NOT_OBSERVED_DB, NOT_OBSERVED_NET, "anything outside the sandbox directories", "writes made after the settle window (they show under a later call)", "processes that started and exited during the call, and (on macOS and Windows) processes whose command line does not name the sandbox", ...(selfStarted ? ["the launched server's own stderr is shown, but a server logging elsewhere is not"] : [])] : ["files, requests and processes"],
      };
      const result = { isError: res.isError, text: res.text, elapsedMs: res.elapsedMs, timedOut: res.timedOut, closed: res.closed, ...(res.rpcError !== undefined ? { rpcError: res.rpcError } : {}) };
      if (res.timedOut || res.closed || res.rpcError !== undefined) failed = true;
      emit({ event: "call", server: named.name, tool, args, result, observed });
    };

    if (o.call) {
      await doCall(o.call.tool, o.call.args);
      if (events[events.length - 1]?.event === "error") failed = true;
    } else {
      showTools();
      if (o.input) {
        if (o.interactive) o.log('type "help" for commands, "quit" to leave');
        for await (const line of o.input) {
          const c = parseCommand(line);
          if (c.cmd === "quit") break;
          if (c.cmd === "empty") continue;
          if (c.cmd === "tools") showTools();
          else if (c.cmd === "help") o.out(o.json ? jsonLine({ format: INSPECT_FORMAT, event: "help", text: HELP }) : `${HELP}\n`);
          else if (c.cmd === "bad") emit({ event: "error", message: c.message });
          else if (c.cmd === "call") {
            await doCall(c.tool, c.args);
            if (live.closed) {
              emit({ event: "error", message: "the server is gone; start inspect again" });
              failed = true;
              break;
            }
          }
        }
      }
    }
    return { exitCode: failed ? 4 : 0, events };
  } finally {
    try {
      await cleanup();
    } finally {
      unhook();
    }
  }
}

/**
 * Lines of a readable stream, for `o.input`. Stops at the end of input. The reader is made when the first line is asked for (an async
 * generator runs lazily): a readline interface made earlier loses every line that arrives while the server is still starting.
 */
export async function* linesOf(stream: NodeJS.ReadableStream): AsyncGenerator<string> {
  yield* createInterface({ input: stream, terminal: false, crlfDelay: Infinity });
}
