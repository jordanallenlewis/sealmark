// The http pack: checks of a Streamable HTTP MCP endpoint as deployed.
// It talks to the configured server.url with fetch, never with the MCP SDK, so it can send what a client library would not
// (a hostile Origin, no credentials, a wrong protocol version, a forged session id). It contacts only that URL.
// Configured header values (credentials) are sent to that URL and nowhere else, and are never written to a report.
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { looksSecret, stripUserinfo } from "../config/placeholders.js";
import { expandHarness } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence, Pack, PackCtx, Verdict } from "../types.js";
import { isLoopbackHostname } from "./shared.js";

const SINCE = "0.2-draft";
const EVIL_ORIGIN = "http://sealmark-evil.example";
const OLD_VERSION = "1999-01-01";
const INIT_VERSION = "2025-06-18";

// ---------------------------------------------------------------------------------------------------------
// Check docs
// ---------------------------------------------------------------------------------------------------------

const DOCS: CheckDoc[] = [
  {
    id: "http-origin",
    pack: "http",
    label: "Origin header validated",
    critical: true,
    advisory: false,
    scope: "server as deployed (the endpoint you configured, with the headers you configured)",
    verifiedBy: ["http"],
    probes: [{ id: "evil-origin", text: `POST initialize with Origin: ${EVIL_ORIGIN} and the configured headers, after a control initialize without it`, kind: "origin" }],
    thresholds: {},
    falsePositive: "A server that deliberately serves browser clients from any origin fails; it should validate against an allow-list instead.",
    falseNegative: "A server that validates Origin only on some paths or methods, or only when a session exists. Not tested: DNS rebinding through the Host header.",
    configKeys: ["server.url", "server.headers", "checks.http-origin.enabled", "checks.http-origin.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-auth",
    pack: "http",
    label: "Rejects requests without credentials",
    critical: false,
    advisory: false,
    scope: "server as deployed (is the configured credential actually required?)",
    verifiedBy: ["http"],
    probes: [{ id: "no-credentials", text: "initialize and tools/list sent without any of the configured headers", kind: "auth" }],
    thresholds: {},
    falsePositive: "A server whose configured header is not a credential (a routing header) is treated as having none: only headers whose names look like credentials count.",
    falseNegative: "Credentials that are valid but under-scoped, tokens that never expire, authorization of individual tools.",
    configKeys: ["server.headers", "checks.http-auth.enabled", "checks.http-auth.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-protocol-version",
    pack: "http",
    label: "Unsupported protocol version rejected",
    critical: false,
    advisory: false,
    scope: "server as deployed (MCP-Protocol-Version validation)",
    verifiedBy: ["http"],
    probes: [{ id: "old-version", text: `tools/list with MCP-Protocol-Version: ${OLD_VERSION}, after a control tools/list with the negotiated version`, kind: "protocol" }],
    thresholds: {},
    falsePositive: "A server that negotiates down quietly is lenient rather than unsafe; the specification says it MUST answer 400.",
    falseNegative: "Versions other than the one tried; behavior on requests that omit the header.",
    configKeys: ["server.url", "checks.http-protocol-version.enabled", "checks.http-protocol-version.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-session",
    pack: "http",
    label: "Session ids required, validated and unguessable",
    critical: false,
    advisory: false,
    scope: "server as deployed (Mcp-Session-Id handling)",
    verifiedBy: ["http"],
    probes: [
      { id: "no-session", text: "tools/list without Mcp-Session-Id", kind: "session" },
      { id: "forged-session", text: "tools/list with Mcp-Session-Id: sm-forged-<random>", kind: "session" },
      { id: "entropy", text: "the issued id is at least 16 printable characters and differs between two initializations", kind: "session" },
    ],
    thresholds: { min_id_chars: { default: 16, configKey: "(fixed)", standardLocked: true } },
    falsePositive: "A server that deliberately offers a session-optional mode.",
    falseNegative: "Ids that look random but are predictable; session fixation; expiry.",
    configKeys: ["server.headers", "checks.http-session.enabled", "checks.http-session.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-cors",
    pack: "http",
    label: "No permissive CORS",
    critical: false,
    advisory: false,
    scope: "server as deployed (answer to a cross-origin preflight)",
    verifiedBy: ["http"],
    probes: [{ id: "preflight", text: `OPTIONS with Origin: ${EVIL_ORIGIN} and Access-Control-Request-Method: POST (no credentials, as a browser sends it)`, kind: "cors" }],
    thresholds: {},
    falsePositive: "A server that is meant to be called from a browser app should allow that one origin, not the probe's.",
    falseNegative: "CORS headers sent only on actual requests, or only to some paths.",
    configKeys: ["server.url", "checks.http-cors.enabled", "checks.http-cors.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-bind",
    pack: "http",
    label: "Listens on loopback only",
    critical: false,
    advisory: true,
    scope: "environment (the machine the server runs on, when the configured URL is loopback; not examined when Sealmark started the server itself)",
    verifiedBy: ["process"],
    probes: [{ id: "listener-table", text: "read this machine's listening-socket table for the URL's port (netstat or ss); no packet is sent to any address", kind: "bind" }],
    thresholds: {},
    falsePositive: "A server meant to be reached from other machines, reached here through localhost.",
    falseNegative: "Only the local machine's table is read, so a server in a container or on another host cannot be seen; a port forwarded by a proxy looks loopback-only. Not examined when Sealmark started the server itself (server.command with server.url), because how that start command binds is its own choice and a container binding 0.0.0.0 is normal there.",
    configKeys: ["server.url", "server.command", "checks.http-bind.enabled", "checks.http-bind.severity"],
    since: SINCE,
    status: "shipped",
  },
  {
    id: "http-tls",
    pack: "http",
    label: "Uses TLS off the local machine",
    critical: false,
    advisory: true,
    scope: "environment (the URL as configured)",
    verifiedBy: ["static"],
    probes: [{ id: "scheme", text: "https: passes; http: to a non-loopback host is noted", kind: "tls" }],
    thresholds: {},
    falsePositive: "Plain http inside a trusted private network, or TLS terminated by a proxy in front.",
    falseNegative: "Certificate validity, protocol versions and cipher choices are not examined.",
    configKeys: ["server.url", "checks.http-tls.enabled", "checks.http-tls.severity"],
    since: SINCE,
    status: "shipped",
  },
];

export function describe(): CheckDoc[] {
  return DOCS;
}
const doc = (id: string): CheckDoc => DOCS.find((d) => d.id === id)!;

// ---------------------------------------------------------------------------------------------------------
// Per-check configuration (enabled, severity)
// ---------------------------------------------------------------------------------------------------------

function settings(ctx: PackCtx, id: string): { disabled?: string; advisory?: boolean; critical?: boolean } {
  const c = ctx.config?.checks?.[id];
  const origin = ctx.config?.origins?.[`/checks/${id}/enabled`]?.source ?? "config";
  const sev = c?.severity ?? null;
  return {
    disabled: c && c.enabled === false ? `disabled by config (${origin})` : undefined,
    advisory: sev === "advisory" ? true : undefined,
    critical: sev === "critical" ? true : sev === "scored" ? false : undefined,
  };
}

function result(ctx: PackCtx, id: string, verdict: Verdict, summary: string, evidence: Evidence[]): CheckResult {
  const d = doc(id);
  const s = settings(ctx, id);
  const advisory = s.advisory ?? d.advisory;
  const base: CheckResult = { id, pack: "http", label: d.label, critical: s.critical ?? d.critical, ...(advisory ? { advisory: true } : {}), scope: d.scope, verdict, summary, evidence };
  return s.disabled ? { ...base, verdict: "na", summary: s.disabled, evidence: [] } : base;
}

// ---------------------------------------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------------------------------------

interface Conn {
  url: string;
  /** Configured headers with placeholders and ${VAR} references filled in. Values never reach evidence. */
  headers: Record<string, string>;
  reqMs: number;
}

interface Reply {
  /** 0 when no HTTP response arrived (connection refused, timeout). */
  status: number;
  headers: Headers;
  /** The JSON-RPC message (from a JSON body or the matching SSE event). */
  rpc?: { id?: unknown; result?: Record<string, unknown>; error?: { code?: number; message?: string } };
  text: string;
  error?: string;
}

const NO_HEADERS = new Headers();

function excerpt(s: string, n = 120): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? `${t.slice(0, n)}...` : t;
}

async function readSse(res: Response, wantId: unknown, ms: number): Promise<{ rpc?: Reply["rpc"]; text: string }> {
  const reader = res.body?.getReader();
  if (!reader) return { text: "" };
  const dec = new TextDecoder();
  let buf = "";
  let total = 0;
  const deadline = Date.now() + ms;
  try {
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) break;
      const chunk = await Promise.race([reader.read(), new Promise<{ done: true; value?: undefined }>((r) => setTimeout(() => r({ done: true }), left).unref())]);
      if (chunk.done) break;
      total += chunk.value.length;
      buf += dec.decode(chunk.value, { stream: true });
      const events = buf.split(/\r?\n\r?\n/);
      buf = events.pop() ?? "";
      for (const ev of events) {
        const data = ev
          .split(/\r?\n/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).replace(/^ /, ""))
          .join("\n");
        if (!data) continue;
        try {
          const msg = JSON.parse(data) as NonNullable<Reply["rpc"]>;
          if (msg && typeof msg === "object" && (wantId === undefined || msg.id === wantId) && ("result" in msg || "error" in msg)) return { rpc: msg, text: excerpt(data, 300) };
        } catch {
          /* not JSON: keep reading */
        }
      }
      if (total > 1024 * 1024) break;
    }
    return { text: excerpt(buf, 300) };
  } finally {
    await reader.cancel().catch(() => {});
  }
}

interface SendOptions {
  method?: "POST" | "DELETE" | "OPTIONS";
  /** Send none of the configured headers (credentials included). */
  noConfigured?: boolean;
  /** Extra headers; a null value removes the header. */
  headers?: Record<string, string | null>;
  body?: unknown;
}

async function send(conn: Conn, o: SendOptions): Promise<Reply> {
  const headers: Record<string, string> = {};
  if (o.method !== "OPTIONS" && o.method !== "DELETE") {
    headers["content-type"] = "application/json";
    headers.accept = "application/json, text/event-stream";
  }
  if (!o.noConfigured) Object.assign(headers, conn.headers);
  for (const [k, v] of Object.entries(o.headers ?? {})) {
    for (const existing of Object.keys(headers)) if (existing.toLowerCase() === k.toLowerCase()) delete headers[existing];
    if (v !== null) headers[k] = v;
  }
  const wantId = (o.body as { id?: unknown } | undefined)?.id;
  try {
    const res = await fetch(conn.url, {
      method: o.method ?? "POST",
      headers,
      ...(o.body !== undefined ? { body: JSON.stringify(o.body) } : {}),
      redirect: "manual",
      signal: AbortSignal.timeout(conn.reqMs),
    });
    const type = res.headers.get("content-type") ?? "";
    if (type.includes("text/event-stream") && res.status === 200) {
      const r = await readSse(res, wantId, conn.reqMs);
      return { status: res.status, headers: res.headers, rpc: r.rpc, text: r.text };
    }
    const raw = (await res.text().catch(() => "")).slice(0, 64 * 1024);
    let rpc: Reply["rpc"];
    if (raw && (type.includes("json") || raw.trimStart().startsWith("{"))) {
      try {
        const parsed = JSON.parse(raw) as Reply["rpc"];
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) rpc = parsed;
      } catch {
        /* plain text error body */
      }
    }
    return { status: res.status, headers: res.headers, rpc, text: excerpt(raw, 300) };
  } catch (e) {
    const err = e as Error & { cause?: { code?: string; message?: string } };
    return { status: 0, headers: NO_HEADERS, text: "", error: `${err.name === "TimeoutError" ? `no response within ${conn.reqMs / 1000} s` : (err.cause?.code ?? err.cause?.message ?? err.message)}` };
  }
}

let nextId = 1;
const rpcBody = (method: string, params?: unknown) => ({ jsonrpc: "2.0", id: nextId++, method, ...(params !== undefined ? { params } : {}) });

const isInitResult = (r: Reply): boolean => r.status === 200 && r.rpc?.result !== undefined && typeof r.rpc.result.protocolVersion === "string";
const hasTools = (r: Reply): boolean => r.status === 200 && Array.isArray(r.rpc?.result?.tools);
/** The Location header of a 3xx reply, in words: a redirect is the usual reason a probe of a correct URL fails (a missing trailing slash). */
const locationOf = (r: Reply): string => (r.status >= 300 && r.status < 400 ? (r.headers.get("location") ?? "") : "");
const describeReply = (r: Reply): string => {
  if (r.status === 0) return `no response (${r.error})`;
  const loc = locationOf(r);
  return `HTTP ${r.status}${loc ? ` (Location: ${excerpt(loc, 100)}; the server redirected the request, try the URL it points to or with a trailing slash)` : ""}${r.text ? `: ${excerpt(r.text, 100)}` : ""}`;
};

interface Session {
  reply: Reply;
  ok: boolean;
  sessionId?: string;
  protocolVersion?: string;
}

async function initialize(conn: Conn, o: Omit<SendOptions, "body" | "method"> = {}): Promise<Session> {
  const reply = await send(conn, { ...o, body: rpcBody("initialize", { protocolVersion: INIT_VERSION, capabilities: {}, clientInfo: { name: "sealmark", version: "0.2" } }) });
  const ok = isInitResult(reply);
  const sessionId = reply.headers.get("mcp-session-id") ?? undefined;
  const protocolVersion = ok ? String(reply.rpc!.result!.protocolVersion) : undefined;
  if (ok) {
    // The handshake's last step. A stateless server answers 202 or 200; either is fine.
    await send(conn, { ...o, headers: { ...(o.headers ?? {}), ...(sessionId ? { "mcp-session-id": sessionId } : {}), "mcp-protocol-version": protocolVersion! }, body: { jsonrpc: "2.0", method: "notifications/initialized" } });
  }
  return { reply, ok, sessionId, protocolVersion };
}

async function listTools(conn: Conn, s: Pick<Session, "sessionId" | "protocolVersion">, o: Omit<SendOptions, "body" | "method"> = {}, over: Record<string, string | null> = {}): Promise<Reply> {
  return send(conn, {
    ...o,
    headers: { ...(o.headers ?? {}), ...(s.sessionId ? { "mcp-session-id": s.sessionId } : {}), ...(s.protocolVersion ? { "mcp-protocol-version": s.protocolVersion } : {}), ...over },
    body: rpcBody("tools/list"),
  });
}

async function terminate(conn: Conn, s: Session | undefined, o: Omit<SendOptions, "body" | "method"> = {}): Promise<void> {
  if (!s?.sessionId) return;
  await send(conn, { ...o, method: "DELETE", headers: { ...(o.headers ?? {}), "mcp-session-id": s.sessionId, ...(s.protocolVersion ? { "mcp-protocol-version": s.protocolVersion } : {}) } });
}

// ---------------------------------------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------------------------------------

export { isLoopbackHostname };

/** Header names that look like credentials (the same rule that redacts them in reports). */
export function credentialHeaders(headers: Record<string, string>): string[] {
  return Object.keys(headers).filter((k) => looksSecret(k));
}

// ---------------------------------------------------------------------------------------------------------
// http-bind: read the OS listener table (no packet is sent to any address)
// ---------------------------------------------------------------------------------------------------------

/** Local addresses that are listening on `port`, from `netstat -an` (Windows, macOS), `ss -ltn` or `netstat -ltn` (Linux) output. */
export function listeningAddresses(text: string, port: number): string[] {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    if (!/\bLISTEN(ING)?\b/i.test(line)) continue;
    for (const tok of line.trim().split(/\s+/)) {
      const m = /^(.*)[:.](\d+)$/.exec(tok);
      if (m && Number(m[2]) === port) {
        out.add(m[1]!.replace(/^\[|\]$/g, "").toLowerCase() || "*");
        break;
      }
    }
  }
  return [...out];
}

export type Exposure = "wildcard" | "interface" | "loopback" | "none";

export function exposureOf(addrs: string[]): { kind: Exposure; addrs: string[] } {
  if (!addrs.length) return { kind: "none", addrs };
  const wildcard = addrs.filter((a) => a === "*" || a === "0.0.0.0" || a === "::" || a === ":::" || a === "0:0:0:0:0:0:0:0");
  if (wildcard.length) return { kind: "wildcard", addrs: wildcard };
  const other = addrs.filter((a) => !isLoopbackHostname(a));
  if (other.length) return { kind: "interface", addrs: other };
  return { kind: "loopback", addrs };
}

function run(cmd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true, timeout: 8000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => (err ? reject(err) : resolve(String(stdout))));
  });
}

async function listenerTable(): Promise<string> {
  if (process.platform === "linux") {
    try {
      return await run("ss", ["-ltn"]);
    } catch {
      return run("netstat", ["-ltn"]);
    }
  }
  return run("netstat", ["-an"]);
}

// ---------------------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------------------

function weakSessionId(id: string): boolean {
  return id.length < 16 || !/^[\x21-\x7e]+$/.test(id);
}

export interface HttpDeps {
  /** Replaces the OS listener-table read (tests). */
  listenerTable?: () => Promise<string>;
}

export function makePack(deps: HttpDeps = {}): Pack {
  return {
    id: "http",
    describe,
    applies(ctx: PackCtx) {
      const url = ctx.config?.server?.url;
      if (!url) return { ok: false, reason: "the server is started over stdio; the http pack needs server.url" };
      return { ok: true };
    },
    async run(ctx: PackCtx): Promise<CheckResult[]> {
      const spec = ctx.config.server;
      // The run's harness placeholders ({upstream}, {bearer}, ...) so a header written with {bearer} is sent with the real value.
      const tctx = { vars: ctx.vars ?? {}, dsns: {}, env: ctx.config.env };
      const url = expandHarness(spec.url!, tctx);
      const configured = Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k, expandHarness(v, tctx)]));
      const probeMs = ctx.config.timeouts?.probe_ms ?? 10_000;
      const conn: Conn = { url, headers: configured, reqMs: Math.min(30_000, Math.max(3_000, probeMs)) };
      const shown = stripUserinfo(url);
      const creds = credentialHeaders(configured);
      let host = "";
      let protocol = "";
      let port = 0;
      try {
        const u = new URL(url);
        host = u.hostname;
        protocol = u.protocol;
        port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
      } catch {
        return DOCS.map((d) => result(ctx, d.id, "inconclusive", `server.url is not a valid URL: ${shown}`, []));
      }
      const loopback = isLoopbackHostname(host);
      const created: Session[] = [];
      const track = async (o?: Omit<SendOptions, "body" | "method">) => {
        const s = await initialize(conn, o);
        if (s.sessionId) created.push(s);
        return s;
      };
      const out: CheckResult[] = [];
      /** A disabled check sends nothing: it is reported na before any probe. */
      const off = (id: string): CheckResult | undefined => (settings(ctx, id).disabled ? result(ctx, id, "na", "", []) : undefined);
      const hdrNames = Object.keys(configured);
      const headerNote = hdrNames.length ? `${hdrNames.length} configured header(s): ${hdrNames.join(", ")}` : "no configured headers";

      try {
        // ---- control: the harness's own handshake, with the configured headers and nothing hostile ----
        const control = await track();
        const controlOk = control.ok;
        const controlEv: Evidence = {
          probe: `POST initialize to ${shown} (${headerNote})`,
          outcome: controlOk ? `valid InitializeResult (protocol ${control.protocolVersion}${control.sessionId ? ", session id issued" : ", no session id"})` : describeReply(control.reply),
          verifiedBy: "http",
          code: "http.control",
        };
        const needControl = (id: string): CheckResult | undefined =>
          controlOk ? undefined : result(ctx, id, "inconclusive", `the harness's own initialize was not accepted (${describeReply(control.reply)}), so the probe could not be told from a misconfiguration; check server.url and server.headers`, [controlEv]);

        // ---- http-origin (critical) ----
        out.push(
          off("http-origin") ??
          needControl("http-origin") ??
            (await (async () => {
              const evil = await track({ headers: { origin: EVIL_ORIGIN } });
              const ev: Evidence = { probe: `POST initialize with Origin: ${EVIL_ORIGIN} (${headerNote})`, outcome: evil.ok ? "valid InitializeResult" : describeReply(evil.reply), verifiedBy: "http", code: "http.origin" };
              if (evil.ok) return result(ctx, "http-origin", "fail", `the server accepted an initialize request from the hostile origin ${EVIL_ORIGIN} (the specification requires Origin validation to stop DNS rebinding)`, [controlEv, ev]);
              if ([400, 403, 421].includes(evil.reply.status)) return result(ctx, "http-origin", "pass", `the hostile origin was rejected with HTTP ${evil.reply.status} while the same request without it succeeded`, [controlEv, ev]);
              if (evil.reply.status === 0) return result(ctx, "http-origin", "inconclusive", `no response to the hostile-origin request (${evil.reply.error})`, [controlEv, ev]);
              return result(ctx, "http-origin", "part", `the hostile origin was not accepted, but the status (${describeReply(evil.reply)}) is not one the specification names (403)`, [controlEv, ev]);
            })()),
        );

        // ---- http-auth ----
        out.push(
          await (async () => {
            const d = off("http-auth");
            if (d) return d;
            if (creds.length === 0) {
              const note = hdrNames.length ? ` (the configured headers ${hdrNames.join(", ")} do not look like credentials)` : "";
              if (loopback) return result(ctx, "http-auth", "na", `no credential header is configured${note} and the server is on loopback, so authentication was not graded`, [controlEv]);
              if (controlOk) return result(ctx, "http-auth", "part", `the server accepts requests with no credentials from a non-loopback address; none are configured, so whether that is intended cannot be told`, [controlEv]);
              if ([401, 403].includes(control.reply.status)) return result(ctx, "http-auth", "pass", `the server rejects requests that carry no credentials (HTTP ${control.reply.status}); none are configured, so nothing further was probed`, [controlEv]);
              return result(ctx, "http-auth", "inconclusive", `no credentials configured and the server answered ${describeReply(control.reply)}`, [controlEv]);
            }
            const c = needControl("http-auth");
            if (c) return c;
            const bare = await track({ noConfigured: true });
            const ev: Evidence = { probe: `POST initialize without the configured headers (${creds.join(", ")} omitted)`, outcome: bare.ok ? "valid InitializeResult" : describeReply(bare.reply), verifiedBy: "http", code: "http.auth" };
            if ([401, 403].includes(bare.reply.status)) return result(ctx, "http-auth", "pass", `requests without credentials are rejected (HTTP ${bare.reply.status})`, [controlEv, ev]);
            if (bare.ok) {
              const tools = await listTools(conn, bare, { noConfigured: true });
              const ev2: Evidence = { probe: "POST tools/list without the configured headers", outcome: hasTools(tools) ? `returned ${(tools.rpc!.result!.tools as unknown[]).length} tool(s)` : describeReply(tools), verifiedBy: "http", code: "http.auth" };
              if (hasTools(tools)) return result(ctx, "http-auth", "fail", `the server answers initialize and tools/list with none of the configured credentials`, [controlEv, ev, ev2]);
              return result(ctx, "http-auth", "part", `initialize works without credentials, but tools/list is protected (${describeReply(tools)})`, [controlEv, ev, ev2]);
            }
            return result(ctx, "http-auth", "inconclusive", `a request without credentials got ${describeReply(bare.reply)}, which is neither acceptance nor the 401/403 rejection`, [controlEv, ev]);
          })(),
        );

        // ---- http-protocol-version ----
        out.push(
          off("http-protocol-version") ??
          needControl("http-protocol-version") ??
            (await (async () => {
              const good = await listTools(conn, control);
              const ev0: Evidence = { probe: `POST tools/list with MCP-Protocol-Version: ${control.protocolVersion}`, outcome: hasTools(good) ? "tools returned" : describeReply(good), verifiedBy: "http", code: "http.control" };
              if (!hasTools(good)) return result(ctx, "http-protocol-version", "inconclusive", `the control tools/list failed (${describeReply(good)}), so the wrong-version probe could not be judged`, [controlEv, ev0]);
              const bad = await listTools(conn, control, {}, { "mcp-protocol-version": OLD_VERSION });
              const ev: Evidence = { probe: `POST tools/list with MCP-Protocol-Version: ${OLD_VERSION}`, outcome: hasTools(bad) ? "tools returned" : describeReply(bad), verifiedBy: "http", code: "http.protocol-version" };
              if (bad.status === 400) return result(ctx, "http-protocol-version", "pass", `an unsupported protocol version is rejected with HTTP 400`, [controlEv, ev0, ev]);
              if (bad.status === 0) return result(ctx, "http-protocol-version", "inconclusive", `no response to the wrong-version request (${bad.error})`, [controlEv, ev0, ev]);
              return result(ctx, "http-protocol-version", "fail", hasTools(bad) ? `the server answered a request with MCP-Protocol-Version ${OLD_VERSION} as if it were valid (the specification requires 400)` : `an unsupported protocol version got ${describeReply(bad)} instead of 400`, [controlEv, ev0, ev]);
            })()),
        );

        // ---- http-session ----
        out.push(
          off("http-session") ??
          needControl("http-session") ??
            (await (async () => {
              if (!control.sessionId) return result(ctx, "http-session", "na", "the server issued no Mcp-Session-Id (stateless), so session handling was not graded", [controlEv]);
              const forged = `sm-forged-${randomBytes(6).toString("hex")}`;
              const none = await listTools(conn, control, {}, { "mcp-session-id": null });
              const fake = await listTools(conn, control, {}, { "mcp-session-id": forged });
              const second = await track();
              const evNone: Evidence = { probe: "POST tools/list without Mcp-Session-Id", outcome: hasTools(none) ? "tools returned" : describeReply(none), verifiedBy: "http", code: "http.session" };
              const evFake: Evidence = { probe: "POST tools/list with a forged Mcp-Session-Id", outcome: hasTools(fake) ? "tools returned" : describeReply(fake), verifiedBy: "http", code: "http.session" };
              const sid = control.sessionId;
              const weakWhy: string[] = [];
              if (weakSessionId(sid)) weakWhy.push(sid.length < 16 ? `only ${sid.length} characters` : "characters outside the visible ASCII range");
              if (second.sessionId && second.sessionId === sid) weakWhy.push("the same id was issued to two separate initializations");
              const evId: Evidence = { probe: "inspect the issued Mcp-Session-Id", outcome: weakWhy.length ? `weak: ${weakWhy.join("; ")}` : `${sid.length} printable characters, different on a second initialization`, verifiedBy: "http", code: "http.session-entropy" };
              const evidence = [controlEv, evNone, evFake, evId];
              const accepted: string[] = [];
              if (hasTools(none)) accepted.push("a request with no session id");
              if (hasTools(fake)) accepted.push("a forged session id");
              if (accepted.length) return result(ctx, "http-session", "fail", `the server issued a session id but accepted ${accepted.join(" and ")}`, evidence);
              const rejectedOk = [none, fake].every((r) => r.status === 400 || r.status === 404);
              if (!rejectedOk) return result(ctx, "http-session", "part", `requests with a missing or forged session id were not accepted, but the statuses (${describeReply(none)}; ${describeReply(fake)}) are not the 400/404 the specification names`, evidence);
              if (weakWhy.length) return result(ctx, "http-session", "part", `session ids are validated, but the issued id is weak: ${weakWhy.join("; ")}`, evidence);
              return result(ctx, "http-session", "pass", `missing and forged session ids are rejected (${none.status}, ${fake.status}) and the issued id is ${sid.length} printable characters, different each time`, evidence);
            })()),
        );

        // ---- http-cors ----
        out.push(
          await (async () => {
            const d = off("http-cors");
            if (d) return d;
            const r = await send(conn, { method: "OPTIONS", noConfigured: true, headers: { origin: EVIL_ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": "content-type, mcp-session-id, authorization" } });
            if (r.status === 0) return result(ctx, "http-cors", "inconclusive", `no response to the preflight (${r.error})`, []);
            const acao = r.headers.get("access-control-allow-origin");
            const acac = (r.headers.get("access-control-allow-credentials") ?? "").toLowerCase() === "true";
            const ev: Evidence = { probe: `OPTIONS with Origin: ${EVIL_ORIGIN}`, outcome: `HTTP ${r.status}; Access-Control-Allow-Origin: ${acao ?? "(absent)"}; Allow-Credentials: ${acac}`, verifiedBy: "http", code: "http.cors" };
            // A redirect answers for the redirect, not for the endpoint behind it: no allowance on it says nothing about CORS.
            if (r.status >= 300 && r.status < 400) return result(ctx, "http-cors", "inconclusive", `HTTP ${r.status}: the server redirected the preflight (Location: ${excerpt(locationOf(r) || "(absent)", 100)}); try the URL with a trailing slash`, [ev]);
            // A pass is a claim about a server the harness could talk to: it needs the control initialize to have worked.
            if (!acao) return controlOk ? result(ctx, "http-cors", "pass", `the preflight from a hostile origin got no CORS allowance (HTTP ${r.status})`, [ev]) : result(ctx, "http-cors", "inconclusive", `the preflight got no CORS allowance (HTTP ${r.status}), but the harness's own initialize was not accepted (${describeReply(control.reply)}), so the answer could not be told from a misconfiguration; check server.url and server.headers`, [controlEv, ev]);
            if (acao === "*") return result(ctx, "http-cors", acac ? "fail" : "part", acac ? "every origin is allowed together with credentials" : "every origin (*) is allowed, so any web page can read responses", [ev]);
            if (acao === EVIL_ORIGIN) return result(ctx, "http-cors", acac ? "fail" : "part", acac ? "the hostile origin is reflected together with credentials" : "the hostile origin is reflected, so any web page can read responses", [ev]);
            return controlOk ? result(ctx, "http-cors", "pass", `CORS names a fixed origin (${acao}), not the hostile one`, [ev]) : result(ctx, "http-cors", "inconclusive", `CORS names a fixed origin (${acao}), but the harness's own initialize was not accepted (${describeReply(control.reply)}), so the answer could not be told from a misconfiguration; check server.url and server.headers`, [controlEv, ev]);
          })(),
        );

        // ---- http-bind (advisory) ----
        out.push(
          await (async () => {
            const d = off("http-bind");
            if (d) return d;
            // A server Sealmark started itself (command + url) is bound however the user's start command binds it,
            // usually 0.0.0.0 inside a CI container. That is not what this advisory is about.
            if (ctx.config.server.command) return result(ctx, "http-bind", "na", "Sealmark started this server itself (server.command), so how it binds in this job is not examined", []);
            if (!loopback) return result(ctx, "http-bind", "na", `the configured host (${host}) is not loopback, so the bind address of the server's machine is not examined`, []);
            let table: string;
            try {
              table = await (deps.listenerTable ?? listenerTable)();
            } catch (e) {
              return result(ctx, "http-bind", "na", `the listening-socket table could not be read (${(e as Error).message})`, []);
            }
            const found = exposureOf(listeningAddresses(table, port));
            const ev: Evidence = { probe: `listening sockets on port ${port}`, outcome: found.addrs.length ? found.addrs.join(", ") : "none found", verifiedBy: "process", code: "http.bind" };
            if (found.kind === "none") return result(ctx, "http-bind", "na", `no socket listening on port ${port} was found on this machine (the server may run in a container or another host)`, [ev]);
            if (found.kind === "wildcard") return result(ctx, "http-bind", "fail", `the server listens on every interface (${found.addrs.join(", ")}), so other machines on the network can reach it`, [ev]);
            if (found.kind === "interface") return result(ctx, "http-bind", "fail", `the server listens on a non-loopback address (${found.addrs.join(", ")})`, [ev]);
            return result(ctx, "http-bind", "pass", `the server listens on loopback only (${found.addrs.join(", ")})`, [ev]);
          })(),
        );

        // ---- http-tls (advisory) ----
        out.push(
          (() => {
            const ev: Evidence = { probe: "server.url scheme", outcome: `${protocol} to ${host}`, verifiedBy: "static", code: "http.tls" };
            if (protocol === "https:") return result(ctx, "http-tls", "pass", "the URL uses https", [ev]);
            if (loopback) return result(ctx, "http-tls", "na", "plain http to a loopback address does not leave the machine", [ev]);
            return result(ctx, "http-tls", creds.length ? "fail" : "part", creds.length ? `plain http to ${host} with credential headers configured (${creds.join(", ")}): they travel unencrypted` : `plain http to ${host}: tool traffic is not encrypted`, [ev]);
          })(),
        );
      } finally {
        // Sessions the probes created are ended so the server does not keep them.
        for (const s of created) await terminate(conn, s).catch(() => {});
      }
      return out;
    },
  };
}

export const pack: Pack = makePack();
export default pack;
