import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { UpstreamMark, UpstreamMode, UpstreamReply, UpstreamRequest, UpstreamStub } from "../types.js";

/**
 * The upstream stub: a loopback HTTP server the harness owns, standing in for the backend of the server
 * under test. It records every request it receives and answers from a script, so "did the server forward this" and "whose credential
 * did it send" become "what did the stub see". It never proxies, never follows anything and never contacts another host; it binds
 * 127.0.0.1 only.
 */

/** One entry of `upstream.responses`: the first entry whose `match` holds answers; an entry with no `match` matches everything. */
export interface UpstreamResponseRule {
  /** Defaults to `responses[<n>]`. */
  id?: string;
  match?: {
    /** Exact, case-insensitive. */
    method?: string;
    /** Regex over the pathname. */
    path?: string;
    /** Regex over the request body. */
    body?: string;
    /** Header name (any case) to regex over its value. */
    header?: Record<string, string>;
  };
  reply: UpstreamReply;
}

export interface UpstreamOptions {
  responses: UpstreamResponseRule[];
  defaultReply: UpstreamReply;
  /** Request bodies are kept up to this many bytes (`upstream.max_body_kib`). */
  maxBodyBytes: number;
  /** How long `slow` mode holds a reply when `setMode` gives no delay. */
  slowHoldMs: number;
  /** The request header the `error` mode echoes. Default `authorization`. */
  credentialHeader?: string;
  log?: (s: string) => void;
}

/** More than this many requests are not kept: the oldest go first (ids stay monotonic, so a mark taken earlier still reads correctly). */
const MAX_KEPT = 20_000;
/** A request body past this is read and thrown away rather than buffered. */
const DRAIN_LIMIT = 16 * 1024 * 1024;
/** What an unconfigured default reply is (`upstream.default_reply`'s own default). */
const FALLBACK_REPLY: UpstreamReply = { status: 200, json: {} };

const rand = (n: number) => randomBytes(n).toString("hex");

const matches = (pattern: string | undefined, text: string): boolean => {
  if (pattern === undefined) return true;
  try {
    return new RegExp(pattern).test(text);
  } catch {
    // A pattern that is not a regex never matches (the configuration layer rejects it before a run).
    return false;
  }
};

function ruleMatches(rule: UpstreamResponseRule, req: { method: string; path: string; body: string; headers: Record<string, string> }): boolean {
  const m = rule.match;
  if (!m) return true;
  if (m.method !== undefined && m.method.toLowerCase() !== req.method.toLowerCase()) return false;
  if (!matches(m.path, req.path)) return false;
  if (!matches(m.body, req.body)) return false;
  for (const [name, pattern] of Object.entries(m.header ?? {})) {
    if (!matches(pattern, req.headers[name.toLowerCase()] ?? "")) return false;
  }
  return true;
}

interface Built {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  minted: string[];
}

/** Fills `{upstream_token}` (a fresh value per occurrence, recorded) and `{token}` (one value for the whole reply), then pads to `bytes`. */
function build(reply: UpstreamReply): Built {
  const minted: string[] = [];
  const whole = `sm-${rand(6)}`;
  const raw = reply.json !== undefined ? JSON.stringify(reply.json) : (reply.body ?? "");
  const text = raw.replace(/\{(upstream_token|token)\}/g, (_m, key: string) => {
    if (key === "token") return whole;
    const t = `sm-row-${rand(4)}`;
    minted.push(t);
    return t;
  });
  let body = Buffer.from(text, "utf8");
  // A `bytes` reply is padded with spaces after the body, which keeps JSON valid.
  if (reply.bytes !== undefined && reply.bytes > body.length) body = Buffer.concat([body, Buffer.alloc(reply.bytes - body.length, 0x20)]);
  const headers: Record<string, string> = { "content-type": reply.json !== undefined || /^\s*[[{]/.test(text) ? "application/json" : "text/plain; charset=utf-8" };
  for (const [k, v] of Object.entries(reply.headers ?? {})) {
    for (const have of Object.keys(headers)) if (have.toLowerCase() === k.toLowerCase()) delete headers[have];
    headers[k] = v;
  }
  return { status: reply.status ?? 200, headers, body, minted };
}

/** Waits `ms`; `release` (called at close) ends every wait early so a held reply does not outlive the stub. */
const sleep = (ms: number, release: Set<() => void>) =>
  new Promise<void>((resolve) => {
    const end = (): void => {
      clearTimeout(t);
      release.delete(end);
      resolve();
    };
    const t = setTimeout(end, ms);
    release.add(end);
  });

export async function startUpstream(o: UpstreamOptions): Promise<UpstreamStub> {
  const credentialHeader = (o.credentialHeader ?? "authorization").toLowerCase();
  const errorCanary = `sm-upstream-err-${rand(6)}`;
  const kept: UpstreamRequest[] = [];
  let lastId = 0;
  let mode: UpstreamMode = "normal";
  let modeDelayMs = o.slowHoldMs;
  let override: UpstreamReply | undefined;
  let closed = false;
  const waiters = new Set<{ check(): void; done(): void }>();
  const timers = new Set<() => void>();

  const haystack = (r: UpstreamRequest): string => `${r.path}${r.query}\n${Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${r.body}`.toLowerCase();
  const since = (mark: UpstreamMark | undefined): UpstreamRequest[] => kept.filter((r) => r.id > (mark ?? 0));
  const find = (needle: string, mark?: UpstreamMark): UpstreamRequest[] => {
    const n = needle.toLowerCase();
    return since(mark).filter((r) => haystack(r).includes(n));
  };

  /** What this request gets, in the order the design pins: the probe's override, then the mode, then the rules, then the default. */
  const decide = (req: UpstreamRequest): { reply: UpstreamReply; ruleId: string; delayMs: number } => {
    if (override) return { reply: override, ruleId: "probe", delayMs: override.delay_ms ?? 0 };
    if (mode === "error") {
      const credential = req.headers[credentialHeader] ?? "";
      return { reply: { status: 500, json: { error: errorCanary, received: { authorization: credential } } }, ruleId: "mode:error", delayMs: 0 };
    }
    if (mode === "slow") return { reply: o.defaultReply ?? FALLBACK_REPLY, ruleId: "mode:slow", delayMs: modeDelayMs };
    for (const [i, rule] of o.responses.entries()) {
      if (ruleMatches(rule, req)) return { reply: rule.reply, ruleId: rule.id ?? `responses[${i}]`, delayMs: rule.reply.delay_ms ?? 0 };
    }
    const d = o.defaultReply ?? FALLBACK_REPLY;
    return { reply: d, ruleId: "default", delayMs: d.delay_ms ?? 0 };
  };

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    let seen = 0;
    let truncated = false;
    req.on("data", (c: Buffer) => {
      seen += c.length;
      if (seen > DRAIN_LIMIT) return;
      const room = o.maxBodyBytes - (seen - c.length);
      if (room <= 0) {
        truncated = true;
        return;
      }
      if (c.length > room) {
        chunks.push(c.subarray(0, room));
        truncated = true;
      } else chunks.push(c);
    });
    req.on("error", () => {});
    req.on("end", () => {
      void (async () => {
        const url = new URL(req.url ?? "/", "http://stub.invalid");
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
        const record: UpstreamRequest = {
          id: ++lastId,
          at: Date.now(),
          method: req.method ?? "GET",
          path: url.pathname,
          query: url.search,
          headers,
          body: Buffer.concat(chunks).toString("utf8"),
          bodyTruncated: truncated,
          reply: { status: 0, bytes: 0, ruleId: "", delayMs: 0 },
          minted: [],
        };
        kept.push(record);
        if (kept.length > MAX_KEPT) kept.splice(0, kept.length - MAX_KEPT);
        try {
          const d = decide(record);
          const built = build(d.reply);
          record.reply = { status: built.status, bytes: built.body.length, ruleId: d.ruleId, delayMs: d.delayMs };
          record.minted = built.minted;
          // The request is visible to find()/waitFor() from here on, even while a slow reply is still being held.
          for (const w of [...waiters]) w.check();
          o.log?.(`upstream: ${record.method} ${record.path} -> ${built.status} (${d.ruleId})`);
          if (d.delayMs > 0) await sleep(d.delayMs, timers);
          if (closed || res.destroyed) return;
          res.writeHead(built.status, { ...built.headers, "content-length": String(built.body.length) });
          res.end(built.body);
        } catch (e) {
          if (!res.headersSent && !res.destroyed) {
            res.writeHead(500, { "content-type": "text/plain" });
            res.end(`upstream stub error: ${(e as Error).message}`);
          }
        }
      })();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // Loopback only: the stub is the server's backend for the length of a run and must never be reachable from the network.
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const port = (server.address() as AddressInfo).port;

  return {
    kind: "http",
    url: `http://127.0.0.1:${port}`,
    port,
    errorCanary,
    mark: () => lastId,
    requests: (mark) => since(mark).map((r) => ({ ...r })),
    find: (needle, mark) => find(needle, mark).map((r) => ({ ...r })),
    setMode(next, opts) {
      mode = next;
      modeDelayMs = opts?.delayMs ?? o.slowHoldMs;
    },
    setOverride(reply) {
      override = reply;
    },
    waitFor(needle, timeoutMs, mark) {
      return new Promise<UpstreamRequest[]>((resolve) => {
        const done = (): void => {
          clearTimeout(timer);
          waiters.delete(waiter);
          resolve(find(needle, mark).map((r) => ({ ...r })));
        };
        const waiter = { check: (): void => (find(needle, mark).length ? done() : undefined), done };
        const timer = setTimeout(done, timeoutMs);
        waiters.add(waiter);
        waiter.check();
      });
    },
    async close() {
      if (closed) return;
      closed = true;
      for (const end of [...timers]) end();
      for (const w of [...waiters]) w.done();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}
