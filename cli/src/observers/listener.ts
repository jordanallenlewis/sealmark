// Loopback canary listener: HTTP and raw TCP on 127.0.0.1 (and [::1] when the host has IPv6 loopback).
// It is the only network target the net pack ever sends a server to. Nothing is proxied or forwarded.
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { isAbsolute, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export interface ListenerOptions {
  /** How long /slow holds the response. Default 40 000 ms (timeout probe 10 s + 30 s). */
  slowHoldMs?: number;
  /** Body size of /big. Default 64 MiB. */
  bigBytes?: number;
}

export interface ConnectionRecord {
  id: number;
  at: number;
  family: "IPv4" | "IPv6";
  remotePort: number;
  /** First bytes the client sent, printable ASCII only (empty when it sent nothing). */
  firstBytes: string;
  /** Number of HTTP requests parsed on this connection. 0 means a non-HTTP client (ftp, gopher, dict, ...). */
  httpRequests: number;
}

export interface RequestRecord {
  id: number;
  at: number;
  family: "IPv4" | "IPv6";
  method: string;
  path: string;
  host: string;
  route: "t" | "redir" | "redir-to" | "big" | "slow" | "other";
  /** Token taken from /t/<token>, /redir/<token> or /redir-to/<token>. */
  token?: string;
  /** The Location the listener sent (/redir-to answered 302). Only ever the listener itself or a sandbox file. */
  location?: string;
  /** /redir-to refused its `to=` target with a 400 (see redirectTargetProblem). A harness bug when it happens in a run. */
  refusedTarget?: boolean;
  status?: number;
  bytesSent: number;
  /** The client went away before the response finished. */
  aborted: boolean;
  /** Response finished (or the client left); false while a /slow request is still held. */
  done: boolean;
}

export interface Listener {
  readonly port: number;
  /** Port of the [::1] listener, when IPv6 loopback is available. Same number as `port` when it was free. */
  readonly port6?: number;
  /** Base URLs without a trailing slash. */
  readonly url: string;
  readonly url6?: string;
  /** Length of the /big body in bytes (64 MiB unless `bigBytes` was given): what a server that consumed the whole body has read. */
  readonly bigBytes: number;
  requests(): RequestRecord[];
  connections(): ConnectionRecord[];
  /** HTTP requests whose path carries this token (any route). */
  hitsFor(token: string): RequestRecord[];
  /** Same as hitsFor, named for the plugin API. */
  expect(token: string): RequestRecord[];
  /** Every request whose path or Location carries the token, in arrival order: the redirecting request and whatever followed it. */
  hopsFor(token: string): RequestRecord[];
  /** Allow /redir-to to send file: URLs that point inside this directory (until this is called every file: target is refused). */
  allowFileRedirectsUnder(dir: string): void;
  /** Connections that never spoke HTTP (raw TCP hits). */
  rawConnections(): ConnectionRecord[];
  /** Poll until a request for the token is seen, or the time runs out. */
  waitForHit(token: string, timeoutMs?: number): Promise<RequestRecord[]>;
  /** Drop recorded hits. Does not close anything. */
  reset(): void;
  close(): Promise<void>;
}

const TOKEN_ROUTE = /^\/(t|redir)\/([^/?#]+)/;
const REDIR_TO_ROUTE = /^\/redir-to\/([^/?#]+)/;

const QUAD = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * A copy of the loopback-spelling test of packs/net.ts (isLoopbackHost, without the DNS option): the listener must not import a
 * pack. The tests assert that both agree on a fixed list of spellings. `host` is a URL hostname, so for http: the parser has
 * already turned 127.1, 0x7f000001 and 2130706433 into 127.0.0.1.
 */
export function isLoopbackSpelling(host: string): boolean {
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
  return false;
}

function insideDir(dir: string, path: string): boolean {
  const fold = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
  const rel = relative(fold(dir), fold(path));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel) && !rel.split(sep).includes(".."));
}

/**
 * Why /redir-to may not send a Location to `to`, or undefined when it may. The listener redirects only to itself or to a file in
 * the sandbox: an http: URL on a loopback spelling with one of its own ports; a gopher:, dict: or ftp: URL on a loopback spelling
 * with one of its own ports; a file: URL inside `fileRoot` (unset: none). https: is never served (the listener speaks plain http),
 * and any other host, port or scheme (data:, javascript:, ...) is refused.
 */
export function redirectTargetProblem(to: string, o: { ports: number[]; fileRoot?: string }): string | undefined {
  let u: URL;
  try {
    u = new URL(to);
  } catch {
    return "not an absolute URL";
  }
  if (u.protocol === "file:") {
    if (!o.fileRoot) return "file: targets are not allowed (no sandbox directory was set)";
    let p: string;
    try {
      p = fileURLToPath(u);
    } catch {
      return "file: URL with a host other than localhost";
    }
    return insideDir(o.fileRoot, p) ? undefined : "file: URL outside the sandbox";
  }
  if (u.protocol !== "http:" && u.protocol !== "gopher:" && u.protocol !== "dict:" && u.protocol !== "ftp:") return `scheme ${u.protocol} is not served`;
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || !isLoopbackSpelling(host)) return `host ${host || "(none)"} is not a loopback address`;
  if (!o.ports.includes(Number(u.port))) return `port ${u.port || "(default)"} is not the listener's`;
  return undefined;
}

function printable(b: Buffer): string {
  return b
    .subarray(0, 120)
    .toString("latin1")
    .replace(/[^\x20-\x7e]/g, ".");
}

export async function startListener(opts: ListenerOptions = {}): Promise<Listener> {
  const slowHoldMs = opts.slowHoldMs ?? 40_000;
  const bigBytes = opts.bigBytes ?? 64 * 1024 * 1024;
  let reqs: RequestRecord[] = [];
  let conns: ConnectionRecord[] = [];
  let nextId = 1;
  const timers = new Set<NodeJS.Timeout>();
  const servers: http.Server[] = [];

  const connState = new WeakMap<Socket, ConnectionRecord>();
  let fileRoot: string | undefined;
  /** The listener's own ports (IPv4 and IPv6), filled in once both servers are listening. */
  let own: number[] = [];

  const make = (family: "IPv4" | "IPv6"): http.Server => {
    const server = http.createServer((req, res) => {
      const path = req.url ?? "/";
      const m = TOKEN_ROUTE.exec(path);
      let token: string | undefined;
      if (m) {
        try {
          token = decodeURIComponent(m[2]!);
        } catch {
          token = m[2];
        }
      }
      const rt = m ? null : REDIR_TO_ROUTE.exec(path);
      if (rt) {
        try {
          token = decodeURIComponent(rt[1]!);
        } catch {
          token = rt[1];
        }
      }
      const route: RequestRecord["route"] = m ? (m[1] as "t" | "redir") : rt ? "redir-to" : path.startsWith("/big") ? "big" : path.startsWith("/slow") ? "slow" : "other";
      const rec: RequestRecord = { id: nextId++, at: Date.now(), family, method: req.method ?? "GET", path, host: String(req.headers.host ?? ""), route, token, bytesSent: 0, aborted: false, done: false };
      reqs.push(rec);
      const cs = connState.get(req.socket);
      if (cs) cs.httpRequests++;
      res.on("close", () => {
        rec.done = true;
        if (!res.writableFinished) rec.aborted = true;
      });
      const send = (status: number, body: string, headers: Record<string, string> = {}) => {
        rec.status = status;
        rec.bytesSent = Buffer.byteLength(body);
        res.writeHead(status, { "content-type": "text/plain", "content-length": String(rec.bytesSent), ...headers });
        res.end(body);
      };
      req.resume();
      if (route === "t") return send(200, `sm-listener-${token}`);
      if (route === "redir") return send(302, "", { location: `/t/${encodeURIComponent(token ?? "")}` });
      if (route === "redir-to") {
        let to = "";
        try {
          to = new URL(path, "http://sm-listener.invalid").searchParams.get("to") ?? "";
        } catch {
          /* refused below */
        }
        const problem = to ? redirectTargetProblem(to, { ports: own, fileRoot }) : "no to= parameter";
        if (problem !== undefined) {
          rec.refusedTarget = true;
          return send(400, `sm-listener: refused redirect target (${problem})`);
        }
        rec.location = to;
        return send(302, "", { location: to });
      }
      if (route === "big") {
        rec.status = 200;
        res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(bigBytes) });
        const chunk = Buffer.alloc(64 * 1024, 0x78);
        let left = bigBytes;
        const pump = () => {
          while (left > 0 && !res.destroyed) {
            const part = left >= chunk.length ? chunk : chunk.subarray(0, left);
            left -= part.length;
            rec.bytesSent += part.length;
            if (!res.write(part)) {
              res.once("drain", pump);
              return;
            }
          }
          if (!res.destroyed) res.end();
        };
        pump();
        return;
      }
      if (route === "slow") {
        const t = setTimeout(() => {
          timers.delete(t);
          if (!res.destroyed) send(200, "sm-listener-slow");
        }, slowHoldMs);
        timers.add(t);
        res.on("close", () => {
          clearTimeout(t);
          timers.delete(t);
        });
        return;
      }
      send(404, "sm-listener: no such route");
    });
    server.on("connection", (socket: Socket) => {
      const rec: ConnectionRecord = { id: nextId++, at: Date.now(), family, remotePort: socket.remotePort ?? 0, firstBytes: "", httpRequests: 0 };
      conns.push(rec);
      connState.set(socket, rec);
      socket.once("data", (b: Buffer) => {
        rec.firstBytes = printable(b);
      });
      socket.on("error", () => {});
    });
    server.on("clientError", (_e, socket) => {
      try {
        socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      } catch {
        socket.destroy();
      }
    });
    return server;
  };

  const listen = (server: http.Server, port: number, host: string) =>
    new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.off("error", reject);
        resolve((server.address() as AddressInfo).port);
      });
    });

  const s4 = make("IPv4");
  const port = await listen(s4, 0, "127.0.0.1");
  servers.push(s4);
  let port6: number | undefined;
  for (const want of [port, 0]) {
    const s6 = make("IPv6");
    try {
      port6 = await listen(s6, want, "::1");
      servers.push(s6);
      break;
    } catch {
      s6.close();
    }
  }

  own = [port, ...(port6 !== undefined ? [port6] : [])];
  const hitsFor = (token: string) => (token ? reqs : []).filter((r) => r.token === token || r.path.includes(token));
  let closed = false;
  return {
    port,
    port6,
    url: `http://127.0.0.1:${port}`,
    url6: port6 !== undefined ? `http://[::1]:${port6}` : undefined,
    bigBytes,
    requests: () => reqs.slice(),
    connections: () => conns.slice(),
    hitsFor,
    expect: hitsFor,
    hopsFor: (token) => (token ? reqs : []).filter((r) => r.token === token || r.path.includes(token) || (r.location ?? "").includes(token)),
    allowFileRedirectsUnder(dir) {
      fileRoot = dir;
    },
    rawConnections: () => conns.filter((c) => c.httpRequests === 0),
    async waitForHit(token, timeoutMs = 500) {
      const end = Date.now() + timeoutMs;
      for (;;) {
        const h = hitsFor(token);
        if (h.length || Date.now() >= end) return h;
        await new Promise((r) => setTimeout(r, 25));
      }
    },
    reset() {
      reqs = [];
      conns = [];
    },
    async close() {
      if (closed) return;
      closed = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      await Promise.all(
        servers.map(
          (s) =>
            new Promise<void>((resolve) => {
              s.close(() => resolve());
              s.closeAllConnections();
            }),
        ),
      );
    },
  };
}
