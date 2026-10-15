// Toy Streamable HTTP MCP server for the round 6 `upstream` pack: a server that forwards one tool call to a backend with the caller's credential.
// Run: node dist/toy/cred-r6.js --mode <mode> --backend <url> [--port <n>] [--backend-timeout-ms <n>]
// Loopback only; prints `listening http://127.0.0.1:<port>/mcp`. Not part of the product surface. Every mode differs from `good` in one thing:
//   good         bearer required; POST {backend}/lookup with the caller's Authorization header unchanged; a backend error becomes a fixed message
//   static       sends TOY_STATIC_TOKEN (read only in this mode) instead of the caller's credential         -> upstream-credential (static)
//   swap         caches the first caller's Authorization header and sends it for every later caller         -> upstream-credential (other identity's)
//   logged       writes the Authorization header to stderr                                                  -> log-secret
//   echoed       appends the caller's token to every reply                                                  -> upstream-credential-echo
//   leak         relays the backend's error body raw                                                        -> upstream-error-leak
//   hang         no timeout on the backend call                                                              -> upstream-slow
//   anon-static  like good, but needs no caller credential and sends TOY_STATIC_TOKEN when there is none    -> upstream-credential (anonymous leg)
//   anon-open    like good, but needs no caller credential and sends none when there is none                  -> upstream-credential passes the anonymous leg
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export const CRED_TOY_MODES = ["good", "static", "swap", "logged", "echoed", "leak", "hang", "anon-static", "anon-open"] as const;
export type CredToyMode = (typeof CRED_TOY_MODES)[number];

export interface CredToy {
  mode: CredToyMode;
  port: number;
  /** The MCP endpoint, for example http://127.0.0.1:41234/mcp. */
  url: string;
  close(): Promise<void>;
}

export interface CredToyOptions {
  port?: number;
  /** Base URL of the backend (the harness's upstream stub). */
  backend: string;
  /** How long `good` waits for the backend (default 3000). `hang` never times out. */
  backendTimeoutMs?: number;
  /** Where `logged` writes (default: this process's stderr). Tests inject a recorder when the toy runs in-process. */
  log?: (line: string) => void;
}

const caller = new AsyncLocalStorage<{ authorization: string | undefined }>();

function makeServer(mode: CredToyMode, o: Required<Pick<CredToyOptions, "backend" | "backendTimeoutMs" | "log">>, state: { cached?: string }): Server {
  const server = new Server({ name: `sealmark-toy-cred-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "lookup", description: "Look up one record in the backend by id.", inputSchema: { type: "object", properties: { id: { type: "string", description: "Record id" } }, required: ["id"] }, annotations: { readOnlyHint: true } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const id = (req.params.arguments ?? {}).id;
    if (typeof id !== "string") return { content: [{ type: "text", text: "id must be a string" }], isError: true };
    const auth = caller.getStore()?.authorization;
    if (mode === "logged") o.log(`lookup id=${id} authorization=${auth ?? "(none)"}`);
    if (mode === "swap" && auth && state.cached === undefined) state.cached = auth;
    const staticToken = process.env.TOY_STATIC_TOKEN ?? "static-service-token";
    const forwarded =
      mode === "static" ? `Bearer ${staticToken}` : mode === "swap" ? state.cached : mode === "anon-static" ? (auth ?? `Bearer ${staticToken}`) : auth;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (forwarded) headers.authorization = forwarded;
    const tail = mode === "echoed" ? ` (caller token: ${auth ?? "none"})` : "";
    let r: Response;
    try {
      r = await fetch(`${o.backend}/lookup`, {
        method: "POST",
        headers,
        body: JSON.stringify({ id, submitter: "mcp:toy" }),
        ...(mode === "hang" ? {} : { signal: AbortSignal.timeout(o.backendTimeoutMs) }),
      });
    } catch {
      return { content: [{ type: "text", text: `the backend did not answer in time${tail}` }], isError: true };
    }
    const text = await r.text();
    if (!r.ok) {
      if (mode === "leak") return { content: [{ type: "text", text: `backend error ${r.status}: ${text}` }], isError: true };
      return { content: [{ type: "text", text: `the backend could not run the lookup (status ${r.status}); nothing from its reply is shown${tail}` }], isError: true };
    }
    let rows = 0;
    try {
      const j = JSON.parse(text) as { rows?: unknown[] };
      rows = Array.isArray(j.rows) ? j.rows.length : 0;
    } catch {
      // a non-JSON backend reply counts as no rows
    }
    return { content: [{ type: "text", text: `found ${rows} record(s) for ${id}${tail}` }] };
  });
  return server;
}

function readBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve(undefined);
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function jsonError(res: http.ServerResponse, status: number, code: number, message: string): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }));
}

export async function startCredToy(mode: CredToyMode, opts: CredToyOptions): Promise<CredToy> {
  const o = { backend: opts.backend.replace(/\/$/, ""), backendTimeoutMs: opts.backendTimeoutMs ?? 3000, log: opts.log ?? ((l: string) => void process.stderr.write(`${l}\n`)) };
  const state: { cached?: string } = {};
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();
  let port = 0;
  const open = mode === "anon-static" || mode === "anon-open";

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    if (url.pathname !== "/mcp") return jsonError(res, 404, -32000, "Not found");
    const host = req.headers.host;
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return jsonError(res, 403, -32000, "Forbidden: invalid Host header");
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    if (origin && origin !== `http://127.0.0.1:${port}` && origin !== `http://localhost:${port}`) return jsonError(res, 403, -32000, "Forbidden: invalid Origin header");
    const authorization = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
    if (!open && !/^Bearer \S+$/.test(authorization ?? "")) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": 'Bearer realm="sealmark-toy"' });
      return void res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }));
    }
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await readBody(req);
      } catch {
        return jsonError(res, 400, -32700, "Parse error");
      }
    }
    const sid = typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : undefined;
    if (sid) {
      const s = sessions.get(sid);
      if (!s) return jsonError(res, 404, -32001, "Session not found");
      return caller.run({ authorization }, () => s.transport.handleRequest(req, res, body));
    }
    if (req.method === "POST" && isInitializeRequest(body)) {
      const server = makeServer(mode, o, state);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => void sessions.set(id, { transport, server }),
      });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      return caller.run({ authorization }, () => transport.handleRequest(req, res, body));
    }
    return jsonError(res, 400, -32000, "Bad Request: Mcp-Session-Id header is required");
  };

  const httpServer = http.createServer((req, res) => {
    handler(req, res).catch((e: unknown) => jsonError(res, 500, -32603, e instanceof Error ? e.message : "internal error"));
  });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.port ?? 0, "127.0.0.1", () => resolve());
  });
  port = (httpServer.address() as { port: number }).port;
  return {
    mode,
    port,
    url: `http://127.0.0.1:${port}/mcp`,
    async close() {
      for (const { transport, server } of sessions.values()) {
        await transport.close().catch(() => {});
        await server.close().catch(() => {});
      }
      sessions.clear();
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
        httpServer.closeAllConnections();
      });
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { mode: { type: "string" }, port: { type: "string" }, backend: { type: "string" }, "backend-timeout-ms": { type: "string" } }, strict: true });
  const mode = values.mode as CredToyMode;
  if (!CRED_TOY_MODES.includes(mode) || !values.backend) {
    process.stderr.write(`toy cred server: --mode must be one of ${CRED_TOY_MODES.join(", ")} and --backend is required\n`);
    process.exit(2);
  }
  const toy = await startCredToy(mode, { port: values.port ? Number(values.port) : 0, backend: values.backend, ...(values["backend-timeout-ms"] ? { backendTimeoutMs: Number(values["backend-timeout-ms"]) } : {}) });
  process.stdout.write(`listening ${toy.url}\n`);
  const stop = () => void toy.close().finally(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
