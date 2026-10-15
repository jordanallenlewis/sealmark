// Toy Streamable HTTP MCP server for the http pack, built on the MCP SDK's StreamableHTTPServerTransport and node:http (no express).
// Run: node dist/toy/http.js --mode <good|open|cors-star|redirect-slash> [--port <n>] [--token <bearer>] [--backend <url>]
// It listens on 127.0.0.1 only (a toy must never be reachable from the network) and prints `listening http://127.0.0.1:<port>/mcp`.
// With --backend <url> (an extra knob, not a mode) the toy also offers a `forward` tool that POSTs {"q": ...} to <url>/sql with the caller's own
// Authorization header, and it accepts any non-empty bearer token (the caller's token is passed through, not compared): the harness's upstream
// stub tests start it that way.
// Not part of the product surface. Expected http pack results, run with the bearer token as server.headers:
//   good       Host/Origin validated, bearer token required, sessions validated, protocol version validated, no CORS headers      A
//   open       nothing validated: any Origin, no auth, a static session id that is never checked, version header ignored, CORS reflected   F
//   cors-star  good, except every response allows any origin with credentials                                                      B
//   redirect-slash  answers every request to /mcp with a 307 to /mcp/ (the endpoint behind it behaves like good): the harness does not
//              follow redirects, so its own initialize fails and every check is inconclusive, http-cors included (a 307 says nothing about CORS)
import { randomUUID } from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export const HTTP_TOY_MODES = ["good", "open", "cors-star", "redirect-slash"] as const;
export type HttpToyMode = (typeof HTTP_TOY_MODES)[number];
/** The bearer token modes `good` and `cors-star` require. */
export const HTTP_TOY_TOKEN = "sm-toy-bearer-token";

export interface HttpToy {
  mode: HttpToyMode;
  port: number;
  /** The MCP endpoint, for example http://127.0.0.1:41234/mcp. */
  url: string;
  token: string;
  /** Requests received so far, by method (tests use it to prove a probe was or was not sent). */
  seen: Record<string, number>;
  close(): Promise<void>;
}

function makeServer(mode: HttpToyMode, backend?: string): Server {
  const server = new Server({ name: `sealmark-toy-http-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: "echo", description: "Return the given text unchanged.", inputSchema: { type: "object", properties: { text: { type: "string", description: "Text to return" } }, required: ["text"] } },
      ...(backend ? [{ name: "list_items", description: "List the items this server knows about.", inputSchema: { type: "object", properties: {} }, annotations: { readOnlyHint: true } }] : []),
      ...(backend ? [{ name: "inspect", description: "Report this server's working directory and whether the marker variable SM_R6_MARKER is set.", inputSchema: { type: "object", properties: {} } }] : []),
      ...(backend ? [{ name: "forward", description: "Send a query to the backend with the caller's own credential and return its reply.", inputSchema: { type: "object", properties: { q: { type: "string", description: "Query text" } }, required: ["q"] } }] : []),
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    if (backend && req.params.name === "inspect") return { content: [{ type: "text", text: JSON.stringify({ cwd: process.cwd(), marker: process.env.SM_R6_MARKER ?? null }) }] };
    if (backend && req.params.name === "list_items") return { content: [{ type: "text", text: "item-1, item-2" }] };
    if (backend && req.params.name === "forward") {
      const q = (req.params.arguments ?? {}).q;
      if (typeof q !== "string") return { content: [{ type: "text", text: "q must be a string" }], isError: true };
      const auth = extra.requestInfo?.headers?.authorization;
      try {
        const r = await fetch(`${backend}/sql`, { method: "POST", headers: { "content-type": "application/json", ...(typeof auth === "string" ? { authorization: auth } : {}) }, body: JSON.stringify({ q }), signal: AbortSignal.timeout(5000) });
        return { content: [{ type: "text", text: await r.text() }], ...(r.ok ? {} : { isError: true }) };
      } catch (e) {
        return { content: [{ type: "text", text: `backend unreachable: ${(e as Error).message}` }], isError: true };
      }
    }
    const text = (req.params.arguments ?? {}).text;
    return typeof text === "string" ? { content: [{ type: "text", text }] } : { content: [{ type: "text", text: "text must be a string" }], isError: true };
  });
  return server;
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
      } else chunks.push(c);
    });
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

function jsonError(res: http.ServerResponse, status: number, code: number, message: string, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }));
}

export async function startHttpToy(mode: HttpToyMode, opts: { port?: number; token?: string; backend?: string } = {}): Promise<HttpToy> {
  const token = opts.token ?? HTTP_TOY_TOKEN;
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server }>();
  let port = 0;
  const seen: Record<string, number> = {};

  const hostOk = (host: string | undefined) => host === `127.0.0.1:${port}` || host === `localhost:${port}` || host === `[::1]:${port}`;
  const originOk = (origin: string) => origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}` || origin === "http://127.0.0.1" || origin === "http://localhost";

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    seen[(req.method ?? "GET").toLowerCase()] = (seen[(req.method ?? "GET").toLowerCase()] ?? 0) + 1;
    if (mode === "redirect-slash" && url.pathname === "/mcp") {
      res.writeHead(307, { location: "/mcp/" });
      return void res.end();
    }
    if (url.pathname !== "/mcp" && !(mode === "redirect-slash" && url.pathname === "/mcp/")) return jsonError(res, 404, -32000, "Not found");
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;

    // CORS first, like a CORS middleware: `good` sends none; `open` reflects any origin with credentials; `cors-star` allows every origin with credentials.
    if (origin && mode === "open") {
      res.setHeader("access-control-allow-origin", origin);
      res.setHeader("access-control-allow-credentials", "true");
    } else if (mode === "cors-star") {
      res.setHeader("access-control-allow-origin", "*");
      res.setHeader("access-control-allow-credentials", "true");
    }

    if (mode !== "open") {
      // DNS-rebinding protection: the Host header and any Origin must be this server's own loopback names.
      if (!hostOk(req.headers.host)) return jsonError(res, 403, -32000, "Forbidden: invalid Host header");
      if (origin && !originOk(origin)) return jsonError(res, 403, -32000, "Forbidden: invalid Origin header");
    }
    if (req.method === "OPTIONS") {
      if (mode !== "good" && mode !== "redirect-slash") {
        res.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
        res.setHeader("access-control-allow-headers", "content-type, authorization, mcp-session-id, mcp-protocol-version");
      }
      res.writeHead(204);
      return void res.end();
    }
    // With a backend the caller's token is passed through to it, so any non-empty bearer is let in here.
    const authorised = opts.backend ? /^Bearer \S+$/.test(req.headers.authorization ?? "") : req.headers.authorization === `Bearer ${token}`;
    if (mode !== "open" && !authorised) {
      return jsonError(res, 401, -32001, "Unauthorized", { "www-authenticate": 'Bearer realm="sealmark-toy"' });
    }

    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await readJson(req);
      } catch {
        return jsonError(res, 400, -32700, "Parse error");
      }
    }

    if (mode === "open") {
      // Stateless, nothing checked. It hands out the same session id every time and never looks at it again, and it ignores the version header.
      delete req.headers["mcp-protocol-version"];
      for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i]!.toLowerCase() === "mcp-protocol-version") req.rawHeaders.splice(i, 2);
      res.setHeader("mcp-session-id", "1");
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      const server = makeServer(mode, opts.backend);
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      return transport.handleRequest(req, res, body);
    }

    const sid = typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : undefined;
    if (sid) {
      const s = sessions.get(sid);
      if (!s) return jsonError(res, 404, -32001, "Session not found");
      return s.transport.handleRequest(req, res, body);
    }
    if (req.method === "POST" && isInitializeRequest(body)) {
      const server = makeServer(mode, opts.backend);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        // `good` answers with an SSE stream (the SDK default); `cors-star` answers with plain JSON, so both framings are exercised.
        enableJsonResponse: mode === "cors-star",
        onsessioninitialized: (id) => void sessions.set(id, { transport, server }),
      });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      return transport.handleRequest(req, res, body);
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
    token,
    seen,
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

// Command line entry: only when this file is the program, not when a test imports it.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { mode: { type: "string" }, port: { type: "string" }, token: { type: "string" }, backend: { type: "string" } }, strict: true });
  const mode = values.mode as HttpToyMode;
  if (!HTTP_TOY_MODES.includes(mode)) {
    process.stderr.write(`toy http server: --mode must be one of ${HTTP_TOY_MODES.join(", ")}\n`);
    process.exit(2);
  }
  const toy = await startHttpToy(mode, { port: values.port ? Number(values.port) : 0, token: values.token, backend: values.backend });
  process.stdout.write(`listening ${toy.url}\n`);
  const stop = () => void toy.close().finally(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
