// Toy Streamable HTTP MCP server for the round 6 rules (probes: expect.upstream, upstream.reply, identity, response.max_bytes).
// It stands between the caller and a backend: tools forward SQL to `POST <backend>/sql` with the caller's Authorization header passed
// through, so what a probe expects of "the upstream" can be tested against a recorder that plays the backend.
// Run: node dist/toy/rules-r6.js --mode <good|agg-raw-rows|bytecap-missing> --backend <url> [--port <n>]
// Listens on 127.0.0.1 only and prints `listening http://127.0.0.1:<port>/mcp`. Not part of the product surface.
//   good            count_rows returns only the count; query returns the backend's rows capped at 1 MiB; every forwarded body carries a submitter tag
//   agg-raw-rows    count_rows returns the backend's raw rows (breaks "aggregate-only")
//   bytecap-missing query relays the whole backend reply (breaks the byte cap)
// A bearer token is required (any non-empty one; the toy checks nothing else about it).
import { randomUUID } from "node:crypto";
import http from "node:http";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

export const RULES_TOY_MODES = ["good", "agg-raw-rows", "bytecap-missing"] as const;
export type RulesToyMode = (typeof RULES_TOY_MODES)[number];
export const RULES_TOY_BYTE_CAP = 1024 * 1024;

export interface RulesToy {
  mode: RulesToyMode;
  port: number;
  url: string;
  close(): Promise<void>;
}

type Reply = { content: { type: "text"; text: string }[]; isError?: boolean; [k: string]: unknown };
const text = (t: string, isError = false): Reply => ({ content: [{ type: "text", text: t }], ...(isError ? { isError } : {}) });

const TOOLS = [
  { name: "list_tables", description: "List the tables this server may serve.", annotations: { readOnlyHint: true }, inputSchema: { type: "object" as const, properties: {} } },
  { name: "count_rows", description: "Count the rows of one allowed table. Answers with the count only.", inputSchema: { type: "object" as const, properties: { table: { type: "string", description: "A table from list_tables" } }, required: ["table"] } },
  { name: "query", description: "Run one read-only SQL query against an allowed table.", inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "A single SELECT" } }, required: ["sql"] } },
];

async function backendCall(backend: string, sql: string, authorization: string | undefined): Promise<{ status: number; body: string }> {
  const res = await fetch(`${backend}/sql`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
    body: JSON.stringify({ sql, submitter: "mcp:toy" }),
    signal: AbortSignal.timeout(3000),
  });
  return { status: res.status, body: await res.text() };
}

function makeServer(mode: RulesToyMode, backend: string, authorization: () => string | undefined): Server {
  const server = new Server({ name: `sealmark-toy-rules-r6-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<Reply> => {
    const a = (req.params.arguments ?? {}) as Record<string, unknown>;
    const name = req.params.name;
    if (name === "list_tables") return text("sales.public.orders\nsales.public.customers");
    if (name !== "count_rows" && name !== "query") return text(`unknown tool ${name}`, true);
    const sql = name === "count_rows" ? (typeof a.table === "string" ? `SELECT count(*) FROM ${a.table}` : undefined) : typeof a.sql === "string" ? a.sql : undefined;
    if (sql === undefined) return text(`${name === "count_rows" ? "table" : "sql"} must be a string`, true);
    let r: { status: number; body: string };
    try {
      r = await backendCall(backend, sql, authorization());
    } catch {
      return text("the backend did not answer in time; try again later", true);
    }
    if (r.status >= 400) return text(`the backend could not run the query (status ${r.status}); nothing from its reply is shown`, true);
    if (name === "count_rows") {
      if (mode === "agg-raw-rows") return text(r.body);
      try {
        const rows = (JSON.parse(r.body) as { rows?: unknown[]; count?: number }).rows ?? [];
        const first = rows[0] as { count?: number } | undefined;
        return text(JSON.stringify({ count: first?.count ?? (JSON.parse(r.body) as { count?: number }).count ?? rows.length }));
      } catch {
        return text("the backend answered with something that is not JSON", true);
      }
    }
    return text(mode === "bytecap-missing" ? r.body : r.body.slice(0, RULES_TOY_BYTE_CAP));
  });
  return server;
}

function jsonError(res: http.ServerResponse, status: number, message: string): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }));
}

function readJson(req: http.IncomingMessage): Promise<unknown> {
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

export async function startRulesToy(mode: RulesToyMode, o: { backend: string; port?: number }): Promise<RulesToy> {
  const backend = o.backend.replace(/\/+$/, "");
  const sessions = new Map<string, { transport: StreamableHTTPServerTransport; server: Server; auth: { value?: string } }>();
  let port = 0;
  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    if (url.pathname !== "/mcp") return jsonError(res, 404, "Not found");
    if (req.headers.host !== `127.0.0.1:${port}` && req.headers.host !== `localhost:${port}`) return jsonError(res, 403, "Forbidden: invalid Host header");
    const authorization = typeof req.headers.authorization === "string" && /^Bearer \S+/.test(req.headers.authorization) ? req.headers.authorization : undefined;
    if (!authorization) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": 'Bearer realm="sealmark-toy"' });
      return void res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }));
    }
    let body: unknown;
    if (req.method === "POST") {
      try {
        body = await readJson(req);
      } catch {
        return jsonError(res, 400, "Parse error");
      }
    }
    const sid = typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : undefined;
    if (sid) {
      const s = sessions.get(sid);
      if (!s) return jsonError(res, 404, "Session not found");
      s.auth.value = authorization; // the caller's own credential, per request
      return s.transport.handleRequest(req, res, body);
    }
    if (req.method === "POST" && isInitializeRequest(body)) {
      const auth: { value?: string } = { value: authorization };
      const server = makeServer(mode, backend, () => auth.value);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), enableJsonResponse: true, onsessioninitialized: (id) => void sessions.set(id, { transport, server, auth }) });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      await server.connect(transport);
      return transport.handleRequest(req, res, body);
    }
    return jsonError(res, 400, "Bad Request: Mcp-Session-Id header is required");
  };
  const httpServer = http.createServer((req, res) => {
    handler(req, res).catch((e: unknown) => jsonError(res, 500, e instanceof Error ? e.message : "internal error"));
  });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(o.port ?? 0, "127.0.0.1", () => resolve());
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
  const { values } = parseArgs({ options: { mode: { type: "string" }, port: { type: "string" }, backend: { type: "string" } }, strict: true });
  const mode = values.mode as RulesToyMode;
  if (!RULES_TOY_MODES.includes(mode) || !values.backend) {
    process.stderr.write(`toy rules-r6 server: --mode must be one of ${RULES_TOY_MODES.join(", ")} and --backend <url> is required\n`);
    process.exit(2);
  }
  const toy = await startRulesToy(mode, { backend: values.backend, port: values.port ? Number(values.port) : 0 });
  process.stdout.write(`listening ${toy.url}\n`);
  const stop = () => void toy.close().finally(() => process.exit(0));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
