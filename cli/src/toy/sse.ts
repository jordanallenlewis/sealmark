// Toy MCP server on the older HTTP+SSE transport (protocol 2024-11-05), built on the MCP SDK's SSEServerTransport and node:http.
// Run: node dist/toy/sse.js [--port <n>] [--token <bearer>]   or   node dist/toy/sse.js --stdio (the same echo tool over stdio)
// It listens on 127.0.0.1 only (a toy must never be reachable from the network) and prints `listening http://127.0.0.1:<port>/sse`.
// GET /sse opens the event stream; its first event names /messages?sessionId=<id>, where the client POSTs its requests. Any other method on
// /sse answers 405, as the common SSE servers do, so a Streamable HTTP client's POST is refused. With --token (or the `token` option) both
// the GET and the POSTs need `Authorization: Bearer <token>`.
// Not part of the product surface: it proves Sealmark connects over SSE and says so when the transport does not match.
import http from "node:http";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export interface SseToy {
  port: number;
  /** The event-stream URL, for example http://127.0.0.1:41234/sse. */
  url: string;
  /** Requests received so far, by method and path ("get /sse", "post /messages"); tests use it to prove which transport reached the toy. */
  seen: Record<string, number>;
  close(): Promise<void>;
}

function makeServer(): Server {
  const server = new Server({ name: "sealmark-toy-sse", version: "0.0.1" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "echo", description: "Return the given text unchanged.", inputSchema: { type: "object", properties: { text: { type: "string", description: "Text to return" } }, required: ["text"] } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const text = (req.params.arguments ?? {}).text;
    return typeof text === "string" ? { content: [{ type: "text", text }] } : { content: [{ type: "text", text: "text must be a string" }], isError: true };
  });
  return server;
}

export async function startSseToy(opts: { port?: number; token?: string } = {}): Promise<SseToy> {
  const sessions = new Map<string, { transport: SSEServerTransport; server: Server }>();
  const seen: Record<string, number> = {};

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://toy");
    const method = (req.method ?? "GET").toUpperCase();
    const key = `${method.toLowerCase()} ${url.pathname}`;
    seen[key] = (seen[key] ?? 0) + 1;
    if (opts.token && req.headers.authorization !== `Bearer ${opts.token}`) {
      res.writeHead(401, { "content-type": "text/plain", "www-authenticate": 'Bearer realm="toy"' });
      return void res.end("unauthorized");
    }
    if (url.pathname === "/sse") {
      if (method !== "GET") {
        res.writeHead(405, { allow: "GET", "content-type": "text/plain" });
        return void res.end("Method Not Allowed");
      }
      const transport = new SSEServerTransport("/messages", res);
      const server = makeServer();
      sessions.set(transport.sessionId, { transport, server });
      res.on("close", () => {
        sessions.delete(transport.sessionId);
        void server.close().catch(() => {});
      });
      await server.connect(transport);
      return;
    }
    if (url.pathname === "/messages" && method === "POST") {
      const s = sessions.get(url.searchParams.get("sessionId") ?? "");
      if (!s) {
        res.writeHead(404, { "content-type": "text/plain" });
        return void res.end("unknown session");
      }
      await s.transport.handlePostMessage(req, res);
      return;
    }
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
  };

  const httpServer = http.createServer((req, res) => {
    handler(req, res).catch((e: unknown) => {
      if (res.headersSent) return void res.end();
      res.writeHead(500, { "content-type": "text/plain" });
      res.end(e instanceof Error ? e.message : "internal error");
    });
  });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(opts.port ?? 0, "127.0.0.1", () => resolve());
  });
  const port = (httpServer.address() as { port: number }).port;

  return {
    port,
    url: `http://127.0.0.1:${port}/sse`,
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
  const { values } = parseArgs({ options: { port: { type: "string" }, token: { type: "string" }, stdio: { type: "boolean" } }, strict: true });
  if (values.stdio) {
    await makeServer().connect(new StdioServerTransport());
  } else {
    const toy = await startSseToy({ port: values.port ? Number(values.port) : 0, token: values.token });
    process.stdout.write(`listening ${toy.url}\n`);
    const stop = () => void toy.close().finally(() => process.exit(0));
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  }
}
