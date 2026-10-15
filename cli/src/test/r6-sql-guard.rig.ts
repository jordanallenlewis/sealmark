// Test support for the sql-guard pack tests (not a test file: no .test suffix). A recorder that implements the pinned
// `UpstreamStub` shape (design 2.2, the part the pack reads), a scripted fake `McpSession`, and a hand-built `PackCtx`.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, EffectiveConfig, PackCtx, PackId, SqlTool } from "../types.js";

export interface Req {
  id: number;
  at: number;
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
}

/** In-memory stub: tests push requests by hand (`record`) or a real HTTP recorder pushes them. */
export class FakeUpstream {
  readonly kind = "http" as const;
  url = "http://127.0.0.1:1";
  port = 1;
  errorCanary = "sm-upstream-err-test";
  readonly all: Req[] = [];
  record(body: string, path = "/sql"): void {
    this.all.push({ id: this.all.length + 1, at: Date.now(), method: "POST", path, query: "", headers: { "content-type": "application/json" }, body, bodyTruncated: false });
  }
  mark(): number {
    return this.all.length;
  }
  requests(since = 0): Req[] {
    return this.all.filter((r) => r.id > since);
  }
  find(needle: string, since = 0): Req[] {
    const n = needle.toLowerCase();
    return this.requests(since).filter((r) => `${r.path}${r.query}\n${JSON.stringify(r.headers)}\n${r.body}`.toLowerCase().includes(n));
  }
  async waitFor(needle: string, timeoutMs: number, since = 0): Promise<Req[]> {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const hit = this.find(needle, since);
      if (hit.length || Date.now() >= end) return hit;
      await new Promise((r) => setTimeout(r, 10));
    }
  }
  setMode(): void {}
  setOverride(): void {}
  async close(): Promise<void> {}
}

/** A real loopback HTTP recorder: answers `{"rows":[]}` to every request and records it in a FakeUpstream. */
export async function startRecorder(): Promise<{ stub: FakeUpstream; url: string; close(): Promise<void> }> {
  const stub = new FakeUpstream();
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      stub.all.push({
        id: stub.all.length + 1,
        at: Date.now(),
        method: req.method ?? "GET",
        path: u.pathname,
        query: u.search,
        headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)])),
        body: Buffer.concat(chunks).toString("utf8"),
        bodyTruncated: false,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"rows":[]}');
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  stub.port = port;
  stub.url = `http://127.0.0.1:${port}`;
  return { stub, url: stub.url, close: () => new Promise<void>((r) => server.close(() => r())) };
}

export const QUERY_TOOL: ToolInfo = {
  name: "query",
  description: "Run one read-only SELECT.",
  inputSchema: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] },
};

export const ok = (text = '{"rows":[]}'): CallResult => ({ isError: false, text, elapsedMs: 1, timedOut: false, closed: false });
export const err = (text = "Error: refused"): CallResult => ({ isError: true, text, elapsedMs: 1, timedOut: false, closed: false });
export const timeout = (): CallResult => ({ isError: true, text: "", elapsedMs: 5000, timedOut: true, closed: false });

/** What the fake server does with a SQL string: the text it forwards to the upstream (any rewriting included), and the reply. */
export type Behavior = (sql: string, args: Record<string, unknown>) => { forward?: string; reply: CallResult };

export class FakeSession {
  readonly calls: { name: string; args: Record<string, unknown> }[] = [];
  closed = false;
  constructor(readonly tools: ToolInfo[], private stub: FakeUpstream, private behavior: Behavior, private arg = "sql") {}
  async call(name: string, args: Record<string, unknown>): Promise<CallResult> {
    this.calls.push({ name, args });
    const sql = String(Array.isArray(args[this.arg]) ? (args[this.arg] as unknown[])[0] : args[this.arg]);
    const out = this.behavior(sql, args);
    if (out.forward !== undefined) this.stub.record(JSON.stringify({ sql: out.forward }));
    return out.reply;
  }
  async close(): Promise<void> {
    this.closed = true;
  }
}

export interface CtxOpts {
  allow?: string[];
  separator?: string;
  checks?: EffectiveConfig["checks"];
  sqlTools?: SqlTool[];
  tools?: ToolInfo[];
  noStub?: boolean;
  open?: () => Promise<McpSession>;
}

/** A hand-built PackCtx for the pack (design section 7: the real stub is P1's; this package tests against the pinned shape). */
export function makeCtx(stub: FakeUpstream, session: FakeSession | undefined, o: CtxOpts = {}): { ctx: PackCtx; opened: () => number } {
  let opens = 0;
  const config = { name: "toy", version: "0.0.1", server: { command: "node" } };
  const base = legacyEffectiveConfig({ config, packs: ["core"] as PackId[], packsExplicit: true, timeoutProbeSec: 1 });
  const eff = { ...base, checks: { ...base.checks, ...(o.checks ?? {}) }, ...(o.allow || o.separator ? { scope: { tools: [], allow: o.allow ?? [], deny: [], separator: o.separator ?? ".", case: "insensitive" } } : {}) } as EffectiveConfig;
  const ctx = {
    pack: "sql-guard" as PackId,
    config: eff,
    tools: o.tools ?? [QUERY_TOOL],
    classification: [],
    open: async () => {
      opens++;
      return o.open ? o.open() : (session as unknown as McpSession);
    },
    active: false,
    timeoutProbeSec: 1,
    hangMs: 1000,
    log: () => {},
    sqlTools: o.sqlTools ?? [{ tool: "query", arg: "sql" }],
    ...(o.noStub ? {} : { upstream: stub }),
  } as unknown as PackCtx;
  return { ctx, opened: () => opens };
}

export const byId = (checks: CheckResult[], id: string): CheckResult => {
  const c = checks.find((x) => x.id === id);
  if (!c) throw new Error(`no check ${id} in ${checks.map((x) => x.id).join(", ")}`);
  return c;
};
