import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { DataError, parseServers, type Fetcher } from "../install-check.js";
import { cliVersion } from "../describe.js";
import { createGradeServer } from "../mcp-server.js";
import { CLI, cliKit, hermeticEnv } from "./helpers.js";

const ESC = "\u001b";
const BASE = "https://data.test/data/v1";

function entry(id: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    name: id,
    ecosystem: "npm",
    versionTested: "1.0.0",
    testedAt: "2026-11-20",
    grade: "B",
    provisional: false,
    packs: { core: "A", fs: "B" },
    toolCount: 3,
    transport: "stdio",
    lastAttemptFailed: null,
    gradeConfirmed: true,
    noGradeReason: null,
    page: `https://sealmark.dev/results/${id}/`,
    json: `https://sealmark.dev/data/v1/servers/${id}.json`,
    ...over,
  };
}

function serverFile(id: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ...entry(id),
    sealmark: { version: "1.0.1", methodology: "0.3-draft" },
    standard: true,
    lastGrade: null,
    lastAttempt: null,
    coverage: { level: "covered", validCalls: 4, toolsCalledValid: 3, toolsTotal: 3 },
    packDetails: [
      { id: "core", status: "graded", letter: "A", provisional: false },
      { id: "fs", status: "graded", letter: "B", provisional: false },
    ],
    launch: `npx -y ${id}@1.0.0 {sandbox}`,
    ...over,
  };
}

const SERVERS = {
  version: "v1",
  updated: "2026-11-21",
  methodology: "0.3-draft",
  count: 5,
  servers: [
    entry("zeta-filesystem"),
    entry("filesystem", { name: "Filesystem" }),
    entry("filesystem-extra", { name: "Extra" }),
    entry("alpha", { name: "my filesystem tool" }),
    entry("other", { name: "Other" }),
  ],
};

const LOOKUP = { version: "v1", updated: "2026-11-21", count: 2, keys: { "npm:filesystem": ["filesystem"], "id:filesystem": ["filesystem"] } };

const jsonRes = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A fake fetcher over a path table; records every URL it was asked for. */
function fake(files: Record<string, () => Response>) {
  const urls: string[] = [];
  const fetcher: Fetcher = async (url) => {
    urls.push(url);
    const make = files[url.slice(BASE.length)];
    return make ? make() : new Response("", { status: 404 });
  };
  return { fetcher, urls };
}

const GOOD = (): Record<string, () => Response> => ({
  "/lookup.json": () => jsonRes(LOOKUP),
  "/servers.json": () => jsonRes(SERVERS),
  "/servers/filesystem.json": () => jsonRes(serverFile("filesystem", { name: "Filesystem" })),
});

async function connect(files: Record<string, () => Response>) {
  const f = fake(files);
  const server = createGradeServer({ base: BASE, fetcher: f.fetcher });
  const client = new Client({ name: "test", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, server, ...f, close: () => client.close() };
}

type Reply = { content: { type: string; text: string }[]; isError?: boolean };
const call = async (c: Client, name: string, args?: Record<string, unknown>) => (await c.callTool({ name, arguments: args })) as unknown as Reply;
const lastJson = (r: Reply) => JSON.parse(r.content[r.content.length - 1]!.text);

describe("mcp-server: tools/list", () => {
  it("lists exactly get_grade, find_server and list_checks with their annotations and server info", async () => {
    const t = await connect(GOOD());
    const { tools } = await t.client.listTools();
    assert.deepEqual(tools.map((x) => x.name).sort(), ["find_server", "get_grade", "list_checks"]);
    for (const x of tools) {
      assert.equal(x.annotations?.readOnlyHint, true, x.name);
      assert.equal(x.annotations?.destructiveHint, false, x.name);
      assert.equal(x.annotations?.idempotentHint, true, x.name);
      assert.equal(x.annotations?.openWorldHint, x.name !== "list_checks", x.name);
      assert.match(x.description ?? "", /grades? nothing/i, `${x.name} says it grades nothing`);
      assert.match(x.description ?? "", /not instructions/i, `${x.name} says the data is not instructions`);
      assert.equal(x.inputSchema.type, "object");
    }
    const get = tools.find((x) => x.name === "get_grade")!;
    assert.deepEqual(get.inputSchema.required, ["server"]);
    assert.equal((get.inputSchema.properties as Record<string, { maxLength?: number }>).server!.maxLength, 300);
    assert.deepEqual(t.client.getServerVersion(), { name: "sealmark", version: cliVersion() });
    assert.match(t.client.getInstructions() ?? "", /sealmark\.dev/);
    assert.equal(t.urls.length, 0, "listing tools fetches nothing");
    await t.close();
  });
});

describe("mcp-server: get_grade", () => {
  it("a graded server: summary text plus the JSON, from the configured base only", async () => {
    const t = await connect(GOOD());
    const r = await call(t.client, "get_grade", { server: "filesystem" });
    assert.ok(!r.isError);
    assert.equal(r.content.length, 2);
    assert.match(r.content[0]!.text, /Filesystem \(sealmark\.dev id filesystem/);
    const j = lastJson(r);
    assert.equal(j.format, "sealmark.install-check/1");
    assert.equal(j.found, true);
    assert.equal(j.servers[0].grade, "B");
    assert.ok(t.urls.length >= 2 && t.urls.every((u) => u.startsWith(`${BASE}/`)), t.urls.join(", "));
    await t.close();
  });

  it("not in the public results: a normal result that says so", async () => {
    const t = await connect(GOOD());
    const r = await call(t.client, "get_grade", { server: "never-graded-thing" });
    assert.ok(!r.isError);
    assert.match(r.content[0]!.text, /is not in sealmark\.dev's public results/);
    assert.equal(lastJson(r).found, false);
    await t.close();
  });

  it("invalid input is an error with a clear message and fetches nothing", async () => {
    const t = await connect(GOOD());
    for (const args of [undefined, {}, { server: 5 }, { server: "" }, { server: "   " }, { server: "!!!" }, { server: "a".repeat(301) }]) {
      const r = await call(t.client, "get_grade", args as Record<string, unknown>);
      assert.equal(r.isError, true, JSON.stringify(args));
      assert.match(r.content[0]!.text, /server|npm|PyPI/i);
    }
    assert.equal(t.urls.length, 0);
    await t.close();
  });

  it("extra argument keys are ignored", async () => {
    const t = await connect(GOOD());
    const r = await call(t.client, "get_grade", { server: "filesystem", bogus: 1 });
    assert.ok(!r.isError);
    await t.close();
  });

  it("unreadable data (HTTP 500, not JSON, cross-origin redirect) is an error with no grade", async () => {
    const cases: Record<string, () => Response> = {
      "HTTP 500": () => new Response("boom", { status: 500 }),
      "not JSON": () => new Response("<html>", { status: 200 }),
      redirect: () => {
        const res = jsonRes(LOOKUP);
        Object.defineProperty(res, "url", { value: "https://evil.example/data/v1/lookup.json" });
        return res;
      },
    };
    for (const [why, make] of Object.entries(cases)) {
      const t = await connect({ ...GOOD(), "/lookup.json": make });
      const r = await call(t.client, "get_grade", { server: "filesystem" });
      assert.equal(r.isError, true, why);
      assert.equal(r.content.length, 1, why);
      assert.doesNotMatch(r.content[0]!.text, /grade B/, why);
      assert.match(r.content[0]!.text, /HTTP 500|is not JSON|redirected to another site/, why);
      await t.close();
    }
  });
});

describe("mcp-server: find_server", () => {
  it("orders exact, then prefix, then substring, ties by id; returns the documented shape", async () => {
    const t = await connect(GOOD());
    const r = await call(t.client, "find_server", { query: "  FileSystem " });
    assert.ok(!r.isError);
    assert.equal(r.content.length, 1);
    const j = lastJson(r);
    assert.equal(j.format, "sealmark.find-server/1");
    assert.equal(j.source, BASE);
    assert.equal(j.updated, "2026-11-21");
    assert.equal(j.count, 5);
    assert.equal(j.query, "FileSystem");
    assert.equal(j.total, 4);
    // exact (filesystem), prefix (filesystem-extra), then substring by id: alpha (name), zeta-filesystem
    assert.deepEqual(j.servers.map((s: { id: string }) => s.id), ["filesystem", "filesystem-extra", "alpha", "zeta-filesystem"]);
    assert.deepEqual(Object.keys(j.servers[0]).sort(), ["ecosystem", "grade", "id", "name", "packs", "page", "provisional", "testedAt", "versionTested"]);
    assert.deepEqual(j.servers[0].packs, { core: "A", fs: "B" });
    assert.deepEqual(t.urls, [`${BASE}/servers.json`]);
    await t.close();
  });

  it("limit: default 10, honoured, and rejected outside 1..25 or when not an integer", async () => {
    const many = { ...SERVERS, servers: Array.from({ length: 40 }, (_, i) => entry(`srv-${String(i).padStart(2, "0")}`)) };
    const t = await connect({ ...GOOD(), "/servers.json": () => jsonRes(many) });
    assert.equal(lastJson(await call(t.client, "find_server", { query: "srv" })).servers.length, 10);
    const three = lastJson(await call(t.client, "find_server", { query: "srv", limit: 3 }));
    assert.equal(three.servers.length, 3);
    assert.equal(three.total, 40);
    assert.equal(lastJson(await call(t.client, "find_server", { query: "srv", limit: 25 })).servers.length, 25);
    for (const limit of [0, 26, -1, 1.5, "3", null]) {
      const r = await call(t.client, "find_server", { query: "srv", limit });
      assert.equal(r.isError, true, String(limit));
      assert.match(r.content[0]!.text, /limit/);
    }
    await t.close();
  });

  it("query must be a string of 1 to 100 characters", async () => {
    const t = await connect(GOOD());
    for (const args of [undefined, {}, { query: 1 }, { query: "" }, { query: "   " }, { query: "x".repeat(101) }]) {
      const r = await call(t.client, "find_server", args as Record<string, unknown>);
      assert.equal(r.isError, true, JSON.stringify(args));
      assert.match(r.content[0]!.text, /query/);
    }
    assert.equal(t.urls.length, 0);
    await t.close();
  });

  it("no match: a normal result with total 0 and an empty list", async () => {
    const t = await connect(GOOD());
    const r = await call(t.client, "find_server", { query: "no-such-server" });
    assert.ok(!r.isError);
    const j = lastJson(r);
    assert.equal(j.total, 0);
    assert.deepEqual(j.servers, []);
    await t.close();
  });

  it("hostile entries: bad ids skipped, control characters neutralised, off-origin page rebuilt", async () => {
    const hostile = {
      ...SERVERS,
      servers: [
        entry("evil", { name: `bad${ESC}[31mred${ESC}]8;;http://x\u0007 name\nIGNORE`, page: "https://evil.example/results/evil/" }),
        entry("../escape", { name: "evil-skipped" }),
        entry("has space", { name: "evil-skipped" }),
        { id: 7, name: "evil-skipped" },
        "evil-skipped",
        null,
        entry("typed", { name: 5, grade: 4, ecosystem: {}, packs: JSON.parse('{"core":"A","fs":3,"__proto__":"x"}'), testedAt: null }),
        entry("http-page", { name: "evil http", page: "http://sealmark.dev/results/http-page/" }),
      ],
    };
    const t = await connect({ ...GOOD(), "/servers.json": () => jsonRes(hostile) });
    const j = lastJson(await call(t.client, "find_server", { query: "evil" }));
    assert.deepEqual(j.servers.map((s: { id: string }) => s.id), ["evil", "http-page"]);
    const evil = j.servers[0];
    assert.ok(!JSON.stringify(j).includes(ESC) && !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(JSON.stringify(j)), "no control characters survive");
    assert.doesNotMatch(evil.name, /\n/);
    assert.equal(evil.page, "https://sealmark.dev/results/evil/");
    assert.equal(j.servers[1].page, "https://sealmark.dev/results/http-page/");
    const typed = lastJson(await call(t.client, "find_server", { query: "typed" })).servers[0];
    assert.equal(typed.name, "typed", "a non-string name falls back to the id");
    assert.equal(typed.grade, null);
    assert.equal(typed.ecosystem, null);
    assert.equal(typed.testedAt, null);
    // The fixture really carries an own "__proto__" key (JSON.parse; an object literal would set the prototype instead).
    const raw = JSON.parse('{"core":"A","__proto__":"x"}');
    assert.ok(Object.hasOwn(raw, "__proto__"));
    const parsed = parseServers({ servers: [entry("p", { packs: raw })] }).servers[0]!;
    assert.ok(Object.hasOwn(parsed.packs, "__proto__"), "kept as a plain own key");
    assert.equal(Object.getPrototypeOf(parsed.packs), Object.prototype, "prototype untouched");
    assert.equal((parsed.packs as Record<string, unknown>).polluted, undefined);
    assert.equal(({} as Record<string, unknown>).x, undefined);
    assert.equal(Object.getPrototypeOf({}), Object.prototype);
    assert.equal(Object.getPrototypeOf(typed.packs), Object.prototype);
    await t.close();
  });

  it("duplicate ids in servers.json: the first entry is kept", () => {
    const r = parseServers({ servers: [entry("dup", { grade: "A" }), entry("other"), entry("dup", { grade: "F" })] });
    assert.deepEqual(r.servers.map((s) => s.id), ["dup", "other"]);
    assert.equal(r.servers[0]!.grade, "A");
  });

  it("malformed or unreadable servers.json is an error", async () => {
    for (const body of [() => jsonRes([]), () => jsonRes({ servers: "x" }), () => jsonRes("str"), () => jsonRes({ count: 1 }), () => new Response("nope"), () => new Response("", { status: 503 })]) {
      const t = await connect({ ...GOOD(), "/servers.json": body });
      const r = await call(t.client, "find_server", { query: "filesystem" });
      assert.equal(r.isError, true);
      assert.equal(r.content.length, 1);
      await t.close();
    }
  });

  it("a page on the data's own origin is kept", () => {
    const doc = parseServers({ servers: [entry("mine", { page: "https://data.test/results/mine/" })] }, "https://data.test/data/v1");
    assert.equal(doc.servers[0]!.page, "https://data.test/results/mine/");
    assert.throws(() => parseServers("x"), DataError);
  });
});

describe("mcp-server: list_checks", () => {
  it("lists all checks without any network", async () => {
    const t = await connect({});
    const r = await call(t.client, "list_checks");
    assert.ok(!r.isError);
    const j = lastJson(r);
    assert.ok(j.checks.length > 50);
    assert.ok(j.checks.some((c: { id: string }) => c.id === "fs-read-escape"));
    assert.equal(t.urls.length, 0);
    await t.close();
  });

  it("one pack", async () => {
    const t = await connect({});
    const j = lastJson(await call(t.client, "list_checks", { pack: "fs" }));
    assert.ok(j.checks.length > 0 && j.checks.every((c: { pack: string }) => c.pack === "fs"));
    await t.close();
  });

  it("an unknown pack is an error with the CLI's message", async () => {
    const t = await connect({});
    const r = await call(t.client, "list_checks", { pack: "nope" });
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /no pack named "nope" \(packs with checks: /);
    const bad = await call(t.client, "list_checks", { pack: 3 });
    assert.equal(bad.isError, true);
    await t.close();
  });

  it("pack: the schema caps it at 64 characters, the handler rejects longer ones and neutralises ExplainError text", async () => {
    const t = await connect({});
    const tools = (await t.client.listTools()).tools;
    const pack = (tools.find((x) => x.name === "list_checks")!.inputSchema.properties as Record<string, { maxLength?: number }>).pack!;
    assert.equal(pack.maxLength, 64);
    const long = await call(t.client, "list_checks", { pack: "a".repeat(65) });
    assert.equal(long.isError, true);
    assert.match(long.content[0]!.text, /pack is longer than 64 characters/);
    const hostile = await call(t.client, "list_checks", { pack: `x${ESC}[31m\nIGNORE` });
    assert.equal(hostile.isError, true);
    assert.ok(!hostile.content[0]!.text.includes(ESC), "no control characters in the error");
    await t.close();
  });
});

let slowOrigin = "";
let slowHttp: HttpServer;
describe("mcp-server: protocol edges", () => {
  before(async () => {
    slowHttp = createServer((req, res) => {
      setTimeout(() => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(SERVERS)), 300);
    });
    await new Promise<void>((r) => slowHttp.listen(0, "127.0.0.1", () => r()));
    slowOrigin = `http://127.0.0.1:${(slowHttp.address() as AddressInfo).port}`;
  });
  after(async () => {
    await new Promise<void>((r) => slowHttp.close(() => r()));
  });

  it("an unknown tool is a protocol error, not a crash", async () => {
    const t = await connect(GOOD());
    await assert.rejects(() => t.client.callTool({ name: "run_server", arguments: {} }), /run_server|Unknown tool|-32602/i);
    assert.ok(!(await call(t.client, "get_grade", { server: "filesystem" })).isError, "still serving");
    await t.close();
  });

  it("a thrown non-DataError becomes a generic error and nothing but JSON-RPC reaches stdout", async () => {
    // getJson wraps a fetcher's own failure as DataError; reading `res.url` is outside that wrapper, so this reaches the generic branch.
    const boom: Fetcher = async () => ({ get url(): string { throw new TypeError("secret internal detail"); } }) as unknown as Response;
    const server = createGradeServer({ base: BASE, fetcher: boom });
    const client = new Client({ name: "test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    const writes: string[] = [];
    const realOut = process.stdout.write;
    const realErr = process.stderr.write;
    process.stdout.write = ((c: unknown) => (writes.push(String(c)), true)) as typeof process.stdout.write;
    process.stderr.write = (() => true) as typeof process.stderr.write;
    let r: Reply;
    try {
      r = await call(client, "find_server", { query: "x" });
    } finally {
      process.stdout.write = realOut;
      process.stderr.write = realErr;
    }
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /failed because of an internal error/);
    assert.doesNotMatch(r.content[0]!.text, /secret internal detail|\bat \w|\.ts|\.js:/);
    assert.deepEqual(writes, [], "nothing written to stdout");
    await client.close();
  });

  it("stdin ending while a tool call is in flight still delivers the reply", { timeout: 60_000 }, async () => {
    const p = spawn(process.execPath, [CLI, "mcp", "--data-url", `${slowOrigin}/data/v1/slow`], { env: hermeticEnv({}), stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.resume();
    const exited = new Promise<number | null>((r) => p.once("exit", (c) => r(c)));
    const msg = (m: unknown) => `${JSON.stringify(m)}\n`;
    p.stdin.write(msg({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } }));
    p.stdin.write(msg({ jsonrpc: "2.0", method: "notifications/initialized" }));
    p.stdin.write(msg({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "find_server", arguments: { query: "filesystem" } } }));
    p.stdin.end();
    assert.equal(await exited, 0);
    const lines = out.split("\n").filter(Boolean).map((l) => JSON.parse(l) as { id?: number; result?: { content: { text: string }[] } });
    const reply = lines.find((l) => l.id === 2);
    assert.ok(reply?.result, `no tools/call reply in: ${out}`);
    assert.equal(JSON.parse(reply.result.content.at(-1)!.text).total, 4);
  });
});

describe("mcp-server: the built CLI over stdio", { timeout: 180_000 }, () => {
  let http: HttpServer;
  let origin: string;
  const hits: string[] = [];
  let tmp: string;
  before(async () => {
    tmp = mkdtempSync(join(tmpdir(), "sealmark-mcp-"));
    http = createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      hits.push(`${req.method} ${path}`);
      const files: Record<string, unknown> = {
        "/data/v1/lookup.json": LOOKUP,
        "/data/v1/servers.json": SERVERS,
        "/data/v1/servers/filesystem.json": serverFile("filesystem", { name: "Filesystem" }),
      };
      if (req.method !== "GET" || !(path in files)) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(files[path]));
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", () => r()));
    origin = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  });
  after(async () => {
    await new Promise<void>((r) => http.close(() => r()));
    rmSync(tmp, { recursive: true, force: true });
  });

  it("serves get_grade and find_server, then exits 0 when stdin closes, with only JSON-RPC on stdout", async () => {
    const transport = new StdioClientTransport({ command: process.execPath, args: [CLI, "mcp", "--data-url", `${origin}/data/v1`], env: hermeticEnv({}) as Record<string, string>, stderr: "pipe" });
    const client = new Client({ name: "e2e", version: "0.0.0" });
    const errors: Error[] = [];
    client.onerror = (e) => errors.push(e);
    transport.onerror = (e) => errors.push(e);
    await client.connect(transport);
    // The SDK transport keeps its child private; the test needs its exit code, which the transport does not report.
    const child = (transport as unknown as { _process: import("node:child_process").ChildProcess })._process;
    const exited = new Promise<number | null>((r) => child.once("exit", (c) => r(c)));
    assert.equal(client.getServerVersion()?.name, "sealmark");
    const g = await call(client, "get_grade", { server: "filesystem" });
    assert.ok(!g.isError, g.content[0]?.text);
    assert.equal(lastJson(g).servers[0].grade, "B");
    const f = await call(client, "find_server", { query: "filesystem" });
    assert.equal(lastJson(f).total, 4);
    const l = await call(client, "list_checks", { pack: "core" });
    assert.ok(!l.isError);
    child.stdin!.end();
    assert.equal(await exited, 0);
    assert.deepEqual(errors, [], "every stdout line parsed as JSON-RPC");
    assert.ok(hits.length > 0 && hits.every((h) => h.startsWith("GET /data/v1/")), hits.join(", "));
  });

  it("--data-url ftp://x is a usage error: exit 2, the message on stderr, nothing on stdout", async () => {
    const r = await new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const p = spawn(process.execPath, [CLI, "mcp", "--data-url", "ftp://x"], { env: hermeticEnv({}), stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("close", (code) => resolve({ code, out, err }));
    });
    assert.equal(r.code, 2);
    assert.equal(r.out, "");
    assert.match(r.err, /--data-url takes an http or https URL/);
  });

  it("a flag mcp does not take is a usage error", () => {
    const { sealmark } = cliKit(() => tmp);
    const r = sealmark(["mcp", "--json"]);
    assert.equal(r.code, 2, r.err);
    assert.equal(r.out, "");
  });

  it("self-grade: the server passes its own core run with an A and no failing check", async () => {
    const { writeYaml } = cliKit(() => tmp);
    const cfg = writeYaml(
      "self.yaml",
      `schema_version: 1\nname: sealmark-mcp\nversion: ${cliVersion()}\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([CLI, "mcp", "--data-url", `${origin}/data/v1`])}\n`,
    );
    const r = await new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const p = spawn(process.execPath, [CLI, "run", "--config", cfg, "--pack", "core", "--fail-under", "none", "--format", "json"], { cwd: tmp, env: hermeticEnv({}), stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("close", (code) => resolve({ code, out, err }));
    });
    assert.equal(r.code, 0, r.err);
    const run = JSON.parse(r.out) as { packs: Record<string, { status: string; grade?: { letter: string } }>; checks: { id: string; verdict: string; summary: string }[] };
    const failing = run.checks.filter((c) => c.verdict !== "pass" && c.verdict !== "na");
    assert.equal(run.packs.core?.grade?.letter, "A", JSON.stringify(failing));
    assert.deepEqual(failing.map((c) => `${c.id}: ${c.verdict}: ${c.summary}`), []);
  });
});
