import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { gradePack } from "../grade.js";
import { describe as describeHttp, exposureOf, listeningAddresses, makePack, pack } from "../packs/http.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import { HTTP_TOY_TOKEN, startHttpToy, type HttpToy } from "../toy/http.js";
import type { CheckResult, EffectiveConfig, PackCtx, ServerSpec, Verdict } from "../types.js";
import { gradeOf, quiet } from "./helpers.js";

const BEARER = { Authorization: `Bearer ${HTTP_TOY_TOKEN}` };

function ctxFor(server: ServerSpec, over: Partial<EffectiveConfig> = {}): PackCtx {
  const config = { ...legacyEffectiveConfig({ config: { name: "http-toy", version: "0.0.1", server }, packs: ["core", "http"], packsExplicit: false, timeoutProbeSec: 2 }), ...over };
  return { pack: "http", config, tools: [], classification: [], open: async () => assert.fail("the http pack must not use the SDK session"), active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet };
}

const verdictsOf = (checks: CheckResult[]): Record<string, Verdict> => Object.fromEntries(checks.map((c) => [c.id, c.verdict]));
/** The design table does not constrain http-bind, which needs netstat or ss on the host: accept pass or na here; the bind suite below pins it with a fake table. */
const tableVerdicts = (checks: CheckResult[]): Record<string, Verdict> => {
  const v = verdictsOf(checks);
  assert.ok(v["http-bind"] === "pass" || v["http-bind"] === "na", `http-bind was ${v["http-bind"]}`);
  return { ...v, "http-bind": "pass" };
};
const by = (checks: CheckResult[], id: string) => checks.find((c) => c.id === id)!;

describe("http pack on toy servers", { timeout: 120_000 }, () => {
  const toys: HttpToy[] = [];
  const out: Record<string, CheckResult[]> = {};
  let disabledToy: HttpToy;

  const start = async (mode: "good" | "open" | "cors-star") => {
    const t = await startHttpToy(mode);
    toys.push(t);
    return t;
  };

  before(async () => {
    const good = await start("good");
    const open = await start("open");
    const star = await start("cors-star");
    disabledToy = await start("good");
    const jobs: Record<string, () => Promise<CheckResult[]>> = {
      good: () => pack.run(ctxFor({ url: good.url, headers: BEARER })),
      open: () => pack.run(ctxFor({ url: open.url })),
      star: () => pack.run(ctxFor({ url: star.url, headers: BEARER })),
      // The server wants a bearer token and none was configured: the harness cannot even handshake.
      goodNoHeaders: () => pack.run(ctxFor({ url: good.url })),
      goodWrongToken: () => pack.run(ctxFor({ url: good.url, headers: { Authorization: "Bearer not-the-token" } })),
      // A routing header is not a credential: auth is graded as if none were configured.
      openRouting: () => pack.run(ctxFor({ url: open.url, headers: { "X-Env": "dev" } })),
      disabled: () => pack.run(ctxFor({ url: disabledToy.url, headers: BEARER }, { checks: { "http-cors": { enabled: false, severity: null }, "http-session": { enabled: true, severity: "advisory" } } })),
    };
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (out[k] = await fn())));
  });

  after(async () => {
    for (const t of toys) await t.close();
  });

  it("good: Host/Origin validated, bearer required, versions and sessions validated, no CORS; every scored check passes; grade A", () => {
    assert.deepEqual(tableVerdicts(out.good), {
      "http-origin": "pass",
      "http-auth": "pass",
      "http-protocol-version": "pass",
      "http-session": "pass",
      "http-cors": "pass",
      "http-bind": "pass",
      "http-tls": "na",
    });
    assert.equal(gradePack("http", out.good)?.letter, "A");
    assert.match(by(out.good, "http-origin").summary, /rejected with HTTP 403/);
    if (by(out.good, "http-bind").verdict === "pass") assert.match(by(out.good, "http-bind").summary, /loopback only/);
  });

  it("open: accepts any origin, needs no credentials, ignores the version header, never validates the session id, reflects CORS; F", () => {
    assert.deepEqual(tableVerdicts(out.open), {
      "http-origin": "fail",
      "http-auth": "na",
      "http-protocol-version": "fail",
      "http-session": "fail",
      "http-cors": "fail",
      "http-bind": "pass",
      "http-tls": "na",
    });
    const g = gradePack("http", out.open)!;
    assert.equal(g.letter, "F");
    assert.deepEqual(g.criticalFails, ["http-origin"]);
    assert.match(by(out.open, "http-session").summary, /accepted a request with no session id and a forged session id/);
  });

  it("cors-star: good except every origin is allowed with credentials; B", () => {
    assert.deepEqual(tableVerdicts(out.star), {
      "http-origin": "pass",
      "http-auth": "pass",
      "http-protocol-version": "pass",
      "http-session": "pass",
      "http-cors": "fail",
      "http-bind": "pass",
      "http-tls": "na",
    });
    assert.equal(gradePack("http", out.star)?.letter, "B");
    assert.match(by(out.star, "http-cors").summary, /every origin is allowed together with credentials/);
  });

  it("when the harness's own handshake is refused, probes are inconclusive with a pointer to the config, not failures", () => {
    for (const k of ["goodNoHeaders", "goodWrongToken"]) {
      const v = verdictsOf(out[k]);
      for (const id of ["http-origin", "http-protocol-version", "http-session"]) assert.equal(v[id], "inconclusive", `${k} ${id}`);
      assert.match(by(out[k], "http-origin").summary, /HTTP 401.*server\.headers/);
    }
    // Round 5 (G14): http-cors passes only when the harness's own initialize worked, so it is inconclusive here too (it used to be a vacuous
    // pass that left a provisional grade). With no check judged there is no grade: a critical check that could not be judged is never an A.
    for (const k of ["goodNoHeaders", "goodWrongToken"]) assert.equal(verdictsOf(out[k])["http-cors"], "inconclusive", k);
    assert.match(by(out.goodNoHeaders, "http-cors").summary, /harness's own initialize was not accepted.*server\.headers/);
    assert.equal(gradePack("http", out.goodNoHeaders), null);
  });

  it("with no credentials configured on loopback http-auth is na; a header that is not a credential does not count", () => {
    assert.equal(verdictsOf(out.goodNoHeaders)["http-auth"], "na");
    assert.equal(verdictsOf(out.openRouting)["http-auth"], "na");
    assert.match(by(out.openRouting, "http-auth").summary, /X-Env do not look like credentials/);
  });

  it("config can disable a check (na with the reason) and make one advisory (excluded from the grade)", () => {
    const cors = by(out.disabled, "http-cors");
    assert.equal(cors.verdict, "na");
    assert.match(cors.summary, /disabled by config/);
    assert.equal(cors.evidence.length, 0);
    assert.equal(disabledToy.seen.options ?? 0, 0, "no preflight was sent for the disabled check");
    const session = by(out.disabled, "http-session");
    assert.equal(session.advisory, true);
    assert.equal(session.verdict, "pass");
    assert.equal(gradePack("http", out.disabled)!.scored, 3);
  });

  it("no configured header value ever reaches a result", () => {
    const text = JSON.stringify(Object.values(out));
    assert.equal(text.includes(HTTP_TOY_TOKEN), false);
    assert.equal(text.includes("not-the-token"), false);
    assert.match(JSON.stringify(out.good), /Authorization/); // names are shown, values are not
  });

  it("every emitted check id is documented; scopes start with server or environment; bind and tls are advisory", () => {
    const docs = describeHttp();
    const ids = docs.map((d) => d.id);
    assert.deepEqual(ids, ["http-origin", "http-auth", "http-protocol-version", "http-session", "http-cors", "http-bind", "http-tls"]);
    assert.equal(new Set(ids).size, ids.length);
    for (const d of docs) {
      assert.equal(d.pack, "http");
      assert.match(d.scope, /^(server|environment)/);
      assert.ok(d.probes.length > 0);
    }
    assert.deepEqual(docs.filter((d) => d.advisory).map((d) => d.id), ["http-bind", "http-tls"]);
    assert.deepEqual(docs.filter((d) => d.critical).map((d) => d.id), ["http-origin"]);
    for (const c of Object.values(out).flat()) assert.ok(ids.includes(c.id));
  });
});

describe("http pack: other servers and edge cases", { timeout: 60_000 }, () => {
  it("is not applicable over stdio and says why; never throws on a bare ctx", () => {
    const r = pack.applies(ctxFor({ command: "x" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.reason, /stdio.*server\.url/);
    assert.equal(pack.applies(ctxFor({ url: "http://127.0.0.1:1/mcp" })).ok, true);
    assert.equal(pack.applies({ pack: "http" } as never).ok, false);
  });

  it("a dead endpoint gives inconclusive checks, not failures, and plain http to a non-loopback host with credentials fails the TLS note", async () => {
    // 0.0.0.0 is not a loopback spelling to the pack, and nothing leaves the machine when connecting to it.
    const checks = await pack.run(ctxFor({ url: "http://0.0.0.0:9/mcp", headers: { "X-Api-Key": "k" } }));
    const v = verdictsOf(checks);
    assert.equal(v["http-origin"], "inconclusive");
    assert.equal(v["http-auth"], "inconclusive");
    assert.equal(v["http-tls"], "fail");
    assert.equal(v["http-bind"], "na");
    assert.match(by(checks, "http-tls").summary, /X-Api-Key/);
    assert.equal(JSON.stringify(checks).includes('"k"'), false);
  });

  it("https is a pass for http-tls", async () => {
    const checks = await pack.run(ctxFor({ url: "https://127.0.0.1:9/mcp" }));
    assert.equal(verdictsOf(checks)["http-tls"], "pass");
  });

  it("a server that issues a short session id and validates it is a part, not a pass", async () => {
    const SID = "abc123";
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const send = (status: number, obj: unknown, headers: Record<string, string> = {}) => {
          res.writeHead(status, { "content-type": "application/json", ...headers });
          res.end(JSON.stringify(obj));
        };
        if (req.method === "DELETE" || req.method === "OPTIONS") return void res.writeHead(204).end();
        const msg = JSON.parse(body || "{}") as { id?: number; method?: string };
        if (msg.method === "initialize") return send(200, { jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "t", version: "1" } } }, { "mcp-session-id": SID });
        if (req.headers["origin"]) return send(403, { error: "origin" });
        if (req.headers["mcp-session-id"] !== SID) return send(req.headers["mcp-session-id"] ? 404 : 400, { error: "session" });
        if (req.headers["mcp-protocol-version"] !== "2025-06-18") return send(400, { error: "version" });
        if (!msg.id) return void res.writeHead(202).end();
        return send(200, { jsonrpc: "2.0", id: msg.id, result: { tools: [] } });
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(srv.address() as { port: number }).port}/mcp`;
      const checks = await pack.run(ctxFor({ url }));
      const s = by(checks, "http-session");
      assert.equal(s.verdict, "part");
      assert.match(s.summary, /only 6 characters/);
      assert.match(s.summary, /same id was issued to two separate initializations/);
      assert.equal(verdictsOf(checks)["http-protocol-version"], "pass");
    } finally {
      srv.closeAllConnections();
      await new Promise((r) => srv.close(r));
    }
  });

  it("an SSE reply is parsed, and an SSE stream that never ends is not waited on", async () => {
    const init = { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "t", version: "1" } };
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (req.method !== "POST") return void res.writeHead(204).end();
        const msg = JSON.parse(body || "{}") as { id?: number; method?: string };
        if (msg.id === undefined) return void res.writeHead(202).end();
        // The answer arrives as an SSE event and the stream is then left open.
        res.writeHead(200, { "content-type": "text/event-stream" });
        const result = msg.method === "initialize" ? init : { tools: [] };
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result })}\n\n`);
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(srv.address() as { port: number }).port}/mcp`;
      const t0 = Date.now();
      const checks = await pack.run(ctxFor({ url }));
      assert.ok(Date.now() - t0 < 8000, "no check waited for the stream to end");
      // It accepted the handshake from the SSE event, so the probes ran: nothing validates Origin or the version here.
      assert.equal(verdictsOf(checks)["http-origin"], "fail");
      assert.equal(verdictsOf(checks)["http-protocol-version"], "fail");
    } finally {
      srv.closeAllConnections();
      await new Promise((r) => srv.close(r));
    }
  });
});

describe("http-bind reads the listener table", () => {
  const WIN = `
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
  TCP    127.0.0.1:9000         0.0.0.0:0              LISTENING
  TCP    [::1]:9000             [::]:0                 LISTENING
  TCP    192.168.1.5:9100       0.0.0.0:0              LISTENING
  TCP    [::]:9200              [::]:0                 LISTENING
  TCP    127.0.0.1:9300         127.0.0.1:50000        ESTABLISHED
`;
  const SS = `State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      511        127.0.0.1:9000      0.0.0.0:*
LISTEN 0      511          0.0.0.0:8080      0.0.0.0:*
LISTEN 0      511             [::]:9200         [::]:*
`;
  const MAC = `tcp4       0      0  127.0.0.1.9000         *.*                    LISTEN
tcp46      0      0  *.8080                 *.*                    LISTEN
`;

  it("parses Windows netstat, Linux ss and macOS netstat output", () => {
    assert.deepEqual(listeningAddresses(WIN, 8080), ["0.0.0.0"]);
    assert.deepEqual(listeningAddresses(WIN, 9000).sort(), ["127.0.0.1", "::1"]);
    assert.deepEqual(listeningAddresses(WIN, 9300), [], "only LISTEN rows count");
    assert.deepEqual(listeningAddresses(SS, 9000), ["127.0.0.1"]);
    assert.deepEqual(listeningAddresses(SS, 9200), ["::"]);
    assert.deepEqual(listeningAddresses(MAC, 9000), ["127.0.0.1"]);
    assert.deepEqual(listeningAddresses(MAC, 8080), ["*"]);
  });

  it("classifies loopback-only, wildcard, a single other interface, and nothing", () => {
    assert.equal(exposureOf(["127.0.0.1", "::1"]).kind, "loopback");
    assert.equal(exposureOf(["0.0.0.0"]).kind, "wildcard");
    assert.equal(exposureOf(["::"]).kind, "wildcard");
    assert.equal(exposureOf(["*"]).kind, "wildcard");
    assert.equal(exposureOf(["192.168.1.5"]).kind, "interface");
    assert.equal(exposureOf(["127.0.0.1", "192.168.1.5"]).kind, "interface");
    assert.equal(exposureOf([]).kind, "none");
  });

  it("the check fails on a wildcard bind, passes on loopback, is na when the table cannot be read, and sends nothing to any address", async () => {
    const toy = await startHttpToy("open");
    try {
      const run = async (table: () => Promise<string>) => by(await makePack({ listenerTable: table }).run(ctxFor({ url: toy.url })), "http-bind");
      const wildcard = await run(async () => `  TCP    0.0.0.0:${toy.port}    0.0.0.0:0    LISTENING\n`);
      assert.equal(wildcard.verdict, "fail");
      assert.match(wildcard.summary, /every interface/);
      assert.equal(wildcard.advisory, true);
      assert.equal((await run(async () => `  TCP    127.0.0.1:${toy.port}    0.0.0.0:0    LISTENING\n`)).verdict, "pass");
      assert.equal((await run(async () => { throw new Error("netstat missing"); })).verdict, "na");
      assert.equal((await run(async () => "")).verdict, "na");
      // A server Sealmark started itself (command + url) is bound however the job binds it: not examined, whatever the table says.
      const launched = by(await makePack({ listenerTable: async () => `  TCP    0.0.0.0:${toy.port}    0.0.0.0:0    LISTENING\n` }).run(ctxFor({ url: toy.url, command: "my-server" })), "http-bind");
      assert.equal(launched.verdict, "na");
      assert.match(launched.summary, /Sealmark started this server itself/);
    } finally {
      await toy.close();
    }
  });
});

describe("http pack through the harness", { timeout: 120_000 }, () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-http-run-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("a URL server is graded by core and http; the token is not in the report; no sandbox is left behind", async () => {
    const toy = await startHttpToy("good");
    try {
      const server: ServerSpec = { url: toy.url, headers: BEARER };
      const base = legacyEffectiveConfig({ config: { name: "http-toy", version: "0.0.1", server }, packs: ["core", "http"], packsExplicit: false, timeoutProbeSec: 2 });
      const r = await runHarness({ config: { name: "http-toy", version: "0.0.1", server }, effective: { ...base, sandbox: { ...base.sandbox, dir } }, packs: ["core", "http"], packsExplicit: false, timeoutProbeSec: 2, log: quiet });
      assert.equal(r.server.transport, "http");
      assert.equal(gradeOf(r, "http")?.letter, "A");
      assert.equal(gradeOf(r, "core")?.letter, "A");
      assert.equal(JSON.stringify(r).includes(HTTP_TOY_TOKEN), false);
      assert.deepEqual(readdirSync(dir), []);
    } finally {
      await toy.close();
    }
  });
});
