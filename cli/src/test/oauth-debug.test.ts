import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";
import { OAUTH_DEBUG_FORMAT, authServerMetadataUrls, isInitializeResult, oauthDebug, plainHttpOffLoopback, oauthDebugJson, parseDebugUrl, renderOauthDebug, type OauthDebugResult, type StepId } from "../oauth-debug.js";
import { CLI, hermeticEnv } from "./helpers.js";

/** What the fixture does at each step; every field defaults to a correct server and authorization server. */
interface Mode {
  challenge?: "full" | "no-rm" | "no-bearer" | "open" | "403" | "404" | "html200" | "sse-open" | "cross-rm";
  prm?: "ok" | "missing" | "wrong-resource" | "no-servers";
  as?: "ok" | "missing" | "wrong-issuer" | "slash-issuer" | "no-token-endpoint" | "off-origin-token";
  pkce?: string[] | null;
  registration?: "advertised" | "none" | "cimd";
  register?: "ok" | "error" | "no-id";
  grantTypes?: string[] | null;
  token?: "error" | "issues" | "html500" | "redirect" | "form200" | "401-noerror" | "huge";
  refresh?: "error" | "issues";
}

interface Seen {
  host: string | undefined;
  method: string;
  path: string;
  auth: string | undefined;
  body: string;
}

const FAKE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";
const SECRET = "sm-fixture-client-secret-value";
const OPAQUE = "gho_SECRETSECRETSECRET123";

let http: Server;
let base = "";
let mode: Mode = {};
let seen: Seen[] = [];

const body = (req: IncomingMessage) =>
  new Promise<string>((r) => {
    let s = "";
    req.on("data", (d) => (s += d));
    req.on("end", () => r(s));
  });

before(async () => {
  http = createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const text = await body(req);
    seen.push({ host: req.headers.host, method: req.method ?? "", path, auth: req.headers.authorization, body: text });
    const json = (status: number, v: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(v));
    const issuer = `${base}/as`;
    // The same fixture answers on localhost: another origin than 127.0.0.1, so a request there shows the report left its two origins.
    const other = base.replace("127.0.0.1", "localhost");
    if (path === "/mcp" && req.method === "POST") {
      const c = mode.challenge ?? "full";
      if (c === "open") return json(200, { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "x", version: "1" } } });
      if (c === "403") return json(403, { error: "forbidden" });
      if (c === "404") return res.writeHead(404).end();
      if (c === "html200") return res.writeHead(200, { "content-type": "text/html" }).end("<html>Sign in</html>");
      if (c === "sse-open") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "x", version: "1" } } })}\n\n`);
        return; // the stream stays open, as a Streamable HTTP server may keep it
      }
      if (c === "cross-rm") return res.writeHead(401, { "www-authenticate": `Bearer resource_metadata="${other}/.well-known/oauth-protected-resource/mcp"` }).end();
      const www = c === "no-bearer" ? 'Basic realm="x"' : c === "no-rm" ? 'Bearer realm="mcp"' : `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`;
      return res.writeHead(401, { "www-authenticate": www }).end();
    }
    if (path === "/.well-known/oauth-protected-resource/mcp") {
      const p = mode.prm ?? "ok";
      if (p === "missing") return res.writeHead(404).end();
      return json(200, { resource: p === "wrong-resource" ? "https://elsewhere.example/mcp" : `${base}/mcp`, authorization_servers: p === "no-servers" ? [] : [issuer], scopes_supported: ["mcp"] });
    }
    if (path === "/.well-known/oauth-authorization-server/as") {
      const a = mode.as ?? "ok";
      if (a === "missing") return res.writeHead(404).end();
      const doc: Record<string, unknown> = {
        issuer: a === "wrong-issuer" ? "https://other-issuer.example" : a === "slash-issuer" ? `${issuer}/` : issuer,
        authorization_endpoint: `${issuer}/authorize`,
        response_types_supported: ["code"],
      };
      if (a === "off-origin-token") doc.token_endpoint = `${other}/as/token`;
      else if (a !== "no-token-endpoint") doc.token_endpoint = `${issuer}/token`;
      const pk = mode.pkce === undefined ? ["S256"] : mode.pkce;
      if (pk) doc.code_challenge_methods_supported = pk;
      const r = mode.registration ?? "advertised";
      if (r === "advertised") doc.registration_endpoint = `${issuer}/register`;
      if (r === "cimd") doc.client_id_metadata_document_supported = true;
      const g = mode.grantTypes === undefined ? ["authorization_code", "refresh_token"] : mode.grantTypes;
      if (g) doc.grant_types_supported = g;
      return json(200, doc);
    }
    if (path === "/as/register" && req.method === "POST") {
      if (mode.register === "no-id") return json(200, {});
      if (mode.register === "error") return json(400, { error: "invalid_redirect_uri", error_description: "loopback redirects are not allowed" });
      return json(201, { client_id: "fixture-client-1", client_secret: SECRET, redirect_uris: JSON.parse(text).redirect_uris });
    }
    if (path === "/as/token" && req.method === "POST") {
      const grant = new URLSearchParams(text).get("grant_type");
      const how = grant === "refresh_token" ? (mode.refresh ?? "error") : (mode.token ?? "error");
      if (how === "issues") return json(200, { access_token: FAKE_JWT, token_type: "Bearer", expires_in: 600 });
      if (how === "redirect") return res.writeHead(307, { location: `${other}/elsewhere?code=leaky-code-value` }).end();
      if (how === "form200") return res.writeHead(200, { "content-type": "application/x-www-form-urlencoded" }).end(`access_token=${OPAQUE}&token_type=bearer`);
      if (how === "401-noerror") return res.writeHead(401).end();
      if (how === "huge") return res.writeHead(500, { "content-type": "text/plain" }).end("x".repeat(600 * 1024));
      if (how === "html500") return res.writeHead(500, { "content-type": "text/html" }).end("<html><body>Internal error \u001b[31m</body></html>");
      return json(400, { error: grant === "refresh_token" ? "invalid_grant" : "invalid_client", error_description: "unknown \u001b[2Jclient" });
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});
after(() => {
  http.closeAllConnections();
  return new Promise<void>((r) => http.close(() => r()));
});
beforeEach(() => {
  mode = {};
  seen = [];
});

const step = (r: OauthDebugResult, id: StepId) => r.steps.find((s) => s.id === id)!;
const run = (m: Mode, o: { register?: boolean } = {}) => {
  mode = m;
  seen = [];
  return oauthDebug(`${base}/mcp`, { register: o.register, timeoutMs: 5000 });
};

describe("oauth-debug: URLs", () => {
  it("authorization-server metadata URLs: RFC 8414 path insertion, then OpenID Connect discovery (both forms)", () => {
    assert.deepEqual(authServerMetadataUrls("https://auth.example/tenant1"), [
      "https://auth.example/.well-known/oauth-authorization-server/tenant1",
      "https://auth.example/.well-known/openid-configuration/tenant1",
      "https://auth.example/tenant1/.well-known/openid-configuration",
    ]);
    assert.deepEqual(authServerMetadataUrls("https://auth.example/"), ["https://auth.example/.well-known/oauth-authorization-server", "https://auth.example/.well-known/openid-configuration"]);
    assert.deepEqual(authServerMetadataUrls("not a url"), []);
  });

  it("parseDebugUrl takes http(s) only and refuses credentials in the URL", () => {
    assert.equal(parseDebugUrl("https://mcp.example/mcp"), "https://mcp.example/mcp");
    assert.throws(() => parseDebugUrl("ftp://x/"), /http or https/);
    assert.throws(() => parseDebugUrl("nonsense"), /not a URL/);
    assert.throws(() => parseDebugUrl("https://u:p@mcp.example/mcp"), /user name or password/);
  });
});

describe("oauth-debug: each step against a fixture authorization server", () => {
  it("a correct server: every step ok, no failing step, and nothing sent to the server carries a token", async () => {
    const r = await run({});
    assert.equal(r.failedAt, null);
    assert.equal(r.authRequired, true);
    assert.deepEqual(
      r.steps.map((s) => [s.id, s.status]),
      [
        ["challenge", "ok"],
        ["resource-metadata", "ok"],
        ["auth-server-metadata", "ok"],
        ["registration", "ok"],
        ["pkce", "ok"],
        ["token", "ok"],
        ["refresh", "ok"],
      ],
    );
    assert.ok(seen.every((s) => s.auth === undefined), "no request carries an Authorization header");
    assert.ok(!seen.some((s) => s.path === "/as/register"), "no registration is sent without --register");
    const tok = seen.find((s) => s.path === "/as/token")!;
    const form = new URLSearchParams(tok.body);
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("resource"), `${base}/mcp`, "RFC 8707 resource names the server");
    assert.ok((form.get("code_verifier") ?? "").length >= 43, "a PKCE verifier of at least 43 characters");
  });

  it("challenge: a server that answers without a token has no flow; the other steps are skipped and nothing fails", async () => {
    const r = await run({ challenge: "open" });
    assert.equal(r.authRequired, false);
    assert.equal(r.failedAt, null);
    assert.equal(step(r, "challenge").status, "ok");
    assert.match(step(r, "challenge").summary, /without a token/);
    assert.ok(r.steps.slice(1).every((s) => s.status === "skipped"));
    assert.equal(seen.length, 1);
  });

  it("challenge: no resource_metadata is a warning and the well-known URL is still found", async () => {
    const r = await run({ challenge: "no-rm" });
    assert.equal(step(r, "challenge").status, "warn");
    assert.equal(step(r, "resource-metadata").status, "ok");
    assert.equal(r.failedAt, null);
  });

  it("challenge: a 401 without a Bearer challenge is a warning; a 403 without a token fails", async () => {
    assert.equal(step(await run({ challenge: "no-bearer" }), "challenge").status, "warn");
    const r = await run({ challenge: "403" });
    assert.equal(step(r, "challenge").status, "fail");
    assert.equal(r.failedAt, "challenge");
    assert.equal(step(r, "resource-metadata").status, "ok", "later steps still run when they have what they need");
  });

  it("resource metadata: missing fails and skips everything after it", async () => {
    const r = await run({ prm: "missing" });
    assert.equal(step(r, "resource-metadata").status, "fail");
    assert.equal(r.failedAt, "resource-metadata");
    for (const id of ["auth-server-metadata", "registration", "pkce", "token", "refresh"] as const) assert.equal(step(r, id).status, "skipped", id);
  });

  it("resource metadata: a resource that is not this server, or no authorization server, fails", async () => {
    const wrong = await run({ prm: "wrong-resource" });
    assert.equal(step(wrong, "resource-metadata").status, "fail");
    assert.match(step(wrong, "resource-metadata").summary, /elsewhere\.example/);
    const none = await run({ prm: "no-servers" });
    assert.equal(step(none, "resource-metadata").status, "fail");
    assert.equal(step(none, "auth-server-metadata").status, "skipped");
  });

  it("authorization-server metadata: missing fails; a different issuer fails; a trailing-slash difference warns", async () => {
    const missing = await run({ as: "missing" });
    assert.equal(step(missing, "auth-server-metadata").status, "fail");
    assert.equal(step(missing, "token").status, "skipped");
    assert.equal(step(await run({ as: "wrong-issuer" }), "auth-server-metadata").status, "fail");
    assert.equal(step(await run({ as: "slash-issuer" }), "auth-server-metadata").status, "warn");
  });

  it("authorization-server metadata: no token_endpoint fails and the token and refresh steps are skipped", async () => {
    const r = await run({ as: "no-token-endpoint" });
    assert.equal(step(r, "auth-server-metadata").status, "fail");
    assert.equal(step(r, "token").status, "skipped");
    assert.equal(step(r, "refresh").status, "skipped");
  });

  it("registration: none advertised warns; client ID metadata documents are ok", async () => {
    assert.equal(step(await run({ registration: "none" }), "registration").status, "warn");
    assert.equal(step(await run({ registration: "cimd" }), "registration").status, "ok");
  });

  it("registration with --register: the client id is used for the token step; the client secret is never shown", async () => {
    const r = await run({}, { register: true });
    assert.equal(step(r, "registration").status, "ok");
    assert.match(step(r, "registration").summary, /fixture-client-1/);
    const reg = JSON.parse(seen.find((s) => s.path === "/as/register")!.body);
    assert.deepEqual(reg.redirect_uris, ["http://127.0.0.1/callback"]);
    assert.equal(new URLSearchParams(seen.find((s) => s.path === "/as/token")!.body).get("client_id"), "fixture-client-1");
    assert.ok(!renderOauthDebug(r).includes(SECRET));
    assert.ok(!oauthDebugJson(r).includes(SECRET));
  });

  it("registration with --register refused: fails with the authorization server's error", async () => {
    const r = await run({ register: "error" }, { register: true });
    assert.equal(step(r, "registration").status, "fail");
    assert.match(step(r, "registration").summary, /invalid_redirect_uri/);
  });

  it("pkce: no code_challenge_methods_supported fails; plain only fails", async () => {
    assert.equal(step(await run({ pkce: null }), "pkce").status, "fail");
    const plain = await run({ pkce: ["plain"] });
    assert.equal(step(plain, "pkce").status, "fail");
    assert.equal(plain.failedAt, "pkce");
  });

  it("token: a token issued for a made-up code fails and the token is never shown", async () => {
    const r = await run({ token: "issues" });
    assert.equal(step(r, "token").status, "fail");
    assert.match(step(r, "token").summary, /made-up/);
    assert.ok(!renderOauthDebug(r).includes(FAKE_JWT));
    assert.ok(!oauthDebugJson(r).includes(FAKE_JWT));
  });

  it("token: a 500 with an HTML body fails (a client cannot read why)", async () => {
    const r = await run({ token: "html500" });
    assert.equal(step(r, "token").status, "fail");
    assert.match(step(r, "token").summary, /RFC 6749/);
  });

  it("refresh: a made-up refresh token issued a token fails; not advertised is skipped with the reason", async () => {
    assert.equal(step(await run({ refresh: "issues" }), "refresh").status, "fail");
    const off = await run({ grantTypes: null });
    assert.equal(step(off, "refresh").status, "skipped");
    assert.match(step(off, "refresh").summary, /not advertised/);
    assert.ok(!seen.some((s) => new URLSearchParams(s.body).get("grant_type") === "refresh_token"));
  });

  it("text output is inert: control characters the authorization server sent are escaped", async () => {
    const out = renderOauthDebug(await run({}));
    assert.ok(!out.includes("\u001b"));
    assert.match(out, /invalid_client/);
  });

  it("an unreachable server fails at the challenge with no response", async () => {
    const r = await oauthDebug("http://127.0.0.1:1/mcp", { timeoutMs: 2000 });
    assert.equal(r.failedAt, "challenge");
    assert.match(step(r, "challenge").summary, /no response/);
  });
});

describe("oauth-debug: two origins only, nothing echoed, real answers told apart", () => {
  const offOrigin = () => seen.filter((x) => x.host?.startsWith("localhost"));
  const both = (r: OauthDebugResult) => renderOauthDebug(r) + oauthDebugJson(r);

  it("a resource_metadata URL on another origin is named, not fetched; the well-known URL is used", async () => {
    const r = await run({ challenge: "cross-rm" });
    assert.deepEqual(offOrigin(), []);
    assert.equal(step(r, "resource-metadata").status, "ok");
    assert.match(step(r, "resource-metadata").evidence.join("\n"), /another origin than the server: not fetched/);
  });

  it("a token_endpoint on another origin is named, not contacted: token and refresh are skipped", async () => {
    const r = await run({ as: "off-origin-token" });
    assert.deepEqual(offOrigin(), []);
    assert.equal(step(r, "token").status, "skipped");
    assert.match(step(r, "token").summary, /not contacted/);
    assert.equal(step(r, "refresh").status, "skipped");
  });

  it("a redirect from the token endpoint is reported, not followed, and its query is not printed", async () => {
    const r = await run({ token: "redirect" });
    assert.deepEqual(offOrigin(), []);
    assert.equal(step(r, "token").status, "warn");
    assert.match(step(r, "token").evidence[0]!, /redirect to http:\/\/localhost:\d+\/elsewhere \(not followed\)/);
    assert.ok(!both(r).includes("leaky-code-value"));
  });

  it("a form-encoded token for a made-up code fails and the token is never printed", async () => {
    const r = await run({ token: "form200" });
    assert.equal(step(r, "token").status, "fail");
    assert.ok(!both(r).includes(OPAQUE));
    assert.match(step(r, "token").evidence[0]!, /body not shown/);
  });

  it("a 401 with no error body, and a body over the cap, fail with the size shown and the body not", async () => {
    assert.equal(step(await run({ token: "401-noerror" }), "token").status, "fail");
    const huge = await run({ token: "huge" });
    assert.equal(step(huge, "token").status, "fail");
    const bytes = Number(/(\d+) bytes; body not shown/.exec(step(huge, "token").evidence[0]!)?.[1]);
    assert.ok(bytes > 0 && bytes <= 256 * 1024, `read at most the cap, got ${bytes}`);
    assert.ok(!step(huge, "token").evidence[0]!.includes("xxxx"));
  });

  it("--register: HTTP 200 with no client_id fails", async () => {
    const r = await run({ register: "no-id" }, { register: true });
    assert.equal(step(r, "registration").status, "fail");
    assert.match(step(r, "registration").summary, /no client_id/);
  });

  it("challenge: an HTML page with 200 is not 'no authorization needed'; a 404 leaves authRequired open", async () => {
    const html = await run({ challenge: "html200" });
    assert.equal(step(html, "challenge").status, "fail");
    assert.equal(html.authRequired, null);
    assert.match(step(html, "challenge").summary, /not an MCP endpoint/);
    const missing = await run({ challenge: "404" });
    assert.equal(missing.authRequired, null);
    assert.equal(step(missing, "challenge").status, "fail");
  });

  it("challenge: an event stream that stays open after the initialize result is an answer, not a timeout", async () => {
    mode = { challenge: "sse-open" };
    seen = [];
    const r = await oauthDebug(`${base}/mcp`, { timeoutMs: 3000 });
    assert.equal(step(r, "challenge").status, "ok");
    assert.equal(r.authRequired, false);
  });

  it("helpers: initialize results in JSON and event streams; plain http off loopback", () => {
    assert.ok(isInitializeResult({ text: "", json: { jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-06-18" } } }));
    assert.ok(isInitializeResult({ text: 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}\n\n', json: undefined }));
    assert.ok(!isInitializeResult({ text: "<html>", json: undefined }));
    assert.ok(!isInitializeResult({ text: "", json: { jsonrpc: "2.0", id: 1, error: { code: -32600 } } }));
    assert.ok(plainHttpOffLoopback("http://auth.example/"));
    assert.ok(!plainHttpOffLoopback("http://127.0.0.1:8080/"));
    assert.ok(!plainHttpOffLoopback("http://localhost/"));
    assert.ok(!plainHttpOffLoopback("https://auth.example/"));
  });
});

describe("oauth-debug: the command", () => {
  const sealmark = (args: string[]) =>
    new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const p = spawn(process.execPath, [CLI, ...args], { env: hermeticEnv({}), stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("close", (code) => resolve({ code, out, err }));
    });

  it("exit 0 and a step-by-step report when no step fails", async () => {
    mode = {};
    const r = await sealmark(["oauth-debug", `${base}/mcp`]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /1 challenge/);
    assert.match(r.out, /7 refresh/);
    assert.match(r.out, /No step failed/);
  });

  it("exit 4 and the first failing step named when one fails; --json prints the format", async () => {
    mode = { pkce: null };
    const r = await sealmark(["oauth-debug", `${base}/mcp`, "--json"]);
    assert.equal(r.code, 4, r.err);
    const j = JSON.parse(r.out);
    assert.equal(j.format, OAUTH_DEBUG_FORMAT);
    assert.equal(j.failedAt, "pkce");
  });

  it("exit 2 for a missing or bad URL, and for a flag of another command", async () => {
    assert.equal((await sealmark(["oauth-debug"])).code, 2);
    assert.equal((await sealmark(["oauth-debug", "ftp://x/"])).code, 2);
    assert.equal((await sealmark(["oauth-debug", `${base}/mcp`, "--pack", "core"])).code, 2);
  });
});
