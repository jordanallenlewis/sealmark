import assert from "node:assert/strict";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { TemplateCtx } from "../config.js";
import { McpSession } from "../mcp.js";
import { badgeFor, runHarness } from "../run.js";
import type { ConfigIntegrity, PackId, RunResult, SealmarkConfig } from "../types.js";
import { freePort } from "./helpers.js";
import { effectiveFor } from "./packctx.js";

// round 6, package harness: a launched HTTP server runs in the sandbox, {upstream} and {bearer} reach the server, plugins see the new
// observers, candidate packs are added when declared, and the stub is closed at the end of the run.

const HTTP_TOY = fileURLToPath(new URL("../toy/http.js", import.meta.url));
const quiet = () => {};

let dir: string;
let n = 0;
before(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "sealmark-r6-run-")));
});
after(() => rmSync(dir, { recursive: true, force: true }));

/** A plugin pack that exercises what plugins get: it reports what it saw as JSON in the check summary. */
const PLUGIN = `export default {
  id: "plugin:r6", version: "1.0.0", sealmark: ">=0",
  describe: () => [{ id: "r6-saw", pack: "plugin:r6", label: "saw", critical: false, advisory: true, scope: "server", verifiedBy: ["upstream"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.3-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  async run(ctx) {
    const h = ctx.helpers;
    const out = { upstream: Boolean(h.upstream), serverLog: Boolean(h.serverLog), openAs: typeof h.openAs, identityOnCtx: Boolean(ctx.identity), vars: Object.keys(ctx.vars ?? {}).sort() };
    if (h.upstream) {
      out.upstreamUrl = h.upstream.url;
      const m = h.upstream.mark();
      out.sent = {};
      for (const who of ["a", "b"]) {
        const s = await h.openAs(who);
        const before = h.upstream.mark();
        const r = await s.call("forward", { q: "as-" + who });
        out.sent[who] = { isError: r.isError, auth: h.upstream.requests(before).map((x) => x.headers.authorization) };
      }
      out.anon = await h.openAs(null).then(() => "opened", (e) => "refused");
      out.total = h.upstream.requests(m).length;
      out.waited = (await h.upstream.waitFor("as-b", 1000, m)).length;
    }
    if (h.serverLog) {
      out.logHasListening = h.serverLog.find("listening") >= 0;
      out.logSince = h.serverLog.since(0).includes("listening");
    }
    return [h.done({ id: "r6-saw", label: "saw", critical: false, scope: "server", advisory: true }, "pass", JSON.stringify(out), [])];
  },
};`;

interface Setup {
  port: number;
  where: { dir: string; parent: string };
  config: SealmarkConfig;
}

async function setup(o: { backend?: boolean; headers?: Record<string, string> } = {}): Promise<Setup> {
  const id = n++;
  const base = join(dir, `t${id}`);
  const parent = join(base, "sandboxes");
  mkdirSync(parent, { recursive: true });
  writeFileSync(join(base, "r6-plugin.mjs"), PLUGIN);
  const port = await freePort();
  const args = [HTTP_TOY, "--mode", "good", "--port", String(port), ...(o.backend === false ? [] : ["--backend", "{upstream}"])];
  const config: SealmarkConfig = {
    name: "r6-launched",
    version: "0.0.1",
    server: { command: process.execPath, args, url: `http://127.0.0.1:${port}/mcp`, headers: o.headers ?? { Authorization: "Bearer {bearer}" }, start_timeout_sec: 30 },
  };
  return { port, where: { dir: base, parent }, config };
}

async function run(s: Setup, packs: PackId[], over: Record<string, unknown> = {}, explicit = true): Promise<RunResult> {
  const plugins = (over.plugins as unknown[] | undefined) ?? [{ module: "./r6-plugin.mjs" }];
  const list = plugins.length ? [...packs, "plugin:r6" as PackId] : packs;
  const effective = effectiveFor(s.config, list, s.where, { ...over, plugins } as never);
  return runHarness({ config: s.config, effective, packs: list, packsExplicit: explicit, timeoutProbeSec: 2, log: quiet });
}

const UPSTREAM = { kind: "http", responses: [], default_reply: { status: 200, json: { rows: [], count: 0 } }, credential_header: "authorization", max_body_kib: 64 };
const saw = (r: RunResult): Record<string, unknown> => {
  const c = r.checks.find((x) => x.id === "r6-saw");
  assert.ok(c, `the plugin ran: ${JSON.stringify(r.packs["plugin:r6" as PackId])}`);
  return JSON.parse(c.summary) as Record<string, unknown>;
};

describe("a launched HTTP server runs inside the sandbox", { timeout: 180_000 }, () => {
  it("its cwd is the sandbox root and the harness's own environment does not reach it; the report says so", async () => {
    process.env.SM_R6_MARKER = "from-the-harness";
    try {
      const s = await setup();
      const r = await run(s, ["core", "fs", "effects"], { upstream: UPSTREAM, probes: [{ tool: "inspect" }, { tool: "list_items" }], plugins: [] });
      assert.equal(r.server.launched, true);
      assert.equal(r.options.sandbox, true, "sandboxOn covers a launched HTTP server");
      assert.equal(r.sandbox?.envMode, "scrubbed");
      const inspected = JSON.parse(JSON.stringify(r.probes?.calls ?? [])) as { tool: string; excerpt?: string; text?: string }[];
      const call = inspected.find((c) => c.tool === "inspect");
      assert.ok(call, JSON.stringify(inspected));
      const reply = JSON.parse(String(call.excerpt ?? call.text)) as { cwd: string; marker: string | null };
      assert.match(reply.cwd, /sealmark-[0-9a-f]+[\\/]root$/, "the server was started in the sandbox root");
      assert.equal(reply.marker, null, "scrubbed environment: the marker from the harness's process is not there");
      assert.ok(!r.notCovered.some((x) => /no sandbox/.test(x)), "the old 'full environment and no sandbox' line is gone");
      assert.ok(r.notCovered.some((x) => /not a security boundary/.test(x)), "the sandbox is a convention: the standing note is printed");
    } finally {
      delete process.env.SM_R6_MARKER;
    }
  });

  it("the fs and effects packs are no longer refused for being 'already running (HTTP)'", async () => {
    const s = await setup();
    const r = await run(s, ["core", "fs", "effects"], { upstream: UPSTREAM, plugins: [] });
    for (const id of ["fs", "effects"] as const) {
      const p = r.packs[id];
      assert.ok(p, id);
      assert.ok(!("reason" in p) || !/already running/.test(String(p.reason)), `${id}: ${JSON.stringify(p)}`);
    }
    // list_items is an unannotated no-argument tool: the effects gate is open.
    assert.equal(r.packs.effects?.status, "graded", JSON.stringify(r.packs.effects));
  });

  it("an HTTP server that is already running keeps the old gate reasons and the old note", async () => {
    const id = n++;
    const parent = join(dir, `t${id}`, "sandboxes");
    mkdirSync(parent, { recursive: true });
    const port = await freePort();
    const { startHttpToy } = await import("../toy/http.js");
    const toy = await startHttpToy("good", { port });
    try {
      const config: SealmarkConfig = { name: "running", version: "0.0.1", server: { url: toy.url, headers: { Authorization: `Bearer ${toy.token}` } } };
      const effective = effectiveFor(config, ["core", "fs"], { dir: join(dir, `t${id}`), parent });
      const r = await runHarness({ config, effective, packs: ["core", "fs"], packsExplicit: true, timeoutProbeSec: 2, log: quiet });
      assert.match(String((r.packs.fs as { reason?: string }).reason), /already running \(HTTP\), so it cannot be started inside the sandbox/);
      assert.equal(r.options.sandbox, false);
    } finally {
      await toy.close();
    }
  });
});

describe("{upstream}, identities and the observers", { timeout: 180_000 }, () => {
  it("{upstream} is expanded in the server's args: the toy forwards to the stub, which records the caller's minted bearer", async () => {
    const s = await setup();
    const r = await run(s, ["core"], { upstream: UPSTREAM });
    const seen = saw(r);
    assert.equal(seen.upstream, true);
    assert.equal(seen.serverLog, true);
    assert.equal(seen.openAs, "function");
    assert.equal(seen.identityOnCtx, true);
    const sent = seen.sent as Record<"a" | "b", { isError: boolean; auth: string[] }>;
    assert.equal(sent.a.isError, false, "the forward reached the stub (the toy answered from its reply)");
    const [authA] = sent.a.auth;
    const [authB] = sent.b.auth;
    assert.match(authA!, /^Bearer sm-bearer-a-[0-9a-f]{12}$/);
    assert.match(authB!, /^Bearer sm-bearer-b-[0-9a-f]{12}$/);
    assert.notEqual(authA, authB, "{bearer:a} and {bearer:b} differ");
    assert.equal(seen.anon, "refused", "an anonymous session sends no Authorization, so the toy refuses it");
    assert.equal(seen.waited, 1, "waitFor resolves on a request already there");
    assert.equal(seen.total, 2);
    assert.deepEqual(r.identities, { names: ["a", "b"], source: "minted" });
    assert.equal(r.upstream?.kind, "http");
    assert.ok(r.upstream!.requests >= 2);
    assert.match(r.upstream!.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.ok((seen.vars as string[]).includes("upstream") && (seen.vars as string[]).includes("bearer:a") && (seen.vars as string[]).includes("bearer:b") && (seen.vars as string[]).includes("bearer"));
    assert.equal(seen.logHasListening, true, "the launched server's output reached the log observer");
  });

  it("identities.a / identities.b from the config win over the minted values", async () => {
    const s = await setup();
    const r = await run(s, ["core"], { upstream: UPSTREAM, identities: { a: "token-from-config-a", b: "token-from-config-b" } });
    const sent = saw(r).sent as Record<"a" | "b", { auth: string[] }>;
    assert.deepEqual(sent.a.auth, ["Bearer token-from-config-a"]);
    assert.deepEqual(sent.b.auth, ["Bearer token-from-config-b"]);
    assert.deepEqual(r.identities, { names: ["a", "b"], source: "config" });
  });

  it("without upstream.kind the plugin gets no upstream helper, and the report no upstream field", async () => {
    const s = await setup({ backend: false, headers: { Authorization: "Bearer sm-toy-bearer-token" } });
    const r = await run(s, ["core"]);
    const seen = saw(r);
    assert.equal(seen.upstream, false);
    assert.equal(seen.openAs, "undefined", "no {bearer} in the server's headers: no identities");
    assert.equal(seen.identityOnCtx, false);
    assert.equal(seen.serverLog, true, "a launched server's log is there either way");
    assert.equal(r.upstream, undefined);
    assert.equal(r.identities, undefined);
  });

  it("the stub is closed when the run ends", async () => {
    const s = await setup();
    const r = await run(s, ["core"], { upstream: UPSTREAM, plugins: [] });
    assert.ok(r.upstream);
    await assert.rejects(fetch(`${r.upstream.url}/x`), "nothing answers on the stub's port after the run");
  });

  it("a stub on a server that cannot reach loopback is a config error that says why", async () => {
    const s = await setup();
    s.config.server.url = "http://203.0.113.9:8080/mcp";
    await assert.rejects(run(s, ["core"], { upstream: UPSTREAM, plugins: [] }), /cannot reach the harness's upstream stub/);
  });
});

describe("anonymous sessions", () => {
  it("openAs(null) drops every header whose value holds {bearer}, and sends the rest", async () => {
    const got: IncomingHttpHeaders[] = [];
    const server = createServer((req, res) => {
      got.push(req.headers);
      req.resume();
      res.statusCode = 401;
      res.end("no");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const spec = { url: `http://127.0.0.1:${port}/mcp`, headers: { Authorization: "Bearer {bearer}", "X-Api-Key": "{bearer:b}", "X-Static": "kept" } };
    const ctx: TemplateCtx = { vars: { bearer: "tok-a", "bearer:a": "tok-a", "bearer:b": "tok-b" }, dsns: {} };
    try {
      await assert.rejects(McpSession.open(spec, ctx, { anonymous: true, connectTimeoutMs: 3000 }));
      await assert.rejects(McpSession.open(spec, ctx, { connectTimeoutMs: 3000 }));
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
    const anon = got[0]!;
    assert.equal(anon.authorization, undefined);
    assert.equal(anon["x-api-key"], undefined);
    assert.equal(anon["x-static"], "kept");
    const named = got.find((h) => h.authorization)!;
    assert.equal(named.authorization, "Bearer tok-a", "{bearer} is identity a's value");
    assert.equal(named["x-api-key"], "tok-b", "{bearer:b} is identity b's value");
  });
});

describe("candidate packs", { timeout: 180_000 }, () => {
  it("are added when declared (default pack list only), with the note; an explicit list is left alone", async () => {
    const s = await setup();
    const declared = { upstream: UPSTREAM, scope: { tools: [{ tool: "forward", param: "q" }], allow: ["a."] }, plugins: [] };
    const r = await run(s, ["core"], declared, false);
    assert.ok(r.options.packsRequested.includes("scope" as PackId) && r.options.packsRequested.includes("upstream" as PackId), JSON.stringify(r.options.packsRequested));
    assert.ok(r.warnings?.includes("scope was declared in the config, so the pack is included"));
    assert.ok(r.warnings?.includes("upstream was declared in the config, so the pack is included"));
    // The packs ran (their verdicts against this toy are not the point here).
    assert.ok(r.packs["scope" as PackId] && r.packs["upstream" as PackId], JSON.stringify(Object.keys(r.packs)));

    const s2 = await setup();
    const explicit = await run(s2, ["core"], declared, true);
    assert.deepEqual(explicit.options.packsRequested, ["core"]);
    assert.ok(!explicit.warnings?.some((w) => /so the pack is included/.test(w)));
    // ... and says what it skipped, as for probes with a check (doctor's autoAddedPacks text).
    assert.ok(explicit.warnings?.includes("scope was declared in the config but the pack list omits scope, so it was skipped (add scope to --pack or packs:)"), JSON.stringify(explicit.warnings));
  });

  it("each gate names its reason when the declaration is missing", async () => {
    const s = await setup({ backend: false, headers: { Authorization: "Bearer sm-toy-bearer-token" } });
    const r = await run(s, ["core", "scope" as PackId, "sql-guard" as PackId, "upstream" as PackId], { plugins: [] });
    const reason = (id: string) => String((r.packs[id as PackId] as { reason?: string }).reason);
    assert.match(reason("scope"), /no `scope.tools` entry names a tool the server declares/);
    assert.match(reason("sql-guard"), /no tool takes a SQL string|no upstream stub: set `upstream.kind: http` \(flag --upstream\) and use `\{upstream\}`/);
    assert.match(reason("upstream"), /no upstream stub: set `upstream.kind: http` \(flag --upstream\) and use `\{upstream\}` in the server config/);
  });

  it("upstream is gated on a valid call: a probes: entry without check", async () => {
    const s = await setup();
    const none = await run(s, ["core", "upstream" as PackId], { upstream: UPSTREAM, plugins: [] });
    assert.match(String((none.packs["upstream" as PackId] as { reason?: string }).reason), /no valid call: add a `probes:` entry without `check` for one tool, or run `sealmark init --probes`/);
  });

  it("never make a run badge-eligible, and the reason says core-only", () => {
    const integrity = { standard: true } as ConfigIntegrity;
    const graded = { status: "graded" as const, grade: { letter: "A" } } as never;
    const only = badgeFor(integrity, { core: graded, scope: graded, "sql-guard": graded, upstream: graded } as never);
    assert.deepEqual(only, { eligible: false, reason: "core-only run: no capability pack was graded" });
    assert.equal(badgeFor(integrity, { core: graded, fs: graded, scope: graded } as never).eligible, true);
  });
});
