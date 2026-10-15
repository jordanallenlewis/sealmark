import assert from "node:assert/strict";
import net from "node:net";
import { afterEach, describe, it } from "node:test";
import { startUpstream, type UpstreamOptions } from "../observers/upstream.js";
import type { UpstreamStub } from "../types.js";

// The upstream stub over real HTTP on loopback.

const OPTS: UpstreamOptions = { responses: [], defaultReply: { status: 200, json: { rows: [], count: 0 } }, maxBodyBytes: 1024 * 1024, slowHoldMs: 300 };

const open: UpstreamStub[] = [];
const start = async (o: Partial<UpstreamOptions> = {}): Promise<UpstreamStub> => {
  const s = await startUpstream({ ...OPTS, ...o });
  open.push(s);
  return s;
};
afterEach(async () => {
  while (open.length) await open.pop()!.close();
});

const post = (s: UpstreamStub, path: string, body: string, headers: Record<string, string> = {}) => fetch(`${s.url}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });

describe("upstream stub: recording", () => {
  it("binds loopback only, on an ephemeral port, and says so in its url", async () => {
    const s = await start();
    assert.match(s.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.equal(s.kind, "http");
    assert.ok(s.port > 0 && s.url.endsWith(`:${s.port}`));
    // The listening socket is not on the wildcard address: nothing but loopback can connect (the address is what node reports).
    const probe = net.connect({ host: "127.0.0.1", port: s.port });
    await new Promise<void>((res, rej) => (probe.once("connect", res), probe.once("error", rej)));
    assert.equal(probe.remoteAddress, "127.0.0.1");
    probe.destroy();
  });

  it("records method, path, query, lower-cased headers and body, with a monotonic id and what it answered", async () => {
    const s = await start();
    const m = s.mark();
    assert.equal(m, 0);
    const r = await post(s, "/sql?x=1&y=2", '{"sql":"SELECT 1"}', { Authorization: "Bearer abc", "X-Trace": "t1" });
    assert.equal(r.status, 200);
    const [req] = s.requests(m);
    assert.equal(req!.id, 1);
    assert.equal(req!.method, "POST");
    assert.equal(req!.path, "/sql");
    assert.equal(req!.query, "?x=1&y=2");
    assert.equal(req!.headers.authorization, "Bearer abc");
    assert.equal(req!.headers["x-trace"], "t1");
    assert.equal(req!.body, '{"sql":"SELECT 1"}');
    assert.equal(req!.bodyTruncated, false);
    assert.deepEqual({ status: req!.reply.status, ruleId: req!.reply.ruleId }, { status: 200, ruleId: "default" });
    assert.equal(req!.reply.bytes, JSON.stringify({ rows: [], count: 0 }).length);
    await post(s, "/two", "{}");
    assert.equal(s.mark(), 2);
    assert.deepEqual(s.requests(1).map((x) => x.path), ["/two"], "since(mark) returns only the later requests");
    assert.equal(s.requests().length, 2);
  });

  it("truncates the body at max_body_kib and says so", async () => {
    const s = await start({ maxBodyBytes: 1024 });
    await post(s, "/big", "x".repeat(5000));
    const [req] = s.requests();
    assert.equal(req!.body.length, 1024);
    assert.equal(req!.bodyTruncated, true);
  });

  it("find() is case-insensitive over path, query, headers and body, and respects the mark", async () => {
    const s = await start();
    await post(s, "/a", "first SM-Token-One");
    const m = s.mark();
    await post(s, "/Needle-Path?q=1", "{}");
    await post(s, "/b", "{}", { "X-Who": "Caller-Header-Value" });
    await post(s, "/c", "body has MiXeD");
    assert.deepEqual(s.find("needle-path", m).map((r) => r.path), ["/Needle-Path"]);
    assert.equal(s.find("caller-header-value", m).length, 1);
    assert.equal(s.find("mixed", m).length, 1);
    assert.equal(s.find("sm-token-one", m).length, 0, "the earlier request is before the mark");
    assert.equal(s.find("sm-token-one").length, 1);
    assert.equal(s.find("no-such-thing").length, 0);
  });

  it("waitFor resolves as soon as a matching request arrives, and with nothing at the timeout", async () => {
    const s = await start();
    const m = s.mark();
    const waiting = s.waitFor("late-token", 5000, m);
    setTimeout(() => void post(s, "/late", "late-token"), 50);
    const got = await waiting;
    assert.equal(got.length, 1);
    assert.equal(got[0]!.path, "/late");
    const t0 = Date.now();
    assert.deepEqual(await s.waitFor("never", 120, m), []);
    assert.ok(Date.now() - t0 >= 100);
    // A request already there resolves at once.
    assert.equal((await s.waitFor("late-token", 5000, m)).length, 1);
  });
});

describe("upstream stub: replies", () => {
  it("answers the first matching rule, in order; an entry with no match ends the list; ids default to responses[n]", async () => {
    const s = await start({
      responses: [
        { id: "count", match: { path: "^/sql$", body: "count\\(\\*\\)" }, reply: { status: 200, json: { rows: [{ count: 3 }] } } },
        { match: { method: "get", path: "^/health$" }, reply: { status: 204, body: "" } },
        { match: { header: { "X-Role": "^admin$" } }, reply: { status: 200, body: "admin reply" } },
        { reply: { status: 418, body: "teapot" } },
      ],
    });
    const r1 = await post(s, "/sql", "SELECT count(*) FROM t");
    assert.deepEqual(await r1.json(), { rows: [{ count: 3 }] });
    const r2 = await fetch(`${s.url}/health`);
    assert.equal(r2.status, 204);
    const r3 = await post(s, "/other", "{}", { "x-role": "admin" });
    assert.equal(await r3.text(), "admin reply");
    const r4 = await post(s, "/sql", "SELECT 1");
    assert.equal(r4.status, 418);
    assert.deepEqual(s.requests().map((r) => r.reply.ruleId), ["count", "responses[1]", "responses[2]", "responses[3]"]);
  });

  it("a request no rule matches gets the default reply", async () => {
    const s = await start({ responses: [{ match: { path: "^/x$" }, reply: { status: 201, body: "x" } }], defaultReply: { status: 200, json: { ok: true } } });
    const r = await post(s, "/y", "{}");
    assert.deepEqual(await r.json(), { ok: true });
    assert.equal(s.requests()[0]!.reply.ruleId, "default");
  });

  it("{upstream_token} is minted fresh per occurrence and recorded; {token} is one value for the whole reply", async () => {
    const s = await start({ defaultReply: { status: 200, body: '{"rows":[{"n":"{upstream_token}"},{"n":"{upstream_token}"}],"id":"{token}","again":"{token}"}' } });
    const r = await post(s, "/q", "{}");
    const text = await r.text();
    const rows = (JSON.parse(text) as { rows: { n: string }[]; id: string; again: string });
    const [a, b] = rows.rows.map((x) => x.n);
    assert.match(a!, /^sm-row-[0-9a-f]{8}$/);
    assert.notEqual(a, b);
    assert.equal(rows.id, rows.again);
    assert.match(rows.id, /^sm-[0-9a-f]{12}$/);
    assert.deepEqual(s.requests()[0]!.minted, [a, b]);
    await post(s, "/q", "{}");
    assert.notEqual(s.requests()[1]!.minted[0], a, "a second reply mints new tokens");
  });

  it("bytes pads the body to N bytes (spaces after the prefix, so JSON stays valid)", async () => {
    const s = await start({ defaultReply: { status: 200, bytes: 70_000, body: '{"rows":["{upstream_token}"]}' } });
    const r = await post(s, "/q", "{}");
    const buf = Buffer.from(await r.arrayBuffer());
    assert.equal(buf.length, 70_000);
    assert.doesNotThrow(() => JSON.parse(buf.toString("utf8")));
    assert.equal(s.requests()[0]!.reply.bytes, 70_000);
  });

  it("a reply's own headers and status are sent", async () => {
    const s = await start({ defaultReply: { status: 429, headers: { "Retry-After": "7", "content-type": "text/x-custom" }, body: "slow down" } });
    const r = await post(s, "/q", "{}");
    assert.equal(r.status, 429);
    assert.equal(r.headers.get("retry-after"), "7");
    assert.equal(r.headers.get("content-type"), "text/x-custom");
  });

  it("mode error answers 500 with the error canary and the credential header it received", async () => {
    const s = await start();
    s.setMode("error");
    const r = await post(s, "/q", "{}", { Authorization: "Bearer sm-bearer-a-123456" });
    assert.equal(r.status, 500);
    const body = (await r.json()) as { error: string; received: { authorization: string } };
    assert.equal(body.error, s.errorCanary);
    assert.match(s.errorCanary, /^sm-upstream-err-[0-9a-f]{12}$/);
    assert.equal(body.received.authorization, "Bearer sm-bearer-a-123456");
    assert.equal(s.requests()[0]!.reply.ruleId, "mode:error");
    s.setMode("normal");
    assert.equal((await post(s, "/q", "{}")).status, 200);
  });

  it("mode error echoes the configured credential header", async () => {
    const s = await start({ credentialHeader: "X-Api-Key" });
    s.setMode("error");
    const body = (await (await post(s, "/q", "{}", { "x-api-key": "k-1" })).json()) as { received: { authorization: string } };
    assert.equal(body.received.authorization, "k-1");
  });

  it("mode slow holds the reply for delayMs (the request is visible while it waits) and then gives the default reply", async () => {
    const s = await start();
    s.setMode("slow", { delayMs: 400 });
    const t0 = Date.now();
    const pending = post(s, "/q", "while-held");
    const seen = await s.waitFor("while-held", 2000);
    assert.equal(seen.length, 1);
    assert.ok(Date.now() - t0 < 350, "the request was recorded before the hold ended");
    const r = await pending;
    assert.ok(Date.now() - t0 >= 380);
    assert.equal(r.status, 200);
    assert.deepEqual({ rule: s.requests()[0]!.reply.ruleId, delay: s.requests()[0]!.reply.delayMs }, { rule: "mode:slow", delay: 400 });
  });

  it("mode slow without a delay uses slowHoldMs", async () => {
    const s = await start({ slowHoldMs: 250 });
    s.setMode("slow");
    const t0 = Date.now();
    await post(s, "/q", "{}");
    assert.ok(Date.now() - t0 >= 230);
  });

  it("an override wins over the mode and over the rules, until it is cleared", async () => {
    const s = await start({ responses: [{ reply: { status: 200, body: "rule" } }] });
    s.setMode("error");
    s.setOverride({ status: 207, body: "override {upstream_token}" });
    const r = await post(s, "/q", "{}");
    assert.equal(r.status, 207);
    assert.match(await r.text(), /^override sm-row-[0-9a-f]{8}$/);
    assert.equal(s.requests()[0]!.reply.ruleId, "probe");
    s.setOverride(undefined);
    assert.equal((await post(s, "/q", "{}")).status, 500, "back to the mode");
    s.setMode("normal");
    assert.equal(await (await post(s, "/q", "{}")).text(), "rule");
  });
});

describe("upstream stub: lifetime", () => {
  it("closes cleanly: the port stops answering, a waiter ends, a held reply does not keep it open, and close() twice is fine", async () => {
    const s = await startUpstream({ ...OPTS, slowHoldMs: 60_000 });
    s.setMode("slow");
    const held = post(s, "/held", "{}").then(
      () => "answered",
      () => "dropped",
    );
    await s.waitFor("/held", 2000);
    const waiter = s.waitFor("never-comes", 60_000);
    const t0 = Date.now();
    await s.close();
    await s.close();
    assert.ok(Date.now() - t0 < 5000, "close does not wait for the held reply");
    assert.deepEqual(await waiter, []);
    assert.equal(await held, "dropped");
    await assert.rejects(fetch(`${s.url}/x`), "the port is closed");
  });
});
