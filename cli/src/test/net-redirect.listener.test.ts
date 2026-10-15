// The listener side of net-redirect: /redir-to answers a 302 only to the listener itself or a sandbox file, and refuses everything
// else with a 400 and a record. See the design notes 4.1.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { pathToFileURL } from "node:url";
import { isLoopbackSpelling, redirectTargetProblem, startListener, type Listener } from "../observers/listener.js";
import { targetProblem } from "../packs/net.js";

let l: Listener;
let root: string;
before(async () => {
  root = mkdtempSync(join(tmpdir(), "sealmark-redir-"));
  l = await startListener({ slowHoldMs: 100, bigBytes: 1024 });
});
after(async () => {
  await l.close();
  rmSync(root, { recursive: true, force: true });
});

const redirTo = (token: string, to: string) => fetch(`${l.url}/redir-to/${token}?to=${encodeURIComponent(to)}`, { redirect: "manual" });

describe("redirectTargetProblem", () => {
  const ports = [4001, 4002];
  const fileRoot = "/tmp/sm-sandbox";
  const o = { ports, fileRoot };

  it("accepts the listener's own URLs, loopback spellings on its own ports and a file inside the sandbox", () => {
    for (const ok of [
      "http://127.0.0.1:4001/t/x",
      "http://localhost:4001/",
      "http://LOCALHOST:4002/t/x",
      "http://[::1]:4002/t/x",
      "http://127.1:4001/t/x",
      "http://0x7f000001:4001/t/x",
      "http://2130706433:4001/t/x",
      "http://0.0.0.0:4001/t/x",
      "http://[::ffff:7f00:1]:4001/t/x",
      "gopher://127.0.0.1:4001/_x",
      "dict://127.0.0.1:4001/d:x",
      "ftp://127.0.0.1:4001/",
      pathToFileURL(`${fileRoot}/canary/secret.txt`).href,
    ]) {
      assert.equal(redirectTargetProblem(ok, o), undefined, ok);
    }
  });

  it("refuses another host, another port, other schemes and a file outside the sandbox", () => {
    const why = (u: string, opts = o) => redirectTargetProblem(u, opts);
    assert.match(why("http://10.0.0.1/")!, /not a loopback address/);
    assert.match(why("http://10.0.0.1:4001/")!, /not a loopback address/);
    assert.match(why("http://169.254.169.254:4001/latest/meta-data/")!, /not a loopback address/);
    assert.match(why("http://example.com:4001/")!, /not a loopback address/);
    assert.match(why("http://127.0.0.1:4003/")!, /port 4003 is not the listener's/);
    assert.match(why("http://127.0.0.1/")!, /port \(default\) is not the listener's/);
    assert.match(why("data:text/plain,x")!, /scheme data: is not served/);
    assert.match(why("javascript:1")!, /scheme javascript: is not served/);
    assert.match(why("gopher://10.0.0.1:4001/_x")!, /not a loopback address/);
    assert.match(why("gopher://127.0.0.1:9/_x")!, /port 9 is not the listener's/);
    assert.match(why("file:///etc/passwd")!, /outside the sandbox/);
    assert.match(why(pathToFileURL(`${fileRoot}/../etc/passwd`).href)!, /outside the sandbox/);
    assert.match(why(pathToFileURL("/tmp/sm-sandbox-evil/x").href)!, /outside the sandbox/);
    assert.match(why("file://example.com/etc/passwd")!, /host other than localhost/);
    assert.match(why("/t/x")!, /not an absolute URL/);
    assert.match(why("")!, /not an absolute URL/);
  });

  it("refuses https even on a loopback host and the listener's own port (the listener speaks plain http)", () => {
    assert.match(redirectTargetProblem("https://127.0.0.1:4001/", o)!, /scheme https: is not served/);
    assert.match(redirectTargetProblem("https://127.0.0.1:4003/", o)!, /scheme https: is not served/);
  });

  it("refuses every file: target until a directory is set", () => {
    assert.match(redirectTargetProblem(pathToFileURL(`${fileRoot}/canary/secret.txt`).href, { ports })!, /no sandbox directory was set/);
  });

  it("is not fooled by credentials or by a host that merely starts with a loopback name", () => {
    assert.match(redirectTargetProblem("http://127.0.0.1:4001@evil.example:4001/", o)!, /evil\.example is not a loopback address/);
    assert.match(redirectTargetProblem("http://127.0.0.1.evil.example:4001/", o)!, /not a loopback address/);
    assert.match(redirectTargetProblem("http://localhost.evil.example:4001/", o)!, /not a loopback address/);
  });
});

describe("the loopback-spelling test is the one packs/net.ts uses", () => {
  // The listener may not import a pack, so it carries a copy; both must say the same on every spelling here. net.ts does not export
  // isLoopbackHost, so its answer is read through targetProblem (undefined means loopback host and own port).
  const spellings = [
    "127.0.0.1",
    "127.0.0.2",
    "127.255.255.255",
    "localhost",
    "LOCALHOST",
    "foo.localhost",
    "localhost.example.com",
    "[::1]",
    "[::]",
    "127.1",
    "0x7f000001",
    "2130706433",
    "0.0.0.0",
    "0.0.0.1",
    "[::ffff:7f00:1]",
    "[::ffff:127.0.0.1]",
    "[::ffff:a00:1]",
    "[::2]",
    "[fe80::1]",
    "10.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "128.0.0.1",
    "8.8.8.8",
    "example.com",
    "127.0.0.1.nip.io",
    "1.2.3.4",
  ];
  const netSays = (url: string) => targetProblem(url, { sandboxDir: "/tmp/sm", ports: [4001], allowDns: false }) === undefined;
  const listenerSays = (url: string) => redirectTargetProblem(url, { ports: [4001] }) === undefined;

  it("agrees on every http: spelling in a fixed list", () => {
    for (const h of spellings) {
      const url = `http://${h}:4001/t/x`;
      assert.equal(listenerSays(url), netSays(url), `${h}: listener ${listenerSays(url)}, net ${netSays(url)}`);
    }
    assert.equal(listenerSays("http://127.1:4001/"), true, "the URL parser makes 127.1 a loopback address");
    assert.equal(listenerSays("http://10.0.0.1:4001/"), false);
  });

  it("agrees on gopher: spellings, where the URL parser leaves the host as written", () => {
    for (const h of spellings) {
      const url = `gopher://${h}:4001/_x`;
      assert.equal(listenerSays(url), netSays(url), `${h}: listener ${listenerSays(url)}, net ${netSays(url)}`);
    }
  });

  it("isLoopbackSpelling alone: loopback, any 127/8, unspecified, ::1, mapped 127/8 and *.localhost", () => {
    for (const h of ["127.0.0.1", "127.9.9.9", "0.0.0.0", "localhost", "a.localhost", "::1", "::", "::ffff:7f00:1"]) assert.equal(isLoopbackSpelling(h), true, h);
    for (const h of ["10.0.0.1", "169.254.169.254", "128.0.0.1", "example.com", "::2", "fe80::1", "::ffff:a00:1", "999.0.0.1", "localhost.example.com", ""]) assert.equal(isLoopbackSpelling(h), false, h);
  });
});

describe("the listener's /redir-to route", () => {
  it("answers 302 with the Location for an allowed target and records it", async () => {
    const to = `${l.url}/t/tok-allowed`;
    const res = await redirTo("tok-allowed", to);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), to);
    assert.equal(await res.text(), "");
    const rec = l.requests().find((r) => r.route === "redir-to" && r.token === "tok-allowed")!;
    assert.equal(rec.status, 302);
    assert.equal(rec.location, to);
    assert.equal(rec.refusedTarget, undefined);
  });

  it("answers 400 and records refusedTarget for a refused target, and never sends a Location", async () => {
    for (const [tok, to] of [
      ["tok-ext", "http://10.0.0.1/t/x"],
      ["tok-meta", "http://169.254.169.254/latest/meta-data/"],
      ["tok-port", "http://127.0.0.1:9/t/x"],
      ["tok-data", "data:text/plain,x"],
      ["tok-js", "javascript:1"],
      ["tok-passwd", "file:///etc/passwd"],
      ["tok-https", `https://127.0.0.1:${l.port}/`],
    ] as const) {
      const res = await redirTo(tok, to);
      assert.equal(res.status, 400, to);
      assert.equal(res.headers.get("location"), null, to);
      assert.match(await res.text(), /^sm-listener: refused redirect target \(.+\)$/, to);
      const rec = l.requests().find((r) => r.route === "redir-to" && r.token === tok)!;
      assert.equal(rec.refusedTarget, true, to);
      assert.equal(rec.location, undefined, to);
      assert.equal(rec.status, 400);
    }
  });

  it("refuses a missing or empty to= with a 400", async () => {
    const none = await fetch(`${l.url}/redir-to/tok-none`, { redirect: "manual" });
    assert.equal(none.status, 400);
    assert.match(await none.text(), /no to= parameter/);
    const empty = await fetch(`${l.url}/redir-to/tok-empty?to=`, { redirect: "manual" });
    assert.equal(empty.status, 400);
  });

  it("refuses a Location to a port that is not the listener's, even on a loopback spelling (must fail)", async () => {
    const res = await redirTo("tok-other-port", "http://127.0.0.1:9/t/tok-other-port");
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("location"), null);
    assert.equal(l.hopsFor("tok-other-port").find((r) => r.location !== undefined), undefined);
  });

  it("serves a file: Location only after allowFileRedirectsUnder, and only inside that directory", async () => {
    const inside = pathToFileURL(join(root, "canary", "secret.txt")).href;
    assert.equal((await redirTo("tok-file-before", inside)).status, 400, "refused until a directory is set");
    l.allowFileRedirectsUnder(root);
    const ok = await redirTo("tok-file-after", inside);
    assert.equal(ok.status, 302);
    assert.equal(ok.headers.get("location"), inside);
    assert.equal((await redirTo("tok-file-out", "file:///etc/passwd")).status, 400);
    assert.equal((await redirTo("tok-file-dotdot", pathToFileURL(join(root, "..", "x")).href)).status, 400);
  });

  it("allows a gopher: target on its own port and refuses one on another port", async () => {
    assert.equal((await redirTo("tok-gopher", `gopher://127.0.0.1:${l.port}/_sm-tok-gopher`)).status, 302);
    assert.equal((await redirTo("tok-gopher-x", "gopher://127.0.0.1:9/_x")).status, 400);
  });

  it("an existing route still works: /redir answers 302 to /t/<token> and /t/<token> answers 200", async () => {
    const r = await fetch(`${l.url}/redir/tok-old`, { redirect: "manual" });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("location"), "/t/tok-old");
    assert.equal((await fetch(`${l.url}/t/tok-old`)).status, 200);
  });
});

describe("hopsFor", () => {
  it("lists the redirecting request and then the request that followed it, in arrival order", async () => {
    const tok = "tok-order";
    await redirTo(tok, `${l.url}/t/${tok}`);
    await fetch(`${l.url}/t/${tok}`);
    await fetch(`${l.url}/t/tok-unrelated`);
    const hops = l.hopsFor(tok);
    assert.deepEqual(hops.map((r) => r.route), ["redir-to", "t"]);
    assert.ok(hops[0]!.id < hops[1]!.id);
    assert.deepEqual(l.hitsFor(tok).map((r) => r.route), ["redir-to", "t"], "hitsFor counts the first hop exactly as before");
  });

  it("matches a Location that carries the token, and an empty token matches nothing", async () => {
    await redirTo("tok-loc", `${l.url}/t/tok-loc-target`);
    assert.equal(l.hopsFor("tok-loc-target").length, 1, "the encoded to= and the Location both carry it, so the one request is listed once");
    assert.deepEqual(l.hopsFor(""), []);
  });

  it("lists a refused redirect too, so the check can print it", async () => {
    await redirTo("tok-refused-hop", "http://10.0.0.1/t/tok-refused-hop");
    const hops = l.hopsFor("tok-refused-hop");
    assert.equal(hops.length, 1);
    assert.equal(hops[0]!.refusedTarget, true);
  });
});
