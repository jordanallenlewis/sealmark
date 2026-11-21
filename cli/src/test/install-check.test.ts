import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import {
  DataError,
  age,
  dataBase,
  installCheck,
  installCheckJson,
  installConfig,
  lookupKeys,
  parseLookup,
  parseServer,
  renderInstallCheck,
  resolveLookup,
  splitLaunch,
  type Fetcher,
} from "../install-check.js";
import { CLI, hermeticEnv } from "./helpers.js";

const ESC = "\u001b";
const NOW = Date.parse("2026-11-21T12:00:00Z");

/** A per-server file the way sealmark.dev's /data/v1/servers/<id>.json writes it (fields this command reads, plus some it ignores). */
function server(id: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    name: "@bytebase/dbhub",
    ecosystem: "npm",
    versionTested: "2.0.1",
    testedAt: "2026-11-20",
    grade: "F",
    provisional: false,
    packs: { core: "A", db: "F" },
    toolCount: 2,
    transport: "stdio",
    lastAttemptFailed: null,
    gradeConfirmed: true,
    noGradeReason: null,
    page: `https://sealmark.dev/results/${id}/`,
    json: `https://sealmark.dev/data/v1/servers/${id}.json`,
    sealmark: { version: "1.0.1", methodology: "0.3-draft" },
    standard: true,
    lastGrade: null,
    lastAttempt: null,
    coverage: { level: "covered", validCalls: 4, toolsCalledValid: 2, toolsTotal: 2 },
    packDetails: [
      { id: "core", status: "graded", letter: "A", provisional: false },
      { id: "db", status: "graded", letter: "F", provisional: false },
      { id: "http", status: "na", letter: null, provisional: false },
    ],
    launch: "npx -y @bytebase/dbhub@2.0.1 --transport stdio --dsn {dsn}",
    ...over,
  };
}

const LOOKUP = {
  version: "v1",
  updated: "2026-11-20",
  count: 4,
  server: "https://sealmark.dev/data/v1/servers/{id}.json",
  keys: {
    "npm:@bytebase/dbhub": ["dbhub"],
    "id:dbhub": ["dbhub"],
    "github:modelcontextprotocol/servers": ["fetch", "git"],
    "pypi:mcp-server-git": ["git"],
    "id:fetch": ["fetch"],
    "id:git": ["git"],
  },
};

const FILES: Record<string, unknown> = {
  "/data/v1/lookup.json": LOOKUP,
  "/data/v1/servers/dbhub.json": server("dbhub"),
  "/data/v1/servers/fetch.json": server("fetch", { name: "mcp-server-fetch", ecosystem: "pypi", grade: "B", versionTested: "2025.4.7", launch: "uvx mcp-server-fetch==2025.4.7" }),
  "/data/v1/servers/git.json": server("git", { name: "mcp-server-git", ecosystem: "pypi", grade: null, lastGrade: { grade: "C", testedAt: "2026-11-01", version: "0.6.2", failingSince: "2026-11-05" } }),
};

/** A fetcher over FILES with the base https://example.test/data/v1; anything else is a 404. */
const fake: Fetcher = async (url) => {
  const path = new URL(url).pathname;
  return path in FILES ? new Response(JSON.stringify(FILES[path]), { status: 200 }) : new Response("not found", { status: 404 });
};
const BASE = "https://example.test/data/v1";

describe("install-check: lookup keys (the site's rules, web/lib/lookup.mjs)", () => {
  it("reads prefixed keys, package and repository URLs and bare names, most specific first", () => {
    assert.deepEqual(lookupKeys("npm:@ByteBase/dbhub@2.0.0"), ["npm:@bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("https://www.npmjs.com/package/@bytebase/dbhub/v/2.0.0"), ["npm:@bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("https://pypi.org/project/MCP-Server-Fetch/2025.4.7/"), ["pypi:mcp-server-fetch"]);
    assert.deepEqual(lookupKeys("https://github.com/Bytebase/dbhub"), ["github:bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("git@github.com:Bytebase/dbhub.git"), ["github:bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("@bytebase/dbhub"), ["npm:@bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("bytebase/dbhub"), ["github:bytebase/dbhub"]);
    assert.deepEqual(lookupKeys("mcp-server-fetch"), ["npm:mcp-server-fetch", "pypi:mcp-server-fetch", "id:mcp-server-fetch"]);
    assert.deepEqual(lookupKeys("id:dbhub"), ["id:dbhub"]);
  });

  it("reads a sealmark.dev results URL as the id", () => {
    assert.deepEqual(lookupKeys("https://sealmark.dev/results/dbhub/"), ["id:dbhub"]);
    assert.deepEqual(lookupKeys("sealmark.dev/results/dbhub"), ["id:dbhub"]);
    assert.deepEqual(lookupKeys("https://sealmark.dev/results/dbhub/#install-h"), ["id:dbhub"]);
  });

  it("gives no key for what is none of these", () => {
    assert.deepEqual(lookupKeys(""), []);
    assert.deepEqual(lookupKeys("   "), []);
    assert.deepEqual(lookupKeys("id:Has Space"), []);
    assert.deepEqual(lookupKeys("https://www.npmjs.com/package/%E0%A4%A"), []);
    assert.deepEqual(lookupKeys("!!!"), []);
  });

  it("resolves the first key the index has; a key named __proto__ or constructor is only a key", () => {
    const ix = parseLookup(LOOKUP);
    assert.deepEqual(resolveLookup(ix, lookupKeys("@bytebase/dbhub@2.0.0")), { key: "npm:@bytebase/dbhub", ids: ["dbhub"] });
    assert.deepEqual(resolveLookup(ix, lookupKeys("https://github.com/modelcontextprotocol/servers/tree/main/src/git")).ids, ["fetch", "git"]);
    assert.deepEqual(resolveLookup(ix, lookupKeys("mcp_server_git")).ids, ["git"], "bare name: npm misses, PyPI hits");
    assert.deepEqual(resolveLookup(ix, lookupKeys("dbhub")).ids, ["dbhub"], "bare name: falls through to the id");
    assert.deepEqual(resolveLookup(ix, lookupKeys("never-graded-mcp")), { key: null, ids: [] });
    assert.deepEqual(resolveLookup(ix, lookupKeys("constructor")).ids, []);
    const proto = parseLookup(JSON.parse('{"keys":{"__proto__":["dbhub"]}}'));
    assert.deepEqual(resolveLookup(proto, ["__proto__"]).ids, ["dbhub"]);
    assert.equal(Object.getPrototypeOf({}), Object.prototype, "parsing the data never touches a prototype");
  });

  it("drops ids that are not ids, and refuses an index with no keys", () => {
    const ix = parseLookup({ keys: { "id:x": ["x", "../etc/passwd", 7, "has space"] } });
    assert.deepEqual(ix.keys.get("id:x"), ["x"]);
    assert.throws(() => parseLookup({ version: "v1" }), DataError);
    assert.throws(() => parseLookup([]), DataError);
  });
});

describe("install-check: install config (the site's rules, web/lib/install-config.mjs)", () => {
  const x = (launch: string | null, o: Record<string, unknown> = {}) => ({ id: "dbhub", transport: "stdio", launch, versionTested: "2.0.1", ...o });

  it("an npx line pinning the graded version gives JSON and a claude mcp add line, placeholders filled", () => {
    const c = installConfig(x("npx -y @bytebase/dbhub@2.0.1 --transport stdio --dsn {dsn}"));
    assert.ok(c);
    assert.deepEqual(JSON.parse(c.json), { mcpServers: { dbhub: { command: "npx", args: ["-y", "@bytebase/dbhub@2.0.1", "--transport", "stdio", "--dsn", "postgresql://USER:PASSWORD@HOST:5432/DATABASE"] } } });
    // The site's words exactly: a word with @ is quoted.
    assert.equal(c.claude, 'claude mcp add dbhub -- npx -y "@bytebase/dbhub@2.0.1" --transport stdio --dsn "postgresql://USER:PASSWORD@HOST:5432/DATABASE"');
    assert.deepEqual(c.fill.map((f) => f.placeholder), ["{dsn}"]);
  });

  it("a uvx line pinning with == works, and a quoted word stays one argument", () => {
    const c = installConfig(x(`uvx mcp-server-fetch==2.0.1 --user-agent "a b"`, { id: "fetch" }));
    assert.ok(c);
    assert.deepEqual(JSON.parse(c.json).mcpServers.fetch.args, ["mcp-server-fetch==2.0.1", "--user-agent", "a b"]);
    assert.match(c.claude, /--user-agent "a b"$/);
  });

  it("gives none: start command withheld, not stdio, not npx/uvx, version not pinned, shell syntax, unknown placeholder, bad id", () => {
    assert.equal(installConfig(x(null)), null, "launch is null while a finding is reported privately");
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1", { transport: "http" })), null);
    assert.equal(installConfig(x("node server.js @bytebase/dbhub@2.0.1")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@latest")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1 $(whoami)")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1; curl evil")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1 {listener}")), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1", { id: "has space" })), null);
    assert.equal(installConfig(x("npx")), null);
  });

  it("gives none when a word has a character outside printable ASCII (an escape or an invisible character)", () => {
    assert.equal(installConfig(x(`npx -y @bytebase/dbhub@2.0.1 "a${ESC}[2Jb"`)), null);
    assert.equal(installConfig(x("npx -y @bytebase/dbhub@2.0.1 a​b")), null);
  });

  it("splits like a shell, or refuses", () => {
    assert.deepEqual(splitLaunch(`npx -y 'a b' "c d" e`), ["npx", "-y", "a b", "c d", "e"]);
    assert.equal(splitLaunch(`npx "unclosed`), null);
    assert.equal(splitLaunch(`npx "$HOME"`), null);
    assert.equal(splitLaunch("npx a|b"), null);
  });
});

describe("install-check: reading the data", () => {
  it("one graded server: grade, areas, date, page and install config", async () => {
    const r = await installCheck("@bytebase/dbhub", { base: BASE, fetcher: fake });
    assert.equal(r.matchedKey, "npm:@bytebase/dbhub");
    assert.equal(r.servers.length, 1);
    const s = r.servers[0]!;
    assert.equal(s.grade, "F");
    assert.deepEqual(s.areas.map((a) => `${a.id} ${a.letter}`), ["core A", "db F"]);
    assert.ok(s.install);
    const text = renderInstallCheck(r, NOW);
    assert.match(text, /^@bytebase\/dbhub \(sealmark\.dev id dbhub, matched as npm:@bytebase\/dbhub\)\n/);
    assert.match(text, /Grade: F, the lowest test-area grade\nTest areas: core A, db F\nCoverage: Tools reached with a valid call: 2 of 2\.\n/);
    assert.match(text, /Tested: version 2\.0\.1 on 2026-11-20 \(1 day ago\) with Sealmark 1\.0\.1 \(methodology 0\.3-draft\), standard settings\n/);
    assert.match(text, /Results: https:\/\/sealmark\.dev\/results\/dbhub\/\n/);
    assert.match(text, /claude mcp add dbhub -- npx -y "@bytebase\/dbhub@2\.0\.1"/);
    assert.match(text, /postgresql:\/\/USER:PASSWORD@HOST:5432\/DATABASE: your Postgres connection string/);
    assert.match(text, /"mcpServers": \{/);
  });

  it("not in the public results: says so, names the keys it tried, and says that is not proof", async () => {
    const r = await installCheck("never-graded-mcp", { base: BASE, fetcher: fake });
    assert.equal(r.servers.length, 0);
    const text = renderInstallCheck(r, NOW);
    assert.match(text, /"never-graded-mcp" is not in sealmark\.dev's public results \(4 graded servers, updated 2026-11-20\)\. Looked up: npm:never-graded-mcp, pypi:never-graded-mcp, id:never-graded-mcp\./);
    assert.match(text, /does not prove a server was never graded/);
    assert.doesNotMatch(text, /Grade:/);
  });

  it("a repository with several graded servers lists each and gives no config", async () => {
    const r = await installCheck("modelcontextprotocol/servers", { base: BASE, fetcher: fake });
    assert.deepEqual(r.servers.map((s) => s.id), ["fetch", "git"]);
    const text = renderInstallCheck(r, NOW);
    assert.match(text, /\(matched as github:modelcontextprotocol\/servers\) names 2 graded servers/);
    assert.match(text, /mcp-server-fetch \(id fetch\): grade B, version 2025\.4\.7 tested 2026-11-20/);
    assert.match(text, /mcp-server-git \(id git\): grade withdrawn/);
    assert.match(text, /sealmark install-check id:<id>/);
    assert.doesNotMatch(text, /claude mcp add/);
  });

  it("a withdrawn grade says so and shows the last grade with its version and date", async () => {
    const r = await installCheck("id:git", { base: BASE, fetcher: fake });
    const text = renderInstallCheck(r, NOW);
    assert.match(text, /Grade: none now\. Re-tests have kept failing since 2026-11-05, so the last grade is withdrawn \(it was C for version 0\.6\.2 on 2026-11-01\)\./);
  });

  const one = (doc: ReturnType<typeof parseServer>) =>
    renderInstallCheck({ query: "x", keys: ["id:x"], matchedKey: "id:x", source: BASE, index: { updated: null, count: 1 }, servers: [{ ...doc, install: installConfig(doc) }], more: 0 }, NOW);

  it("no overall grade with a reason (no tools): the reason once, no second coverage line, no config", () => {
    const doc = parseServer(server("x", { grade: null, toolCount: 0, coverage: { level: "hygiene-only", validCalls: 0, toolsCalledValid: 0, toolsTotal: 0 }, noGradeReason: { kind: "no-tools", text: "The server declared no tools under default settings. It probably needs configuration first." }, packDetails: [{ id: "core", status: "graded", letter: "B" }], launch: "node x.js" }), "x");
    const text = one(doc);
    assert.match(text, /Grade: none\. The server declared no tools under default settings\. It probably needs configuration first\.\nTest areas: core B\n/);
    assert.doesNotMatch(text, /Coverage:/);
    assert.match(text, /No install config:/);
  });

  it("a grade that covers only the handshake and tool metadata says so (the page's words)", () => {
    const doc = parseServer(server("x", { grade: "A", toolCount: 1, coverage: { level: "hygiene-only", validCalls: 0, toolsCalledValid: 0, toolsTotal: 1 }, packDetails: [{ id: "core", status: "graded", letter: "A" }] }), "x");
    assert.equal(doc.coverage.kind, "hygiene");
    assert.match(one(doc), /Grade: A, the lowest test-area grade\nTest areas: core A\nCoverage: None of the 1 tool could be called with default settings, so this grade covers the handshake and tool metadata only\.\n/);
    const low = parseServer(server("x", { coverage: { level: "low", validCalls: 1, toolsCalledValid: 1, toolsTotal: 5 } }), "x");
    assert.match(one(low), /Coverage: Only 1 of 5 tools could be called with default settings, so the deeper test areas cover only that tool\./);
    const none = parseServer(server("x", { coverage: null }), "x");
    assert.match(one(none), /Coverage: This result has no record of how many tools were called\./);
  });

  it("a failed re-test counts only on or after the graded run's date, in the page's words", () => {
    const after_ = parseServer(server("x", { lastAttempt: { date: "2026-11-21", status: "failed", kind: "start-fail", startKind: "dependency-resolution" } }), "x");
    assert.match(one(after_), /The latest re-test, on 2026-11-21, could not start the server \(a dependency could not be installed\), so this grade is still the one from 2026-11-20\./);
    const sameDay = parseServer(server("x", { lastAttempt: { date: "2026-11-20", status: "failed", kind: "timeout" } }), "x");
    assert.match(one(sameDay), /The latest re-test, on 2026-11-20, timed out, so this grade is still the one from 2026-11-20\./);
    const older = parseServer(server("x", { lastAttempt: { date: "2026-11-01", status: "failed", kind: "timeout" } }), "x");
    assert.equal(older.retest, null);
    assert.doesNotMatch(one(older), /re-test/);
    const notFailed = parseServer(server("x", { lastAttempt: { date: "2026-11-21", status: "ok", kind: "timeout" } }), "x");
    assert.equal(notFailed.retest, null);
  });

  it("a withdrawn grade keeps the reason and calls the config's version the last one graded", () => {
    const doc = parseServer(server("x", { grade: null, lastGrade: { grade: "B", testedAt: "2026-11-01", version: "0.1.2", failingSince: "2026-11-09" }, versionTested: "0.1.2", noGradeReason: { kind: "retest-failing", text: "Version 0.1.5 has failed to start since 2026-11-09." }, launch: "npx -y x@0.1.2" }), "x");
    const text = one(doc);
    assert.match(text, /so the last grade is withdrawn \(it was B for version 0\.1\.2 on 2026-11-01\)\.\nVersion 0\.1\.5 has failed to start since 2026-11-09\.\n/);
    assert.match(text, /this starts version 0\.1\.2, the last version graded; re-tests of newer versions keep failing/);
  });

  it("a provisional grade says so", () => {
    assert.match(one(parseServer(server("x", { grade: "A", provisional: true }), "x")), /Grade: A \(provisional\)/);
  });

  it("the results link is kept only on sealmark.dev or the data's own origin", () => {
    assert.equal(parseServer(server("x", { page: "https://evil.test/results/x/" }), "x").page, "https://sealmark.dev/results/x/");
    assert.equal(parseServer(server("x", { page: "https://" }), "x").page, "https://sealmark.dev/results/x/");
    assert.equal(parseServer(server("x", { page: "https://mirror.test/results/x/" }), "x", "https://mirror.test/data/v1").page, "https://mirror.test/results/x/");
  });

  it("server-controlled text is made inert: no escape sequence or line break reaches the terminal", async () => {
    const hostile = server("dbhub", { name: `evil${ESC}]8;;https://x${ESC}\\\n[ PASS ] forged`, noGradeReason: null });
    const r = await installCheck("dbhub", { base: BASE, fetcher: async (url) => new Response(JSON.stringify(url.endsWith("lookup.json") ? LOOKUP : hostile)) });
    const text = renderInstallCheck(r, NOW);
    assert.ok(!text.includes(ESC), "no raw ESC in the text output");
    assert.doesNotMatch(text, /\n\[ PASS \] forged/);
    const json = installCheckJson(r);
    assert.ok(!json.includes(ESC), "no raw ESC in the JSON");
    assert.ok(!JSON.parse(json).servers[0].name.includes(ESC), "nor once a reader parses it");
  });

  it("--json: one sealmark.install-check/1 object; the config snippet keeps its lines", async () => {
    const out = JSON.parse(installCheckJson(await installCheck("dbhub", { base: BASE, fetcher: fake })));
    assert.equal(out.format, "sealmark.install-check/1");
    assert.equal(out.found, true);
    assert.equal(out.servers[0].id, "dbhub");
    assert.ok(out.servers[0].install.json.includes("\n"), "the JSON snippet is printed as written");
    assert.deepEqual(JSON.parse(out.servers[0].install.json).mcpServers.dbhub.command, "npx");
    const withdrawn = JSON.parse(installCheckJson(await installCheck("id:git", { base: BASE, fetcher: fake })));
    assert.deepEqual(withdrawn.servers[0].lastGrade, { grade: "C", testedAt: "2026-11-01", version: "0.6.2", failingSince: "2026-11-05" });
    assert.equal(withdrawn.servers[0].coverage.kind, "covered");
    const none = JSON.parse(installCheckJson(await installCheck("nope-mcp", { base: BASE, fetcher: fake })));
    assert.equal(none.found, false);
    assert.deepEqual(none.servers, []);
  });

  it("unreadable data is a DataError, never a guess: offline, timeout, HTTP error, not JSON, a file for another id", async () => {
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async () => Promise.reject(Object.assign(new TypeError("fetch failed"), { cause: { code: "ENOTFOUND" } })) }), /could not reach https:\/\/example\.test\/data\/v1\/lookup\.json \(ENOTFOUND\)/);
    // AbortSignal.timeout's timer does not hold the event loop open (Node 22); a real hung request holds it with its socket.
    const hold = setTimeout(() => {}, 5_000);
    try {
      await assert.rejects(
        installCheck("dbhub", { base: BASE, timeoutMs: 50, fetcher: (_url, init) => new Promise((_res, rej) => init.signal.addEventListener("abort", () => rej(init.signal.reason))) }),
        /no answer in 0 s/,
      );
    } finally {
      clearTimeout(hold);
    }
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async () => new Response("x", { status: 503 }) }), /answered HTTP 503/);
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async () => new Response("<html>") }), /is not JSON/);
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async (url) => new Response(JSON.stringify(url.endsWith("lookup.json") ? LOOKUP : server("other"))) }), /does not describe dbhub/);
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async (url) => new Response(JSON.stringify(url.endsWith("lookup.json") ? LOOKUP : server("dbhub", { testedAt: "yesterday" }))) }), /no tested version or date/);
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async (url) => (url.endsWith("lookup.json") ? new Response(JSON.stringify(LOOKUP)) : new Response("", { status: 404 })) }), /dbhub\.json answered HTTP 404/);
  });

  it("a body over 8 MiB is refused while it is read, even with no content-length", async () => {
    const chunk = new Uint8Array(1024 * 1024).fill(0x20);
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (sent++ > 20) c.close();
        else c.enqueue(chunk);
      },
    });
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: async () => new Response(body) }), /larger than 8 MiB/);
    assert.ok(sent <= 10, `stopped reading early (read ${sent} MiB)`);
  });

  it("a redirect to another origin is refused", async () => {
    const moved = async () => {
      const res = new Response(JSON.stringify(LOOKUP));
      Object.defineProperty(res, "url", { value: "https://elsewhere.test/data/v1/lookup.json" });
      return res;
    };
    await assert.rejects(installCheck("dbhub", { base: BASE, fetcher: moved }), /redirected to another site \(https:\/\/elsewhere\.test\)/);
  });

  it("--data-url takes an http(s) base and drops a trailing slash", () => {
    assert.equal(dataBase(undefined), "https://sealmark.dev/data/v1");
    assert.equal(dataBase("http://127.0.0.1:8080/data/v1/"), "http://127.0.0.1:8080/data/v1");
    assert.throws(() => dataBase("file:///etc"), /http or https/);
    assert.throws(() => dataBase("not a url"), /not a URL/);
    assert.throws(() => dataBase("https://x.test/data?x=1"), /no \? or #/);
  });

  it("age is counted in UTC days", () => {
    assert.equal(age("2026-11-21", NOW), "today");
    assert.equal(age("2026-11-20", NOW), "1 day ago");
    assert.equal(age("2026-11-09", NOW), "12 days ago");
    assert.equal(age("2026-11-22", NOW), "");
  });
});

describe("install-check: the command", () => {
  let http: Server;
  let base: string;
  before(async () => {
    http = createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (req.method !== "GET" || !(path in FILES)) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(FILES[path]));
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", () => r()));
    base = `http://127.0.0.1:${(http.address() as AddressInfo).port}/data/v1`;
  });
  after(() => new Promise<void>((r) => http.close(() => r())));

  /** Runs the built CLI without blocking this process, so the fixture server above can answer it. */
  const sealmark = (args: string[]) =>
    new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const p = spawn(process.execPath, [CLI, ...args], { env: hermeticEnv({}), stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("close", (code) => resolve({ code, out, err }));
    });

  it("a graded server: exit 0, its grade and the config that starts the graded version", async () => {
    const r = await sealmark(["install-check", "@bytebase/dbhub", "--data-url", base]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /Grade: F, the lowest test-area grade/);
    assert.match(r.out, /claude mcp add dbhub -- npx -y "@bytebase\/dbhub@2\.0\.1"/);
  });

  it("--json prints the object", async () => {
    const r = await sealmark(["install-check", "https://sealmark.dev/results/dbhub/", "--json", "--data-url", base]);
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(r.out).servers[0].grade, "F");
  });

  it("not in the public results: exit 3 and says not graded under that name", async () => {
    const r = await sealmark(["install-check", "never-graded-mcp", "--data-url", base]);
    assert.equal(r.code, 3, r.err);
    assert.match(r.out, /is not in sealmark\.dev's public results/);
  });

  it("data that cannot be read: exit 4, a reason, no grade", async () => {
    const r = await sealmark(["install-check", "dbhub", "--data-url", "http://127.0.0.1:9/data/v1"]);
    assert.equal(r.code, 4);
    assert.equal(r.out, "");
    assert.match(r.err, /could not reach http:\/\/127\.0\.0\.1:9\/data\/v1\/lookup\.json .*No grade shown/);
  });

  it("usage errors exit 2: no server, a name that is no key, a bad --data-url, a flag it does not take", async () => {
    for (const args of [["install-check"], ["install-check", "!!!"], ["install-check", "dbhub", "--data-url", "ftp://x"], ["install-check", "dbhub", "--pack", "core"]]) {
      const r = await sealmark([...args, ...(args.includes("--data-url") ? [] : ["--data-url", base])]);
      assert.equal(r.code, 2, `${args.join(" ")}: ${r.err}`);
    }
  });
});
