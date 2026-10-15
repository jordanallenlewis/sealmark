import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, openSync, closeSync, readdirSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync, lstatSync, realpathSync, statSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { after, before, describe, it } from "node:test";
import { McpSession, SessionError, driftHint, resolvePackage } from "../mcp.js";
import { startListener } from "../observers/listener.js";
import { createSandbox, createTempCwd, type Sandbox } from "../sandbox.js";
import { TOY } from "./helpers.js";

const WIN = process.platform === "win32";
const CTX = { vars: {}, dsns: {} };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const same = (a: string, b: string) => (WIN ? a.toLowerCase() === b.toLowerCase() : a === b);

async function until(cond: () => boolean | Promise<boolean>, ms = 10_000, step = 100): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return true;
    await sleep(step);
  }
  return cond();
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};

/** A small MCP server written next to the tests' scratch space; it imports the SDK by absolute URL. */
function writeProbeServer(dir: string): string {
  const sdk = (p: string) => import.meta.resolve(`@modelcontextprotocol/sdk/${p}`);
  const file = join(dir, "probe-server.mjs");
  writeFileSync(
    file,
    `import { Server } from ${JSON.stringify(sdk("server/index.js"))};
import { StdioServerTransport } from ${JSON.stringify(sdk("server/stdio.js"))};
import { CallToolRequestSchema, ListToolsRequestSchema, ListPromptsRequestSchema, ListResourcesRequestSchema } from ${JSON.stringify(sdk("types.js"))};
const mode = process.argv[2] ?? "info";
if (mode === "drift") { console.error("Traceback (most recent call last):\\nModuleNotFoundError: No module named 'sm_missing'"); process.exit(1); }
if (mode === "slow") await new Promise((r) => setTimeout(r, 700));
const caps = { tools: {} };
if (mode === "extras" || mode === "badextras") { caps.prompts = {}; caps.resources = {}; }
const server = new Server({ name: "probe", version: "1.0.0" }, { capabilities: caps });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "info", description: "info", inputSchema: { type: "object", properties: {} } }] }));
server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: JSON.stringify({ cwd: process.cwd(), env: process.env }) }] }));
if (caps.prompts) {
  server.setRequestHandler(ListPromptsRequestSchema, async (req) => {
    if (mode === "badextras") throw new Error("prompts exploded");
    return req.params?.cursor ? { prompts: [{ name: "p2", description: "second" }] } : { prompts: [{ name: "p1", description: "first" }], nextCursor: "c1" };
  });
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [{ uri: "file:///x", name: "x" }] }));
}
process.stdin.once("close", () => process.exit(0));
await server.connect(new StdioServerTransport());
`,
  );
  return file;
}

describe("sandbox layout", () => {
  let sb: Sandbox;
  before(async () => {
    sb = await createSandbox({ slowHoldMs: 300 });
  });
  after(async () => {
    const r = await sb.destroy();
    assert.equal(r.cleanedUp, true, `leftover: ${r.leftover.join(", ")}`);
    assert.equal(existsSync(sb.dir), false);
  });

  it("creates the directories, canary files and control file", () => {
    for (const d of [sb.root, sb.rootEvil, sb.canary, sb.home, sb.tmp, sb.bin]) assert.ok(existsSync(d), d);
    assert.equal(readFileSync(sb.files.canary, "utf8"), sb.tokens.canary);
    assert.equal(readFileSync(sb.files.evil, "utf8"), sb.tokens.evil);
    assert.equal(readFileSync(sb.files.ok, "utf8"), sb.tokens.control);
    assert.match(sb.tokens.canary, /^sm-fscanary-[0-9a-f]{16}$/);
    assert.notEqual(sb.tokens.canary, sb.tokens.evil);
  });

  it("keeps the canary outside the root and the root-evil sibling a string-prefix trap", () => {
    assert.ok(relative(sb.root, sb.canary).startsWith(".."));
    assert.ok(!sb.canary.startsWith(sb.root + sep));
    assert.ok(sb.rootEvil.startsWith(sb.root), "root-evil must start with the root path as a plain string prefix");
    assert.ok(relative(sb.root, sb.rootEvil).startsWith(".."), "but must not be inside it");
    // Nothing a server can reach by walking the root without following links contains a canary token.
    const stack = [sb.root];
    while (stack.length) {
      const d = stack.pop()!;
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        const st = lstatSync(p);
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) stack.push(p);
        else {
          const text = readFileSync(p, "utf8");
          assert.ok(!text.includes(sb.tokens.canary) && !text.includes(sb.tokens.evil), p);
        }
      }
    }
  });

  it("creates the directory link (junction on Windows) and reports the file symlink honestly", () => {
    assert.equal(sb.links.dir.ok, true, sb.links.dir.reason ?? "");
    assert.equal(sb.links.dir.kind, WIN ? "junction" : "symlink");
    assert.equal(readFileSync(join(sb.files.linkDir, "secret.txt"), "utf8"), sb.tokens.canary);
    if (sb.links.file.ok) assert.equal(readFileSync(sb.files.linkFile, "utf8"), sb.tokens.canary);
    else {
      assert.equal(sb.links.file.kind, "na");
      assert.match(sb.links.file.reason ?? "", /Developer Mode|elevated|EPERM|operation not permitted/i);
    }
  });

  it("writes cross-platform bin programs that do what the exec pack needs", () => {
    const run = (name: "sm-canary" | "sm-echo", args: string[]) => spawnSync(sb.bins[name].program, [...sb.bins[name].args, ...args], { cwd: sb.tmp, encoding: "utf8", windowsHide: true });
    const e = run("sm-echo", ["a;", "b&&c"]);
    assert.equal(e.status, 0);
    const argvFile = readdirSync(sb.root).find((n) => n.startsWith("argv-"))!;
    const rec = JSON.parse(readFileSync(join(sb.root, argvFile), "utf8")) as { argv: string[]; cwd: string };
    assert.deepEqual(rec.argv, ["a;", "b&&c"]);
    assert.ok(same(realpathSync.native(rec.cwd), realpathSync.native(sb.tmp)));
    const c = run("sm-canary", ["x"]);
    assert.equal(c.status, 0);
    const executed = readdirSync(sb.canary).filter((n) => n.startsWith("executed-"));
    assert.equal(executed.length, 1);
    rmSync(join(sb.canary, executed[0]!));
    rmSync(join(sb.root, argvFile));
    // A shell that resolves the bare name through PATH finds the launcher (this is how injected commands get found).
    const viaShell = spawnSync(WIN ? "sm-canary x & echo done" : "sm-canary x; echo done", { shell: true, env: sb.env(), cwd: sb.tmp, encoding: "utf8", windowsHide: true });
    assert.match(viaShell.stdout, /sm-canary ran/);
    assert.equal(readdirSync(sb.canary).filter((n) => n.startsWith("executed-")).length, 1);
    rmSync(join(sb.canary, readdirSync(sb.canary).find((n) => n.startsWith("executed-"))!));
    const spew = spawnSync(sb.bins["sm-spew"].program, [...sb.bins["sm-spew"].args, "2"], { maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    assert.equal(spew.stdout.length, 2 * 1024 * 1024);
    const slept = Date.now();
    spawnSync(sb.bins["sm-sleep"].program, [...sb.bins["sm-sleep"].args, "0.2"], { windowsHide: true });
    assert.ok(Date.now() - slept >= 150);
  });

  it("the run directory, the home and the tmp are private to the owner on POSIX", { skip: process.platform === "win32" }, () => {
    for (const d of [sb.dir, sb.home, sb.tmp]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
  });

  it("creates a sandbox directory that does not exist yet", async () => {
    const base = mkdtempSync(join(tmpdir(), "sm-test-nested-"));
    try {
      const nested = await createSandbox({ dir: join(base, "nested", "deeper") });
      assert.ok(existsSync(nested.root));
      assert.equal((await nested.destroy()).cleanedUp, true);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });

  it("creates the large file lazily", async () => {
    assert.equal(existsSync(sb.files.big), false);
    const p = await sb.bigFile(2);
    assert.equal(lstatSync(p).size, 2 * 1024 * 1024);
    rmSync(p);
  });
});

describe("environment", () => {
  let sb: Sandbox;
  let dir: string;
  let script: string;
  before(async () => {
    sb = await createSandbox();
    dir = mkdtempSync(join(tmpdir(), "sm-test-env-"));
    script = writeProbeServer(dir);
  });
  after(async () => {
    await sb.destroy();
    rmSync(dir, { recursive: true, force: true });
  });

  const ALLOWED = new Set(
    [
      "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "HOME",
      ...(WIN
        ? ["USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "USERNAME", "USERDOMAIN", "LOGONSERVER", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "PROGRAMFILES", "PROCESSOR_ARCHITECTURE"]
        : ["USER", "LOGNAME", "SHELL", "TERM"]),
      "SM_EXTRA", "SEALMARK_CANARY", "NPM_CONFIG_CACHE", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR",
      // macOS adds this to every process it starts (CoreFoundation); it is not passed by Sealmark and holds no user data.
      ...(process.platform === "darwin" ? ["__CF_USER_TEXT_ENCODING"] : []),
    ].map((k) => k.toUpperCase()),
  );

  it("builder output has only allowlisted names, sandbox paths first, and no real secret", () => {
    process.env.SM_TEST_SECRET_KEY = "real-secret-value";
    try {
      const e = sb.env({ SM_EXTRA: "1" });
      for (const k of Object.keys(e)) assert.ok(ALLOWED.has(k.toUpperCase()), `unexpected env name ${k}`);
      assert.ok(e.PATH!.startsWith(sb.bin));
      assert.equal(e.HOME, sb.home);
      assert.equal(e.TEMP, sb.tmp);
      assert.equal(e.TMPDIR, sb.tmp);
      assert.equal(e.SM_EXTRA, "1");
      assert.ok(!Object.values(e).includes("real-secret-value"));
      if (WIN) {
        assert.equal(e.USERPROFILE, sb.home);
        assert.equal(e.APPDATA, sb.home);
        assert.equal(e.LOCALAPPDATA, sb.home);
        const upper = Object.keys(e).map((k) => k.toUpperCase());
        assert.equal(new Set(upper).size, upper.length, "no case-duplicate names");
      }
    } finally {
      delete process.env.SM_TEST_SECRET_KEY;
    }
  });

  it("keep_env copies only the named variables", () => {
    process.env.SM_TEST_KEEP_ME = "kept";
    try {
      assert.equal(sb.env({}, { keepEnv: ["SM_TEST_KEEP_ME"] }).SM_TEST_KEEP_ME, "kept");
      assert.equal(sb.env({}).SM_TEST_KEEP_ME, undefined);
    } finally {
      delete process.env.SM_TEST_KEEP_ME;
    }
  });

  it("the server process sees only the allowlist (checked inside the child), starts in the sandbox root", async () => {
    process.env.SM_TEST_SECRET_KEY = "real-secret-value";
    process.env.OPENAI_API_KEY = "sk-not-for-the-server";
    const real = { user: process.env.USERNAME, home: process.env.HOME, userprofile: process.env.USERPROFILE };
    try {
      const s = await McpSession.open({ command: process.execPath, args: [script, "info"] }, CTX, { cwd: sb.root, baseEnv: sb.env({ SM_EXTRA: "1" }), envMode: "scrubbed" });
      try {
        const r = await s.call("info", {});
        assert.equal(r.isError, false, r.rpcError ?? "");
        const seen = JSON.parse(r.text) as { cwd: string; env: Record<string, string> };
        assert.ok(same(realpathSync.native(seen.cwd), realpathSync.native(sb.root)), `cwd ${seen.cwd}`);
        for (const k of Object.keys(seen.env)) assert.ok(ALLOWED.has(k.toUpperCase()), `child saw unexpected env name ${k}`);
        assert.ok(!JSON.stringify(seen.env).includes("real-secret-value"));
        assert.ok(!JSON.stringify(seen.env).includes("sk-not-for-the-server"));
        const get = (k: string) => Object.entries(seen.env).find(([n]) => n.toUpperCase() === k)?.[1];
        assert.equal(get("HOME"), sb.home);
        assert.equal(get("TEMP"), sb.tmp);
        assert.ok(get("PATH")!.startsWith(sb.bin));
        assert.equal(get("SM_EXTRA"), "1");
        if (WIN) {
          assert.equal(get("USERPROFILE"), sb.home);
          assert.equal(get("USERNAME"), "sealmark");
          if (real.user) assert.notEqual(get("USERNAME"), real.user);
          assert.ok(get("SYSTEMROOT"), "SystemRoot must be present or most Windows programs fail");
        }
      } finally {
        await s.close();
      }
    } finally {
      delete process.env.SM_TEST_SECRET_KEY;
      delete process.env.OPENAI_API_KEY;
    }
  });

  it('envMode "inherit" passes the real environment; "scrubbed" without baseEnv is refused', async () => {
    process.env.SM_TEST_SECRET_KEY = "real-secret-value";
    try {
      const s = await McpSession.open({ command: process.execPath, args: [script, "info"] }, CTX, { envMode: "inherit" });
      try {
        const seen = JSON.parse((await s.call("info", {})).text) as { env: Record<string, string> };
        assert.equal(seen.env.SM_TEST_SECRET_KEY, "real-secret-value");
      } finally {
        await s.close();
      }
      await assert.rejects(McpSession.open({ command: process.execPath, args: [script, "info"] }, CTX, { envMode: "scrubbed" }), /needs baseEnv/);
    } finally {
      delete process.env.SM_TEST_SECRET_KEY;
    }
  });
});

describe("fs observer", () => {
  let sb: Sandbox;
  before(async () => {
    sb = await createSandbox();
  });
  after(async () => {
    await sb.destroy();
  });

  it("detects add, change and remove, and does not call a touch a change", async () => {
    writeFileSync(join(sb.home, "gone.txt"), "bye");
    writeFileSync(join(sb.tmp, "touch.txt"), "same");
    const before = await sb.fs.snapshot();
    writeFileSync(join(sb.root, "new.txt"), "hello");
    writeFileSync(sb.files.ok, "changed");
    rmSync(join(sb.home, "gone.txt"));
    const when = new Date(Date.now() + 60_000);
    utimesSync(join(sb.tmp, "touch.txt"), when, when);
    const d = await sb.fs.diffSince(before);
    assert.deepEqual(d.added, ["root/new.txt"]);
    assert.deepEqual(d.changed, ["root/ok.txt"]);
    assert.deepEqual(d.removed, ["home/gone.txt"]);
    assert.deepEqual(d.touched, ["tmp/touch.txt"]);
    assert.equal(d.any, true);
    const none = await sb.fs.diffSince(await sb.fs.snapshot());
    assert.equal(none.any, false);
  });

  it("records a link without walking it, and sees a write that went through it", async () => {
    const before = await sb.fs.snapshot();
    assert.equal(before["root/link-dir"]?.kind, "link");
    assert.ok(!Object.keys(before).some((k) => k.startsWith("root/link-dir/")), "must not walk into the junction");
    writeFileSync(join(sb.files.linkDir, "lw-test.txt"), "escaped");
    const d = await sb.fs.diffSince(before);
    assert.deepEqual(d.added, ["canary/lw-test.txt"]);
    assert.equal(sb.fs.resolve("canary/lw-test.txt"), join(sb.canary, "lw-test.txt"));
  });

  it("hashes small files and compares big ones by size and mtime", async () => {
    const big = await sb.bigFile(9);
    const before = await sb.fs.snapshot(["root"]);
    assert.equal(before["root/big.bin"]?.hash, undefined);
    assert.ok(before["root/ok.txt"]?.hash);
    writeFileSync(big, "x", { flag: "r+" });
    const d = await sb.fs.diffSince(before, ["root"]);
    assert.ok(d.changed.includes("root/big.bin"));
  });
});

describe("listener", () => {
  it("serves the routes and records tokens, connections and raw TCP", async () => {
    const l = await startListener({ slowHoldMs: 300, bigBytes: 4 * 1024 * 1024 });
    try {
      assert.ok(l.port > 0);
      const t = await fetch(`${l.url}/t/tok1`);
      assert.equal(await t.text(), "sm-listener-tok1");
      assert.equal(l.hitsFor("tok1").length, 1);
      assert.equal(l.hitsFor("tok1")[0]!.family, "IPv4");
      assert.equal(l.hitsFor("tok1")[0]!.route, "t");
      assert.equal(l.hitsFor("nope").length, 0);
      assert.equal(l.hitsFor("").length, 0);

      const r = await fetch(`${l.url}/redir/tok2`, { redirect: "manual" });
      assert.equal(r.status, 302);
      assert.equal(r.headers.get("location"), "/t/tok2");
      await fetch(`${l.url}/t/tok2`);
      assert.deepEqual(l.hitsFor("tok2").map((h) => h.route), ["redir", "t"]);

      if (l.port6 !== undefined) {
        const v6 = await fetch(`${l.url6}/t/tok6`);
        assert.equal(v6.status, 200);
        assert.equal(l.hitsFor("tok6")[0]!.family, "IPv6");
      }

      const sock = net.connect(l.port, "127.0.0.1");
      await new Promise<void>((res) => sock.once("connect", () => res()));
      sock.write("USER anonymous\r\n");
      assert.ok(await until(() => l.rawConnections().some((c) => c.firstBytes.startsWith("USER anonymous")), 3000, 25), "first bytes of a raw TCP client are recorded");
      sock.destroy();
      assert.equal(l.rawConnections().length, 1);
      assert.ok(l.connections().length >= 4, "every connection is recorded, HTTP or not");

      const big = await fetch(`${l.url}/big`);
      assert.equal((await big.arrayBuffer()).byteLength, 4 * 1024 * 1024);

      const t0 = Date.now();
      assert.equal((await fetch(`${l.url}/slow`)).status, 200);
      assert.ok(Date.now() - t0 >= 250, "slow holds the response");

      const waited = l.waitForHit("late", 1000);
      setTimeout(() => void fetch(`${l.url}/t/late`).catch(() => {}), 100);
      assert.equal((await waited).length, 1);

      l.reset();
      assert.equal(l.requests().length + l.connections().length, 0);
    } finally {
      await l.close();
    }
  });

  it("close() returns promptly even with a held /slow request", async () => {
    const l = await startListener({ slowHoldMs: 60_000 });
    const pending = fetch(`${l.url}/slow`).then(
      () => "answered",
      () => "dropped",
    );
    assert.ok(await until(() => l.requests().length === 1, 3000, 25));
    const t0 = Date.now();
    await l.close();
    assert.ok(Date.now() - t0 < 3000);
    assert.equal(await pending, "dropped");
  });
});

describe("process observer and cleanup", () => {
  it("destroy() kills lingering bin children (direct and through the launcher) and removes the directory", async () => {
    const sb = await createSandbox();
    const kids: ChildProcess[] = [];
    // cwd outside the sandbox so the directory itself is not held open by the child.
    kids.push(spawn(sb.bins["sm-sleep"].program, [...sb.bins["sm-sleep"].args, "60"], { cwd: tmpdir(), stdio: "ignore", windowsHide: true }));
    const opts = { cwd: tmpdir(), stdio: "ignore", windowsHide: true } as const;
    kids.push(WIN ? spawn(`"${sb.bins["sm-sleep"].launcher}" 60`, { ...opts, shell: true }) : spawn(sb.bins["sm-sleep"].launcher, ["60"], opts));
    for (const k of kids) k.on("error", () => {});
    const pids = kids.map((k) => k.pid!);
    assert.ok(pids.every((p) => p > 0));
    await sleep(800);
    assert.ok(pids.every(alive));
    const strays = await sb.proc.strays();
    assert.ok(strays.some((p) => p.pid === pids[0]), "the direct child is recognised as belonging to the sandbox");
    assert.ok(!strays.some((p) => p.pid === process.pid), "the harness itself is never a stray");
    const r = await sb.destroy();
    assert.equal(r.cleanedUp, true, `leftover: ${r.leftover.join(", ")}`);
    assert.equal(existsSync(sb.dir), false);
    assert.ok(await until(() => pids.every((p) => !alive(p)), 5000), "children must be gone");
    assert.equal(sb.proc.isAlive(pids[0]!), false);
  });

  it("destroy() never follows a link out of the sandbox, and is idempotent", async () => {
    const outside = mkdtempSync(join(tmpdir(), "sm-test-outside-"));
    writeFileSync(join(outside, "keep.txt"), "must survive");
    const sb = await createSandbox();
    try {
      symlinkSync(outside, join(sb.root, "evil-link"), WIN ? "junction" : "dir");
      const r = await sb.destroy();
      assert.equal(r.cleanedUp, true, `leftover: ${r.leftover.join(", ")}`);
      assert.equal(readFileSync(join(outside, "keep.txt"), "utf8"), "must survive");
      assert.equal((await sb.destroy()).cleanedUp, true);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("destroy({ keep: true }) stops everything but leaves the directory", async () => {
    const sb = await createSandbox();
    const r = await sb.destroy({ keep: true });
    assert.equal(r.kept, true);
    assert.ok(existsSync(sb.dir));
    rmSync(sb.dir, { recursive: true, force: true });
  });

  it("reports cleanedUp:false for a locked file, then succeeds once it is released", { skip: WIN ? false : "file locks that block delete are a Windows behaviour" }, async () => {
    const sb = await createSandbox({ destroyRetries: 2, destroyRetryDelayMs: 150 });
    const locked = join(sb.tmp, "locked.bin");
    writeFileSync(locked, "x");
    // The path travels in the environment, not on the command line, so the process is not matched as a sandbox stray.
    const ps = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$f=[IO.File]::Open($env:SM_LOCK,'Open','ReadWrite','None'); Start-Sleep 120"], { cwd: tmpdir(), env: { ...process.env, SM_LOCK: locked }, stdio: "ignore", windowsHide: true });
    try {
      const isLocked = () => {
        try {
          closeSync(openSync(locked, "r+"));
          return false;
        } catch {
          return true;
        }
      };
      assert.ok(await until(isLocked, 20_000, 200), "PowerShell never took the lock");
      const first = await sb.destroy();
      assert.equal(first.cleanedUp, false);
      assert.ok(first.leftover.includes(sb.dir), "the leftover list names the sandbox path");
      assert.equal(first.path, sb.dir);
      assert.ok(existsSync(locked));
      spawnSync("taskkill", ["/PID", String(ps.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      assert.ok(await until(() => !isLocked(), 10_000, 200));
      const second = await sb.destroy();
      assert.equal(second.cleanedUp, true, `leftover: ${second.leftover.join(", ")}`);
      assert.equal(existsSync(sb.dir), false);
    } finally {
      spawnSync("taskkill", ["/PID", String(ps.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      rmSync(sb.dir, { recursive: true, force: true });
    }
  });

  it("aborts sizeExceeded when the sandbox grows past the cap", async () => {
    const sb = await createSandbox({ maxBytes: 1 << 20, pollMs: 100 });
    try {
      assert.equal(sb.sizeExceeded.aborted, false);
      const aborted = new Promise<boolean>((res) => {
        sb.sizeExceeded.addEventListener("abort", () => res(true), { once: true });
        setTimeout(() => res(false), 8000).unref();
      });
      writeFileSync(join(sb.tmp, "fill.bin"), Buffer.alloc(2 << 20, 1));
      assert.equal(await aborted, true);
      assert.match(String((sb.sizeExceeded.reason as Error).message), /grew past/);
      assert.ok((await sb.sizeBytes()) > 1 << 20);
    } finally {
      await sb.destroy();
    }
  });
});

describe("mcp session options", () => {
  let dir: string;
  let script: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sm-test-mcp-"));
    script = writeProbeServer(dir);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("surfaces a dependency-drift hint and the full stderr on SessionError", async () => {
    await assert.rejects(
      McpSession.open({ command: process.execPath, args: [script, "drift"] }, CTX, { connectTimeoutMs: 10_000 }),
      (e: unknown) => {
        assert.ok(e instanceof SessionError);
        assert.match((e as SessionError).hint ?? "", /dependencies may have drifted/);
        assert.match((e as SessionError).stderr ?? "", /ModuleNotFoundError: No module named 'sm_missing'/);
        return true;
      },
    );
    assert.equal(driftHint("ImportError: x"), "the server's dependencies may have drifted; pin them (uvx --with 'pkg<N', npx pkg@x.y.z)");
    assert.equal(driftHint("Error: ordinary failure"), undefined);
    assert.ok(driftHint("Error [ERR_MODULE_NOT_FOUND]: Cannot find package"));
  });

  it("reports startup progress while a slow server starts", async () => {
    const msgs: string[] = [];
    const s = await McpSession.open({ command: process.execPath, args: [script, "slow"] }, CTX, { onProgress: (m) => msgs.push(m), progressEveryMs: 200, connectTimeoutMs: 20_000 });
    await s.close();
    assert.ok(msgs.length >= 1, "at least one progress line");
    assert.match(msgs[0]!, /^still starting the server \(\d+s\)…$/);
  });

  it("exposes the pid, lists prompts and resources when advertised, and notes list failures", async () => {
    const s = await McpSession.open({ command: process.execPath, args: [script, "extras"] }, CTX, {});
    try {
      assert.ok(s.pid && s.pid > 0);
      assert.deepEqual(s.prompts.map((p) => p.name), ["p1", "p2"], "pagination is followed");
      assert.deepEqual(s.resources.map((r) => r.uri), ["file:///x"]);
      assert.deepEqual(s.listErrors, []);
    } finally {
      await s.close();
    }
    const bad = await McpSession.open({ command: process.execPath, args: [script, "badextras"] }, CTX, {});
    try {
      assert.equal(bad.prompts.length, 0);
      assert.match(bad.listErrors[0] ?? "", /prompts\/list failed: .*prompts exploded/);
    } finally {
      await bad.close();
    }
    const plain = await McpSession.open({ command: process.execPath, args: [script, "info"] }, CTX, {});
    try {
      assert.deepEqual([plain.prompts, plain.resources, plain.listErrors], [[], [], []]);
    } finally {
      await plain.close();
    }
  });

  it("cleanCwd starts the server in a fresh temp directory that is removed on close", async () => {
    const s = await McpSession.open({ command: process.execPath, args: [script, "info"] }, CTX, { cleanCwd: true });
    let cwd = "";
    try {
      cwd = (JSON.parse((await s.call("info", {})).text) as { cwd: string }).cwd;
      assert.match(cwd, /sealmark-cwd-/);
      assert.ok(existsSync(cwd));
    } finally {
      await s.close();
    }
    assert.ok(await until(() => !existsSync(cwd), 5000), "temp cwd removed");
    const t = await createTempCwd();
    assert.ok(existsSync(t.dir));
    await t.remove();
    assert.equal(existsSync(t.dir), false);
  });

  it("still starts the toy server the original way (no new options)", async () => {
    const s = await McpSession.open({ command: process.execPath, args: [TOY, "--mode", "nosql"] }, CTX, {});
    try {
      assert.deepEqual(s.tools.map((t) => t.name), ["echo", "add"]);
      assert.equal(s.serverInfo.name, "sealmark-toy-nosql");
    } finally {
      await s.close();
    }
  });
});

describe("resolvePackage (file reads only)", () => {
  let root: string;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sm-test-resolve-"));
    const put = (p: string, text: string, when?: number) => {
      mkdirSync(join(p, ".."), { recursive: true });
      writeFileSync(p, text);
      if (when) utimesSync(p, new Date(when), new Date(when));
    };
    const npx = join(root, "npx", "_npx");
    put(join(npx, "aaa", "node_modules", "@acme", "server-x", "package.json"), JSON.stringify({ name: "@acme/server-x", version: "1.0.0" }), Date.now() - 86_400_000);
    put(join(npx, "bbb", "node_modules", "@acme", "server-x", "package.json"), JSON.stringify({ name: "@acme/server-x", version: "1.2.3", dependencies: { dep: "^1.0.0", missing: "^2" } }), Date.now());
    put(join(npx, "bbb", "node_modules", "dep", "package.json"), JSON.stringify({ name: "dep", version: "1.4.0" }));
    const uv = join(root, "uv", "environments-v2");
    const site = WIN ? join(uv, "mcp-server-x-0a1b2c", "Lib", "site-packages") : join(uv, "mcp-server-x-0a1b2c", "lib", "python3.13", "site-packages");
    put(join(site, "mcp_server_x-0.3.2.dist-info", "METADATA"), "Metadata-Version: 2.1\nName: mcp-server-x\nVersion: 0.3.2\nRequires-Dist: httpx>=0.27\nRequires-Dist: pydantic<3\n");
    put(join(site, "httpx-0.27.1.dist-info", "METADATA"), "Name: httpx\nVersion: 0.27.1\n");
  });
  after(() => rmSync(root, { recursive: true, force: true }));
  const roots = () => ({ npx: [join(root, "npx", "_npx")], uv: [join(root, "uv", "environments-v2")] });

  it("npx: several cached versions and no exact pin are ambiguous (the newest entry is not claimed to have run); a pick reads its dependency versions", () => {
    const r = resolvePackage("npx", ["-y", "@acme/server-x@latest", "/some/dir"], { roots: roots() });
    assert.equal(r?.source, "npx-cache (ambiguous)");
    assert.equal(r?.name, "@acme/server-x");
    assert.equal(r?.version, undefined);
    assert.deepEqual(r?.candidates, ["1.0.0", "1.2.3"]);
    assert.equal(r?.dependencies, undefined);
    const picked = resolvePackage("npx", ["-y", "@acme/server-x@latest", "/some/dir"], { roots: roots(), pick: "1.2.3" });
    assert.equal(picked?.source, "npx-cache");
    assert.equal(picked?.version, "1.2.3");
    assert.deepEqual(picked?.dependencies, { dep: "1.4.0" });
    assert.equal(resolvePackage("npx.cmd", ["--yes", "@acme/server-x@1.0.0"], { roots: roots() })?.version, "1.0.0", "an exact version in the spec wins");
    assert.equal(resolvePackage("cmd", ["/c", "npx", "-y", "@acme/server-x"], { roots: roots() })?.source, "npx-cache (ambiguous)");
  });

  it("uvx: reads Version, Requires-Dist and every dist-info", () => {
    const r = resolvePackage("uvx", ["--python", "3.13", "mcp-server-x", "--flag"], { roots: roots() });
    assert.equal(r?.source, "uv-cache");
    assert.equal(r?.version, "0.3.2");
    assert.deepEqual(r?.dependencies, { mcp_server_x: "0.3.2", httpx: "0.27.1" });
    assert.deepEqual(r?.requires, ["httpx>=0.27", "pydantic<3"]);
    assert.equal(resolvePackage("uvx", ["--from", "mcp-server-x==0.3.2", "mcp-server-x"], { roots: roots() })?.version, "0.3.2");
  });

  it("reports not found, and undefined for commands that are not launchers", () => {
    assert.deepEqual(resolvePackage("npx", ["-y", "no-such-pkg"], { roots: roots() }), { name: "no-such-pkg", source: "not found" });
    assert.deepEqual(resolvePackage("uvx", ["no-such-pkg"], { roots: roots() }), { name: "no-such-pkg", source: "not found" });
    assert.equal(resolvePackage("node", ["server.js"], { roots: roots() }), undefined);
    assert.equal(resolvePackage("npx", ["-y"], { roots: roots() }), undefined);
    assert.deepEqual(resolvePackage("npx", ["-y", "x"], { roots: { npx: [join(root, "nowhere")] } }), { name: "x", source: "not found" });
  });
});


