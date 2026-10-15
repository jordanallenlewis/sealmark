import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig, type EffectiveConfig } from "../config/index.js";
import { DOCTOR_DUMMY_DSN, diagnoseStartup, findOnPath, renderDoctor, runDoctor, type DoctorReport } from "../doctor.js";
import { TOY } from "./helpers.js";

const DIST_TOY = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));

let root: string;
let counter = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-doctor-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

/** A config in its own directory; a sandbox parent inside the test root lets the tests check that nothing is left behind. */
function config(server: { command: string; args?: string[]; env?: Record<string, string> } | { url: string }, extra = ""): { cfg: EffectiveConfig; sandboxParent: string } {
  const dir = join(root, `c${++counter}`);
  const sandboxParent = join(dir, "sb");
  mkdirSync(sandboxParent, { recursive: true });
  const body = "command" in server ? `  command: ${JSON.stringify(server.command)}\n  args: ${JSON.stringify(server.args ?? [])}\n  env: ${JSON.stringify(server.env ?? {})}\n` : `  url: ${JSON.stringify(server.url)}\n`;
  writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: doc-test\nserver:\n${body}sandbox:\n  dir: ${JSON.stringify(sandboxParent)}\n${extra}`);
  return { cfg: loadEffectiveConfig({ cwd: dir, env: {}, isolated: true }), sandboxParent };
}
const node = (...args: string[]) => ({ command: process.execPath, args });
const run = (cfg: EffectiveConfig, extra: object = {}) => runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false, ...extra });
const item = (r: DoctorReport, id: string) => [...r.environment, ...r.servers.flatMap((s) => s.items)].find((i) => i.id === id);
const pack = (r: DoctorReport, id: string) => r.servers[0].packs.find((p) => p.pack === id)!;

describe("findOnPath", () => {
  const exists = (...present: string[]) => (p: string) => present.includes(p);
  it("finds npx.cmd for npx on Windows through PATHEXT, in PATH order", () => {
    const path = "C:\\bin;C:\\Program Files\\nodejs";
    assert.equal(findOnPath("npx", path, { platform: "win32", pathext: ".COM;.EXE;.CMD", exists: exists("C:\\Program Files\\nodejs\\npx.CMD") }), "C:\\Program Files\\nodejs\\npx.CMD");
    assert.equal(findOnPath("npx", path, { platform: "win32", pathext: ".EXE;.CMD", exists: exists("C:\\bin\\npx.EXE", "C:\\Program Files\\nodejs\\npx.CMD") }), "C:\\bin\\npx.EXE", "first directory wins");
    assert.equal(findOnPath("node.exe", path, { platform: "win32", pathext: ".EXE;.CMD", exists: exists("C:\\bin\\node.exe") }), "C:\\bin\\node.exe", "a name that already has an extension is not suffixed again");
    assert.equal(findOnPath("nope", path, { platform: "win32", pathext: ".EXE", exists: exists() }), undefined);
  });
  it("accepts quoted PATH entries and ignores empty ones", () => {
    assert.equal(findOnPath("git", ';"C:\\Git\\cmd";', { platform: "win32", pathext: ".EXE", exists: exists("C:\\Git\\cmd\\git.EXE") }), "C:\\Git\\cmd\\git.EXE");
  });
  it("checks a path with a separator as given, on its own", () => {
    assert.equal(findOnPath("C:\\tools\\srv", "C:\\other", { platform: "win32", pathext: ".EXE", exists: exists("C:\\tools\\srv.EXE") }), "C:\\tools\\srv.EXE");
    assert.equal(findOnPath("C:\\tools\\srv", "C:\\tools", { platform: "win32", pathext: ".EXE", exists: exists("C:\\other\\srv.EXE") }), undefined);
    assert.equal(findOnPath("/opt/srv/run", "/bin", { platform: "linux", exists: exists("/opt/srv/run") }), "/opt/srv/run");
  });
  it("uses ':' and no extensions on POSIX", () => {
    assert.equal(findOnPath("uvx", "/usr/local/bin:/usr/bin", { platform: "linux", exists: exists("/usr/bin/uvx") }), "/usr/bin/uvx");
    assert.equal(findOnPath("uvx", "/usr/bin", { platform: "linux", exists: exists("/usr/bin/uvx.exe") }), undefined);
  });
  it("finds this node on the real PATH", () => {
    const hit = findOnPath("node", process.env.PATH ?? process.env.Path ?? "");
    assert.ok(hit && existsSync(hit), `node not found on PATH: ${hit}`);
  });
});

describe("diagnoseStartup", () => {
  const d = (error: string, stderr = "") => diagnoseStartup(error, stderr, { command: "srv", timeoutMs: 10_000 }).join("\n");
  it("recognises dependency drift", () => assert.match(d("closed", "ModuleNotFoundError: No module named 'x'"), /dependencies may have drifted; pin them/));
  it("recognises a command that is missing", () => assert.match(d("spawn srv ENOENT"), /launcher "srv" or a file it needs was not found.*short PATH/));
  it("recognises a start-up timeout and names the limit", () => assert.match(d("Request timed out"), /did not answer within 10 s.*--connect-timeout/));
  it("recognises a missing setting", () => assert.match(d("closed", "Error: API_KEY is required"), /put it under server\.env/));
  it("recognises a busy port", () => assert.match(d("closed", "listen EADDRINUSE :::3000"), /port .* already in use/));
  it("says nothing it does not know", () => assert.equal(d("some other failure"), ""));
});

describe("runDoctor", { timeout: 120_000 }, () => {
  it("a healthy server: every step ok, tools listed, classification and a reason for every pack", async () => {
    const { cfg, sandboxParent } = config(node(TOY, "--mode", "nosql"));
    const r = await run(cfg);
    assert.equal(r.ok, true, renderDoctor(r));
    assert.equal(r.exitCode, 0);
    for (const id of ["node", "sandbox", "link-dir", "listener"]) assert.ok(["ok", "warn"].includes(item(r, id)!.status), id);
    assert.equal(item(r, "listener")!.status, "ok");
    const s = r.servers[0];
    assert.equal(s.name, "doc-test");
    assert.equal(s.transport, "stdio");
    assert.equal(item(r, "command")!.status, "ok");
    assert.equal(item(r, "start")!.status, "ok");
    assert.ok(s.startup!.tools > 0);
    assert.deepEqual(s.startup!.capabilities, ["tools"]);
    assert.ok(s.classification!.length === s.startup!.tools);
    assert.match(s.classificationText![0], /^Classification:/);
    // The three candidate packs of round 6 are always listed (their position depends on RUN_ORDER, so they are checked apart).
    const listed = s.packs.map((p) => p.pack as string);
    assert.deepEqual(listed.filter((p) => !["scope", "sql-guard", "upstream"].includes(p)), ["core", "db", "http", "fs", "git", "net", "sqlite", "exec", "effects", "custom"]);
    for (const p of ["scope", "sql-guard", "upstream"]) assert.ok(listed.includes(p), `${p} is listed`);
    assert.equal(pack(r, "core").applies, true);
    assert.match(pack(r, "db").reason, /no \{dsn\}.*placeholder/);
    assert.equal(pack(r, "db").applies, false);
    assert.match(pack(r, "http").reason, /needs server\.url/);
    assert.match(pack(r, "exec").reason, /only with --active/);
    assert.equal(pack(r, "exec").requested, false, "exec is opt-in");
    assert.match(pack(r, "custom").reason, /no probes/);
    assert.deepEqual(readdirSync(sandboxParent), [], "the sandbox is deleted");
    const text = renderDoctor(r);
    assert.match(text, /^sealmark doctor/);
    assert.match(text, /Server "doc-test" \(stdio\)/);
    assert.match(text, /^Packs$/m);
    assert.match(text, /No problems found/);
  });

  it("starts a database server with a dummy loopback DSN and counts its SQL tools", async () => {
    const { cfg } = config(node(TOY, "--mode", "good", "--dsn", "{dsn}"));
    const r = await run(cfg);
    assert.equal(r.ok, true, renderDoctor(r));
    assert.equal(item(r, "placeholders")!.status, "info");
    assert.match(item(r, "placeholders")!.detail!, /127\.0\.0\.1:1/);
    assert.equal(DOCTOR_DUMMY_DSN, "postgres://sm_admin:unused@127.0.0.1:1/sealmark_seed");
    assert.equal(pack(r, "db").applies, true);
    assert.match(pack(r, "db").reason, /1 SQL tool\(s\) and a database placeholder/);
  });

  it("reports a command that does not exist, exits 4, and starts nothing", async () => {
    const { cfg } = config({ command: "sealmark-no-such-command-xyz" });
    const r = await run(cfg);
    assert.equal(r.ok, false);
    assert.equal(r.exitCode, 4);
    assert.equal(item(r, "command")!.status, "fail");
    assert.match(item(r, "command")!.title, /"sealmark-no-such-command-xyz" was not found/);
    assert.equal(item(r, "start")!.status, "info");
    assert.equal(r.servers[0].packs.find((p) => p.pack === "core")!.applies, false);
    assert.match(renderDoctor(r), /FAIL {2}command "sealmark-no-such-command-xyz" was not found/);
  });

  it("shows the server's stderr and the drift hint when it dies on a missing module", async () => {
    const { cfg } = config(node("-e", "console.error('ModuleNotFoundError: No module named demo_dep'); process.exit(1)"));
    const r = await run(cfg);
    assert.equal(r.exitCode, 4);
    const start = item(r, "start")!;
    assert.equal(start.status, "fail");
    assert.match(r.servers[0].stderr, /ModuleNotFoundError: No module named demo_dep/);
    assert.ok(r.servers[0].items.some((i) => i.id === "advice" && /dependencies may have drifted/.test(i.title)));
    assert.match(renderDoctor(r), /\| ModuleNotFoundError: No module named demo_dep/);
  });

  it("gives up on a server that never answers, within the limit, and leaves no process or directory behind", async () => {
    const { cfg, sandboxParent } = config(node("-e", "setInterval(() => {}, 1000)"));
    const t0 = Date.now();
    const r = await run(cfg, { startupTimeoutMs: 1500 });
    assert.ok(Date.now() - t0 < 15_000, "doctor must not hang on a silent server");
    assert.equal(r.exitCode, 4);
    assert.ok(r.servers[0].items.some((i) => i.id === "advice" && /did not answer within 2 s/.test(i.title)));
    assert.deepEqual(readdirSync(sandboxParent), []);
  });

  it("explains a start-up that needs a variable the scrubbed environment does not carry", async () => {
    const script = "if (!process.env.NEEDED_SETTING) { console.error('Error: NEEDED_SETTING is required'); process.exit(2); }";
    const { cfg } = config(node("-e", script));
    const r = await run(cfg);
    assert.equal(r.exitCode, 4);
    assert.ok(r.servers[0].items.some((i) => i.id === "advice" && /server\.env/.test(i.title)));
  });

  it("classifies a file server's tools as path tools and says which packs would be considered", async () => {
    const { cfg } = config({ command: process.execPath, args: [DIST_TOY("fs"), "--mode", "good", "--root", "{sandbox}"] });
    const r = await run(cfg);
    assert.equal(r.ok, true, renderDoctor(r));
    const rows = r.servers[0].classification!;
    assert.ok(rows.some((c) => c.class === "path" && c.confidence !== "low"), `no path tool in ${JSON.stringify(rows.map((c) => [c.tool, c.class, c.confidence]))}`);
    assert.ok(r.servers[0].classificationText!.some((l) => /packs applied: core, .*fs/.test(l)), "core is listed first, as the run's line has it");
  });

  it("tells a URL server's pack story: net would run", async () => {
    const { cfg } = config({ command: process.execPath, args: [DIST_TOY("net"), "--mode", "good"] });
    const r = await run(cfg);
    assert.equal(r.ok, true, renderDoctor(r));
    assert.equal(pack(r, "net").applies, true, pack(r, "net").reason);
    assert.match(pack(r, "net").reason, /URL tools: fetch/);
  });

  it("with the sandbox off: warns, starts the server in a throwaway directory, and disables the sandbox packs", async () => {
    const { cfg } = config(node(TOY, "--mode", "nosql"), "");
    const off = loadEffectiveConfig({ cwd: cfg.cwd, env: {}, isolated: true, flags: { sandbox: false } });
    const r = await run(off);
    assert.equal(r.ok, true, renderDoctor(r));
    assert.equal(item(r, "sandbox-off")!.status, "warn");
    assert.match(pack(r, "fs").reason, /sandbox is off/);
    assert.match(pack(r, "exec").reason, /only with --active|sandbox is off/);
  });

  it("an exec pack listed in the config still needs --active, and --active lifts that gate", async () => {
    const { cfg } = config(node(TOY, "--mode", "nosql"), "packs: [core, exec]\n");
    const r = await run(cfg);
    assert.equal(pack(r, "exec").requested, true);
    assert.match(pack(r, "exec").reason, /only with --active/);
    const active = loadEffectiveConfig({ cwd: cfg.cwd, env: {}, isolated: true, flags: { active: true } });
    const r2 = await run(active);
    assert.doesNotMatch(pack(r2, "exec").reason, /only with --active/, "with --active the next gate (no command-running tool) speaks instead");
  });

  it("reports an HTTP server that cannot be reached", async () => {
    const { cfg } = config({ url: "http://127.0.0.1:1/mcp" });
    const r = await run(cfg, { startupTimeoutMs: 3000 });
    assert.equal(r.exitCode, 4);
    assert.equal(r.servers[0].transport, "http");
    assert.equal(item(r, "start")!.status, "fail");
    assert.equal(item(r, "command"), undefined, "an HTTP server has no launcher to resolve");
    assert.match(pack(r, "http").reason, /tool list could not be read/);
  });

  it("restricts to one server of several, and rejects an unknown name", async () => {
    const dir = join(root, `multi${++counter}`);
    mkdirSync(dir);
    const spec = (mode: string) => `    command: ${JSON.stringify(process.execPath)}\n    args: ${JSON.stringify([TOY, "--mode", mode])}\n`;
    const sandboxParent = join(dir, "sb");
    mkdirSync(sandboxParent);
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nservers:\n  one:\n${spec("nosql")}  two:\n${spec("nosql")}sandbox:\n  dir: ${JSON.stringify(sandboxParent)}\n`);
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    const all = await run(cfg);
    assert.deepEqual(all.servers.map((s) => s.name), ["one", "two"]);
    const only = await run(cfg, { server: "two" });
    assert.deepEqual(only.servers.map((s) => s.name), ["two"]);
    assert.deepEqual(readdirSync(sandboxParent), [], "one sandbox serves every server and is deleted");
    await assert.rejects(run(cfg, { server: "three" }), /no server named "three" is selected \(selected: one, two\)/);
  });

  it("does not print secrets: a header or env value under a secret-looking name is shown as <redacted>", async () => {
    const { cfg } = config({ command: process.execPath, args: [TOY, "--mode", "nosql"], env: { API_TOKEN: "sk-fake-doctor-0000000000" } });
    const r = await run(cfg);
    assert.equal(JSON.stringify(r).includes("sk-fake-doctor-0000000000"), false);
    assert.equal(renderDoctor(r).includes("sk-fake-doctor-0000000000"), false);
  });
});
