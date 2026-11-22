import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { after, before, describe, it } from "node:test";
import { jsonLine, parseArgsJson, parseCommand, renderEvent, type InspectEvent } from "../inspect.js";
import { CLI, cliKit, hermeticEnv, q } from "./helpers.js";

const FS_TOY = new URL("../toy/fs.js", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-inspect-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeYaml } = cliKit(() => dir);

const fsConfig = (file: string, mode = "logger", extra = ""): string =>
  writeYaml(file, `schema_version: 1\nname: insp\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([FS_TOY, "--mode", mode, "--root", "{sandbox}"])}\n${extra}`);

/** The CLI with text on stdin (commands) and a closed stdin otherwise. */
const withInput = (args: string[], input: string) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: "utf8", timeout: 120_000, input, env: hermeticEnv() });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const events = (out: string): Record<string, any>[] => out.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

describe("inspect: parsing", () => {
  it("reads call lines, defaults the arguments to {} and refuses what is not an object", () => {
    assert.deepEqual(parseCommand("call read_file"), { cmd: "call", tool: "read_file", args: {} });
    assert.deepEqual(parseCommand('  call  read_file   {"path": "a b.txt"} '), { cmd: "call", tool: "read_file", args: { path: "a b.txt" } });
    assert.equal(parseCommand("").cmd, "empty");
    assert.equal(parseCommand("exit").cmd, "quit");
    assert.equal(parseCommand("list").cmd, "tools");
    for (const bad of ["call", 'call t [1]', "call t null", "call t {oops", "call t 5", "frobnicate"]) assert.equal(parseCommand(bad).cmd, "bad", bad);
    assert.equal(typeof parseArgsJson("[]"), "string");
    assert.deepEqual(parseArgsJson(""), {});
  });

  it("prints a server's text without its control characters", () => {
    const e: InspectEvent = {
      event: "call",
      server: "s",
      tool: "t\u001b[31m",
      args: {},
      result: { isError: false, text: "line\u001b]0;pwned\u0007 ‮evil", elapsedMs: 1, timedOut: false, closed: false },
      observed: { scope: "x", watching: true, files: { added: [], removed: [], changed: [], touched: [] }, requests: [], processes: [], stderr: ["\u001b[2Jclear"], notObserved: [] },
    };
    const text = renderEvent(e);
    assert.doesNotMatch(text, /[\u001b\u0007‮]/);
  });
});

describe("inspect: hostile text", () => {
  it("--json escapes the C1 controls, bidi overrides and zero-width characters JSON.stringify leaves raw", () => {
    const line = jsonLine({ text: "a\u009b31mb\u202ec\u200bd\u007f", ok: "plain é" });
    assert.doesNotMatch(line, /[\u007f-\u009f\u202e\u200b]/);
    assert.deepEqual(JSON.parse(line), { text: "a\u009b31mb\u202ec\u200bd\u007f", ok: "plain é" });
  });

  it("a server that dies printing escape sequences on stderr does not reach the terminal with them", () => {
    const script = `process.stderr.write("\\u001b]0;PWNED\\u0007\\u001b[31mred\\n"); process.exit(3)`;
    const cfg = writeYaml("esc.yaml", `schema_version: 1\nname: esc\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ["-e", ${q(script)}]\n`);
    const r = sealmark(["inspect", "--config", cfg, "--connect-timeout", "5"]);
    assert.equal(r.code, 4);
    assert.doesNotMatch(r.err, /[\u001b\u0007]/);
  });
});

describe("inspect: against the toy file server", () => {
  it("expands {sandbox} to a real directory even with --no-sandbox, as run does", () => {
    const r = sealmark(["inspect", "--config", fsConfig("ns.yaml"), "--no-sandbox", "--call", "list_dir", "--args", '{"path":"."}']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /list_dir {2}ok/);
    assert.match(r.out, /nothing: the sandbox is off/);
  });

  it("does not stop for a reader that closes stdout early, and leaves no sandbox directory behind", () => {
    // This spawn gets its own TMPDIR: the sandbox and cwd directories land there, so a sibling test file creating
    // sealmark-* entries in the shared os.tmpdir() at the same time (node --test runs files concurrently) cannot look like a leak.
    const own = mkdtempSync(join(dir, "tmp-"));
    const input = `${Array.from({ length: 14 }, () => 'call list_dir {"path":"."}').join("\n")}\n`;
    const r = spawnSync("sh", ["-c", `${q(process.execPath)} ${q(CLI)} inspect --config ${q(fsConfig("pipe.yaml"))} --json | head -c 50 >/dev/null`], { cwd: dir, encoding: "utf8", input, timeout: 120_000, env: hermeticEnv({ TMPDIR: own }) });
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr, /EPIPE|unexpected error/);
    assert.deepEqual(readdirSync(own), [], "anything left in the run's own TMPDIR is a leak");
  });

  it("lists the tools and, with --call, shows the reply and the file the tool wrote", () => {
    const cfg = fsConfig("a.yaml");
    const r = sealmark(["inspect", "--config", cfg, "--call", "write_file", "--args", '{"path":"made.txt","content":"hello"}']);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /write_file {2}ok/);
    assert.match(r.out, /Wrote 5 bytes/);
    assert.match(r.out, /files added: root\/made\.txt/);
    assert.match(r.out, /requests to the harness listener: none/);
    assert.match(r.out, /not observed: .*database/);
  });

  it("sees a read-only-looking tool write (the toy's logger mode appends to <root>/.log)", () => {
    const r = sealmark(["inspect", "--config", fsConfig("b.yaml"), "--call", "list_dir", "--args", '{"path":"."}', "--json"]);
    assert.equal(r.code, 0, r.err);
    const [e] = events(r.out);
    assert.equal(e!.format, "sealmark.inspect/1");
    assert.equal(e!.event, "call");
    assert.equal(e!.observed.watching, true);
    assert.deepEqual(e!.observed.files.added, []);
    const read = events(sealmark(["inspect", "--config", fsConfig("b2.yaml"), "--call", "read_file", "--args", '{"path":"nope.txt"}', "--json"]).out)[0]!;
    assert.deepEqual(read.observed.files.added, ["root/.log"]);
    assert.equal(read.result.isError, true);
  });

  it("reads commands from stdin, keeps going after a bad line and attributes each call's files to that call only", () => {
    const input = ['call write_file {"path":"one.txt","content":"1"}', "call nope", "call write_file {bad", 'call write_file {"path":"two.txt","content":"2"}', "quit", 'call write_file {"path":"after-quit.txt","content":"3"}'].join("\n");
    const r = withInput(["inspect", "--config", fsConfig("c.yaml"), "--json"], input);
    assert.equal(r.code, 0, r.err);
    const ev = events(r.out);
    assert.deepEqual(ev.map((e) => e.event), ["tools", "call", "error", "error", "call"]);
    assert.deepEqual(ev[1]!.observed.files.added, ["root/one.txt"]);
    assert.deepEqual(ev[4]!.observed.files.added, ["root/two.txt"]);
    assert.match(ev[2]!.message, /no tool named "nope"/);
    assert.match(ev[3]!.message, /not valid JSON/);
  });

  it("with no input it lists the tools and stops", () => {
    const r = withInput(["inspect", "--config", fsConfig("d.yaml")], "");
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /insp: 4 tools/);
    assert.match(r.out, /write_file\(path, content\)/);
  });

  it("says nothing was observed when the sandbox is off, instead of reporting no effects", () => {
    const root = mkdtempSync(join(dir, "own-root-"));
    const cfg = writeYaml("e.yaml", `schema_version: 1\nname: insp\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q([FS_TOY, "--mode", "logger", "--root", root])}\n`);
    const r = sealmark(["inspect", "--config", cfg, "--no-sandbox", "--call", "stat", "--args", JSON.stringify({ path: root })]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /nothing: the sandbox is off/);
    assert.doesNotMatch(r.out, /no change seen/);
    assert.match(r.err, /sandbox is off/);
  });

  it("calling an unknown tool with --call exits 4 and starts nothing it was not asked for", () => {
    const r = sealmark(["inspect", "--config", fsConfig("f.yaml"), "--call", "delete_everything"]);
    assert.equal(r.code, 4);
    assert.match(r.out, /no tool named "delete_everything"/);
  });
});

describe("inspect: usage errors exit 2", () => {
  it("--args without --call, malformed --args, an unknown --server", () => {
    const cfg = fsConfig("g.yaml");
    assert.equal(sealmark(["inspect", "--config", cfg, "--args", "{}"]).code, 2);
    const bad = sealmark(["inspect", "--config", cfg, "--call", "stat", "--args", "[1]"]);
    assert.equal(bad.code, 2);
    assert.match(bad.err, /JSON object/);
    const srv = sealmark(["inspect", "--config", cfg, "--server", "ghost", "--call", "stat"]);
    assert.equal(srv.code, 2);
    assert.match(srv.err, /no server named "ghost"/);
  });

  it("refuses a configuration that needs a database, and the flags of other commands", () => {
    const cfg = writeYaml("h.yaml", `schema_version: 1\nname: db\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ["-e", "0", "{dsn}"]\n`);
    const r = sealmark(["inspect", "--config", cfg]);
    assert.equal(r.code, 2);
    assert.match(r.err, /starts no database/);
    assert.equal(sealmark(["inspect", "--config", fsConfig("h2.yaml"), "--pack", "core"]).code, 2);
  });

  it("refuses {upstream} and {bearer}: made-up values would make the replies mislead", () => {
    for (const ph of ["{upstream}", "{bearer}"]) {
      const cfg = writeYaml("ph.yaml", `schema_version: 1\nname: ph\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ["-e", "0", ${q(ph)}]\n`);
      const r = sealmark(["inspect", "--config", cfg]);
      assert.equal(r.code, 2, ph);
      assert.match(r.err, /inspect starts neither/);
    }
  });

  it("a server that does not start exits 4 and points at doctor", () => {
    const cfg = writeYaml("i.yaml", `schema_version: 1\nname: dead\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ["-e", "process.exit(3)"]\n`);
    const r = sealmark(["inspect", "--config", cfg, "--connect-timeout", "5"]);
    assert.equal(r.code, 4);
    assert.match(r.err, /sealmark doctor/);
  });
});

