import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ConfigError } from "../config/model.js";
import type { TemplateCtx } from "../config/placeholders.js";
import { createLayout, type Layout } from "../sandbox.js";
import { stageFiles } from "../staged-files.js";
import type { ProbeCall } from "../probes.js";
import type { RunResult } from "../types.js";
import { cliKit, q } from "./helpers.js";
import { FS_TOY } from "./packctx.js";

let dir: string;
const kept: string[] = [];
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-staged-"));
});
after(() => {
  for (const k of kept) rmSync(k, { recursive: true, force: true });
  rmSync(dir, { recursive: true, force: true });
});

const { sealmark, writeYaml, readJson } = cliKit(() => dir);

describe("stageFiles", () => {
  let l: Layout;
  let n = 0;
  let ctx: TemplateCtx;
  const roots = () => ({ sandbox: l.root, home: l.home });
  const log = () => {};
  before(() => {
    const d = join(dir, `unit-${++n}`);
    mkdirSync(d);
    l = createLayout(d);
    ctx = { vars: { sandbox: l.root, sandbox_home: l.home, listener: "http://127.0.0.1:4242" }, dsns: {}, env: { SM_STAGED_VAR: "from-env" } };
  });

  it("writes a file with expanded content and returns its path", () => {
    const logged: string[] = [];
    const out = stageFiles([{ path: "{sandbox}/staged/hello.txt", content: "hello {listener} ${SM_STAGED_VAR}" }], ctx, roots(), (s) => logged.push(s));
    assert.deepEqual(out, [join(l.root, "staged", "hello.txt")]);
    assert.equal(readFileSync(out[0], "utf8"), "hello http://127.0.0.1:4242 from-env");
    if (process.platform !== "win32") assert.equal(lstatSync(out[0]).mode & 0o777, 0o644);
    assert.deepEqual(logged, ["staged 1 file(s) in the sandbox"]);
  });

  it("writes under {sandbox_home} and {dir}, and an empty or missing list writes nothing", () => {
    const out = stageFiles(
      [
        { path: "{sandbox_home}/.config/app.json", content: "{}" },
        { path: "{dir}/other.txt", content: "x" },
      ],
      { ...ctx, vars: { ...ctx.vars } },
      roots(),
      log,
    );
    assert.deepEqual(out, [join(l.home, ".config", "app.json"), join(l.root, "other.txt")]);
    assert.deepEqual(stageFiles([], ctx, roots(), log), []);
    assert.deepEqual(stageFiles(undefined, ctx, roots(), log), []);
  });

  it("refuses a path that leaves the sandbox through .. or a sibling with the same prefix", () => {
    assert.throws(() => stageFiles([{ path: "{sandbox}/../x", content: "" }], ctx, roots(), log), (e) => e instanceof ConfigError && /server\.files: \{sandbox\}\/\.\.\/x resolves outside the sandbox/.test(e.message));
    assert.throws(() => stageFiles([{ path: "{sandbox}/a/../../x", content: "" }], ctx, roots(), log), ConfigError);
    assert.throws(() => stageFiles([{ path: "{sandbox}-evil/x", content: "" }], ctx, roots(), log), /resolves outside the sandbox/);
    assert.equal(existsSync(join(l.root, "..", "x")), false);
  });

  it("refuses a path that reaches the canary directory through the layout's own link", (t) => {
    if (!l.links.dir.ok) return t.skip("directory links are not available here");
    assert.throws(() => stageFiles([{ path: "{sandbox}/link-dir/sub/x.txt", content: "" }], ctx, roots(), log), /resolves outside the sandbox/);
    assert.equal(existsSync(join(l.canary, "sub")), false, "nothing was created through the link");
  });

  it("never overwrites a file the harness made, and a path listed twice is refused", () => {
    assert.throws(() => stageFiles([{ path: "{sandbox}/ok.txt", content: "mine" }], ctx, roots(), log), (e) => e instanceof ConfigError && /server\.files: \{sandbox\}\/ok\.txt is a file the harness owns/.test(e.message));
    assert.equal(readFileSync(l.files.ok, "utf8"), l.tokens.control);
    assert.throws(
      () =>
        stageFiles(
          [
            { path: "{sandbox}/dup.txt", content: "1" },
            { path: "{sandbox}/dup.txt", content: "2" },
          ],
          ctx,
          roots(),
          log,
        ),
      ConfigError,
    );
  });

  it("names a placeholder that has no value", () => {
    assert.throws(() => stageFiles([{ path: "{canary}/x", content: "" }], ctx, roots(), log), /server\.files: \{canary\}\/x still has a placeholder/);
  });
});

// ---- through the CLI, with the toy fs server ----

const FS_ARGS = [FS_TOY, "--mode", "good", "--root", "{sandbox}"];
const PROBE = `probes:\n  - id: staged-hello\n    tool: read_file\n    args:\n      path: ${q("{sandbox}/staged/hello.txt")}\n    expect:\n      text:\n        matches: ${q("hello http")}\n`;
const config = (files: string, extra = ""): string =>
  `name: staged-test\nversion: 1.0.0\nserver:\n  command: ${q(process.execPath)}\n  args: ${q(FS_ARGS)}\n  files:\n${files}\n${extra}`;
const file = (path: string, content: string): string => `    - path: ${q(path)}\n      content: ${q(content)}`;
const RUN = ["--pack", "core", "--timeout-probe", "2", "--fail-under", "none"];

describe("server.files through the CLI", { timeout: 180_000 }, () => {
  it("a staged file exists before the server starts: a probe reads it, there is no warning, and the kept sandbox holds it", () => {
    const cfg = writeYaml("ok.yaml", config(file("{sandbox}/staged/hello.txt", "hello {listener}"), PROBE));
    const json = join(dir, "ok.json");
    const r = sealmark(["run", "--config", cfg, ...RUN, "--keep-sandbox", "--format", "json", "--out", json]);
    const place = /the sandbox was kept at (.+?) \(--keep-sandbox\)/.exec(r.err)?.[1];
    if (place) kept.push(place);
    assert.equal(r.code, 0, r.err);
    assert.ok(place, `the kept sandbox is named: ${r.err}`);
    assert.doesNotMatch(r.err, /warning:.*(probe|staged-hello)/i);
    assert.match(r.err, /staged 1 file\(s\) in the sandbox/);
    const staged = readFileSync(join(place, "root", "staged", "hello.txt"), "utf8");
    assert.match(staged, /^hello http:\/\/127\.0\.0\.1:\d+$/);
    // The probe really ran (a clean stderr alone would also be true if it had not): the call is in the report and it read the file.
    const call = (readJson<RunResult>(json).probes?.calls as ProbeCall[] | undefined)?.find((c) => c.id === "staged-hello");
    assert.ok(call, "the probe was made");
    assert.equal(call.valid, true);
    assert.match(call.excerpt, /hello http/);
    assert.deepEqual(call.misses, []);
  });

  it("a staged file is never reported as a server write", () => {
    const cfg = writeYaml("quiet.yaml", config(file("{sandbox}/staged/hello.txt", "hello {listener}")));
    const json = join(dir, "quiet.json");
    const r = sealmark(["run", "--config", cfg, "--pack", "fs,effects", "--timeout-probe", "2", "--fail-under", "none", "--format", "json", "--out", json]);
    assert.equal(r.code, 0, r.err);
    const run = readJson<RunResult>(json);
    assert.ok(!JSON.stringify(run.checks.map((c) => c.evidence)).includes("hello.txt"), "hello.txt is not in any evidence");
  });

  it("database placeholders in content are refused when the config loads", () => {
    const r = sealmark(["run", "--config", writeYaml("dsn.yaml", config(file("{sandbox}/staged/db.txt", "url={dsn}"))), ...RUN]);
    assert.equal(r.code, 2);
    assert.match(r.err, /server\.files cannot carry database placeholders/);
  });

  it("a path outside {sandbox} and {sandbox_home}, such as {canary}, is refused when the config loads", () => {
    const r = sealmark(["run", "--config", writeYaml("canary.yaml", config(file("{canary}/x.txt", "x"))), ...RUN]);
    assert.equal(r.code, 2);
    assert.match(r.err, /staged files are written only inside the sandbox/);
  });

  it("an escape through .. is a ConfigError at run time (exit 2) and writes nothing", () => {
    const r = sealmark(["run", "--config", writeYaml("escape.yaml", config(file("{sandbox}/../escape.txt", "x"))), ...RUN]);
    assert.equal(r.code, 2);
    assert.match(r.err, /resolves outside the sandbox/);
  });

  it("a harness-owned file such as ok.txt is refused (exit 2)", () => {
    const r = sealmark(["run", "--config", writeYaml("owned.yaml", config(file("{sandbox}/ok.txt", "x"))), ...RUN]);
    assert.equal(r.code, 2);
    assert.match(r.err, /is a file the harness owns/);
  });

  it("--no-sandbox with staged files exits 2", () => {
    const r = sealmark(["run", "--config", writeYaml("nosb.yaml", config(file("{sandbox}/staged/hello.txt", "x"))), ...RUN, "--no-sandbox"]);
    assert.equal(r.code, 2);
    assert.match(r.err, /staged files \(server\.files\) need the sandbox/);
  });

  it("a server that is already running (a bare --url) cannot be given staged files: exit 2 before any connection", () => {
    const cfg = writeYaml("url.yaml", `name: staged-url\nversion: 1.0.0\nserver:\n  url: http://127.0.0.1:9/mcp\n  files:\n${file("{sandbox}/staged/hello.txt", "x")}\n`);
    const r = sealmark(["run", "--config", cfg, ...RUN]);
    assert.equal(r.code, 2);
    assert.match(r.err, /staged files need a server Sealmark starts/);
  });
});
