import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { launchServer, LaunchError } from "../launch.js";
import { decideExit } from "../report/exit.js";
import { secretLiterals } from "../report/secrets.js";
import { HTTP_TOY_TOKEN } from "../toy/http.js";
import type { RunResult } from "../types.js";
import { CLI, FAST, TOY, cliKit, freePort, hermeticEnv, q, srv } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-safety-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml, toyConfig } = cliKit(() => dir);
const POSIX = process.platform !== "win32";
const sub = (name: string): string => mkdtempSync(join(dir, `${name}-`));

/** A command line that starts the repo's good HTTP toy server (a real MCP server over Streamable HTTP) on `port`. */
const httpToyCommand = (port: number): string => {
  const mod = pathToFileURL(fileURLToPath(new URL("../toy/http.js", import.meta.url))).href;
  const script = `import(${JSON.stringify(mod)}).then((m) => m.startHttpToy("good", { port: ${port}, token: ${JSON.stringify(HTTP_TOY_TOKEN)} }))`;
  return `${process.execPath} -e '${script}'`;
};

describe("safety: report destinations are checked before the run (finding 2)", { timeout: 300_000 }, () => {
  it("--out-dir, --out and --write-baseline that cannot be written exit 2 with one line, before any run", () => {
    const d = sub("dest");
    writeFileSync(join(d, "afile"), "x");
    const cfg = toyConfig("dest.yaml", "nosql");
    for (const flags of [["--out-dir", "afile"], ["--format", "json", "--out", "afile/x.json"], ["--write-baseline", "afile/base.json"]]) {
      const t0 = Date.now();
      const r = sealmark(["run", "--config", cfg, ...FAST, ...flags], d);
      assert.equal(r.code, 2, `${flags.join(" ")}: ${r.err}`);
      assert.match(r.err, /^sealmark: Cannot write (--out-dir|--out|--write-baseline) .*afile/m);
      assert.ok(!/unexpected error|\n\s+at /.test(r.err), `no stack trace: ${r.err}`);
      assert.ok(!/starting the server under test/.test(r.err), "the run never started");
      assert.ok(Date.now() - t0 < 20_000);
    }
  });

  it("a read-only directory is refused up front too", { skip: !POSIX || process.getuid?.() === 0 }, () => {
    const d = sub("ro");
    const ro = join(d, "ro");
    mkdirSync(ro);
    chmodSync(ro, 0o555);
    try {
      const r = sealmark(["run", "--config", toyConfig("ro.yaml", "nosql"), ...FAST, "--format", "json", "--out", join(ro, "r.json")], d);
      assert.equal(r.code, 2, r.err);
      assert.match(r.err, /Cannot write --out .*EACCES/);
    } finally {
      chmodSync(ro, 0o755);
    }
  });

  it("creates the --out-dir before the run, and leaves no probe file behind", () => {
    const d = sub("mk");
    const r = sealmark(["run", "--config", toyConfig("mk.yaml", "nosql"), ...FAST, "--format", "json", "--out-dir", "a/b/c"], d);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(readdirSync(join(d, "a", "b", "c")), ["sealmark-report.json"]);
  });

  it("a write that fails after the run still prints the report on stdout and says why, without a stack", () => {
    const d = sub("late");
    // The directory is writable (the early check passes) but one report file's name is taken by a directory.
    mkdirSync(join(d, "out", "sealmark-report.json"), { recursive: true });
    const r = sealmark(["run", "--config", toyConfig("late.yaml", "nosql"), ...FAST, "--format", "json", "--format", "text", "--out-dir", "out"], d);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /sealmark: could not write the report to .*sealmark-report\.json: EISDIR/);
    assert.ok(!/unexpected error|\n\s+at /.test(r.err), r.err);
    assert.equal((JSON.parse(r.out) as { server: { name: string } }).server.name, "cli-test", "the rendered report is on stdout");
    assert.ok(existsSync(join(d, "out", "sealmark-report.txt")), "the other format was written");
    assert.match(r.err, /^sealmark exit 2: a report or baseline file could not be written/m);
  });
});

describe("safety: secrets on the command line and in the URL (findings 14 and 15)", { timeout: 300_000 }, () => {
  it("secretLiterals harvests secret-looking flag values (both forms) and query parameters from any layer", () => {
    const d = sub("lit");
    const cfg = loadEffectiveConfig({
      cwd: d,
      flags: { start: "my-server --token abc123XYZ --api-key=xyz789ABC --port 8000 --password ${PW}", url: "http://127.0.0.1:8000/mcp?token=QUERYsecretTOK55&x=1&sig=a%20b%26cc" },
      env: { PW: "from-the-environment" },
    });
    const lits = secretLiterals(cfg);
    for (const v of ["abc123XYZ", "xyz789ABC", "--api-key=xyz789ABC", "QUERYsecretTOK55", "a b&cc", "from-the-environment"]) assert.ok(lits.includes(v), `${v} in ${JSON.stringify(lits)}`);
    assert.ok(!lits.includes("8000") && !lits.includes("1"), "ordinary values are left alone");
  });

  it("a secret in the --start command line is scrubbed from every report format", () => {
    const d = sub("argsecret");
    // The toy server rejects unknown flags, so a stdio shim forwards to it and ignores the secrets.
    const shim = join(d, "shim.mjs");
    writeFileSync(shim, `process.argv = [process.argv[0], ${q(TOY)}, "--mode", "nosql"];\nawait import(${q(pathToFileURL(TOY).href)});\n`);
    const start = `${process.execPath} ${shim} --api-key=SUPERsecretARG999 --token hunter2pass`;
    for (const fmt of ["json", "text", "markdown", "summary"]) {
      const r = sealmark(["run", "--start", start, ...FAST, "--format", fmt], d);
      assert.equal(r.code, 0, `${fmt}: ${r.err}`);
      for (const secret of ["SUPERsecretARG999", "hunter2pass"]) {
        assert.ok(!r.out.includes(secret), `${fmt} report leaks ${secret}`);
        assert.ok(!r.err.includes(secret), `${fmt} stderr leaks ${secret}`);
      }
    }
  });

  it("a query-string credential in --url is in neither the stderr progress lines nor the JSON", async () => {
    const d = sub("query");
    const port = await freePort();
    const r = sealmark(["run", "--start", httpToyCommand(port), "--url", `http://127.0.0.1:${port}/mcp?token=QUERYsecretTOK55&x=1`, "--header", `Authorization: Bearer ${HTTP_TOY_TOKEN}`, "--pack", "core", "--format", "json", "--timeout-probe", "2"], d);
    assert.ok(r.code === 0 || r.code === 4, r.err);
    assert.match(r.err, /starting the server/);
    assert.ok(!r.err.includes("QUERYsecretTOK55"), r.err);
    assert.ok(!r.out.includes("QUERYsecretTOK55"), "no leak in the report");
  });
});

describe("safety: exit decisions (findings 17, 43, 51, 41)", { timeout: 300_000 }, () => {
  const poison = (name: string, criticalFail: number) => writeYaml(name, `schema_version: 1\nname: crit\nversion: 1.0.0\noutput:\n  exit_policy:\n    critical_fail: ${criticalFail}\nserver:\n  ${srv("poison", 2)}\n`);

  it("--write-baseline writes for a graded run whatever critical_fail is, and names the real reason when it refuses", () => {
    for (const code of [1, 2, 3, 4]) {
      const d = sub(`wb${code}`);
      const r = sealmark(["run", "--fail-under", "none", "--config", poison(`wb${code}.yaml`, code), ...FAST, "--write-baseline", "wb.json"], d);
      assert.equal(r.code, code, r.err);
      assert.ok(existsSync(join(d, "wb.json")), `critical_fail ${code} still wrote the baseline: ${r.err}`);
      assert.ok(!/baseline not written/.test(r.err), r.err);
      assert.match(r.err, new RegExp(`^sealmark exit ${code}: a critical check failed \\(output\\.exit_policy\\.critical_fail is ${code}\\)`, "m"));
    }
    const d = sub("wbfail");
    const r = sealmark(["run", "--fail-under", "none", "--start", "/no/such/sealmark-server --x", "--url", "http://127.0.0.1:9/mcp", "--write-baseline", "wb.json"], d);
    assert.equal(r.code, 4, r.err);
    assert.match(r.err, /baseline not written to wb\.json: a server failed to run/);
    assert.ok(!existsSync(join(d, "wb.json")));
  });

  it("one line says what the exit code means: 0, 1, soft-fail and 4", () => {
    const d = sub("exitline");
    const good = toyConfig("el-good.yaml", "nosql");
    const bad = toyConfig("el-bad.yaml", "bad");
    const ok = sealmark(["run", "--config", good, ...FAST, "--fail-under", "B"], d);
    assert.equal(ok.code, 0, ok.err);
    assert.match(ok.err, /^sealmark exit 0: every graded pack meets the gate \(B\)$/m);
    const low = sealmark(["run", "--config", bad, ...FAST, "--fail-under", "A"], d);
    assert.equal(low.code, 1);
    assert.match(low.err, /^sealmark exit 1: a graded pack is below the gate \(A\)$/m);
    assert.equal(low.err.match(/^sealmark exit /gm)?.length, 1, "exactly one such line");
    const soft = sealmark(["run", "--config", bad, ...FAST, "--fail-under", "A", "--soft-fail"], d);
    assert.equal(soft.code, 0);
    assert.match(soft.err, /^sealmark exit 0: --soft-fail: a graded pack is below the gate \(A\) \(would exit 1\)$/m);
    const broken = sealmark(["run", "--start", "/no/such/sealmark-server --x", "--url", "http://127.0.0.1:9/mcp"], d);
    assert.equal(broken.code, 4);
    assert.match(broken.err, /^sealmark exit 4: a server failed to run$/m);
  });

  it("decideExit gives the cause of the worst code", () => {
    const failed = { status: "failed", server: "x", error: "boom", sealmark: { version: "0", methodology: "0" } } as never;
    const d = decideExit([failed], { treatInconclusiveAs: "pass", criticalFail: 0, failOnGate: true, failOnRegressions: true, failOnDrift: false, regressions: [], drift: [], baseline: false });
    assert.deepEqual([d.code, d.reason], [4, "a server failed to run"]);
    const none = decideExit([], { treatInconclusiveAs: "pass", criticalFail: 0, failOnGate: true, failOnRegressions: true, failOnDrift: false, regressions: [], drift: [], baseline: false });
    assert.match(none.reason, /the gate is off \(--fail-under none\); grades do not affect the exit code/);
  });

  it("a thrown non-harness error in one server fails that server, not the whole multi-server run", () => {
    const d = sub("multi");
    const cfg = writeYaml("multi.yaml", `schema_version: 1\nname: multi\nversion: 1.0.0\nservers:\n  good:\n    ${srv("nosql")}\n  bad:\n    url: "{sandbox}"\n`);
    const r = sealmark(["run", "--config", cfg, ...FAST, "--format", "json"], d);
    assert.equal(r.code, 4, r.err);
    assert.ok(!/\n\s+at /.test(r.err), `no stack trace: ${r.err}`);
    const runs = (JSON.parse(r.out) as { runs: (RunResult | { status: string; server: string; error: string })[] }).runs;
    assert.deepEqual(runs.map((x) => ("status" in x ? "failed" : x.server.name)), ["good", "failed"]);
    assert.equal(runs.find((x) => "status" in x)?.server, "bad");
  });

  it("a stale stderr log from an earlier failed run is removed by a later run in the same directory", () => {
    const d = sub("stale");
    const first = sealmark(["run", "--start", `${process.execPath} ${join(d, "missing.js")}`, "--pack", "core", "--format", "json", "--out-dir", "rep", "--connect-timeout", "5"], d);
    assert.equal(first.code, 4, first.err);
    assert.ok(existsSync(join(d, "rep", "sealmark-report.stderr.log")), "the failed run saved its stderr");
    const second = sealmark(["run", "--config", toyConfig("stale.yaml", "nosql"), ...FAST, "--format", "json", "--out-dir", "rep"], d);
    assert.equal(second.code, 0, second.err);
    assert.ok(!existsSync(join(d, "rep", "sealmark-report.stderr.log")), "the stale log is gone");
    assert.ok(existsSync(join(d, "rep", "sealmark-report.json")));
  });
});

describe("safety: a 401 on connect says what to type (finding 56)", { timeout: 120_000 }, () => {
  it("adds the --bearer / --header hint when no Authorization header is configured", async () => {
    const d = sub("hint");
    const port = await freePort();
    const r = sealmark(["run", "--start", httpToyCommand(port), "--url", `http://127.0.0.1:${port}/mcp`, "--pack", "core", "--timeout-probe", "2"], d);
    assert.equal(r.code, 4, r.err);
    assert.match(r.err, /^hint: the server answered 401: pass a token with --bearer or --header/m);
  });
});

describe("safety: --start-timeout is honoured (finding 33)", { timeout: 60_000 }, () => {
  it("a listener that accepts and never replies does not stretch the limit by the probe's own 2 s", async () => {
    // The launched process listens on the URL's port and never answers HTTP, so every probe runs into its own timeout.
    const other = await freePort();
    const t0 = Date.now();
    await assert.rejects(
      launchServer({ command: process.execPath, args: ["-e", `require("net").createServer(() => {}).listen(${other}, "127.0.0.1");`], env: {}, url: `http://127.0.0.1:${other}/mcp`, timeoutMs: 1000 }),
      (e: Error) => e instanceof LaunchError && /did not answer within 1 s/.test(e.message),
    );
    const took = Date.now() - t0;
    assert.ok(took < 3_000, `took ${took} ms for a 1 s limit`);
  });
});

// ---------------------------------------------------------------------------------------------------------
// Signals: the launched server must be gone after sealmark is stopped (findings 6, 7, 57)
// ---------------------------------------------------------------------------------------------------------

describe("safety: signals stop the launched server", { timeout: 240_000, skip: !POSIX }, () => {
  /** answers the first request with 401 (so the launch is "ready") and then hangs forever; optionally ignores SIGTERM. */
  const hangScript = (d: string, ignoreTerm: boolean): string => {
    const f = join(d, `hang-${ignoreTerm ? "stubborn" : "plain"}.cjs`);
    writeFileSync(f, `${ignoreTerm ? 'process.on("SIGTERM", () => {});\n' : ""}let n = 0;\nrequire("http").createServer((q, s) => { if (n++ === 0) { s.statusCode = 401; s.end("no"); } }).listen(Number(process.argv[2]), "127.0.0.1");\n`);
    return f;
  };
  const isUp = async (port: number): Promise<boolean> => {
    try {
      await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", body: "{}", signal: AbortSignal.timeout(500) });
      return true;
    } catch (e) {
      return (e as Error).name === "TimeoutError"; // accepted but never answered: still up
    }
  };

  async function exercise(command: "run" | "doctor", signals: NodeJS.Signals[], ignoreTerm: boolean, gapMs: number): Promise<{ code: number | null; signal: NodeJS.Signals | null; goneAfterMs: number; err: string }> {
    const d = sub(`sig-${command}`);
    const port = await freePort();
    const child = spawn(process.execPath, [CLI, command, "--start", `${process.execPath} ${hangScript(d, ignoreTerm)} ${port}`, "--url", `http://127.0.0.1:${port}/mcp`, ...(command === "run" ? FAST : [])], { cwd: d, env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let err = "";
    child.stderr.on("data", (b: Buffer) => (err += b.toString()));
    child.stdout.on("data", () => {});
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((res) => child.once("exit", (code, signal) => res({ code, signal })));
    const t0 = Date.now();
    while (!/the server answered/.test(err)) {
      assert.ok(Date.now() - t0 < 60_000, `the server never came up: ${err}`);
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(await isUp(port), "the launched server is up before the signal");
    for (let i = 0; i < signals.length; i++) {
      if (i > 0) await new Promise((r) => setTimeout(r, gapMs));
      child.kill(signals[i]);
    }
    const { code, signal } = await exited;
    const t1 = Date.now();
    while (await isUp(port)) {
      if (Date.now() - t1 > 8_000) {
        // do not leave a stray server behind when the assertion fails
        try {
          child.kill("SIGKILL");
        } catch {
          /* gone */
        }
        assert.fail(`the launched server is still up after sealmark exited (${command}, ${signals.join("+")}): ${err}`);
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    return { code, signal, goneAfterMs: Date.now() - t1, err };
  }

  it("SIGINT, SIGTERM and SIGHUP each stop the server and exit 128 + the signal number (run)", async () => {
    for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]] as const) {
      const r = await exercise("run", [sig], false, 0);
      assert.equal(r.code, code, `${sig}: ${r.err}`);
    }
  });

  it("a second Ctrl+C during cleanup does not kill sealmark and orphan a server that ignores SIGTERM", async () => {
    const r = await exercise("run", ["SIGINT", "SIGINT"], true, 400);
    assert.equal(r.code, 130, r.err);
    assert.ok(r.goneAfterMs < 2_500, `forced quit must not wait for the 3 s grace: ${r.goneAfterMs} ms`);
  });

  it("doctor handles SIGHUP and a double SIGINT the same way", async () => {
    const a = await exercise("doctor", ["SIGHUP"], false, 0);
    assert.equal(a.code, 129, a.err);
    const b = await exercise("doctor", ["SIGINT", "SIGINT"], true, 400);
    assert.equal(b.code, 130, b.err);
  });
});
