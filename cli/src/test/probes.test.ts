import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import { ConfigError } from "../config.js";
import type { ProbeSpec } from "../config/model.js";
import { McpSession, type ToolInfo } from "../mcp.js";
import { REGISTRY } from "../packs/index.js";
import { describe as describeCustom, pack as customPack, probesReport, probeVars, runProbe, runValidCalls, validateProbes, type PlanInput } from "../probes.js";
import { legacyEffectiveConfig, runHarness } from "../run.js";
import { createSandbox } from "../sandbox.js";
import type { ConfigIntegrity, EffectiveConfig, PackId, RunResult, Sandbox, SealmarkConfig } from "../types.js";
import { gradeOf, quiet, verdicts } from "./helpers.js";

const PROBES_TOY = fileURLToPath(new URL("../toy/probes.js", import.meta.url));
const EXEC_TOY = fileURLToPath(new URL("../toy/exec.js", import.meta.url));
const INTEGRITY: ConfigIntegrity = { hash: "test-hash", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} };

const toyConfig = (script: string, name: string, mode: string, extra: string[] = []): SealmarkConfig => ({
  name,
  version: "0.0.1",
  server: { command: process.execPath, args: [script, "--mode", mode, ...extra], env: {} },
});
const probesToy = (mode: string) => toyConfig(PROBES_TOY, `toy-probes-${mode}`, mode);

let dir: string;
let parent: string;
let sb: Sandbox;
const leftovers = () => readdirSync(parent).filter((n) => n.startsWith("sealmark-"));

function effective(config: SealmarkConfig, probes: ProbeSpec[], packs: PackId[] = ["custom"], over: Partial<EffectiveConfig> = {}): EffectiveConfig {
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: false, timeoutProbeSec: 2 });
  return { ...base, integrity: INTEGRITY, cwd: dir, probes, ...over, sandbox: { ...base.sandbox, dir: parent } };
}

const runCustom = (config: SealmarkConfig, probes: ProbeSpec[], o: { active?: boolean; packs?: PackId[] } = {}): Promise<RunResult> =>
  runHarness({ config, effective: effective(config, probes, o.packs ?? ["custom"]), packs: o.packs ?? ["custom"], packsExplicit: false, active: o.active ?? false, timeoutProbeSec: 2, log: quiet });

// ---- tools for the validator tests (the shapes of the toy servers, classified the normal way) ----
const T = (name: string, description: string, props: Record<string, { type: string; items?: { type: string } }>, required: string[]): ToolInfo => ({
  name,
  description,
  inputSchema: { type: "object", properties: props, required },
});
const TOOLS: ToolInfo[] = [
  T("read_file", "Read a file and return its text.", { path: { type: "string" } }, ["path"]),
  T("write_file", "Write text to a file.", { path: { type: "string" }, content: { type: "string" } }, ["path", "content"]),
  T("delete_file", "Delete a file.", { path: { type: "string" } }, ["path"]),
  T("fetch", "Fetch a web page over HTTP and return its body.", { url: { type: "string" } }, ["url"]),
  T("echo", "Echo the text back.", { text: { type: "string" } }, ["text"]),
  T("nap", "Wait for a number of milliseconds.", { ms: { type: "number" } }, ["ms"]),
  T("run", "Run a program with a list of arguments and return what it prints.", { program: { type: "string" }, args: { type: "array", items: { type: "string" } } }, ["program"]),
  T("shell", "Run one command line and return what it prints.", { command: { type: "string" } }, ["command"]),
  T("query", "Run a SQL query against the database", { sql: { type: "string" } }, ["sql"]),
];

const CHECK = { id: "custom-delete-scope", label: "Delete refuses paths outside the root", critical: true, scope: "server (delete tool path validation)" };
const SPEC_EXAMPLE: ProbeSpec = {
  id: "delete-outside-root",
  check: CHECK,
  tool: "delete_file",
  args: { path: "{canary}/secret.txt" },
  timeout_ms: 10000,
  expect: {
    is_error: true,
    text: { matches: "outside|denied", not_matches: "sm-fscanary" },
    files: { unchanged: ["{canary}/secret.txt"], created: [], absent: ["{canary}/deleted-marker"] },
    listener: "none",
    duration_ms: { max: 5000 },
  },
};

describe("custom probes", { timeout: 240_000 }, () => {
  const results: Record<string, RunResult> = {};
  let input: PlanInput;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-probes-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
    sb = await createSandbox({ dir: parent, slowHoldMs: 1000 });
    input = { tools: TOOLS, classification: classifyTools({ tools: TOOLS }).classification, sandbox: sb, reservedCheckIds: ["protocol", "exec-cwd"] };

    // The same probe list against three servers that differ in one way each.
    const probes: ProbeSpec[] = [
      // Read first: the traverse server deletes the canary in the delete probe, and a leak needs the file to be there.
      {
        id: "read-outside-root",
        check: { id: "custom-read-scope", label: "Read refuses paths outside the root", critical: true, scope: "server (read tool path validation)" },
        tool: "read_file",
        args: { path: "{canary}/secret.txt" },
        expect: { is_error: true, text: { not_matches: "sm-fscanary" }, files: { unchanged: ["{canary}/secret.txt"] } },
      },
      SPEC_EXAMPLE,
      {
        id: "fetch-loopback",
        check: { id: "custom-fetch-scope", label: "Fetch refuses the loopback listener", critical: false, scope: "server (fetch address validation)" },
        tool: "fetch",
        args: { url: "{listener}/t/{token}" },
        expect: { is_error: true, listener: "none" },
      },
      {
        id: "nap-fast",
        check: { id: "custom-latency", label: "Short waits return promptly", critical: false, scope: "server (latency)" },
        tool: "nap",
        args: { ms: 50 },
        expect: { duration_ms: { max: 5000 } },
      },
      {
        id: "nap-limit",
        check: { id: "custom-latency", label: "Short waits return promptly", critical: false, scope: "server (latency)" },
        tool: "nap",
        args: { ms: 500 },
        expect: { duration_ms: { max: 100 } },
      },
      {
        id: "write-creates",
        check: { id: "custom-write-created", label: "Writing inside the root creates the file", critical: false, scope: "server (write)" },
        tool: "write_file",
        args: { path: "{sandbox}/made-{token}.txt", content: "{token}" },
        expect: { is_error: false, files: { created: ["{sandbox}/made-{token}.txt"] } },
      },
      {
        id: "nap-timeout",
        check: { id: "custom-timeout", label: "A long wait finishes", critical: false, scope: "server (latency)" },
        tool: "nap",
        args: { ms: 5000 },
        timeout_ms: 300,
        expect: { is_error: false },
      },
      // Coverage only: no check, so the custom pack leaves it to the core session.
      { tool: "echo", args: { text: "{token}" } },
    ];
    const jobs: Record<string, () => Promise<RunResult>> = {
      good: () => runCustom(probesToy("good"), probes),
      traverse: () => runCustom(probesToy("traverse"), probes),
      open: () => runCustom(probesToy("open"), probes),
      execActive: () =>
        runCustom(
          toyConfig(EXEC_TOY, "toy-exec-good", "good", ["--timeout", "6"]),
          [
            {
              id: "exec-echo",
              check: { id: "custom-exec", label: "The command tool runs a harness program", critical: false, scope: "server (command tool)" },
              tool: "run",
              args: { program: "sm-echo", args: ["hi-{token}"] },
              active: true,
              expect: { is_error: false, text: { matches: "hi-sm-" } },
            },
          ],
          { active: true },
        ),
      execInactive: () =>
        runCustom(toyConfig(EXEC_TOY, "toy-exec-good", "good", ["--timeout", "6"]), [
          {
            id: "exec-echo",
            check: { id: "custom-exec", label: "The command tool runs a harness program", critical: false, scope: "server (command tool)" },
            tool: "run",
            args: { program: "sm-echo", args: ["hi"] },
            active: true,
            expect: { is_error: false },
          },
        ]),
    };
    await Promise.all(Object.entries(jobs).map(async ([k, fn]) => void (results[k] = await fn())));
  });

  after(async () => {
    await sb.destroy();
    rmSync(dir, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------------------------------------------------
  describe("validation", () => {
    const plan = (...specs: ProbeSpec[]) => validateProbes(specs, input);
    const rejects = (spec: ProbeSpec | ProbeSpec[], re: RegExp) =>
      assert.throws(
        () => validateProbes([spec].flat(), input),
        (e: unknown) => e instanceof ConfigError && re.test((e as Error).message),
        String(re),
      );

    it("accepts the example from the design and returns the checks it defines", () => {
      const p = plan(SPEC_EXAMPLE, { tool: "echo", args: { text: "{token}" } });
      assert.equal(p.probes.length, 2);
      assert.deepEqual(p.checks, [{ id: "custom-delete-scope", label: "Delete refuses paths outside the root", critical: true, scope: "server (delete tool path validation)" }]);
      assert.equal(p.probes[0].id, "delete-outside-root");
      assert.equal(p.probes[1].id, "echo#2");
      assert.equal(p.probes[0].timeoutMs, 10000);
      assert.equal(p.probes[1].timeoutMs, 10000);
    });

    it("an unknown tool is an error that lists the tools the server offers", () => {
      rejects({ tool: "nope", args: {} }, /probes\[0\]: unknown tool "nope" \(the server offers: read_file, write_file/);
    });

    it("a bad regular expression is an error that names the clause", () => {
      rejects({ ...SPEC_EXAMPLE, expect: { text: { matches: "(unclosed" } } }, /expect\.text\.matches is not a valid regular expression/);
      rejects({ ...SPEC_EXAMPLE, expect: { text: { not_matches: "[" } } }, /expect\.text\.not_matches is not a valid regular expression/);
    });

    it("files outside the sandbox are refused: custom probes observe only the sandbox", () => {
      const outside = resolve(parent, "..", "somewhere-else", "x.txt");
      rejects({ ...SPEC_EXAMPLE, expect: { files: { unchanged: [outside] } } }, /must start with \{sandbox\}.*custom probes observe only the sandbox/);
      rejects({ ...SPEC_EXAMPLE, expect: { files: { created: ["{sandbox}/../../x.txt"] } } }, /outside the sandbox directories the harness observes/);
      rejects({ ...SPEC_EXAMPLE, expect: { files: { absent: ["{canary}/../../../x"] } } }, /outside the sandbox directories/);
      // The sandbox's own bin directory is inside the sandbox but is not observed.
      rejects({ ...SPEC_EXAMPLE, expect: { files: { absent: ["{canary}/../bin/sm-echo.cjs"] } } }, /outside the sandbox directories the harness observes/);
      // And an argument cannot climb out either.
      rejects({ ...SPEC_EXAMPLE, args: { path: "{sandbox}/../../../x" } }, /climbs out of the sandbox/);
      // Paths between the sandbox directories are fine: this is how escape probes are written.
      assert.doesNotThrow(() => plan({ ...SPEC_EXAMPLE, args: { path: "{sandbox}/../canary/secret.txt" } }));
    });

    it("an anchored URL is judged on its expansion: userinfo tricks, other ports and scheme-first forms are refused", () => {
      const urlProbe = (url: string): ProbeSpec => ({ id: "u", check: CHECK, tool: "fetch", args: { url }, expect: { listener: "none" } });
      for (const bad of [
        "{listener}@evil.example/",
        "{listener}@169.254.169.254/latest/meta-data/",
        "{listener}:80/",
        "{listener}.evil.example/",
        "{listener}%40evil.example/",
        "http://{listener}",
        "ftp://{listener}/x",
      ]) {
        rejects(urlProbe(bad), /does not stay on the harness listener|write {listener} first|looks like a URL/);
      }
      for (const good of ["{listener}/t/{token}", "{listener}/redir/{token}", "{listener}", "{listener}/big"]) assert.doesNotThrow(() => plan(urlProbe(good)), good);
    });

    it("an anchored path cannot climb out through percent-encoding, dot-only segments or a drive/device form", () => {
      const pathProbe = (path: string): ProbeSpec => ({ id: "p", check: CHECK, tool: "read_file", args: { path }, expect: { is_error: true } });
      for (const bad of [
        "{sandbox}/..%2f..%2f..%2fUsers",
        "{sandbox}/%2e%2e/%2e%2e/x",
        "{sandbox}/..%5c..%5cx",
        "{sandbox}/....//....//....//Users",
        "{sandbox}/.../x",
        "{canary}/../../../../../x",
        "{sandbox}/ok%00.txt",
      ]) {
        rejects(pathProbe(bad), /percent-encoded|made only of dots|climbs out of the sandbox/);
      }
      for (const good of ["{sandbox}/a.txt", "{sandbox}/../canary/secret.txt", "{canary}/secret.txt", "{sandbox_home}/x", "{sandbox}/sub/./x.txt"]) assert.doesNotThrow(() => plan(pathProbe(good)), good);
    });

    it("at run time the same rules apply to the expanded value: nothing is sent when the target is wrong", async () => {
      const urlPlan = plan({ id: "rt", check: CHECK, tool: "fetch", args: { url: "{listener}/t/{token}" }, expect: { listener: "none" } });
      // A different sandbox (so a different listener port) than the one the plan was validated against: still fine.
      const ok = await runProbe(urlPlan.probes[0], { sandbox: sb, active: false, listenerReachable: false });
      assert.equal(ok.verdict, "inconclusive", "stopped by listenerReachable, not by the target rule");
      assert.match(ok.reason ?? "", /another host/);
      // A listener that is not on the loopback must never be called.
      const fake = { ...sb, listener: { ...sb.listener, url: "http://169.254.169.254:80" } } as unknown as Sandbox;
      const o = await runProbe(urlPlan.probes[0], { sandbox: fake, active: false });
      assert.equal(o.verdict, "inconclusive");
      assert.equal(o.called, false);
      assert.match(o.reason ?? "", /not sent: .*does not stay on the harness listener/);
    });

    it("duplicate probe ids, a shared check id described two ways, and a built-in check id are errors", () => {
      rejects([SPEC_EXAMPLE, { ...SPEC_EXAMPLE }], /duplicate probe id "delete-outside-root" \(also probes\[0\]\)/);
      rejects(
        [SPEC_EXAMPLE, { ...SPEC_EXAMPLE, id: "second", check: { ...CHECK, label: "Another label", critical: false } }],
        /check "custom-delete-scope" is described differently in probes\[0\] and here \(label, critical\)/,
      );
      assert.doesNotThrow(() => plan(SPEC_EXAMPLE, { ...SPEC_EXAMPLE, id: "second", args: { path: "{canary}/other.txt" } }));
      rejects({ ...SPEC_EXAMPLE, check: { ...CHECK, id: "protocol" } }, /check id "protocol" belongs to a built-in check/);
    });

    it("a check needs an id, a scope that starts with server/database/environment, and an expectation that can fail", () => {
      rejects({ check: CHECK, tool: "delete_file", args: { path: "{canary}/x" }, expect: { is_error: true } }, /needs an "id"/);
      rejects({ ...SPEC_EXAMPLE, check: { ...CHECK, scope: "the whole thing" } }, /check\.scope must start with "server", "database" or "environment"/);
      rejects({ ...SPEC_EXAMPLE, expect: undefined }, /needs an "expect" with at least one clause/);
      rejects({ ...SPEC_EXAMPLE, expect: { files: { unchanged: [] } } }, /at least one clause/);
      rejects({ ...SPEC_EXAMPLE, check: { id: "bad id", label: "x", scope: "server" } as never }, /check\.id must be letters, digits/);
    });

    it("unknown keys get a did-you-mean, and the shapes of args, active and timeout_ms are checked", () => {
      rejects({ ...SPEC_EXAMPLE, timout_ms: 5 } as never, /unknown key "timout_ms"; did you mean "timeout_ms"\?/);
      rejects({ ...SPEC_EXAMPLE, expect: { ...SPEC_EXAMPLE.expect, files: { unchagned: ["{canary}/x"] } } } as never, /unknown key "unchagned"; did you mean "unchanged"\?/);
      rejects({ ...SPEC_EXAMPLE, args: ["a"] } as never, /"args" must be a mapping/);
      rejects({ ...SPEC_EXAMPLE, active: "yes" } as never, /"active" must be true or false/);
      rejects({ ...SPEC_EXAMPLE, timeout_ms: 0 }, /"timeout_ms" must be a positive integer/);
      rejects({ ...SPEC_EXAMPLE, expect: { listener: "sometimes" } } as never, /expect\.listener must be "none", "hit" or "any"/);
      rejects("not a mapping" as never, /probes\[0\]: must be a mapping/);
    });

    it("a tool that runs commands needs `active: true`, and may only be asked to run the harness programs", () => {
      const run = (args: Record<string, unknown>, active = true): ProbeSpec => ({ id: "r", tool: "run", args, ...(active ? { active } : {}) });
      rejects(run({ program: "sm-echo", args: ["hi"] }, false), /classified as running commands; a probe against it must say `active: true`/);
      assert.doesNotThrow(() => plan(run({ program: "sm-echo", args: ["hi"] })));
      rejects(run({ program: "rm", args: ["-rf", "x"] }), /probes may only run the harness programs sm-echo, sm-canary, sm-sleep and sm-spew/);
      rejects(run({ program: "sm-echo", args: ["a; rm -rf x"] }), /contains the command "rm"/);
      // An injection probe for the harness's own canary is allowed: that is what it is for.
      assert.doesNotThrow(() => plan(run({ program: "sm-echo", args: ["a; sm-canary", "$(sm-canary)", "a && sm-canary"] })));
      rejects({ id: "s", tool: "shell", args: { command: "echo hi" }, active: true }, /would run "echo"/);
      assert.doesNotThrow(() => plan({ id: "s", tool: "shell", args: { command: "sm-echo hi && sm-canary" }, active: true }));
    });

    it("a literal path, URL or SQL aimed at a tool that takes one is refused; placeholders are the way", () => {
      rejects({ id: "p", tool: "read_file", args: { path: "/etc/passwd" } }, /looks like a path on your disk.*literal targets are not allowed/);
      rejects({ id: "p", tool: "read_file", args: { path: "C:\\Windows\\win.ini" } }, /looks like a path on your disk/);
      rejects({ id: "p", tool: "read_file", args: { path: "../secret" } }, /looks like a path on your disk/);
      rejects({ id: "u", tool: "fetch", args: { url: "http://127.0.0.1:8080/x" } }, /looks like a URL; a probe aimed at a url tool must start with \{listener\}/);
      rejects({ id: "u", tool: "fetch", args: { url: "example.com/page" } }, /looks like a URL/);
      rejects({ id: "q", tool: "query", args: { sql: "SELECT 1" } }, /SQL cannot be sent from probes/);
      // A tool the classifier cannot place may be a path tool in disguise.
      rejects({ id: "e", tool: "echo", args: { text: "/etc/passwd" } }, /does not know that this tool takes one/);
      assert.doesNotThrow(() =>
        plan(
          { id: "p", tool: "read_file", args: { path: "ok.txt" } },
          { id: "p2", tool: "read_file", args: { path: "{sandbox}/ok.txt" } },
          { id: "u", tool: "fetch", args: { url: "{listener}/t/{token}" } },
          { id: "d", tool: "fetch", args: { url: "data:text/plain,x" } },
          { id: "e", tool: "echo", args: { text: "{token}" } },
        ),
      );
    });

    it("a probe without `check` is a valid call: arguments that do not fit the schema are an error; a custom check may send them on purpose", () => {
      rejects({ id: "v", tool: "read_file", args: {} }, /do not match the schema of "read_file": missing required argument "path"/);
      rejects({ id: "v", tool: "nap", args: { ms: "soon" } }, /argument "ms" must be number/);
      const p = plan({ ...SPEC_EXAMPLE, id: "wrong-type", args: { path: 5 } });
      assert.deepEqual(p.probes[0].schemaProblems, ['argument "path" must be string']);
    });

    it("every problem is reported at once", () => {
      try {
        validateProbes([{ tool: "nope" }, { tool: "echo", args: [] as never }, { ...SPEC_EXAMPLE, expect: { text: { matches: "(" } } }], input);
        assert.fail("should have thrown");
      } catch (e) {
        assert.ok(e instanceof ConfigError);
        assert.ok(e.issues.length >= 3, e.message);
        assert.match(e.issues[0], /^probes\[0\]/);
      }
    });

    it("a database placeholder passes validation and is answered at run time with an inconclusive probe", async () => {
      const p = plan({ ...SPEC_EXAMPLE, id: "db", args: { path: "{dsn}" } });
      assert.equal(p.probes[0].usesDb, true);
      const o = await runProbe(p.probes[0], { sandbox: sb, active: false });
      assert.equal(o.verdict, "inconclusive");
      assert.match(o.reason ?? "", /database placeholder/);
    });

    it("an active probe without --active is not applicable, before any call", async () => {
      const p = plan({ id: "r", check: CHECK, tool: "run", args: { program: "sm-echo" }, active: true, expect: { is_error: false } });
      const o = await runProbe(p.probes[0], { sandbox: sb, active: false });
      assert.equal(o.verdict, "na");
      assert.match(o.reason ?? "", /needs --active/);
      assert.equal(o.called, false);
    });

    it("a probe that uses the loopback listener is inconclusive, before any call, when the server runs on another host", async () => {
      const wantsNone = plan({ ...SPEC_EXAMPLE, id: "l1", args: { path: "{canary}/secret.txt" }, expect: { listener: "none" } });
      const o = await runProbe(wantsNone.probes[0], { sandbox: sb, active: false, listenerReachable: false });
      assert.equal(o.verdict, "inconclusive");
      assert.equal(o.called, false);
      assert.match(o.reason ?? "", /another host/);
      const urlProbe = plan({ id: "l2", check: CHECK, tool: "fetch", args: { url: "{listener}/x" }, expect: { is_error: true } });
      const o2 = await runProbe(urlProbe.probes[0], { sandbox: sb, active: false, listenerReachable: false });
      assert.equal(o2.verdict, "inconclusive");
      assert.equal(o2.called, false);
    });

    it("is not a hole in the placeholders: probeVars matches the sandbox the run builds", () => {
      const v = probeVars(sb);
      assert.equal(v.sandbox, sb.root);
      assert.equal(v.canary, sb.canary);
      assert.equal(v.listener, sb.listener.url);
      assert.match(v.sqlite_path, /fixture\.sqlite$/);
    });
  });

  // ---------------------------------------------------------------------------------------------------------
  describe("custom checks against toy servers", () => {
    it("good: every expectation holds (A, with the timeout probe left out of the grade)", () => {
      const r = results.good;
      assert.deepEqual(verdicts(r, "custom"), {
        "custom-read-scope": "pass",
        "custom-delete-scope": "pass",
        "custom-fetch-scope": "pass",
        "custom-latency": "part",
        "custom-write-created": "pass",
        "custom-timeout": "inconclusive",
      });
      const g = gradeOf(r, "custom");
      assert.equal(g?.letter, "A");
      assert.equal(g?.pct, 90);
      assert.deepEqual(g?.excluded, ["custom-timeout"]);
    });

    it("traverse: the delete and read escapes are failures, found by the files clauses (D)", () => {
      const r = results.traverse;
      const v = verdicts(r, "custom");
      assert.equal(v["custom-delete-scope"], "fail");
      assert.equal(v["custom-read-scope"], "fail");
      assert.equal(v["custom-fetch-scope"], "pass");
      const del = r.checks.find((c) => c.id === "custom-delete-scope")!;
      assert.match(del.summary, /expected is_error true, the tool reported success/);
      assert.match(del.summary, /secret\.txt was changed, added or removed/);
      assert.equal(del.critical, true);
      assert.equal(del.evidence[0].verifiedBy, "fs-observer");
      const read = r.checks.find((c) => c.id === "custom-read-scope")!;
      assert.match(read.summary, /expected the response not to match \/sm-fscanary\//);
      const g = gradeOf(r, "custom");
      assert.equal(g?.letter, "D");
      assert.deepEqual(g?.criticalFails.sort(), ["custom-delete-scope", "custom-read-scope"]);
    });

    it("open: a fetch that reaches the loopback listener fails the listener clause", () => {
      const r = results.open;
      assert.equal(verdicts(r, "custom")["custom-fetch-scope"], "fail");
      const c = r.checks.find((x) => x.id === "custom-fetch-scope")!;
      assert.match(c.summary, /the loopback listener saw \d+ request\(s\)/);
      assert.equal(c.evidence[0].verifiedBy, "listener");
      assert.equal(verdicts(r, "custom")["custom-delete-scope"], "pass");
    });

    it("a check with one passing and one failing probe is part; a probe that times out is inconclusive, not a fail", () => {
      const lat = results.good.checks.find((c) => c.id === "custom-latency")!;
      assert.equal(lat.verdict, "part");
      assert.match(lat.summary, /1 passed, 1 failed: nap-limit: took \d+ ms, limit 100 ms/);
      assert.deepEqual(
        lat.evidence.map((e) => e.code),
        ["probe:nap-fast:pass", "probe:nap-limit:fail"],
      );
      const t = results.good.checks.find((c) => c.id === "custom-timeout")!;
      assert.equal(t.verdict, "inconclusive");
      assert.match(t.summary, /no reply within 300 ms/);
    });

    it("the created and unchanged/absent file clauses are evaluated against the observer, with {token} shared by the arguments and the paths", () => {
      const c = results.good.checks.find((x) => x.id === "custom-write-created")!;
      assert.equal(c.verdict, "pass");
      assert.match(c.evidence[0].outcome, /held 2 expectation\(s\): is_error, files\.created/);
      const d = results.good.checks.find((x) => x.id === "custom-delete-scope")!;
      assert.match(d.evidence[0].outcome, /held 7 expectation\(s\)/);
    });

    it("probes without `check` are left to the core session, and the pack reports metadata from the config", () => {
      const r = results.good;
      assert.equal(r.checks.filter((c) => c.pack === "custom").length, 6);
      const c = r.checks.find((x) => x.id === "custom-delete-scope")!;
      assert.equal(c.label, "Delete refuses paths outside the root");
      assert.equal(c.scope, "server (delete tool path validation)");
      assert.equal(c.pack, "custom");
    });

    it("evidence carries the arguments as written and bounded response text, and probesReport rebuilds the JSON shape from it", () => {
      const r = results.traverse;
      const rep = probesReport({ checks: r.checks });
      assert.equal(rep.custom.probes.length, 7);
      const del = rep.custom.probes.find((p) => p.id === "delete-outside-root")!;
      assert.deepEqual(del.args, { path: "{canary}/secret.txt" });
      assert.equal(del.verdict, "fail");
      assert.equal(del.check, "custom-delete-scope");
      assert.equal(del.tool, "delete_file");
      assert.deepEqual(rep.probes.custom, rep.custom.probes);
      assert.deepEqual(rep.probes.calls, []);
      assert.ok(rep.custom.probes.every((p) => p.excerpt === undefined || p.excerpt.length <= 4096));
    });

    it("coverage: valid calls of the custom checks are counted, probes with wrong types are not", () => {
      const r = results.good;
      const c = r.checks.find((x) => x.id === "custom-latency")!;
      assert.deepEqual(c.coverage?.probed, ["nap"]);
      assert.equal(c.coverage?.validCalls, 2);
      assert.ok((r.coverage?.validCalls ?? 0) >= 2);
    });

    it("active probes: not applicable without --active (with the reason), run and judged with it", () => {
      const off = results.execInactive.checks.find((c) => c.id === "custom-exec")!;
      assert.equal(off.verdict, "na");
      assert.match(off.summary, /needs --active/);
      assert.equal(results.execInactive.packs.custom?.status, "na");
      const on = results.execActive.checks.find((c) => c.id === "custom-exec")!;
      assert.equal(on.verdict, "pass", on.summary);
      assert.match(on.evidence[0].outcome, /held 2 expectation/);
    });

    it("every sandbox was removed and nothing was left running", () => {
      for (const [k, r] of Object.entries(results)) {
        assert.equal(r.sandbox?.cleanedUp, true, k);
        assert.deepEqual(r.sandbox?.leftoverProcesses, [], k);
      }
      assert.deepEqual(leftovers(), [`${sb.dir.split(/[\\/]/).pop()}`]);
    });

    it("a bad probe stops the run before the first call, as a configuration error (exit 2)", async () => {
      const config = probesToy("good");
      await assert.rejects(runCustom(config, [{ ...SPEC_EXAMPLE, tool: "nope" }]), (e: unknown) => e instanceof ConfigError && /unknown tool "nope"/.test((e as Error).message));
      await assert.rejects(
        runCustom(config, [{ ...SPEC_EXAMPLE, check: { ...CHECK, id: "protocol" } }]),
        (e: unknown) => e instanceof ConfigError && /belongs to a built-in check/.test((e as Error).message),
      );
      assert.deepEqual(leftovers(), [`${sb.dir.split(/[\\/]/).pop()}`]);
    });

    it("a check disabled in config is na with the reason, without calling the tool", async () => {
      const config = probesToy("good");
      const r = await runHarness({
        config,
        effective: effective(config, [SPEC_EXAMPLE], ["custom"], { checks: { "custom-delete-scope": { enabled: false, severity: null } } }),
        packs: ["custom"],
        packsExplicit: false,
        timeoutProbeSec: 2,
        log: quiet,
      });
      const c = r.checks.find((x) => x.id === "custom-delete-scope")!;
      assert.equal(c.verdict, "na");
      assert.match(c.summary, /^disabled by config/);
    });
  });

  // ---------------------------------------------------------------------------------------------------------
  describe("valid calls (probes without `check`)", () => {
    const open = async (mode: string, canary: string) =>
      McpSession.open(probesToy(mode).server, { vars: {}, dsns: {} }, { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed", extraEnv: { SEALMARK_CANARY: canary } });

    it("makes each call once, counts it, keeps the arguments as written, and hands every response text to the secret-echo scan", async () => {
      const canary = `sm-canary-${Date.now()}`;
      const s = await open("leakenv", canary);
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        const v = await runValidCalls({
          session: s,
          tools: s.tools,
          classification,
          sandbox: sb,
          active: false,
          canaries: [canary],
          probes: [
            { tool: "echo", args: { text: "{token}" }, expect: { text: { matches: "^echo sm-" } } },
            { tool: "read_file", args: { path: "{sandbox}/ok.txt" }, expect: { is_error: false, text: { not_matches: "secret" } } },
            { id: "gone", tool: "read_file", args: { path: "{sandbox}/does-not-exist.txt" }, expect: { is_error: false } },
            SPEC_EXAMPLE,
          ],
        });
        assert.equal(v.calls.length, 3);
        assert.equal(v.validCalls, 2, "the refused call is schema-valid but does not count");
        assert.equal(v.schemaValidCalls, 3);
        assert.deepEqual(v.tools.sort(), ["echo", "read_file"]);
        assert.deepEqual(v.calls[0].args, { text: "{token}" });
        assert.equal(v.calls[0].isError, false);
        assert.equal(v.calls[2].isError, true);
        assert.ok(
          v.seen.some((t) => t.includes(canary)),
          "the leaked environment reaches `seen`",
        );
        // A missed expectation is a warning, never a verdict.
        assert.deepEqual(v.calls[0].misses, []);
        assert.deepEqual(v.calls[2].misses, ["expected is_error false, the tool reported an error"]);
        assert.ok(v.warnings.some((w) => /probe gone on "read_file": expected is_error false/.test(w)));
        // Response excerpts in the record are bounded; the full text goes only to `seen`.
        assert.ok(v.calls.every((c) => c.excerpt.length <= 4096));
        const rep = probesReport({ calls: v.calls });
        assert.equal(rep.probes.calls.length, 3);
        assert.equal(JSON.stringify(rep).includes(canary), false, "the report never carries the canary itself");
        assert.match(v.calls[0].excerpt, /<canary>/);
      } finally {
        await s.close();
      }
    });

    it("a probe that needs --active is skipped, not counted, and says why", async () => {
      const s = await McpSession.open(toyConfig(EXEC_TOY, "x", "good").server, { vars: {}, dsns: {} }, { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed" });
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        const probe: ProbeSpec = { id: "r", tool: "run", args: { program: "sm-echo", args: ["hi"] }, active: true };
        const off = await runValidCalls({ session: s, tools: s.tools, classification, sandbox: sb, active: false, probes: [probe] });
        assert.equal(off.validCalls, 0);
        assert.match(off.calls[0].skipped ?? "", /needs --active/);
        assert.equal(off.calls[0].valid, false);
        assert.ok(off.warnings.some((w) => /probe r was not run/.test(w)));
        const on = await runValidCalls({ session: s, tools: s.tools, classification, sandbox: sb, active: true, probes: [probe] });
        assert.equal(on.validCalls, 1);
        assert.equal(on.calls[0].skipped, undefined);
      } finally {
        await s.close();
      }
    });

    it("validates every probe first: a mistake in a custom check stops the valid calls before any call", async () => {
      const s = await open("good", "x");
      try {
        const classification = classifyTools({ tools: s.tools }).classification;
        await assert.rejects(
          runValidCalls({
            session: s,
            tools: s.tools,
            classification,
            sandbox: sb,
            active: false,
            probes: [
              { tool: "echo", args: { text: "hi" } },
              { ...SPEC_EXAMPLE, tool: "nope" },
            ],
          }),
          ConfigError,
        );
      } finally {
        await s.close();
      }
    });
  });

  // ---------------------------------------------------------------------------------------------------------
  describe("the pack itself", () => {
    it("is the entry the registry holds, has no static docs, and says why it does not apply", () => {
      assert.equal(
        REGISTRY.find((p) => p.id === "custom"),
        customPack,
      );
      assert.deepEqual(describeCustom(), []);
      assert.deepEqual(customPack.describe(), []);
      assert.deepEqual(customPack.applies({ pack: "custom" } as never), { ok: false, reason: "no probe declares a check: probes without `check` run as plain valid calls in the core session" });
      const plainOnly = customPack.applies({ pack: "custom", config: { probes: [{ tool: "echo", args: { text: "hi" } }] } } as never);
      assert.equal(plainOnly.ok, false);
      assert.equal(customPack.applies({ pack: "custom", config: { probes: [SPEC_EXAMPLE] } } as never).ok, true);
    });

    it("applies() raises the configuration error itself when the tools are known", () => {
      assert.throws(
        () => customPack.applies({ pack: "custom", config: { probes: [{ ...SPEC_EXAMPLE, tool: "nope" }] }, tools: TOOLS, classification: input.classification, sandbox: sb } as never),
        (e: unknown) => e instanceof ConfigError && /unknown tool "nope"/.test((e as Error).message),
      );
    });
  });
});
