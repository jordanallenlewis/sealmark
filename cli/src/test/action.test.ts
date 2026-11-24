import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { siteBadgeSnippets } from "../badge-snippet.js";
import { CLI_FLAGS } from "../cli-spec.js";
import { CLI, TOY, hermeticEnv } from "./helpers.js";

// Run from dist/test, so the repository root is three levels up.
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const ACTION_DIR = join(ROOT, "action");
const RUN_MJS = join(ACTION_DIR, "run.mjs");
const text = (path: string): string => readFileSync(path, "utf8");

const action = parse(text(join(ACTION_DIR, "action.yml"))) as {
  inputs: Record<string, { required?: boolean; default?: string }>;
  outputs: Record<string, { value: string }>;
  runs: { using: string; steps: Record<string, any>[] };
};
const readme = text(join(ACTION_DIR, "README.md"));
const runSource = text(RUN_MJS);

const inputNames = Object.keys(action.inputs);
const outputNames = Object.keys(action.outputs);
/** The first column of a README table row: | `name` | ... */
const tableNames = (md: string): string[] => [...md.matchAll(/^\| `([a-z-]+)` \|/gm)].map((m) => m[1]);
const sectionOf = (md: string, heading: string): string => md.split(new RegExp(`^## ${heading}\\s*$`, "m"))[1]?.split(/^## /m)[0] ?? "";

describe("action.yml is a composite action whose inputs, outputs and README agree", () => {
  it("is composite and names the action", () => {
    assert.equal(action.runs.using, "composite");
    assert.ok(inputNames.length >= 17, "every input of the design is present");
    for (const name of ["version", "start", "url", "config", "pack", "fail-under", "soft-fail", "baseline", "write-baseline", "fail-on", "bearer-env", "args", "report-dir", "upload-sarif", "artifact", "badge", "badge-id", "comment", "github-token", "node-version", "working-directory"]) {
      assert.ok(inputNames.includes(name), `input ${name}`);
    }
    for (const name of ["exit-code", "report-dir", "json", "sarif", "junit", "summary", "badge", "shields", "badge-text", "badge-markdown", "badge-html", "badge-rst", "comment", "comment-url"]) assert.ok(outputNames.includes(name), `output ${name}`);
  });

  it("every input is optional and has the documented default", () => {
    for (const [name, def] of Object.entries(action.inputs)) assert.equal(def.required, false, `${name} must say required: false`);
    assert.equal(action.inputs["soft-fail"].default, "false");
    assert.equal(action.inputs["report-dir"].default, "sealmark-report");
    assert.equal(action.inputs["upload-sarif"].default, "true");
    assert.equal(action.inputs.artifact.default, "true");
    assert.equal(action.inputs["node-version"].default, "24");
    assert.equal(action.inputs["working-directory"].default, ".");
    assert.equal(action.inputs.badge.default, "auto");
    assert.equal(action.inputs["badge-id"].default, undefined);
    assert.equal(action.inputs.comment.default, "false", "the action never comments unless asked");
    assert.equal(action.inputs["github-token"].default, "${{ github.token }}");
  });

  it("the version input defaults to the version in cli/package.json", () => {
    const pkg = JSON.parse(text(fileURLToPath(new URL("../../package.json", import.meta.url)))) as { version: string };
    assert.equal(action.inputs.version.default, pkg.version);
  });

  it("the README lists every input and every output, and nothing the action does not have", () => {
    const inputs = tableNames(sectionOf(readme, "Inputs"));
    const outputs = tableNames(sectionOf(readme, "Outputs"));
    for (const name of inputNames) assert.ok(inputs.includes(name), `README inputs table is missing ${name}`);
    for (const name of inputs) assert.ok(inputNames.includes(name), `README lists an input action.yml does not have: ${name}`);
    for (const name of outputNames) assert.ok(outputs.includes(name), `README outputs table is missing ${name}`);
    for (const name of outputs) assert.ok(outputNames.includes(name), `README lists an output action.yml does not have: ${name}`);
  });

  it("the README says what must be true before uses: works", () => {
    // The repository is public (since 2026-11), so the examples name the real owner and pin a release tag that matches the CLI version.
    const pkg = JSON.parse(text(fileURLToPath(new URL("../../package.json", import.meta.url)))) as { version: string };
    const uses = [...readme.matchAll(/^\s*-?\s*uses: (\S+\/sealmark\/action@\S+)/gm)].map((m) => m[1]);
    assert.ok(uses.length >= 2, "the workflow example and the bearer example both show a uses: line");
    for (const u of uses) assert.equal(u, `jordanallenlewis/sealmark/action@v${pkg.version}`, `${u}: the real owner and the tag of this CLI version`);
    assert.ok(!/<owner>|action@main/.test(readme), "no placeholder owner and no unpinned @main");
    assert.match(readme, /is on npm/);
    assert.match(readme, /contents: read/);
    assert.match(readme, /security-events: write/);
    assert.match(readme, /Code Security/);
    assert.match(readme, /upload-sarif: 'false'/);
    assert.match(readme, /Not verified/);
  });

  it("every output is a steps.run.outputs value the script writes", () => {
    for (const [name, def] of Object.entries(action.outputs)) {
      // The comment URL comes from the comment step, the only step that holds the token.
      if (name === "comment-url") {
        assert.equal(def.value, "${{ steps.comment.outputs.url }}");
        continue;
      }
      assert.equal(def.value, `\${{ steps.run.outputs.${name} }}`);
      assert.ok(runSource.includes(name === "json" || name === "sarif" || name === "junit" || name === "summary" ? name : `"${name}"`), `run.mjs never writes ${name}`);
    }
  });

  it("setup-node is pinned to the SHA the CLI workflow uses; the other actions say to pin them", () => {
    const sha = (text(join(ROOT, ".github", "workflows", "cli.yml")).match(/actions\/setup-node@([0-9a-f]{40})/) ?? [])[1];
    assert.ok(sha, "cli.yml pins setup-node");
    const steps = action.runs.steps;
    assert.equal(steps[0].uses, `actions/setup-node@${sha}`);
    const source = text(join(ACTION_DIR, "action.yml"));
    const note = "# pin to a commit SHA before relying on this; no network was available to resolve one when this was written";
    for (const uses of ["github/codeql-action/upload-sarif@v3", "actions/upload-artifact@v4"]) {
      assert.ok(source.includes(`${note}\n    - uses: ${uses}`), `${uses} must follow the pin-me comment`);
    }
  });

  it("the run step maps every input to SEALMARK_INPUT_<NAME> and run.mjs reads only mapped ones", () => {
    const run = action.runs.steps.find((s) => s.id === "run")!;
    assert.equal(run.shell, "bash");
    assert.equal(run["working-directory"], "${{ inputs.working-directory }}");
    assert.equal(run.run, 'node "${{ github.action_path }}/run.mjs"');
    const mapped = Object.keys(run.env).sort();
    // Every input but the token: Sealmark and the server under test run in this step, so it never holds github-token.
    assert.deepEqual(mapped, inputNames.filter((n) => n !== "github-token").map((n) => `SEALMARK_INPUT_${n.toUpperCase().replaceAll("-", "_")}`).sort());
    assert.ok(!Object.values(run.env).some((v) => String(v).includes("github-token") || String(v).includes("github.token")), "no token in the run step");
    for (const [name, value] of Object.entries(run.env)) assert.match(String(value), /^\$\{\{ inputs\.[a-z-]+ \}\}$/, name);
    const read = new Set([...runSource.matchAll(/(?:input|get|one)\("([A-Z_]+)"|, "([A-Z_]+)"\)/g)].map((m) => `SEALMARK_INPUT_${m[1] ?? m[2]}`));
    for (const name of read) assert.ok(mapped.includes(name), `run.mjs reads ${name}, which action.yml does not map`);
  });

  it("only the comment step gets the token, only with comment, after the run step", () => {
    const steps = action.runs.steps;
    const at = steps.findIndex((s) => s.id === "comment");
    assert.ok(at > steps.findIndex((s) => s.id === "run"), "the comment step comes after the run step");
    const step = steps[at];
    assert.equal(step.if, "always() && inputs.comment == 'true' && steps.run.outputs.comment != ''");
    assert.deepEqual(step.env, { SEALMARK_INPUT_GITHUB_TOKEN: "${{ inputs.github-token }}", SEALMARK_COMMENT_FILE: "${{ steps.run.outputs.comment }}" });
    assert.equal(step.run, 'node "${{ github.action_path }}/post-comment.mjs"');
    const holders = steps.filter((s) => JSON.stringify(s).includes("inputs.github-token"));
    assert.deepEqual(holders.map((s) => s.id), ["comment"], "no other step references the token");
  });

  it("the SARIF upload and the artifact still run after a failed run", () => {
    const [sarif, artifact] = action.runs.steps.filter((s) => /upload-(sarif|artifact)@/.test(s.uses ?? ""));
    assert.equal(sarif.if, "always() && inputs.upload-sarif == 'true' && steps.run.outputs.sarif != ''");
    assert.equal(sarif.with.sarif_file, "${{ steps.run.outputs.sarif }}");
    assert.equal(artifact.if, "always() && inputs.artifact == 'true'");
    assert.equal(artifact.with.name, "sealmark-report");
    assert.equal(artifact.with.path, "${{ inputs.working-directory }}/${{ inputs.report-dir }}");
  });
});

describe("run.mjs emits only flags the CLI has", () => {
  it("every --flag literal is in CLI_FLAGS", () => {
    const known = new Set(CLI_FLAGS.map((f) => f.name));
    const used = [...runSource.matchAll(/"--([a-z][a-z-]*)"/g)].map((m) => m[1]);
    assert.ok(used.length >= 12, `expected the flags of the design, found ${used.join(", ")}`);
    for (const flag of used) assert.ok(known.has(flag), `--${flag} is not a sealmark flag`);
  });
});

describe("run.mjs runs a real Sealmark and reports like the CLI", () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-action-"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  /** Runs run.mjs the way the composite step does: inputs as SEALMARK_INPUT_*, outputs and the step summary in files. */
  function act(name: string, env: Record<string, string>, bin: string = CLI) {
    mkdirSync(join(dir, name), { recursive: true });
    // process.cwd() in the child is the real path, which differs from a temp path behind a symlink (macOS /var).
    const work = realpathSync(join(dir, name));
    const outFile = join(work, "out");
    const sumFile = join(work, "sum");
    const r = spawnSync(process.execPath, [RUN_MJS], {
      cwd: work,
      encoding: "utf8",
      timeout: 120_000,
      env: hermeticEnv({ SEALMARK_ACTION_BIN: bin, GITHUB_OUTPUT: outFile, GITHUB_STEP_SUMMARY: sumFile, ...env }),
    });
    const outputs: Record<string, string> = {};
    if (existsSync(outFile)) {
      // name=value lines, and GitHub's name<<DELIMITER ... DELIMITER form for a value with line breaks.
      const lines = text(outFile).split("\n");
      for (let i = 0; i < lines.length; i++) {
        const heredoc = /^([a-z-]+)<<(\S+)$/.exec(lines[i]);
        if (heredoc) {
          const end = lines.indexOf(heredoc[2], i + 1);
          assert.ok(end > i, `output ${heredoc[1]} has no closing delimiter`);
          outputs[heredoc[1]] = lines.slice(i + 1, end).join("\n");
          i = end;
        } else if (lines[i].includes("=")) outputs[lines[i].slice(0, lines[i].indexOf("="))] = lines[i].slice(lines[i].indexOf("=") + 1);
      }
    }
    return { code: r.status, stdout: r.stdout, stderr: r.stderr, outputs, summary: existsSync(sumFile) ? text(sumFile) : "", work };
  }
  const toy = (mode: string) => ({ SEALMARK_INPUT_START: `${process.execPath} ${TOY} --mode ${mode}`, SEALMARK_INPUT_PACK: "core" });

  it("exit 0 with the gate off: outputs name the report files, the step summary has the grade", () => {
    const r = act("pass", { ...toy("nosql"), SEALMARK_INPUT_FAIL_UNDER: "none", SEALMARK_INPUT_REPORT_DIR: "rep", SEALMARK_INPUT_ARGS: "--timeout-probe 2" });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.outputs["exit-code"], "0");
    assert.equal(r.outputs["report-dir"], join(r.work, "rep"));
    for (const key of ["json", "sarif", "junit"]) assert.ok(r.outputs[key] && existsSync(r.outputs[key]), `${key} path exists: ${r.outputs[key]}`);
    assert.match(r.outputs.summary, /^core [A-F]$/);
    assert.match(r.summary, /^## Sealmark\n\n```text\n[\s\S]*core[\s\S]*\n```\n/);
    // One server from start: badge auto writes the self-reported badge; --timeout-probe 2 makes the run CUSTOM, which earns no badge.
    for (const key of ["badge", "shields"]) assert.ok(r.outputs[key] && existsSync(r.outputs[key]), `${key} path exists: ${r.outputs[key]}`);
    assert.equal(r.outputs.badge, join(r.work, "rep", "sealmark-report.badge.svg"));
    assert.match(r.outputs["badge-text"], /^sealmark \S+: no badge: custom run$/);
    assert.ok(text(r.outputs.badge).startsWith("<svg "), "the badge output is the CLI's own SVG");
    assert.match(r.summary, /\n### Badge\n\nSelf-reported badge of this run: `sealmark \S+: no badge: custom run`\n/);
    for (const key of ["badge-markdown", "badge-html", "badge-rst"]) assert.equal(r.outputs[key], "", `${key} is empty without badge-id`);
  });

  it("badge-id: the outputs and the job summary carry the same sealmark.dev snippets as sealmark badge --id", () => {
    const r = act("badgeid", { ...toy("nosql"), SEALMARK_INPUT_FAIL_UNDER: "none", SEALMARK_INPUT_BADGE: "false", SEALMARK_INPUT_BADGE_ID: "filesystem", SEALMARK_INPUT_ARGS: "--timeout-probe 2" });
    assert.equal(r.code, 0, r.stderr);
    const want = siteBadgeSnippets("filesystem").variants.badge!;
    assert.equal(r.outputs["badge-markdown"], want.markdown);
    assert.equal(r.outputs["badge-html"], want.html);
    assert.equal(r.outputs["badge-rst"], want.rst, "the three-line rst survives the multi-line output form");
    assert.equal(r.outputs.badge, "", "badge: false writes no self-reported badge");
    assert.equal(r.outputs["badge-text"], "");
    assert.ok(r.summary.includes(`\`\`\`markdown\n${want.markdown}\n\`\`\``));
    assert.ok(r.summary.includes(`\`\`\`rst\n${want.rst}\n\`\`\``));
    assert.match(r.summary, /exists only while that server's latest fleet run earns a badge, which https:\/\/sealmark\.dev\/results\/filesystem\/ then shows; otherwise it is a 404/);
    assert.doesNotMatch(r.summary, /Self-reported badge/);
    assert.ok(!r.stdout.includes("--start"), "the command line is not echoed");
  });

  it("exits with the CLI's code: a toy below the gate exits 1 and says so in the outputs", () => {
    const r = act("gate", { ...toy("poison"), SEALMARK_INPUT_FAIL_UNDER: "A", SEALMARK_INPUT_ARGS: "--timeout-probe 2" });
    assert.equal(r.code, 1, r.stderr);
    assert.equal(r.outputs["exit-code"], "1");
    assert.ok(existsSync(r.outputs.json), "the reports are written when the gate fails");
    assert.ok(existsSync(r.outputs.sarif));
  });

  it("soft-fail keeps the job green", () => {
    const r = act("soft", { ...toy("poison"), SEALMARK_INPUT_FAIL_UNDER: "A", SEALMARK_INPUT_SOFT_FAIL: "true", SEALMARK_INPUT_ARGS: "--timeout-probe 2" });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.outputs["exit-code"], "0");
  });

  it("with no start, url or config it exits 2 and says what to set", () => {
    const r = act("empty", { SEALMARK_INPUT_PACK: "core" });
    assert.equal(r.code, 2);
    assert.ok(`${r.stdout}${r.stderr}`.includes("sealmark action: set start and url (or config)"));
    assert.deepEqual(r.outputs, {});
  });

  /** A stand-in for the CLI: records its argv and, with a report in SEALMARK_FAKE_REPORT, writes it into --out-dir. */
  function fakeBin(name: string): { bin: string; argvFile: string } {
    const argvFile = join(dir, `${name}.argv.json`);
    const bin = join(dir, `${name}.mjs`);
    writeFileSync(
      bin,
      [
        `import { mkdirSync, writeFileSync } from "node:fs";`,
        `import { join } from "node:path";`,
        `const argv = process.argv.slice(2);`,
        `writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(argv));`,
        `if (process.env.SEALMARK_FAKE_REPORT) {`,
        `  const dir = argv[argv.indexOf("--out-dir") + 1];`,
        `  mkdirSync(dir, { recursive: true });`,
        `  writeFileSync(join(dir, "sealmark-report.json"), process.env.SEALMARK_FAKE_REPORT);`,
        `}`,
        `process.exit(Number(process.env.SEALMARK_FAKE_EXIT ?? 0));`,
      ].join("\n"),
    );
    return { bin, argvFile };
  }

  it("bearer-env passes the literal ${NAME}; the token value never reaches argv or any output", () => {
    const fake = fakeBin("bearer");
    const token = "tok-9f8e7d6c5b4a-do-not-print";
    const r = act("bearer", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_INPUT_BEARER_ENV: "MY_TOKEN", MY_TOKEN: token }, fake.bin);
    assert.equal(r.code, 0, r.stderr);
    const argv = JSON.parse(text(fake.argvFile)) as string[];
    const at = argv.indexOf("--bearer");
    assert.ok(at >= 0, "--bearer is passed");
    assert.equal(argv[at + 1], "${MY_TOKEN}");
    assert.ok(!argv.includes(token) && !argv.some((a) => a.includes(token)), "no argv element carries the token value");
    assert.ok(![r.stdout, r.stderr, text(join(r.work, "out"))].some((s) => s.includes(token)), "the token is in no output");
    assert.ok(r.stdout.includes("MY_TOKEN"), "the variable name may be printed");
  });

  it("a bearer-env that is not a variable name is refused without echoing it", () => {
    const fake = fakeBin("badbearer");
    const pasted = "pasted-token.value-123";
    const r = act("badbearer", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_INPUT_BEARER_ENV: pasted }, fake.bin);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /bearer-env takes the NAME of an environment variable/);
    assert.ok(!`${r.stdout}${r.stderr}`.includes(pasted));
    assert.ok(!existsSync(fake.argvFile), "Sealmark was not started");
  });

  it("builds argv from every input in order and ends with the report formats", () => {
    const fake = fakeBin("argv");
    const r = act(
      "argv",
      {
        SEALMARK_INPUT_START: "node server.js",
        SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp",
        SEALMARK_INPUT_CONFIG: "sealmark.yaml",
        SEALMARK_INPUT_PACK: "core, fs ,",
        SEALMARK_INPUT_FAIL_UNDER: "B",
        SEALMARK_INPUT_SOFT_FAIL: "true",
        SEALMARK_INPUT_BASELINE: "base.json",
        SEALMARK_INPUT_WRITE_BASELINE: "next.json",
        SEALMARK_INPUT_FAIL_ON: "regressions,drift",
        SEALMARK_INPUT_ARGS: `--header "X-Team: a b" --name 'two words' --active ""`,
        SEALMARK_INPUT_REPORT_DIR: "out/reports",
      },
      fake.bin,
    );
    assert.equal(r.code, 0, r.stderr);
    const argv = JSON.parse(text(fake.argvFile)) as string[];
    assert.deepEqual(argv, [
      "run",
      "--start", "node server.js",
      "--url", "http://127.0.0.1:1/mcp",
      "--config", "sealmark.yaml",
      "--pack", "core",
      "--pack", "fs",
      "--fail-under", "B",
      "--soft-fail",
      "--baseline", "base.json",
      "--write-baseline", "next.json",
      "--fail-on", "regressions,drift",
      "--header", "X-Team: a b",
      "--name", "two words",
      "--active",
      "",
      "--format", "summary,json,junit,sarif",
      "--out-dir", join(r.work, "out", "reports"),
    ]);
  });

  it("badge auto adds the badge formats only for a run sure to grade one server; true and false decide; anything else exits 2", () => {
    const formatsOf = (name: string, env: Record<string, string>): string => {
      const fake = fakeBin(name);
      const r = act(name, env, fake.bin);
      assert.equal(r.code, 0, r.stderr);
      const argv = JSON.parse(text(fake.argvFile)) as string[];
      return argv[argv.indexOf("--format") + 1];
    };
    const url = { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp" };
    const withBadge = "summary,json,junit,sarif,badge,shields";
    const without = "summary,json,junit,sarif";
    assert.equal(formatsOf("b-url", url), withBadge, "url alone is one server");
    assert.equal(formatsOf("b-start", { SEALMARK_INPUT_START: "node s.js" }), withBadge, "start alone is one server");
    assert.equal(formatsOf("b-config", { SEALMARK_INPUT_CONFIG: "sealmark.yaml" }), without, "a config may hold several servers");
    assert.equal(formatsOf("b-config-url", { ...url, SEALMARK_INPUT_CONFIG: "sealmark.yaml" }), without);
    assert.equal(formatsOf("b-server", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_ARGS: "--server api" }), withBadge, "--server <name> picks one");
    assert.equal(formatsOf("b-server-eq", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_ARGS: "--server=api" }), withBadge);
    assert.equal(formatsOf("b-server-all", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_ARGS: "--server all" }), without, "--server all is several");
    assert.equal(formatsOf("b-server-last", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_ARGS: "--server api --server all" }), without, "the CLI keeps the last --server");
    assert.equal(formatsOf("b-server-last2", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_ARGS: "--server=all --server api" }), withBadge);
    assert.equal(formatsOf("b-false", { ...url, SEALMARK_INPUT_BADGE: "false" }), without);
    assert.equal(formatsOf("b-true", { SEALMARK_INPUT_CONFIG: "sealmark.yaml", SEALMARK_INPUT_BADGE: "TRUE" }), withBadge, "true always asks; the CLI decides");
    for (const [name, env, msg] of [
      ["b-bad", { ...url, SEALMARK_INPUT_BADGE: "yes" }, /badge: expected auto, true or false/],
      ["b-badid", { ...url, SEALMARK_INPUT_BADGE_ID: "https://sealmark.dev/results/x/" }, /badge-id takes a sealmark\.dev server id/],
      ["b-badid2", { ...url, SEALMARK_INPUT_BADGE_ID: "My_Server" }, /badge-id takes a sealmark\.dev server id/],
    ] as const) {
      const fake = fakeBin(name);
      const r = act(name, env, fake.bin);
      assert.equal(r.code, 2, name);
      assert.match(r.stderr, msg);
      assert.ok(!existsSync(fake.argvFile), `${name}: Sealmark was not started`);
    }
  });

  it("badge-text reads the CLI's shields document and drops control characters; a broken one leaves it empty", () => {
    const bin = join(dir, "btext-shields.mjs");
    writeFileSync(
      bin,
      [
        `import { mkdirSync, writeFileSync } from "node:fs";`,
        `import { join } from "node:path";`,
        `const argv = process.argv.slice(2);`,
        `const dir = argv[argv.indexOf("--out-dir") + 1];`,
        `mkdirSync(dir, { recursive: true });`,
        `writeFileSync(join(dir, "sealmark-report.shields.json"), process.env.SEALMARK_FAKE_SHIELDS);`,
      ].join("\n"),
    );
    const url = { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp" };
    const ok = act("btext-ok", { ...url, SEALMARK_FAKE_SHIELDS: JSON.stringify({ schemaVersion: 1, label: "sealmark 1.0", message: "core A · fs B\nINJECTED=1 · self-reported", color: "green" }) }, bin);
    assert.equal(ok.outputs["badge-text"], "sealmark 1.0: core A · fs B INJECTED=1 · self-reported");
    assert.ok(!("INJECTED" in ok.outputs), "a line break in the text cannot start a new output");
    const broken = act("btext-broken", { ...url, SEALMARK_FAKE_SHIELDS: "{not json" }, bin);
    assert.equal(broken.code, 0);
    assert.equal(broken.outputs["badge-text"], "");
    assert.ok(broken.outputs.shields, "the file path is still reported");
  });

  it("badge files left from an earlier run never pass for this run's badge", () => {
    const old = JSON.stringify({ schemaVersion: 1, label: "sealmark 1.0", message: "core A · fs A · self-reported", color: "brightgreen" });
    const seed = (name: string) => {
      const rep = join(dir, name, "sealmark-report");
      mkdirSync(rep, { recursive: true });
      writeFileSync(join(rep, "sealmark-report.shields.json"), old);
      writeFileSync(join(rep, "sealmark-report.badge.svg"), "<svg>old</svg>");
      return rep;
    };
    // badge on, and the CLI stops (exit 2) before it writes anything: the old files are gone and no output names them.
    const repOn = seed("stale-on");
    const on = act("stale-on", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_FAKE_EXIT: "2" }, fakeBin("stale-on").bin);
    assert.equal(on.code, 2);
    for (const key of ["badge", "shields", "badge-text"]) assert.equal(on.outputs[key], "", key);
    assert.ok(!existsSync(join(repOn, "sealmark-report.shields.json")) && !existsSync(join(repOn, "sealmark-report.badge.svg")), "the old files were removed before the run");
    assert.doesNotMatch(on.summary, /Badge/);
    // badge off: the files are left alone (this run did not ask for them) and no output reads them.
    const repOff = seed("stale-off");
    const off = act("stale-off", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_INPUT_BADGE: "false" }, fakeBin("stale-off").bin);
    assert.equal(off.code, 0, off.stderr);
    for (const key of ["badge", "shields", "badge-text"]) assert.equal(off.outputs[key], "", key);
    assert.ok(existsSync(join(repOff, "sealmark-report.shields.json")), "badge: false never deletes a file");
    assert.doesNotMatch(off.summary, /Badge/);
  });

  it("an unclosed quote in args exits 2", () => {
    const fake = fakeBin("quote");
    const r = act("quote", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_INPUT_ARGS: `--name "oops` }, fake.bin);
    assert.equal(r.code, 2);
    assert.match(r.stderr, /quote is not closed/);
  });

  it("the summary output reads each run's graded packs; several servers are named; a failed run says failed", () => {
    const fake = fakeBin("summary");
    const pack = (letter: string) => ({ status: "graded", grade: { letter } });
    const one = act("one", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp", SEALMARK_FAKE_REPORT: JSON.stringify({ server: { name: "a" }, packs: { core: pack("A"), db: { status: "na" }, fs: pack("C") } }) }, fake.bin);
    assert.equal(one.outputs.summary, "core A · fs C");
    const many = act(
      "many",
      {
        SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp",
        SEALMARK_FAKE_EXIT: "1",
        SEALMARK_FAKE_REPORT: JSON.stringify({ runs: [{ server: { name: "a" }, packs: { core: pack("B") } }, { status: "failed", server: "b\nINJECTED=1", error: "x", sealmark: {} }] }),
      },
      fake.bin,
    );
    assert.equal(many.code, 1);
    assert.equal(many.outputs["exit-code"], "1");
    assert.equal(many.outputs.summary, "a: core B | b INJECTED=1: failed");
    assert.ok(!Object.keys(many.outputs).includes("INJECTED"), "a server name cannot add an output line");
    const none = act("none", { SEALMARK_INPUT_URL: "http://127.0.0.1:1/mcp" }, fake.bin);
    assert.equal(none.outputs.json, "", "a report that was not written is an empty output");
    assert.equal(none.outputs.summary, "");
    assert.equal(none.summary, "", "no step summary without a grade");
  });
});
