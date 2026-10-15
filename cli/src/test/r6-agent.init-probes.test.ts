// Round 6, package rules-agent: `sealmark init --probes`: the generator, the block, --write, --json,
// idempotence, and that it never prompts. The generator is tested on hand-built tools; the command on the probes toy through the real CLI.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { classifyTools } from "../classify.js";
import { loadEffectiveConfig } from "../config/index.js";
import type { ProbeSpec } from "../config/model.js";
import type { ToolInfo } from "../mcp.js";
import { PROBES_FORMAT, generateValidProbes, probesJson, renderProbesBlock, validateProbes } from "../probes.js";
import { CLI, hermeticEnv } from "./helpers.js";

const T = (name: string, description: string, props: Record<string, { type: string; items?: { type: string } }>, required: string[], extra: Partial<ToolInfo> = {}): ToolInfo => ({
  name,
  description,
  inputSchema: { type: "object", properties: props, required },
  ...extra,
});
const gen = (tools: ToolInfo[], o: { upstream?: boolean; scope?: { tools: { tool: string; param: string }[]; allow: string[] }; sqlTools?: { tool: string; arg: string }[] } = {}) =>
  generateValidProbes({ tools, classification: classifyTools({ tools, sqlTools: o.sqlTools }).classification, upstream: o.upstream ?? false, ...(o.scope ? { scope: o.scope } : {}) });

describe("r6 agent: generateValidProbes", () => {
  const TOOLS: ToolInfo[] = [
    T("read_file", "Read a file and return its text.", { path: { type: "string" } }, ["path"]),
    T("write_file", "Write text to a file.", { path: { type: "string" }, content: { type: "string" } }, ["path", "content"]),
    T("delete_file", "Delete a file.", { path: { type: "string" } }, ["path"]),
    T("fetch", "Fetch a web page over HTTP and return its body.", { url: { type: "string" } }, ["url"]),
    T("echo", "Echo the text back.", { text: { type: "string" } }, ["text"]),
    T("nap", "Wait for a number of milliseconds.", { ms: { type: "number" } }, ["ms"]),
    T("shell", "Run one command line and return what it prints.", { command: { type: "string" } }, ["command"]),
  ];

  it("fills each kind of argument with a target the harness owns, writers first and deleters last, tools otherwise by name", () => {
    const g = gen(TOOLS);
    assert.deepEqual(g.probes.map((p) => p.tool), ["write_file", "echo", "fetch", "nap", "read_file", "shell", "delete_file"]);
    const by = (t: string) => g.probes.find((p) => p.tool === t)!;
    assert.deepEqual(by("write_file").args, { path: "{sandbox}/ok.txt", content: "sm-{token}" });
    assert.deepEqual(by("read_file").args, { path: "{sandbox}/ok.txt" });
    assert.deepEqual(by("fetch").args, { url: "{listener}/t/{token}" });
    assert.deepEqual(by("echo").args, { text: "sm-{token}" });
    assert.deepEqual(by("nap").args, { ms: 1 });
    assert.deepEqual(by("shell"), { tool: "shell", args: { command: "sm-echo" }, active: true }, "a command tool runs only a harness program, and needs active: true");
    assert.deepEqual(g.skipped, []);
  });

  it("is deterministic: the same tools in any order give the same list and the same block", () => {
    const a = gen(TOOLS);
    const b = gen([...TOOLS].reverse());
    assert.deepEqual(a, b);
    assert.equal(renderProbesBlock(a), renderProbesBlock(b));
    assert.ok(!/sm-[0-9a-f]{12}/.test(renderProbesBlock(a)), "placeholders stay unexpanded: no per-run value in the block");
  });

  it("every generated probe is accepted by the validator (the block round-trips)", () => {
    const g = gen(TOOLS);
    const classification = classifyTools({ tools: TOOLS }).classification;
    const plan = validateProbes(g.probes as unknown as ProbeSpec[], { tools: TOOLS, classification });
    assert.equal(plan.probes.length, g.probes.length);
    // and the YAML of the block parses back to the same probes
    const doc = parse(renderProbesBlock(g)) as { probes: unknown[] };
    assert.deepEqual(doc.probes, JSON.parse(JSON.stringify(g.probes)));
  });

  it("writes SQL only when an upstream stub is declared; otherwise the entry is a comment with the reason", () => {
    const tools = [T("query", "Run a SQL query against the database", { sql: { type: "string" } }, ["sql"])];
    const off = gen(tools, { sqlTools: [{ tool: "query", arg: "sql" }] });
    assert.deepEqual(off.probes, []);
    assert.match(off.skipped[0]!.reason, /SQL is sent only to a stub the harness owns: set upstream\.kind: http \(flag --upstream\)/);
    const block = renderProbesBlock(off);
    assert.ok(!/^probes:/m.test(block), "nothing generated: no probes: key (an empty list would block --write later)");
    assert.match(block, /# query: SQL is sent only to a stub/);
    assert.match(block, /#   - \{ tool: query, args: \{ sql: "SELECT 1 AS sm_\{token\}" \} \}/);
    const on = gen(tools, { sqlTools: [{ tool: "query", arg: "sql" }], upstream: true });
    assert.deepEqual(on.probes, [{ tool: "query", args: { sql: "SELECT 1 AS sm_{token}" } }]);
  });

  it("gives a scoped tool the first exact scope.allow identifier; prefixes alone are skipped with the reason", () => {
    const tools = [T("describe_table", "Describe a table.", { table: { type: "string" } }, ["table"])];
    const scope = (allow: string[]) => ({ tools: [{ tool: "describe_table", param: "table" }], allow });
    assert.deepEqual(gen(tools, { scope: scope(["sales.public.", "sales.public.orders", "sales.public.customers"]) }).probes, [{ tool: "describe_table", args: { table: "sales.public.orders" } }]);
    const prefixOnly = gen(tools, { scope: scope(["sales.public."]) });
    assert.deepEqual(prefixOnly.probes, []);
    assert.match(prefixOnly.skipped[0]!.reason, /scope\.allow has no exact identifier for "table"/);
  });

  it("calls a no-argument tool only when it declares readOnlyHint; otherwise it is skipped with the reason and a commented entry", () => {
    const tools = [
      T("list_tables", "List the tables.", {}, [], { annotations: { readOnlyHint: true } } as Partial<ToolInfo>),
      T("reset_all", "Reset everything.", {}, []),
    ];
    const g = gen(tools);
    assert.deepEqual(g.probes, [{ tool: "list_tables", args: {} }]);
    assert.equal(g.skipped.length, 1);
    assert.equal(g.skipped[0]!.tool, "reset_all");
    assert.match(g.skipped[0]!.reason, /does not declare readOnlyHint/);
    assert.match(renderProbesBlock(g), /#   - \{ tool: reset_all, args: \{\} \}/);
  });

  it("skips what it cannot fill (a required object it does not know the shape of) and a git tool, naming the reason", () => {
    const tools = [
      T("bulk", "Do many things.", { items: { type: "array", items: { type: "object" } } }, ["items"]),
      T("git_log", "Show the git commit history of a repository.", { repo_path: { type: "string" } }, ["repo_path"]),
    ];
    const g = gen(tools);
    assert.deepEqual(g.probes, []);
    assert.equal(g.skipped.length, 2);
    assert.ok(g.skipped.every((s) => /^cannot fill: /.test(s.reason)), JSON.stringify(g.skipped));
  });

  it("probesJson is sealmark.probes/1 with probes and skipped (tool and reason only)", () => {
    const j = probesJson(gen([...TOOLS, T("reset_all", "Reset.", {}, [])]));
    assert.equal(j.format, PROBES_FORMAT);
    assert.equal(PROBES_FORMAT, "sealmark.probes/1");
    assert.equal(j.probes.length, 7);
    assert.deepEqual(Object.keys(j.skipped[0]!).sort(), ["reason", "tool"]);
  });
});

describe("r6 agent: sealmark init --probes (the CLI)", () => {
  const PROBES_TOY = fileURLToPath(new URL("../toy/probes.js", import.meta.url));
  let root: string;
  let n = 0;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sealmark-r6probes-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  const project = (extra = ""): string => {
    const dir = join(root, `p${++n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: r6-init\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([PROBES_TOY, "--mode", "good"])}\n${extra}`);
    return dir;
  };
  // Standard input is closed and is not a terminal: a prompt would hang or fail here.
  const sm = (dir: string, args: string[]) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: "utf8", timeout: 90_000, env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };

  it("prints the block on stdout, exit 0, and the same block every time", () => {
    const dir = project();
    const a = sm(dir, ["init", "--probes"]);
    assert.equal(a.code, 0, a.err);
    assert.match(a.out, /^# Valid calls generated by `sealmark init --probes`/);
    assert.match(a.out, /\nprobes:\n {2}- \{ tool: write_file, args: \{ path: "\{sandbox\}\/ok\.txt", content: "sm-\{token\}" \} \}\n/);
    const b = sm(dir, ["init", "--probes", "--yes"]);
    assert.equal(b.out, a.out, "idempotent: two runs, identical block (and --yes changes nothing)");
    assert.equal(readFileSync(join(dir, "sealmark.yaml"), "utf8").includes("probes:"), false, "without --write the file is untouched");
  });

  it("--write appends the block once; the file then loads and carries the probes; a second --write exits 2 with the exact message", () => {
    const dir = project();
    const first = sm(dir, ["init", "--probes", "--write", "--yes"]);
    assert.equal(first.code, 0, first.err);
    assert.equal(first.out, "", "with --write the block goes to the file, not stdout");
    assert.match(first.err, /wrote 6 probe\(s\) to .*sealmark\.yaml/);
    assert.match(first.err, /next: sealmark run/);
    const text = readFileSync(join(dir, "sealmark.yaml"), "utf8");
    assert.equal((text.match(/^probes:/gm) ?? []).length, 1);
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    assert.equal(cfg.probes.length, 6);
    const second = sm(dir, ["init", "--probes", "--write", "--yes"]);
    assert.equal(second.code, 2);
    assert.match(second.err, /sealmark: `probes:` already exists in sealmark\.yaml; merge by hand or remove it/);
    assert.equal(readFileSync(join(dir, "sealmark.yaml"), "utf8"), text, "the file is not touched the second time");
  });

  it("--json prints sealmark.probes/1 and nothing else on stdout", () => {
    const r = sm(project(), ["init", "--probes", "--json"]);
    assert.equal(r.code, 0, r.err);
    const j = JSON.parse(r.out) as { format: string; probes: { tool: string }[]; skipped: unknown[] };
    assert.equal(j.format, "sealmark.probes/1");
    assert.equal(j.probes.length, 6);
    assert.deepEqual(j.skipped, []);
    assert.ok(!("written" in j));
  });

  it("--write --json writes the file and reports where", () => {
    const dir = project();
    const r = sm(dir, ["init", "--probes", "--write", "--json"]);
    assert.equal(r.code, 0, r.err);
    assert.match((JSON.parse(r.out) as { written: string }).written, /sealmark\.yaml$/);
    assert.ok(readFileSync(join(dir, "sealmark.yaml"), "utf8").includes("probes:"));
  });

  it("--write with no config file exits 2 and says what to run; a config that already has probes: is refused before the server starts", () => {
    const dir = join(root, `empty${++n}`);
    mkdirSync(dir, { recursive: true });
    const r = sm(dir, ["init", "--probes", "--write", "--start", `${process.execPath} ${PROBES_TOY} --mode good`]);
    assert.equal(r.code, 2);
    assert.match(r.err, /there is no sealmark\.yaml to write to: create it first \(sealmark init --from-url <url> --yes\), or leave out --write to print the block/);
    const has = project("probes:\n  - { tool: echo, args: { text: \"sm-{token}\" } }\n");
    const t0 = Date.now();
    const r2 = sm(has, ["init", "--probes", "--write"]);
    assert.equal(r2.code, 2);
    assert.match(r2.err, /`probes:` already exists in sealmark\.yaml/);
    assert.ok(!/starting "r6-init"/.test(r2.err), `the server was not started (${Date.now() - t0} ms)`);
  });

  it("a server that does not start exits 4 and points at doctor", () => {
    const dir = join(root, `bad${++n}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: bad\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ["-e", "process.exit(3)"]\n`);
    const r = sm(dir, ["init", "--probes", "--connect-timeout", "5"]);
    assert.equal(r.code, 4);
    assert.match(r.err, /init --probes could not read the server's tool list/);
    assert.match(r.err, /run `sealmark doctor` to see every step/);
    assert.equal(r.out, "");
  });

  it("the flags that only make sense with --probes are a usage error without it, and --probes does not mix with the import flags", () => {
    const dir = project();
    const a = sm(dir, ["init", "--write"]);
    assert.equal(a.code, 2);
    assert.match(a.err, /--write applies to "sealmark init" only with --probes/);
    const b = sm(dir, ["init", "--url", "http://127.0.0.1:1/mcp"]);
    assert.equal(b.code, 2);
    assert.match(b.err, /--url applies to "sealmark init" only with --probes/);
    const c = sm(dir, ["init", "--probes", "--from-url", "http://127.0.0.1:1/mcp"]);
    assert.equal(c.code, 2);
    assert.match(c.err, /--probes cannot be combined with --from-url/);
    const d = sm(dir, ["init", "--json"]);
    assert.equal(d.code, 2);
    assert.match(d.err, /--json applies to "sealmark init" only with --probes/);
  });

  it("a configuration that declares several servers must be told which: --server <name>", () => {
    const dir = join(root, `multi${++n}`);
    mkdirSync(dir, { recursive: true });
    const srv = (m: string) => `    command: ${JSON.stringify(process.execPath)}\n    args: ${JSON.stringify([PROBES_TOY, "--mode", m])}\n`;
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: multi\nservers:\n  one:\n${srv("good")}  two:\n${srv("good")}run:\n  server: all\n`);
    const r = sm(dir, ["init", "--probes"]);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /declares several servers \(one, two\): pick one with --server <name>/);
    const one = sm(dir, ["init", "--probes", "--server", "one"]);
    assert.equal(one.code, 0, one.err);
    assert.match(one.out, /^# Valid calls generated/);
  });
});
