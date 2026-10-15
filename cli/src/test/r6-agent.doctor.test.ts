// Round 6, package rules-agent: what `doctor` tells an agent to add to the configuration, and the auto-add rule
//. Pure functions are tested directly; one test runs doctor on a real toy server.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import { loadEffectiveConfig } from "../config/index.js";
import type { EffectiveConfig } from "../config/index.js";
import { autoAddedPacks, renderDoctor, rulesOf, runDoctor, suggestionsAfterRun, suggestionsFor, type SuggestInput } from "../doctor.js";
import type { ToolInfo } from "../mcp.js";

const T = (name: string, description: string, props: Record<string, { type: string; description?: string }>, required: string[]): ToolInfo => ({ name, description, inputSchema: { type: "object", properties: props, required } });
const TOOLS: ToolInfo[] = [
  T("describe_table", "Describe one table. Only tables in the allowed catalog are served.", { table: { type: "string" } }, ["table"]),
  T("query", "Run a read-only SQL query", { sql: { type: "string" } }, ["sql"]),
  T("search_notes", "Search the notes for a text.", { q: { type: "string" } }, ["q"]),
  T("read_file", "Read a file. Works only inside the allowed directories.", { path: { type: "string" } }, ["path"]),
];

const input = (over: Partial<SuggestInput> = {}): SuggestInput => ({
  tools: TOOLS,
  classification: classifyTools({ tools: TOOLS }).classification,
  spec: { url: "http://127.0.0.1:8080/mcp", command: "node", args: ["server.js"] },
  transport: "http",
  selfStarted: true,
  sandboxEnabled: true,
  probes: 1,
  usesDsn: false,
  sqlTools: [],
  rules: { upstreamKind: null, scopeTools: [], scopeAllow: [] },
  ...over,
});
const ids = (s: { id: string }[]) => s.map((x) => x.id);

describe("r6 agent: doctor suggestions", () => {
  it("suggests scope for a tool whose string parameter is named like an identifier and whose description speaks of what is allowed", () => {
    const s = suggestionsFor(input());
    const scope = s.find((x) => x.id === "scope:describe_table")!;
    assert.ok(scope, ids(s).join(","));
    assert.equal(scope.kind, "scope");
    assert.deepEqual(scope.tools, ["describe_table"]);
    assert.match(scope.config, /scope:\n {2}tools:\n {4}- \{ tool: describe_table, param: table \}\n {2}allow: \[\] {3}# fill in/);
    assert.deepEqual(scope.flags, ["--scope-tool describe_table=table", "--scope-allow <identifier>"]);
    assert.ok(!ids(s).includes("scope:search_notes"), "a free-text tool is not a scope candidate");
  });

  it("does not suggest scope for a file tool another pack already covers, nor for a tool already in scope.tools", () => {
    assert.ok(!ids(suggestionsFor(input())).includes("scope:read_file"));
    assert.ok(!ids(suggestionsFor(input({ rules: { upstreamKind: null, scopeTools: [{ tool: "describe_table", param: "table" }], scopeAllow: ["a"] } }))).includes("scope:describe_table"));
  });

  it("suggests a stub and sql-guard for a SQL tool with no stub and no {dsn}; nothing once the stub is declared or a database placeholder is used", () => {
    const s = suggestionsFor(input({ sqlTools: [{ tool: "query" }] }));
    const up = s.find((x) => x.id === "upstream:http")!;
    assert.equal(up.kind, "upstream");
    assert.deepEqual(up.flags, ["--upstream"]);
    assert.match(up.config, /^upstream:\n {2}kind: http\n/);
    assert.match(up.config, /\{upstream\}/);
    assert.deepEqual(up.tools, ["query"]);
    const guard = s.find((x) => x.id === "sql-guard:query")!;
    assert.equal(guard.kind, "sql-guard");
    assert.match(guard.config, /already listed under sql_tools/);
    assert.ok(!ids(suggestionsFor(input({ sqlTools: [{ tool: "query" }], rules: { upstreamKind: "http", scopeTools: [], scopeAllow: [] } }))).some((i) => i.startsWith("upstream:") || i.startsWith("sql-guard:")));
    assert.ok(!ids(suggestionsFor(input({ usesDsn: true, sqlTools: [{ tool: "query" }] }))).includes("upstream:http"));
    assert.ok(!ids(suggestionsFor(input({ spec: { command: "node", args: ["s.js", "{sqlite_path}"] }, transport: "stdio", selfStarted: false }))).includes("upstream:http"), "the sqlite pack covers a database file");
  });

  it("suggests {bearer} for a literal Authorization header and never repeats the literal", () => {
    const secret = "tok-literal-abc123";
    const s = suggestionsFor(input({ spec: { url: "http://127.0.0.1:8080/mcp", command: "node", headers: { authorization: `Bearer ${secret}` } } }));
    const id = s.find((x) => x.id === "identity:authorization")!;
    assert.equal(id.kind, "identity");
    assert.match(id.config, /Authorization: "Bearer \{bearer\}"/);
    assert.match(id.config, /identities:/);
    assert.ok(!JSON.stringify(s).includes(secret), "no suggestion carries the credential");
    assert.deepEqual(id.flags, ['--header "Authorization: Bearer {bearer}"', "--identity-a <token>", "--identity-b <token>"]);
    // already using {bearer}: nothing to suggest; a stdio server has no headers to speak of
    assert.ok(!ids(suggestionsFor(input({ spec: { url: "u", headers: { Authorization: "Bearer {bearer}" } } }))).includes("identity:authorization"));
    assert.ok(!ids(suggestionsFor(input({ transport: "stdio", spec: { command: "x", headers: { Authorization: "Bearer x" } } }))).includes("identity:authorization"));
  });

  it("suggests init --probes when the config has no probes, and the sandbox when a launched server runs without it", () => {
    const s = suggestionsFor(input({ probes: 0, sandboxEnabled: false }));
    const p = s.find((x) => x.id === "probes:none")!;
    assert.equal(p.kind, "probes");
    assert.match(p.why, /generate one valid call per tool/);
    assert.deepEqual(p.flags, ["sealmark init --probes --write --yes"]);
    assert.match(p.config, /sealmark init --probes --write --yes/);
    const sb = s.find((x) => x.id === "sandbox:enable")!;
    assert.equal(sb.kind, "sandbox");
    assert.match(sb.config, /enabled: true/);
    assert.ok(!ids(suggestionsFor(input())).includes("probes:none") && !ids(suggestionsFor(input())).includes("sandbox:enable"));
    assert.ok(!ids(suggestionsFor(input({ transport: "http", selfStarted: false, sandboxEnabled: false, spec: { url: "http://x" } }))).includes("sandbox:enable"), "a server that is already running is not ours to sandbox");
  });

  it("every suggestion has the full shape, stable ids and no duplicates, and the order is deterministic", () => {
    const a = suggestionsFor(input({ probes: 0, sqlTools: [{ tool: "query" }], spec: { url: "u", command: "n", headers: { Authorization: "Bearer x" } } }));
    const b = suggestionsFor(input({ probes: 0, sqlTools: [{ tool: "query" }], spec: { url: "u", command: "n", headers: { Authorization: "Bearer x" } } }));
    assert.deepEqual(a, b);
    assert.equal(new Set(ids(a)).size, a.length);
    for (const s of a) {
      assert.ok(s.id && s.why && s.config.endsWith("\n") && Array.isArray(s.flags), s.id);
      assert.ok(["scope", "sql-guard", "upstream", "identity", "probes", "sandbox"].includes(s.kind));
    }
  });

  it("after a run: an inconclusive check names the key to change", () => {
    const out = suggestionsAfterRun([
      { id: "upstream-credential", verdict: "inconclusive", summary: "every call was refused: the server rejects minted tokens; set identities.a." },
      { id: "scope-escape", verdict: "inconclusive", summary: "no control call succeeded." },
      { id: "sql-guard-statements", verdict: "inconclusive", summary: "the control did not reach the stub." },
      { id: "upstream-slow", verdict: "inconclusive", summary: "no valid call." },
      { id: "protocol", verdict: "pass", summary: "ok" },
    ]);
    assert.deepEqual(ids(out), ["identity:tokens", "scope:control", "sql-guard:control", "probes:none"]);
    assert.match(out[0]!.config, /identities:/);
    assert.match(out[1]!.why, /compare them with the identifiers the server lists/);
    assert.deepEqual(suggestionsAfterRun([{ id: "scope-escape", verdict: "pass", summary: "" }]), []);
  });
});

describe("r6 agent: the auto-add rule (one function for run and doctor, seam S11)", () => {
  const cfg = (o: { packs?: string[]; layer?: string; explicit?: boolean; probes?: unknown[]; value?: object } = {}): EffectiveConfig =>
    ({
      packs: o.packs ?? ["core", "http", "fs"],
      packsExplicit: o.explicit ?? false,
      origins: o.layer ? { "/packs": { layer: o.layer } } : {},
      probes: o.probes ?? [],
      value: o.value ?? {},
    }) as unknown as EffectiveConfig;
  const declared = { upstream: { kind: "http" }, scope: { tools: [{ tool: "describe_table", param: "table" }], allow: ["sales.public."] } };

  it("adds the packs a declaration asks for when nobody chose the pack list, with the note text the run prints", () => {
    const a = autoAddedPacks(cfg({ value: declared, probes: [{ tool: "x", check: { id: "c", label: "l", scope: "server" } }] }), { hasSqlTool: true });
    assert.deepEqual(a.packs, ["custom", "scope", "sql-guard", "upstream"]);
    assert.deepEqual(a.notes, [
      "probes with a check were declared, so the custom pack is included",
      "scope was declared in the config, so the pack is included",
      "sql-guard was declared in the config, so the pack is included",
      "upstream was declared in the config, so the pack is included",
    ]);
    assert.deepEqual(a.skipped, []);
  });

  it("sql-guard needs a SQL tool; upstream needs only the stub; scope needs scope.tools; nothing declared adds nothing", () => {
    assert.deepEqual(autoAddedPacks(cfg({ value: { upstream: { kind: "http" } } }), { hasSqlTool: false }).packs, ["upstream"]);
    assert.deepEqual(autoAddedPacks(cfg({ value: { scope: { tools: [], allow: [] } } }), { hasSqlTool: true }).packs, []);
    assert.deepEqual(autoAddedPacks(cfg(), { hasSqlTool: true }), { packs: [], notes: [], skipped: [] });
  });

  it("respects a list the user chose (--pack, or packs: in a file) and says what was skipped; a profile or default list counts as shipped", () => {
    const chosen = autoAddedPacks(cfg({ value: declared, explicit: true, layer: "flag" }), { hasSqlTool: true });
    assert.deepEqual(chosen.packs, []);
    assert.deepEqual(chosen.skipped, [
      "scope was declared in the config but the pack list omits scope, so it was skipped (add scope to --pack or packs:)",
      "sql-guard was declared in the config but the pack list omits sql-guard, so it was skipped (add sql-guard to --pack or packs:)",
      "upstream was declared in the config but the pack list omits upstream, so it was skipped (add upstream to --pack or packs:)",
    ]);
    assert.equal(autoAddedPacks(cfg({ value: declared, explicit: true, layer: "profile" }), { hasSqlTool: true }).packs.length, 3);
    assert.equal(autoAddedPacks(cfg({ value: declared, explicit: true, layer: "default" }), { hasSqlTool: true }).packs.length, 3);
    // a list that already names the pack needs no adding
    assert.deepEqual(autoAddedPacks(cfg({ value: declared, packs: ["core", "scope", "sql-guard", "upstream"], explicit: true, layer: "flag" }), { hasSqlTool: true }), { packs: [], notes: [], skipped: [] });
  });

  it("rulesOf reads the typed fields when the config layer has them, and the raw tree otherwise", () => {
    assert.deepEqual(rulesOf(cfg({ value: declared })), { upstreamKind: "http", scopeTools: [{ tool: "describe_table", param: "table" }], scopeAllow: ["sales.public."] });
    const typed = { ...cfg(), upstream: { kind: "http" }, scope: { tools: [{ tool: "a", param: "b" }, { nope: 1 }], allow: ["x", 3] } } as unknown as EffectiveConfig;
    assert.deepEqual(rulesOf(typed), { upstreamKind: "http", scopeTools: [{ tool: "a", param: "b" }], scopeAllow: ["x"] });
    assert.deepEqual(rulesOf(cfg()), { upstreamKind: null, scopeTools: [], scopeAllow: [] });
  });
});

describe("r6 agent: doctor --json carries suggestions", () => {
  const PROBES_TOY = fileURLToPath(new URL("../toy/probes.js", import.meta.url));
  let root: string;
  before(() => {
    root = mkdtempSync(join(tmpdir(), "sealmark-r6doc-"));
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  it("a server with no probes: suggestions[] has probes:none, the JSON round-trips, and the text has a Suggestions block", async () => {
    const dir = join(root, "c1");
    mkdirSync(join(dir, "sb"), { recursive: true });
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: r6-doc\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([PROBES_TOY, "--mode", "good"])}\nsandbox:\n  dir: ${JSON.stringify(join(dir, "sb"))}\n`);
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    const report = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
    assert.equal(report.ok, true, renderDoctor(report));
    const wire = JSON.parse(JSON.stringify(report)) as { suggestions: { id: string; kind: string; flags: string[]; config: string; why: string }[]; servers: { packs: { pack: string }[]; classification: unknown[] }[] };
    assert.ok(Array.isArray(wire.suggestions));
    const p = wire.suggestions.find((s) => s.id === "probes:none")!;
    assert.ok(p, "probes:none");
    assert.deepEqual(p.flags, ["sealmark init --probes --write --yes"]);
    assert.ok(wire.servers[0]!.classification.length > 0 && wire.servers[0]!.packs.length > 0, "an agent reads classification and packs next to suggestions");
    const text = renderDoctor(report);
    assert.match(text, /Suggestions \(each one: why, the YAML to paste into sealmark\.yaml, the equivalent flags\)/);
    assert.match(text, /- probes:none: no probes: are declared/);
    assert.match(text, /\n {2}candidate packs \(not part of the standard profile; each runs when its declaration exists in the config\):\n {2}scope {6}n\/a {8}no `scope\.tools` entry names a tool the server declares\n {2}sql-guard {2}n\/a/);
    assert.match(text, /\n {2}sqlite {3}n\/a/, "the standard rows keep their column width");
  });

  it("a server with probes has no probes:none", async () => {
    const dir = join(root, "c2");
    mkdirSync(join(dir, "sb"), { recursive: true });
    writeFileSync(join(dir, "sealmark.yaml"), `schema_version: 1\nname: r6-doc\nserver:\n  command: ${JSON.stringify(process.execPath)}\n  args: ${JSON.stringify([PROBES_TOY, "--mode", "good"])}\nsandbox:\n  dir: ${JSON.stringify(join(dir, "sb"))}\nprobes:\n  - { tool: echo, args: { text: "sm-{token}" } }\n`);
    const cfg = loadEffectiveConfig({ cwd: dir, env: {}, isolated: true });
    const report = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false });
    assert.ok(!report.suggestions!.some((s) => s.id === "probes:none"));
  });
});
