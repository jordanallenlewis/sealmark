import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classificationBlock, classifyTools, coreOnlyNotes, fillArgs, globToRegExp, packsFor, type ClassifyInput } from "../classify.js";
import { ConfigError } from "../config.js";
import type { ToolInfo } from "../mcp.js";
import { REGISTRY, RUN_ORDER, describeAll } from "../packs/index.js";
import { BUILTIN_PACKS, type ToolAnnotations, type ToolClassification } from "../types.js";

// ---- fixture helpers -------------------------------------------------------------------------------------
// The tool lists below are hand-written shapes (names, parameters, annotations) of public reference servers.

type P = Record<string, unknown>;
const str = (description?: string): P => ({ type: "string", ...(description ? { description } : {}) });
const strs: P = { type: "array", items: { type: "string" } };
const num: P = { type: "number" };
const bool: P = { type: "boolean" };

function tool(name: string, props: Record<string, P>, o: { required?: string[]; description?: string; annotations?: ToolAnnotations } = {}): ToolInfo {
  return { name, description: o.description ?? "", inputSchema: { type: "object", properties: props, required: o.required ?? [] }, ...(o.annotations ? { annotations: o.annotations } : {}) } as ToolInfo;
}

const RO: ToolAnnotations = { readOnlyHint: true };
const WRITE: ToolAnnotations = { readOnlyHint: false, idempotentHint: true, destructiveHint: true };

const FS_TOOLS: ToolInfo[] = [
  tool("read_file", { path: str(), tail: num, head: num }, { required: ["path"], description: "Read the complete contents of a file as text.", annotations: RO }),
  tool("read_text_file", { path: str(), tail: num, head: num }, { required: ["path"], description: "Read the complete contents of a file from the file system as text.", annotations: RO }),
  tool("read_media_file", { path: str() }, { required: ["path"], description: "Read an image or audio file.", annotations: RO }),
  tool("read_multiple_files", { paths: strs }, { required: ["paths"], description: "Read the contents of multiple files simultaneously.", annotations: RO }),
  tool("write_file", { path: str(), content: str() }, { required: ["path", "content"], description: "Create a new file or overwrite an existing file.", annotations: WRITE }),
  tool("edit_file", { path: str(), edits: { type: "array", items: { type: "object", properties: { oldText: str(), newText: str() } } }, dryRun: bool }, { required: ["path", "edits"], description: "Make line-based edits to a text file." }),
  tool("create_directory", { path: str() }, { required: ["path"], description: "Create a new directory." }),
  tool("list_directory", { path: str() }, { required: ["path"], description: "Get a detailed listing of all files and directories in a specified path.", annotations: RO }),
  tool("list_directory_with_sizes", { path: str(), sortBy: { type: "string", enum: ["name", "size"] } }, { required: ["path"], annotations: RO }),
  tool("directory_tree", { path: str() }, { required: ["path"], description: "Get a recursive tree view of files and directories.", annotations: RO }),
  tool("move_file", { source: str(), destination: str() }, { required: ["source", "destination"], description: "Move or rename files and directories.", annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: false } }),
  tool("search_files", { path: str(), pattern: str(), excludePatterns: strs }, { required: ["path", "pattern"], description: "Recursively search for files matching a pattern.", annotations: RO }),
  tool("get_file_info", { path: str() }, { required: ["path"], description: "Retrieve detailed metadata about a file or directory.", annotations: RO }),
  tool("list_allowed_directories", {}, { description: "Returns the list of directories that this server is allowed to access.", annotations: RO }),
];

const FETCH_TOOLS: ToolInfo[] = [
  tool("fetch", { url: { type: "string", format: "uri", description: "URL to fetch" }, max_length: num, start_index: num, raw: bool }, { required: ["url"], description: "Fetches a URL from the internet and extracts its contents as markdown." }),
];

const GIT_TOOLS: ToolInfo[] = [
  tool("git_status", { repo_path: str() }, { required: ["repo_path"], description: "Shows the working tree status.", annotations: RO }),
  tool("git_diff_unstaged", { repo_path: str() }, { required: ["repo_path"], annotations: RO }),
  tool("git_diff_staged", { repo_path: str() }, { required: ["repo_path"], annotations: RO }),
  tool("git_diff", { repo_path: str(), target: str() }, { required: ["repo_path", "target"], description: "Shows differences between branches or commits.", annotations: RO }),
  tool("git_commit", { repo_path: str(), message: str() }, { required: ["repo_path", "message"], description: "Records changes to the repository.", annotations: { readOnlyHint: false, destructiveHint: false } }),
  tool("git_add", { repo_path: str(), files: strs }, { required: ["repo_path", "files"], description: "Adds file contents to the staging area.", annotations: { readOnlyHint: false, destructiveHint: false } }),
  tool("git_reset", { repo_path: str() }, { required: ["repo_path"], description: "Unstages all staged changes.", annotations: { readOnlyHint: false, destructiveHint: true } }),
  tool("git_log", { repo_path: str(), max_count: num }, { required: ["repo_path"], annotations: RO }),
  tool("git_create_branch", { repo_path: str(), branch_name: str(), base_branch: str() }, { required: ["repo_path", "branch_name"] }),
  tool("git_checkout", { repo_path: str(), branch_name: str() }, { required: ["repo_path", "branch_name"] }),
  tool("git_show", { repo_path: str(), revision: str() }, { required: ["repo_path", "revision"], annotations: RO }),
  tool("git_branch", { repo_path: str(), branch_type: { type: "string", enum: ["local", "remote", "all"] }, contains: str() }, { required: ["repo_path", "branch_type"], annotations: RO }),
];

const entity = { type: "array", items: { type: "object", properties: { name: str() } } };
const MEMORY_TOOLS: ToolInfo[] = [
  tool("create_entities", { entities: entity }, { required: ["entities"], description: "Create multiple new entities in the knowledge graph." }),
  tool("create_relations", { relations: entity }, { required: ["relations"] }),
  tool("add_observations", { observations: entity }, { required: ["observations"] }),
  tool("delete_entities", { entityNames: strs }, { required: ["entityNames"], description: "Delete multiple entities and their associated relations." }),
  tool("read_graph", {}, { description: "Read the entire knowledge graph." }),
  tool("search_nodes", { query: str("The search query to match against entity names") }, { required: ["query"], description: "Search for nodes in the knowledge graph based on a query." }),
  tool("open_nodes", { names: strs }, { required: ["names"], description: "Open specific nodes in the knowledge graph by their names." }),
];

const byTool = (rows: ToolClassification[]) => Object.fromEntries(rows.map((r) => [r.tool, r]));
const classify = (tools: ToolInfo[], o: Omit<ClassifyInput, "tools"> = {}) => classifyTools({ tools, ...o });
const summary = (rows: ToolClassification[]) => Object.fromEntries(rows.map((r) => [r.tool, `${r.class}/${r.confidence}`]));

describe("classifier: reference-server shaped tool lists", () => {
  it("path tools: 13 of 14 are path (the object-array editor is fillable now), the no-argument tool is opaque", () => {
    const rows = byTool(classify(FS_TOOLS).classification);
    const paths = Object.values(rows).filter((r) => r.class === "path");
    assert.equal(paths.length, 13);
    assert.equal(rows.edit_file.class, "path");
    assert.deepEqual(rows.edit_file.unfillable, []);
    assert.equal(rows.list_allowed_directories.class, "opaque");
    assert.match(rows.list_allowed_directories.reasons[0], /no parameters/);
  });

  it("path tools: strong param plus a name hint is high, a destructive tool drops one step", () => {
    const rows = byTool(classify(FS_TOOLS).classification);
    assert.equal(rows.read_text_file.confidence, "high");
    assert.equal(rows.create_directory.confidence, "high"); // "directory" is in the name
    assert.equal(rows.write_file.confidence, "medium"); // high, lowered by destructiveHint
    assert.match(rows.write_file.reasons.join(" "), /destructiveHint is true/);
    assert.equal(rows.move_file.confidence, "high");
  });

  it("a strong param with no hint in the name or description is medium", () => {
    const [r] = classify([tool("stat_it", { path: str() }, { required: ["path"], description: "Get info." })]).classification;
    assert.equal(`${r.class}/${r.confidence}`, "path/medium");
    assert.deepEqual(r.reasons, ['param "path"']);
  });

  it("path tools: roles are recorded (path, dest, paths, content) and annotations are copied", () => {
    const rows = byTool(classify(FS_TOOLS).classification);
    assert.deepEqual(rows.move_file.params, { path: "source", dest: "destination" });
    assert.deepEqual(rows.read_multiple_files.params, { paths: "paths" });
    assert.deepEqual(rows.write_file.params, { path: "path", content: "content" });
    assert.deepEqual(rows.read_file.annotations, { readOnlyHint: true });
    assert.equal(rows.search_files.class, "path");
    assert.deepEqual(rows.search_files.unfillable, []);
  });

  it("fetch: a url param with format uri and a name hint is high", () => {
    const [row] = classify(FETCH_TOOLS).classification;
    assert.equal(row.class, "url");
    assert.equal(row.confidence, "high");
    assert.deepEqual(row.params, { url: "url" });
    assert.match(row.reasons.join(" "), /name matches \/fetch\//);
  });

  it("git tools: all twelve are git, high except the destructive one (medium), and keep their secondary roles", () => {
    const rows = byTool(classify(GIT_TOOLS).classification);
    for (const r of Object.values(rows)) assert.equal(`${r.class}/${r.confidence}`, r.tool === "git_reset" ? "git/medium" : "git/high", r.tool);
    assert.equal(rows.git_diff.params.target, "target");
    assert.equal(rows.git_commit.params.message, "message");
    assert.equal(rows.git_add.params.files, "files");
    assert.equal(rows.git_create_branch.params.branch_name, "branch_name");
    assert.equal(rows.git_show.params.revision, "revision");
    assert.equal(rows.git_diff.params.repo, "repo_path");
    assert.deepEqual(rows.git_branch.unfillable, []); // the required enum is fillable
  });

  it("memory tools: text or opaque, never probed, all core only", () => {
    const rows = classify(MEMORY_TOOLS).classification;
    const s = summary(rows);
    assert.deepEqual(s, {
      create_entities: "opaque/low",
      create_relations: "opaque/low",
      add_observations: "opaque/low",
      delete_entities: "text/low",
      read_graph: "opaque/low",
      search_nodes: "text/low",
      open_nodes: "text/low",
    });
    for (const r of rows) assert.deepEqual(packsFor(r, { active: true, sandboxEnabled: true }), []);
    assert.equal(coreOnlyNotes(rows).length, 7);
    // The entities parameter is an array of objects with scalar properties: fillable now (round 5), so the tool is opaque because it has no string parameter.
    assert.match(coreOnlyNotes(rows)[0], /^tool "create_entities" is covered by the core checks only: the tool has no string parameters; add it under tools: to include it$/);
    // A tool without parameters is not told to add itself under tools: (there is nothing to classify).
    assert.equal(coreOnlyNotes(rows).find((n) => n.includes('"read_graph"')), 'tool "read_graph" is covered by the core checks only: the tool takes no parameters');
    // A tool a counted probes: entry already called is not told to write one (seam S6).
    const unfillable = classify([tool("create_thing", { cfg: { type: "object" } }, { required: ["cfg"] })]).classification;
    assert.match(coreOnlyNotes(unfillable)[0], /; write a probes: entry to call it$/);
    assert.doesNotMatch(coreOnlyNotes(unfillable, ["create_thing"])[0], /probes:/);
    // A text tool the heuristics merely rated low keeps the old hint.
    assert.match(coreOnlyNotes(rows).find((n) => n.includes('"delete_entities"'))!, /add it under tools: to include it$/);
  });
});

describe("classifier: heuristics", () => {
  it("run_shell{command} is a command tool and never sql", () => {
    const [r] = classify([tool("run_shell", { command: str() }, { required: ["command"], description: "Run a shell command." })]).classification;
    assert.equal(r.class, "command");
    assert.equal(r.confidence, "high");
    assert.equal(r.style, "shell");
    assert.notEqual(r.class, "sql");
  });

  it("program + args is spawn style", () => {
    const [r] = classify([tool("run", { program: str(), args: strs }, { required: ["program"] })]).classification;
    assert.equal(r.class, "command");
    assert.equal(r.style, "spawn");
    assert.deepEqual(r.params, { command: "program", args: "args" });
  });

  it("query{query} without a SQL hint is text/low and says why; with a hint it is sql/medium", () => {
    const [bare] = classify([tool("query", { query: str() }, { required: ["query"], description: "Search the index." })]).classification;
    assert.equal(bare.class, "text");
    assert.equal(bare.confidence, "low");
    assert.match(bare.reasons.join(" "), /not clearly SQL/);
    assert.doesNotMatch(bare.reasons.join(" "), /sql_tools/, "a search tool is not told to declare itself SQL");
    const [dbish] = classify([tool("query", { query: str() }, { required: ["query"], description: "Look up records in the warehouse." })]).classification;
    assert.match(dbish.reasons.join(" "), /list it under sql_tools/);
    const [hinted] = classify([tool("query", { query: str() }, { required: ["query"], description: "Run a read-only query against the database." })]).classification;
    assert.equal(hinted.class, "sql");
    assert.equal(hinted.confidence, "medium");
    assert.deepEqual(hinted.params, { sql: "query" });
  });

  it("sql param named sql with a sql hint is high", () => {
    const [r] = classify([tool("execute_sql", { sql: str() }, { required: ["sql"], description: "Execute a SQL statement." })]).classification;
    assert.equal(`${r.class}/${r.confidence}`, "sql/high");
  });

  it("a sql tool that also requires an argument the harness cannot fill stays sql but is core only", () => {
    const [r] = classify([tool("run_query", { sql: str(), options: { type: "object" } }, { required: ["sql", "options"], description: "Run SQL." })]).classification;
    assert.equal(r.class, "sql");
    assert.equal(r.confidence, "low");
    assert.deepEqual(packsFor(r, { active: true, sandboxEnabled: true }), []);
  });

  it("a sql tool whose other required argument is a string the harness fills is sql with high confidence (round 5)", () => {
    const [r] = classify([tool("run_query", { sql: str(), database: str() }, { required: ["sql", "database"], description: "Run SQL." })]).classification;
    assert.equal(`${r.class}/${r.confidence}`, "sql/high");
  });

  it("specificity: a command beats a path; path wins over url and url is kept as secondary", () => {
    const both = classify([tool("download", { url: str(), path: str() }, { required: ["url", "path"] })]).classification[0];
    assert.equal(both.class, "path");
    assert.deepEqual(both.secondary, ["url"]);
    const cmd = classify([tool("exec_in", { command: str(), cwd: str(), file: str() }, { required: ["command"], description: "Run a command." })]).classification[0];
    assert.equal(cmd.class, "command");
    assert.deepEqual(cmd.secondary, ["path"]);
  });

  it("git beats path for a generic path param with a git hint", () => {
    const [r] = classify([tool("git_root", { path: str() }, { required: ["path"] })]).classification;
    assert.equal(r.class, "git");
    assert.deepEqual(r.secondary, ["path"]);
  });

  it("generic names need a hint: target alone is text, target on a file tool is path/medium", () => {
    const [none] = classify([tool("lookup", { target: str() }, { required: ["target"], description: "Look something up." })]).classification;
    assert.equal(none.class, "text");
    assert.match(none.reasons.join(" "), /could be a path/);
    const [some] = classify([tool("copy_item", { target: str() }, { required: ["target"] })]).classification;
    assert.equal(`${some.class}/${some.confidence}`, "path/medium");
    assert.match(some.reasons.join(" "), /generic param "target"/);
  });

  it("parameter names compare case- and separator-insensitively", () => {
    const [r] = classify([tool("readFile", { filePath: str() }, { required: ["filePath"] })]).classification;
    assert.equal(r.class, "path");
    assert.equal(r.confidence, "high"); // camelCase name splits into read + file
    assert.deepEqual(r.params, { path: "filePath" });
  });

  it("only string params count: a number named path is not a path, all-enum tools are opaque", () => {
    const [num1] = classify([tool("read_thing", { path: num }, { required: ["path"] })]).classification;
    assert.equal(num1.class, "opaque");
    assert.match(num1.reasons[0], /no string parameters/);
    const [en] = classify([tool("mode", { mode: { type: "string", enum: ["a", "b"] } }, { required: ["mode"] })]).classification;
    assert.equal(en.class, "opaque");
    assert.match(en.reasons[0], /enum/);
  });

  it("nullable strings (anyOf string|null) count as strings", () => {
    const [r] = classify([tool("read_file", { path: { anyOf: [{ type: "string" }, { type: "null" }] } }, { required: ["path"] })]).classification;
    assert.equal(r.class, "path");
  });

  it("destructiveHint lowers a git tool one step", () => {
    const [r] = classify([tool("git_reset", { repo_path: str() }, { required: ["repo_path"], annotations: { destructiveHint: true } })]).classification;
    assert.equal(`${r.class}/${r.confidence}`, "git/medium");
  });
});

describe("classifier: config overrides and filters", () => {
  const T = tool("fetch_thing", { address: str() }, { required: ["address"] });

  it("an opaque override wins over the heuristics and is marked explicit", () => {
    const [r] = classify(FETCH_TOOLS, { overrides: { fetch: { class: "opaque" } } }).classification;
    assert.equal(r.class, "opaque");
    assert.equal(r.confidence, "explicit");
    assert.equal(r.source, "override");
    assert.deepEqual(r.reasons, ["override: tools.overrides"]);
  });

  it("an override can name the parameter that plays a role, and unlocks the pack", () => {
    const [r] = classify([T], { overrides: { fetch_thing: { class: "url", params: { url: "address" } } } }).classification;
    assert.deepEqual(r.params, { url: "address" });
    assert.deepEqual(packsFor(r, { active: false, sandboxEnabled: true }), ["net", "effects"]);
  });

  it("an override without params borrows the heuristic's roles", () => {
    const [r] = classify([tool("thing", { file: str() }, { required: ["file"] })], { overrides: { thing: { class: "path" } } }).classification;
    assert.deepEqual(r.params, { path: "file" });
    assert.equal(r.confidence, "explicit");
  });

  it("an override naming a parameter the tool lacks is a ConfigError that lists the real ones", () => {
    assert.throws(() => classify([T], { overrides: { fetch_thing: { class: "url", params: { url: "nope" } } } }), (e: unknown) => e instanceof ConfigError && /no parameter "nope".*address/.test((e as Error).message));
  });

  it("an override for a tool the server does not declare is a warning", () => {
    const out = classify([T], { overrides: { ghost: { class: "opaque" } } });
    assert.match(out.warnings[0], /"ghost".*no such tool/);
  });

  it("sql_tools entries are explicit with source sql_tools", () => {
    const [r] = classify([tool("q", { stmt: str() }, { required: ["stmt"] })], { sqlTools: [{ tool: "q", arg: "stmt" }] }).classification;
    assert.equal(r.class, "sql");
    assert.equal(r.confidence, "explicit");
    assert.equal(r.source, "sql_tools");
    assert.deepEqual(r.params, { sql: "stmt" });
  });

  it("include is evaluated before exclude; excluded tools stay listed as opaque/excluded", () => {
    const rows = byTool(classify(FS_TOOLS, { include: ["read_*", "list_*", "write_file"], exclude: ["read_media_*", "write_file"] }).classification);
    assert.equal(rows.read_file.class, "path");
    assert.equal(rows.read_media_file.excluded, true);
    assert.match(rows.read_media_file.reasons[0], /excluded by tools\.exclude \(read_media_\*\)/);
    assert.equal(rows.write_file.excluded, true); // matched by include, then removed by exclude
    assert.equal(rows.move_file.excluded, true);
    assert.match(rows.move_file.reasons[0], /not matched by tools\.include/);
    assert.equal(rows.move_file.class, "opaque");
    assert.deepEqual(packsFor(rows.move_file, { active: true, sandboxEnabled: true }), []);
  });

  it("globs are anchored and escape regex characters", () => {
    assert.ok(globToRegExp("admin_*").test("admin_users"));
    assert.ok(!globToRegExp("admin_*").test("x_admin_users"));
    assert.ok(globToRegExp("a.b").test("a.b"));
    assert.ok(!globToRegExp("a.b").test("axb"));
    assert.ok(globToRegExp("t?st").test("test"));
  });
});

describe("classifier: gating", () => {
  const cls = (over: Partial<ToolClassification>): ToolClassification => ({ tool: "t", class: "path", confidence: "medium", params: {}, unfillable: [], reasons: [], ...over });
  const ON = { active: false, sandboxEnabled: true };

  it("low confidence is core only, whatever the class", () => {
    for (const c of ["path", "url", "git", "command", "sql", "text", "opaque"] as const) assert.deepEqual(packsFor(cls({ class: c, confidence: "low" }), { active: true, sandboxEnabled: true }), [], c);
  });

  it("medium unlocks fs, net, git and effects", () => {
    assert.deepEqual(packsFor(cls({ class: "path" }), ON), ["fs", "effects"]);
    assert.deepEqual(packsFor(cls({ class: "url" }), ON), ["net", "effects"]);
    assert.deepEqual(packsFor(cls({ class: "git" }), ON), ["git", "effects"]);
  });

  it("exec needs high or explicit confidence and --active, and a command tool is probed by no other pack", () => {
    assert.deepEqual(packsFor(cls({ class: "command", confidence: "high" }), ON), []);
    assert.deepEqual(packsFor(cls({ class: "command", confidence: "high" }), { active: true, sandboxEnabled: true }), ["exec"]);
    assert.deepEqual(packsFor(cls({ class: "command", confidence: "explicit" }), { active: true, sandboxEnabled: true }), ["exec"]);
    assert.deepEqual(packsFor(cls({ class: "command", confidence: "medium" }), { active: true, sandboxEnabled: true }), []);
  });

  it("without the sandbox, fs, git, exec and effects are off but net stays", () => {
    const off = { active: true, sandboxEnabled: false };
    assert.deepEqual(packsFor(cls({ class: "path" }), off), []);
    assert.deepEqual(packsFor(cls({ class: "git" }), off), []);
    assert.deepEqual(packsFor(cls({ class: "command", confidence: "high" }), off), []);
    assert.deepEqual(packsFor(cls({ class: "url" }), off), ["net"]);
  });

  it("excluded tools get no pack", () => {
    assert.deepEqual(packsFor(cls({ class: "opaque", confidence: "explicit", excluded: true }), ON), []);
  });
});

describe("classifier: report rows and argument filling", () => {
  it("prints the documented line for a single path tool", () => {
    const rows = classify([FS_TOOLS[1]]).classification;
    assert.deepEqual(classificationBlock(rows, ["fs", "effects"]), [
      "Classification:",
      '  read_text_file  path  high  [readOnly]  ← param "path", name matches /read|file/',
      "  packs applied: fs, effects",
    ]);
  });

  it("core-only tools print why and how to include them", () => {
    const rows = classify([tool("search_nodes", { query: str() }, { required: ["query"] })]).classification;
    const lines = classificationBlock(rows, []);
    assert.match(lines[1], /^ {2}search_nodes {2}text {2}low {2}core only: .*; add it under tools: to include it$/);
    assert.equal(lines[2], "  packs applied: none");
  });

  it("columns line up across tools", () => {
    const lines = classificationBlock(classify(FS_TOOLS.slice(0, 3)).classification);
    const col = (l: string) => l.indexOf("path");
    assert.equal(new Set(lines.slice(1).map(col)).size, 1);
  });

  it("fillArgs places values by role and fills other required parameters harmlessly", () => {
    const t = FS_TOOLS.find((x) => x.name === "search_files")!;
    const c = classify([t]).classification[0];
    assert.deepEqual(fillArgs(t, c, { path: "/s/root" }, "tok"), { path: "/s/root", pattern: "tok" });
    const mv = FS_TOOLS.find((x) => x.name === "move_file")!;
    assert.deepEqual(fillArgs(mv, classify([mv]).classification[0], { path: "a", dest: "b" }, "tok"), { source: "a", destination: "b" });
    const br = GIT_TOOLS.find((x) => x.name === "git_branch")!;
    assert.deepEqual(fillArgs(br, classify([br]).classification[0], { repo: "/r" }, "tok"), { repo_path: "/r", branch_type: "local" });
    const add = GIT_TOOLS.find((x) => x.name === "git_add")!;
    assert.deepEqual(fillArgs(add, classify([add]).classification[0], { repo: "/r", files: "x" }, "tok"), { repo_path: "/r", files: ["x"] });
  });

  it("fillArgs refuses a tool with an unfillable required parameter", () => {
    const t = tool("edit_file", { path: str(), options: { type: "object" } }, { required: ["path", "options"] });
    assert.equal(fillArgs(t, classify([t]).classification[0], { path: "x" }, "tok"), undefined);
  });

  it("fillArgs builds an array of objects from the item's properties (an edit tool)", () => {
    const t = FS_TOOLS.find((x) => x.name === "edit_file")!;
    assert.deepEqual(fillArgs(t, classify([t]).classification[0], { path: "x" }, "tok"), { path: "x", edits: [{ oldText: "tok", newText: "tok" }] });
  });
});

describe("pack registry", () => {
  it("has one entry per built-in pack id, in a run order that covers every non-core/db pack once", () => {
    assert.deepEqual(REGISTRY.map((p) => p.id).sort(), [...BUILTIN_PACKS].sort());
    assert.deepEqual([...RUN_ORDER].sort(), BUILTIN_PACKS.filter((p) => p !== "core" && p !== "db").sort());
  });

  it("check docs: ids are unique across packs, belong to their pack, and every doc names its scope", () => {
    const docs = describeAll();
    const ids = docs.map((d) => d.id);
    assert.equal(new Set(ids).size, ids.length, `duplicate check ids: ${ids.filter((x, i) => ids.indexOf(x) !== i)}`);
    for (const d of docs) {
      assert.ok(REGISTRY.some((p) => p.id === d.pack), d.id);
      assert.match(d.scope, /^(server|database|environment)/, `${d.id}: scope must start with server, database or environment`);
    }
  });

  it("a pack that is not implemented yet says so", () => {
    for (const p of REGISTRY) {
      const r = p.applies({ pack: p.id } as never);
      if (!r.ok) assert.ok(r.reason.length > 0, p.id);
    }
  });
});
