import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classificationBlock, classifyTools, coreOnlyHint, coreOnlyNotes, fillArgs, packsFor } from "../classify.js";
import type { ToolInfo } from "../mcp.js";

// Synthetic ToolInfo fixtures for the round-5 classifier rules: path names by suffix and prefix, enum arrays,
// one-level descent into object and array-of-object parameters, hints that need the tool name, and the wording of the core-only notes.

const str = (description?: string) => ({ type: "string", ...(description ? { description } : {}) });
const tool = (name: string, properties: Record<string, unknown>, required: string[] = [], description = ""): ToolInfo =>
  ({ name, description, inputSchema: { type: "object", properties, required } }) as ToolInfo;
const classify = (t: ToolInfo) => classifyTools({ tools: [t] }).classification[0]!;
const ON = { active: false, sandboxEnabled: true };

describe("path parameters are recognised by suffix and prefix", () => {
  it("{source_path, destination_path} is a path tool with a destination", () => {
    const c = classify(tool("relocate", { source_path: str(), destination_path: str() }, ["source_path", "destination_path"]));
    assert.equal(c.class, "path");
    assert.deepEqual(c.params, { path: "source_path", dest: "destination_path" });
    assert.deepEqual(packsFor(c, ON), ["fs", "effects"]);
  });

  it("{inputPath, outputPath} puts the destination on the output name, whatever the order", () => {
    const c = classify(tool("convert", { outputPath: str(), inputPath: str() }, ["outputPath", "inputPath"]));
    assert.equal(c.class, "path");
    assert.deepEqual(c.params, { path: "inputPath", dest: "outputPath" });
  });

  it("{outputPath} alone is a path tool whose only path is a destination", () => {
    const c = classify(tool("export", { outputPath: str() }, ["outputPath"]));
    assert.equal(c.class, "path");
    assert.equal(c.params.path, "outputPath");
    assert.equal(c.params.dest, undefined);
    assert.equal(c.confidence, "medium");
  });

  it("other spellings: target_dir, newFilename, sourceFile", () => {
    for (const name of ["target_dir", "newFilename", "sourceFile", "download-directory"]) {
      assert.equal(classify(tool("do_it", { [name]: str() }, [name])).class, "path", name);
    }
  });

  it("near miss: names that merely end in the same letters are not paths (xpath, profile, redir, a repository path stays git)", () => {
    for (const name of ["xpath", "profile", "redir", "userProfile"]) {
      const c = classify(tool("do_it", { [name]: str() }, [name]));
      assert.notEqual(c.class, "path", name);
    }
    const git = classify(tool("git_status", { repo_path: str() }, ["repo_path"]));
    assert.equal(git.class, "git");
    assert.equal(git.secondary, undefined, "a repository path is not also read as a path");
  });

  it("near miss: a number named outputPath is not a path", () => {
    assert.equal(classify(tool("do_it", { outputPath: { type: "number" } }, ["outputPath"])).class, "opaque");
  });
});

describe("enum arrays are fillable", () => {
  it("{reviewTypes: enum[]} alone: not unfillable, filled with the first value, and the reason says why no pack calls it", () => {
    const t = tool("review", { reviewTypes: { type: "array", items: { type: "string", enum: ["security", "style"] } } }, ["reviewTypes"]);
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.equal(c.class, "opaque");
    assert.match(c.reasons[0]!, /every string parameter is an enum/);
    assert.deepEqual(fillArgs(t, c, {}, "tok"), { reviewTypes: ["security"] });
  });

  it("an enum array next to a path parameter no longer makes the path tool unfillable", () => {
    const t = tool("review_file", { path: str(), reviewTypes: { type: "array", items: { type: "string", enum: ["security", "style"] } } }, ["path", "reviewTypes"]);
    const c = classify(t);
    assert.equal(c.class, "path");
    assert.deepEqual(c.unfillable, []);
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", reviewTypes: ["security"] });
  });

  it("near miss: an enum array with no values is still unfillable", () => {
    const c = classify(tool("review", { path: str(), kinds: { type: "array", items: { type: "string", enum: [] } } }, ["path", "kinds"]));
    assert.deepEqual(c.unfillable, ["kinds"]);
  });
});

describe("the classifier descends one level into object and array-of-object parameters", () => {
  const files = { type: "array", items: { type: "object", properties: { file_path: str(), ranges: { type: "array", items: { type: "object", properties: { start: { type: "number" }, end: { type: "number" } }, required: ["start", "end"] } } }, required: ["file_path", "ranges"] } };

  it("{files: [{file_path, ranges}]}: the tool reads paths the harness cannot aim at, and says so", () => {
    const t = tool("read_files", { files }, ["files"], "Read files with line ranges.");
    const c = classify(t);
    assert.equal(c.class, "opaque");
    assert.deepEqual(c.unfillable, ["files"]);
    assert.match(c.reasons.join(" "), /would be path \(param "files\[\]\.file_path", .*\), but required parameter "files" cannot be filled by the harness/);
    assert.deepEqual(packsFor(c, ON), []);
    assert.equal(fillArgs(t, c, {}, "tok"), undefined);
  });

  it("the same shape with scalar-only items still cannot be aimed: a path key one level down makes the parameter unfillable", () => {
    const c = classify(tool("read_files", { files: { type: "array", items: { type: "object", properties: { file_path: str() }, required: ["file_path"] } } }, ["files"]));
    assert.deepEqual(c.unfillable, ["files"]);
    assert.match(c.reasons.join(" "), /files\[\]\.file_path/);
  });

  it("near miss: an optional nested path parameter does not block a tool that has a top-level path", () => {
    const c = classify(tool("read_file", { path: str(), extra: { type: "array", items: { type: "object", properties: { file_path: str() } } } }, ["path"]));
    assert.equal(c.class, "path");
    assert.deepEqual(c.unfillable, []);
  });

  it("edits: [{oldText, newText}] is fillable, so an edit tool can be called at all", () => {
    const t = tool("edit_file", { path: str(), edits: { type: "array", items: { type: "object", properties: { oldText: str(), newText: str() }, required: ["oldText", "newText"] } }, dryRun: { type: "boolean" } }, ["path", "edits"], "Edit a file.");
    const c = classify(t);
    assert.equal(c.class, "path");
    assert.deepEqual(c.unfillable, []);
    assert.deepEqual(fillArgs(t, c, { path: "/s/ok.txt" }, "tok"), { path: "/s/ok.txt", edits: [{ oldText: "tok", newText: "tok" }] });
  });

  it("an object parameter is built from its required scalar properties only", () => {
    const t = tool("read_file", { path: str(), options: { type: "object", properties: { encoding: { type: "string", enum: ["utf8", "latin1"] }, limit: { type: "number" }, label: str() }, required: ["encoding", "limit"] } }, ["path", "options"]);
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", options: { encoding: "utf8", limit: 1 } });
  });

  it("near miss: a free-form object, an object with a required nested object, and an array of arrays stay unfillable", () => {
    for (const shape of [{ type: "object" }, { type: "object", properties: { inner: { type: "object" } }, required: ["inner"] }, { type: "array", items: { type: "array", items: { type: "string" } } }]) {
      assert.deepEqual(classify(tool("read_file", { path: str(), opts: shape }, ["path", "opts"])).unfillable, ["opts"], JSON.stringify(shape));
    }
  });
});

describe("a generic parameter needs the hint in the tool name, the title or its own description", () => {
  it("{target} with 'list the indexes' only in the tool description is text/low", () => {
    const c = classify(tool("lookup", { target: str() }, ["target"], "Use this to list the indexes of a collection."));
    assert.equal(`${c.class}/${c.confidence}`, "text/low");
    assert.match(c.reasons.join(" "), /could be a path, but nothing in the tool name, its title or the parameter's own description says so/);
  });

  it("near miss: the hint in the tool name, the title or the parameter's own description still promotes it", () => {
    assert.equal(classify(tool("copy_item", { target: str() }, ["target"])).class, "path");
    const titled = { ...tool("lookup", { target: str() }, ["target"]), title: "Read a file" } as ToolInfo;
    assert.equal(classify(titled).class, "path");
    const own = classify(tool("lookup", { target: str("The file to read") }, ["target"], "Looks something up."));
    assert.equal(`${own.class}/${own.confidence}`, "path/medium");
    assert.match(own.reasons.join(" "), /parameter description/);
  });

  it("near miss: the word git in the description alone still makes a generic path a repository (a literal word, not a common verb)", () => {
    assert.equal(classify(tool("repo_info", { path: str() }, ["path"], "Show information about a git repository.")).class, "git");
  });
});

describe("the notes for a tool only the core checks reach say what was decided", () => {
  it("a free-text parameter names itself and the signals it lacked", () => {
    const c = classify(tool("echo", { text: str() }, ["text"], "Echoes."));
    assert.equal(c.reasons[0], 'free-text parameter "text": no path, URL, command, SQL or repository signal');
    assert.match(coreOnlyNotes([c])[0]!, /; add it under tools: to include it$/);
  });

  it("an enum-only tool says every string parameter is an enum; a tool with no parameters carries no tools: hint", () => {
    const e = classify(tool("mode", { mode: { type: "string", enum: ["a", "b"] }, count: { type: "number" } }, ["mode", "count"]));
    assert.match(e.reasons[0]!, /^no free-text parameter: every string parameter is an enum$/);
    const none = classify(tool("ping", {}));
    assert.equal(coreOnlyHint(none), "");
    assert.equal(coreOnlyNotes([none])[0], 'tool "ping" is covered by the core checks only: the tool takes no parameters');
    assert.doesNotMatch(classificationBlock([none]).join("\n"), /tools:/);
    assert.match(classificationBlock([none]).join("\n"), /core only: the tool takes no parameters$/m);
  });

  it("a tool a counted probes: entry already called is not told to write one", () => {
    const c = classify(tool("make", { cfg: { type: "object" } }, ["cfg"]));
    assert.match(coreOnlyNotes([c])[0]!, /cannot be filled by the harness; write a probes: entry to call it$/);
    assert.match(coreOnlyNotes([c], ["make"])[0]!, /cannot be filled by the harness$/);
    assert.equal(coreOnlyHint({ ...c, source: "override", unfillable: [] }, ["make"]), `it is overridden to class ${c.class}, which no pack probes`);
    assert.doesNotMatch(classificationBlock([c], undefined, ["make"]).join("\n"), /probes:/);
  });
});
