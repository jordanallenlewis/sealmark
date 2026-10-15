// Classifier ranking: evidence strength decides between candidates that both reach medium, SPECIFICITY only breaks ties.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools, packsFor } from "../classify.js";
import type { ToolInfo } from "../mcp.js";

type P = Record<string, unknown>;
const str = (extra: P = {}): P => ({ type: "string", ...extra });
const uri = (): P => str({ format: "uri" });
const strs: P = { type: "array", items: { type: "string" } };

function tool(name: string, props: Record<string, P>, o: { required?: string[]; description?: string } = {}): ToolInfo {
  return { name, description: o.description ?? "", inputSchema: { type: "object", properties: props, required: o.required ?? Object.keys(props) } } as ToolInfo;
}
const classify = (t: ToolInfo) => classifyTools({ tools: [t] }).classification[0]!;
const packs = (t: ToolInfo) => packsFor(classify(t), { active: false, sandboxEnabled: true });

describe("classifier ranking: a strong parameter outranks a generic parameter plus a name hint", () => {
  // `name` is a generic path name and "file" in the tool name is the hint, so a path candidate reaches medium; `data` has format uri.
  const uriName = tool("load_file_resource", { name: str(), data: uri() }, { description: "Loads a remote file resource and returns its text." });

  it("a format:uri parameter beats a generic name plus a file hint: url primary, path secondary, and the net pack applies", () => {
    const r = classify(uriName);
    assert.equal(r.class, "url");
    assert.equal(r.confidence, "medium");
    assert.deepEqual(r.params.url, "data");
    assert.deepEqual(r.secondary, ["path"]);
    assert.match(r.reasons.join(" "), /format "uri"/);
    assert.deepEqual(packs(uriName), ["net", "effects"]);
  });

  it("a strong url-named parameter beats a generic name plus a file hint too", () => {
    const r = classify(tool("save_file_copy", { name: str(), url: str() }));
    assert.equal(r.class, "url");
    assert.deepEqual(r.secondary, ["path"]);
  });

  it("a strong path parameter without a uri parameter stays path, and the same tool without the hint is not promoted", () => {
    const r = classify(tool("read_file", { path: str() }));
    assert.equal(r.class, "path");
    assert.equal(r.secondary, undefined);
    const generic = classify(tool("copy_file", { name: str(), note: str() }));
    assert.equal(generic.class, "path");
    assert.equal(generic.secondary, undefined);
  });

  it("two equally strong readings keep the specificity order and are both recorded", () => {
    const r = classify(tool("download", { url: str(), path: str() }));
    assert.equal(r.class, "path");
    assert.deepEqual(r.secondary, ["url"]);
    const viaUri = classify(tool("fetch_to_disk", { source: str(), target: str({ format: "uri" }) }));
    assert.equal(viaUri.class, "path");
    assert.deepEqual(viaUri.secondary, ["url"]);
  });

  it("a hint word that picks between two readings of the SAME parameter still decides (git_root{path} is git)", () => {
    const r = classify(tool("git_root", { path: str() }));
    assert.equal(r.class, "git");
    assert.deepEqual(r.secondary, ["path"]);
  });

  it("command and sql keep their place ahead of a stronger-looking path or url reading", () => {
    const cmd = classify(tool("run_script", { code: str(), file: str() }, { required: ["code"], description: "Run some code." }));
    assert.equal(cmd.class, "command");
    const web = classify(tool("run_script", { code: str(), link: uri() }, { required: ["code"], description: "Run some code." }));
    assert.equal(web.class, "command");
  });

  it("a uri parameter that is not a string does not count", () => {
    const r = classify(tool("load_file_resource", { name: str(), data: { type: "number", format: "uri" } }));
    assert.equal(r.class, "path");
  });
});

describe("classifier: 'git-style' is a format, not a repository", () => {
  const edits = { type: "array", items: { type: "object", properties: { oldText: str(), newText: str() } } };

  it("a path writer whose description says git-style diff is not git; its object-array edits parameter is fillable (round 5), so it is a path tool", () => {
    const t = tool("edit_file", { path: str(), edits }, { description: "Make line-based edits to a text file. Returns a git-style diff showing the changes made." });
    const r = classify(t);
    assert.notEqual(r.class, "git");
    assert.equal(r.class, "path");
    assert.deepEqual(r.unfillable, []);
    assert.deepEqual(packs(t), ["fs", "effects"]);
  });

  it("the same writer whose edits parameter cannot be built (a free-form object item) is still uncovered as a path tool, with the reason", () => {
    const t = tool("edit_file", { path: str(), edits: { type: "array", items: { type: "object" } } }, { description: "Make line-based edits to a text file. Returns a git-style diff showing the changes made." });
    const r = classify(t);
    assert.equal(r.class, "opaque");
    assert.match(r.reasons.join(" "), /would be path/);
    assert.match(r.reasons.join(" "), /"edits"/);
    assert.deepEqual(packs(t), []);
  });

  it("a fillable path writer with the same description is a path tool", () => {
    const r = classify(tool("write_patch", { path: str(), content: str() }, { description: "Writes the file and returns a git-style diff." }));
    assert.equal(r.class, "path");
  });

  it("the word git on its own is still a git signal, in the name or the description", () => {
    assert.equal(classify(tool("git_root", { path: str() })).class, "git");
    assert.equal(classify(tool("repo_info", { path: str() }, { description: "Show information about a git repository." })).class, "git");
  });

  it("path-array tools are unaffected", () => {
    const r = classify(tool("read_many", { paths: strs }, { description: "Read files; the output is a git-style listing." }));
    assert.equal(r.class, "path");
  });
});
