import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { gradePack } from "../grade.js";
import type { McpSession, ToolInfo } from "../mcp.js";
import { applyChecksConfig, describe as describeCore, protocolFailure, runCore, type CoreCtx } from "../packs/core.js";
import { MAX_DESCRIPTION, MAX_FINDINGS, paramDescriptions, toolDescriptions, words } from "../packs/descriptions.js";
import type { CheckResult } from "../types.js";

// Round 8: the description lint. Two advisory candidate checks in core that read only the tools/list listing.

const t = (name: string, description: string | undefined, properties: Record<string, unknown> = {}, required?: unknown[]): ToolInfo =>
  ({ name, ...(description === undefined ? {} : { description }), inputSchema: { type: "object", properties, ...(required ? { required } : {}) } }) as ToolInfo;
const str = (description?: string) => ({ type: "string", ...(description ? { description } : {}) });
const codes = (c: CheckResult) => c.evidence.map((e) => e.code);

describe("words", () => {
  it("splits camelCase and snake_case and drops punctuation", () => {
    assert.deepEqual(words("getUserById"), ["get", "user", "by", "id"]);
    assert.deepEqual(words("get_user-by.id"), ["get", "user", "by", "id"]);
    assert.deepEqual(words("Get user, by ID."), ["get", "user", "by", "id"]);
  });
});

describe("tool-descriptions", () => {
  it("is advisory, in core, never critical; n/a with no tools", () => {
    const c = toolDescriptions([]);
    assert.equal(c.id, "tool-descriptions");
    assert.equal(c.pack, "core");
    assert.equal(c.advisory, true);
    assert.equal(c.critical, false);
    assert.equal(c.verdict, "na");
  });

  it("pass: every tool has its own description", () => {
    const c = toolDescriptions([t("list_tables", "Lists the tables in the database"), t("query", "Runs one read-only SELECT and returns rows")]);
    assert.equal(c.verdict, "pass", c.summary);
    assert.equal(c.evidence.length, 1);
    assert.equal(c.evidence[0].verifiedBy, "static");
  });

  it("missing or under 10 characters: part, one finding per tool, named", () => {
    const c = toolDescriptions([t("a_tool", undefined), t("b_tool", "  short  "), t("c_tool", "Does a thing well enough")]);
    assert.equal(c.verdict, "part");
    assert.deepEqual(codes(c), ["descriptions.missing", "descriptions.missing"]);
    assert.deepEqual(c.evidence.map((e) => e.tool), ["a_tool", "b_tool"]);
    assert.match(c.evidence[0].outcome, /no description/);
    assert.match(c.evidence[1].outcome, /5 character\(s\), under 10/);
    assert.match(c.summary, /^2 of 3 tool\(s\) have no useful description/);
  });

  it("exactly 10 characters is enough", () => {
    assert.equal(toolDescriptions([t("x", "0123456789")]).verdict, "pass");
  });

  it("no tool with a usable description: fail", () => {
    assert.equal(toolDescriptions([t("a", undefined), t("b", "")]).verdict, "fail");
  });

  it("restates the name: part", () => {
    const c = toolDescriptions([t("get_weather_report", "Get weather report."), t("other", "Something else entirely")]);
    assert.equal(c.verdict, "part");
    assert.deepEqual(codes(c), ["descriptions.restates-name"]);
    assert.equal(toolDescriptions([t("getWeatherReport", "get-weather-report")]).verdict, "part");
  });

  it(`over ${MAX_DESCRIPTION} characters: part; exactly ${MAX_DESCRIPTION} passes`, () => {
    assert.equal(toolDescriptions([t("x", "a".repeat(MAX_DESCRIPTION))]).verdict, "pass");
    const c = toolDescriptions([t("x", "a".repeat(MAX_DESCRIPTION + 1))]);
    assert.equal(c.verdict, "part");
    assert.deepEqual(codes(c), ["descriptions.too-long"]);
    assert.match(c.evidence[0].outcome, /1025 characters, over 1024/);
  });

  it("two tools sharing one description (same words): fail, both named", () => {
    const c = toolDescriptions([t("read", "Reads a file from disk."), t("read_v2", "reads a FILE from disk"), t("write", "Writes a file to disk")]);
    assert.equal(c.verdict, "fail");
    assert.deepEqual(codes(c), ["descriptions.duplicate"]);
    assert.match(c.evidence[0].outcome, /^2 tools share one description: read, read_v2$/);
    assert.equal(c.evidence[0].tool, undefined);
  });

  it("names that differ only by case or separators: fail; an exact duplicate is protocol's, not counted here", () => {
    const c = toolDescriptions([t("get_user", "Fetches one user by id"), t("getUser", "Fetches a user record by id"), t("get-users", "Lists every user")]);
    assert.equal(c.verdict, "fail");
    assert.deepEqual(codes(c), ["descriptions.name-collision"]);
    assert.match(c.evidence[0].outcome, /get_user, getUser$/);
    const exact = toolDescriptions([t("same", "First of the two tools"), t("same", "Second of the two tools")]);
    assert.equal(exact.verdict, "pass", exact.summary);
  });

  it(`caps evidence at ${MAX_FINDINGS} lines plus one count line`, () => {
    const c = toolDescriptions(Array.from({ length: 40 }, (_, i) => t(`tool_${i}`, undefined)));
    assert.equal(c.evidence.length, MAX_FINDINGS + 1);
    assert.equal(c.evidence.at(-1)!.code, "descriptions.more");
    assert.match(c.evidence.at(-1)!.outcome, /^15 more finding\(s\) not listed$/);
  });

  it("disabled by config: n/a", () => {
    const c = toolDescriptions([t("a", undefined)], { enabled: false, severity: null });
    assert.equal(c.verdict, "na");
    assert.equal(c.summary, "disabled by config");
  });

  it("a non-string description from the server is read as missing, not thrown on", () => {
    const c = toolDescriptions([{ name: "x", description: 42 as unknown as string, inputSchema: { type: "object" } }]);
    assert.equal(c.verdict, "fail");
    assert.deepEqual(codes(c), ["descriptions.missing"]);
  });
});

describe("param-descriptions", () => {
  it("is advisory, in core; n/a when no tool takes a parameter, or with no tools", () => {
    const c = paramDescriptions([t("a", "Lists everything here")]);
    assert.equal(c.id, "param-descriptions");
    assert.equal(c.advisory, true);
    assert.equal(c.critical, false);
    assert.equal(c.verdict, "na");
    assert.equal(c.summary, "no tool takes a parameter");
    assert.equal(paramDescriptions([]).verdict, "na");
  });

  it("pass: described and typed; enum, const and boolean document themselves", () => {
    const c = paramDescriptions([
      t("q", "Runs a query", { sql: str("One SELECT statement"), mode: { type: "string", enum: ["fast", "safe"] }, v: { const: 1 }, dry_run: { type: "boolean" } }, ["sql"]),
    ]);
    assert.equal(c.verdict, "pass", c.summary);
    assert.equal(c.summary, "4 of 4 parameter(s) are described and typed");
  });

  it("a title counts as a description; a description that only restates the name does not", () => {
    assert.equal(paramDescriptions([t("q", "Runs a query", { sql: { type: "string", title: "SQL text to run" } })]).verdict, "pass");
    const c = paramDescriptions([t("q", "Runs a query", { file_path: str("File path") })]);
    assert.equal(c.verdict, "fail");
    assert.deepEqual(codes(c), ["params.undocumented"]);
  });

  it("the 90 % boundary: 9 of 10 clean passes (the finding is still listed), 8 of 10 is a part", () => {
    const props = (bad: number) => Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`p${i}`, i < bad ? { type: "string" } : str(`parameter number ${i}`)]));
    const nine = paramDescriptions([t("x", "A tool with ten parameters", props(1))]);
    assert.equal(nine.verdict, "pass");
    assert.deepEqual(codes(nine), ["params.undocumented"]);
    assert.match(nine.evidence[0].outcome, /^x: 1 of 10 parameter\(s\) not described: p0$/);
    assert.equal(paramDescriptions([t("x", "A tool with ten parameters", props(2))]).verdict, "part");
  });

  it("the 50 % boundary: 5 of 10 is a part, 4 of 10 fails", () => {
    const props = (bad: number) => Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`p${i}`, i < bad ? { type: "string" } : str(`parameter number ${i}`)]));
    assert.equal(paramDescriptions([t("x", "A tool with ten parameters", props(5))]).verdict, "part");
    const f = paramDescriptions([t("x", "A tool with ten parameters", props(6))]);
    assert.equal(f.verdict, "fail");
    assert.equal(f.summary, "4 of 10 parameter(s) are described and typed");
  });

  it("untyped: a parameter with no type, enum, const, composition, $ref, properties or items", () => {
    const c = paramDescriptions([
      t("x", "Mixed parameter shapes", { a: { description: "Free-form value" }, b: { anyOf: [{ type: "string" }], description: "Either" }, c: { $ref: "#/defs/c", description: "Ref" }, d: { items: {}, description: "List" } }),
    ]);
    assert.deepEqual(codes(c), ["params.untyped"]);
    assert.match(c.evidence[0].outcome, /^x: 1 of 4 parameter\(s\) state no type: a$/);
    assert.equal(c.verdict, "part");
  });

  it("a non-object parameter schema (true, null) is neither described nor typed, and does not throw", () => {
    const c = paramDescriptions([t("x", "Odd schema here", { a: true, b: null })]);
    assert.deepEqual(codes(c), ["params.undocumented", "params.untyped"]);
    assert.equal(c.verdict, "fail");
  });

  it("a required name the properties do not declare: fail, even when every declared parameter is clean", () => {
    const c = paramDescriptions([t("x", "Needs a ghost", { a: str("The real one") }, ["a", "ghost", "ghost", 7])]);
    assert.equal(c.verdict, "fail");
    assert.deepEqual(codes(c), ["params.required-undeclared"]);
    assert.match(c.evidence[0].outcome, /required but not declared in properties: ghost$/);
    assert.equal(c.summary, "1 of 1 parameter(s) are described and typed, 1 required name(s) not declared");
    // With no properties at all the undeclared name still counts: the check is not n/a.
    assert.equal(paramDescriptions([t("y", "Only required", {}, ["q"])]).verdict, "fail");
  });

  it("an inherited name (toString) in required is not read as declared", () => {
    assert.equal(paramDescriptions([t("x", "Needs toString", { a: str("The real one") }, ["toString"])]).verdict, "fail");
  });

  it(`caps evidence at ${MAX_FINDINGS} lines plus one count line`, () => {
    const c = paramDescriptions(Array.from({ length: 30 }, (_, i) => t(`tool_${i}`, "A tool here", { p: { type: "string" } })));
    assert.equal(c.evidence.length, MAX_FINDINGS + 1);
    assert.match(c.evidence.at(-1)!.outcome, /^5 more finding\(s\) not listed$/);
  });

  it("disabled by config: n/a", () => {
    assert.equal(paramDescriptions([t("x", "A tool here", { p: { type: "string" } })], { enabled: false, severity: null }).verdict, "na");
  });
});

// ---------------------------------------------------------------------------------------------------------

const ctxFor = (tools: ToolInfo[], checks?: CoreCtx["checks"]): CoreCtx => ({ session: { tools, serverInfo: { name: "t" }, prompts: [], resources: [] } as unknown as McpSession, canaries: [], seen: [], hangMs: 2000, ...(checks ? { checks } : {}) });

describe("the description lint inside core", () => {
  it("a server with no tools: both n/a, after the five checks of before", async () => {
    const out = await runCore(ctxFor([]));
    assert.deepEqual(out.map((c) => c.id), ["protocol", "tool-poisoning", "robust-input", "secret-echo", "instructions-hygiene", "tool-descriptions", "param-descriptions"]);
    assert.deepEqual(out.slice(5).map((c) => c.verdict), ["na", "na"]);
  });

  it("never moves the core letter: the same checks with and without the lint grade the same", () => {
    const scored: CheckResult[] = [
      { id: "protocol", pack: "core", label: "p", critical: false, scope: "server", verdict: "pass", summary: "", evidence: [] },
      { id: "secret-echo", pack: "core", label: "s", critical: true, scope: "server", verdict: "pass", summary: "", evidence: [] },
    ];
    const lint = [toolDescriptions([t("a", undefined), t("b", undefined)]), paramDescriptions([t("a", "x", { p: true })])];
    assert.deepEqual(lint.map((c) => c.verdict), ["fail", "fail"]);
    assert.deepEqual(gradePack("core", [...scored, ...lint]), gradePack("core", scored));
  });

  it("severity from config makes it scored (a CUSTOM run, see integrity), through core's config step", () => {
    const [c] = applyChecksConfig([toolDescriptions([t("a", undefined)])], { "tool-descriptions": { enabled: true, severity: "scored" } });
    assert.equal(c.advisory, undefined);
    assert.equal(c.verdict, "fail");
  });

  it("protocolFailure reports both as inconclusive, advisory", () => {
    const out = protocolFailure("bad listing");
    for (const id of ["tool-descriptions", "param-descriptions"]) {
      const c = out.find((x) => x.id === id)!;
      assert.equal(c.verdict, "inconclusive");
      assert.equal(c.advisory, true);
    }
  });

  it("describe() lists both as advisory core checks from 0.3-draft with their config keys", () => {
    const docs = describeCore();
    for (const id of ["tool-descriptions", "param-descriptions"]) {
      const d = docs.find((x) => x.id === id)!;
      assert.equal(d.advisory, true);
      assert.equal(d.critical, false);
      assert.equal(d.pack, "core");
      assert.equal(d.since, "0.3-draft");
      assert.deepEqual(d.configKeys, [`checks.${id}.enabled`, `checks.${id}.severity`]);
      assert.ok(d.probes.every((p) => p.core === false));
    }
  });
});
