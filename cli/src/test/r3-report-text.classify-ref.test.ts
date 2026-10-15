import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyTools, fillArgs } from "../classify.js";
import type { ToolInfo } from "../mcp.js";

// Synthetic schemas only. A pydantic `Literal[...]` parameter arrives as `{"$ref": "#/$defs/Mode"}`.

const tool = (name: string, schema: Record<string, unknown>): ToolInfo => ({ name, description: "Read a file.", inputSchema: { type: "object", ...schema } }) as ToolInfo;

const classify = (t: ToolInfo) => classifyTools({ tools: [t] }).classification[0]!;

describe("a required enum declared through $ref is fillable", () => {
  it("#/$defs: the tool is not unfillable and the enum is filled with its first value", () => {
    const t = tool("read_file", {
      properties: { path: { type: "string" }, mode: { $ref: "#/$defs/Mode" } },
      required: ["path", "mode"],
      $defs: { Mode: { type: "string", enum: ["text", "binary"] } },
    });
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.equal(c.class, "path");
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", mode: "text" });
  });

  it("#/definitions works the same way", () => {
    const t = tool("read_file", {
      properties: { path: { type: "string" }, mode: { $ref: "#/definitions/Mode" } },
      required: ["path", "mode"],
      definitions: { Mode: { enum: ["raw", "cooked"] } },
    });
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", mode: "raw" });
  });

  it("a const behind a $ref is filled with the constant", () => {
    const t = tool("read_file", {
      properties: { path: { type: "string" }, kind: { $ref: "#/$defs/Kind" } },
      required: ["path", "kind"],
      $defs: { Kind: { const: "file" } },
    });
    assert.deepEqual(fillArgs(t, classify(t), { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", kind: "file" });
  });

  it("a $ref to a string and a $ref inside an array's items are classified by what they point at", () => {
    const t = tool("read_file", {
      properties: { path: { $ref: "#/$defs/P" }, names: { type: "array", items: { $ref: "#/$defs/P" } } },
      required: ["path", "names"],
      $defs: { P: { type: "string" } },
    });
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.equal(c.params.path, "path");
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", names: ["tok"] });
  });

  it("a $ref inside anyOf (an Optional parameter) resolves; the sibling default of the $ref is kept", () => {
    const t = tool("read_file", {
      properties: { path: { type: "string" }, mode: { $ref: "#/$defs/Mode", default: "binary" }, opt: { anyOf: [{ $ref: "#/$defs/Mode" }, { type: "null" }] } },
      required: ["path", "mode"],
      $defs: { Mode: { type: "string", enum: ["text", "binary"] } },
    });
    const c = classify(t);
    assert.deepEqual(c.unfillable, []);
    assert.deepEqual(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", mode: "binary" });
  });

  it("a $ref to an object is classified by what it points at: scalar properties are fillable (round 5), a free-form or nested object stays unfillable", () => {
    const fillable = tool("read_file", {
      properties: { path: { type: "string" }, opts: { $ref: "#/$defs/Opts" } },
      required: ["path", "opts"],
      $defs: { Opts: { type: "object", properties: { a: { type: "string" } } } },
    });
    assert.deepEqual(classify(fillable).unfillable, []);
    assert.deepEqual(fillArgs(fillable, classify(fillable), { path: "/s/a.txt" }, "tok"), { path: "/s/a.txt", opts: { a: "tok" } });
    const nested = tool("read_file", {
      properties: { path: { type: "string" }, opts: { $ref: "#/$defs/Opts" } },
      required: ["path", "opts"],
      $defs: { Opts: { type: "object", properties: { a: { type: "object" } }, required: ["a"] } },
    });
    assert.deepEqual(classify(nested).unfillable, ["opts"]);
    const free = tool("read_file", { properties: { path: { type: "string" }, opts: { $ref: "#/$defs/Opts" } }, required: ["path", "opts"], $defs: { Opts: { type: "object" } } });
    assert.deepEqual(classify(free).unfillable, ["opts"]);
  });
});

describe("a $ref the tool's own schema cannot answer stays unfillable", () => {
  it("an external $ref is other", () => {
    const t = tool("read_file", { properties: { path: { type: "string" }, mode: { $ref: "https://example.invalid/schemas/mode.json" } }, required: ["path", "mode"] });
    const c = classify(t);
    assert.deepEqual(c.unfillable, ["mode"]);
    assert.equal(fillArgs(t, c, { path: "/s/a.txt" }, "tok"), undefined);
  });

  it("a pointer into properties, and a name that is not defined, are not followed", () => {
    const t = tool("read_file", {
      properties: { path: { type: "string" }, a: { $ref: "#/properties/path" }, b: { $ref: "#/$defs/Missing" } },
      required: ["path", "a", "b"],
      $defs: {},
    });
    assert.deepEqual(classify(t).unfillable, ["a", "b"]);
  });

  it("a $ref that points at itself stops and stays unfillable", () => {
    const t = tool("read_file", { properties: { path: { type: "string" }, mode: { $ref: "#/$defs/Loop" } }, required: ["path", "mode"], $defs: { Loop: { $ref: "#/$defs/Loop" } } });
    assert.deepEqual(classify(t).unfillable, ["mode"]);
  });

  it("a chain of references resolves up to eight steps and not beyond", () => {
    const chain = (links: number) => {
      const defs: Record<string, unknown> = {};
      for (let i = 0; i < links; i++) defs[`D${i}`] = i === links - 1 ? { enum: ["x"] } : { $ref: `#/$defs/D${i + 1}` };
      return tool("read_file", { properties: { path: { type: "string" }, mode: { $ref: "#/$defs/D0" } }, required: ["path", "mode"], $defs: defs });
    };
    assert.deepEqual(classify(chain(8)).unfillable, [], "eight definitions deep resolves");
    assert.deepEqual(classify(chain(9)).unfillable, ["mode"], "a ninth link is not followed");
  });

  it("a wide cycle through anyOf terminates and classifies the parameter without hanging", () => {
    const branches = Array.from({ length: 30 }, () => ({ $ref: "#/$defs/A" }));
    const t = tool("read_file", { properties: { path: { type: "string" }, mode: { $ref: "#/$defs/A" } }, required: ["path", "mode"], $defs: { A: { anyOf: [...branches, { type: "string" }] } } });
    const started = Date.now();
    classify(t);
    assert.ok(Date.now() - started < 2000, "the schema walk is bounded");
  });
});
