import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { NODE_MIN, nodeItem } from "../doctor.js";
import { compareBaseline } from "../report/baseline.js";
import { decideExit, type ExitPolicy } from "../report/exit.js";
import type { PackGrade, RunResult, ToolAnnotations, ToolClassification } from "../types.js";
import { check } from "./helpers.js";

const grade = (letter: PackGrade["letter"]): PackGrade => ({ pack: "core", points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [] });
const cls = (tool: string, annotations?: ToolAnnotations): ToolClassification => ({ tool, class: "text", confidence: "low", params: {}, unfillable: [], reasons: [], ...(annotations ? { annotations } : {}) });

function run(tools: string[], annotations: Record<string, ToolAnnotations | undefined> = {}): RunResult {
  return {
    sealmark: { version: "0.2.0", methodology: "0.2-draft" },
    server: { name: "srv", version: "1.0.0", command: "node s.js", env: {}, transport: "stdio", tools, sqlTools: [] },
    options: { packsRequested: ["core"], timeoutProbeSec: 10 },
    startedAt: "2026-10-08T00:00:00.000Z",
    durationMs: 10,
    packs: { core: { status: "graded", grade: grade("B") } },
    checks: [check("protocol", "pass")],
    notCovered: [],
    config: { hash: "sha256:aaaa", profile: "standard", standard: true, standardDiff: [], methodology: "0.2-draft", schemaVersion: 1, locked: {} },
    classification: tools.map((t) => cls(t, annotations[t])),
  };
}

describe("baseline: tool-surface drift", () => {
  it("tools added, tools removed and changed annotations are three kinds of drift entry, and no regression", () => {
    const base = run(["read", "write", "gone"], { read: { readOnlyHint: true }, write: { destructiveHint: true } });
    const now = run(["read", "write", "run_shell", "exec2"], { read: { readOnlyHint: false }, write: { destructiveHint: true } });
    const d = compareBaseline([base], [now]);
    assert.deepEqual(d.regressions, []);
    assert.deepEqual(d.improvements, []);
    assert.deepEqual(d.notes, [], "drift is not a note any more");
    assert.deepEqual(d.drift.map((e) => [e.kind, e.severity, e.text]), [
      ["tool-added", "notable", "server srv: tools added: run_shell, exec2"],
      ["tool-removed", "breaking", "server srv: tools removed: gone"],
      ["annotation-changed", "notable", "server srv, tool read: annotations changed readOnlyHint true -> false"],
    ]);
  });

  it("a hint that appears or disappears is a change too, and several hints share one note", () => {
    const d = compareBaseline([run(["t"], { t: { readOnlyHint: true } })], [run(["t"], { t: { destructiveHint: true } })]);
    assert.deepEqual(d.drift.map((e) => e.text), ["server srv, tool t: annotations changed readOnlyHint true -> unset, destructiveHint unset -> true"]);
    assert.deepEqual(d.regressions, []);
  });

  it("identical runs give no note", () => {
    const a = run(["read", "write"], { read: { readOnlyHint: true } });
    assert.deepEqual(compareBaseline([a], [run(["read", "write"], { read: { readOnlyHint: true } })]).drift, []);
  });

  it("a long list is cut", () => {
    const names = Array.from({ length: 25 }, (_, i) => `t${i}`);
    const [entry] = compareBaseline([run([])], [run(names)]).drift;
    assert.ok(entry.text.endsWith("t9 and 15 more"), entry.text);
  });

  it("an old baseline without tools or classification does not throw", () => {
    const old = run([]) as unknown as Record<string, unknown>;
    delete (old.server as Record<string, unknown>).tools;
    delete old.classification;
    assert.doesNotThrow(() => compareBaseline([old as unknown as RunResult], [run(["a"])]));
  });

  it("drift never moves the exit code unless the policy asks for it (failOnDrift)", () => {
    const d = compareBaseline([run(["a"])], [run(["a", "run_shell"])]);
    const policy: ExitPolicy = { treatInconclusiveAs: "pass", criticalFail: 0, failOnGate: false, failOnRegressions: true, failOnDrift: false, regressions: d.regressions, drift: d.drift, baseline: true };
    assert.equal(decideExit([run(["a", "run_shell"])], policy).code, 0);
    assert.equal(decideExit([run(["a", "run_shell"])], { ...policy, failOnDrift: true }).code, 1);
  });
});

describe("doctor: the Node minimum", () => {
  it("NODE_MIN is the engines range in package.json", () => {
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL("../../package.json", import.meta.url)), "utf8")) as { engines: { node: string } };
    assert.equal(pkg.engines.node, `>=${NODE_MIN.join(".")}`);
  });

  it("Node 22.12 fails the node item, 22.13 and later pass", () => {
    assert.equal(nodeItem("v22.12.0").status, "fail");
    assert.match(nodeItem("v22.12.0").detail ?? "", /needs Node 22\.13 or newer/);
    for (const v of ["v22.13.0", "v22.20.1", "v23.0.0", "v24.1.0"]) assert.equal(nodeItem(v).status, "ok", v);
    assert.equal(nodeItem("v20.19.0").status, "fail");
  });
});
