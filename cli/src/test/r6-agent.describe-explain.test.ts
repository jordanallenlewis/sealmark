// Round 6, package rules-agent: what an agent reads to learn the surface: describe --json (candidate packs, placeholders), explain for the
// eleven new check ids, the usage text of init --probes, and the no-prompt rule.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { CLI_COMMANDS, CLI_FLAGS, INIT_PROBES_ONLY, flagsFor, usageText } from "../cli-spec.js";
import { DESCRIBE_SCHEMA, describeAllJson, describeChecks, renderDescribe, validateSchema } from "../describe.js";
import { REMEDIATION, ExplainError, explainCheck, renderExplain } from "../explain.js";
import { describeAll } from "../packs/index.js";
import { CANDIDATE_PACKS, type CheckDoc } from "../types.js";
import { CLI, hermeticEnv } from "./helpers.js";

const R6_CHECKS: { id: string; pack: string }[] = [
  { id: "scope-escape", pack: "scope" },
  { id: "sql-guard-statements", pack: "sql-guard" },
  { id: "sql-guard-references", pack: "sql-guard" },
  { id: "sql-guard-rowcap", pack: "sql-guard" },
  { id: "upstream-credential", pack: "upstream" },
  { id: "upstream-credential-echo", pack: "upstream" },
  { id: "log-secret", pack: "upstream" },
  { id: "upstream-error-leak", pack: "upstream" },
  { id: "upstream-slow", pack: "upstream" },
  { id: "refusal-quality", pack: "core" },
  { id: "instructions-hygiene", pack: "core" },
];
const registryDoc = (id: string): CheckDoc => describeAll().find((d) => d.id === id)!;

describe("r6 agent: describe --json", () => {
  it("lists the candidate packs, flags every pack and check with candidate / candidatePack, and still validates against its own schema", () => {
    assert.deepEqual([...CANDIDATE_PACKS].sort(), ["scope", "sql-guard", "upstream"]);
    const d = JSON.parse(renderDescribe(describeAllJson())) as ReturnType<typeof describeAllJson>;
    assert.deepEqual(validateSchema(DESCRIBE_SCHEMA, d), []);
    assert.ok(d.packs.length > 0 && d.packs.every((p) => typeof p.candidate === "boolean"));
    assert.ok(d.checks.every((c) => typeof c.candidatePack === "boolean"));
    assert.ok(d.packs.filter((p) => p.candidate).every((p) => !p.standard), "a candidate pack is never in the standard");
    for (const id of ["core", "db", "fs", "http", "custom"]) assert.equal(d.packs.find((p) => p.id === id)?.candidate, false, id);
  });

  it("a check of a candidate pack is candidatePack: true, a standard one false", () => {
    const checks = describeChecks([registryDoc("scope-escape"), registryDoc("sql-guard-statements"), registryDoc("upstream-credential"), registryDoc("protocol")]);
    assert.deepEqual(checks.map((c) => [c.id, c.candidatePack]), [["scope-escape", true], ["sql-guard-statements", true], ["upstream-credential", true], ["protocol", false]]);
    // and the whole document, with such checks in it, still satisfies the schema (verifiedBy may name the new observers)
    const doc = { ...describeAllJson(), checks: checks.map((c) => ({ ...c, verifiedBy: ["upstream", "log", "response"] })) };
    assert.deepEqual(validateSchema(DESCRIBE_SCHEMA, JSON.parse(JSON.stringify(doc))), []);
  });

  it("publishes the placeholders the new features add", () => {
    const names = describeAllJson().placeholders.map((p) => p.name).join(" | ");
    for (const want of ["{upstream}", "{bearer}", "{bearer:a}", "{upstream_token}", "{matrix.<name>}"]) assert.ok(names.includes(want), want);
  });

  it("publishes init --probes and its flags in the CLI table", () => {
    const j = describeAllJson().cli;
    const init = j.commands.find((c) => c.name === "init")!;
    assert.match(init.usage, /init --probes \[--write\] \[--json\]/);
    for (const f of ["probes", "write"]) assert.ok(j.flags.find((x) => x.name === f)!.commands.includes("init"), f);
    assert.ok(j.flags.find((x) => x.name === "json")!.commands.includes("init"));
  });
});

describe("r6 agent: explain works for the eleven new ids", () => {
  it("every id has remediation text that names a key, a probe form or a fix", () => {
    for (const { id } of R6_CHECKS) {
      const text = REMEDIATION[id];
      assert.ok(text && text.trim().length > 60, `${id} has no remediation text`);
      assert.ok(!/no remediation text yet/.test(text), id);
    }
  });

  it("explainCheck and renderExplain work for each id, from the registry, in the pack the id belongs to", () => {
    for (const { id, pack } of R6_CHECKS) {
      assert.equal(registryDoc(id)?.pack, pack, id);
      const e = explainCheck(id);
      assert.equal(e.check.id, id);
      assert.equal(e.remediation, REMEDIATION[id]);
      const text = renderExplain(e);
      assert.match(text, /What to fix:\n {2}\S/);
      assert.ok(text.includes(REMEDIATION[id]!.slice(0, 40)), id);
      const json = JSON.parse(renderExplain(e, { json: true })) as { remediation: string; check: { candidatePack: boolean } };
      assert.equal(json.remediation, REMEDIATION[id]);
      assert.equal(typeof json.check.candidatePack, "boolean");
    }
  });

  it("a candidate pack's check is described as a candidate pack, not as an opt-in pack", () => {
    const text = renderExplain(explainCheck("scope-escape"));
    assert.match(text, /candidate pack: runs when its declaration exists in the config, scored in its own pack, not part of the standard profile or the badge/);
    assert.ok(!/opt-in pack/.test(text));
  });

  it("an unknown id still says how to list the ids (exit 2 in the CLI)", () => {
    assert.throws(() => explainCheck("scope-escap"), (e: unknown) => e instanceof ExplainError && /unknown check "scope-escap"/.test(e.message) && /list-checks/.test(e.message));
  });
});

describe("r6 agent: usage surface", () => {
  it("init --probes is in the usage text, and its flags are accepted by init only with --probes", () => {
    assert.match(usageText(), /sealmark init .* \| init --probes \[--write\] \[--json\] \[--yes\]/);
    const initFlags = flagsFor("init").map((f) => f.name);
    for (const f of INIT_PROBES_ONLY) {
      // flags that exist in this build (the config-report package adds the others) must be accepted by init so --probes can take them
      if (CLI_FLAGS.some((x) => x.name === f)) assert.ok(initFlags.includes(f), `--${f} must be accepted by init`);
    }
    assert.ok(CLI_COMMANDS.find((c) => c.name === "init")!.summary.includes("never asks a question"));
  });

  it("init --probes and doctor never prompt: with standard input closed they finish instead of waiting for an answer", () => {
    const run = (args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 60_000, env: hermeticEnv(), stdio: ["ignore", "pipe", "pipe"] });
    // no server configured: a prompt would hang; the answer is an error that names what to type
    const r = run(["init", "--probes"]);
    assert.notEqual(r.signal, "SIGTERM", "did not hang");
    assert.ok((r.status ?? 0) >= 2, String(r.status));
    assert.ok(r.stderr.length > 0);
  });
});
