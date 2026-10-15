import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import { CI_PROVIDERS, ciSnippet } from "../ci-snippet.js";
import { CLI_COMMANDS, CLI_FLAGS, cliSpecJson, usageText } from "../cli-spec.js";
import { UsageError, fixtureCommand } from "../commands.js";
import { DESCRIBE_SCHEMA, describeAllJson, renderDescribe, validateSchema } from "../describe.js";
import { REMEDIATION, explainCheck, renderExplain } from "../explain.js";
import { CANDIDATE_CHECKS } from "../config/index.js";
import { describeAll } from "../packs/index.js";

const flag = (name: string) => CLI_FLAGS.find((f) => f.name === name)!;

describe("help text says what the commands do", () => {
  it("HT1: --fixture advertises fs, git and sqlite, and says DuckDB is planned", () => {
    const text = usageText();
    assert.match(text, /--fixture <fs\|git\|sqlite>/);
    assert.ok(!text.includes("<fs|git|sqlite|duckdb>"), "the planned fixture name is not in the metavar");
    assert.equal(flag("fixture").metavar, "<fs|git|sqlite>");
    assert.match(flag("fixture").description, /DuckDB is planned/);
  });

  it("HT1: a fixture generator that is not built yet is refused, exit 2 (only duckdb; fs, git and sqlite are built)", () => {
    assert.throws(() => fixtureCommand("duckdb", undefined, () => {}), (e: unknown) => e instanceof UsageError && /not available in this build yet/.test(e.message));
    const cli = fileURLToPath(new URL("../cli.js", import.meta.url));
    const r = spawnSync(process.execPath, [cli, "run", "--fixture", "duckdb"], { encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not available in this build yet/);
  });

  it("HT2: --yes and --server describe both meanings (run and init)", () => {
    assert.deepEqual(flag("yes").commands.includes("init"), true);
    assert.match(flag("yes").description, /run: .*--pg/);
    assert.match(flag("yes").description, /init: .*never ask/);
    assert.deepEqual(flag("server").commands.includes("init"), true);
    assert.match(flag("server").description, /run/);
    assert.match(flag("server").description, /init: .*client\/name/);
  });

  it("HT2: explain takes --json, in the usage line and in the published flag table", () => {
    assert.equal(CLI_COMMANDS.find((c) => c.name === "explain")!.usage, "explain <check-id> [--json]");
    assert.match(usageText(), /sealmark explain <check-id> \[--json\]/);
    assert.ok(flag("json").commands.includes("explain"));
    const wire = JSON.parse(renderDescribe(describeAllJson())) as ReturnType<typeof describeAllJson>;
    assert.deepEqual(validateSchema(DESCRIBE_SCHEMA, wire), []);
    const json = (wire.cli.flags as { name: string; commands: string[] }[]).find((f) => f.name === "json")!;
    assert.ok(json.commands.includes("explain"));
    assert.ok(cliSpecJson().flags.find((f) => f.name === "json")!.commands.includes("explain"));
  });

  it("HT3: --effective says it is accepted for compatibility, and is no longer in the usage line", () => {
    assert.match(flag("effective").description, /Accepted for compatibility; config show always prints the effective configuration\./);
    assert.ok(flag("effective").commands.includes("config show"), "the flag entry stays so describe --json and old scripts still list it");
    const usage = CLI_COMMANDS.find((c) => c.name === "config show")!.usage;
    assert.ok(!usage.includes("--effective"), usage);
    assert.ok(!/config show \[--effective\]/.test(usageText()));
  });

  it("HT3: the CI snippets tell a stdio-server user to drop --url, and still parse as YAML", () => {
    for (const p of CI_PROVIDERS) {
      const text = ciSnippet(p, "9.8.7");
      assert.match(text, /stdio server \(no HTTP URL\): drop the --url line and keep --start "npx -y your-server"/, p);
      assert.ok(parse(text), p);
    }
  });
});

describe("HT4: explain says what to fix", () => {
  it("every shipped check id has a remediation in the table, and none is empty", () => {
    for (const c of describeAll()) {
      // A candidate check may ship before its remediation text (explain falls back); once it has text, the text must be real.
      if ((CANDIDATE_CHECKS as readonly string[]).includes(c.id) && REMEDIATION[c.id] === undefined) continue;
      assert.ok(REMEDIATION[c.id]?.trim().length > 20, `${c.id} has no remediation text`);
      assert.equal(explainCheck(c.id).remediation, REMEDIATION[c.id]);
    }
    for (const id of Object.keys(REMEDIATION)) assert.ok(describeAll().some((c) => c.id === id), `REMEDIATION names unknown check ${id}`);
  });

  it("net-redirect has real remediation text, whether or not it is still a candidate", () => {
    assert.equal(
      REMEDIATION["net-redirect"],
      "Re-validate every redirect target with the same host, scheme and address rules as the original URL before following it, and never follow a redirect to a non-http(s) scheme.",
    );
    const e = explainCheck("net-redirect");
    assert.equal(e.remediation, REMEDIATION["net-redirect"]);
    assert.match(renderExplain(e), /What to fix:[\s\S]*Re-validate every redirect target/);
  });

  it("prints a What to fix section before the closing line, and carries remediation in --json", () => {
    const text = renderExplain(explainCheck("rls"));
    const at = text.indexOf("What to fix:");
    assert.ok(at > text.indexOf("Settings:"), "after the settings");
    assert.ok(at < text.indexOf("An A means"), "before the closing line");
    const j = JSON.parse(renderExplain(explainCheck("rls"), { json: true })) as { remediation: string };
    assert.equal(j.remediation, REMEDIATION.rls);
  });

  it("falls back for ids without text (custom and plugin checks)", () => {
    const docs = describeAll().map((c) => (c.id === "protocol" ? { ...c, id: "my-plugin-check" } : c));
    const e = explainCheck("my-plugin-check", docs);
    assert.equal(e.remediation, "(no remediation text yet)");
    assert.match(renderExplain(e), /What to fix:\n {2}\(no remediation text yet\)/);
  });
});
