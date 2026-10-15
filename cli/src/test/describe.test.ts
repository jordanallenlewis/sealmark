import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { parseArgs } from "node:util";
import { CLI_COMMANDS, CLI_FLAGS, EXIT_CODES, SIGNAL_EXIT_CODES, cliSpecJson, flagsFor, matchCommand, parseArgsSpec, usageText } from "../cli-spec.js";
import { FLAG_DEFS } from "../config/flags.js";
import { CHECKS, METHODOLOGY, SCHEMA, STANDARD_PACKS } from "../config/index.js";
import { DESCRIBE_FORMAT, DESCRIBE_SCHEMA, checkConsistency, cliVersion, describeAllJson, describeChecks, renderDescribe, validateSchema } from "../describe.js";
import { ExplainError, explainCheck, listChecks, renderExplain, renderListChecks } from "../explain.js";
import { describeAll } from "../packs/index.js";
import type { CheckDoc } from "../types.js";

/** A check doc for tests that must not depend on which packs have shipped. */
const doc = (o: Partial<CheckDoc> & { id: string }): CheckDoc => ({
  pack: "db",
  label: `${o.id} label`,
  critical: false,
  advisory: false,
  scope: "server",
  verifiedBy: ["response"],
  probes: [],
  thresholds: {},
  falsePositive: "",
  falseNegative: "",
  configKeys: [],
  since: "0.2-draft",
  status: "shipped",
  ...o,
});

describe("cli-spec", () => {
  it("lists every configuration-mapped flag exactly once, with its schema path", () => {
    const names = CLI_FLAGS.map((f) => f.name);
    assert.equal(new Set(names).size, names.length, "flag names are unique");
    for (const d of FLAG_DEFS) {
      const f = CLI_FLAGS.find((x) => x.name === d.name);
      assert.ok(f, `--${d.name} is in FLAG_DEFS but not in the CLI spec`);
      assert.equal(f.schemaPath, d.path);
      assert.equal(f.type, d.kind === "pairs" ? "list" : d.kind === "command" ? "string" : d.kind);
      assert.equal(Boolean(f.negatable), Boolean(d.negatable));
    }
    for (const f of CLI_FLAGS) if (f.schemaPath) assert.ok(SCHEMA.some((l) => l.path === f.schemaPath), `--${f.name} maps to unknown setting ${f.schemaPath}`);
  });

  it("only mentions commands that exist, and every command has a usage line starting with its name", () => {
    const names = new Set(CLI_COMMANDS.map((c) => c.name));
    assert.equal(names.size, CLI_COMMANDS.length);
    for (const f of CLI_FLAGS) for (const c of f.commands) assert.ok(names.has(c), `--${f.name} names unknown command ${c}`);
    for (const c of CLI_COMMANDS) assert.ok(c.usage.startsWith(c.name), c.usage);
    for (const c of CLI_COMMANDS) {
      // every flag the usage line shows is a flag the spec knows
      for (const m of c.usage.matchAll(/--([a-z][a-z-]*)/g)) assert.ok(CLI_FLAGS.some((f) => f.name === m[1] || `no-${f.name}` === m[1]), `${c.name}: usage shows unknown --${m[1]}`);
    }
  });

  it("marks the safety flags, which the configuration says only the command line may set", () => {
    assert.deepEqual(CLI_FLAGS.filter((f) => f.safety).map((f) => f.name).sort(), ["active", "yes"]);
    for (const n of ["active", "yes"]) assert.equal(SCHEMA.find((l) => l.path === n)?.flagOnly, true);
  });

  it("builds options that util.parseArgs accepts", () => {
    const { values, positionals } = parseArgs({
      args: ["config", "show", "--origins", "--json", "--no-sandbox", "--pack", "core", "--pack", "fs", "--timeout-probe", "3", "--client", "cursor", "-h"],
      options: parseArgsSpec(),
      allowPositionals: true,
      allowNegative: true,
    });
    assert.deepEqual(positionals, ["config", "show"]);
    assert.equal(values.origins, true);
    assert.equal(values.sandbox, false, "--no-sandbox arrives as sandbox: false");
    assert.deepEqual(values.pack, ["core", "fs"]);
    assert.deepEqual(values.client, ["cursor"]);
    assert.equal(values.help, true);
  });

  it("matches one- and two-word commands and returns the rest as arguments", () => {
    assert.equal(matchCommand(["run"])?.command.name, "run");
    assert.equal(matchCommand(["config", "show"])?.command.name, "config show");
    assert.deepEqual(matchCommand(["explain", "fs-read-escape"])?.rest, ["fs-read-escape"]);
    assert.equal(matchCommand(["config"]), undefined, "config alone is not a command");
    assert.equal(matchCommand(["nope"]), undefined);
    assert.equal(matchCommand([]), undefined);
  });

  it("says which flags a command takes", () => {
    const init = flagsFor("init").map((f) => f.name);
    for (const n of ["from", "from-url", "client", "force", "yes", "config", "server", "help"]) assert.ok(init.includes(n), `init should take --${n}`);
    assert.equal(init.includes("fail-under"), false);
    assert.ok(flagsFor("run").some((f) => f.name === "active"));
    assert.ok(flagsFor("doctor").some((f) => f.name === "json"));
  });

  it("keeps the exit codes of the shipped CLI", () => {
    assert.deepEqual(EXIT_CODES.map((e) => e.code), [0, 1, 2, 3, 4]);
    assert.match(EXIT_CODES[1].meaning, /--fail-under/);
    assert.match(EXIT_CODES[1].meaning, /provisional A\* is below an A gate/);
    assert.match(EXIT_CODES[1].meaning, /inconclusive pack under output\.exit_policy\.treat_inconclusive_as: fail/);
    assert.match(EXIT_CODES[3].meaning, /no pack was graded/);
    assert.deepEqual(SIGNAL_EXIT_CODES.map((e) => [e.code, e.meaning.match(/SIG[A-Z]+/)?.[0]]), [[129, "SIGHUP"], [130, "SIGINT"], [143, "SIGTERM"]]);
  });

  it("generates usage text that shows every command, flag and exit code", () => {
    const text = usageText();
    for (const c of CLI_COMMANDS) assert.ok(text.includes(c.usage), c.name);
    for (const f of CLI_FLAGS) if (f.commands.length && f.status !== "planned") assert.ok(text.includes(`--${f.negatable ? "[no-]" : ""}${f.name}`), f.name);
    for (const e of EXIT_CODES) assert.ok(text.includes(`${e.code}  `));
  });

  it("publishes planned flags as planned, and neither prints nor accepts them", () => {
    const planned = CLI_FLAGS.filter((f) => f.status === "planned").map((f) => f.name);
    // --fixture and --into shipped with the sqlite fixture (integration round 1): nothing is planned now, but the mechanism stays tested.
    assert.deepEqual(planned, [], "no flag is marked planned");
    assert.ok("fixture" in parseArgsSpec() && "into" in parseArgsSpec(), "--fixture and --into are accepted");
    for (const n of planned) {
      assert.equal(usageText().includes(`--${n}`), false, n);
      assert.equal(n in parseArgsSpec(), false, n);
      assert.throws(() => parseArgs({ args: [`--${n}`, "x"], options: parseArgsSpec(), allowPositionals: true }), /Unknown option/);
    }
    const wire = JSON.parse(JSON.stringify(cliSpecJson())) as { flags: { name: string; status?: string }[] };
    assert.deepEqual(wire.flags.filter((f) => f.status).map((f) => f.name), planned);
  });

  it("publishes a copy, not the table itself", () => {
    const a = cliSpecJson();
    a.flags[0].commands.push("tampered");
    assert.equal(CLI_FLAGS[0].commands.includes("tampered"), false);
  });
});

describe("describe --json", () => {
  const d = describeAllJson();
  // JSON.stringify is what the CLI prints; validating the round-tripped value is validating what a consumer receives.
  const wire = JSON.parse(renderDescribe(d)) as ReturnType<typeof describeAllJson>;

  it("validates against its own schema", () => {
    assert.deepEqual(validateSchema(DESCRIBE_SCHEMA, wire), []);
    assert.equal(wire.format, DESCRIBE_FORMAT);
  });

  it("reports the versions", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };
    assert.equal(wire.sealmark.version, pkg.version);
    assert.equal(cliVersion(), pkg.version);
    assert.equal(wire.sealmark.methodology, METHODOLOGY);
    assert.equal(wire.sealmark.methodology, "0.3-draft", "the published methodology; bump it only together with standard.hash.txt");
  });

  it("lists every check the registry emits, once, with severity and pack membership", () => {
    const registry = describeAll();
    assert.deepEqual(wire.checks.map((c) => c.id), registry.map((c) => c.id));
    assert.equal(new Set(wire.checks.map((c) => c.id)).size, wire.checks.length);
    const protocol = wire.checks.find((c) => c.id === "protocol")!;
    assert.equal(protocol.severity, "scored");
    assert.equal(wire.checks.find((c) => c.id === "secret-echo")!.severity, "critical");
    assert.equal(wire.checks.find((c) => c.id === "audit")!.severity, "advisory");
    for (const p of wire.packs) assert.deepEqual(p.checks, wire.checks.filter((c) => c.pack === p.id).map((c) => c.id));
    assert.equal(wire.checks.length, 56, "45 through round 5, plus the 11 round 6 candidates");
    assert.equal(wire.packs.find((p) => p.id === "core")!.standard, true);
    assert.equal(wire.packs.find((p) => p.id === "exec")!.standard, false, "exec is opt-in");
    assert.ok(STANDARD_PACKS.every((id) => wire.packs.some((p) => p.id === id)));
  });

  it("0.3-draft: net-redirect is a locked, scored standard check; db-privilege and the round 6 checks are the unlocked candidates", () => {
    const redirect = wire.checks.find((c) => c.id === "net-redirect")!;
    assert.equal(redirect.candidate, false);
    assert.equal(redirect.standardLocked, true);
    assert.equal(redirect.severity, "scored");
    const privilege = wire.checks.find((c) => c.id === "db-privilege")!;
    assert.equal(privilege.candidate, true);
    assert.equal(privilege.standardLocked, false);
    assert.equal(privilege.severity, "advisory");
    assert.deepEqual(wire.checks.filter((c) => c.candidate).map((c) => c.id), [
      "refusal-quality",
      "instructions-hygiene",
      "db-privilege",
      "scope-escape",
      "sql-guard-statements",
      "sql-guard-references",
      "sql-guard-rowcap",
      "upstream-credential",
      "upstream-credential-echo",
      "log-secret",
      "upstream-error-leak",
      "upstream-slow",
    ]);
    const retries = wire.configKeys.find((k) => k.path === "retries.call")!;
    assert.equal(retries.deprecated, true);
    assert.equal(retries.standardLocked, false);
  });

  it("records that db-rowcap and db-timeout replace cap-timeout (acceptance 21)", () => {
    for (const id of ["db-rowcap", "db-timeout"]) assert.deepEqual(wire.checks.find((c) => c.id === id)?.replaces, ["cap-timeout"], id);
  });

  it("lists the settings of each check, merged from the registry and the configuration table", () => {
    const rowcap = wire.checks.find((c) => c.id === "db-rowcap")!;
    assert.ok(rowcap.configKeys.includes("checks.db-rowcap.row_cap"));
    assert.ok(rowcap.configKeys.includes("checks.db-rowcap.severity"));
    assert.equal(rowcap.standardLocked, true);
  });

  it("publishes every configuration key with its metadata", () => {
    assert.equal(wire.configKeys.length, SCHEMA.length);
    const key = (p: string) => wire.configKeys.find((k) => k.path === p)!;
    assert.equal(key("db.pg").secret, true);
    assert.equal(key("active").flagOnly, true);
    assert.equal(key("timeout_probe_sec").standardLocked, true);
    assert.equal(key("tools.exclude").mergeable, true);
    assert.equal(key("checks.cap-timeout.timeout_sec").deprecated, true);
    assert.deepEqual(key("checks.cap-timeout.timeout_sec").replacedBy, ["checks.db-timeout.expected_sec"]);
    assert.deepEqual(key("sandbox.enabled").default, true);
    assert.deepEqual(key("output.format").enum, ["text", "json", "markdown", "junit", "sarif", "summary", "badge", "shields"]);
    for (const k of wire.configKeys) assert.ok(k.description.length > 10, `${k.path} needs a description`);
  });

  it("publishes the shipped profiles, the placeholders and the CLI table", () => {
    assert.deepEqual(wire.profiles.map((p) => p.name).slice(0, 5), ["standard", "quick", "ci", "strict", "paranoid"]);
    assert.equal(wire.profiles.find((p) => p.name === "quick")!.standard, false);
    assert.equal(wire.profiles.find((p) => p.name === "standard")!.standard, true);
    assert.ok(wire.placeholders.some((p) => p.name.startsWith("{sandbox}")));
    assert.deepEqual(wire.cli, JSON.parse(JSON.stringify(cliSpecJson())));
  });

  it("is deterministic", () => {
    assert.equal(renderDescribe(describeAllJson()), renderDescribe(describeAllJson()));
  });
});

describe("validateSchema", () => {
  const good = JSON.parse(renderDescribe(describeAllJson()));
  const clone = () => JSON.parse(JSON.stringify(good));
  it("rejects a missing required property, an unexpected one, a wrong type and a value outside an enum", () => {
    const a = clone();
    delete a.sealmark.methodology;
    assert.match(validateSchema(DESCRIBE_SCHEMA, a).join("\n"), /\$\.sealmark: missing required "methodology"/);
    const b = clone();
    b.checks[0].surprise = 1;
    assert.match(validateSchema(DESCRIBE_SCHEMA, b).join("\n"), /\$\.checks\[0\]: unexpected property "surprise"/);
    const c = clone();
    c.checks[0].critical = "yes";
    assert.match(validateSchema(DESCRIBE_SCHEMA, c).join("\n"), /\$\.checks\[0\]\.critical: expected boolean, got string/);
    const e = clone();
    e.checks[0].verifiedBy = ["telepathy"];
    assert.match(validateSchema(DESCRIBE_SCHEMA, e).join("\n"), /"telepathy" is not one of/);
    const f = clone();
    f.cli.exitCodes[0].code = 9;
    assert.match(validateSchema(DESCRIBE_SCHEMA, f).join("\n"), /\$\.cli\.exitCodes\[0\]\.code: 9 is not one of/);
    assert.match(validateSchema(DESCRIBE_SCHEMA, [])[0], /expected object, got array/);
  });
  it("treats an integer as a number and {} as anything", () => {
    assert.deepEqual(validateSchema({ type: "number" }, 3), []);
    assert.deepEqual(validateSchema({ type: "integer" }, 3.5), ["$: expected integer, got number"]);
    assert.deepEqual(validateSchema({}, { any: ["thing"] }), []);
  });
});

describe("check registry consistency", () => {
  const c = checkConsistency();
  it("documents every check once, with a scope that says what it measures", () => {
    assert.deepEqual(c.duplicates, [], "a check id is documented twice");
    assert.deepEqual(c.badScope, [], "a scope must start with server, database or environment");
  });
  it("uses the same pack and the same ids as the configuration table, wherever a pack has shipped its docs", () => {
    assert.deepEqual(c.packMismatch, []);
    assert.deepEqual(c.inRegistryNotConfig, [], "a pack documents a check the configuration cannot address, so checks.<id>.severity would be rejected");
    assert.deepEqual(c.badReplaces, []);
  });
  it("documents every check id the configuration can address", () => {
    // Red until every pack owner ships describe(); the list says which are missing.
    assert.deepEqual(c.inConfigNotRegistry, [], `${CHECKS.length} ids in the configuration table; undocumented: ${c.inConfigNotRegistry.join(", ")}`);
  });
  it("detects problems in a registry it is given", () => {
    const bad = checkConsistency([doc({ id: "protocol", pack: "db" }), doc({ id: "protocol" }), doc({ id: "mine", scope: "the code" }), doc({ id: "x", replaces: ["no-such"] })]);
    assert.deepEqual(bad.duplicates, ["protocol"]);
    assert.deepEqual(bad.badScope, ["mine"]);
    assert.deepEqual(bad.packMismatch.map((p) => p.id), ["protocol", "protocol"]);
    assert.deepEqual(bad.inRegistryNotConfig, ["mine", "x"]);
    assert.deepEqual(bad.badReplaces, [{ id: "x", replaces: "no-such" }]);
  });
});

describe("list-checks", () => {
  it("lists checks with pack, severity, lock state and scope", () => {
    const rows = listChecks();
    const row = rows.find((r) => r.id === "mutating-sql")!;
    assert.equal(row.pack, "db");
    assert.equal(row.severity, "critical");
    assert.equal(row.standardLocked, true);
    assert.equal(row.standardPack, true);
    assert.equal(rows.find((r) => r.id === "exec-injection")!.standardPack, false);
  });
  it("filters by pack and rejects an unknown pack with a suggestion", () => {
    assert.ok(listChecks({ pack: "core" }).every((r) => r.pack === "core"));
    assert.deepEqual(new Set(listChecks({ pack: ["core", "db"] }).map((r) => r.pack)), new Set(["core", "db"]));
    assert.throws(() => listChecks({ pack: "cor" }), (e: Error) => e instanceof ExplainError && /did you mean "core"\?/.test(e.message));
  });
  it("renders a table and JSON", () => {
    const text = renderListChecks(listChecks({ pack: "core" }));
    assert.match(text, /^ID +PACK +SEVERITY +LOCKED +SCOPE$/m);
    assert.match(text, /^protocol +core +scored +yes/m);
    assert.match(text, /LOCKED: every setting/);
    const json = JSON.parse(renderListChecks(listChecks({ pack: "core" }), { json: true })) as { checks: unknown[] };
    assert.equal(json.checks.length, 6, "the four core checks and the two round 6 advisories");
    assert.equal(renderListChecks([]), "no checks\n");
  });
  it("marks opt-in packs and checks that are not shipped", () => {
    const docs = [doc({ id: "a-one", pack: "exec" }), doc({ id: "b-two", status: "planned" })];
    const text = renderListChecks(listChecks({ docs }));
    assert.match(text, /a-one .* \[opt-in\]/);
    assert.match(text, /b-two .* \[planned\]/);
  });
});

describe("explain", () => {
  it("explains a check from the registry: scope, scoring, probes, settings", () => {
    const e = explainCheck("db-rowcap");
    assert.equal(e.check.pack, "db");
    assert.deepEqual(e.replaces, ["cap-timeout"]);
    assert.ok(e.settings.some((s) => s.path === "checks.db-rowcap.row_cap" && s.default === 10000 && s.standardLocked));
    assert.equal(e.settings.some((s) => s.path.startsWith("checks.cap-timeout")), false, "deprecated aliases are not offered as settings");
    const text = renderExplain(e);
    assert.match(text, /^db-rowcap {2}\(pack db\)/);
    assert.match(text, /Scope: +server/);
    assert.match(text, /Scoring: +scored: pass = 1 point, part = 0\.5, fail = 0/);
    assert.match(text, /Replaces: +cap-timeout/);
    assert.match(text, /checks\.db-rowcap\.row_cap = 10000 +\(locked\)/);
    assert.match(text, /It is not a security endorsement\./);
  });
  it("says what a critical check does to the grade", () => {
    assert.match(renderExplain(explainCheck("mutating-sql")), /A fail caps the pack's grade at D/);
    assert.match(renderExplain(explainCheck("audit")), /advisory: reported with its verdict but not part of the score/);
  });
  it("resolves an old id to what replaced it, and says so", () => {
    assert.throws(() => explainCheck("cap-timeout"), (e: Error) => e instanceof ExplainError && /replaced by db-rowcap and db-timeout/.test(e.message));
    const docs = [doc({ id: "new-one", replaces: ["old-one"] })];
    const e = explainCheck("old-one", docs);
    assert.equal(e.check.id, "new-one");
    assert.match(renderExplain(e, { asked: "old-one" }), /^note: "old-one" was replaced; showing new-one/);
  });
  it("suggests the closest id for a typo and counts the checks otherwise", () => {
    assert.throws(() => explainCheck("mutating-sq"), (e: Error) => e instanceof ExplainError && /unknown check "mutating-sq"; did you mean "mutating-sql"\?/.test(e.message));
    assert.throws(() => explainCheck("zzzzzzzzzz"), (e: Error) => e instanceof ExplainError && /sealmark list-checks/.test(e.message));
  });
  it("renders probes, thresholds and false-positive notes when the pack documents them", () => {
    const docs = [
      doc({
        id: "demo",
        critical: true,
        probes: [{ id: "p1", text: "send the thing", core: true, kind: "variant" }, { id: "p2", text: "send another" }],
        thresholds: { cap: { default: 5, configKey: "checks.demo.cap", standardLocked: true } },
        falsePositive: "a server configured to allow it",
        falseNegative: "encodings outside the corpus",
      }),
    ];
    const text = renderExplain(explainCheck("demo", docs));
    assert.match(text, /- p1 \[core\] \(variant\): send the thing/);
    assert.match(text, /- p2: send another/);
    assert.match(text, /- cap: 5 +setting checks\.demo\.cap +\(locked\)/);
    assert.match(text, /Known false positives:\n {2}a server configured to allow it/);
    assert.match(text, /Known false negatives:\n {2}encodings outside the corpus/);
    assert.match(renderExplain(explainCheck("demo", [doc({ id: "demo" })])), /the corpus is not listed in this build/);
  });
  it("renders JSON", () => {
    const j = JSON.parse(renderExplain(explainCheck("protocol"), { json: true })) as { check: { id: string } };
    assert.equal(j.check.id, "protocol");
  });
  it("describeChecks marks a check locked only when every setting that affects it is", () => {
    const [locked] = describeChecks([doc({ id: "db-rowcap" })]);
    assert.equal(locked.standardLocked, true);
    const [open] = describeChecks([doc({ id: "protocol", configKeys: ["sandbox.dir"] })]);
    assert.equal(open.standardLocked, false, "sandbox.dir is not grade-affecting, so it is not locked");
  });
});
