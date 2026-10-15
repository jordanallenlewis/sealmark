import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { parse } from "yaml";
import { cliKit } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r3-show-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeYaml, toyConfig } = cliKit(() => dir);

interface ShowJson {
  value: { name: string };
  origins: Record<string, unknown>;
  integrity: { standard: boolean; hash: string; diff: { path: string; standard: unknown; effective: unknown }[] };
}

describe("config show says STANDARD or CUSTOM", { timeout: 120_000 }, () => {
  it("a plain configuration starts with a STANDARD comment carrying the hash, and still parses as YAML", () => {
    const r = sealmark(["config", "show", "--config", toyConfig("plain.yaml", "nosql")]);
    assert.equal(r.code, 0, r.err);
    const first = r.out.split("\n")[0];
    assert.match(first, /^# STANDARD: every grade-affecting setting equals the published profile \(hash sha256:[0-9a-f]{64}\)$/);
    assert.equal((parse(r.out) as { name: string }).name, "cli-test");
  });

  it("checks.rls.enabled: false is CUSTOM and names the setting", () => {
    const cfg = writeYaml(
      "rls-off.yaml",
      `schema_version: 1\nname: rls-off\nserver:\n  command: node\n  args: [server.js]\nchecks:\n  rls:\n    enabled: false\n`,
    );
    const r = sealmark(["config", "show", "--config", cfg]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out.split("\n")[0], /^# CUSTOM: 1 setting differs from the standard profile: checks\.rls\.enabled$/);
    assert.equal((parse(r.out) as { name: string }).name, "rls-off");
  });

  it("two differing settings are counted and listed", () => {
    const cfg = writeYaml(
      "two.yaml",
      `schema_version: 1\nname: two\nserver:\n  command: node\nchecks:\n  rls:\n    enabled: false\ntimeout_probe_sec: 7\n`,
    );
    const first = sealmark(["config", "show", "--config", cfg]).out.split("\n")[0];
    assert.match(first, /^# CUSTOM: 2 settings differ from the standard profile: /);
    assert.match(first, /checks\.rls\.enabled/);
    assert.match(first, /timeout_probe_sec/);
  });

  it("--json carries integrity: standard, hash and the diff with path, standard and effective", () => {
    const plain = JSON.parse(sealmark(["config", "show", "--json", "--config", toyConfig("plain-json.yaml", "nosql")]).out) as ShowJson;
    assert.equal(plain.integrity.standard, true);
    assert.match(plain.integrity.hash, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(plain.integrity.diff, []);
    assert.equal(plain.value.name, "cli-test", "value and origins are unchanged");
    assert.ok(Object.keys(plain.origins).length > 10);

    const cfg = writeYaml("rls-json.yaml", `schema_version: 1\nname: rls-json\nserver:\n  command: node\nchecks:\n  rls:\n    enabled: false\n`);
    const custom = JSON.parse(sealmark(["config", "show", "--json", "--config", cfg]).out) as ShowJson;
    assert.equal(custom.integrity.standard, false);
    assert.notEqual(custom.integrity.hash, plain.integrity.hash, "the hash is of the effective locked settings");
    assert.deepEqual(custom.integrity.diff, [{ path: "checks.rls.enabled", standard: true, effective: false }]);
  });

  it("--origins keeps the label on the first line, and --effective is still accepted", () => {
    const cfg = toyConfig("origins.yaml", "nosql");
    const withFlag = sealmark(["config", "show", "--effective", "--origins", "--config", cfg]);
    assert.equal(withFlag.code, 0, withFlag.err);
    assert.match(withFlag.out.split("\n")[0], /^# STANDARD: /);
    assert.match(withFlag.out, /^profile: standard {3}# default$/m);
    assert.equal(sealmark(["config", "show", "--effective", "--config", cfg]).out, sealmark(["config", "show", "--config", cfg]).out);
  });
});
