import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { displaySpec, loadEffectiveConfig, renderShow } from "../config/index.js";
import { redactValue, secretShaped } from "../config/placeholders.js";
import { keyBefore } from "../packs/core.js";
import { secretLiterals } from "../report/secrets.js";
import { cliKit, FAST, srv } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-redaction-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark, writeYaml } = cliKit(() => dir);

const DSN = "postgres://app:S3cretPassw0rd@db.internal:5432/prod";
const PAT = "ghp_abcdefghijklmnop1234";

describe("secret-echo evidence never quotes what surrounds a leaked canary", () => {
  it("keyBefore returns only the name the value was printed under", () => {
    const text = `{"PATH":"C:\\\\x","SHELL":"hunter2-neighbour","SEALMARK_CANARY":"sm-canary-1","AFTER":"hunter3-after"}`;
    assert.equal(keyBefore(text, text.indexOf("sm-canary-1")), "SEALMARK_CANARY");
    const escaped = `bad input; env={\\"SEALMARK_FAKE_API_KEY\\":\\"sk-1\\"}`;
    assert.equal(keyBefore(escaped, escaped.indexOf("sk-1")), "SEALMARK_FAKE_API_KEY");
    assert.equal(keyBefore("SEALMARK_CANARY=sm-1", 16), "SEALMARK_CANARY");
    assert.equal(keyBefore("some prose sm-canary-1", 11), undefined);
  });

  it("an env dump with the sandbox off (the real environment) leaks neither the neighbours nor the sentinel, even with --no-redact", () => {
    const sub = mkdtempSync(join(dir, "echo-"));
    const cfg = writeYaml("echo.yaml", `schema_version: 1\nname: sec\nserver:\n  ${srv("echoenv", 2)}\n`);
    const env = { SM_REVIEW_SENTINEL: "hunter2-sentinel-value-9f8e7d", ZZ_NEIGHBOUR: "neighbour-value-abc123xyz" };
    for (const extra of [[], ["--no-redact"]]) {
      const r = sealmark(["run", "--config", cfg, ...FAST, "--no-sandbox", "--format", "json", ...extra], sub, env);
      assert.ok(r.code === 0 || r.code === 1, r.err + r.out.slice(0, 300));
      assert.match(r.out, /SEALMARK_CANARY found at offset/);
      assert.ok(!r.out.includes("hunter2-sentinel-value-9f8e7d"), `sentinel leaked (${extra.join(" ") || "default"})`);
      assert.ok(!r.out.includes("neighbour-value-abc123xyz"), `neighbour leaked (${extra.join(" ") || "default"})`);
    }
  });

  it("with the sandbox off the real environment's values are also scrubbed from every other string in the report", () => {
    const base = { servers: [{ name: "s", spec: { command: "x" } }], db: { embedded: null, pg: null }, origins: {}, value: {} } as never;
    const env = { SM_REVIEW_SENTINEL: "hunter2-sentinel-value-9f8e7d", HOME_DIR_X: "/home/someone/long/path", PLAINWORD: "production", SHORT: "abc", API_TOKEN: "tok12345" };
    const off = secretLiterals({ ...(base as object), env, sandbox: { enabled: false, scrub_env: true, keep_env: [] } } as never);
    assert.ok(off.includes("hunter2-sentinel-value-9f8e7d"));
    assert.ok(off.includes("tok12345"), "a secret-named value is taken whatever its length class");
    for (const no of ["/home/someone/long/path", "production", "abc"]) assert.ok(!off.includes(no), `${no} is not taken`);
    const inheritedByFlag = secretLiterals({ ...(base as object), env, sandbox: { enabled: true, scrub_env: false, keep_env: [] } } as never);
    assert.ok(inheritedByFlag.includes("hunter2-sentinel-value-9f8e7d"));
    const scrubbed = secretLiterals({ ...(base as object), env, sandbox: { enabled: true, scrub_env: true, keep_env: [] } } as never);
    assert.ok(!scrubbed.includes("hunter2-sentinel-value-9f8e7d"), "a scrubbed sandbox never gave the server these");
    const kept = secretLiterals({ ...(base as object), env, sandbox: { enabled: true, scrub_env: true, keep_env: ["SM_REVIEW_SENTINEL"] } } as never);
    assert.ok(kept.includes("hunter2-sentinel-value-9f8e7d"), "keep_env lets it through to the server");
  });
});

describe("env and header values are hidden by shape, not only by name", () => {
  it("URL credentials are dropped from any value, whatever the variable is called", () => {
    assert.equal(redactValue("DATABASE_URL", DSN), "postgres://db.internal:5432/prod");
    assert.equal(redactValue("UPSTREAM", DSN), "postgres://db.internal:5432/prod");
    assert.equal(redactValue("UPSTREAM", "https://user:pw@host/x?y=1"), "https://host/x?y=1");
    assert.equal(redactValue("PLAIN", "https://host/x"), "https://host/x");
  });

  it("well-known token shapes are hidden under any name; ordinary values are kept", () => {
    for (const v of [PAT, "github_pat_11ABCDEFG0abcdefghijkl_xyz", "sk-proj-abcdefghijklmnop12", "AKIAABCDEFGHIJKLMNOP", "xoxb-1234567890-abcdefghij", "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "0123456789abcdef0123456789abcdef", "host=h user=u password=hunter2 dbname=x"]) {
      assert.equal(secretShaped(v), true, v);
      assert.equal(redactValue("SOMETHING", v), "<redacted>", v);
    }
    for (const v of ["3000", "production", "/usr/local/lib/node_modules/some-package/bin", "C:\\Program Files\\nodejs\\node.exe", "https://example.com/mcp", "a-reasonably-long-descriptive-name-without-digits", "node"]) {
      assert.equal(secretShaped(v), false, v);
      assert.equal(redactValue("SOMETHING", v), v, v);
    }
  });

  it("names: PAT, DSN, private and connection-string names are secret; PATH and similar are not", () => {
    for (const k of ["MY_PAT", "GH_PAT", "PAT", "DB_DSN", "SENTRY_DSN", "PRIVATE_KEY_PATH", "CONNECTION_STRING", "DB_CONN_STR", "AZURE_SAS", "DB_PWD"]) assert.equal(redactValue(k, "abcdef"), "<redacted>", k);
    for (const k of ["PATH", "PATHEXT", "PATTERN", "COMPUTERNAME", "PORT", "NODE_ENV", "LOG_LEVEL"]) assert.equal(redactValue(k, "abcdef"), "abcdef", k);
    assert.equal(redactValue("API_KEY", "${API_KEY}"), "${API_KEY}", "a reference is not a secret");
    assert.equal(redactValue("DATABASE_URL", "{dsn}"), "{dsn}", "a placeholder is not a secret");
  });

  it("displaySpec, config show and secretLiterals all agree", () => {
    const spec = { command: "node", args: ["srv.js"], env: { DATABASE_URL: DSN, MY_PAT: PAT, UPSTREAM: DSN, PORT: "3000" }, headers: { "X-Trace": PAT } };
    const shown = displaySpec(spec);
    const text = JSON.stringify(shown);
    for (const secret of ["S3cretPassw0rd", PAT]) assert.ok(!text.includes(secret), secret);
    assert.equal(shown.env.PORT, "3000");
    assert.equal(shown.env.UPSTREAM, "postgres://db.internal:5432/prod");

    const lits = secretLiterals({ servers: [{ name: "s", spec }], db: { embedded: null, pg: null }, origins: {}, value: {}, env: {} } as never);
    assert.ok(lits.includes("S3cretPassw0rd"), "the DSN password is scrubbed if a server echoes it");
    assert.ok(lits.includes(PAT));
    assert.ok(!lits.includes("3000"));
  });

  it("sealmark config show prints neither secret", () => {
    const cfg = writeYaml("show.yaml", `schema_version: 1\nname: s\nserver:\n  command: node\n  env:\n    DATABASE_URL: ${JSON.stringify(DSN)}\n    MY_PAT: ${PAT}\n    UPSTREAM: ${JSON.stringify(DSN)}\n    PORT: 3000\n`);
    for (const args of [["config", "show", "--config", cfg], ["config", "show", "--config", cfg, "--json"]]) {
      const r = sealmark(args);
      assert.equal(r.code, 0, r.err);
      assert.ok(!r.out.includes("S3cretPassw0rd"), args.join(" "));
      assert.ok(!r.out.includes(PAT), args.join(" "));
      assert.match(r.out, /PORT.{0,4}3000/);
    }
    const e = loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, flags: { config: cfg } });
    assert.ok(!renderShow(e).includes("S3cretPassw0rd"));
  });
});
