import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { describeAll } from "../packs/index.js";
import { pack as fsPack } from "../packs/fs.js";
import { ROLE_PASSWORD, roleDsn } from "../seed.js";
import { directCtx, fsConfig } from "./packctx.js";

/** Snapshot of `sealmark describe` ids, in registry order (DC1: the registry reads each pack's own describe()). */
const DESCRIBE_IDS = [
  "core/protocol", "core/tool-poisoning", "core/robust-input", "core/secret-echo", "core/refusal-quality", "core/instructions-hygiene",
  "db/read-only", "db/write-gate", "db/rls", "db/mutating-sql", "db/pii", "db/pii-masked", "db/db-rowcap", "db/db-timeout", "db/audit", "db/db-privilege",
  "http/http-origin", "http/http-auth", "http/http-protocol-version", "http/http-session", "http/http-cors", "http/http-bind", "http/http-tls",
  "fs/fs-read-escape", "fs/fs-write-escape", "fs/fs-link-escape", "fs/fs-size-cap",
  "git/git-repo-scope", "git/git-arg-injection",
  "net/net-loopback-ssrf", "net/net-scheme-allowlist", "net/net-caps", "net/net-redirect",
  "sqlite/sqlite-read-only", "sqlite/sqlite-mutating-sql", "sqlite/sqlite-file-read", "sqlite/sqlite-file-write", "sqlite/sqlite-extension-load", "sqlite/sqlite-rowcap", "sqlite/sqlite-timeout",
  "exec/exec-injection", "exec/exec-cwd", "exec/exec-timeout-cap", "exec/exec-allowlist",
  "scope/scope-escape",
  "sql-guard/sql-guard-statements", "sql-guard/sql-guard-references", "sql-guard/sql-guard-rowcap",
  "upstream/upstream-credential", "upstream/upstream-credential-echo", "upstream/log-secret", "upstream/upstream-error-leak", "upstream/upstream-slow",
  "effects/annotation-honesty", "effects/openworld-honesty", "effects/undeclared-writes",
];

describe("dead-code package", () => {
  it("describeAll() still lists the same 56 checks in the same order (45 through round 5, 11 from round 6)", () => {
    assert.deepEqual(describeAll().map((d) => `${d.pack}/${d.id}`), DESCRIBE_IDS);
  });

  it("the retired cap-timeout id is not documented", () => {
    assert.ok(!describeAll().some((d) => d.id === "cap-timeout"));
  });

  it("ROLE_PASSWORD is random per process, stable within it, and used by roleDsn", async () => {
    const again = (await import("../seed.js")).ROLE_PASSWORD;
    assert.equal(again, ROLE_PASSWORD);
    assert.notEqual(ROLE_PASSWORD, "sealmark-test-only");
    assert.match(ROLE_PASSWORD, /^sm-[0-9a-f]{24}$/);
    const dsn = roleDsn({ host: "127.0.0.1", port: 5432, adminUser: "a", adminPassword: "b" }, "analyst");
    assert.ok(dsn.includes(`sm_analyst:${ROLE_PASSWORD}@`));
  });
});

describe("fs escape checks on the standard corpus", { timeout: 120_000 }, () => {
  let dir: string;
  let parent: string;
  const where = () => ({ dir, parent });
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-dc-test-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("the standard corpus still passes on the good toy", async () => {
    const d = await directCtx(fsConfig("good"), "fs", where());
    try {
      const out = await fsPack.run(d.ctx);
      assert.equal(out.find((c) => c.id === "fs-read-escape")!.verdict, "pass");
      assert.equal(out.find((c) => c.id === "fs-write-escape")!.verdict, "pass");
    } finally {
      await d.close();
    }
  });
});
