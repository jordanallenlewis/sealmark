import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { TemplateCtx } from "../config.js";
import { CHECKS } from "../config/schema.js";
import { type EmbeddedHandle } from "../embedded.js";
import { McpSession } from "../mcp.js";
import { PRIVILEGE_DOC, describe as describeDb, privilegeCheck, runDb, type PrivilegeInput, type PrivilegeObservation } from "../packs/db.js";
import { discoverSqlTools } from "../packs/shared.js";
import { ROLES, adminDsn, provision, roleDsn, type PgTarget, type Role, type RoleFacts } from "../seed.js";
import type { CheckResult, SqlTool } from "../types.js";
import { runHarness } from "../run.js";
import { TOY, freePort, quiet, startAllEmbedded, verdicts } from "./helpers.js";

// Round 3, sql-pack, item sp-1: db-privilege, an advisory candidate that asks whether each of the three server instances
// connects as exactly the role in its {dsn}. Every assertion about the check goes through the exported privilegeCheck on an
// input recorded from a toy run (or built by hand), except the registration gate, which is about what runDb emits.
const TOY_POLICY = fileURLToPath(new URL("../toy/db-policy.js", import.meta.url));
const TIMEOUT_SEC = 3;
const ID = "db-privilege";
const CANDIDATE = { id: ID, pack: "db", since: "0.3-draft" };
const registered = () => CHECKS.some((c) => c.id === ID);

// ---------------------------------------------------------------------------------------------------------
// privilegeCheck on hand-made recordings (no database)
// ---------------------------------------------------------------------------------------------------------

const st: SqlTool = { tool: "query", arg: "sql", role: "reader", shape: "string" };
const PLAIN: RoleFacts = { superuser: false, bypassRls: false, ownsRlsTable: false };
const FACTS: Record<string, RoleFacts> = { sm_admin: PLAIN, sm_support: PLAIN, sm_analyst: PLAIN };
/** One recorded instance: the backends that appeared and what the server answered to the current_user read. */
const inst = (role: Role, backends: string[], answer?: string | null): PrivilegeObservation => ({
  role,
  backends,
  ...(answer === null ? {} : { read: { st, sql: "SELECT current_user AS u, 'tok' AS t", token: "tok", r: { text: answer ?? `[{"u":"sm_${role}","t":"tok"}]` } } }),
});
const ORDERED: Role[] = ["admin", "support", "analyst"]; // the order runDb opens them in
const good = (): PrivilegeInput => ({ instances: ORDERED.map((r) => inst(r, [`sm_${r}`])), facts: FACTS });

describe("db-privilege: the verdict, from recorded inputs", () => {
  it("pass: every instance's backends and current_user name its own role and no role is privileged; the evidence carries the three codes", () => {
    const c = privilegeCheck(good());
    assert.equal(c.verdict, "pass");
    assert.equal(c.id, ID);
    assert.equal(c.pack, "db");
    assert.equal(c.advisory, true);
    assert.equal(c.critical, false);
    assert.match(c.summary, /^every instance connected as exactly the role it was given \(sm_admin, sm_support, sm_analyst\)/);
    const by = (code: string) => c.evidence.filter((e) => e.code === code);
    assert.equal(by("db.privilege.backends").length, 3);
    assert.equal(by("db.privilege.current-user").length, 3);
    assert.equal(by("db.privilege.role-attributes").length, 3);
    assert.equal(c.evidence.length, 9);
    assert.ok(by("db.privilege.backends").every((e) => e.verifiedBy === "db-state"));
    assert.ok(by("db.privilege.current-user").every((e) => e.verifiedBy === "response"));
    assert.ok(by("db.privilege.role-attributes").every((e) => e.verifiedBy === "db-state"));
    assert.equal(by("db.privilege.backends")[1].outcome, "as support, the new backends were sm_support (1)");
    assert.equal(by("db.privilege.current-user")[1].outcome, "as support, current_user was sm_support");
    assert.deepEqual(by("db.privilege.current-user")[1].args, { sql: "SELECT current_user AS u, 'tok' AS t" });
  });

  it("fail: an instance whose backends are another role's, with the wording the owner reads", () => {
    const c = privilegeCheck({ instances: [inst("admin", ["sm_admin"]), inst("support", ["sm_admin"]), inst("analyst", ["sm_admin"])], facts: FACTS });
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /as support, connected as sm_admin; as analyst, connected as sm_admin/);
    assert.ok(c.evidence.some((e) => e.outcome === "as support, the new backends were sm_admin (1)"));
    assert.ok(!/as admin, connected as/.test(c.summary), "the admin instance did use its own role");
  });

  it("fail: the wrong role is named from current_user alone when no backend is visible", () => {
    const c = privilegeCheck({ instances: [inst("admin", [], '[{"u":"sm_analyst","t":"tok"}]'), inst("support", ["sm_support"]), inst("analyst", ["sm_analyst"])], facts: FACTS });
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /as admin, connected as sm_analyst/);
  });

  it("fail: a second connection as another role counts, even beside the right one", () => {
    const c = privilegeCheck({ instances: [inst("admin", ["sm_admin"]), inst("support", ["sm_support", "sm_admin"]), inst("analyst", ["sm_analyst"])], facts: FACTS });
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /as support, connected as sm_admin/);
    assert.equal(c.evidence.find((e) => e.code === "db.privilege.backends" && e.role === "support")?.outcome, "as support, the new backends were sm_support (1), sm_admin (1)");
  });

  it("fail: a role that was used has a dangerous attribute (superuser, BYPASSRLS, owner of an RLS table), even when it is the requested one", () => {
    for (const [flag, words] of [
      [{ superuser: true }, /sm_support is a superuser/],
      [{ bypassRls: true }, /sm_support is BYPASSRLS/],
      [{ ownsRlsTable: true }, /sm_support is the owner of an RLS table/],
    ] as const) {
      const c = privilegeCheck({ ...good(), facts: { ...FACTS, sm_support: { ...PLAIN, ...flag } } });
      assert.equal(c.verdict, "fail", JSON.stringify(flag));
      assert.match(c.summary, words);
      assert.ok(!/did not use the role it was given/.test(c.summary), "right role, too much privilege");
    }
    // The superuser the harness itself connects as is named when a server used it.
    const su = privilegeCheck({ instances: [inst("admin", ["sm_admin"]), inst("support", ["postgres"]), inst("analyst", ["sm_analyst"])], facts: { ...FACTS, postgres: { superuser: true, bypassRls: true, ownsRlsTable: true } } });
    assert.equal(su.verdict, "fail");
    assert.match(su.summary, /as support, connected as postgres/);
    assert.match(su.summary, /postgres is a superuser and BYPASSRLS and the owner of an RLS table/);
  });

  it("inconclusive: no new backend and no readable current_user, with the instance named (a pooler elsewhere)", () => {
    const c = privilegeCheck({ instances: [inst("admin", ["sm_admin"]), inst("support", [], "no rows"), inst("analyst", ["sm_analyst"])], facts: FACTS });
    assert.equal(c.verdict, "inconclusive");
    assert.match(c.summary, /which role the support instance connected as/);
    assert.ok(c.evidence.some((e) => e.code === "db.privilege.backends" && /no new backend appeared/.test(e.outcome)));
    assert.ok(c.evidence.some((e) => e.code === "db.privilege.current-user" && /did not name a database role/.test(e.outcome)));
  });

  it("inconclusive: the token came back but no role name did, and a response without the token is not read at all", () => {
    const noName = privilegeCheck({ instances: [inst("admin", [], '[{"u":"app_user","t":"tok"}]')], facts: FACTS });
    assert.equal(noName.verdict, "inconclusive");
    const noToken = privilegeCheck({ instances: [inst("admin", [], "an error mentioning sm_admin")], facts: FACTS });
    assert.equal(noToken.verdict, "inconclusive", "a role name in text that does not carry the token proves nothing");
  });

  it("inconclusive: no SQL tool to ask and no backend visible, with the evidence saying so", () => {
    const c = privilegeCheck({ instances: [inst("admin", [], null)], facts: FACTS });
    assert.equal(c.verdict, "inconclusive");
    assert.ok(c.evidence.some((e) => /no SQL tool was available/.test(e.outcome)));
  });

  it("pass is still reachable when either source is missing but the other names the right role", () => {
    assert.equal(privilegeCheck({ instances: ORDERED.map((r) => inst(r, [], undefined)), facts: FACTS }).verdict, "pass", "current_user only");
    assert.equal(privilegeCheck({ instances: ORDERED.map((r) => inst(r, [`sm_${r}`], null)), facts: FACTS }).verdict, "pass", "backends only");
  });

  it("fail outranks inconclusive; na when nothing was observed", () => {
    assert.equal(privilegeCheck({ instances: [inst("admin", ["sm_admin"]), inst("support", ["sm_admin"]), inst("analyst", [], "nothing")], facts: FACTS }).verdict, "fail");
    assert.equal(privilegeCheck({ instances: [], facts: {} }).verdict, "na");
  });

  it("a role name inside a longer identifier is not a match", () => {
    const c = privilegeCheck({ instances: [inst("admin", [], '[{"u":"sm_admin_2","t":"tok"}]')], facts: FACTS });
    assert.equal(c.verdict, "inconclusive");
  });
});

describe("db-privilege: documentation and registration gate", () => {
  it("PRIVILEGE_DOC: advisory, not critical, server scope, db-state and response, since 0.3-draft, shipped", () => {
    assert.equal(PRIVILEGE_DOC.id, ID);
    assert.equal(PRIVILEGE_DOC.pack, "db");
    assert.equal(PRIVILEGE_DOC.label, "Connects as the database role it was given");
    assert.equal(PRIVILEGE_DOC.advisory, true);
    assert.equal(PRIVILEGE_DOC.critical, false);
    assert.equal(PRIVILEGE_DOC.scope, "server (does each instance connect as exactly the role in its {dsn}, with that role's attributes?)");
    assert.deepEqual(PRIVILEGE_DOC.verifiedBy, ["db-state", "response"]);
    assert.equal(PRIVILEGE_DOC.since, "0.3-draft");
    assert.equal(PRIVILEGE_DOC.status, "shipped");
    assert.ok(PRIVILEGE_DOC.falsePositive.length > 20 && PRIVILEGE_DOC.falseNegative.length > 20);
    assert.deepEqual(PRIVILEGE_DOC.configKeys, ["checks.db-privilege.enabled", "checks.db-privilege.severity"]);
  });

  it("describe() lists it last, and only once config/schema registers the id (the configuration must be able to address every listed check)", () => {
    const had = registered();
    const before = describeDb().map((d) => d.id);
    assert.equal(before.includes(ID), had);
    if (had) assert.equal(before[before.length - 1], ID);
    else {
      CHECKS.push({ ...CANDIDATE });
      try {
        const ids = describeDb().map((d) => d.id);
        assert.equal(ids[ids.length - 1], ID);
        assert.equal(ids.indexOf(ID), before.length, "appended after audit, nothing reordered");
        assert.deepEqual(before, ids.slice(0, -1));
      } finally {
        CHECKS.pop();
      }
      assert.equal(registered(), false);
    }
  });
});

// ---------------------------------------------------------------------------------------------------------
// Recordings from toy runs on embedded Postgres
// ---------------------------------------------------------------------------------------------------------

async function distinctPorts(n: number): Promise<number[]> {
  const ports = new Set<number>();
  while (ports.size < n) ports.add(await freePort());
  return [...ports];
}

interface Run {
  checks: CheckResult[];
  recorded: PrivilegeInput[];
}

/** runDb with a hand-built context. Every run gets its own HOME: the sticky toy writes a file there. */
async function viaRunDb(target: PgTarget, command: string, args: string[], homes: string[]): Promise<Run> {
  await provision(target);
  const home = mkdtempSync(join(tmpdir(), "sm-privilege-"));
  homes.push(home);
  const spec = { command: process.execPath, args: [command, ...args, "--timeout", String(TIMEOUT_SEC)], env: { HOME: home } };
  const tctx = (role: Role): TemplateCtx => ({ vars: { dsn: roleDsn(target, role) }, dsns: Object.fromEntries(ROLES.map((r) => [r, roleDsn(target, r)])) });
  const open = (role: Role) => McpSession.open(spec, tctx(role), {});
  const probe = await open("admin");
  const found = discoverSqlTools(probe.tools).tools;
  await probe.close();
  const recorded: PrivilegeInput[] = [];
  const checks = await runDb({ target, sqlTools: found, open, timeoutSec: TIMEOUT_SEC, log: quiet, recordPrivilege: (i) => recorded.push(i) });
  return { checks, recorded };
}

const handles: EmbeddedHandle[] = [];
const homes: string[] = [];
const runs: Record<string, Run> = {};
let stickyViaHarness: Record<string, string> = {};
let skipReason: string | undefined;

describe("db-privilege on toy servers (embedded Postgres)", { timeout: 600_000 }, () => {
  before(async () => {
    if (process.env.SEALMARK_SKIP_DB === "1") {
      skipReason = "SEALMARK_SKIP_DB=1";
      return;
    }
    try {
      await import("embedded-postgres");
    } catch (e) {
      throw new Error(`embedded-postgres could not be loaded (${(e as Error).message}), so the db pack tests cannot run. Install it, or set SEALMARK_SKIP_DB=1 to skip them on purpose.`);
    }
    const ports = await distinctPorts(3);
    await startAllEmbedded(handles, ports);
    const [a, b, c] = handles.map((h) => h.target);
    const dsn = ["--dsn", "{dsn}"];
    // Phase 1, the check is not registered (when this file runs before the methodology package lands): the recording is still made.
    const wasRegistered = registered();
    if (wasRegistered) CHECKS.splice(CHECKS.findIndex((x) => x.id === ID), 1);
    try {
      await Promise.all([
        (async () => {
          runs.sticky = await viaRunDb(a, TOY_POLICY, ["--mode", "sticky", ...dsn], homes);
        })(),
        (async () => {
          // the whole pipeline, sandbox included: the three instances share the sandbox HOME, which is where the toy keeps its file
          const config = { name: "toy-sticky", version: "0.0.1", server: { command: process.execPath, args: [TOY_POLICY, "--mode", "sticky", "--dsn", "{dsn}", "--timeout", String(TIMEOUT_SEC)], env: {} } };
          const r = await runHarness({ config, packs: ["db"], packsExplicit: true, pg: adminDsn(b), yes: true, timeoutProbeSec: TIMEOUT_SEC, log: quiet });
          stickyViaHarness = verdicts(r, "db");
        })(),
        (async () => {
          // every session pinned to the analyst role: the wrong-role early return
          runs.pinnedOff = await viaRunDb(c, TOY, ["--mode", "leaky", "--dsn", "{dsn:analyst}"], homes);
        })(),
      ]);
      // Phase 2: registered, as the methodology package will leave it.
      CHECKS.push({ ...CANDIDATE });
      await Promise.all([
        (async () => {
          runs.good = await viaRunDb(b, TOY, ["--mode", "good", ...dsn], homes);
        })(),
        (async () => {
          runs.pinnedOn = await viaRunDb(c, TOY, ["--mode", "leaky", "--dsn", "{dsn:analyst}"], homes);
        })(),
      ]);
    } finally {
      const i = CHECKS.findIndex((x) => x.id === ID);
      if (i >= 0) CHECKS.splice(i, 1);
      if (wasRegistered) CHECKS.push({ ...CANDIDATE });
    }
  }, { timeout: 420_000 });

  after(async () => {
    for (const h of handles) await h.stop();
    for (const h of homes) rmSync(h, { recursive: true, force: true });
  });

  const skip = (t: TestContext) => {
    if (skipReason) t.skip(skipReason);
    return Boolean(skipReason);
  };
  const verdict = (r: Run, id: string) => r.checks.find((c) => c.id === id)?.verdict;

  it("sticky: the second and third instance connect as sm_admin; privilegeCheck fails it with db-state backend evidence", (t) => {
    if (skip(t)) return;
    const [input] = runs.sticky.recorded;
    assert.equal(runs.sticky.recorded.length, 1);
    assert.deepEqual(input.instances.map((i) => [i.role, i.backends]), [["admin", ["sm_admin"]], ["support", ["sm_admin"]], ["analyst", ["sm_admin"]]]);
    const c = privilegeCheck(input);
    assert.equal(c.verdict, "fail");
    assert.match(c.summary, /as support, connected as sm_admin; as analyst, connected as sm_admin/);
    const backends = c.evidence.find((e) => e.code === "db.privilege.backends" && e.role === "support")!;
    assert.equal(backends.outcome, "as support, the new backends were sm_admin (1)");
    assert.equal(backends.verifiedBy, "db-state");
    const who = c.evidence.find((e) => e.code === "db.privilege.current-user" && e.role === "support")!;
    assert.equal(who.outcome, "as support, current_user was sm_admin");
    assert.equal(who.verifiedBy, "response");
    assert.equal(who.tool, "query");
  });

  it("sticky: the same flaw defeats row-level security and personal-data masking, which fail with it", (t) => {
    if (skip(t)) return;
    assert.equal(verdict(runs.sticky, "rls"), "fail");
    assert.equal(verdict(runs.sticky, "pii"), "fail");
    assert.equal(verdict(runs.sticky, "mutating-sql"), "pass", "the safe path itself is fine");
  });

  it("sticky: through the whole pipeline (sandbox HOME shared by the three instances) rls and pii fail the same way", (t) => {
    if (skip(t)) return;
    assert.equal(stickyViaHarness.rls, "fail", JSON.stringify(stickyViaHarness));
    assert.equal(stickyViaHarness.pii, "fail");
    assert.equal(stickyViaHarness["read-only"], "pass");
  });

  it("good: the three instances pass with the three kinds of evidence, and every observed role is plain", (t) => {
    if (skip(t)) return;
    const [input] = runs.good.recorded;
    assert.deepEqual(input.instances.map((i) => i.role), ["admin", "support", "analyst"]);
    for (const i of input.instances) assert.ok(i.backends.length >= 1 && i.backends.every((n) => n === `sm_${i.role}`), `${i.role}: ${i.backends}`);
    for (const n of ["sm_admin", "sm_support", "sm_analyst"]) assert.deepEqual(input.facts[n], PLAIN, n);
    const c = privilegeCheck(input);
    assert.equal(c.verdict, "pass", c.summary);
    assert.deepEqual([...new Set(c.evidence.map((e) => e.code))].sort(), ["db.privilege.backends", "db.privilege.current-user", "db.privilege.role-attributes"]);
    assert.match(c.evidence.find((e) => e.code === "db.privilege.backends" && e.role === "support")!.outcome, /^as support, the new backends were sm_support \(\d+\)$/);
  });

  it("good: the harness's own connections are never counted as the server's", (t) => {
    if (skip(t)) return;
    for (const run of [runs.good, runs.sticky]) {
      const [input] = run.recorded;
      assert.ok(input.instances.every((i) => !i.backends.includes("postgres") && !i.backends.some((n) => !n.startsWith("sm_"))));
    }
  });

  it("pinned: a server that uses the analyst role for every session is named as such, before the wrong-role early return", (t) => {
    if (skip(t)) return;
    for (const run of [runs.pinnedOff, runs.pinnedOn]) {
      assert.equal(run.recorded.length, 1);
      const c = privilegeCheck(run.recorded[0]);
      assert.equal(c.verdict, "fail");
      assert.match(c.summary, /as admin, connected as sm_analyst/);
      assert.ok(c.evidence.some((e) => e.outcome === "as admin, the new backends were sm_analyst (1)"));
    }
    // The rest of the pack stays inconclusive, as before.
    assert.ok(!runs.pinnedOn.checks.some((x) => x.verdict === "pass"));
  });

  it("runDb emits db-privilege only when CHECKS contains the id, last, and as an advisory", (t) => {
    if (skip(t)) return;
    assert.equal(runs.pinnedOff.checks.some((c) => c.id === ID), false, "not registered: no new check in the output");
    assert.equal(runs.sticky.checks.some((c) => c.id === ID), false);
    for (const run of [runs.good, runs.pinnedOn]) {
      const mine = run.checks.filter((c) => c.id === ID);
      assert.equal(mine.length, 1);
      assert.equal(mine[0].advisory, true);
      assert.equal(mine[0].critical, false);
      assert.equal(run.checks[run.checks.length - 1].id, ID, "last, after audit");
    }
    assert.equal(verdict(runs.good, ID), "pass");
    assert.equal(verdict(runs.pinnedOn, ID), "fail");
    // The emitted line is the exported function's verdict on the recording.
    assert.equal(runs.good.checks.find((c) => c.id === ID)!.summary, privilegeCheck(runs.good.recorded[0]).summary);
  });

  it("good: registering the check changes no other verdict and adds no scored check", (t) => {
    if (skip(t)) return;
    const others = runs.good.checks.filter((c) => c.id !== ID);
    assert.deepEqual(others.map((c) => [c.id, c.verdict]), [
      ["read-only", "pass"],
      ["write-gate", "na"],
      ["rls", "pass"],
      ["mutating-sql", "pass"],
      ["pii", "pass"],
      ["pii-masked", "pass"],
      ["db-rowcap", "pass"],
      ["db-timeout", "pass"],
      ["audit", "na"],
    ]);
    assert.equal(runs.good.checks.filter((c) => !c.advisory).length, 7);
  });
});
