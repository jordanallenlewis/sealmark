import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SCOPE_FAMILIES, caseControl, controlIdentifiers, describe as describeScope, inScope, scopeCorpus, type ScopeSettings } from "../packs/scope.js";

// Round 6 (design 3.3): the published out-of-scope corpus is pinned for the three allow forms, and every identifier in it is out of scope
// under both case rules. The generator is pure; a counter stands in for the random token so the text is stable.

const counter = (): (() => string) => {
  let n = 0;
  return () => String(++n).padStart(3, "0");
};
const settings = (allow: string[], deny: string[] = ["hr.private.salaries"], over: Partial<ScopeSettings> = {}): Pick<ScopeSettings, "allow" | "deny" | "separator" | "case"> => ({ allow, deny, separator: ".", case: "insensitive", ...over });
const table = (s: ReturnType<typeof settings>): string[] => scopeCorpus(s, counter()).map((p) => `${p.id} | ${p.identifier} | ${p.needle}`);

describe("the scope corpus, pinned", () => {
  it("exact allow entry", () => {
    assert.deepEqual(table(settings(["sales.public.orders"])), [
      "sibling | sales.public.orders_sm001 | sm001",
      "container | sales.public | sales.public",
      "container#2 | sales | sales",
      "partial | sales.public.ord | sales.public.ord",
      "prefix-abuse | sales.public.ordersx | sales.public.ordersx",
      "case | SALES.PUBLIC.ORDERS_SM002 | sm002",
      'quoted | "sales"."public"."outside_sm003" | sm003',
      "separator-encoded | sales%2Epublic%2Eoutside_sm004 | sm004",
      "separator-encoded#2 | sales/public/outside_sm005 | sm005",
      "traversal | sales.public.orders.._sm006 | sm006",
      "traversal#2 | sales.public.orders/../outside_sm007 | sm007",
      "deny | hr.private.salaries | hr.private.salaries",
    ]);
  });

  it("prefix allow entry", () => {
    assert.deepEqual(table(settings(["sales.public."])), [
      "container | sales.public | sales.public",
      "container#2 | sales | sales",
      "partial | sales.pub | sales.pub",
      "prefix-abuse | sales.publicx.t_sm001 | sm001",
      "case | SALES.PUBLICX.T_SM002 | sm002",
      'quoted | "sales"."public"."outside_sm003" | sm003',
      "separator-encoded | sales%2Epublic%2Eoutside_sm004 | sm004",
      "separator-encoded#2 | sales/public/outside_sm005 | sm005",
      "traversal | sales.public.sm_base.._sm006 | sm006",
      "traversal#2 | sales.public.sm_base/../outside_sm007 | sm007",
      "deny | hr.private.salaries | hr.private.salaries",
    ]);
  });

  it("exact and prefix together: forms that the prefix makes allowed are not escapes and are left out", () => {
    const rows = table(settings(["sales.public.orders", "sales.public."]));
    assert.deepEqual(rows, [
      "container | sales.public | sales.public",
      "container#2 | sales | sales",
      "prefix-abuse | sales.publicx.t_sm002 | sm002",
      "case | SALES.PUBLICX.T_SM003 | sm003",
      'quoted | "sales"."public"."outside_sm004" | sm004',
      "separator-encoded | sales%2Epublic%2Eoutside_sm005 | sm005",
      "separator-encoded#2 | sales/public/outside_sm006 | sm006",
      "traversal | sales.public.orders.._sm007 | sm007",
      "traversal#2 | sales.public.orders/../outside_sm008 | sm008",
      "deny | hr.private.salaries | hr.private.salaries",
    ]);
  });

  it("every deny entry is a probe as written, and deny wins over allow", () => {
    const s = settings(["sales.public."], ["sales.public.secret", "hr."]);
    const deny = scopeCorpus(s, counter()).filter((p) => p.family === "deny");
    assert.deepEqual(deny.map((p) => p.identifier), ["sales.public.secret", "hr."]);
    assert.equal(inScope("sales.public.secret", s), false);
    assert.equal(inScope("sales.public.orders", s), true);
  });

  it("controls: up to three exact entries, else one name under the first prefix", () => {
    assert.deepEqual(controlIdentifiers({ allow: ["a.b", "c.d", "e.f", "g.h"], separator: "." }, counter()).map((c) => c.identifier), ["a.b", "c.d", "e.f"]);
    assert.deepEqual(controlIdentifiers({ allow: ["sales.public."], separator: "." }, counter()), [{ identifier: "sales.public.sm_control_001", needle: "sm_control_001" }]);
    assert.deepEqual(controlIdentifiers({ allow: [], separator: "." }), []);
  });

  it("case-control: the upper-case spelling of the first exact entry, only when the scope is case-insensitive", () => {
    assert.equal(caseControl({ allow: ["sales.public.orders"], separator: ".", case: "insensitive" }), "SALES.PUBLIC.ORDERS");
    assert.equal(caseControl({ allow: ["sales.public.orders"], separator: ".", case: "sensitive" }), undefined);
    assert.equal(caseControl({ allow: ["sales.public."], separator: ".", case: "insensitive" }), undefined);
  });
});

describe("every family's identifier is out of scope under both case rules", () => {
  const forms: [string, string[]][] = [
    ["exact", ["sales.public.orders"]],
    ["prefix", ["sales.public."]],
    ["both", ["sales.public.orders", "sales.public."]],
    ["two exact", ["a.b.c", "x.y"]],
    ["single segment", ["orders"]],
    ["other separator", ["sales/public/orders"]],
  ];
  for (const [name, allow] of forms) {
    for (const mode of ["sensitive", "insensitive"] as const) {
      it(`${name}, case ${mode}`, () => {
        const s = settings(allow, ["hr.private.salaries"], { case: mode, ...(name === "other separator" ? { separator: "/" } : {}) });
        const corpus = scopeCorpus(s);
        assert.ok(corpus.length >= 3, `${name}: ${corpus.length} probes`);
        for (const p of corpus) {
          assert.equal(inScope(p.identifier, s, "sensitive"), false, `${p.id}: ${p.identifier} (sensitive)`);
          assert.equal(inScope(p.identifier, s, "insensitive"), false, `${p.id}: ${p.identifier} (insensitive)`);
          assert.ok(p.identifier.length > 0 && p.needle.length > 0);
        }
        // Each token-bearing probe is on a fresh identifier, so a stub observation maps back to one probe.
        const needles = corpus.filter((p) => p.needle !== p.identifier).map((p) => p.needle);
        assert.equal(new Set(needles).size, needles.length);
      });
    }
  }

  it("the allowed names themselves are in scope, with the case rule applied", () => {
    const s = settings(["sales.public.orders", "lake."]);
    assert.equal(inScope("sales.public.orders", s), true);
    assert.equal(inScope("SALES.PUBLIC.ORDERS", s, "insensitive"), true);
    assert.equal(inScope("SALES.PUBLIC.ORDERS", s, "sensitive"), false);
    assert.equal(inScope("lake.x", s), true);
    assert.equal(inScope("lakex.y", s), false);
    assert.equal(inScope("lake.x/../y", s), false);
  });
});

describe("describe()", () => {
  it("documents scope-escape and every family the run sends", () => {
    const [doc] = describeScope();
    assert.equal(doc.id, "scope-escape");
    assert.equal(doc.critical, true);
    assert.equal(doc.advisory, false);
    const ids = doc.probes.map((p) => p.id);
    for (const f of SCOPE_FAMILIES) assert.ok(ids.includes(f.id), f.id);
    for (const p of scopeCorpus(settings(["sales.public.orders", "sales.public."]))) assert.ok(ids.includes(p.family), p.family);
    assert.deepEqual(doc.verifiedBy, ["upstream", "response"]);
    assert.ok(doc.configKeys.includes("scope.allow") && doc.configKeys.includes("checks.scope-escape.severity"));
  });
});
