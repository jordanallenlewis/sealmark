import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { parse } from "yaml";
import { ciSnippet } from "../ci-snippet.js";
import { loadEffectiveConfig } from "../config/index.js";
import { renderReport, renderText } from "../report.js";
import { badgeText } from "../report/badge.js";
import { PACK_ORDER, orderedPackIds } from "../report/common.js";
import { renderMarkdown } from "../report/markdown.js";
import { makeRunNormaliser, makeSecretScrubber, redactResult } from "../report/redact.js";
import { secretLiterals } from "../report/secrets.js";
import type { PackGrade, RunResult } from "../types.js";
import { check } from "./helpers.js";

/** Round 6, package P2 (config-report): redaction of the stub's port and the minted identities, the candidate-pack label, the badge, suggestions, the CI lines. */

const hex = (n: number, seed = 3) => Array.from({ length: n }, (_, i) => "0123456789abcdef"[(seed * (i + 5) + i * i) % 16]).join("");
const A = `sm-bearer-a-${hex(12)}`;
const B = `sm-bearer-b-${hex(12, 5)}`;
const PORT = 43211;

function grade(pack: string, letter: PackGrade["letter"]): PackGrade {
  return { pack: pack as PackGrade["pack"], points: 3, scored: 4, pct: 75, raw: letter, letter, capped: false, criticalFails: [], provisional: false, excluded: [] };
}

function run(over: Record<string, unknown> = {}, packs: Record<string, PackGrade["letter"]> = { core: "A", scope: "B" }): RunResult {
  const graded = Object.fromEntries(Object.entries(packs).map(([id, l]) => [id, { status: "graded", grade: grade(id, l) }]));
  return {
    sealmark: { version: "0.2.1", methodology: "0.3-draft" },
    server: { name: "Toy", version: "1.0.0", command: "node toy.js", env: {}, transport: "http", launched: true, tools: ["describe_table"], sqlTools: [] },
    options: { packsRequested: Object.keys(packs), timeoutProbeSec: 10, sandbox: true },
    startedAt: "2026-10-14T00:00:00.000Z",
    durationMs: 5,
    packs: graded,
    checks: [check("protocol", "pass"), check("scope-escape", "pass", { pack: "scope" as never, critical: true })],
    notCovered: [],
    config: { hash: "sha256:aa", profile: "standard", standard: true, standardDiff: [], methodology: "0.3-draft", schemaVersion: 1, locked: {} },
    sandbox: { enabled: true, dir: "/tmp/sealmark-0123456789", envMode: "scrubbed", listenerPort: 40000, kept: false, cleanedUp: true, leftoverProcesses: [] },
    badge: { eligible: true },
    ...over,
  } as unknown as RunResult;
}

describe("the second ephemeral port and the minted tokens are rewritten to stable names", () => {
  const norm = makeRunNormaliser({ listenerPort: 40000, upstreamPort: PORT });

  it("the upstream port follows a host in any spelling, in a URL and percent-encoded", () => {
    assert.equal(norm(`POST http://127.0.0.1:${PORT}/sql`), "POST http://127.0.0.1:{upstream_port}/sql");
    assert.equal(norm(`backend=localhost:${PORT} and [::1]:${PORT}`), "backend=localhost:{upstream_port} and [::1]:{upstream_port}");
    assert.equal(norm(`u=http%3A%2F%2F127.0.0.1%3A${PORT}`), "u=http%3A%2F%2F127.0.0.1%3A{upstream_port}".replace("%3A{upstream_port}", "%3A{upstream_port}"));
    assert.equal(norm("127.0.0.1:40000 and 127.0.0.1:43211"), "127.0.0.1:{listener_port} and 127.0.0.1:{upstream_port}");
    assert.equal(norm(`a:${PORT}0 b:1${PORT}`), `a:${PORT}0 b:1${PORT}`, "a longer number is not the port");
  });

  it("the old single-argument form keeps working", () => {
    assert.equal(makeRunNormaliser(40000)("127.0.0.1:40000"), "127.0.0.1:{listener_port}");
    assert.equal(makeRunNormaliser(null)("127.0.0.1:40000"), "127.0.0.1:40000");
  });

  it("a minted bearer becomes {bearer:a} / {bearer:b} in evidence text, a file name and a URL", () => {
    assert.equal(norm(`Authorization: Bearer ${A}`), "Authorization: Bearer {bearer:a}");
    assert.equal(norm(`saw ${B} and ${A}`), "saw {bearer:b} and {bearer:a}");
    assert.equal(norm(`log-${A}.txt`), "log-{bearer:a}.txt");
    assert.equal(norm(`http://127.0.0.1:${PORT}/sql?access=${B}&x=1`), "http://127.0.0.1:{upstream_port}/sql?access={bearer:b}&x=1");
    assert.equal(norm(`path/${A}/x`), "path/{bearer:a}/x");
  });

  it("the stub's row marker and error canary are rewritten; a lookalike inside a longer word is not", () => {
    assert.equal(norm(`row sm-row-${hex(8)} echoed`), "row {row} echoed");
    assert.equal(norm(`body sm-upstream-err-${hex(12)}`), "body {upstream_error}");
    assert.equal(norm(`xsm-bearer-a-${hex(12)}`), `xsm-bearer-a-${hex(12)}`);
    assert.equal(norm(`sm-bearer-a-${hex(11)}`), `sm-bearer-a-${hex(11)}`);
    assert.equal(norm(`sm-bearer-c-${hex(12)}`), `sm-bearer-c-${hex(12)}`);
  });
});

describe("redactResult with an upstream stub in the result", () => {
  it("prints the stub's address as {upstream} and rewrites the port and bearers everywhere in the result", () => {
    const r = run(
      { upstream: { kind: "http", requests: 4, scripted: 1, url: `http://127.0.0.1:${PORT}` }, identities: { names: ["a", "b"], source: "minted" } },
      { core: "A", scope: "B" },
    );
    r.checks[1].summary = `reached http://127.0.0.1:${PORT}/sql with ${A}`;
    r.checks[1].evidence = [{ probe: `sibling ${B}`, outcome: `POST 127.0.0.1:${PORT} Authorization: Bearer ${A}`, verifiedBy: "upstream" } as never];
    const out = redactResult(r);
    assert.equal((out as unknown as { upstream: { url: string } }).upstream.url, "{upstream}");
    const json = JSON.stringify(out);
    assert.ok(!json.includes(String(PORT)), "the stub port is gone");
    assert.ok(!json.includes(A) && !json.includes(B), "no minted bearer is left");
    assert.match(json, /\{bearer:a\}/);
    assert.match(json, /\{bearer:b\}/);
    assert.match(json, /127\.0\.0\.1:\{upstream_port\}/);
  });

  it("--no-redact leaves everything as it was", () => {
    const r = run({ upstream: { kind: "http", requests: 1, scripted: 0, url: `http://127.0.0.1:${PORT}` } });
    assert.equal((redactResult(r, { redact: false }) as unknown as { upstream: { url: string } }).upstream.url, `http://127.0.0.1:${PORT}`);
  });

  it("a result without a stub is untouched by the new rules (no upstream key appears)", () => {
    assert.ok(!("upstream" in redactResult(run())));
  });
});

describe("identities.* values are secrets", () => {
  const empty = mkdtempSync(join(tmpdir(), "sealmark-r6rep-"));
  after(() => rmSync(empty, { recursive: true, force: true }));
  const cfgOf = (flags: string, env: Record<string, string> = {}) => loadEffectiveConfig({ cwd: empty, isolated: true, env, flags: { start: "node srv.js", ...JSON.parse(flags) } });

  it("secretLiterals lists the value as written and as read from the environment", () => {
    const cfg = cfgOf('{"identity-a":"${TOKEN_A}","identity-b":"literal-token-b"}', { TOKEN_A: "resolved-token-a" });
    const lits = secretLiterals(cfg);
    assert.ok(lits.includes("resolved-token-a"));
    assert.ok(lits.includes("literal-token-b"));
    const scrub = makeSecretScrubber(lits);
    assert.equal(scrub("saw resolved-token-a and literal-token-b"), "saw <redacted> and <redacted>");
  });

  it("a configuration without identities adds nothing", () => {
    assert.deepEqual(secretLiterals(cfgOf("{}")).filter((s) => /token/i.test(s)), []);
  });
});

describe("a candidate pack is labelled in every format and stays off the badge", () => {
  it("text: the label follows the grade; a standard pack has none", () => {
    const t = renderText(run());
    assert.match(t, /^PACK scope  GRADE B  \(.*\)  candidate pack: not part of the standard profile$/m);
    assert.match(t, /^PACK core  GRADE A  \([^)]*\)$/m);
  });

  it("markdown: an italic line under the pack's grade", () => {
    const md = renderMarkdown([run()]);
    assert.match(md, /Pack `scope`\n\n\*\*Grade B\*\*[^\n]*\n\n_candidate pack: not part of the standard profile_/);
    assert.ok(!/Pack `core`[\s\S]{0,200}candidate pack/.test(md.split("Pack `scope`")[0]));
  });

  it("the pack order puts the candidate packs after effects and before custom, and the report follows it", () => {
    assert.deepEqual(PACK_ORDER.slice(8, 13), ["effects", "scope", "sql-guard", "upstream", "custom"]);
    const r = run({}, { upstream: "A", core: "A", custom: "A", scope: "B" });
    assert.deepEqual(orderedPackIds(r), ["core", "scope", "upstream", "custom"]);
  });

  it("the badge lists standard packs only; a candidate-only run has nothing to show", () => {
    assert.equal(badgeText(run()).message, "core A · self-reported");
    assert.equal(badgeText(run({}, { scope: "A", upstream: "B" })).message, "no badge: nothing graded");
  });

  it("the shields and svg formats do not name a candidate pack", () => {
    for (const fmt of ["badge", "shields"] as const) assert.ok(!renderReport(fmt, [run()]).includes("scope"), fmt);
  });
});

describe("the stub, the identities, the launched-server sandbox and the suggestions are reported", () => {
  const r = () =>
    run({
      upstream: { kind: "http", requests: 12, scripted: 3, url: `http://127.0.0.1:${PORT}` },
      identities: { names: ["a", "b"], source: "minted" },
      suggestions: [{ id: "probes", kind: "probes", why: "no probes: one valid call per tool gives core real coverage", config: "probes:\n  - { tool: list_tables, args: {} }\n", flags: ["init", "--probes", "--write", "--yes"] }],
    });

  it("text: sandbox line says the launched server ran inside it; the stub and identity lines print placeholders and names only", () => {
    const t = renderText(r());
    assert.match(t, /^sandbox: .*the launched HTTP server was started inside the sandbox/m);
    assert.match(t, /^upstream: http stub \{upstream\}, 12 requests recorded \(3 answered by a scripted reply\)$/m);
    assert.match(t, /^identities: a, b \(minted for this run\)$/m);
    assert.ok(!t.includes(String(PORT)));
  });

  it("text: a Suggestions block names the key, the flags and the YAML to paste, and comes before the closing line", () => {
    const t = renderText(r());
    const i = t.indexOf("Suggestions:");
    assert.ok(i > 0);
    assert.match(t.slice(i), /^Suggestions:\n  - \[probes\] no probes: .*\n      flags: init --probes --write --yes\n      sealmark\.yaml:\n        probes:\n          - \{ tool: list_tables, args: \{\} \}\n/);
    assert.ok(i < t.indexOf("An A means these checks passed"));
  });

  it("text --quiet omits the suggestions; markdown has a Suggestions heading with a yaml block", () => {
    assert.ok(!renderText(r(), { verbosity: "quiet" }).includes("Suggestions:"));
    const md = renderMarkdown([r()]);
    assert.match(md, /## Suggestions\n\n- \*\*probes\*\*: no probes: .* Flags: `init --probes --write --yes`\n\n  ```yaml\n  probes:/);
    assert.match(md, /the launched HTTP server was started inside the sandbox/);
    assert.match(md, /upstream: http stub \{upstream\}/);
  });

  it("a result without the new fields prints none of them", () => {
    const t = renderText(run());
    assert.ok(!/^upstream:|^identities:|Suggestions:/m.test(t));
  });

  it("JSON carries the fields as the harness set them, redacted", () => {
    const j = JSON.parse(renderReport("json", [r()])) as { upstream: { url: string; requests: number }; identities: { names: string[] }; suggestions: { id: string }[] };
    assert.equal(j.upstream.url, "{upstream}");
    assert.equal(j.upstream.requests, 12);
    assert.deepEqual(j.identities.names, ["a", "b"]);
    assert.equal(j.suggestions[0].id, "probes");
  });
});

describe("init --ci prints the lines the configuration declares", () => {
  const command = (text: string): string => {
    const doc = parse(text) as { sealmark: { script: string[] } };
    return doc.sealmark.script[0];
  };

  it("without declarations the job is the plain one", () => {
    assert.equal(command(ciSnippet("gitlab", "1.2.3")).trim(), 'npx -y sealmark@1.2.3 run --start "my-server --port 8000" --url http://localhost:8000/mcp');
  });

  it("a declared stub, bearer passthrough and scope become flags, and the command stays one parsed YAML string", () => {
    const text = ciSnippet("gitlab", "1.2.3", { upstream: true, bearer: true, scopeTools: [{ tool: "describe_table", param: "table" }], scopeAllow: ["sales.public."], scopeDeny: ["hr.private.salaries"] });
    assert.equal(
      command(text).trim(),
      'npx -y sealmark@1.2.3 run --start "my-server --port 8000 --backend {upstream}" --url http://localhost:8000/mcp --upstream --header "Authorization: Bearer {bearer}" --scope-tool describe_table=table --scope-allow sales.public. --scope-deny hr.private.salaries',
    );
  });

  it("a github job gets the same lines and an identifier with a space is quoted", () => {
    const text = ciSnippet("github", "1.2.3", { scopeAllow: ["my schema."], scopeTools: [{ tool: "t", param: "p" }] });
    const doc = parse(text) as { jobs: { sealmark: { steps: { run?: string }[] } } };
    const cmd = doc.jobs.sealmark.steps.find((s) => s.run)!.run!;
    assert.match(cmd, /--scope-tool t=p --scope-allow "my schema\."/);
  });
});
