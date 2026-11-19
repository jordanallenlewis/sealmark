import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { BADGE_VARIANTS, checkId, renderBadgeSnippets, selfReportedSnippets, siteBadgeSnippets } from "../badge-snippet.js";
import { cliKit } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-badge-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));
const { sealmark } = cliKit(() => dir);

describe("badge snippets for a sealmark.dev badge (--id)", () => {
  it("are the same strings the site's copy buttons give (sealmark-site web/lib/badge.mjs badgeSnippets)", () => {
    const s = siteBadgeSnippets("filesystem");
    assert.equal(s.source, "sealmark.dev");
    assert.equal(s.link, "https://sealmark.dev/results/filesystem/");
    assert.deepEqual(Object.keys(s.variants), [...BADGE_VARIANTS]);
    assert.deepEqual(s.variants.badge, {
      image: "https://sealmark.dev/badge/filesystem.svg",
      markdown: "[![Sealmark](https://sealmark.dev/badge/filesystem.svg)](https://sealmark.dev/results/filesystem/)",
      html: '<a href="https://sealmark.dev/results/filesystem/"><img src="https://sealmark.dev/badge/filesystem.svg" alt="Sealmark"></a>',
      rst: ".. image:: https://sealmark.dev/badge/filesystem.svg\n   :target: https://sealmark.dev/results/filesystem/\n   :alt: Sealmark",
    });
    assert.equal(s.variants.card?.image, "https://sealmark.dev/badge/filesystem-card.svg");
    assert.equal(s.variants.shields?.image, "https://img.shields.io/endpoint?url=https%3A%2F%2Fsealmark.dev%2Fbadge%2Ffilesystem.json");
    assert.equal(s.variants.shields?.markdown, "[![Sealmark](https://img.shields.io/endpoint?url=https%3A%2F%2Fsealmark.dev%2Fbadge%2Ffilesystem.json)](https://sealmark.dev/results/filesystem/)");
  });

  it("take only a server id: lower-case letters, digits and inner hyphens", () => {
    for (const ok of ["git", "a", "mcp-server-123", "9x"]) assert.equal(checkId(ok), ok);
    assert.equal(checkId("  git \n"), "git", "surrounding whitespace from a paste is dropped");
    for (const bad of ["", "Git", "my_server", "-x", "x-", "a/b", "a b", "../etc", "x".repeat(101), "a\nb"]) assert.throws(() => checkId(bad), /is not a sealmark\.dev server id/, bad);
    assert.throws(() => checkId("https://sealmark.dev/results/git/"), /not a URL/);
  });
});

describe("badge snippets for a self-reported badge (--svg)", () => {
  it("say self-reported in the alt text, and link only when asked", () => {
    const s = selfReportedSnippets("badge/sealmark-report.badge.svg");
    assert.equal(s.source, "self-reported");
    assert.equal(s.link, undefined);
    assert.deepEqual(Object.keys(s.variants), ["badge"]);
    assert.deepEqual(s.variants.badge, {
      image: "badge/sealmark-report.badge.svg",
      markdown: "![Sealmark (self-reported)](badge/sealmark-report.badge.svg)",
      html: '<img src="badge/sealmark-report.badge.svg" alt="Sealmark (self-reported)">',
      rst: ".. image:: badge/sealmark-report.badge.svg\n   :alt: Sealmark (self-reported)",
    });
    const linked = selfReportedSnippets("https://raw.githubusercontent.com/o/r/main/badge/x.svg", "https://github.com/o/r/actions");
    assert.equal(linked.link, "https://github.com/o/r/actions");
    assert.equal(linked.variants.badge?.markdown, "[![Sealmark (self-reported)](https://raw.githubusercontent.com/o/r/main/badge/x.svg)](https://github.com/o/r/actions)");
    assert.equal(linked.variants.badge?.rst, ".. image:: https://raw.githubusercontent.com/o/r/main/badge/x.svg\n   :target: https://github.com/o/r/actions\n   :alt: Sealmark (self-reported)");
    assert.equal(selfReportedSnippets("/docs/badge.svg").variants.badge?.image, "/docs/badge.svg", "a repository-root path is kept");
  });

  it("refuse what would render in one format and break in another, and anything but a path or https", () => {
    for (const [bad, why] of [
      ["my badge.svg", /space, quote or bracket/],
      ['x".svg', /space, quote or bracket/],
      ["x).svg", /space, quote or bracket/],
      ["x<script>.svg", /space, quote or bracket/],
      ["badge\\x.svg", /forward slashes/],
      ["javascript:alert(1)", /space, quote or bracket|only a relative path/],
      ["javascript:void", /only a relative path/],
      ["http://example.com/x.svg", /only a relative path/],
      ["data:image/svg+xml;base64,AAAA", /only a relative path/],
      ["//example.com/x.svg", /write the scheme/],
      ["", /needs a value/],
    ] as const) {
      assert.throws(() => selfReportedSnippets(bad), why, bad);
    }
    assert.throws(() => selfReportedSnippets("x.svg", "ci/run"), /--link takes an https:\/\/ URL/);
    assert.throws(() => selfReportedSnippets("x.svg", "http://example.com"), /only a relative path/);
    assert.throws(() => selfReportedSnippets("x.svg", "https://x.dev/?a=1&copy;b"), /HTML character reference/);
    assert.throws(() => selfReportedSnippets("x.svg", "https://x.dev/?a=1&#169;b"), /HTML character reference/);
    assert.equal(selfReportedSnippets("x.svg", "https://x.dev/?a=1&b=2").link, "https://x.dev/?a=1&b=2", "a plain & between parameters is fine");
    assert.throws(() => selfReportedSnippets("x.svg", "https://x.dev/run_"), /reference name in reStructuredText/);
    assert.throws(() => selfReportedSnippets("badge_", undefined), /reference name in reStructuredText/);
  });
});

describe("the text form", () => {
  it("prints the three formats under a header that says where the image comes from", () => {
    const text = renderBadgeSnippets(siteBadgeSnippets("git"));
    assert.match(text, /^# Sealmark badge from sealmark\.dev \(flat badge\), linked to https:\/\/sealmark\.dev\/results\/git\/\n/);
    assert.match(text, /exists only while that server's latest fleet run earns a badge/);
    assert.match(text, /for any other server it is a 404, so check the page before you paste/);
    assert.ok(text.includes("\nMarkdown:\n[![Sealmark](https://sealmark.dev/badge/git.svg)](https://sealmark.dev/results/git/)\n"));
    assert.ok(text.includes('\nHTML:\n<a href="https://sealmark.dev/results/git/"><img src="https://sealmark.dev/badge/git.svg" alt="Sealmark"></a>\n'));
    assert.ok(text.includes("\nreStructuredText:\n.. image:: https://sealmark.dev/badge/git.svg\n   :target: https://sealmark.dev/results/git/\n   :alt: Sealmark\n"), "rst keeps its indentation so it pastes as is");
    assert.match(renderBadgeSnippets(siteBadgeSnippets("git"), "card"), /\(card\)[\s\S]*git-card\.svg/);
    assert.match(renderBadgeSnippets(siteBadgeSnippets("git"), "shields"), /drawn by shields\.io[\s\S]*img\.shields\.io\/endpoint/);
    const own = renderBadgeSnippets(selfReportedSnippets("badge/b.svg"));
    assert.match(own, /^# Self-reported Sealmark badge: badge\/b\.svg\n/);
    assert.throws(() => renderBadgeSnippets(selfReportedSnippets("badge/b.svg"), "card"), /only for a sealmark\.dev badge/);
  });

  it("reads no report and fetches nothing: the module imports nothing", () => {
    const src = readFileSync(fileURLToPath(new URL("../../src/badge-snippet.ts", import.meta.url)), "utf8");
    assert.doesNotMatch(src, /^import /m);
    assert.doesNotMatch(src, /\bfetch\(|node:https?|node:net/);
  });
});

describe("sealmark badge", { timeout: 120_000 }, () => {
  it("--id prints the snippets and exits 0; --json is the same data", () => {
    const r = sealmark(["badge", "--id", "filesystem"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, renderBadgeSnippets(siteBadgeSnippets("filesystem")));
    const card = sealmark(["badge", "--id", "filesystem", "--variant", "card"]);
    assert.equal(card.out, renderBadgeSnippets(siteBadgeSnippets("filesystem"), "card"));
    const j = sealmark(["badge", "--id", "filesystem", "--json"]);
    assert.equal(j.code, 0, j.err);
    assert.deepEqual(JSON.parse(j.out), siteBadgeSnippets("filesystem"));
    assert.equal(JSON.parse(j.out).schema, "sealmark.badge-snippets/1");
  });

  it("--svg prints self-reported snippets, with --link when given", () => {
    const r = sealmark(["badge", "--svg", "badge/sealmark-report.badge.svg", "--link", "https://github.com/o/r/actions"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, renderBadgeSnippets(selfReportedSnippets("badge/sealmark-report.badge.svg", "https://github.com/o/r/actions")));
  });

  it("usage errors exit 2 and say what to do", () => {
    const cases: [string[], RegExp][] = [
      [["badge"], /badge needs --id <id> .* or --svg <path>/],
      [["badge", "--id", "git", "--svg", "b.svg"], /not both/],
      [["badge", "--id", "git", "--link", "https://x.dev"], /--link applies to badge --svg/],
      [["badge", "--svg", "b.svg", "--variant", "card"], /--variant applies to badge --id/],
      [["badge", "--id", "git", "--variant", "huge"], /unknown variant "huge" \(use badge, card, shields\)/],
      [["badge", "--id", "Git"], /is not a sealmark\.dev server id/],
      [["badge", "--svg", "my badge.svg"], /space, quote or bracket/],
      [["badge", "--id", "git", "--fail-under", "B"], /--fail-under does not apply to "sealmark badge"/],
      [["run", "--id", "git"], /--id does not apply to "sealmark run"/],
      [["badge", "--id", "git", "extra"], /unexpected argument "extra"/],
    ];
    for (const [args, msg] of cases) {
      const r = sealmark(args);
      assert.equal(r.code, 2, args.join(" "));
      assert.equal(r.out, "", "nothing on stdout");
      assert.match(r.err, msg, args.join(" "));
    }
  });
});
