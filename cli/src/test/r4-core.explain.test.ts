// Round 4, package core: `sealmark explain` "What to fix" carries the guidance for the refusal model, the net-caps window, git scope,
// the sqlite probe forms and the sqlite timeout window.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { explainCheck, renderExplain } from "../explain.js";

const fix = (id: string) => explainCheck(id).remediation;

/** Every check whose What to fix text changed in round 5 (docs-web package). */
const ROUND5 = [
  "protocol",
  "tool-poisoning",
  "robust-input",
  "mutating-sql",
  "fs-read-escape",
  "fs-write-escape",
  "fs-link-escape",
  "fs-size-cap",
  "net-scheme-allowlist",
  "http-cors",
  "sqlite-file-read",
  "sqlite-file-write",
  "sqlite-rowcap",
  "annotation-honesty",
];

describe("explain: What to fix for the round 4 rules", () => {
  it("net-loopback-ssrf says what a refusal must say and that a failed fetch is not one", () => {
    const t = fix("net-loopback-ssrf");
    assert.match(t, /ties the decline to the target/);
    assert.match(t, /JSON-RPC -32602/);
    assert.match(t, /not read as a refusal/);
    assert.match(t, /net\.control_url/);
    assert.match(t, /IPv4-mapped IPv6/);
  });

  it("net-caps names the time window and --timeout-probe", () => {
    const t = fix("net-caps");
    assert.match(t, /timeout_probe_sec \+ 8 s/);
    assert.match(t, /set --timeout-probe to the server's timeout/);
  });

  it("git-repo-scope names symlinks, the staged change and the {sandbox} placeholder", () => {
    const t = fix("git-repo-scope");
    assert.match(t, /symbolic links/);
    assert.match(t, /staged/);
    assert.match(t, /\{sandbox\}\/repo/);
  });

  it("sqlite-extension-load names the forms it tries, sqlite-timeout the 8 s window", () => {
    assert.match(fix("sqlite-extension-load"), /a SELECT for a reader, an INSERT and then an UPDATE for a declared writer/);
    assert.match(fix("sqlite-extension-load"), /inconclusive, not passed/);
    assert.match(fix("sqlite-timeout"), /expected_sec \+ 8 s \(18 s with the default 10\)/);
    assert.match(fix("sqlite-timeout"), /--timeout-probe/);
  });

  it("round 5: net-loopback-ssrf names the rule phrases, the hostless twin and the relay note", () => {
    const t = fix("net-loopback-ssrf");
    assert.match(t, /ties the decline to the target or to the rule/);
    assert.match(t, /refused to connect/);
    assert.match(t, /a data: URL/);
    assert.match(t, /one answer for everything/);
    assert.match(t, /constant sentence/);
    assert.match(t, /may relay the probe values to its own upstream/);
    assert.match(t, /tools\.exclude/);
    assert.match(fix("net-scheme-allowlist"), /explains nothing about the scheme/);
  });

  it("round 5: tool-poisoning and protocol name the instructions, serverInfo and stdout", () => {
    assert.match(fix("tool-poisoning"), /server instructions and serverInfo/);
    assert.match(fix("protocol"), /only JSON-RPC messages to stdout/);
    assert.match(fix("robust-input"), /internals leak/);
  });

  it("round 5: mutating-sql names the four terminators and the sql_tools args remedy", () => {
    const t = fix("mutating-sql");
    for (const w of ["COMMIT", "ROLLBACK", "END", "ABORT"]) assert.ok(t.includes(w), w);
    assert.match(t, /sql_tools: \[\{tool, arg, args: \{<param>: <value>\}\}\]/);
  });

  it("round 5: sqlite file checks name the engine rule, the forms and the part rule; the row cap names plain-text caps", () => {
    assert.match(fix("sqlite-file-read"), /sqlite_version\(\)/);
    assert.match(fix("sqlite-file-read"), /stacked statements/);
    assert.match(fix("sqlite-file-read"), /makes the check part/);
    assert.match(fix("sqlite-file-write"), /DDL-only tool/);
    assert.match(fix("sqlite-rowcap"), /plain-text limit message/);
  });

  it("round 5: git-repo-scope names relative paths, write tools and the part rule; fs names arrays, backslashes, edits and rootless", () => {
    const g = fix("git-repo-scope");
    assert.match(g, /relative paths/);
    assert.match(g, /A tool that writes/);
    assert.match(g, /part, at any confidence/);
    assert.match(fix("fs-read-escape"), /every element of an array/);
    assert.match(fix("fs-read-escape"), /server\.rootless: true/);
    assert.match(fix("fs-write-escape"), /edit/);
    assert.match(fix("fs-link-escape"), /dangling link/);
  });

  it("the text reaches the explain output under What to fix", () => {
    for (const id of ["net-loopback-ssrf", "net-caps", "git-repo-scope", "sqlite-extension-load", "sqlite-timeout", ...ROUND5]) {
      const out = renderExplain(explainCheck(id));
      assert.ok(out.includes(`What to fix:\n  ${fix(id)}`), id);
    }
  });
});
