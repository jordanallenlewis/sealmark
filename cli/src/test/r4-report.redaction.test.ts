import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { makePathRewriter, makeRunNormaliser, redactResult } from "../report/redact.js";
import type { RunResult } from "../types.js";

const SB = "/tmp/sealmark-abc123XY";
const PORT = 41234;

describe("the listener port follows a host in any spelling", () => {
  const norm = makeRunNormaliser(PORT);
  for (const host of ["127.0.0.1", "127.1", "0x7f000001", "2130706433", "0.0.0.0", "[::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[0:0:0:0:0:0:0:1]", "localhost", "LOCALHOST", "127.0.0.1.nip.example"]) {
    it(host, () => {
      assert.equal(norm(`http://${host}:${PORT}/x`), `http://${host}:{listener_port}/x`);
      assert.equal(norm(`${host}:${PORT}`), `${host}:{listener_port}`);
    });
  }

  it("a percent-encoded URL carries the encoded colon", () => {
    assert.equal(norm(`to=http%3A%2F%2F127.0.0.1%3A${PORT}%2Fx`), "to=http%3A%2F%2F127.0.0.1%3A{listener_port}%2Fx");
    assert.equal(norm(`to=http%3A%2F%2Flocalhost%3a${PORT}`), "to=http%3A%2F%2Flocalhost%3a{listener_port}");
  });

  it("near misses stay: a longer port, another port, the number without a host", () => {
    assert.equal(norm(`127.0.0.1:${PORT}5`), `127.0.0.1:${PORT}5`);
    assert.equal(norm("127.0.0.1:9999"), "127.0.0.1:9999");
    assert.equal(norm(`pid ${PORT} took 3s`), `pid ${PORT} took 3s`);
    assert.equal(norm(`${PORT}`), `${PORT}`);
  });
});

describe("a percent-encoded sandbox path is rewritten like a plain one", () => {
  const rw = makePathRewriter(SB);
  const enc = encodeURIComponent(SB);

  it("a file:// URL passed as a query value keeps its scheme slashes", () => {
    assert.equal(rw(`to=file%3A%2F%2F%2F${enc.replace(/^%2F/, "")}%2Fcanary%2Fsecret.txt`), "to=file%3A%2F%2F%2F{canary}%2Fsecret.txt");
  });

  it("the other directories and the bare directory", () => {
    assert.equal(rw(`x=${enc}%2Froot%2Fa%2Fb.txt&y=1`), "x=%2F{sandbox}%2Fa%2Fb.txt&y=1", "the leading encoded slash stays; an & ends the path");
    assert.equal(rw(`x=${enc}%2Fhome`), "x=%2F{sandbox_home}");
    assert.equal(rw(`x=${enc}%2Froot-evil%2Fs`), "x=%2F{sandbox_evil}%2Fs", "root-evil is not read as root");
    assert.equal(rw(`x=${enc}`), "x=%2F{sandbox_dir}");
  });

  it("the lower-case hex spelling and an encoded backslash", () => {
    assert.equal(rw(enc.toLowerCase() + "%2fcanary%2fsecret.txt"), "%2f{canary}%2Fsecret.txt");
    assert.equal(rw(`${enc}%5Ccanary%5Csecret.txt`), "%2F{canary}%2Fsecret.txt");
  });

  it("a directory with a space is rewritten in its encodeURI form too", () => {
    const sp = makePathRewriter("/tmp/sealmark x1");
    assert.equal(sp("file:///tmp/sealmark%20x1/canary/secret.txt"), "file:{canary}/secret.txt");
    assert.equal(sp("/tmp/sealmark x1/root/a"), "{sandbox}/a");
    assert.equal(sp("%2Ftmp%2Fsealmark%20x1%2Fcanary%2Fa"), "%2F{canary}%2Fa");
  });

  it("near miss: another directory with the same prefix and a longer name stay", () => {
    assert.equal(rw(`x=${encodeURIComponent("/tmp/sealmark-abc123XYZ")}%2Fcanary`), `x=${encodeURIComponent("/tmp/sealmark-abc123XYZ")}%2Fcanary`);
    assert.equal(rw("x=%2Fvar%2Fother%2Fcanary"), "x=%2Fvar%2Fother%2Fcanary");
  });
});

describe("every per-run token shape is rewritten", () => {
  const norm = makeRunNormaliser(null);
  const HEX = "0123456789ab";

  it("the db session token", () => {
    assert.equal(norm("application_name=sm-who-0123abcd"), "application_name={who}");
    assert.equal(norm("sm-who-0123abcd and sm-who-fedcba98"), "{who} and {who}");
  });

  it("a doubled prefix, a token after an underscore or a dash, and one after an encoded separator", () => {
    assert.equal(norm(`sm-sm-${HEX}`), "{token}");
    assert.equal(norm(`gopher://x/_sm-${HEX}`), "gopher://x/_{token}");
    assert.equal(norm(`a-sm-${HEX}`), "a-{token}");
    assert.equal(norm(`%2Fsm-${HEX}`), "%2F{token}");
    assert.equal(norm(`dict://x/d:sm-${HEX}`), "dict://x/d:{token}");
  });

  it("near misses: a letter or a digit before, a longer or shorter run, a word that merely starts with sm-", () => {
    assert.equal(norm(`xsm-${HEX}`), `xsm-${HEX}`);
    assert.equal(norm(`9sm-${HEX}`), `9sm-${HEX}`);
    assert.equal(norm(`sm-${HEX}c`), `sm-${HEX}c`);
    assert.equal(norm("sm-who-0123abc"), "sm-who-0123abc");
    assert.equal(norm("sm-who-0123abcde"), "sm-who-0123abcde");
    assert.equal(norm("sm-who-ami"), "sm-who-ami");
    assert.equal(norm("sm-sm-short"), "sm-sm-short");
  });
});

describe("the redacted result carries none of it", () => {
  const run = (kept = false): RunResult =>
    ({
      sealmark: { version: "0.2.1", methodology: "0.3-draft" },
      server: { name: "toy", version: "1", command: "node t.js", env: {}, transport: "stdio", tools: [], sqlTools: [] },
      options: { packsRequested: ["net"], timeoutProbeSec: 2 },
      startedAt: "x",
      durationMs: 1,
      packs: {},
      checks: [
        {
          id: "net-scheme-file",
          pack: "net",
          label: "l",
          critical: true,
          scope: "s",
          verdict: "fail",
          summary: `fetched http://[::ffff:7f00:1]:${PORT}/t/sm-sm-0123456789ab`,
          evidence: [{ probe: `fetch ?to=file%3A%2F%2F%2F${encodeURIComponent(SB).slice(3)}%2Fcanary%2Fsecret.txt via http://2130706433:${PORT}/`, outcome: "application_name sm-who-0123abcd", verifiedBy: "listener" }],
        },
      ],
      notCovered: [],
      sandbox: { dir: SB, envMode: "scrubbed", listenerPort: PORT, cleanedUp: true, leftoverProcesses: [], active: false, enabled: true, kept },
    }) as RunResult;

  it("redaction on: no real path, port or token is left", () => {
    const out = JSON.stringify(redactResult(run()).checks);
    assert.ok(!out.includes("abc123XY"), out);
    assert.ok(!out.includes(String(PORT)), out);
    assert.ok(!/sm-[a-z]*-?[0-9a-f]{8,}/.test(out), out);
    assert.match(out, /\{who\}/);
    assert.match(out, /\{canary\}%2Fsecret\.txt/);
  });

  it("a kept sandbox keeps everything the reader will look for", () => {
    const out = JSON.stringify(redactResult(run(true)).checks);
    assert.ok(out.includes(String(PORT)));
    assert.ok(out.includes("sm-who-0123abcd"));
  });
});
