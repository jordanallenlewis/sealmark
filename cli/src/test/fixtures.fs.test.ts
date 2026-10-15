import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { BIN_NAMES, createLayout, createSandbox } from "../sandbox.js";
import { cliKit } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-fixture-fs-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark } = cliKit(() => dir);
const tokenOf = (doc: string, label: string): string => new RegExp(`${label}: (\\S+)`).exec(doc)?.[1] ?? "";

describe("run --fixture fs", { timeout: 120_000 }, () => {
  it("writes the sandbox layout with tokens that match the files and the description", () => {
    const into = join(dir, "fx");
    const r = sealmark(["run", "--fixture", "fs", "--into", into]);
    assert.equal(r.code, 0, r.err);
    for (const p of ["root/ok.txt", "root-evil/secret.txt", "canary/secret.txt", "home", "tmp", "bin/sm-canary.cjs", "bin/sm-echo.cjs", "bin/sm-sleep.cjs", "bin/sm-spew.cjs", ".sealmark-sandbox", "SEALMARK-FIXTURE.txt"]) {
      assert.ok(existsSync(join(into, p)), `${p} is written`);
    }
    const doc = readFileSync(join(into, "SEALMARK-FIXTURE.txt"), "utf8");
    assert.equal(tokenOf(doc, "control token"), readFileSync(join(into, "root", "ok.txt"), "utf8"));
    assert.equal(tokenOf(doc, "evil token"), readFileSync(join(into, "root-evil", "secret.txt"), "utf8"));
    assert.equal(tokenOf(doc, "canary token"), readFileSync(join(into, "canary", "secret.txt"), "utf8"));
    assert.match(doc, /link-dir: (symlink|junction|not created \()/);
    assert.match(doc, /link\.txt: (symlink|not created \()/);
    assert.ok(doc.includes(join(into, "root")), "the description lists the real paths");
    assert.match(r.err, /This is what the sandbox builds for \{sandbox\}; point your server at .*root by hand to explore what the fs pack sees\. The real run always uses a fresh sandbox\./);
    assert.ok(r.err.includes(tokenOf(doc, "control token")), "the tokens are printed");
    if (existsSync(join(into, "root", "link.txt"))) assert.ok(lstatSync(join(into, "root", "link.txt")).isSymbolicLink());
  });

  it("two runs into different directories use different tokens", () => {
    const a = join(dir, "a");
    const b = join(dir, "b");
    assert.equal(sealmark(["run", "--fixture", "fs", "--into", a]).code, 0);
    assert.equal(sealmark(["run", "--fixture", "fs", "--into", b]).code, 0);
    const read = (d: string) => readFileSync(join(d, "SEALMARK-FIXTURE.txt"), "utf8");
    for (const label of ["control token", "evil token", "canary token"]) assert.notEqual(tokenOf(read(a), label), tokenOf(read(b), label), label);
  });

  it("a second run into the same directory exits 2 and leaves the first untouched", () => {
    const into = join(dir, "twice");
    assert.equal(sealmark(["run", "--fixture", "fs", "--into", into]).code, 0);
    const before = readFileSync(join(into, "root", "ok.txt"), "utf8");
    const r = sealmark(["run", "--fixture", "fs", "--into", into]);
    assert.equal(r.code, 2);
    assert.match(r.err, /already exists; choose another --into directory or delete it/);
    assert.equal(readFileSync(join(into, "root", "ok.txt"), "utf8"), before);
  });

  it("duckdb and unknown names still exit 2", () => {
    const d = sealmark(["run", "--fixture", "duckdb"]);
    assert.equal(d.code, 2);
    assert.match(d.err, /DuckDB fixtures are planned/);
    const n = sealmark(["run", "--fixture", "x"]);
    assert.equal(n.code, 2);
    assert.match(n.err, /--fixture must be fs, git, sqlite or duckdb, got "x"/);
  });

  it("createLayout builds what a real sandbox builds: same files, tokens and bins", async () => {
    const parent = join(dir, "layouts");
    mkdirSync(join(parent, "l"), { recursive: true });
    const layout = createLayout(join(parent, "l"));
    const sb = await createSandbox({ dir: parent });
    try {
      assert.deepEqual(Object.keys(layout.files).sort(), Object.keys(sb.files).sort());
      assert.deepEqual(Object.keys(layout.tokens).sort(), Object.keys(sb.tokens).sort());
      assert.deepEqual(Object.keys(layout.links).sort(), Object.keys(sb.links).sort());
      assert.deepEqual(Object.keys(layout.bins).sort(), [...BIN_NAMES].sort());
      assert.deepEqual(Object.keys(layout.bins).sort(), Object.keys(sb.bins).sort());
      assert.equal(layout.links.dir.ok, sb.links.dir.ok);
      assert.equal(readFileSync(layout.files.ok, "utf8"), layout.tokens.control);
      assert.notEqual(layout.tokens.control, sb.tokens.control, "fresh tokens each time");
    } finally {
      await sb.destroy();
    }
  });
});
