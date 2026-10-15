import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { resolvePackage } from "../resolve.js";

// A fabricated uv cache: no process is spawned and nothing is read from the real cache.
let dir: string;
let n = 0;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-resolve-uv-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const fresh = () => {
  const base = join(dir, `cache-${n++}`);
  const roots = { envs: join(base, "environments-v2"), archive: join(base, "archive-v0") };
  mkdirSync(roots.envs, { recursive: true });
  mkdirSync(roots.archive, { recursive: true });
  return roots;
};

/** `<site>/<dist>-<version>.dist-info/METADATA`, optionally with a modification time in the past or future. */
function dist(site: string, name: string, version: string, o: { requires?: string[]; mtime?: number } = {}): void {
  const info = join(site, `${name}-${version}.dist-info`);
  mkdirSync(info, { recursive: true });
  writeFileSync(join(info, "METADATA"), [`Metadata-Version: 2.1`, `Name: ${name}`, `Version: ${version}`, ...(o.requires ?? []).map((r) => `Requires-Dist: ${r}`), ""].join("\n"));
  if (o.mtime) utimesSync(info, o.mtime, o.mtime);
}

const site = (root: string, hash: string, py = "python3.13") => join(root, hash, "lib", py, "site-packages");
const uvx = (pkg: string): [string, string[]] => ["uvx", [pkg]];

describe("uvx resolution against the current uv cache layout", () => {
  it("finds a package in a hash-named archive-v0 directory and reports its version", () => {
    const c = fresh();
    mkdirSync(join(c.envs, "0f3a9c1d5e7b2a48"), { recursive: true });
    dist(site(c.archive, "AbCdEfGh123"), "toytool", "1.2.3", { requires: ["httpx>=0.27"] });
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } });
    assert.equal(r?.source, "uv-cache");
    assert.equal(r?.version, "1.2.3");
    assert.deepEqual(r?.requires, ["httpx>=0.27"]);
    assert.equal(r?.dependencies?.toytool, "1.2.3");
  });

  it("finds a wheel unpacked straight into an archive-v0 directory", () => {
    const c = fresh();
    dist(join(c.archive, "Zy9Xw8Vu7"), "toytool", "2.0.0");
    assert.equal(resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } })?.version, "2.0.0");
  });

  it("finds a package in a hash-named environment directory", () => {
    const c = fresh();
    dist(site(c.envs, "16460d1dd8dae25e"), "toytool", "3.1.4");
    dist(site(c.envs, "16460d1dd8dae25e"), "helperlib", "0.9.0");
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } });
    assert.equal(r?.version, "3.1.4");
    assert.deepEqual(r?.dependencies, { toytool: "3.1.4", helperlib: "0.9.0" });
  });

  it("follows the symlink from an environment into archive-v0", () => {
    const c = fresh();
    const target = site(c.archive, "LinkTarget001");
    dist(target, "toytool", "4.5.6");
    mkdirSync(join(c.envs, "deadbeef00112233", "lib", "python3.13"), { recursive: true });
    symlinkSync(target, site(c.envs, "deadbeef00112233"), "dir");
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs] } });
    assert.equal(r?.source, "uv-cache");
    assert.equal(r?.version, "4.5.6");
  });

  it("still resolves the old <pkg>-* environment layout", () => {
    const c = fresh();
    dist(site(c.envs, "toytool-3f9a1c"), "toytool", "0.9.1");
    assert.equal(resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } })?.version, "0.9.1");
  });

  it("matches the normalised name: toy_tool, Toy.Tool and toy-tool are one package", () => {
    const c = fresh();
    dist(site(c.archive, "NormHash001"), "toy_tool", "7.0.0");
    assert.equal(resolvePackage(...uvx("Toy.Tool"), { roots: { uv: [c.archive] } })?.version, "7.0.0");
    assert.equal(resolvePackage(...uvx("toy-tool"), { roots: { uv: [c.archive] } })?.version, "7.0.0");
  });

  it("several cached versions and no pin: no version is named, the candidates are (the newest entry is only the one unpacked last)", () => {
    const c = fresh();
    dist(site(c.archive, "OldOne"), "toytool", "1.0.0", { mtime: 1_700_000_000 });
    dist(site(c.archive, "NewOne"), "toytool", "1.1.0", { mtime: 1_800_000_000 });
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.archive] } });
    assert.equal(r?.source, "uv-cache (ambiguous)");
    assert.equal(r?.version, undefined, "a wrong version is worse than none");
    assert.deepEqual(r?.candidates, ["1.0.0", "1.1.0"]);
    assert.equal(r?.dependencies, undefined, "the dependency set of a guessed environment is not reported either");
    // A range does not narrow, so it stays ambiguous.
    const range = resolvePackage("uvx", ["toytool>=1.0"], { roots: { uv: [c.archive] } });
    assert.equal(range?.version, undefined);
    assert.deepEqual(range?.candidates, ["1.0.0", "1.1.0"]);
  });

  it("a pinned version narrows the choice to exactly that version, whatever the modification times say", () => {
    const c = fresh();
    dist(site(c.archive, "OldOne"), "toytool", "1.0.0", { mtime: 1_700_000_000 });
    dist(site(c.archive, "NewOne"), "toytool", "1.1.0", { mtime: 1_800_000_000 });
    for (const args of [["toytool==1.0.0"], ["--from", "toytool@1.0.0", "toytool"]]) {
      const r = resolvePackage("uvx", args, { roots: { uv: [c.archive] } });
      assert.equal(r?.version, "1.0.0");
      assert.equal(r?.source, "uv-cache");
      assert.equal(r?.pinned, true);
      assert.equal(r?.candidates, undefined);
    }
    // A pin the cache does not hold is not answered with some other version.
    assert.equal(resolvePackage("uvx", ["toytool==9.9.9"], { roots: { uv: [c.archive] } })?.source, "not found");
  });

  it("the same version unpacked twice is one candidate: it resolves, the newest copy wins", () => {
    const c = fresh();
    dist(site(c.archive, "CopyA"), "toytool", "1.0.0", { mtime: 1_700_000_000 });
    dist(site(c.envs, "CopyB"), "toytool", "1.0.0", { mtime: 1_800_000_000 });
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } });
    assert.equal(r?.version, "1.0.0");
    assert.equal(r?.source, "uv-cache");
    assert.equal(r?.candidates, undefined);
  });

  it("pick takes the version the server announced among several, with its own dependency set; a leading v and the case do not matter", () => {
    const c = fresh();
    dist(site(c.archive, "OldOne"), "toytool", "1.0.0", { mtime: 1_700_000_000 });
    dist(site(c.archive, "OldOne"), "oldhelper", "0.1.0");
    dist(site(c.archive, "NewOne"), "toytool", "1.1.0", { mtime: 1_800_000_000 });
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.archive] }, pick: "v1.0.0" });
    assert.equal(r?.version, "1.0.0");
    assert.equal(r?.source, "uv-cache");
    assert.deepEqual(r?.dependencies, { toytool: "1.0.0", oldhelper: "0.1.0" });
    assert.equal(resolvePackage(...uvx("toytool"), { roots: { uv: [c.archive] }, pick: "3.0.0" })?.source, "not found", "a version the cache does not hold is not invented");
  });

  it("another package's dist-info does not match, and a near-miss name is not a match", () => {
    const c = fresh();
    dist(site(c.archive, "OtherHash"), "toytool-extras", "9.9.9");
    dist(site(c.archive, "OtherHash2"), "othertool", "1.0.0");
    const r = resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } });
    assert.equal(r?.source, "not found");
    assert.equal(r?.version, undefined);
  });

  it("an empty cache, and a cache directory that does not exist, are 'not found' (no throw)", () => {
    const c = fresh();
    assert.equal(resolvePackage(...uvx("toytool"), { roots: { uv: [c.envs, c.archive] } })?.source, "not found");
    assert.equal(resolvePackage(...uvx("toytool"), { roots: { uv: [join(dir, "missing")] } })?.source, "not found");
  });

  it("the default cache locations are both environments-v2 and archive-v0 under UV_CACHE_DIR", () => {
    const base = join(dir, "uv-cache-dir");
    dist(site(join(base, "archive-v0"), "EnvHash01"), "toytool", "5.5.5");
    const r = resolvePackage(...uvx("toytool"), { env: { UV_CACHE_DIR: base }, platform: "linux" });
    assert.equal(r?.version, "5.5.5");
    assert.equal(r?.source, "uv-cache");
  });
});
