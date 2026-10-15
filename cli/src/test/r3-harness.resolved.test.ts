import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { runHarness } from "../run.js";
import type { RunResult } from "../types.js";
import { TOY, quiet } from "./helpers.js";

// A stand-in launcher named `npx`: it ignores its arguments and runs the toy server, so the harness sees an npx launch of a package
// that is in a fabricated npx cache (or not), with no network. POSIX only: the stand-in is a shell script.
describe("r3-harness: resolved package version", { skip: process.platform === "win32" }, () => {
  let dir: string;
  let prior: string | undefined;
  let n = 0;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sm-r3-resolved-"));
    mkdirSync(join(dir, "cache"));
    writeFileSync(join(dir, "npx"), `#!/bin/sh\nexec "${process.execPath}" "${TOY}" --mode nosql\n`);
    chmodSync(join(dir, "npx"), 0o755);
    prior = process.env.npm_config_cache;
    process.env.npm_config_cache = join(dir, "cache");
  });
  after(() => {
    if (prior === undefined) delete process.env.npm_config_cache;
    else process.env.npm_config_cache = prior;
    rmSync(dir, { recursive: true, force: true });
  });

  it("a package that is not in the cache is reported without a version key, never as 'unknown'", async () => {
    const r = await runHarness({
      config: { name: "toy-npx", version: "0.0.1", server: { command: join(dir, "npx"), args: ["-y", "sm-r3-not-a-real-package"], env: {} } },
      packs: ["core"],
      packsExplicit: false,
      timeoutProbeSec: 2,
      log: quiet,
    });
    const pkg = r.server.resolved?.package;
    assert.ok(pkg, "the launch was recognised as an npx launch");
    assert.equal(pkg.source, "not found");
    assert.equal(pkg.name, "sm-r3-not-a-real-package");
    const json = JSON.parse(JSON.stringify(r)) as { server: { resolved: { package: Record<string, unknown> } } };
    assert.equal("version" in json.server.resolved.package, false);
    assert.equal(JSON.stringify(r).includes('"unknown"'), false, "no 'unknown' version string anywhere in the JSON");
  });

  // ---- round 4 (E1): the version in the cache is not necessarily the one that ran ----

  /** A fresh npx cache holding the given versions of `pkg` (each in its own hash directory, with a modification time that says which was unpacked last). */
  function npxCache(pkg: string, versions: { v: string; mtime: number; sdk?: string }[]): string {
    const cache = join(dir, `cache-${n++}`);
    for (const [i, x] of versions.entries()) {
      const nm = join(cache, "_npx", `hash${i}`, "node_modules");
      mkdirSync(join(nm, pkg), { recursive: true });
      const manifest = join(nm, pkg, "package.json");
      writeFileSync(manifest, JSON.stringify({ name: pkg, version: x.v, ...(x.sdk ? { dependencies: { "@modelcontextprotocol/sdk": "^1.0.0" } } : {}) }));
      utimesSync(manifest, x.mtime, x.mtime);
      if (x.sdk) {
        mkdirSync(join(nm, "@modelcontextprotocol", "sdk"), { recursive: true });
        writeFileSync(join(nm, "@modelcontextprotocol", "sdk", "package.json"), JSON.stringify({ name: "@modelcontextprotocol/sdk", version: x.sdk }));
      }
    }
    return cache;
  }

  /** Runs the toy behind a stand-in `npx` that makes it announce `announced`, with `cache` as the npx cache. */
  async function launch(cache: string, spec: string, announced: string): Promise<RunResult> {
    const bin = join(dir, `bin-${n++}`);
    mkdirSync(bin);
    writeFileSync(join(bin, "npx"), `#!/bin/sh\nexec "${process.execPath}" "${TOY}" --mode nosql --server-version ${announced}\n`);
    chmodSync(join(bin, "npx"), 0o755);
    process.env.npm_config_cache = cache;
    return runHarness({
      config: { name: "toy-npx", version: "0.0.0", server: { command: join(bin, "npx"), args: ["-y", spec], env: {} } },
      packs: ["core"],
      packsExplicit: false,
      timeoutProbeSec: 2,
      log: quiet,
    });
  }

  const TWO = [
    { v: "1.0.0", mtime: 1_800_000_000 }, // the OLDER version was unpacked LAST: the newest-mtime rule would have named it
    { v: "2.0.0", mtime: 1_700_000_000 },
  ];

  it("two cached versions, no pin, and an announced version that matches neither: no version is named and the candidates are", async () => {
    const r = await launch(npxCache("sm-r4-pkg", TWO), "sm-r4-pkg", "0.0.1");
    const pkg = r.server.resolved?.package;
    assert.equal(pkg?.source, "npx-cache (ambiguous)");
    assert.equal("version" in (pkg ?? {}), false, "a wrong version is worse than none");
    assert.deepEqual(pkg?.candidates, ["1.0.0", "2.0.0"]);
    assert.equal(r.server.resolved?.dependencies, undefined);
    assert.ok(
      r.warnings?.includes("resolved package sm-r4-pkg unknown (several versions in the npx cache: 1.0.0, 2.0.0; the server announced 0.0.1; pin the version)"),
      JSON.stringify(r.warnings),
    );
  });

  it("two cached versions and an announced version that matches one: that one is taken (a leading v does not matter)", async () => {
    for (const announced of ["2.0.0", "v2.0.0"]) {
      const r = await launch(npxCache("sm-r4-pkg", TWO), "sm-r4-pkg", announced);
      const pkg = r.server.resolved?.package;
      assert.equal(pkg?.version, "2.0.0", `announced ${announced}`);
      assert.equal(pkg?.source, "npx-cache");
      assert.equal(pkg?.candidates, undefined);
      assert.ok(!(r.warnings ?? []).some((w) => /resolved package/.test(w)), JSON.stringify(r.warnings));
    }
  });

  it("a pinned spec resolves exactly, whatever the modification times and whatever the server announces", async () => {
    const r = await launch(npxCache("sm-r4-pkg", TWO), "sm-r4-pkg@2.0.0", "0.0.1");
    assert.equal(r.server.resolved?.package?.version, "2.0.0");
    assert.equal(r.server.resolved?.package?.source, "npx-cache");
    assert.ok(!(r.warnings ?? []).some((w) => /resolved package/.test(w)), "the pin is the version that ran: nothing to warn about");
  });

  it("one cached version that differs from a package-like announced version is kept, with a warning that says what each is (round 5: never 'pin the version')", async () => {
    const r = await launch(npxCache("sm-r4-pkg", [{ v: "1.0.0", mtime: 1_800_000_000 }]), "sm-r4-pkg", "3.4.5");
    assert.equal(r.server.resolved?.package?.version, "1.0.0");
    assert.ok(r.warnings?.includes("the cache holds one version (1.0.0); the server announces its own version string (3.4.5)"), JSON.stringify(r.warnings));
    assert.ok(!(r.warnings ?? []).some((w) => /pin the version/.test(w)), JSON.stringify(r.warnings));
  });

  it("near-misses stay quiet: the announced version equals the resolved one, is the SDK's, or is not version-shaped", async () => {
    const same = await launch(npxCache("sm-r4-pkg", [{ v: "1.0.0", mtime: 1_800_000_000 }]), "sm-r4-pkg", "1.0.0");
    assert.equal(same.server.resolved?.package?.version, "1.0.0");
    assert.ok(!(same.warnings ?? []).some((w) => /resolved package/.test(w)), JSON.stringify(same.warnings));
    // A server that never sets its own version announces the SDK's: it says nothing about which build of the package ran.
    const sdk = await launch(npxCache("sm-r4-pkg", [{ v: "1.0.0", mtime: 1_800_000_000, sdk: "1.29.0" }]), "sm-r4-pkg", "1.29.0");
    assert.equal(sdk.server.resolved?.package?.version, "1.0.0");
    assert.ok(!(sdk.warnings ?? []).some((w) => /resolved package/.test(w)), JSON.stringify(sdk.warnings));
    const word = await launch(npxCache("sm-r4-pkg", [{ v: "1.0.0", mtime: 1_800_000_000 }]), "sm-r4-pkg", "latest");
    assert.ok(!(word.warnings ?? []).some((w) => /resolved package/.test(w)), JSON.stringify(word.warnings));
  });
});
