import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { loadEffectiveConfig } from "../config/index.js";

const fwd = (p: string) => p.split("\\").join("/");

describe("relative server paths", () => {
  it("anchors ./ and ../ command and argument paths to the config file's folder, not the working directory", () => {
    const root = mkdtempSync(join(tmpdir(), "sm-relpath-"));
    try {
      const proj = join(root, "proj");
      const elsewhere = join(root, "elsewhere");
      mkdirSync(proj);
      mkdirSync(elsewhere);
      writeFileSync(join(proj, "sealmark.yaml"), 'schema_version: 1\nname: x\nserver:\n  command: node\n  args: ["./dist/server.js", "--flag", "../shared/config.json", "plain-arg", "node_modules/pkg"]\n');
      const eff = loadEffectiveConfig({ cwd: elsewhere, isolated: true, env: {}, flags: { config: join(proj, "sealmark.yaml") } });
      const args = eff.server.args ?? [];
      assert.equal(args[0], fwd(resolve(proj, "dist/server.js")));
      assert.equal(args[1], "--flag");
      assert.equal(args[2], fwd(resolve(proj, "../shared/config.json")));
      assert.equal(args[3], "plain-arg", "an ordinary argument is left alone");
      assert.equal(args[4], "node_modules/pkg", "only leading ./ and ../ paths are anchored");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
