import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";

// The regression corpus (cli/corpus): every manifest must be well formed, pinned and free of secrets.
// Replaying the servers is corpus.yml's job (untrusted code runs only in that sandbox), not this offline test.
const dir = new URL("../../corpus/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
const KINDS = ["crash", "false-positive", "false-negative", "slow", "hardening"];
const VERDICTS = ["pass", "fail", "part", "inconclusive", "na"];

describe("regression corpus manifests", () => {
  it("has a valid manifest for every file", () => {
    for (const f of files) {
      const raw = readFileSync(new URL(f, dir), "utf8");
      const m = JSON.parse(raw);
      assert.equal(m.id + ".json", f, `${f}: id must match the file name`);
      assert.ok(Number.isInteger(m.issue) && m.issue > 0, `${f}: issue number required`);
      assert.ok(KINDS.includes(m.exposed), `${f}: exposed must be one of ${KINDS.join(", ")}`);
      assert.ok(["npm", "pypi", "github"].includes(m.ecosystem), `${f}: ecosystem`);
      assert.match(m.launch, /(@|==)\d|@[0-9a-f]{7,40}\b|#[0-9a-f]{7,40}\b/, `${f}: launch must pin an exact version or commit`);
      assert.ok(m.expect && typeof m.expect === "object", `${f}: expect required`);
      for (const v of Object.values(m.expect.checks ?? {})) assert.ok(VERDICTS.includes(v as string), `${f}: bad verdict ${String(v)}`);
      assert.doesNotMatch(raw, /(gh[pousr]_|sk-|xox[bap]-|AKIA)[A-Za-z0-9_-]{8,}|\/home\/|\/Users\//, `${f}: no secrets or private paths`);
    }
  });
});
