// The source tree holds only real modules. A copy such as "run 2.ts" (what a file manager makes on a duplicate) compiles next to
// the module it shadows, ships in the npm package under dist/, and nothing tests it: 1.0.0 shipped ten of them.
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

/** "run 2.ts", "oauth-http 2.yaml", "x (1).ts", "a copy.ts": the names a duplicated file gets. */
const STRAY_COPY = /( \d+| \(\d+\)| copy)\.[A-Za-z0-9]+$/;

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
}

const SRC = fileURLToPath(new URL("../../src", import.meta.url));
const DIST = fileURLToPath(new URL("..", import.meta.url));

describe("source tree", () => {
  it("the stray-copy pattern matches duplicate names and nothing real", () => {
    for (const n of ["run 2.ts", "oauth-http 2.yaml", "types (1).ts", "probes copy.ts", "r7-oauth.e2e.test 2.ts"]) assert.match(n, STRAY_COPY, n);
    for (const n of ["run.ts", "r7-oauth.e2e.test.ts", "cred-r6.ts", "x509.ts", "r5-sql.terminators.test.ts", "oauth-http.yaml"]) assert.doesNotMatch(n, STRAY_COPY, n);
  });

  it("src/ has no stray copies of a module, test or fixture", () => {
    assert.deepEqual(walk(SRC).filter((f) => STRAY_COPY.test(f)).map((f) => relative(SRC, f)), []);
  });

  it("the built dist/ (what npm ships) has no stray copies either", () => {
    assert.deepEqual(walk(DIST).filter((f) => STRAY_COPY.test(f)).map((f) => relative(DIST, f)), []);
  });
});
