// Round 5, package net (G14): http-cors on a redirect. A 3xx preflight says nothing about CORS, and a pass needs the control initialize
// to have worked. Toy: the http toy's redirect-slash mode (307 from /mcp to /mcp/); the default mode must still pass.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { pack } from "../packs/http.js";
import { legacyEffectiveConfig } from "../run.js";
import { HTTP_TOY_TOKEN, startHttpToy, type HttpToy } from "../toy/http.js";
import type { CheckResult, PackCtx, ServerSpec } from "../types.js";
import { quiet } from "./helpers.js";

const BEARER = { Authorization: `Bearer ${HTTP_TOY_TOKEN}` };

function ctxFor(server: ServerSpec): PackCtx {
  const config = legacyEffectiveConfig({ config: { name: "http-toy", version: "0.0.1", server }, packs: ["core", "http"], packsExplicit: false, timeoutProbeSec: 2 });
  return { pack: "http", config, tools: [], classification: [], open: async () => assert.fail("the http pack must not use the SDK session"), active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet };
}
const by = (checks: CheckResult[], id: string) => checks.find((c) => c.id === id)!;

describe("r5 net: http-cors on a redirect", { timeout: 120_000 }, () => {
  const toys: HttpToy[] = [];
  let slash: CheckResult[];
  let good: CheckResult[];
  let slashUrl: string;
  let slashWithSlash: CheckResult[];

  before(async () => {
    const a = await startHttpToy("redirect-slash");
    const b = await startHttpToy("good");
    toys.push(a, b);
    slashUrl = a.url;
    [slash, good, slashWithSlash] = await Promise.all([
      pack.run(ctxFor({ url: a.url, headers: BEARER })),
      pack.run(ctxFor({ url: b.url, headers: BEARER })),
      // The URL with the trailing slash the redirect names: the endpoint behind the redirect is the good toy.
      pack.run(ctxFor({ url: `${a.url}/`, headers: BEARER })),
    ]);
  });
  after(async () => {
    for (const t of toys) await t.close();
  });

  it("redirect-slash: http-cors is inconclusive, names the status and the Location, and says what to try", () => {
    const c = by(slash, "http-cors");
    assert.equal(c.verdict, "inconclusive", c.summary);
    assert.match(c.summary, /HTTP 307: the server redirected the preflight \(Location: \/mcp\/\); try the URL with a trailing slash/);
  });

  it("redirect-slash: the sibling checks are inconclusive on the same failed control, and the hint names the Location header", () => {
    for (const id of ["http-origin", "http-protocol-version", "http-session"]) {
      const c = by(slash, id);
      assert.equal(c.verdict, "inconclusive", id);
      assert.match(c.summary, /HTTP 307 \(Location: \/mcp\/;/, id);
    }
  });

  it("the default mode still passes http-cors; so does the URL with the trailing slash on the redirecting toy", () => {
    assert.equal(by(good, "http-cors").verdict, "pass");
    assert.equal(by(slashWithSlash, "http-cors").verdict, "pass", `${by(slashWithSlash, "http-cors").summary} (${slashUrl}/)`);
  });
});
