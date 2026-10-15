import assert from "node:assert/strict";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { describe, it } from "node:test";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import { boundSeen, runCore, type CoreCtx } from "../packs/core.js";

// The canary scan needs the count of captured responses and the first one that holds a canary. A hostile server can answer every
// malformed call with tens of MiB, so nothing else may stay in memory until the scan runs.

const MIB = 1024 * 1024;
const CANARY = "sm-canary-0123456789abcdef";
const tool = (name: string): ToolInfo => ({ name, description: `${name} does a thing`, inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } }) as ToolInfo;

function server(n: number, reply: (call: number) => CallResult) {
  let call = 0;
  const session = {
    tools: Array.from({ length: n }, (_, i) => tool(`t${i}`)),
    serverInfo: { name: "stub", version: "1.0.0" },
    capabilities: {},
    prompts: [],
    resources: [],
    listErrors: [],
    async call() {
      return reply(call++);
    },
    async alive() {
      return true;
    },
  } as unknown as McpSession;
  const ctx: CoreCtx = { session, canaries: [CANARY], seen: [], hangMs: 1000 };
  return ctx;
}
/** A fresh, flat string of `size` characters (a repeated literal would share one allocation and prove nothing). */
const big = (i: number, size: number) => `${i}:`.padEnd(size, "x");
const answer = (text: string, o: Partial<CallResult> = {}): CallResult => ({ isError: true, text, elapsedMs: 1, timedOut: false, closed: false, ...o });
/** Forces a collection without needing --expose-gc on the command line. */
const gc = (): (() => void) => {
  setFlagsFromString("--expose-gc");
  return runInNewContext("gc") as () => void;
};

describe("the canary scan keeps only what it needs", () => {
  it("20 tools answering every call with 5 MiB leave under 64 MiB retained, and secret-echo still passes", async () => {
    const collect = gc();
    const ctx = server(20, (i) => answer(big(i, 5 * MIB)));
    collect();
    const before = process.memoryUsage().heapUsed;
    const checks = await runCore(ctx);
    collect();
    const grown = process.memoryUsage().heapUsed - before;
    assert.ok(grown < 64 * MIB, `retained ${(grown / MIB).toFixed(1)} MiB`);
    const secret = checks.find((c) => c.id === "secret-echo")!;
    assert.equal(secret.verdict, "pass");
    // 20 tools x 5 variants, text plus an empty rpcError each: the count of non-empty responses is what the pass line reports (every one is an error reply).
    assert.match(secret.summary, /and 100 captured response\(s\), 0 of them successful result\(s\)$/);
    assert.equal(ctx.seen.filter(Boolean).length, 100);
  });

  it("a canary deep inside a big response is still found, with the same offset and length in the evidence", async () => {
    const at = 3 * MIB + 17;
    const text = `${"y".repeat(at - 17)} SEALMARK_CANARY=${CANARY}${"z".repeat(MIB)}`;
    const ctx = server(3, (i) => answer(i === 2 ? text : big(i, MIB)));
    const secret = (await runCore(ctx)).find((c) => c.id === "secret-echo")!;
    assert.equal(secret.verdict, "fail");
    assert.equal(secret.evidence[0].outcome, `SEALMARK_CANARY found at offset ${text.indexOf(CANARY)} of a ${text.length}-character response, printed as SEALMARK_CANARY=<canary> (the surrounding text is not quoted)`);
    assert.equal(ctx.seen.filter((t) => t.includes(CANARY)).length, 1, "only the first hit is retained");
  });

  it("a hit already in seen (a probes: response) stays the first hit; later ones are not kept", () => {
    const hit = `x SEALMARK_CANARY=${CANARY}`;
    assert.deepEqual(boundSeen(["", "plain", hit, hit, "tail"], [CANARY]), ["", "\u0000", hit, "\u0000", "\u0000"]);
  });
});
