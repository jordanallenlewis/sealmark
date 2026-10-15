import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { McpSession, ProtocolViolation } from "../mcp.js";
import type { SealmarkConfig } from "../types.js";
import { runPacks } from "./packctx.js";

// tools/list is bounded in total (5000 tools, 32 MiB), not only per page. A server that lists 6000 tiny tools across pages is
// a protocol finding, reported quickly, and a listing under the bound is accepted.
const FLOOD = fileURLToPath(new URL("../toy/listflood.js", import.meta.url));
const spec = (extra: string[] = []) => ({ command: process.execPath, args: [FLOOD, ...extra] });

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r3-listflood-"));
  mkdirSync(join(dir, "sandboxes"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

describe("r3 fs-net: the tools/list bound", { timeout: 120_000 }, () => {
  it("6000 tools across pages: open() throws a ProtocolViolation that names the bound", async () => {
    await assert.rejects(McpSession.open(spec(), { vars: {}, dsns: {} }, {}), (e: unknown) => {
      assert.ok(e instanceof ProtocolViolation, String(e));
      assert.match((e as Error).message, /tools\/list returned more than 5000 tools \(or 32 MiB\)/);
      return true;
    });
  });

  it("near miss: 4000 tools in pages are accepted", async () => {
    const s = await McpSession.open(spec(["--count", "4000"]), { vars: {}, dsns: {} }, {});
    try {
      assert.equal(s.tools.length, 4000);
    } finally {
      await s.close();
    }
  });

  it("a run reports the protocol check as a fail with the bound in its summary, inside a bounded time", async () => {
    const config: SealmarkConfig = { name: "toy-listflood", version: "0.0.1", server: spec() as SealmarkConfig["server"] };
    const t0 = Date.now();
    const run = await runPacks(config, ["core"], { dir, parent: join(dir, "sandboxes") });
    const elapsed = Date.now() - t0;
    const protocol = run.checks.find((c) => c.id === "protocol");
    assert.ok(protocol, JSON.stringify(run.checks.map((c) => c.id)));
    assert.equal(protocol.verdict, "fail", protocol.summary);
    assert.match(`${protocol.summary} ${protocol.evidence.map((e) => e.outcome).join(" ")}`, /more than 5000 tools \(or 32 MiB\)/);
    assert.ok(elapsed < 60_000, `finished in ${elapsed} ms`);
  });
});
