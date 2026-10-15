import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { classifyTools } from "../classify.js";
import { McpSession } from "../mcp.js";
import { createSandbox, type Sandbox } from "../sandbox.js";
import { pack } from "../packs/net.js";
import { legacyEffectiveConfig } from "../run.js";
import type { CheckResult, PackCtx } from "../types.js";
import { quiet } from "./helpers.js";

// net-scheme-allowlist reads the blocks a server answers a data: URL with. The token the harness put in the URL is looked for in the
// decoded bytes of a resource, image or audio block; a block that only echoes the URL is not "decoded".
const TOY = fileURLToPath(new URL("../toy/net-datablob.js", import.meta.url));
const PROBE_SEC = 2;

let parent: string;
const sandboxes: Sandbox[] = [];
const out: Record<string, CheckResult[]> = {};

async function runMode(mode: string): Promise<CheckResult[]> {
  const server = { command: process.execPath, args: [TOY, "--mode", mode], env: {} as Record<string, string> };
  const sandbox = await createSandbox({ dir: parent, timeoutProbeSec: PROBE_SEC, log: quiet });
  sandboxes.push(sandbox);
  const open = () => McpSession.open(server, { vars: {}, dsns: {} }, { cwd: sandbox.root, baseEnv: sandbox.env(), envMode: "scrubbed" });
  const first = await open();
  const tools = first.tools;
  await first.close();
  const classification = classifyTools({ tools, overrides: {}, include: ["*"], exclude: [] }).classification;
  const ctx: PackCtx = {
    pack: "net",
    config: legacyEffectiveConfig({ config: { name: `datablob-${mode}`, version: "0.0.1", server }, packs: ["core", "net"], packsExplicit: false, timeoutProbeSec: PROBE_SEC }),
    tools,
    classification,
    sandbox,
    sandboxEnabled: true,
    open,
    active: false,
    timeoutProbeSec: PROBE_SEC,
    hangMs: 2000,
    log: quiet,
  };
  assert.equal(pack.applies(ctx).ok, true);
  return pack.run(ctx);
}

const scheme = (mode: string): CheckResult => out[mode]!.find((c) => c.id === "net-scheme-allowlist")!;
const text = (mode: string): string => scheme(mode).evidence.map((e) => `${e.probe} | ${e.outcome}`).join("\n");

describe("r3 fs-net: data: URLs answered with content blocks", { timeout: 240_000 }, () => {
  before(async () => {
    parent = mkdtempSync(join(tmpdir(), "sealmark-r3-datablob-"));
    await Promise.all(["resource", "image", "echo", "strict"].map(async (m) => void (out[m] = await runMode(m))));
  });
  after(async () => {
    for (const sb of sandboxes) await sb.destroy().catch(() => {});
    rmSync(parent, { recursive: true, force: true });
  });

  it("the decoded content in a resource blob is a part, with the explicit evidence", () => {
    assert.equal(scheme("resource").verdict, "part", scheme("resource").summary);
    assert.match(text("resource"), /the server decoded the data: URL and returned its content as a resource block/);
    assert.doesNotMatch(text("resource"), /not readable as text/);
    assert.match(scheme("resource").summary, /accepts data: URLs \(data\)/);
  });

  it("the same content in an image block is found too", () => {
    assert.equal(scheme("image").verdict, "part", scheme("image").summary);
    assert.match(text("image"), /returned its content as an image block/);
  });

  it("near miss: a blob that only echoes the URL is not reported as decoded, and refusing data: passes", () => {
    assert.doesNotMatch(text("echo"), /decoded the data: URL/);
    assert.notEqual(scheme("echo").verdict, "part", scheme("echo").summary);
    assert.equal(scheme("strict").verdict, "pass", scheme("strict").summary);
  });
});
