import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { HarnessError, runHarness } from "../run.js";
import { CONNECT_TIMEOUT_ADVICE, connectTimeoutMessage, isConnectTimeout } from "../launch.js";
import type { PackId, RunResult } from "../types.js";
import { q } from "./helpers.js";

// Harness behaviour that decides which packs run and how they are started.
const DSN = fileURLToPath(new URL("../toy/dsn-required.js", import.meta.url));
const HANG = fileURLToPath(new URL("../toy/hang.js", import.meta.url));
const SKIP_DB = process.env.SEALMARK_SKIP_DB === "1" ? "SEALMARK_SKIP_DB=1" : false;

let dir: string;
let parent: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-r4-packs-"));
  parent = join(dir, "sandboxes");
  mkdirSync(parent);
});
after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

const CHECK = `check: { id: custom-echo-acked, label: "An echo is acknowledged", critical: false, scope: "server (echo tool)" }`;
const PROBE = `probes:\n  - { id: echo-ack, ${CHECK}, tool: echo, args: { text: hello }, expect: { text: { matches: "^echo: hello" } } }\n`;

interface Run {
  r: RunResult;
  log: string[];
}
async function run(file: string, flags: { pack?: string[]; embedded?: boolean } = {}): Promise<Run> {
  const eff = loadEffectiveConfig({ cwd: dir, flags: { config: file, ...(flags.pack ? { pack: flags.pack } : {}) }, env: {}, isolated: true });
  const log: string[] = [];
  const r = await runHarness({
    config: { name: eff.name, version: eff.version, server: eff.server },
    effective: eff,
    packs: eff.packs as PackId[],
    packsExplicit: eff.packsExplicit,
    ...(flags.embedded === false ? { embedded: false } : {}),
    timeoutProbeSec: 2,
    log: (s) => log.push(s),
  });
  return { r, log };
}

const configFor = (name: string, server: string, tail = ""): string => {
  const file = join(dir, `${name}.yaml`);
  writeFileSync(file, `schema_version: 1\nname: ${name}\nversion: 0.0.1\nserver:\n  ${server}\nsandbox:\n  dir: ${q(parent)}\n${tail}`);
  return file;
};
const dsnServer = `command: ${q(process.execPath)}\n  args: [${q(DSN)}, "--dsn", "{dsn}"]`;
const plainServer = `command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "iserror"]`;

describe("r4-harness: the custom pack on a server that needs {dsn} (E3)", { timeout: 240_000, skip: SKIP_DB }, () => {
  it("a check probe on a {dsn} server gets a graded custom pack: the pack's own sessions start the server with the database's connection string", async () => {
    const { r } = await run(configFor("dsn-custom", dsnServer, PROBE), { pack: ["core", "custom"] });
    assert.equal(r.packs.custom?.status, "graded", JSON.stringify(r.packs.custom));
    assert.equal(r.checks.find((c) => c.id === "custom-echo-acked")?.verdict, "pass");
    assert.ok(r.options.packsRequested.includes("custom"));
  });
});

describe("r4-harness: the pack list the user typed is respected (E7)", { timeout: 240_000 }, () => {
  const PLAIN_PROBE = `probes:\n  - { id: note-ack, check: { id: custom-note-acked, label: "A note is acknowledged", critical: false, scope: "server (note tool)" }, tool: note, args: { text: hello }, expect: { text: { matches: "^noted" } } }\n`;
  const SKIPPED = "probes with a check were declared but the pack list omits custom, so they were skipped (add custom to --pack or packs:)";
  const ADDED = "probes with a check were declared, so the custom pack is included";

  it("--pack core with a check probe: custom is not run, and the warning is in the report, not only on stderr", async () => {
    const { r, log } = await run(configFor("explicit-core", plainServer, PLAIN_PROBE), { pack: ["core"] });
    assert.equal(r.packs.custom, undefined, "custom did not run");
    assert.ok(!r.options.packsRequested.includes("custom"));
    assert.ok(r.warnings?.includes(SKIPPED), JSON.stringify(r.warnings));
    assert.ok(log.some((l) => l.includes(SKIPPED)));
    assert.equal(r.checks.some((c) => c.id === "custom-note-acked"), false);
  });

  it("--pack core --pack custom: the user asked for it, so it runs with no note at all", async () => {
    const { r, log } = await run(configFor("explicit-both", plainServer, PLAIN_PROBE), { pack: ["core", "custom"] });
    assert.equal(r.packs.custom?.status, "graded");
    assert.ok(!(r.warnings ?? []).some((w) => w === SKIPPED || w === ADDED));
    assert.ok(!log.some((l) => l.includes(ADDED)));
  });

  it("near-miss: the default pack list gets custom appended, and the note is in the report's warnings too", async () => {
    const { r, log } = await run(configFor("default-list", plainServer, PLAIN_PROBE));
    assert.equal(r.packs.custom?.status, "graded");
    assert.ok(r.options.packsRequested.includes("custom"));
    assert.ok(r.warnings?.includes(ADDED), JSON.stringify(r.warnings));
    assert.ok(log.includes(`note: ${ADDED}`));
  });

  it("a packs: list written in the file is respected as well", async () => {
    const { r } = await run(configFor("file-list", plainServer, `packs: [core]\n${PLAIN_PROBE}`));
    assert.equal(r.packs.custom, undefined);
    assert.ok(r.warnings?.includes(SKIPPED), JSON.stringify(r.warnings));
  });
});

describe("r4-harness: a server that does not answer initialize names the limit and the flag (E5)", { timeout: 120_000 }, () => {
  it("the connect-timeout failure says how long it waited and what to type", async () => {
    const file = configFor("hang", `command: ${q(process.execPath)}\n  args: [${q(HANG)}, "--mode", "hang"]`, `timeouts:\n  connect_ms: 1500\n`);
    await assert.rejects(run(file), (e: unknown) => {
      assert.ok(e instanceof HarnessError);
      assert.match(e.message, /^the server did not answer initialize within 2 s \(--connect-timeout\)\./);
      assert.ok(e.message.includes(CONNECT_TIMEOUT_ADVICE));
      assert.doesNotMatch(e.message, /-32001/);
      return true;
    });
  });

  it("the sentence is shared: the helper, the matcher and a near-miss that is not a timeout", () => {
    assert.ok(connectTimeoutMessage(60_000).startsWith("the server did not answer initialize within 60 s (--connect-timeout). "));
    assert.equal(isConnectTimeout("MCP error -32001: Request timed out"), true);
    assert.equal(isConnectTimeout("Connection closed"), false);
    assert.equal(isConnectTimeout("spawn nope ENOENT"), false);
  });
});

describe("r4-harness: a pack the harness cannot run is inconclusive, one the server does not suit is n/a (E10)", { timeout: 120_000 }, () => {
  const plugin = (name: string, applies: string): string => {
    writeFileSync(
      join(dir, `${name}.mjs`),
      `export default {
  id: "plugin:${name}", version: "1.0.0", sealmark: "*",
  describe: () => [{ id: "${name}-check", pack: "plugin:${name}", label: "X", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => (${applies}),
  run: async () => [],
};\n`,
    );
    return configFor(`plugin-${name}`, plainServer, `plugins:\n  - { module: ./${name}.mjs }\n`);
  };

  it("kind harness: recorded inconclusive with the reason", async () => {
    const { r } = await run(plugin("noenv", `{ ok: false, kind: "harness", reason: "node:sqlite is not available in this Node" }`));
    assert.deepEqual(r.packs["plugin:noenv" as PackId], { status: "inconclusive", reason: "node:sqlite is not available in this Node" });
  });

  it("near-miss: the default kind (server) stays n/a", async () => {
    const { r } = await run(plugin("noserver", `{ ok: false, reason: "this server has no such tool" }`));
    assert.deepEqual(r.packs["plugin:noserver" as PackId], { status: "na", reason: "this server has no such tool" });
  });
});
