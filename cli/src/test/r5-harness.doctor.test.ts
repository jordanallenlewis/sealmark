import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadEffectiveConfig } from "../config/index.js";
import { diagnoseStartup, orphanedSegments, renderDoctor, runDoctor, segmentItem, usageError } from "../doctor.js";
import { parseIpcs, type IpcsRow } from "../embedded.js";
import { versionWarnings, type ResolvedPackage } from "../resolve.js";
import { TOY } from "./helpers.js";

// Round 5, G13 (the two `harness` bullets) and G11 (doctor lists orphaned shared-memory segments, removes nothing).

const toy = (name: string) => fileURLToPath(new URL(`../toy/${name}.js`, import.meta.url));
const q = JSON.stringify;

let dir: string;
let parent: string;
let counter = 0;
const load = (server: { command: string; args: string[] }) => {
  const file = join(dir, `c${++counter}.yaml`);
  writeFileSync(file, `schema_version: 1\nname: r5-doctor\nversion: 0.0.1\nserver:\n  command: ${q(server.command)}\n  args: ${q(server.args)}\nsandbox:\n  dir: ${q(parent)}\n`);
  return loadEffectiveConfig({ cwd: dir, flags: { config: file }, env: {}, isolated: true });
};
const node = (...args: string[]) => ({ command: process.execPath, args });

describe("r5-harness: doctor", { timeout: 900_000 }, () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-r5-doctor-"));
    parent = join(dir, "sandboxes");
    mkdirSync(parent);
  });
  after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }));

  describe("orphaned shared-memory segments", () => {
    const text = `IPC status from <running system>
T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP NATTCH  SEGSZ  CPID  LPID   ATIME    DTIME    CTIME
Shared Memory:
m 100 0x2fe5e36e --rw------- alice    staff alice    staff      0     56   4242   4242  7:45:15  7:45:31  7:45:15
m 101 0x2fe5e36f --rw------- alice    staff alice    staff      2     56   4243   4243  7:45:15  7:45:31  7:45:15
m 102 0x2fe5e370 --rw------- alice    staff alice    staff      0     56   4244   4244  7:45:15  7:45:31  7:45:15
m 103 0x2fe5e371 --rw------- alice    staff alice    staff      0   8192   4245   4245  7:45:15  7:45:31  7:45:15
m 104 0x2fe5e372 --rw------- bob      staff bob      staff      0     56   4246   4246  7:45:15  7:45:31  7:45:15
`;
    const rows = parseIpcs(text);
    const alive = (pid: number) => pid === 4244; // the creator of segment 102 still runs

    it("lists only what looks orphaned: this user's, nothing attached, creator gone, under 1 KiB", () => {
      assert.deepEqual(orphanedSegments(rows, { user: "alice", alive }).map((r) => r.id), [100]);
    });

    it("a listing without creator pids cannot show the creator is dead, so nothing is listed", () => {
      const noCpid: IpcsRow[] = rows.map(({ cpid: _c, ...r }) => r);
      assert.deepEqual(orphanedSegments(noCpid, { user: "alice", alive: () => false }), []);
    });

    it("the item names the command and says doctor removes nothing", () => {
      const item = segmentItem(orphanedSegments(rows, { user: "alice", alive }))!;
      assert.equal(item.status, "warn");
      assert.match(item.title, /1 possibly orphaned shared-memory segment \(id 100\)/);
      assert.match(item.detail!, /ipcs -m/);
      assert.match(item.detail!, /ipcrm -m <id>/);
      assert.match(item.detail!, /doctor removes nothing/);
      assert.equal(segmentItem([]), undefined);
    });

    it("runDoctor puts the item in the environment from a fake ipcs, and a clean machine adds nothing", async () => {
      const cfg = load(node(toy("probes"), "--mode", "good"));
      const withOrphans = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false, segments: async () => rows, pidAlive: alive, user: "alice" });
      const item = withOrphans.environment.find((i) => i.id === "shm-orphans");
      assert.ok(item, renderDoctor(withOrphans));
      assert.match(renderDoctor(withOrphans), /possibly orphaned shared-memory segment/);
      const clean = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false, segments: async () => [], user: "alice" });
      assert.equal(clean.environment.some((i) => i.id === "shm-orphans"), false);
      const none = await runDoctor({ cfg, startupTimeoutMs: 20_000, handleSignals: false, segments: async () => undefined, user: "alice" });
      assert.equal(none.environment.some((i) => i.id === "shm-orphans"), false, "no ipcs here: nothing is said");
    });
  });

  describe("hints", () => {
    const d = (error: string, stderr = "") => diagnoseStartup(error, stderr, { command: "srv", timeoutMs: 10_000 }).join("\n");

    it("a git server that says 'not a valid Git repository' is told what to pass", () => {
      assert.match(d("the server closed", "fatal: not a valid Git repository: /tmp/x"), /a git server needs `--repository \{sandbox\}\/repo` \(or its environment variable set to it\)/);
      assert.ok(!/git server needs/.test(d("the server closed", "boom")), "near-miss: no git hint without the git message");
    });

    it("a click-style usage error is about a flag, not about the environment", () => {
      const stderr = "Usage: srv [OPTIONS]\nTry 'srv --help' for help.\n\nError: Missing option '--api-key'.\n";
      assert.equal(usageError(stderr), "Missing option '--api-key'.");
      const said = d("the server closed", stderr);
      assert.match(said, /usage error \(Missing option '--api-key'\.\)/);
      assert.match(said, /command-line flag/);
      assert.ok(!/wanted a setting from its environment/.test(said), said);
    });

    it("near-miss: a missing-key message without usage text still points at the environment", () => {
      assert.match(d("the server closed", "Error: API_KEY is not set"), /wanted a setting from its environment/);
      assert.equal(usageError("Error: API_KEY is not set"), undefined);
    });
  });

  describe("start-up", () => {
    const wrapper = (name: string, body: string): string => {
      const file = join(dir, name);
      writeFileSync(file, body);
      return file;
    };

    it("a usage error keeps its Error: line in the stderr doctor shows even when a long usage text pushes it out of the tail", async () => {
      const w = wrapper("usage.mjs", `process.stderr.write("Usage: srv [OPTIONS]\\nError: Missing option '--api-key'.\\n" + "  --some-option  a long description of an option\\n".repeat(200));\nprocess.exit(2);\n`);
      const r = await runDoctor({ cfg: load(node(w)), startupTimeoutMs: 20_000, handleSignals: false, segments: async () => undefined });
      const s = r.servers[0]!;
      assert.ok(s.stderr.includes("Error: Missing option '--api-key'."), s.stderr.slice(0, 200));
      const advice = s.items.filter((i) => i.id === "advice").map((i) => i.title).join("\n");
      assert.match(advice, /command-line flag/);
      assert.ok(!/environment/.test(advice), advice);
    });

    it("a server that is still downloading at the default 10 s limit is given 60 s once, and says why", async () => {
      const marker = join(dir, "first-start.txt");
      const w = wrapper(
        "download.mjs",
        `import { existsSync, writeFileSync } from "node:fs";
if (!existsSync(${q(marker)})) {
  writeFileSync(${q(marker)}, "x");
  process.stderr.write("Downloading some-package (12.3 MiB)\\n");
  setTimeout(() => process.exit(1), 20000);
} else {
  process.argv.splice(2, 0, "--mode", "nosql");
  await import(${q(pathToFileURL(TOY).href)});
}
`,
      );
      const logs: string[] = [];
      const r = await runDoctor({ cfg: load(node(w)), handleSignals: false, segments: async () => undefined, log: (s) => logs.push(s) });
      assert.equal(r.servers[0]!.items.find((i) => i.id === "start")?.status, "ok", renderDoctor(r));
      assert.ok(logs.some((l) => /still downloading itself: starting .* again with a limit of 60 s/.test(l)), logs.join("\n"));
    });

    it("near-miss: an explicit --connect-timeout is never extended, and a timeout without download output is not retried", async () => {
      const w = wrapper("quiet-hang.mjs", `setTimeout(() => process.exit(1), 20000);\n`);
      const logs: string[] = [];
      const t0 = Date.now();
      const r = await runDoctor({ cfg: load(node(w)), startupTimeoutMs: 1500, handleSignals: false, segments: async () => undefined, log: (s) => logs.push(s) });
      assert.equal(r.servers[0]!.items.find((i) => i.id === "start")?.status, "fail");
      assert.ok(!logs.some((l) => /again with a limit/.test(l)));
      assert.ok(Date.now() - t0 < 120_000, "a timeout without download output fails at the limit it was given, not after a retry");
    });
  });

  describe("what the output says", () => {
    it("path tools and no {sandbox} placeholder: the hint names server.env and server.rootless; with {sandbox} there is no hint", async () => {
      const without = await runDoctor({ cfg: load(node(toy("probes"), "--mode", "good")), startupTimeoutMs: 20_000, handleSignals: false, segments: async () => undefined });
      const hint = without.servers[0]!.items.find((i) => i.id === "sandbox-placeholder");
      assert.ok(hint, renderDoctor(without));
      assert.match(hint.detail!, /server\.env/);
      assert.match(hint.detail!, /server\.rootless/);
      const withIt = await runDoctor({ cfg: load(node(toy("fs"), "--mode", "good", "--root", "{sandbox}")), startupTimeoutMs: 20_000, handleSignals: false, segments: async () => undefined });
      assert.equal(withIt.servers[0]!.items.some((i) => i.id === "sandbox-placeholder"), false);
    });

    it("every doctor run above left no sandbox behind", () => {
      assert.deepEqual(readdirSync(parent), []);
    });
  });
});

describe("r5-harness: version warnings (pure)", () => {
  const one = (version: string, extra: Partial<ResolvedPackage> = {}): ResolvedPackage => ({ name: "srv", version, source: "npx-cache", ...extra });

  it("one cached version that the server's own announcement differs from: says what each is, and never 'pin the version'", () => {
    const v = versionWarnings({ pkg: one("2.4.1"), serverInfoVersion: "1.0.0", configVersion: "0.0.0" });
    assert.deepEqual(v.warnings, ["the cache holds one version (2.4.1); the server announces its own version string (1.0.0)"]);
    assert.ok(!/pin the version/.test(v.warnings.join(" ")));
    assert.equal(v.headerVersion, "1.0.0");
  });

  it("several cached versions and none named: 'pin the version' is the advice that helps, and it stays", () => {
    const v = versionWarnings({ pkg: { name: "srv", source: "npx-cache (ambiguous)", candidates: ["1.0.0", "1.1.0"] }, serverInfoVersion: "0.9.0", configVersion: "0.0.0" });
    assert.equal(v.warnings.length, 1);
    assert.match(v.warnings[0]!, /several versions in the npx cache: 1\.0\.0, 1\.1\.0; the server announced 0\.9\.0; pin the version/);
  });

  it("a pinned package is not second-guessed, and an announcement equal to the resolved version says nothing", () => {
    assert.deepEqual(versionWarnings({ pkg: one("2.4.1", { pinned: true }), serverInfoVersion: "1.0.0", configVersion: "0.0.0" }).warnings, []);
    assert.deepEqual(versionWarnings({ pkg: one("2.4.1"), serverInfoVersion: "v2.4.1", configVersion: "0.0.0" }).warnings, []);
  });

  it("the serverInfo.version warning is suppressed when the resolved package version equals the configured version", () => {
    assert.deepEqual(versionWarnings({ pkg: one("2.4.1", { pinned: true }), serverInfoVersion: "1.0.0", configVersion: "2.4.1" }).warnings, []);
    const differs = versionWarnings({ pkg: one("2.4.1", { pinned: true }), serverInfoVersion: "1.0.0", configVersion: "3.0.0" });
    assert.deepEqual(differs.warnings, ["serverInfo.version 1.0.0 differs from config version 3.0.0 (resolved package: srv 2.4.1)"]);
  });

  it("an empty serverInfo.version makes the header use the resolved package version, with a note", () => {
    const v = versionWarnings({ pkg: one("2.4.1"), serverInfoVersion: "", configVersion: "0.0.0" });
    assert.equal(v.headerVersion, "2.4.1");
    assert.match(v.note!, /announced no version, so the resolved package version \(2\.4\.1\) is shown/);
    assert.deepEqual(v.warnings, []);
  });

  it("no information at all keeps the configured label; a configured version is never replaced", () => {
    assert.equal(versionWarnings({ serverInfoVersion: "", configVersion: "0.0.0" }).headerVersion, "0.0.0");
    assert.equal(versionWarnings({ pkg: one("2.4.1"), serverInfoVersion: "", configVersion: "5.0.0" }).headerVersion, "5.0.0");
  });

  it("a SDK-version announcement is not a difference worth a warning", () => {
    const pkg = one("2.4.1", { dependencies: { "@modelcontextprotocol/sdk": "1.2.3" } });
    assert.deepEqual(versionWarnings({ pkg, serverInfoVersion: "1.2.3", configVersion: "0.0.0" }).warnings, []);
  });
});
