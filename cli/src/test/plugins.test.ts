import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ConfigError } from "../config.js";
import { loadPlugins, makeHelpers, satisfies } from "../plugins.js";
import type { PackCtx } from "../types.js";

describe("plugin version ranges", () => {
  const yes = (v: string, r: string) => assert.equal(satisfies(v, r), true, `${v} should satisfy ${r}`);
  const no = (v: string, r: string) => assert.equal(satisfies(v, r), false, `${v} should not satisfy ${r}`);

  it("comparators with partial versions behave like npm", () => {
    yes("0.2.0", ">=0.2 <0.3");
    yes("0.2.9", ">=0.2 <0.3");
    no("0.3.0", ">=0.2 <0.3");
    no("0.1.9", ">=0.2 <0.3");
    yes("0.3.0", ">0.2");
    no("0.2.5", ">0.2");
    yes("0.2.5", "<=0.2");
    no("0.3.0", "<=0.2");
    yes("1.2.3", "<=1.2.3");
    no("1.2.4", "<=1.2.3");
  });

  it("caret and tilde", () => {
    yes("0.2.5", "^0.2");
    no("0.3.0", "^0.2");
    yes("1.9.0", "^1.2.3");
    no("2.0.0", "^1.2.3");
    no("1.2.2", "^1.2.3");
    yes("0.0.3", "^0.0.3");
    no("0.0.4", "^0.0.3");
    yes("0.2.9", "~0.2.1");
    no("0.3.0", "~0.2.1");
    yes("1.9.0", "~1");
    no("2.0.0", "~1");
  });

  it("exact versions, x-ranges, wildcards and OR", () => {
    yes("0.2.0", "0.2.0");
    no("0.2.1", "0.2.0");
    yes("0.2.7", "0.2.x");
    no("0.3.0", "0.2.x");
    yes("0.2.7", "0.2");
    yes("9.9.9", "*");
    yes("0.1.0", "0.1.x || >=1");
    yes("2.0.0", "0.1.x || >=1");
    no("0.5.0", "0.1.x || >=1");
  });

  it("a prerelease or build suffix is ignored", () => {
    yes("0.2.0-draft", ">=0.2 <0.3");
    yes("v0.2.0", "^0.2");
  });

  it("a range it cannot read throws", () => {
    assert.throws(() => satisfies("0.2.0", ">=banana"), /not a version/);
  });
});

const GOOD = (extra = "") => `export default {
  id: "plugin:ok", version: "1.2.3", sealmark: ">=0.1 <1",
  describe: () => [{ id: "ok-check", pack: "plugin:ok", label: "Fine", critical: false, advisory: false, scope: "server", verifiedBy: ["response"], probes: [], thresholds: {}, falsePositive: "", falseNegative: "", configKeys: [], since: "0.2-draft", status: "shipped" }],
  applies: () => ({ ok: true }),
  run: async (ctx) => [ctx.helpers.done({ id: "ok-check", label: "Fine", critical: false, scope: "server (test)" }, "pass", "opt=" + JSON.stringify(ctx.options), [])],
  ${extra}
};`;

describe("plugin loader", () => {
  let dir: string;
  const write = (name: string, body: string) => {
    writeFileSync(join(dir, name), body);
    return `./${name}`;
  };
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sealmark-plugin-test-"));
    mkdirSync(join(dir, "sub"));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const load = (module: string, extra: { options?: Record<string, unknown>; reserved?: string[]; baseDir?: string; version?: string } = {}) =>
    loadPlugins([{ module, ...(extra.options ? { options: extra.options } : {}) }], { sealmarkVersion: extra.version ?? "0.1.0", baseDir: extra.baseDir ?? dir, reservedCheckIds: extra.reserved ?? ["protocol", "rls"] });

  it("loads a module by path relative to the config directory and wraps it as a Pack", async () => {
    const [pack] = await load(write("ok.mjs", GOOD()), { options: { a: 1 } });
    assert.equal(pack.id, "plugin:ok");
    const docs = pack.describe();
    assert.equal(docs[0].label, "[plugin:ok] Fine");
    assert.equal(docs[0].pack, "plugin:ok");
    const ctx = { pack: "plugin:ok", tools: [], classification: [] } as unknown as PackCtx;
    assert.deepEqual(pack.applies(ctx), { ok: true });
    const [c] = await pack.run(ctx);
    assert.equal(c.pack, "plugin:ok");
    assert.equal(c.label, "[plugin:ok] Fine");
    assert.equal(c.summary, 'opt={"a":1}');
  });

  it("resolves a relative path against the config directory, not the working directory", async () => {
    write("sub/inner.mjs", GOOD());
    const [pack] = await load("./sub/inner.mjs");
    assert.equal(pack.id, "plugin:ok");
  });

  it("a missing module is a ConfigError that names it", async () => {
    await assert.rejects(load("./nope.mjs"), (e: unknown) => e instanceof ConfigError && /nope\.mjs.*could not be loaded/.test((e as Error).message));
  });

  it("a version range the running sealmark does not satisfy is a ConfigError", async () => {
    await assert.rejects(load(write("old.mjs", GOOD()), { version: "2.0.0" }), (e: unknown) => e instanceof ConfigError && /plugin:ok.*requires sealmark >=0\.1 <1.*2\.0\.0/.test((e as Error).message));
  });

  it("a malformed export is refused with the reason", async () => {
    await assert.rejects(load(write("noid.mjs", `export default { id: "s3", version: "1", sealmark: "*", describe(){return []}, applies(){}, run(){} };`)), /id must look like "plugin:name"/);
    await assert.rejects(load(write("nofn.mjs", `export default { id: "plugin:x", version: "1", sealmark: "*", describe(){return []}, applies(){} };`)), /must export run\(\)/);
    await assert.rejects(load(write("nover.mjs", `export default { id: "plugin:x", sealmark: "*", describe(){return []}, applies(){}, run(){} };`)), /version string/);
    await assert.rejects(load(write("norange.mjs", `export default { id: "plugin:x", version: "1", describe(){return []}, applies(){}, run(){} };`)), /sealmark version range/);
    await assert.rejects(load(write("nodefault.mjs", `export const x = 1;`)), /no default export/);
  });

  it("a check id that belongs to a built-in pack is refused at load", async () => {
    const mod = write("collide.mjs", GOOD().replace('"ok-check"', '"rls"').replace('"ok-check"', '"rls"'));
    await assert.rejects(load(mod), (e: unknown) => e instanceof ConfigError && /check id "rls".*built-in/.test((e as Error).message));
  });

  it("the same plugin declared twice is refused", async () => {
    const m = write("twice.mjs", GOOD());
    await assert.rejects(loadPlugins([{ module: m }, { module: m }], { sealmarkVersion: "0.1.0", baseDir: dir, reservedCheckIds: [] }), /declared twice/);
  });

  it("results for another pack, built-in check ids and duplicate ids are rejected when the plugin runs", async () => {
    const run = (body: string) => load(write(`r-${Math.random().toString(36).slice(2)}.mjs`, GOOD().replace(/run: async[^\n]*\n/, `run: async (ctx) => ${body},\n`))).then(([p]) => p.run({ pack: "plugin:ok" } as unknown as PackCtx));
    const base = `{ id: "ok-check", label: "x", critical: false, scope: "server", verdict: "pass", summary: "s", evidence: [] }`;
    await assert.rejects(run(`[{ ...${base}, pack: "core" }]`), /may only report its own pack/);
    await assert.rejects(run(`[{ ...${base}, id: "protocol", pack: "plugin:ok" }]`), /belongs to a built-in pack/);
    await assert.rejects(run(`[{ ...${base}, pack: "plugin:ok" }, { ...${base}, pack: "plugin:ok" }]`), /twice/);
    await assert.rejects(run(`"not a list"`), /instead of a list of checks/);
  });
});

describe("plugin helpers", () => {
  it("token() is unique and embeds nothing but hex", () => {
    const h = makeHelpers("plugin:t", {} as PackCtx);
    const a = h.token();
    assert.match(a, /^sm-[0-9a-f]{12}$/);
    assert.notEqual(a, h.token());
  });

  it("without a sandbox the file helpers explain themselves and inSandbox is false", async () => {
    const h = makeHelpers("plugin:t", { sandbox: undefined } as unknown as PackCtx);
    await assert.rejects(h.snapshot(), /sandbox is not available/);
    assert.equal(h.inSandbox(tmpdir()), false);
    assert.deepEqual(h.listener.expect("x"), []);
  });

  it("inSandbox is lexical: inside, the directory itself, a sibling with the same prefix, and a .. escape", () => {
    const s = join(tmpdir(), "sealmark-abc");
    const h = makeHelpers("plugin:t", { sandbox: { dir: s }, sandboxEnabled: true } as unknown as PackCtx);
    assert.equal(h.inSandbox(join(s, "root", "a.txt")), true);
    assert.equal(h.inSandbox(s), true);
    assert.equal(h.inSandbox(`${s}-evil`), false);
    assert.equal(h.inSandbox(join(s, "root", "..", "..", "x")), false);
  });

  it("done() fills pack, prefixes the label once and keeps the metadata", () => {
    const h = makeHelpers("plugin:t", {} as PackCtx);
    const c = h.done({ id: "c", label: "Thing", critical: true, scope: "server" }, "fail", "bad", []);
    assert.equal(c.pack, "plugin:t");
    assert.equal(c.label, "[plugin:t] Thing");
    assert.equal(c.critical, true);
    assert.equal(h.done({ id: "c", label: "[plugin:t] Thing", critical: true, scope: "server" }, "pass", "", []).label, "[plugin:t] Thing");
  });
});
