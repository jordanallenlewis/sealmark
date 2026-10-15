// Test support for the sandbox packs (fs, git, effects): config builders for the toy servers, a runner that goes through
// runHarness (real gating, sessions and cleanup), and a hand-built PackCtx for tests that need to tweak the sandbox.
// Not a test file itself (no .test suffix), so `node --test dist/test/**/*.test.js` does not run it.
import { readFileSync, existsSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyTools } from "../classify.js";
import { McpSession } from "../mcp.js";
import { runHarness } from "../run.js";
import { legacyEffectiveConfig } from "../run.js";
import { createSandbox, type Sandbox } from "../sandbox.js";
import type { EffectiveConfig, PackCtx, PackId, RunResult, SealmarkConfig } from "../types.js";

export const FS_TOY = fileURLToPath(new URL("../toy/fs.js", import.meta.url));
export const GIT_TOY = fileURLToPath(new URL("../toy/git.js", import.meta.url));
export const quiet = () => {};

export function fsConfig(mode: string, o: { root?: string; trace?: string } = {}): SealmarkConfig {
  const args = [FS_TOY, "--mode", mode, "--root", o.root ?? "{sandbox}", ...(o.trace ? ["--trace", o.trace] : [])];
  return { name: `toy-fs-${mode}`, version: "0.0.1", server: { command: process.execPath, args, env: {} } };
}

export function gitConfig(mode: string, o: { repo?: string; trace?: string } = {}): SealmarkConfig {
  const args = [GIT_TOY, "--mode", mode, "--repo", o.repo ?? "{sandbox}/repo", ...(o.trace ? ["--trace", o.trace] : [])];
  return { name: `toy-git-${mode}`, version: "0.0.1", server: { command: process.execPath, args, env: {} } };
}

type Over = Omit<Partial<EffectiveConfig>, "sandbox"> & { sandbox?: Partial<EffectiveConfig["sandbox"]> };

export function effectiveFor(config: SealmarkConfig, packs: PackId[], where: { dir: string; parent: string }, over: Over = {}): EffectiveConfig {
  const base = legacyEffectiveConfig({ config, packs, packsExplicit: true, timeoutProbeSec: 2 });
  const { sandbox, ...rest } = over;
  return { ...base, cwd: where.dir, ...rest, sandbox: { ...base.sandbox, dir: where.parent, ...sandbox } };
}

/** Runs the harness on a toy with the given packs; the sandbox is created under `where.parent` and removed afterwards. */
export function runPacks(config: SealmarkConfig, packs: PackId[], where: { dir: string; parent: string }, over: Over = {}): Promise<RunResult> {
  return runHarness({ config, effective: effectiveFor(config, packs, where, over), packs, packsExplicit: true, timeoutProbeSec: 2, log: quiet });
}

export function readTrace(file: string): { tool: string; args: Record<string, unknown> }[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { tool: string; args: Record<string, unknown> });
}

/** Every string argument of a traced call, arrays flattened. */
export function stringArgs(args: Record<string, unknown>): string[] {
  return Object.values(args).flatMap((v) => (typeof v === "string" ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []));
}

/** Acceptance item 9: a path a probe sent is inside the sandbox directory (after resolving `..`, `\\?\` and file://). */
export function insideDir(dir: string, p: string): boolean {
  let s = p.replace(/^file:\/\//i, "").replace(/^\\\\\?\\/, "");
  if (/^\/[A-Za-z]:[\\/]/.test(s)) s = s.slice(1);
  const fold = (x: string) => (process.platform === "win32" ? x.toLowerCase() : x);
  const abs = isAbsolute(s) ? s : resolve(dir, "root", s);
  const rel = relative(fold(resolve(dir)), fold(resolve(abs)));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export interface Direct {
  ctx: PackCtx;
  sandbox: Sandbox;
  /** The real sandbox, even when `ctx.sandbox` is a tweaked copy. */
  close(): Promise<void>;
}

/**
 * A PackCtx built by hand: a real sandbox and real sessions on the toy, with the option to replace the sandbox object seen
 * by the pack (to simulate a link that could not be created, for example).
 */
export async function directCtx(
  config: SealmarkConfig,
  pack: PackId,
  where: { dir: string; parent: string },
  o: { over?: Over; tweak?: (sb: Sandbox) => Sandbox } = {},
): Promise<Direct> {
  const eff = effectiveFor(config, [pack], where, o.over);
  const sb = await createSandbox({ dir: where.parent, timeoutProbeSec: 2 });
  const opts = { cwd: sb.root, baseEnv: sb.env(), envMode: "scrubbed" as const };
  const tctx = { vars: { sandbox: sb.root, sandbox_home: sb.home, listener: sb.listener.url }, dsns: {} };
  const sessions: McpSession[] = [];
  const open = async () => {
    const s = await McpSession.open(eff.server, tctx, opts);
    sessions.push(s);
    return s;
  };
  const first = await open();
  const tools = first.tools;
  const classification = classifyTools({ tools }).classification;
  const seen = o.tweak ? o.tweak(sb) : sb;
  const ctx: PackCtx = { pack, config: eff, tools, classification, sandbox: seen, sandboxEnabled: true, open, active: false, timeoutProbeSec: 2, hangMs: 2000, log: quiet };
  return {
    ctx,
    sandbox: sb,
    async close() {
      for (const s of sessions) await s.close();
      await sb.destroy();
    },
  };
}
