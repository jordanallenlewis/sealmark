import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startEmbedded, type EmbeddedHandle } from "../embedded.js";
import type { CheckResult, PackId, RunResult, SealmarkConfig, Verdict } from "../types.js";

/** dist/toy/server.js, resolved from dist/test/helpers.js. */
export const TOY = fileURLToPath(new URL("../toy/server.js", import.meta.url));
export const CLI = fileURLToPath(new URL("../cli.js", import.meta.url));

export function toyConfig(mode: string, extraArgs: string[] = []): SealmarkConfig {
  return { name: `toy-${mode}`, version: "0.0.1", server: { command: process.execPath, args: [TOY, "--mode", mode, ...extraArgs], env: {} } };
}

export function verdicts(r: RunResult, pack: PackId): Record<string, Verdict> {
  return Object.fromEntries(r.checks.filter((c) => c.pack === pack).map((c) => [c.id, c.verdict]));
}

export function gradeOf(r: RunResult, pack: PackId) {
  const p = r.packs[pack];
  return p?.status === "graded" ? p.grade : undefined;
}

/** Builds a check for grade tests; scope and evidence are irrelevant there. */
export function check(id: string, verdict: Verdict, o: { critical?: boolean; advisory?: boolean; pack?: PackId } = {}): CheckResult {
  return { id, pack: o.pack ?? "core", label: id, critical: Boolean(o.critical), advisory: o.advisory, scope: "test", verdict, summary: "test", evidence: [] };
}

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => res(port));
    });
  });
}

export const quiet = () => {};

/**
 * Start several embedded Postgres instances in parallel. Every instance that did start is added to `handles` even when
 * another one failed, so the suite's after() hook can stop them instead of leaving servers behind.
 */
export async function startAllEmbedded(handles: EmbeddedHandle[], ports: number[]): Promise<void> {
  const settled = await Promise.allSettled(ports.map((p) => startEmbedded(p)));
  for (const s of settled) if (s.status === "fulfilled") handles.push(s.value);
  const bad = settled.find((s): s is PromiseRejectedResult => s.status === "rejected");
  if (bad) throw bad.reason;
}

/**
 * The environment for spawning the CLI in a test: your real environment minus every SEALMARK_* variable, with the
 * user-level config file switched off, so a file in %APPDATA% or a variable in your shell cannot change a result.
 */
export function hermeticEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  // CI, NO_COLOR and FORCE_COLOR change the default profile and the summary colors; a test sets them on purpose through `extra`.
  for (const [k, v] of Object.entries(process.env)) if (!k.toUpperCase().startsWith("SEALMARK_") && !["CI", "NO_COLOR", "FORCE_COLOR"].includes(k)) env[k] = v;
  return { ...env, SEALMARK_USER_CONFIG: "none", ...extra };
}

/**
 * Helpers for tests that spawn the CLI. `getDir` returns the test file's scratch directory (created in its own before() hook).
 * Everything is hermetic: see hermeticEnv.
 */
export function cliKit(getDir: () => string) {
  const writeYaml = (file: string, text: string): string => {
    const path = join(getDir(), file);
    writeFileSync(path, text);
    return path;
  };
  /** JSON strings are valid YAML double-quoted scalars, so Windows paths survive. */
  const writeConfig = (file: string, command: string, args: string[]): string =>
    writeYaml(file, `name: cli-test\nversion: 1.0.0\nserver:\n  command: ${JSON.stringify(command)}\n  args: ${JSON.stringify(args)}\n`);
  const toyConfigFile = (file: string, mode: string): string => writeConfig(file, process.execPath, [TOY, "--mode", mode]);
  /** Points every place `init` looks for MCP client configs at an empty directory, so tests never read (or import) the real ones. */
  const noClients = (): Record<string, string> => {
    const h = join(getDir(), "no-clients");
    mkdirSync(h, { recursive: true });
    return { HOME: h, USERPROFILE: h, APPDATA: h, LOCALAPPDATA: h, XDG_CONFIG_HOME: h };
  };
  const sealmark = (args: string[], cwd: string = getDir(), env: Record<string, string> = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", timeout: 120_000, env: hermeticEnv(env) });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const readJson = <T = RunResult>(path: string): T => JSON.parse(readFileSync(path, "utf8")) as T;
  return { writeYaml, writeConfig, toyConfig: toyConfigFile, noClients, sealmark, readJson };
}

export const q = (v: unknown): string => JSON.stringify(v);
/** `command:` and `args:` lines for a toy server, indented to sit under a key at `indent` spaces. */
export const srv = (mode: string, indent = 4): string => `command: ${q(process.execPath)}\n${" ".repeat(indent)}args: ${q([TOY, "--mode", mode])}`;
/** Flags for a quick core-only run. */
// Toy servers grade below A on purpose, so most tests turn the default A gate off; a test about the gate passes its own --fail-under after this.
export const FAST = ["--pack", "core", "--timeout-probe", "2", "--fail-under", "none"];
