import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { isMap, parseDocument } from "yaml";
import { describeProfiles, loadUserProfiles, migrateFile, renderShow, type EffectiveConfig, type FlagValues } from "./config/index.js";
import { CLIENT_IDS, nodeImportEnv, type ClientId } from "./config/import.js";
import { InitError, readlineIO, runInit } from "./config/wizard.js";
import { renderDescribe } from "./describe.js";
import { renderDoctor, rulesOf, runDoctor, type DoctorCapture } from "./doctor.js";
import { generateValidProbes, probesJson, renderProbesBlock } from "./probes.js";
import { ExplainError, explainCheck, listChecks, renderExplain, renderListChecks } from "./explain.js";
import { writeFixture } from "./fixtures.js";

/** Bad flag, flag combination or argument: exit 2. */
export class UsageError extends Error {}

export interface CommandOutput {
  code: number;
  stdout?: string;
}

// ---------------------------------------------------------------------------------------------------------
// init (the wizard lives in config/wizard.ts; this is only the glue)
// ---------------------------------------------------------------------------------------------------------

export interface InitCommandOptions {
  configPath: string;
  force: boolean;
  from?: string;
  fromUrl?: string;
  /** `--client`: read only these MCP clients' configuration files. */
  clients?: string[];
  /** `--server`: comma separated names, `client/name`, or `all`. */
  server?: string;
  /** `--yes`: never ask questions. */
  yes: boolean;
  log: (s: string) => void;
}

/**
 * `sealmark init`: imports servers from the MCP clients on this machine (or from a one-liner), asks which to grade and
 * whether to point them at harness-owned targets when stdin is a terminal, and writes sealmark.yaml, sealmark.local.yaml
 * and .gitignore. Without a terminal, or with --yes, it takes the defaults and never prompts.
 */
export async function initCommand(o: InitCommandOptions): Promise<CommandOutput> {
  const bad = (o.clients ?? []).filter((c) => !(CLIENT_IDS as readonly string[]).includes(c));
  if (bad.length) throw new UsageError(`--client must be one of ${CLIENT_IDS.join(", ")}; got ${bad.map((b) => `"${b}"`).join(", ")}`);
  const interactive = !o.yes && Boolean(process.stdin.isTTY) && Boolean(process.stderr.isTTY) && o.from === undefined && o.fromUrl === undefined;
  const io = interactive ? readlineIO() : undefined;
  try {
    const outcome = await runInit({
      env: nodeImportEnv(),
      configPath: o.configPath,
      force: o.force,
      ...(o.clients?.length ? { clients: o.clients as ClientId[] } : {}),
      ...(o.from !== undefined ? { fromCommand: o.from } : {}),
      ...(o.fromUrl !== undefined ? { fromUrl: o.fromUrl } : {}),
      ...(o.server ? { select: o.server.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
      ...(io ? { io } : {}),
    });
    // With a terminal the wizard already printed its messages through the questions' output.
    if (!io) for (const m of outcome.messages) o.log(m);
    if (outcome.template) o.log('Edit "server" to point at your MCP server, then run: sealmark run');
    return { code: 0 };
  } catch (e) {
    if (e instanceof InitError) throw new UsageError(e.message);
    throw e;
  } finally {
    io?.close();
  }
}

// ---------------------------------------------------------------------------------------------------------
// init --probes
// ---------------------------------------------------------------------------------------------------------

export interface InitProbesOptions {
  /** The configuration file `--write` appends to. */
  configPath: string;
  /** `--write`: append the block to the configuration file instead of printing it. */
  write: boolean;
  /** `--json`: print `sealmark.probes/1` instead of the YAML block. */
  json: boolean;
  startupTimeoutMs?: number;
  log: (s: string) => void;
}

/**
 * `sealmark init --probes [--write] [--json]`: opens the server exactly as `doctor` does, and writes one valid call per tool as a
 * `probes:` block (stdout, or appended to the configuration file with --write). Never asks a question: nothing here needs an answer, so
 * it behaves the same in a terminal, in CI and in an agent. Idempotent: the same server and configuration give the same block; --write
 * refuses (exit 2) when `probes:` already exists instead of merging.
 */
export async function initProbesCommand(cfg: EffectiveConfig, o: InitProbesOptions): Promise<CommandOutput> {
  if (cfg.servers.length > 1) throw new UsageError(`this configuration declares several servers (${cfg.servers.map((s) => s.name).join(", ")}): pick one with --server <name>`);
  const name = basename(o.configPath);
  // Refuse before the server is started: a --write that cannot succeed should not cost a server start.
  let existing: string | undefined;
  if (o.write) {
    if (!existsSync(o.configPath)) throw new UsageError(`there is no ${name} to write to: create it first (sealmark init --from-url <url> --yes), or leave out --write to print the block`);
    existing = readFileSync(o.configPath, "utf8");
    if (hasProbesKey(existing, name)) throw new UsageError(`\`probes:\` already exists in ${name}; merge by hand or remove it`);
    if (cfg.probes.length) throw new UsageError(`probes are already configured outside ${name} (a profile, sealmark.local.yaml or an environment variable); merge by hand or remove them`);
  }
  let captured = undefined as DoctorCapture | undefined;
  const report = await runDoctor({ cfg, startupTimeoutMs: o.startupTimeoutMs, log: o.log, capture: (c) => (captured ??= c) });
  if (!captured) {
    const failing = [...report.environment, ...report.servers.flatMap((s) => s.items)].filter((i) => i.status === "fail");
    o.log("sealmark: init --probes could not read the server's tool list");
    for (const f of failing) o.log(`  ${f.title}${f.detail ? `: ${f.detail}` : ""}`);
    o.log("run `sealmark doctor` to see every step, fix what it reports, then run this again");
    return { code: 4 };
  }
  const rules = rulesOf(cfg);
  const sep = (cfg.value as { scope?: { separator?: unknown } } | undefined)?.scope?.separator;
  const gen = generateValidProbes({
    tools: captured.tools,
    classification: captured.classification,
    upstream: rules.upstreamKind !== null,
    scope: { tools: rules.scopeTools, allow: rules.scopeAllow, ...(typeof sep === "string" && sep ? { separator: sep } : {}) },
    transport: captured.transport,
  });
  const block = renderProbesBlock(gen);
  if (o.write) {
    if (gen.probes.length) {
      writeFileSync(o.configPath, `${existing!.endsWith("\n") || !existing ? existing : `${existing}\n`}\n${block}`);
      o.log(`wrote ${gen.probes.length} probe(s) to ${o.configPath}${gen.skipped.length ? `; ${gen.skipped.length} tool(s) were left out and are listed as comments there` : ""}`);
      o.log("next: sealmark run");
    } else o.log(`nothing written: no valid call could be generated (${gen.skipped.map((s) => `${s.tool}: ${s.reason}`).join("; ") || "the server declares no tools"})`);
  } else if (!o.json && !gen.probes.length) o.log("no valid call could be generated; the reasons are in the comments of the block");
  if (o.json) return { code: 0, stdout: `${JSON.stringify({ ...probesJson(gen), ...(o.write && gen.probes.length ? { written: o.configPath } : {}) }, null, 2)}\n` };
  return { code: 0, ...(o.write ? {} : { stdout: block }) };
}

/** True when the YAML document has a top-level `probes` key (an empty list counts: there is something to merge by hand). */
function hasProbesKey(text: string, name: string): boolean {
  const doc = parseDocument(text);
  if (doc.errors.length) throw new UsageError(`${name} is not valid YAML (${doc.errors[0]!.message.split("\n")[0]}); fix it, then run this again`);
  return isMap(doc.contents) && doc.contents.has("probes");
}

// ---------------------------------------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------------------------------------

export async function doctorCommand(cfg: EffectiveConfig, o: { server?: string; json: boolean; startupTimeoutMs?: number; log: (s: string) => void }): Promise<CommandOutput> {
  let report;
  try {
    report = await runDoctor({ cfg, ...(o.server && o.server !== "all" ? { server: o.server } : {}), ...(o.startupTimeoutMs ? { startupTimeoutMs: o.startupTimeoutMs } : {}), log: o.log });
  } catch (e) {
    // "no server named ..." is a mistake in the command, not a failing step.
    if (e instanceof Error && /^no server named/.test(e.message)) throw new UsageError(e.message);
    throw e;
  }
  return { code: report.exitCode, stdout: o.json ? `${JSON.stringify(report, null, 2)}\n` : renderDoctor(report) };
}

// ---------------------------------------------------------------------------------------------------------
// run --fixture
// ---------------------------------------------------------------------------------------------------------

/** Writes the fixture the sandbox generates, for hand runs: `sealmark run --fixture sqlite --into ./dir` (the work is in fixtures.ts). */
export function fixtureCommand(name: string, into: string | undefined, log: (s: string) => void): Promise<CommandOutput> {
  return writeFixture(name, into, log);
}

// ---------------------------------------------------------------------------------------------------------
// config show | profiles | migrate
// ---------------------------------------------------------------------------------------------------------

export function configShow(cfg: EffectiveConfig, o: { origins: boolean; json: boolean }): CommandOutput {
  return { code: 0, stdout: renderShow(cfg, { origins: o.origins, json: o.json }) };
}

const MAX_DIFF = 10;

export function configProfiles(opts: { cwd: string; flags: FlagValues; env: Record<string, string | undefined> }, json: boolean): CommandOutput {
  const rows = describeProfiles(loadUserProfiles(opts));
  if (json) return { code: 0, stdout: `${JSON.stringify({ profiles: rows }, null, 2)}\n` };
  const w = Math.max(...rows.map((r) => r.name.length), 7);
  const out = [`${"PROFILE".padEnd(w)}  KIND     STANDARD  EXTENDS     DESCRIPTION`];
  for (const r of rows) {
    out.push(`${r.name.padEnd(w)}  ${(r.shipped ? "shipped" : "user").padEnd(7)}  ${(r.standard ? "yes" : "no").padEnd(8)}  ${(r.extends ?? "-").padEnd(10)}  ${r.description ?? ""}`.trimEnd());
    for (const reason of r.reasons.slice(0, 3)) out.push(`${" ".repeat(w + 2)}not standard: ${reason.path} (${reason.origin})`);
    const diffs = r.diff.slice(0, MAX_DIFF);
    for (const d of diffs) out.push(`${" ".repeat(w + 2)}${d.path}: standard ${JSON.stringify(d.standard)}, profile ${JSON.stringify(d.profile)}`);
    if (r.diff.length > MAX_DIFF) out.push(`${" ".repeat(w + 2)}... and ${r.diff.length - MAX_DIFF} more setting(s) differ from standard`);
  }
  out.push("", "STANDARD: a run that uses only this profile can still be a STANDARD run (grade comparable and badge-eligible). Any other profile makes the run CUSTOM.");
  return { code: 0, stdout: `${out.join("\n")}\n` };
}

export function configMigrate(configPath: string, o: { force: boolean }, log: (s: string) => void): CommandOutput {
  const res = migrateFile(configPath, { write: false });
  if (!res.changed) {
    log(`${configPath} is already at schema_version ${res.to}; nothing to do`);
    for (const n of res.notes) log(`note: ${n}`);
    return { code: 0 };
  }
  // Keep the first original: a second migration must not overwrite the only copy of what the user wrote.
  const backup = `${configPath}.bak`;
  if (!existsSync(backup) || o.force) copyFileSync(configPath, backup);
  const done = migrateFile(configPath, { write: true });
  const lines = [`migrated ${configPath} from schema_version ${done.from} to ${done.to} (original kept at ${backup})`, ...done.notes.map((n) => `note: ${n}`), done.diff];
  return { code: 0, stdout: `${lines.filter(Boolean).join("\n")}\n` };
}

// ---------------------------------------------------------------------------------------------------------
// list-checks | explain | describe
// ---------------------------------------------------------------------------------------------------------

export function listChecksCommand(o: { pack?: string[]; json: boolean }): CommandOutput {
  try {
    return { code: 0, stdout: renderListChecks(listChecks({ pack: o.pack?.length ? o.pack : undefined }), { json: o.json }) };
  } catch (e) {
    if (e instanceof ExplainError) throw new UsageError(e.message);
    throw e;
  }
}

export function explainCommand(id: string | undefined, json: boolean): CommandOutput {
  if (!id) throw new UsageError("explain needs a check id; run `sealmark list-checks` to see them");
  try {
    return { code: 0, stdout: renderExplain(explainCheck(id), { json, asked: id }) };
  } catch (e) {
    if (e instanceof ExplainError) throw new UsageError(e.message);
    throw e;
  }
}

export function describeCommand(): CommandOutput {
  return { code: 0, stdout: renderDescribe() };
}
