#!/usr/bin/env node
import { accessSync, constants, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { INIT_PROBES_ONLY, matchCommand, flagsFor, parseArgsSpec, usageText } from "./cli-spec.js";
import {
  UsageError,
  initProbesCommand,
  configMigrate,
  configProfiles,
  configShow,
  describeCommand,
  explainCommand,
  doctorCommand,
  fixtureCommand,
  initCommand,
  listChecksCommand,
  type CommandOutput,
} from "./commands.js";
import { ConfigError, METHODOLOGY, loadEffectiveConfig, type EffectiveConfig } from "./config/index.js";
import { cliVersion } from "./describe.js";
import { inCi } from "./config/index.js";
import { makeSecretScrubber } from "./report/redact.js";
import { inertLines } from "./report/sanitize.js";
import { CI_PROVIDERS, ciSnippet, type CiDeclared, type CiProvider } from "./ci-snippet.js";
import { FORMATS, FORMAT_EXT, isFailed, renderReport, summaryLine, type AnyRun, type FailedRun, type ReportFormat, type RenderOptions } from "./report.js";
import { compareBaseline, parseBaseline, type BaselineDiff } from "./report/baseline.js";
import { decideExit } from "./report/exit.js";
import { driftFails } from "./report/drift.js";
import { diffCommand } from "./diff.js";
import { secretLiterals } from "./report/secrets.js";
import { setCallEvidence } from "./packs/core.js";
import { interruptCode, wasInterrupted } from "./launch.js";
import { HarnessError, runHarness } from "./run.js";
import { toSealmarkConfig } from "./config/index.js";
import type { Letter, PackId, RunResult } from "./types.js";

const HEADING = `sealmark: behavioral conformance tests for MCP servers (methodology ${METHODOLOGY})`;
const USAGE = usageText(HEADING);

/** The parsed flags that cli.ts reads by name. The full set comes from cli-spec.ts at run time, so util.parseArgs cannot type it. */
interface Values {
  help?: boolean;
  version?: boolean;
  config?: string;
  force?: boolean;
  json?: boolean;
  from?: string;
  'from-url'?: string;
  client?: string[];
  server?: string;
  pack?: string[];
  origins?: boolean;
  replay?: string;
  fixture?: string;
  probes?: boolean;
  write?: boolean;
  [flag: string]: unknown;
}

function parse(argv: string[]): { values: Values; positionals: string[] } {
  try {
    const r = parseArgs({ args: argv, allowPositionals: true, allowNegative: true, options: parseArgsSpec() });
    return { values: r.values as unknown as Values, positionals: r.positionals };
  } catch (e) {
    // Node adds a second sentence about passing a value that starts with "-"; the first sentence is the whole news.
    throw new UsageError((e as Error).message.replace(/\. To specify a positional argument.*$/s, ""));
  }
}

/** What to type next after a usage error: the full usage stays behind --help, and an unknown check id points at the list. */
function usageHint(command: string | undefined, message: string): string {
  if ((command === "explain" || command === "list-checks") && !message.includes("list-checks")) return "run sealmark list-checks to see every check id, or sealmark --help for usage";
  return "run sealmark --help for usage";
}

const logErr = (s: string) => process.stderr.write(`${s}\n`);
/** For stderr lines that can carry the launched server's output or a value it chose (its version, tool names, check text): inert, line structure kept. */
const logSafe = (s: string) => logErr(inertLines(s));

// ---------------------------------------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------------------------------------

function replayBlock(path: string): { hash?: unknown; locked?: unknown; methodology?: unknown } {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(resolve(path), "utf8").replace(/^﻿/, ""));
  } catch (e) {
    throw new ConfigError(`--replay: cannot read ${path} (${(e as Error).message})`);
  }
  const first = Array.isArray((data as { runs?: unknown[] })?.runs) ? (data as { runs: unknown[] }).runs[0] : data;
  const block = (first as { config?: unknown } | undefined)?.config;
  if (!block || typeof block !== "object") throw new ConfigError(`--replay: ${path} has no "config" block; it must be a JSON report written by sealmark 0.2 or later`);
  return block as { hash?: unknown; locked?: unknown; methodology?: unknown };
}

function readText(path: string, what: string): string {
  try {
    return readFileSync(resolve(path), "utf8").replace(/^﻿/, "");
  } catch {
    throw new ConfigError(`Cannot read ${what} ${path}.`);
  }
}

function writeOut(path: string, body: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body.endsWith("\n") ? body : `${body}\n`);
}

/** What went wrong with a file operation in one line, without a stack: "EACCES: permission denied" and the like. */
const fsReason = (e: unknown): string => {
  const err = e as NodeJS.ErrnoException;
  const text = String(err.message ?? e).replace(/^[A-Z0-9_]+: /, "").replace(/,\s*\w+\s+'.*$/, "");
  return err.code ? `${err.code}: ${text}` : text;
};

/**
 * Proves before the run that a report destination can be written, so a typo or a read-only directory costs a second and not the
 * whole run. `dir` creates the directory itself (--out-dir); a file only needs its parent. Nothing is left behind except the
 * created directories.
 */
function ensureWritable(target: string, what: string, kind: "dir" | "file"): void {
  const dir = kind === "dir" ? target : dirname(target);
  try {
    if (kind === "file" && statSync(target, { throwIfNoEntry: false })?.isDirectory()) throw Object.assign(new Error("it is a directory"), { code: "EISDIR" });
    mkdirSync(dir, { recursive: true });
    if (kind === "file" && statSync(target, { throwIfNoEntry: false })) accessSync(target, constants.W_OK);
    // /dev/null and friends: the directory is not ours to write into, and the device itself is already known to be writable.
    if (kind === "file" && statSync(target, { throwIfNoEntry: false })?.isCharacterDevice()) return;
    const probe = join(dir, `.sealmark-write-test-${process.pid}`);
    writeFileSync(probe, "");
    rmSync(probe, { force: true });
  } catch (e) {
    throw new ConfigError(`Cannot write ${what} ${target}: ${fsReason(e)}. Choose a directory you can write to.`);
  }
}

const safeName = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "_");

async function runCommand(values: Values): Promise<CommandOutput> {
  if (values.fixture !== undefined) return await fixtureCommand(values.fixture, values.into as string | undefined, logErr);

  const cfg = loadEffectiveConfig({
    cwd: process.cwd(),
    flags: values,
    env: process.env,
    ...(values.replay ? { replay: replayBlock(values.replay) } : {}),
  });
  const o = cfg.output;
  const quiet = o.verbosity === "quiet";
  // --verbosity verbose prints every evidence line, so robust-input records each call it makes (tool, variant, arguments, outcome).
  setCallEvidence(o.verbosity === "verbose");
  // Progress lines can carry the launched server's URL or output; they are scrubbed once the secrets are known (below).
  let scrubLine = (t: string) => t;
  const log = (s: string) => {
    if (!quiet) logSafe(scrubLine(s));
  };

  for (const w of cfg.warnings) logErr(`warning: ${w}`);
  if (cfg.db.pg && !cfg.yes) {
    throw new UsageError("--pg drops and recreates the database sealmark_seed and creates the roles sm_analyst, sm_support and sm_admin on that server. Add --yes to allow it.");
  }
  if (!o.redact) logErr("warning: --no-redact prints secret-looking values and real sandbox paths in the report; use it only for local debugging, and do not share the output");
  if (cfg.active && cfg.packs.includes("exec")) {
    logErr("warning: --active: the exec pack will ask command-running tools to run harness-owned programs from the sandbox bin directory. Only use it for servers you trust or inside a throwaway VM.");
  }

  // ---- output plan, validated before the (expensive) run ----
  const formats = [...new Set<string>(o.formats.length ? o.formats : [o.format])] as ReportFormat[];
  for (const f of formats) if (!FORMATS.includes(f)) throw new UsageError(`unknown report format "${f}" (use ${FORMATS.join(", ")})`);
  if (cfg.servers.length > 1 && formats.some((f) => f === "badge" || f === "shields")) throw new UsageError("the badge and shields formats take one server; run with --server <name>");
  // Several formats are one file each; without --out-dir they go to ./sealmark-report/ (the ci profile asks for junit and json).
  const outDir = o.out_dir ? resolve(o.out_dir) : formats.length > 1 ? resolve("sealmark-report") : undefined;
  // `summary` is for eyes: with other formats it goes to the console and the rest go to files.
  const toConsole = formats.length > 1 && formats.includes("summary");
  const fileFormats = toConsole ? formats.filter((f) => f !== "summary") : formats;
  if (formats.length > 1 && !o.out_dir && fileFormats.length) logErr(`${fileFormats.length} report ${fileFormats.length > 1 ? "formats" : "format"} (${fileFormats.join(", ")}): writing one file each into ${outDir}`);
  if (formats.length > 1 && o.out && !o.out_dir && fileFormats.length) logErr(`warning: --out ${o.out} is ignored with several formats: the report files go to ${outDir} (use --out-dir to choose another directory)`);
  const destination = (f: ReportFormat): string | undefined => (outDir ? join(outDir, `sealmark-report.${FORMAT_EXT[f]}`) : o.out ? resolve(o.out) : undefined);
  const toStdout = formats.length === 1 && destination(formats[0]) === undefined;
  // A bad destination is found now, not after a run that may take minutes (exit 2, one line).
  if (fileFormats.length) {
    if (outDir) ensureWritable(outDir, o.out_dir ? "--out-dir" : "the report directory", "dir");
    else if (o.out) ensureWritable(resolve(o.out), "--out", "file");
  }
  if (o.write_baseline) ensureWritable(resolve(o.write_baseline), "--write-baseline", "file");
  const template = o.template ? readText(o.template, "the report template") : undefined;
  if (template && !formats.some((f) => f === "text" || f === "markdown")) logErr("warning: a report template applies to the text and markdown formats only; it is ignored here");
  // fail_on is a set: any = the gate and regressions, regressions = regressions only, drift = breaking or notable tool-surface drift.
  // exit_policy.regressions_only is the old spelling of [regressions].
  const failOn = new Set(o.fail_on);
  const failOnGate = failOn.has("any") && o.exit_policy.regressions_only !== true;
  const failOnRegressions = failOn.has("any") || failOn.has("regressions") || o.exit_policy.regressions_only === true;
  const failOnDrift = failOn.has("drift");
  const needsBaseline = failOn.has("drift") ? "drift" : failOn.has("regressions") || o.exit_policy.regressions_only ? "regressions" : undefined;
  if (needsBaseline && !o.baseline) throw new UsageError(`--fail-on ${needsBaseline} compares with a baseline; add --baseline <report.json>`);
  const baseline = o.baseline ? (() => {
    try {
      return parseBaseline(readText(o.baseline, "the baseline"), `baseline ${o.baseline}`);
    } catch (e) {
      throw e instanceof ConfigError ? e : new ConfigError((e as Error).message);
    }
  })() : undefined;
  // Colors only where they will be seen as colors: a terminal or a CI log. NO_COLOR always wins.
  const color = !process.env.NO_COLOR && Boolean(process.stdout.isTTY || process.env.FORCE_COLOR || inCi(process.env));
  const ropts: RenderOptions = { redact: o.redact, secrets: secretLiterals(cfg), verbosity: o.verbosity, color, ...(o.exit_policy.fail_under ? { gate: o.exit_policy.fail_under } : {}), treatInconclusiveAs: o.exit_policy.treat_inconclusive_as, ...(template ? { template } : {}) };
  if (o.redact) scrubLine = makeSecretScrubber(ropts.secrets);
  if (cfg.profile === "ci" && !values.profile && inCi(process.env) && (cfg.origins["/profile"]?.layer ?? "default") === "default") logErr("CI detected: using the ci profile (a readable summary here, JUnit and JSON files in ./sealmark-report/). Use --profile standard to turn this off.");

  // ---- the runs ----
  const multi = cfg.servers.length > 1;
  const sealmarkVersion = cliVersion();
  const runs: AnyRun[] = [];
  const stderrBase = outDir ? join(outDir, "sealmark-report") : o.out ? resolve(o.out) : undefined;
  const stderrLog = (name: string) => `${stderrBase}${multi ? `.${safeName(name)}` : ""}.stderr.log`;
  // A server's stderr from an earlier failed run must not sit next to this run's (maybe green) report and be uploaded with it.
  if (stderrBase) for (const s of cfg.servers) rmSync(stderrLog(s.name), { force: true });
  for (const s of cfg.servers) {
    if (multi) log(`== server ${s.name} ==`);
    const eff: EffectiveConfig = { ...cfg, name: s.name, server: s.spec, servers: [s] };
    try {
      runs.push(
        await runHarness({
          config: toSealmarkConfig(eff),
          effective: eff,
          packs: cfg.packs as PackId[],
          packsExplicit: cfg.packsExplicit,
          pg: cfg.db.pg ?? undefined,
          embedded: cfg.db.embedded ?? undefined,
          yes: cfg.yes,
          active: cfg.active,
          timeoutProbeSec: cfg.timeoutProbeSec,
          log,
        }),
      );
    } catch (e) {
      // A config problem keeps its exit 2; anything else that is not a HarnessError is this server's failure, not everyone's.
      if (e instanceof ConfigError || e instanceof UsageError) throw e;
      // A launch that died can have printed its own settings (tokens included) before exiting: scrub every place it lands.
      const scrub = o.redact ? makeSecretScrubber(ropts.secrets) : (t: string) => t;
      const harness = e instanceof HarnessError ? e : undefined;
      const message = scrub(harness ? harness.message : `unexpected error: ${e instanceof Error ? e.message : String(e)}`);
      const hint = harness?.hint ? scrub(harness.hint) : undefined;
      logSafe(`sealmark: harness failure${multi ? ` (server ${s.name})` : ""}: ${message}`);
      if (hint) logSafe(`hint: ${hint}`);
      let stderrFile: string | undefined;
      if (harness?.stderr && stderrBase) {
        stderrFile = stderrLog(s.name);
        try {
          // A file, not a screen: the server's stderr is kept byte for byte (secrets scrubbed) so it can be read with a viewer of your choice.
          writeOut(stderrFile, scrub(harness.stderr));
          logErr(`server stderr saved to ${stderrFile}`);
        } catch (we) {
          logErr(`warning: could not write ${stderrFile}: ${(we as Error).message}`);
          stderrFile = undefined;
        }
      }
      const failed: FailedRun = {
        status: "failed",
        server: s.name,
        error: message,
        ...(hint ? { hint } : {}),
        ...(stderrFile ? { stderrFile } : {}),
        sealmark: { version: sealmarkVersion, methodology: cfg.integrity.methodology },
      };
      runs.push(failed);
    }
  }

  // ---- report ----
  let stdout: string | undefined;
  const writeFailures: string[] = [];
  for (const f of formats) {
    const dest = f === "summary" && toConsole ? undefined : destination(f);
    // Colors belong on the console; a summary written to a file stays plain text.
    const body = renderReport(f, runs, f === "summary" && dest ? { ...ropts, color: false } : ropts);
    if (dest) {
      try {
        writeOut(dest, body);
        logErr(`report written to ${dest}`);
      } catch (e) {
        // The run is not thrown away: the report goes to stdout instead, and the exit code says the file is missing.
        writeFailures.push(`could not write the report to ${dest}: ${fsReason(e)}; it is printed on stdout instead`);
        stdout = (stdout ?? "") + (body.endsWith("\n") ? body : `${body}\n`);
      }
    } else stdout = (stdout ?? "") + (body.endsWith("\n") ? body : `${body}\n`);
  }
  const done = runs.filter((r): r is RunResult => !isFailed(r));
  const summaryOnStdout = toConsole || (toStdout && (formats[0] === "text" || formats[0] === "summary"));
  if (!summaryOnStdout) {
    // The report is in a file or a machine format (a summary written to a file counts as one): say the grades where a human or a CI log will see them (addendum item 22).
    for (const r of done) logSafe(`${multi ? `${r.server.name}: ` : ""}${summaryLine(r)}`);
    // Configuration warnings were already printed before the run.
    for (const r of done) for (const w of r.warnings ?? []) if (!cfg.warnings.includes(w)) logSafe(`warning: ${w}`);
  }

  // ---- baseline and exit code ----
  let diff: BaselineDiff | undefined;
  if (baseline) {
    diff = compareBaseline(baseline, runs);
    for (const n of diff.notes) logSafe(`baseline: ${n}`);
    if (!quiet) for (const i of diff.improvements) logSafe(`baseline: improved: ${i}`);
    for (const d of diff.drift) logSafe(`drift: ${d.text}`);
    const fails = driftFails(diff.drift).length;
    if (!failOnDrift && fails > 0) logSafe(`note: ${fails} tool-surface change(s) do not affect the exit code; add --fail-on drift to fail on them`);
  }
  const decision = decideExit(runs, {
    failUnder: (o.exit_policy.fail_under ?? undefined) as Letter | undefined,
    treatInconclusiveAs: o.exit_policy.treat_inconclusive_as,
    criticalFail: o.exit_policy.critical_fail,
    failOnGate,
    failOnRegressions,
    failOnDrift,
    regressions: diff?.regressions ?? [],
    drift: diff?.drift ?? [],
    baseline: Boolean(baseline),
  });
  for (const m of decision.messages) logSafe(m);
  let exitCode = decision.code;
  if (o.exit_policy.soft_fail && decision.code === 1) {
    // Only the grade gate is softened; harness errors (2, 3, 4) must still fail the job.
    logErr("soft-fail: the gate (a grade below --fail-under, an inconclusive pack counted as failing, a critical-fail exit code, or a baseline regression) would exit 1; exiting 0 because --soft-fail is set");
    exitCode = 0;
  }

  // ---- write-baseline: a ratchet never moves down on its own ----
  if (o.write_baseline) {
    // The reason comes from the runs, not from the exit code: critical_fail can make the code 3 or 4 on a run that graded fine.
    const hasGrade = (r: RunResult) => Object.values(r.packs).some((pk) => pk?.status === "graded" && pk.grade);
    const why = runs.some(isFailed) ? "a server failed to run" : done.some((r) => !hasGrade(r)) ? "nothing was graded" : diff?.regressions.length ? "the run regressed against the baseline" : undefined;
    if (why) logErr(`baseline not written to ${o.write_baseline}: ${why}`);
    else {
      try {
        writeOut(resolve(o.write_baseline), renderReport("json", runs, ropts));
        logErr(`baseline written to ${resolve(o.write_baseline)}`);
      } catch (e) {
        writeFailures.push(`could not write the baseline to ${resolve(o.write_baseline)}: ${fsReason(e)}`);
      }
    }
  }
  for (const m of writeFailures) logErr(`sealmark: ${m}`);
  if (writeFailures.length && exitCode < 2) exitCode = 2;

  // ---- what the exit code means, in one line (the last thing a CI log shows) ----
  // A signal that landed while the last pack finished: the signal handler sets the exit code, so the line must not say the gate was met.
  if (wasInterrupted()) {
    const code = interruptCode() ?? 130;
    // SIGINT is an interruption (Ctrl-C); a SIGTERM or SIGHUP is a stop, and the signal-handling tests pin that it is never called "interrupted".
    logErr(`sealmark exit ${code}: ${code === 130 ? "interrupted" : "stopped"}`);
    return { code, stdout };
  }
  const softened = exitCode === 0 && decision.code === 1;
  const meaning = writeFailures.length && decision.code < 2 ? "a report or baseline file could not be written" : softened ? `--soft-fail: ${decision.reason} (would exit 1)` : decision.reason;
  if (exitCode !== 0) logErr(`sealmark exit ${exitCode}: ${meaning}`);
  else log(`sealmark exit 0: ${meaning}`);
  return { code: exitCode, stdout };
}

// ---------------------------------------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------------------------------------

async function main(argv: string[]): Promise<CommandOutput> {
  let known: string | undefined;
  try {
    const { values, positionals } = parse(argv);
    if (values.version) return { code: 0, stdout: `sealmark ${cliVersion()}\n` };
    if (values.help) return { code: 0, stdout: USAGE };
    const m = matchCommand(positionals);
    if (!m) {
      const [first, second] = positionals;
      if (first === "config") throw new UsageError(second ? `unknown config command "${second}" (use show, profiles or migrate)` : "config needs a subcommand: show, profiles or migrate");
      if (!first && values.fixture !== undefined) {
        throw new UsageError(`missing command: did you mean sealmark run --fixture ${String(values.fixture)}${values.into !== undefined ? ` --into ${String(values.into)}` : ""}`);
      }
      throw new UsageError(first ? `unknown command "${first}"` : "missing command");
    }
    const { command, rest } = m;
    known = command.name;
    const accepted = new Set(flagsFor(command.name).map((f) => f.name));
    if (command.name === "explain") accepted.add("json");
    for (const [key, v] of Object.entries(values)) {
      if (v !== undefined && !accepted.has(key)) throw new UsageError(`--${key} does not apply to "sealmark ${command.name}"`);
      if (v !== undefined && command.name === "init" && !values.probes && INIT_PROBES_ONLY.has(key)) throw new UsageError(`--${key} applies to "sealmark init" only with --probes (sealmark init --probes ...); without it init writes a config from an MCP client's configuration, --from or --from-url`);
    }
    if (command.name === "init" && values.probes) {
      const clash = (["from", "from-url", "ci", "client", "force"] as const).find((k) => values[k] !== undefined && values[k] !== false);
      if (clash) throw new UsageError(`--probes cannot be combined with --${clash}: --probes reads the server from the configuration (or --url / --start) and writes a probes: block; run the two steps separately`);
    }
    const maxArgs = command.args?.length ?? 0;
    if (rest.length > maxArgs) throw new UsageError(`unexpected argument "${rest[maxArgs]}"`);
    const minArgs = command.args?.filter((a) => a.required).length ?? 0;
    // explain says where to find a check id when it is missing, so only diff is checked here.
    if (command.name === "diff" && rest.length < minArgs) throw new UsageError("diff needs two report files: sealmark diff before.json after.json");

    const cwd = process.cwd();
    switch (command.name) {
      case "init":
        if (values.probes) {
          const cfg = loadEffectiveConfig({ cwd, flags: values, env: process.env });
          for (const w of cfg.warnings) logErr(`warning: ${w}`);
          return await initProbesCommand(cfg, {
            configPath: resolve(values.config ?? "sealmark.yaml"),
            write: Boolean(values.write),
            json: Boolean(values.json),
            startupTimeoutMs: values["connect-timeout"] !== undefined ? cfg.timeouts.connect_ms : undefined,
            log: logSafe,
          });
        }
        if (values.ci !== undefined) {
          if (!(CI_PROVIDERS as readonly string[]).includes(String(values.ci))) throw new UsageError(`--ci: unknown provider "${values.ci}" (use ${CI_PROVIDERS.join(" or ")})`);
          // The job carries the lines the configuration declares (the upstream stub, {bearer}, a scope), so CI does what `sealmark run` does locally.
          // No configuration, or one that does not load, gives the plain job: printing a snippet never fails on the config.
          let declared: CiDeclared = {};
          try {
            const cfg = loadEffectiveConfig({ cwd, flags: values, env: process.env });
            declared = {
              upstream: cfg.upstream?.kind === "http",
              bearer: /\{bearer(?::[ab])?\}/.test(JSON.stringify(cfg.server.headers ?? {})),
              scopeTools: cfg.scope?.tools ?? [],
              scopeAllow: cfg.scope?.allow ?? [],
              scopeDeny: cfg.scope?.deny ?? [],
            };
          } catch {
            declared = {};
          }
          return { code: 0, stdout: ciSnippet(values.ci as CiProvider, cliVersion(), declared) };
        }
        return await initCommand({
          configPath: resolve(values.config ?? "sealmark.yaml"),
          force: Boolean(values.force),
          from: values.from,
          fromUrl: values["from-url"],
          clients: values.client,
          server: values.server,
          yes: Boolean(values.yes),
          log: logErr,
        });
      case "run":
        return await runCommand(values);
      case "describe":
        return describeCommand();
      case "explain":
        return explainCommand(rest[0], Boolean(values.json));
      case "diff":
        return diffCommand(rest[0], rest[1], { json: Boolean(values.json) });
      case "list-checks":
        return listChecksCommand({ pack: [...((values.pack as string[] | undefined) ?? []), ...((values.suite as string[] | undefined) ?? [])], json: Boolean(values.json) });
      case "config show": {
        const cfg = loadEffectiveConfig({ cwd, flags: values, env: process.env });
        for (const w of cfg.warnings) logErr(`warning: ${w}`);
        return configShow(cfg, { origins: Boolean(values.origins), json: Boolean(values.json) });
      }
      case "config profiles":
        return configProfiles({ cwd, flags: values, env: process.env }, Boolean(values.json));
      case "config migrate":
        return configMigrate(resolve(values.config ?? "sealmark.yaml"), { force: Boolean(values.force) }, logErr);
      case "doctor": {
        const cfg = loadEffectiveConfig({ cwd, flags: values, env: process.env });
        for (const w of cfg.warnings) logErr(`warning: ${w}`);
        // doctor waits 10 s for a server by default so a hung start fails fast; --connect-timeout sets it explicitly.
        return await doctorCommand(cfg, { server: values.server, json: Boolean(values.json), startupTimeoutMs: values["connect-timeout"] !== undefined ? cfg.timeouts.connect_ms : undefined, log: logSafe });
      }
      default:
        throw new UsageError(`unknown command "${command.name}"`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`sealmark: ${e.message}\n${usageHint(known, e.message)}\n`);
      return { code: 2 };
    }
    if (e instanceof ConfigError) {
      process.stderr.write(`sealmark: ${e.message}\n`);
      return { code: 2 };
    }
    if (e instanceof HarnessError) {
      process.stderr.write(`sealmark: harness failure: ${e.message}\n`);
      if (e.hint) process.stderr.write(`hint: ${e.hint}\n`);
      return { code: 4 };
    }
    process.stderr.write(`sealmark: unexpected error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
    return { code: 4 };
  }
}

const { code, stdout } = await main(process.argv.slice(2));
// Exit once stdout has flushed so a piped report is never truncated, and stray child handles cannot keep us alive.
if (stdout) process.stdout.write(stdout, () => process.exit(code));
else process.exit(code);
