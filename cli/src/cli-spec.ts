import { FLAG_DEFS } from "./config/flags.js";

/**
 * The command-line surface as data: commands, flags and exit codes. One table, three consumers:
 * cli.ts builds its usage text and its util.parseArgs options from it (`usageText`, `parseArgsSpec`),
 * `sealmark describe --json` publishes it, and the docs are generated from that JSON. A flag that exists
 * in cli.ts but not here is a bug, and a test in describe.test.ts keeps this file honest against FLAG_DEFS.
 *
 * Flags that map 1:1 onto a configuration setting come from config/flags.ts (FLAG_DEFS); this file adds
 * only the meta flags (help, force, json, ...) and says which commands accept which flag.
 */

export interface CliFlag {
  /** Long name without the dashes, as util.parseArgs reports it. */
  name: string;
  type: "string" | "boolean" | "list";
  /** One-letter alias, without the dash. */
  short?: string;
  /** `--no-<name>` is accepted (boolean flags only). */
  negatable?: boolean;
  /** Placeholder for the value in usage text, for example `<sec>`. */
  metavar?: string;
  description: string;
  /** Commands that accept the flag. */
  commands: string[];
  /** Configuration setting the flag sets, when it maps 1:1 onto one (from config/flags.ts). */
  schemaPath?: string;
  /** Safety flag: only the command line can set it, never a file or an environment variable. */
  safety?: boolean;
  /** Designed but not implemented: listed in `describe --json` for the docs, absent from the usage text and rejected by the parser. */
  status?: "planned";
}

export interface CliCommand {
  /** `run`, `init`, `config show`, ... */
  name: string;
  /** One line of usage without the program name: `init [--from "<command>"] ...`. */
  usage: string;
  summary: string;
  /** Positional arguments, for the docs. */
  args?: { name: string; required: boolean; description: string }[];
}

export interface ExitCode {
  code: 0 | 1 | 2 | 3 | 4 | 129 | 130 | 143;
  meaning: string;
}

export const EXIT_CODES: readonly ExitCode[] = [
  { code: 0, meaning: "ok" },
  { code: 1, meaning: "a graded pack is below --fail-under (a provisional A* is below an A gate), an inconclusive pack under output.exit_policy.treat_inconclusive_as: fail, or a baseline comparison found a regression" },
  { code: 2, meaning: "usage or configuration error" },
  { code: 3, meaning: "no pack was graded" },
  { code: 4, meaning: "harness or server failure (the server would not start, the database was unavailable, or doctor found a failing step)" },
];

/**
 * What the shell reports when a signal ends a run (128 + the signal number). Kept apart from EXIT_CODES, which are the codes
 * sealmark decides itself (and the ones the README table lists); --help and `describe --json` print both.
 */
export const SIGNAL_EXIT_CODES: readonly ExitCode[] = [
  { code: 129, meaning: "interrupted by SIGHUP (the terminal closed)" },
  { code: 130, meaning: "interrupted by SIGINT (Ctrl-C)" },
  { code: 143, meaning: "terminated by SIGTERM" },
];

export const CLI_COMMANDS: readonly CliCommand[] = [
  {
    name: "init",
    usage:
      'init [--ci <gitlab|github>] [--from "<command line>" | --from-url <url>] [--client <name>] [--server <name>] [--yes] [--force] [--config <path>] | init --probes [--write] [--json] [--yes] [--url <url>] [--start "<command line>"] [--config <path>]',
    summary:
      "Write sealmark.yaml (and sealmark.local.yaml for secrets) from an MCP client's configuration, a one-line command, or a template. With --probes, start the server like doctor does and write one valid call per tool as a probes: block (never asks a question).",
  },
  {
    name: "run",
    usage: 'run [--url <url>] [--start "<command line>"] [--header "Name: value"]... [--bearer <token>] [--start-timeout <sec>] [--name <name>] [--upstream] [--scope-tool <tool=param>]... [--scope-allow <id>]... [--scope-deny <id>]... [--identity-a <token>] [--identity-b <token>] [--soft-fail] [--config <path>] [--profile <name>] [--pack <id>]... [--server <name|all>] [--fail-under A-F] [--format <fmt>] [--out <file>] [--active] [--no-sandbox] [--replay <report.json>]',
    summary: "Grade the configured server(s) and print the report.",
  },
  {
    name: "doctor",
    usage: 'doctor [--url <url>] [--start "<command line>"] [--header "Name: value"]... [--bearer <token>] [--start-timeout <sec>] [--name <name>] [--upstream] [--scope-tool <tool=param>]... [--scope-allow <id>]... [--scope-deny <id>]... [--identity-a <token>] [--identity-b <token>] [--config <path>] [--profile <name>] [--server <name>] [--json]',
    summary: "Check that sealmark can start your server: tools on PATH, the launcher, the sandbox, initialize and tools/list, the classification and why each pack would run or not.",
  },
  {
    name: "describe",
    usage: "describe --json",
    summary: "Print the machine-readable description of this build: methodology and CLI versions, the check registry, configuration keys, commands, flags and exit codes.",
  },
  {
    name: "explain",
    usage: "explain <check-id> [--json]",
    summary: "Explain one check: what it measures, its probes, verdict rules, known false positives and negatives, the settings that affect it, and what to fix when it fails.",
    args: [{ name: "check-id", required: true, description: "A check id from `sealmark list-checks`." }],
  },
  {
    name: "list-checks",
    usage: "list-checks [--pack <id>] [--json]",
    summary: "List every check with its pack, severity, scope and whether its settings are locked by the standard profile.",
  },
  {
    name: "diff",
    usage: "diff <before.json> <after.json> [--json]",
    summary: "Compare two JSON reports without running anything: verdict regressions and improvements, and tool-surface drift. Exit 1 when something regressed or drifted.",
    args: [
      { name: "before.json", required: true, description: "The earlier JSON report (a --write-baseline file or --format json output)." },
      { name: "after.json", required: true, description: "The later JSON report." },
    ],
  },
  {
    name: "config show",
    usage: 'config show [--origins] [--json] [--config <path>] [--profile <name>] [--url <url>] [--start "<command line>"] [--header "Name: value"]... [--bearer <token>] [--start-timeout <sec>] [--name <name>] [--soft-fail] [--format <fmt>]...',
    summary: "Print the merged configuration, with the origin of every value on request.",
  },
  {
    name: "config profiles",
    usage: "config profiles [--json]",
    summary: "List shipped and user profiles with their difference from the standard profile.",
  },
  {
    name: "config migrate",
    usage: "config migrate [--config <path>]",
    summary: "Rewrite a configuration file from an older schema_version to the current one and print the diff.",
  },
];

const ALL = CLI_COMMANDS.map((c) => c.name);
const TOPIC: Record<string, string[]> = {
  config: ["run", "doctor", "init", "config show", "config migrate"],
  profile: ["run", "doctor", "config show"],
  pack: ["run", "list-checks", "config show"],
  suite: ["run", "list-checks", "config show"],
  server: ["run", "doctor", "init", "config show"],
};

/**
 * Which commands accept each configuration-mapped flag. `config show` takes every one of them: it is how a person
 * inspects the command line they wrote for CI (the `flag` origin is only reachable through it). Flags not listed apply to `run` (and `config show`).
 */
function commandsFor(name: string): string[] {
  if (name in TOPIC) return TOPIC[name];
  // `init --probes` opens the server the way doctor does, so it takes the flags that say which server and how to start it.
  if (["sandbox-dir", "sandbox", "connect-timeout"].includes(name)) return ["run", "doctor", "init", "config show"];
  if (["timeout-probe", "keep-sandbox", "pack-timeout"].includes(name)) return ["run", "doctor", "config show"];
  if (name === "yes") return ["run", "init", "config show"];
  if (["url", "start", "header", "bearer", "start-timeout"].includes(name)) return ["run", "doctor", "init", "config show"];
  if (name === "name") return ["run", "doctor", "init", "config show"];
  // Round 6 (config-report package adds the flags to FLAG_DEFS): they describe the server's setup, so doctor and init --probes read them too.
  if (name === "upstream" || name.startsWith("scope-") || name.startsWith("identity-")) return ["run", "doctor", "init", "config show"];
  return ["run", "config show"];
}

/** Flags `init` accepts only together with --probes (they select and start the server): without it they are a usage error, not silently ignored. */
export const INIT_PROBES_ONLY = new Set(["json", "url", "start", "header", "bearer", "start-timeout", "name", "connect-timeout", "sandbox", "sandbox-dir", "upstream", "write", "scope-tool", "scope-allow", "scope-deny", "identity-a", "identity-b"]);

const META: CliFlag[] = [
  { name: "help", type: "boolean", short: "h", description: "Print usage and exit.", commands: ALL },
  { name: "version", type: "boolean", short: "v", description: "Print the sealmark version and exit.", commands: [] },
  { name: "force", type: "boolean", description: "Overwrite files that already exist.", commands: ["init", "config migrate"] },
  { name: "json", type: "boolean", description: "Machine-readable output.", commands: ["doctor", "describe", "diff", "explain", "list-checks", "config show", "config profiles", "init"] },
  { name: "probes", type: "boolean", description: "init: start the server like doctor does and write one valid call per tool as a probes: block (stdout, or the config file with --write). Never prompts.", commands: ["init"] },
  { name: "write", type: "boolean", description: "init --probes: append the block to the config file; exit 2 when it already has a probes: key.", commands: ["init"] },
  { name: "from", type: "string", metavar: "<command line>", description: 'Write a config from a one-liner, for example --from "npx -y @modelcontextprotocol/server-filesystem {sandbox}".', commands: ["init"] },
  { name: "ci", type: "string", metavar: "<gitlab|github>", description: "Print a ready-to-paste CI job for this provider and write nothing.", commands: ["init"] },
  { name: "from-url", type: "string", metavar: "<url>", description: "Write a config for an already running Streamable HTTP server.", commands: ["init"] },
  { name: "client", type: "list", metavar: "<name>", description: "Only read this MCP client's configuration (claude-desktop, claude-code, cursor, vscode, copilot-cli).", commands: ["init"] },
  { name: "effective", type: "boolean", description: "Accepted for compatibility; config show always prints the effective configuration.", commands: ["config show"] },
  { name: "origins", type: "boolean", description: "Annotate every value with where it came from.", commands: ["config show"] },
  { name: "replay", type: "string", metavar: "<report.json>", description: "Re-run with the locked settings of a previous JSON report, after verifying its config hash.", commands: ["run"] },
  { name: "fixture", type: "string", metavar: "<fs|git|sqlite>", description: "Write a fixture the sandbox generates, for hand runs: the fs layout, the git repositories or the SQLite database (DuckDB is planned).", commands: ["run"] },
  { name: "into", type: "string", metavar: "<dir>", description: "Directory for --fixture.", commands: ["run"] },
];

const SAFETY = new Set(["active", "yes"]);

function metavarFor(name: string): string {
  if (name === "pack" || name === "suite") return "<id>";
  if (name === "url") return "<url>";
  if (name === "start") return "<command line>";
  if (name === "header") return '"Name: value"';
  if (name === "bearer") return "<token>";
  if (name === "start-timeout") return "<sec>";
  if (name === "name") return "<name>";
  if (name === "fail-under") return "<A-F>";
  if (name === "timeout-probe" || name === "connect-timeout" || name === "pack-timeout") return "<sec>";
  if (name === "config" || name === "out" || name === "baseline" || name === "write-baseline" || name === "template") return "<file>";
  if (name === "out-dir" || name === "sandbox-dir") return "<dir>";
  return "<value>";
}

function fromDef(d: (typeof FLAG_DEFS)[number]): CliFlag {
  return {
    name: d.name,
    type: d.kind === "pairs" ? "list" : d.kind === "command" ? "string" : d.kind,
    ...(d.negatable ? { negatable: true } : {}),
    ...(d.kind !== "boolean" ? { metavar: metavarFor(d.name) } : {}),
    description: d.description,
    commands: commandsFor(d.name),
    ...(d.path ? { schemaPath: d.path } : {}),
    ...(SAFETY.has(d.name) ? { safety: true } : {}),
  };
}

export const CLI_FLAGS: readonly CliFlag[] = [...FLAG_DEFS.map(fromDef), ...META];

const COMMAND_NAMES = new Set(ALL);

/** Options for util.parseArgs, built from the table. Use with `allowNegative: true` and `allowPositionals: true`. */
export function parseArgsSpec(): Record<string, { type: "string" | "boolean"; short?: string; multiple?: boolean }> {
  return Object.fromEntries(
    CLI_FLAGS.filter((f) => f.status !== "planned").map((f) => [
      f.name,
      { type: f.type === "boolean" ? ("boolean" as const) : ("string" as const), ...(f.short ? { short: f.short } : {}), ...(f.type === "list" ? { multiple: true } : {}) },
    ]),
  );
}

/** Matches positionals to a command name. `["config", "show"]` is the command `config show`; returns the rest as arguments. */
export function matchCommand(positionals: readonly string[]): { command: CliCommand; rest: string[] } | undefined {
  for (const n of [2, 1]) {
    const name = positionals.slice(0, n).join(" ");
    if (positionals.length >= n && COMMAND_NAMES.has(name)) return { command: CLI_COMMANDS.find((c) => c.name === name)!, rest: positionals.slice(n) };
  }
  return undefined;
}

/** Flags a command accepts, for validating a flag against the command it was given to. */
export function flagsFor(command: string): CliFlag[] {
  return CLI_FLAGS.filter((f) => f.commands.includes(command));
}

/** The usage text, generated from the table. `heading` lets cli.ts keep its own first line. */
export function usageText(heading = "sealmark: behavioral conformance tests for MCP servers"): string {
  const lines = [heading, "", "usage:"];
  for (const c of CLI_COMMANDS) lines.push(`  sealmark ${c.usage}`);
  lines.push("", "flags:");
  for (const f of CLI_FLAGS) {
    if ((f.commands.length === 0 && f.name !== "version") || f.status === "planned") continue;
    const left = `--${f.negatable ? `[no-]` : ""}${f.name}${f.metavar ? ` ${f.metavar}` : ""}${f.short ? `, -${f.short}` : ""}`;
    lines.push(`  ${left.padEnd(34)} ${f.description}`);
  }
  lines.push("", "exit codes:");
  for (const e of [...EXIT_CODES, ...SIGNAL_EXIT_CODES]) lines.push(`  ${e.code}  ${e.meaning}`);
  return `${lines.join("\n")}\n`;
}

/** The part of the table `sealmark describe --json` publishes under `cli`. */
export function cliSpecJson(): { commands: CliCommand[]; flags: CliFlag[]; exitCodes: ExitCode[] } {
  return { commands: CLI_COMMANDS.map((c) => ({ ...c })), flags: CLI_FLAGS.map((f) => ({ ...f, commands: [...f.commands] })), exitCodes: [...EXIT_CODES, ...SIGNAL_EXIT_CODES].map((e) => ({ ...e })) };
}
