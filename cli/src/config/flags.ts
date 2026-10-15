import { newLayer, type Layer } from "./layers.js";
import { findLeaf } from "./schema.js";
import { getIn, isPlainObject, pointer, setIn } from "./util.js";
import { validateLeaf, type VCtx } from "./loader.js";
import { coerceText } from "./validators.js";
import { splitCommandLine } from "./wizard.js";

export interface FlagDef {
  /** Long option name without dashes, as util.parseArgs reports it. */
  name: string;
  /** Schema path the flag sets. Absent for meta flags (--config). */
  path?: string;
  /** "pairs" is a repeatable `Name: value` flag that builds a map; "command" is one command line that becomes server.command + server.args. */
  kind: "string" | "boolean" | "list" | "pairs" | "command";
  /** Boolean flag with a --no-<name> form (use parseArgs allowNegative). */
  negatable?: boolean;
  /** Turns the raw value into the schema value (seconds to milliseconds, upper-casing a letter). */
  transform?: (raw: string) => unknown;
  /** A boolean flag that sets its path to this value instead of `true` (`--upstream` sets `upstream.kind` to "http"). */
  set?: unknown;
  /**
   * A "list" flag whose every item is a structured entry: turns one raw item into the entry, or returns a string starting with "!" that
   * is the error to report (`--scope-tool describe_table=table`). Items are not split at commas.
   */
  item?: (raw: string) => unknown;
  description: string;
}

const seconds = (raw: string): unknown => {
  const n = Number(raw.trim());
  return raw.trim() !== "" && Number.isFinite(n) ? Math.round(n * 1000) : raw;
};

/** RFC 7230 token: what an HTTP header name may be made of. */
export const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * The shell syntax Sealmark does not run: `--start` is split into words and started directly. Returns the first
 * unquoted word that is a shell operator, or undefined. Quoted words (`"sh -c 'a && b'"`, `';'`) are arguments, not syntax.
 */
export function shellSyntaxIn(line: string): string | undefined {
  const words: { text: string; quoted: boolean }[] = [];
  let cur = "";
  let quoted = false;
  let started = false;
  let quote: string | undefined;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = undefined;
      else if (quote === '"' && c === "\\" && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      started = quoted = true;
    } else if (/\s/.test(c)) {
      if (started || cur) words.push({ text: cur, quoted });
      cur = "";
      started = quoted = false;
    } else cur += c;
  }
  if (started || cur) words.push({ text: cur, quoted });
  const operator = /^(?:\d?>>?(?:&\d?)?|<|\|\|?|&&?|;)/; // a word that starts with one: `>log`, `|cat`, `&&`, `2>&1`
  const embedded = /&&|\|\||;$/; // `x&&y`, `cd;`
  for (const w of words) if (!w.quoted && (operator.test(w.text) || embedded.test(w.text))) return w.text;
  return undefined;
}

/** `--scope-tool tool=param` as a `scope.tools` entry. */
const scopeToolItem = (raw: string): unknown => {
  const at = raw.indexOf("=");
  const tool = at > 0 ? raw.slice(0, at).trim() : "";
  const param = at > 0 ? raw.slice(at + 1).trim() : "";
  return tool && param ? { tool, param } : `!expected tool=param (for example describe_table=table), got "${raw}"`;
};

/** Every flag that maps 1:1 onto a schema path. cli.ts builds its parseArgs options from this table. */
export const FLAG_DEFS: readonly FlagDef[] = [
  { name: "config", kind: "string", description: "Project config file (default sealmark.yaml)." },
  { name: "profile", path: "profile", kind: "string", description: "Profile to start from." },
  // The server under test, from the command line: no config file needed.
  { name: "url", path: "server.url", kind: "string", description: "URL of the MCP server to test (Streamable HTTP). With --start, Sealmark starts the server and waits for this URL to answer." },
  { name: "start", path: "server.command", kind: "command", description: "Command line that starts the server, for example --start \"my-server --port 8000\". With --url it is launched, awaited, tested and stopped; alone it is a stdio server. It is not run through a shell: no &&, |, ;, > or & and no VAR=value prefix (wrap it: --start \"sh -c '...'\")." },
  { name: "header", path: "server.headers", kind: "pairs", description: "HTTP header for --url as \"Name: value\"; repeat for several. Put a CI secret in single quotes, --header 'Authorization: Bearer ${MCP_TOKEN}', and Sealmark reads it from the environment, so it never shows in the process list." },
  { name: "bearer", path: "server.headers", kind: "string", transform: (raw) => ({ Authorization: `Bearer ${raw.trim()}` }), description: "Bearer token for --url: sets the header Authorization: Bearer <token>. Put a CI secret in single quotes, --bearer '${MCP_TOKEN}', and Sealmark reads it from the environment. Easier than --header in a CI file, because \"Authorization: Bearer x\" contains \": \" and breaks a plain YAML value." },
  { name: "start-timeout", path: "server.start_timeout_sec", kind: "string", description: "Seconds to wait for --start's server to answer on --url (default 60)." },
  { name: "name", path: "name", kind: "string", description: "Display name of the server in the report." },
  { name: "soft-fail", path: "output.exit_policy.soft_fail", kind: "boolean", description: "A grade below the gate prints a warning and exits 0. Config errors, nothing graded and server failures still fail." },
  { name: "pack", path: "packs", kind: "list", description: "Test suite (pack) to run; repeat for several. --suite is the same flag." },
  { name: "suite", path: "packs", kind: "list", description: "Test suite to run; repeat for several. Same as --pack." },
  { name: "timeout-probe", path: "timeout_probe_sec", kind: "string", description: "Seconds the cap and timeout probes wait." },
  { name: "connect-timeout", path: "timeouts.connect_ms", kind: "string", transform: seconds, description: "Seconds to wait for the server to start." },
  { name: "fail-under", path: "output.exit_policy.fail_under", kind: "string", transform: (r) => (/^(none|off)$/i.test(r.trim()) ? null : r.toUpperCase()), description: "Exit 1 when a graded pack is below this letter. Default A: anything below an A fails. Use B, C, D or F to relax it, or none to turn the gate off." },
  { name: "format", path: "output.formats", kind: "list", description: "Report format; repeat the flag or comma-separate for several (text, json, markdown, junit, sarif, summary, badge, shields)." },
  { name: "out", path: "output.out", kind: "string", description: "Write the report to this file." },
  { name: "out-dir", path: "output.out_dir", kind: "string", description: "Directory for multi-format output." },
  { name: "template", path: "output.template", kind: "string", description: "Report template path." },
  { name: "baseline", path: "output.baseline", kind: "string", description: "Prior JSON report to compare against." },
  { name: "write-baseline", path: "output.write_baseline", kind: "string", description: "Write the current JSON report for later --baseline runs." },
  { name: "fail-on", path: "output.fail_on", kind: "list", description: "With a baseline, what decides the exit code: any (the default), regressions or drift; repeat the flag or comma-separate for several." },
  { name: "verbosity", path: "output.verbosity", kind: "string", description: "quiet, normal or verbose." },
  { name: "redact", path: "output.redact", kind: "boolean", negatable: true, description: "--no-redact prints secret-looking values (local debugging only)." },
  { name: "embedded", path: "db.embedded", kind: "boolean", negatable: true, description: "--no-embedded disables the embedded Postgres." },
  { name: "pg", path: "db.pg", kind: "string", description: "Superuser DSN of an existing Postgres (needs --yes)." },
  { name: "yes", path: "yes", kind: "boolean", description: "run: confirm that --pg may recreate the seed database. init: take the defaults and never ask questions." },
  { name: "active", path: "active", kind: "boolean", description: "Allow the exec pack and active custom probes." },
  { name: "sandbox", path: "sandbox.enabled", kind: "boolean", negatable: true, description: "--no-sandbox disables the sandbox (the run becomes CUSTOM)." },
  { name: "sandbox-dir", path: "sandbox.dir", kind: "string", description: "Parent directory for the sandbox." },
  { name: "keep-sandbox", path: "sandbox.keep", kind: "boolean", description: "Keep the sandbox after the run." },
  { name: "pack-timeout", path: "sandbox.pack_timeout_sec", kind: "string", description: "Seconds before one pack is abandoned." },
  // Round 6: the upstream stub, declared scope and caller identities (candidate packs; none of these is locked).
  { name: "upstream", path: "upstream.kind", kind: "boolean", set: "http", description: "Start the harness's upstream stub (upstream.kind: http) and fill {upstream} in the server config with its URL, so the scope, sql-guard and upstream packs can see what the server forwards." },
  { name: "scope-tool", path: "scope.tools", kind: "list", item: scopeToolItem, description: "A tool that takes an identifier the server restricts, as tool=param (for example describe_table=table); repeat for several. Needs --scope-allow." },
  { name: "scope-allow", path: "scope.allow", kind: "list", description: "An identifier the server may serve; an entry ending with the separator is a prefix (sales.public.). Repeat for several." },
  { name: "scope-deny", path: "scope.deny", kind: "list", description: "An identifier the server must refuse even inside the allow list. Repeat for several." },
  { name: "identity-a", path: "identities.a", kind: "string", description: "Token for caller A ({bearer}, {bearer:a}) when the server validates tokens it did not issue. Put a CI secret in single quotes, --identity-a '${TOKEN_A}', and Sealmark reads it from the environment." },
  { name: "identity-b", path: "identities.b", kind: "string", description: "Token for caller B ({bearer:b}); must differ from --identity-a. Single-quote a CI secret as for --identity-a." },
  { name: "server", path: "run.server", kind: "string", description: "Entry of `servers` to use (run also accepts `all`). init: the imported servers to write, as comma separated names, client/name, or all." },
];

/** Options object for util.parseArgs (use with allowNegative: true). `help`, `force` and similar stay in cli.ts. */
export function parseArgsOptions(): Record<string, { type: "string" | "boolean"; multiple?: boolean }> {
  return Object.fromEntries(FLAG_DEFS.map((d) => [d.name, { type: d.kind === "boolean" ? "boolean" : "string", ...(d.kind === "list" || d.kind === "pairs" ? { multiple: true } : {}) } as const]));
}

/** Flag values as util.parseArgs returns them: strings, booleans, string arrays. Both `{ sandbox: false }` and `{ "no-sandbox": true }` mean --no-sandbox. */
export type FlagValues = Record<string, unknown>;

export function flagsToLayer(flags: FlagValues, issues: string[]): Layer {
  const layer = newLayer("flag", "flags");
  for (const def of FLAG_DEFS) {
    if (!def.path) continue;
    let raw = flags[def.name];
    if (def.negatable && flags[`no-${def.name}`] === true) raw = false;
    if (raw === undefined) continue;
    const segs = def.path.split(".");
    const leaf = findLeaf(segs);
    if (!leaf) throw new Error(`flag --${def.name} maps to unknown schema path ${def.path}`);
    const source = def.negatable && raw === false ? `--no-${def.name}` : `--${def.name}`;
    const ctx: VCtx = { kind: "flag", where: () => source, showPath: false, issues, lines: layer.lines };
    if (def.kind === "command") {
      // One command line becomes command + args, the way `init --from` reads it.
      let parts: string[];
      try {
        parts = splitCommandLine(String(raw));
      } catch (e) {
        issues.push(`--${def.name}: ${(e as Error).message}`);
        continue;
      }
      if (!parts.length) {
        issues.push(`--${def.name}: expected a command line, got an empty string`);
        continue;
      }
      const first = parts[0];
      const op = shellSyntaxIn(String(raw));
      if (op !== undefined || /^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) {
        const what = op !== undefined ? `"${op}"` : `the leading ${first.split("=")[0]}=...`;
        issues.push(
          `--${def.name} is not run through a shell, so ${what} would not work as in a shell; wrap it: --${def.name} "sh -c '...'" ` +
            `(to set an environment variable, use env: in sealmark.yaml or --${def.name} "env NAME=value command").`,
        );
        continue;
      }
      const cctx: VCtx = { kind: "flag", where: () => `--${def.name}`, showPath: false, issues, lines: layer.lines };
      for (const [segs, val] of [[["server", "command"], parts[0]], [["server", "args"], parts.slice(1)]] as const) {
        const cleaned = validateLeaf(findLeaf([...segs])!, val, [...segs], cctx);
        if (cleaned === undefined) continue;
        setIn(layer.data, [...segs], cleaned);
        layer.sources.set(pointer([...segs]), `flag --${def.name}`);
      }
      continue;
    }
    let value: unknown;
    if (def.kind === "pairs") {
      const map: Record<string, string> = {};
      for (const item of Array.isArray(raw) ? raw : [raw]) {
        const text = String(item);
        const at = text.indexOf(":");
        if (at <= 0) {
          issues.push(`--${def.name}: expected "Name: value", got "${text}"`);
          continue;
        }
        const hname = text.slice(0, at).trim();
        if (!HEADER_NAME.test(hname)) {
          issues.push(`--${def.name}: "${hname}" is not a valid HTTP header name (letters, digits and - only; no spaces)`);
          continue;
        }
        map[hname] = text.slice(at + 1).trim();
      }
      value = map;
    } else if (def.kind === "boolean") value = raw === true && def.set !== undefined ? def.set : raw;
    else if (def.kind === "list" && def.item) {
      const items: unknown[] = [];
      for (const r of Array.isArray(raw) ? raw : [raw]) {
        const made = def.item(String(r));
        if (typeof made === "string" && made.startsWith("!")) issues.push(`--${def.name}: ${made.slice(1)}`);
        else items.push(made);
      }
      if (!items.length) continue;
      value = items;
    } else if (def.kind === "list") value = (Array.isArray(raw) ? raw : [raw]).flatMap((v) => String(v).split(",")).map((s) => s.trim()).filter(Boolean);
    else {
      if ((def.name === "bearer" || def.name.startsWith("identity-")) && !String(raw).trim()) {
        issues.push(`--${def.name}: expected a token, got an empty string (is the CI variable set?)`);
        continue;
      }
      if (def.name === "bearer" && /^bearer\s/i.test(String(raw).trim())) {
        issues.push('--bearer takes the token only; Sealmark adds "Bearer " itself (use --header "Authorization: ..." for another scheme)');
        continue;
      }
      const text = def.transform ? def.transform(String(raw)) : String(raw);
      value = typeof text === "string" ? coerceText(leaf.shape, text) : text;
    }
    // A nullable setting can be switched off with a flag value that transforms to null (--fail-under none).
    const cleaned = value === null && leaf.nullable ? null : validateLeaf(leaf, value, segs, ctx);
    if (cleaned === undefined) continue;
    // --bearer and --header both fill server.headers: add to what is there instead of replacing it.
    const existing = getIn(layer.data, segs);
    if (def.name === "bearer" && isPlainObject(existing) && isPlainObject(cleaned)) {
      const clash = Object.keys(existing).find((k) => Object.keys(cleaned).some((c) => c.toLowerCase() === k.toLowerCase()));
      if (clash) {
        issues.push(`--bearer and --header ${clash} both set the Authorization header; use one of them`);
        continue;
      }
      setIn(layer.data, segs, { ...existing, ...cleaned });
    } else setIn(layer.data, segs, cleaned);
    if (def.kind === "pairs" || def.name === "bearer") for (const k of Object.keys(cleaned as Record<string, unknown>)) layer.sources.set(pointer([...segs, k]), `flag ${source}`);
    layer.sources.set(pointer(segs), `flag ${source}`);
  }
  return layer;
}
