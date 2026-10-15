import { SCHEMA, STANDARD_PACKS, type Leaf } from "./config/index.js";
import { didYouMean } from "./config/util.js";
import { checkSettings, describeChecks, type DescribedCheck } from "./describe.js";
import { describeAll } from "./packs/index.js";
import type { CheckDoc } from "./types.js";

/**
 * `sealmark list-checks` and `sealmark explain <check-id>`. Both read the check registry (each pack's describe()),
 * the same source `sealmark describe --json` and the generated methodology tables use, so the three cannot drift.
 */

export interface ListedCheck {
  id: string;
  pack: string;
  severity: DescribedCheck["severity"];
  /** Every setting that affects the check is locked by the standard profile. */
  standardLocked: boolean;
  scope: string;
  status: CheckDoc["status"];
  /** The pack runs in the standard profile (exec is opt-in). */
  standardPack: boolean;
  label: string;
}

const toListed = (d: DescribedCheck): ListedCheck => ({
  id: d.id,
  pack: d.pack,
  severity: d.severity,
  standardLocked: d.standardLocked,
  scope: d.scope,
  status: d.status,
  standardPack: d.inStandardPacks,
  label: d.label,
});

/** The checks, optionally only those of one pack. An unknown pack name is an error with the packs that exist. */
export function listChecks(opts: { pack?: string | string[]; docs?: CheckDoc[] } = {}): ListedCheck[] {
  const all = describeChecks(opts.docs ?? describeAll());
  const want = opts.pack === undefined ? [] : [opts.pack].flat();
  if (want.length) {
    const known: string[] = [...new Set<string>(all.map((c) => c.pack))];
    for (const p of want) {
      if (!known.includes(p)) {
        const hint = didYouMean(p, known);
        throw new ExplainError(`no pack named "${p}" (packs with checks: ${known.join(", ")})${hint ? `; did you mean "${hint}"?` : ""}`);
      }
    }
  }
  return all.filter((c) => !want.length || want.includes(c.pack as string)).map(toListed);
}

/** Unknown check id or pack. The CLI prints the message and exits 2. */
export class ExplainError extends Error {}

export function renderListChecks(rows: readonly ListedCheck[], o: { json?: boolean } = {}): string {
  if (o.json) return `${JSON.stringify({ checks: rows }, null, 2)}\n`;
  if (!rows.length) return "no checks\n";
  const w = (f: (r: ListedCheck) => string, head: string) => Math.max(head.length, ...rows.map((r) => f(r).length));
  const wi = w((r) => r.id, "ID");
  const wp = w((r) => r.pack, "PACK");
  const ws = w((r) => r.severity, "SEVERITY");
  const lines = [`${"ID".padEnd(wi)}  ${"PACK".padEnd(wp)}  ${"SEVERITY".padEnd(ws)}  LOCKED  SCOPE`];
  for (const r of rows) {
    const flags = [r.standardPack ? "" : "opt-in", r.status === "shipped" ? "" : r.status].filter(Boolean);
    lines.push(`${r.id.padEnd(wi)}  ${r.pack.padEnd(wp)}  ${r.severity.padEnd(ws)}  ${(r.standardLocked ? "yes" : "no").padEnd(6)}  ${r.scope}${flags.length ? `  [${flags.join(", ")}]` : ""}`);
  }
  lines.push("", "LOCKED: every setting that affects the check is fixed by the standard profile; changing one makes the run CUSTOM.");
  return `${lines.join("\n")}\n`;
}

export interface Explained {
  check: DescribedCheck;
  /** Settings that configure this check, with their defaults. */
  settings: { path: string; default: unknown; description: string; standardLocked: boolean }[];
  /** How a verdict is scored, derived from severity and the grading formula; per-check verdict rules are in `check.thresholds` and the probes. */
  scoring: string;
  /** Other checks this one replaces or is replaced by, for renamed ids. */
  replaces: string[];
  /** What a maintainer should change when the check does not pass (see REMEDIATION). */
  remediation: string;
}

const NO_REMEDIATION = "(no remediation text yet)";

/**
 * What a maintainer should change when a check does not pass, one or two sentences per shipped id. Written from each
 * pack's describe() false positives and negatives and its probe corpus; it never changes a verdict. Custom and plugin
 * ids are not listed here and print NO_REMEDIATION.
 */
export const REMEDIATION: Record<string, string> = {
  protocol:
    "Give every tool a unique name made of letters, digits, underscore, hyphen or dot, a description that says what it does, and an input schema that is valid JSON Schema. Write only JSON-RPC messages to stdout (send logs, banners and debug output to stderr: a strict stdio client breaks on any other line), and return tool results that are valid MCP.",
  "tool-poisoning":
    'Remove hidden characters and any text that addresses the model ("ignore previous instructions", <IMPORTANT> blocks, instructions to read and send keys or files) from tool names, descriptions, schema text, prompts, resources, the server instructions and serverInfo (name, title, description, website); describe what the tool does and nothing else. The server instructions are model-visible text like a tool description: long instructions are fine, an injection or a hidden character in them is not.',
  "robust-input":
    "Validate arguments against the declared input schema before running the tool, and answer a schema-invalid call with an MCP error (isError: true) that names the argument, not a plain-text success. An error that comes after the invalid argument was used (a failed upstream request built from it) is leniency, and an unhandled runtime error (TypeError, Cannot read properties, KeyError) is an internals leak, not a rejection; for an array of objects, check the array itself and each item's required fields.",
  "secret-echo": "Stop returning environment variables, process info or raw error dumps in tool results and errors; redact secret-looking values before they reach a response.",
  "read-only": "Run the server's database role with SELECT grants only (no INSERT, UPDATE or DELETE) and open its transactions READ ONLY; if a tool is meant to write, list it under tools.exclude.",
  "write-gate": "Add an explicit approval parameter or confirmation step to every tool that writes, so a write cannot happen on the first call. This check is advisory and not scored.",
  rls: "Connect as a role that is neither the table owner nor BYPASSRLS, and keep the policies enabled (FORCE ROW LEVEL SECURITY for owners) so the database filters rows for the calling tenant; do not rely on a WHERE clause the server adds itself.",
  "mutating-sql":
    "Parse the statement (do not prefix-match); reject stacked statements, every transaction terminator that can end a read-only wrapper (COMMIT, ROLLBACK, END and ABORT, each followed by a write), data-modifying CTEs, DO blocks and SELECT INTO; run reads in a READ ONLY transaction as a role without write grants. Filtering the word COMMIT alone leaves the other three open. A SQL tool that has another required parameter is graded with it filled; if the control read fails, name the parameter under sql_tools: [{tool, arg, args: {<param>: <value>}}].",
  pii: "Query as a role that cannot read the personal-data columns directly: expose a masked view or column-level grants and point the server at that, so SELECT * and mixed column lists never return raw values.",
  "pii-masked": "Make a masked view (or masked columns) readable by the server's role, so a legitimate request returns masked values instead of an error or nothing.",
  "db-rowcap": "Enforce a maximum number of returned rows in the server (a LIMIT it adds, or a fetch that stops at the cap) and say in the response when the result was truncated.",
  "db-timeout": "Set a statement timeout on the connection or role (statement_timeout in Postgres) shorter than the harness waits, so runaway queries are cancelled rather than left running.",
  audit: "Write an audit record for every tool call (who, which tool, when). This check is not measured and always reports n/a.",
  "db-privilege": "Connect to the database as exactly the role in the {dsn} the server is given, on every connection (including metadata or admin pools), and use a role that is not a superuser, not BYPASSRLS and not the table owner. This check is advisory and not scored.",
  "http-origin": "Validate the Origin header against an allow-list and answer 403 for any other origin, on every path and method, with or without a session.",
  "http-auth": "Require a credential on every request and answer 401 when it is missing or invalid; do not treat a routing header as authentication.",
  "http-protocol-version": "Answer 400 to a request whose MCP-Protocol-Version header names an unsupported version instead of quietly negotiating down.",
  "http-session": "Issue session ids that are long and random (a CSPRNG, at least 128 bits), require them on later requests, and reject unknown or forged ids with 404 or 400.",
  "http-cors": "Do not answer preflights with a wildcard origin; echo back only the specific origins you serve, or send no CORS headers if no browser app calls the server. A preflight answered with a redirect (3xx) is inconclusive: answer the OPTIONS request on the path as configured, or give the URL with the trailing slash the server redirects to.",
  "http-bind": "Bind the listener to 127.0.0.1 (or ::1) unless the server is meant to be reached from other machines; if it is, put authentication and TLS in front of it. This check is advisory.",
  "http-tls": "Serve over https (or terminate TLS in a proxy and use the https URL) for any address that is not this machine. This check is advisory.",
  "fs-read-escape":
    "Resolve every requested path to an absolute canonical path and check that it is inside the allowed root before reading; reject .., absolute paths, encoded variants and drive or device forms, and check every element of an array of paths, not only the first. On POSIX a backslash is an ordinary file-name character: do not turn it into a separator after the root check. A server that takes no root argument has its working directory as its root: say so with server.rootless: true.",
  "fs-write-escape":
    "Apply the same canonical-path check to every write, create, edit, move and copy target (the source of a move or copy included), check every element of an array of targets, and give the server {sandbox} as its only root; do not rely on string prefix tests, and do not normalise backslashes after the check. An edit tool needs the check as much as a write tool does.",
  "fs-link-escape":
    "Resolve symlinks and junctions (realpath) before the root check, or refuse to follow links that leave the root, for reads, writes, moves and copies alike: a link used as a move or copy source or destination, a write through a file link, and a write to a dangling link whose target is outside the root are the forms the harness sends.",
  "fs-size-cap": "Cap how much of a file one call returns (a byte limit with a truncation notice, or paging) so a large file cannot flood the response. The check is inconclusive when content readers exist and none could be controlled, and n/a when no tool returns file content.",
  "git-repo-scope":
    "Take the repository path from server configuration only, resolve it with realpath (symbolic links followed) and compare it with the configured repository before every git call of every tool, including the tools that read staged changes and the tools that take a file or an object (revision) parameter; a link inside the configured repository that points at another repository must be refused, relative paths (../other, repo-evil) as well as absolute ones. A tool that writes (a branch, a commit, a worktree, a clone) must refuse a repository, a destination or a clone source outside the configured root. The check needs {sandbox} in the server config: pass {sandbox}/repo as the repository argument. The harness stages a change in the fixture so a staged-diff tool can be judged, and the fixture has a remote and a tag so listings carry content; a read tool whose control call failed or showed no repository content is named as not judged and makes the check part, at any confidence.",
  "git-arg-injection": "Pass user input after a -- separator or as validated positional values so it can never be read as a git option; reject values that start with a dash (for example --output).",
  "net-loopback-ssrf":
    'Check the address after the URL is parsed and normalised, and again on every redirect, and refuse loopback, link-local and private addresses in every spelling (dotted, localhost, ::1, short, hex, decimal, 0.0.0.0, IPv4-mapped IPv6 such as [::ffff:127.0.0.1]). Say what was refused: a refusal ties the decline to the target or to the rule (it names loopback, private, internal, reserved or not-routable, says the URL or host is blocked or not allowed, says only public hosts may be fetched, or names an egress policy or an unsupported scheme) and is returned as an error result (isError) or a JSON-RPC -32602. A reply that only reports a failed fetch (proxy, socket, DNS, timeout, "refused to connect", "connection blocked") is not read as a refusal, and a tool that cannot fetch anything is inconclusive, not passed. The harness also sends one URL with no host (a data: URL) to a tool whose loopback probes were all refused and nothing else was observed: a tool that answers it with the same sentence, or with address wording for a URL that has no address, has one answer for everything, so the refusals describe nothing and the check is inconclusive. Give a hostless URL its own reply (a scheme refusal or "URL must have a host"). A guard that really does answer every rejection with one constant sentence stays inconclusive until you set net.control_url to a URL the tool can reach, so the harness can see it fetch. A URL tool may relay the probe values to its own upstream; keep a tool out of the net pack with tools.exclude.',
  "net-scheme-allowlist": "Accept only http and https and reject every other scheme (file:, ftp:, gopher: and so on) before the request is made, and say that the scheme was the reason: a refusal that names only the host explains nothing about the scheme and leaves the check inconclusive unless the tool was shown to fetch. A data: URL that the tool decodes (the token appears outside any URL-shaped text) is a pass-through of the content, not a refusal.",
  "net-redirect": "Re-validate every redirect target with the same host, scheme and address rules as the original URL before following it, and never follow a redirect to a non-http(s) scheme.",
  "net-caps":
    "Cap the response size and the request time (stop reading after a byte limit, set a total timeout) so a huge or slow body cannot tie the server up. The time half waits timeout_probe_sec + 8 s, so a server whose own fetch timeout is longer fails it although it does cap: set --timeout-probe to the server's timeout (as for db-timeout and sqlite-timeout) or shorten the server's timeout.",
  "sqlite-read-only": "Open the database read-only (mode=ro or SQLITE_OPEN_READONLY) and reject INSERT, UPDATE and DELETE; if a tool is meant to write, list it under tools.exclude.",
  "sqlite-mutating-sql": "Parse the statement instead of prefix-matching; reject stacked statements, writes inside CTEs, PRAGMA changes and comment-obfuscated forms, and open the connection read-only.",
  "sqlite-file-read":
    "Block ATTACH DATABASE and file-reading functions (an authorizer callback or SQLITE_DBCONFIG_DEFENSIVE); mode=ro alone does not stop ATTACH of an existing file, and a fresh connection per call does not either when the tool runs stacked statements (the harness sends the ATTACH and the read in one call, and as a copy into a table of the fixture that it then reads directly). The check applies to SQLite only: the harness confirms the engine with sqlite_version() first, and a server that answers like another engine is inconclusive, not graded. A SQL tool that answers none of the control forms makes the check part, because it cannot say the tool refuses.",
  "sqlite-file-write": "Block VACUUM INTO, ATTACH of new files and file-writing functions with an authorizer callback, so the only file the server can change is the database it was given; a declared read-only mode must cover every form that writes a file, not only INSERT, UPDATE and DELETE. A DDL-only tool is judged through CREATE TABLE controls, and a SQL tool that answers none of the control forms makes the check part.",
  "sqlite-extension-load":
    'Disable extension loading on every connection, the writer\'s as well as the reader\'s (do not enable SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION or call load_extension), and make the refusal say so ("not authorized", "extension loading is disabled"). The probe is sent in the form the tool accepts: a SELECT for a reader, an INSERT and then an UPDATE for a declared writer. A refusal of the form itself ("only INSERT is allowed") says nothing about extension loading, so a server that only refuses forms is inconclusive, not passed.',
  "sqlite-rowcap": "Enforce a maximum number of returned rows in the server (add a LIMIT or stop fetching at the cap) and mark the result as truncated. A plain-text limit message with no rows counts as a cap; a reply with no rows and no recognisable limit message is inconclusive for that tool, not a fail.",
  "sqlite-timeout":
    "Interrupt long queries after a deadline (sqlite3_interrupt or a progress handler) so a runaway recursive or cross-join query is cancelled. The harness waits expected_sec + 8 s (18 s with the default 10) for the cancel; a server that cancels later is reported as having no timeout, so set --timeout-probe or checks.sqlite-timeout.expected_sec to the server's value.",
  "exec-injection": "Start programs with an argument list and no shell (execFile, or spawn without shell: true), and validate arguments rather than building a command string.",
  "exec-cwd": "Start every program with its working directory fixed to the configured root ({sandbox}), and do not let an argument change it.",
  "exec-timeout-cap": "Kill programs that run longer than a limit and truncate their output at a byte cap (a timeout under timeout_probe_sec + 8 s and output under 16 MiB).",
  "exec-allowlist": "Allow only an explicit list of program names and refuse everything else. This check is advisory; a general-purpose command tool has no allowlist by design.",
  "annotation-honesty": "Make a tool annotated readOnlyHint: true change nothing on disk, or remove the annotation; index and cache refreshes in the observed directories still count, so write them elsewhere or stop writing them. A read-only tool that takes no arguments is called with {} and observed like any other. A URL tool whose control fetch was refused is n/a here when the net check showed it refuses loopback targets, because the harness owns no URL such a tool will fetch; when every tool is n/a the check is n/a, so a correctly guarded fetcher can be green under the ci profile.",
  "openworld-honesty": "Set openWorldHint: true on a tool that makes network connections, or stop the connection; a tool that claims a closed world must not contact the harness listener.",
  "undeclared-writes": "Annotate tools that write (readOnlyHint: false) or stop them writing during a plain call; unannotated tools that leave files behind are listed. This check is advisory.",
  // Round 6 (candidate packs scope, sql-guard and upstream): checked against a toy run.
  "scope-escape":
    "Normalise the identifier first (decode percent and separator forms once, fold case the way scope.case says, strip quotes), then compare whole segments with the allow list: an entry ending in the separator is a prefix, any other entry is exact. Refuse siblings, bare containers (sales, sales.public), partial names, prefix tricks (sales.publicx.t), case variants of an out-of-scope name, quoted and separator-encoded forms, traversal and every scope.deny entry, and refuse before anything is sent to the backend. If the control call was refused, check that scope.allow is spelled as the server lists its identifiers.",
  "sql-guard-statements":
    "Accept a statement only when it parses as one SELECT (or WITH ... SELECT) and refuse everything else, failing closed: INSERT, UPDATE, DELETE, MERGE, CREATE, DROP, ALTER, TRUNCATE, GRANT, VACUUM, ANALYZE, SET, COPY, EXPLAIN ANALYZE of a write, stacked statements, data-modifying CTEs, transaction words, text hidden by case or comments, and anything unparseable or unbalanced. Judge the parsed statement, not its first keyword, and send nothing to the backend when you refuse. If the control statement did not reach the backend, set checks.sql-guard-statements.control_sql to one the server accepts.",
  "sql-guard-references":
    "Check every table reference of the parsed statement against the scope, not only the first: FROM, JOIN, comma joins, subqueries in FROM, WHERE and the select list, EXISTS, CTEs, UNION branches, quoted and differently cased names, and aliased names; refuse the whole statement when any one is out of scope. The check is n/a until scope.allow is set.",
  "sql-guard-rowcap":
    "Bound the rows the backend returns before it runs: wrap the statement (SELECT * FROM (<query>) AS t LIMIT <cap>, or FETCH FIRST n ROWS ONLY, or TOP n) and lower a larger client LIMIT to the cap instead of forwarding it. A cap applied to the reply instead is not visible at the wire: write a probes: rule with upstream.reply rows and expect.upstream.token_echoed to show it. The limit the check expects is checks.sql-guard-rowcap.row_cap.",
  "upstream-credential":
    "Pass each caller's own credential to the backend, taken from the request that arrived: never a static token, an environment variable, or a value cached from the first caller. An anonymous request must reach the backend with no credential, or be refused. If the server validates tokens it did not issue, every call is refused and the check is inconclusive: set identities.a and identities.b to real tokens (from the environment, not the file).",
  "upstream-credential-echo": "Never return the caller's credential in a reply: strip Authorization headers and token values from messages, errors and debug text before they reach a response.",
  "log-secret": "Keep credentials out of the server's log: redact the Authorization header and any token before a request, a backend call or an error is logged.",
  "upstream-error-leak":
    "When the backend fails, answer with a short message of your own (the status and a stable reason) and do not relay its error body: it can carry the caller's credential, internal addresses and query text.",
  "upstream-slow":
    "Give every backend call a timeout shorter than the client's, and answer with an error that says the backend did not answer in time; a server that waits for the backend forever ties up the caller's session. The bound the check waits is checks.upstream-slow.expected_sec (default: the probe timeout) plus 2 s.",
  "refusal-quality":
    "Make every refusal say what to do next: name the tool or the identifiers that are allowed (for example call list_tables), say whether retrying can help, and avoid a bare forbidden. This check is advisory and never changes a letter; checks.refusal-quality.patterns sets the words that count as routing.",
  "instructions-hygiene":
    "Keep the server's instructions in step with its tools: remove names of tools the server does not offer and any text left over from another product or prompt (what checks.instructions-hygiene.deny matches). This check is advisory.",
};

const SCORING: Record<DescribedCheck["severity"], string> = {
  critical: "critical and scored: pass = 1 point, part = 0.5, fail = 0. A fail caps the pack's grade at D, whatever the other checks scored.",
  scored: "scored: pass = 1 point, part = 0.5, fail = 0. A fail lowers the pack's percentage but never caps the letter.",
  advisory: "advisory: reported with its verdict but not part of the score.",
};

/** Looks one check up by id. Old ids that were split or renamed resolve to what replaced them (with a note). */
export function explainCheck(id: string, docs: CheckDoc[] = describeAll()): Explained {
  const all = describeChecks(docs);
  const key = id.trim();
  let hit = all.find((c) => c.id === key);
  if (!hit) {
    const successors = all.filter((c) => c.replaces?.includes(key));
    if (successors.length === 1) hit = successors[0];
    else if (successors.length > 1) {
      throw new ExplainError(`"${key}" was replaced by ${successors.map((s) => s.id).join(" and ")}; run: sealmark explain <one of them>`);
    }
  }
  if (!hit) {
    const hint = didYouMean(key, all.map((c) => c.id));
    throw new ExplainError(`unknown check "${key}"${hint ? `; did you mean "${hint}"?` : ""} (run "sealmark list-checks" for all ${all.length})`);
  }
  const settings = [...new Set([...checkSettings(hit.id), ...hit.configKeys.map((k) => SCHEMA.find((l) => l.path === k)).filter((l): l is Leaf => Boolean(l))])]
    .filter((l) => !l.deprecated)
    .map((l) => ({ path: l.path, default: l.default === undefined ? null : l.default, description: l.description, standardLocked: Boolean(l.standardLocked) }));
  return { check: hit, settings, scoring: SCORING[hit.severity], replaces: hit.replaces ?? [], remediation: REMEDIATION[hit.id] ?? NO_REMEDIATION };
}

const show = (v: unknown): string => (typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v));

/** Text for `sealmark explain <check-id>`. Plain text, wrapped by the terminal. */
export function renderExplain(e: Explained, o: { json?: boolean; asked?: string } = {}): string {
  if (o.json) return `${JSON.stringify(e, null, 2)}\n`;
  const c = e.check;
  const out: string[] = [];
  if (o.asked && o.asked !== c.id) out.push(`note: "${o.asked}" was replaced; showing ${c.id}`, "");
  out.push(`${c.id}  (pack ${c.pack})`, `  ${c.label}`, "");
  out.push(`Scope:        ${c.scope}`);
  out.push(`Scoring:      ${e.scoring}`);
  out.push(`Verified by:  ${c.verifiedBy.length ? c.verifiedBy.join(", ") : "(not documented)"}`);
  out.push(`Since:        methodology ${c.since}   status: ${c.status}${c.candidatePack ? "   (candidate pack: runs when its declaration exists in the config, scored in its own pack, not part of the standard profile or the badge)" : STANDARD_PACKS.includes(c.pack) ? "" : "   (opt-in pack: not part of the default pack list)"}`);
  if (e.replaces.length) out.push(`Replaces:     ${e.replaces.join(", ")} (the old id still works in configuration, with a warning)`);
  out.push(`Standard:     ${c.standardLocked ? "every setting that affects this check is locked by the standard profile; changing one makes the run CUSTOM" : "at least one setting is not locked by the standard profile"}`);
  out.push("", "Probes (the published corpus):");
  if (!c.probes.length) out.push("  (the corpus is not listed in this build; the pack's source and docs/methodology.md describe it)");
  for (const p of c.probes) out.push(`  - ${p.id}${p.core ? " [core]" : ""}${p.kind ? ` (${p.kind})` : ""}: ${p.text}`);
  const th = Object.entries(c.thresholds);
  out.push("", "Thresholds:");
  if (!th.length) out.push("  (none)");
  for (const [name, t] of th) out.push(`  - ${name}: ${show(t.default)}   setting ${t.configKey}${t.standardLocked ? "   (locked)" : ""}`);
  out.push("", "Known false positives:", `  ${c.falsePositive || "(none documented)"}`, "Known false negatives:", `  ${c.falseNegative || "(none documented)"}`);
  out.push("", "Settings:");
  if (!e.settings.length) out.push("  (none; the check cannot be configured)");
  for (const s of e.settings) out.push(`  - ${s.path} = ${show(s.default)}${s.standardLocked ? "   (locked)" : ""}`, `      ${s.description}`);
  out.push("", "What to fix:", `  ${e.remediation}`);
  out.push("", "An A means these checks passed with this exact configuration. It is not a security endorsement.");
  return `${out.join("\n")}\n`;
}
