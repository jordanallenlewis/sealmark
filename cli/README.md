# sealmark (CLI)

Behavioral conformance tests for MCP servers you run or build. Sealmark starts your server, calls its tools directly with fixed inputs (no LLM in the loop), and reports what happened with evidence for every line. A letter grade summarises each pack.

**Status: methodology 0.3-draft, published on npm as `sealmark`.** Run `npx sealmark`. Checks, thresholds, and the CLI surface can still change before 1.0. Methodology 0.3-draft is not released yet: the standard hash differs from 0.2-draft, so a 0.2-draft report cannot be `--replay`ed and a 0.2-draft baseline prints a "different configuration" note. The per-check definitions are in [`docs/methodology.md`](../docs/methodology.md), which also lists what changed in 0.3-draft; `sealmark list-checks`, `sealmark explain <check-id>` and `sealmark describe --json` print the same registry from the code.

## What it covers, and what it does not

Sealmark runs `core` on any MCP server. Deeper packs run only when the harness can give the server a target it owns: a sandbox directory (`fs`, `git`, `effects`), a loopback listener (`net`), a seeded Postgres (`db`), a seeded SQLite file (`sqlite`), the HTTP endpoint you configured (`http`), or a harness-owned upstream stub the server uses as its backend (`scope`, `sql-guard`, `upstream`, the candidate packs of [Backends, scope and callers](#backends-scope-and-callers)). Tools it cannot classify get `core` checks and are listed as not covered.

The `exec` pack and active custom probes run only with `--active`.

A grade is STANDARD only when the run used the published standard profile unchanged; every other run is labelled custom and its differences are listed.

Out of scope: prompt injection carried in tool output, authentication flows that need real credentials, supply chain and install-time behavior, servers that need valid-looking secrets to do anything, SSRF via link-local or private ranges, redirects from a public host to loopback, DNS rebinding, and anything a malicious server does outside the sandbox convention. Redirects served by the harness's own loopback listener are tested by the scored `net-redirect` check. Prompt arguments are not probed either: Sealmark lists prompts and scans their text, but never calls `prompts/get`.

**An A means these checks passed with this exact configuration. It is not a security endorsement.**

`core` is hygiene only: protocol and schema checks, tool-poisoning indicators in tool metadata, survival of malformed input, and a secret canary. It calls tools only with invalid input, so a `core` A on a server that does little proves little. A core-only result is labelled `hygiene only` in the report and is never badge-eligible.

| Pack | Applies when | What it measures | Needs |
|---|---|---|---|
| `core` | always | handshake and schemas (and whether stdout carries only JSON-RPC), poisoning indicators (including hidden and terminal control characters) in tool, prompt and resource text, the server instructions and `serverInfo`, malformed-input survival, secret echo | nothing |
| `db` | a tool takes SQL and the config has a `{dsn}` placeholder | read-only by default, row-level security, mutating-SQL blocking (a 19-case corpus; the terminators `COMMIT`, `ROLLBACK`, `END` and `ABORT` are each probed), personal-data masking (and that a masked view is readable), row cap, timeout, and three advisory checks: the write approval gate, audit logging (a placeholder) and `db-privilege` (does each instance connect as the role it was given) | embedded Postgres (default) or `--pg` |
| `sqlite` | a tool takes SQL and the config has `{sqlite_path}` (SQLite servers only: the harness confirms the engine with `sqlite_version()`, and a server that answers like another engine is inconclusive, never graded) | the same ideas on an embedded engine, plus attach/vacuum file access (single-call, stacked and copy-into-fixture forms, verified in the fixture file; an `ATTACH` made through a writer is followed through the controlled reader; a SQL tool that cannot be controlled makes the check `part`) and extension loading (a refusal that does not mention extensions is not a denial) | Node 22.13 or newer |
| `fs` | a tool takes a file path (medium confidence or higher), or `server.rootless: true` | reads and writes outside the root (the write corpus mirrors the read corpus: percent-encoded, `file://`, dot-slash and backslash forms, a second array element, move and copy through links, edit tools), link escapes (including a write through a file link and to a dangling link), size cap. A server that answers none of the escape probes is inconclusive, never a pass | sandbox |
| `git` | a tool takes a repository path and the config has `{sandbox}` | repository scope (the fixture has a staged change, a remote, a tag and a link planted in the repository; read tools are aimed at other repositories with absolute and relative paths, write tools are judged by observation, and a read tool that could not be judged makes the check `part`), argument injection | sandbox, `git` on PATH |
| `net` | a tool takes a URL (a `url` parameter on a tool whose primary class is `path` counts) | loopback SSRF (every spelling of 127.0.0.1 in the corpus, IPv4-mapped IPv6 included; a refusal must tie itself to the target or the rule, and a hostless twin probe decides whether refusal text describes the target), scheme allow-list, response caps, and `net-redirect` (scored, not critical; `n/a` unless the server already fetched the listener, `inconclusive` when re-validation cannot be measured) | loopback listener |
| `http` | `server.url` is set | origin validation, authentication, protocol version, sessions, CORS, bind address (advisory; not examined when Sealmark started the server itself with `--start` + `--url`), TLS | an HTTP server |
| `effects` | a tool with annotations (or an unannotated read-style tool) takes a harness-owned target (a path, a repository, a URL or no argument) | whether `readOnlyHint` and `openWorldHint` are honest. It sees writes inside the directories the sandbox owns, not writes elsewhere. `n/a` for a URL tool that refuses loopback targets, because the harness owns no URL such a tool will fetch | sandbox |
| `exec` | a tool runs commands, **and `--active`** | argument injection, working directory, timeout cap (a "killed" reply is confirmed against the process table), allow-list | `--active`, sandbox |
| `scope` (candidate) | `scope.tools` names a tool and `scope.allow` lists what it may serve | `scope-escape`: identifiers outside the scope (siblings, containers, partial names, a prefix without its separator, other case, quoted, encoded separators, traversal, `scope.deny`) are refused and, with a stub, never reach the backend | nothing, or the upstream stub |
| `sql-guard` (candidate) | a SQL tool and `upstream.kind: http` | the statement allowlist (20 forbidden forms: DML, DDL, stacked, DML in a CTE, terminators, case-obfuscated, unparseable...), out-of-scope references in every SQL position, and the row cap as forwarded | the upstream stub |
| `upstream` (candidate) | `upstream.kind: http` and at least one valid call (`probes:` without `check`) | each caller's own token reaches the backend (`{bearer}`), no reply or log line holds a token, upstream error bodies are not relayed with the credential, a slow backend does not hang the server | the upstream stub, `{bearer}` in `server.headers` |
| `custom` | `probes:` with a `check:` in the config. Added to the default pack list for you; a list you chose yourself (`--pack`, or `packs:` in a file) that leaves `custom` out skips it and says so in a warning | your own checks | `--active` for active probes |

Not built: DNS rebinding (the harness owns no DNS), redirects from a public host to loopback (it contacts only its own listener), DuckDB fixtures and grading (`{duckdb_path}` is a placeholder only), and MySQL. A badge service, a Marketplace listing of the GitHub Action and a Claude Code plugin are owner decisions, not code. Output-side prompt injection is not planned (it needs an LLM).

### Candidate checks

A new scored check changes grades, and a grade is a methodology. So a check that is not yet part of the published standard ships as a **candidate**: it runs in every run and is listed in the report, but in a standard pack it is advisory (never scored), and the standard profile and its hash do not contain it. The candidates are `db-privilege` (pack `db`), the two `core` advisories `refusal-quality` (do refusals tell the caller what to do instead?) and `instructions-hygiene` (do the server's instructions name a tool it does not offer, or match `checks.instructions-hygiene.deny`?), and the checks of the three **candidate packs** `scope`, `sql-guard` and `upstream`, which are scored inside their own pack, labelled `candidate pack` in every report and never make a run badge-eligible (`docs/methodology.md`, "Candidate packs"). `db-privilege` asks whether each of the three server instances connected as exactly the database role it was given. It is advisory because every credential comes from the harness, so a server that behaves correctly would otherwise add one near-automatic point to every db grade and move letters up. Switching a candidate off (`checks.db-privilege.enabled: false`) or scoring it (`severity: scored`) makes the run CUSTOM, like any other check. `net-redirect` was the first candidate (0.2.1); methodology 0.3-draft promoted it to a scored, non-critical standard check (decided by recommendation; the owner may veto). Promoting a candidate into the standard is a methodology change: see `docs/methodology.md`, "Candidate checks".

## Quickstart

Requires Node 22.13 or newer. No Docker.

```bash
npx sealmark init            # imports servers from your MCP clients, or writes a template
npx sealmark doctor          # can sealmark start your server? which packs would run?
npx sealmark run
```

`init` looks for MCP servers in Claude Desktop, Claude Code (`~/.claude.json`, `.mcp.json`), Cursor, VS Code and the GitHub Copilot CLI, asks which to grade (with a terminal; `--yes` or no terminal takes the defaults), offers to point directories at `{sandbox}`, files the server reads or writes (a memory or data file named by an absolute path) at `{sandbox}/<name>` so your real file is never touched, a SQLite path at `{sqlite_path}`, and connection strings at `{dsn}` (with `--yes` the offers are accepted), and writes `sealmark.yaml`, a `.gitignore` entry for `sealmark.local.yaml` and, only when some server has a secret or a machine-specific value to put there, `sealmark.local.yaml` itself (`init` never writes it empty). The `yaml-language-server` schema line is written only when `./node_modules/sealmark/schema/sealmark.schema.json` exists under the target directory (`npm i -D sealmark` adds it); otherwise `init` writes a comment that names the local path and the hosted copy (`https://sealmark.dev/schema/v1/sealmark.schema.json`, available after the next site deploy) in its place. It refuses to overwrite an existing file unless you pass `--force`. `init --from "npx -y @modelcontextprotocol/server-filesystem {sandbox}"` writes a config from a one-liner and `init --from-url https://host/mcp` from a URL. `init --ci gitlab|github` prints a ready-to-paste CI job and writes nothing (see [CI](#ci)).

## Commands

| Command | What it does |
|---|---|
| `sealmark init` | write `sealmark.yaml` from a client's configuration, a one-liner, or a template. `init --ci gitlab\|github` prints a CI job instead and writes nothing |
| `sealmark init --probes [--write] [--yes] [--json]` | start the server the way `doctor` does and print a `probes:` block with one valid call per tool (a tool it cannot fill is written commented out with the reason). `--write` appends it to `sealmark.yaml` when the file has no `probes:` key and exits 2 otherwise; `--json` prints `sealmark.probes/1`. The same server and config give the same block |
| `sealmark run` | grade the configured server(s) and print the report |
| `sealmark doctor [--server name] [--json]` | start the server the way `run` would and say what works, what does not, and why each pack would or would not run. Grades nothing. Exit 4 if a step failed. Prints **Suggestions**: what to add to `sealmark.yaml` (the YAML to paste and the equivalent flags); `--json` carries them as `suggestions[]` |
| `sealmark diff <before.json> <after.json> [--json]` | compare two JSON reports of the same server without running anything: regressions, improvements and tool-surface drift. Exit 1 on a regression or a breaking or notable drift, 2 for an unreadable file (see [Drift](#tool-surface-drift)) |
| `sealmark list-checks [--pack id] [--json]` | every check with its pack, severity, scope, and whether its settings are locked by the standard profile |
| `sealmark explain <check-id>` | what a check measures, its probes, thresholds, known false positives and negatives, and the settings that affect it |
| `sealmark describe --json` | the machine-readable description of this build (checks, config keys, commands, flags, exit codes) |
| `sealmark config show [--origins] [--json]` | the merged configuration. The first line says whether a run with it would be `# STANDARD` or `# CUSTOM` and, for CUSTOM, which settings differ from the standard profile. `--origins` says where every value came from; `--json` adds an `integrity` object (`standard`, `hash`, `diff`) |
| `sealmark config profiles [--json]` | shipped and user profiles with their difference from `standard` |
| `sealmark config migrate [--config f]` | rewrite a config file to the current `schema_version`; the original is kept as `<file>.bak` |

`sealmark --help` prints every flag; it is generated from the same table as `describe --json`.

### Flags of `run`

| Flag | Meaning |
|---|---|
| `--config <file>` | project config. Default `sealmark.yaml`; `sealmark.local.yaml` beside it is read too |
| `--profile <name>` | `standard` (default), `quick`, `ci`, `strict`, `paranoid`, or one you define |
| `--pack <id>` | run only these packs (repeatable). A subset of the standard packs makes the run CUSTOM. A list you give here is used as written: `custom` is not added to it, so probes with a `check:` are skipped with a warning unless you name `custom` |
| `--url <url>` | the MCP server to test over Streamable HTTP (`server.url`). With `--start` Sealmark starts the server and waits for this URL to answer. See [CI](#ci) |
| `--start "<command line>"` | the command that starts the server (`server.command` + `server.args`), for example `--start "my-server --port 8000"`. With `--url`: launch, wait, test, stop. Alone: a stdio server. Not run through a shell: no `&&`, no `VAR=value` prefix (use `sh -c '...'`) |
| `--header "Name: value"` | an HTTP header for `--url`; repeat for several. `${VAR}` inside single quotes is read from the environment by Sealmark, so a secret stays out of the process list and the report |
| `--bearer <token>` | shorthand for `--header "Authorization: Bearer <token>"`. Use `--bearer '${MCP_TOKEN}'` (single quotes) so Sealmark reads the token from the environment |
| `--start-timeout <sec>` | how long the URL gets to answer after `--start`. Default 60 s. A server that never answers fails the run (exit 4) |
| `--name <text>` | the server's display name in the report (`name`) |
| `--upstream` | start the harness-owned upstream stub (`upstream.kind: http`); the server must reach it through `{upstream}` |
| `--scope-tool <tool=param>`, `--scope-allow <id>`, `--scope-deny <id>` | `scope.tools`, `scope.allow`, `scope.deny` (repeatable). An entry ending in the separator (`.`) is a prefix |
| `--identity-a <token>`, `--identity-b <token>` | `identities.a`/`.b`: real caller tokens for a server that validates them, instead of the minted ones. Use `'${TOKEN_A}'` so the value comes from the environment |
| `--soft-fail` | a grade below the gate prints a warning and exits 0. Exit 2, 3 and 4 still fail (see [Exit codes](#exit-codes)) |
| `--server <name\|all>` | with `servers:` in the config, run one entry or all of them (default all) |
| `--fail-under <A-F\|none>` | exit 1 if any graded pack is below this letter. **Default A: anything below an A fails.** `B`, `C`, `D` or `F` relax it (a lower-case letter is read as the upper-case one, and the run says so once); `none` turns the gate off (`--soft-fail` keeps the gate but turns the exit into 0) |
| `--format text\|json\|markdown\|junit\|sarif\|summary\|badge\|shields` | report format; repeat the flag or comma-separate for several. Default `text`. `summary` is the short CI view; `badge` and `shields` render a README badge for one server (see [Other formats](#other-formats) and [Badge](#badge)) |
| `--out <file>` | write the report to a file instead of stdout (also for `summary`) |
| `--out-dir <dir>` | write one file per format named in `output.formats` (`sealmark-report.json`, `.junit.xml`, `.sarif`, `.md`, `.txt`, `.summary.txt`, `.badge.svg`, `.shields.json`). Several formats without `--out-dir` go to `./sealmark-report/`; when `summary` is one of several it is printed to the console instead of written to a file |
| `--template <file>` | Handlebars-style template for the `text` and `markdown` formats (see below) |
| `--verbosity quiet\|normal\|verbose` | quiet: grades and failures only. verbose: every evidence line and probe argument |
| `--no-redact` | print secret-looking values and real sandbox paths. Local debugging only; do not share the output |
| `--baseline <report.json>` | compare with an earlier JSON report and fail on regressions |
| `--write-baseline <file>` | save this run's JSON for later `--baseline` runs (not written when the run regressed) |
| `--fail-on any\|regressions\|drift` | what decides exit 1; repeat the flag or comma-separate for several (`output.fail_on`). `any` (default): the gate and regressions. `regressions`: only regressions, with a baseline. `drift`: a breaking or notable tool-surface change against the baseline; alone it turns the grade gate off. `regressions,drift` and `any,drift` combine. `regressions` and `drift` need `--baseline` (exit 2 without one) |
| `--replay <report.json>` | re-run with the locked settings of an earlier report, after checking its config hash |
| `--timeout-probe <sec>` | how long the cap and timeout probes wait. Default 10 |
| `--connect-timeout <sec>` | how long the server gets to answer `initialize` and `tools/list` (start-up of a stdio server included). Default 60 for `run`; `doctor` uses 10 unless you pass it. A progress line prints every 15 s. Not the same as `--start-timeout`, which is how long a started HTTP server gets to answer on `--url` |
| `--active` | allow the `exec` pack and active custom probes. Only the command line can set it |
| `--no-sandbox` | do not confine the server: it inherits your environment, `fs`, `git`, `exec`, `effects` and `sqlite` are n/a, and the run is CUSTOM |
| `--sandbox-dir <dir>` | parent directory for the sandbox (default: the OS temp directory) |
| `--keep-sandbox` | do not delete the sandbox; its real path is then shown in the report |
| `--pack-timeout <sec>` | abandon one pack after this many seconds (it becomes inconclusive). Default 600 |
| `--embedded` / `--no-embedded` | use (default) or do not use the embedded Postgres |
| `--pg <dsn>` | use your own Postgres instead. Needs a superuser and **`--yes`** (see [Safety](#safety-notes)) |
| `--fixture fs\|git\|sqlite --into <dir>` | write a fixture the sandbox generates, for hand runs: the `fs` layout, the `git` repositories or the SQLite database. Default directory `./sealmark-fixtures`; it refuses to write over an earlier fixture. `duckdb` is planned and exits 2 |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ok. Every graded pack met `--fail-under` (default A; `none` disables the gate) and there was no regression. Also what a below-gate grade exits with under `--soft-fail` |
| 1 | a graded pack is below `--fail-under` (a provisional `A*` is below an A gate), an inconclusive pack counts as failing (`ci` profile), or a `--baseline` comparison found a regression, or (with `--fail-on drift`) the tool surface drifted. With `--soft-fail` this becomes exit 0 and a `soft-fail:` warning on stderr; 2, 3 and 4 still fail |
| 2 | usage or configuration error (bad flag, invalid `sealmark.yaml`, `--pg` without `--yes`, `--pack exec` without `--active`, `init` over an existing file) |
| 3 | no pack was graded. The reasons are in the report |
| 4 | harness or server failure (the server would not start, the database could not be provisioned, `doctor` found a failing step) |
| 129, 130, 143 | the run was stopped by a signal: SIGHUP (129), SIGINT or Ctrl-C (130), SIGTERM (143), that is 128 plus the signal number. The harness cleans up first and starts no further server after the signal, and the last line on stderr is `sealmark exit 130: interrupted` (with the signal's own code; `stopped` instead of `interrupted` for SIGTERM and SIGHUP), even when the signal landed as the last pack finished, so the line and the exit code agree. The JSON has `interrupted: true` and the warning "the run was interrupted; the report may be incomplete". If a directory could not be removed it says `cleanup did not finish: <path> (remove it by hand)` on stderr, also when the 15 s limit on cleanup is reached; with `--keep-sandbox` the last line is `kept sandbox: <path>` |

Exit 3 is decided before `--fail-under`: a run that grades nothing never passes the gate. An inconclusive pack has no letter, so `--fail-under` cannot judge it; the run prints a `warning: pack ... was inconclusive` line, or exits 1 when `output.exit_policy.treat_inconclusive_as` is `fail`. The `ci` profile sets it to `fail` (decided by recommendation; the owner may veto), so a CI job does not go green because a pack could not be judged; outside CI the default stays `pass`. A **provisional** grade (`A*`: a critical check was inconclusive) does not meet `--fail-under A`: the message reads `pack core graded A* (provisional: a critical check was inconclusive), which does not meet --fail-under A` and the run exits 1. The rule is specific to the A gate, where "proven top mark" is the claim; a provisional B still meets `--fail-under B`. `--fail-under none` prints `the gate is off (--fail-under none); grades do not affect the exit code`; the `warning: pack ... was inconclusive` lines are still printed, and when `treat_inconclusive_as` is `fail` a note says that it does not affect the exit code while the gate is off. `output.exit_policy.critical_fail: <code>` (default 0) makes a critical fail exit with that code. With several servers the code is the worst of them. `--soft-fail` (`output.exit_policy.soft_fail`) only softens exit 1: a gate miss, an inconclusive pack counted as failing, or a baseline regression. It never hides a configuration error (2), a run that graded nothing (3) or a server that could not be started (4).

When the console does not already show the grades (the report goes to a file with `--out` or `--out-dir`, which includes `--format summary --out <file>`, or the format on stdout is a machine one such as `json`), the grades are also printed to stderr, one line per server, followed by any configuration warning that was not printed before the run. The line names a critical fail whether or not it capped the grade, and a critical check at `part` (which does not cap) as `critical part`:

```
core A (hygiene only) · db D capped: critical fail: mutating-sql
db F critical fail: mutating-sql · fs B critical part: fs-read-escape
```

When a server cannot be started, the run exits 4, prints a hint if the stderr looks like drifted dependencies, saves the full server stderr to `<out>.stderr.log`, and writes the report file with `"status": "failed"`, the `error`, and the `stderrFile`.

## Configuration

Everything is configurable and nothing configurable is hidden. Layers, lowest to highest:

1. built-in defaults,
2. the selected profile (`standard` unless `profile:` or `--profile`; profiles may `extends:` another),
3. your user file: `%APPDATA%\sealmark\config.yaml` on Windows, `$XDG_CONFIG_HOME/sealmark/config.yaml` elsewhere,
4. `sealmark.yaml` (or `--config`) and `sealmark.local.yaml` beside it (keep it out of git),
5. `SEALMARK_*` environment variables (`SEALMARK_PACKS=core,fs`, `SEALMARK_SANDBOX__DIR=D:\tmp`; a double underscore nests). Every config setting has one, but a flag has one only when it maps onto a setting: `--url` is `SEALMARK_SERVER__URL`, `--start-timeout` is `SEALMARK_SERVER__START_TIMEOUT_SEC`, `--soft-fail` is `SEALMARK_OUTPUT__EXIT_POLICY__SOFT_FAIL`. `--start` has no environment form: `SEALMARK_SERVER__COMMAND` is one program name, not a command line, so set `SEALMARK_SERVER__COMMAND=node SEALMARK_SERVER__ARGS=server.js,--port,8000` (a comma list). `--header` and `--bearer` have none either: a header name from the environment is upper-cased with `_` kept (`SEALMARK_SERVER__HEADERS__X_API_KEY` is sent as `x_api_key`, not `X-Api-Key`), so a hyphenated header needs the flag or a file, and a single-word one such as `Authorization` can also come from `SEALMARK_SERVER__HEADERS__AUTHORIZATION`,
6. command-line flags.

Lists replace, except the ones that append (`tools.exclude`, corpus `add`/`remove`, `notCovered.extra`, `plugins`); maps merge; `null` resets to the built-in default. `--active` and `--yes` come only from flags. Unknown keys are errors with a did-you-mean and `file:line`. `sealmark config show --origins` prints every value with its origin, secrets redacted and placeholders unexpanded. A JSON Schema for editors is written to `schema/sealmark.schema.json` on build (`init` writes the `yaml-language-server` line that uses it when the package is installed locally, see [Quickstart](#quickstart)). Four older keys are accepted and ignored with a warning, so existing files keep loading: `retries.call` (nothing retries a control call; it was a locked setting that nothing read, and methodology 0.3-draft unlocked and deprecated it), `retries.connect`, `concurrency.*` and `output.interactive`.

```yaml
schema_version: 1
name: my-server
version: 1.0.0
server:
  command: npx
  args: ["-y", "some-mcp-server", "{sandbox}"]
  env:
    API_KEY: "${MY_API_KEY}"        # an environment reference, resolved when the run starts
  files:                             # staged files, written inside the sandbox before the server starts (file only)
    - path: "{sandbox}/config/app.ini"
      content: |
        mode=test
sql_tools:                           # optional: detected from the tool list; an entry adds or corrects, it never hides a detected tool
  - { tool: query, arg: sql }
  - { tool: run_sql, arg: query, args: { database: main } }   # args: values for the tool's other required parameters
packs: [core, db, fs, net, git, http, effects]
tools:
  exclude: ["admin_*"]
  overrides:
    legacy_thing: { class: opaque }  # the classifier's guess is wrong: say so
checks:
  fs-size-cap: { enabled: false }    # allowed, but the run becomes CUSTOM
output:
  format: text
  fail_on: [any, drift]               # with --baseline: the gate, regressions and tool-surface drift all exit 1
```

For several servers use `servers: { fs: {...}, fetch: {...} }` instead of `server:` (not both) and `sealmark run --server fs` or `--server all`.

**`sql_tools` adds or corrects, and never hides.** The `db` and `sqlite` packs find SQL tools from the tool list (a string parameter named `sql`, `sql_query` or `sqlquery`, or `query` or `statement` with SQL words in the tool name or the parameter's own description). An explicit `sql_tools` entry wins for the tool it names (a missing `role`, `shape` and approval parameter are filled in from the schema), but a tool that detection finds is still probed when the list leaves it out, and a detected writer cannot be relabelled a reader, so a list cannot keep a run STANDARD by hiding a writer. To keep a tool out of a run use `tools.exclude` (locked: the run becomes CUSTOM). Each entry must name a tool the server declares and a string argument that tool has, otherwise exit 2. A SQL tool with other required parameters is graded with them filled (an enum's first value, a boolean `false`, a number's minimum or 1, otherwise a token; a `default` wins). When a placeholder cannot satisfy one, the control read fails and the report says what to type next: `args: {<param>: <value>}` on the entry sets scalar values (string, number or boolean) for those parameters.

**`server.rootless`** (default `false`): the server takes no root argument, so the `fs` pack treats its working directory, `{sandbox}`, as the allowed root and runs every probe. A server that reads and writes any path then fails the escape checks, which is what it does. `doctor` and the `fs` n/a reason suggest it when a path tool exists and no `{sandbox}` placeholder does. Adding coverage never weakens a grade, so the run stays STANDARD.

An unknown `{word}` placeholder in `server.command`, `args`, `env`, `url` or `headers` is a warning with a did-you-mean (the server receives the literal text). `tools.overrides.<tool>: {class: path|url|git}` with no usable parameter for that class is a config error that names the fix (`params: {path: <name>}`).

`server.files` writes small files into the sandbox before the server starts, for a server that reads a config file. `path` must start with `{sandbox}`, `{dir}` or `{sandbox_home}` and stay inside it after expansion (`..` is refused); `content` may use `{sandbox}`, `{sandbox_home}`, `{listener}`, `{sqlite_path}` and `${VAR}` but never a database placeholder (`{dsn}` and friends: the server is started once per database role and a file cannot change between roles, so pass the connection string through `args` or `env`). It is a list of objects, so it has no flag and no environment variable. It needs a server Sealmark starts in the sandbox: a bare `--url` server, or `--no-sandbox`, is an error. `output.fail_on` is a list (`any`, `regressions`, `drift`); a single value is read as a one-item list, and `SEALMARK_OUTPUT__FAIL_ON=regressions,drift` works.

### Backends, scope and callers

A server that fronts a backend (a SQL engine, an API) is graded with three declarations; every key below is also a flag and a `SEALMARK_*` variable, and none of them is locked, so declaring them keeps a run STANDARD:

```yaml
server:
  command: node
  args: ["server.js", "--port", "8080", "--backend", "{upstream}"]   # the server's backend is the harness's stub
  url: http://127.0.0.1:8080/mcp
  headers: { Authorization: "Bearer {bearer}" }                     # one minted token per caller
upstream:
  kind: http
  default_reply: { status: 200, json: { rows: [] } }
  responses:                                                        # first match wins; no match: default_reply
    - { id: count, match: { path: "^/sql$", body: "count\\(\\*\\)" }, reply: { json: { rows: [{ count: 3 }] } } }
scope:
  tools: [{ tool: describe_table, param: table }]
  allow: ["sales.public."]                                          # "x.y." is a prefix, anything else exact
  deny: ["hr.private.salaries"]
sql_tools: [{ tool: query, arg: sql }]
```

| Key | Default | Meaning |
|---|---|---|
| `upstream.kind` | `null` | `http` starts the stub (flag `--upstream`). The server config must use `{upstream}`, and the server must run on this machine (the stub listens on loopback only) |
| `upstream.responses`, `upstream.default_reply` | `[]`, `{status: 200, json: {}}` | scripted replies: `match` on `method`, `path`, `body` (regexes) and `header`; a reply has one of `body`, `json` or `bytes` (padded to that size), plus `status`, `headers`, `delay_ms`. `{upstream_token}` in a reply body mints a marker per occurrence (for `expect.upstream.token_echoed`) |
| `upstream.credential_header`, `upstream.max_body_kib` | `authorization`, `1024` | the header the upstream pack reads; how much of each request body is kept |
| `identities.a`, `identities.b` | minted | secrets. `{bearer}` is `{bearer:a}`. The harness mints `sm-bearer-a-<hex>`/`sm-bearer-b-<hex>` per run; set these only for a server that validates tokens, from the environment, never literally |
| `scope.tools`, `scope.allow`, `scope.deny`, `scope.separator`, `scope.case` | `[]`, `[]`, `[]`, `.`, `insensitive` | the identifier parameter of each tool, what it may serve, what it must never serve |
| `checks.sql-guard-rowcap.row_cap`, `checks.sql-guard-statements.control_sql`, `checks.upstream-slow.expected_sec` | `10000`, a `SELECT` on an allowed name, `timeout_probe_sec` | thresholds and the control statement |
| `checks.refusal-quality.patterns`, `checks.instructions-hygiene.deny` | the routing words, `[]` | what a routing refusal looks like; patterns the instructions must not match (a leftover prompt, a product name) |

`probes:` takes rule clauses for such a server: `identity: a|b|none`, `matrix`, `cases`, a scripted `upstream.reply`, and `expect.upstream` (`requests: none|any`, `none_matching`, `all_matching`, `header`, `token_echoed`), `expect.log` and `expect.response.max_bytes`; SQL may be sent to a SQL tool when the stub is declared. The guide on the website has the clauses and a worked example; `sealmark explain <check-id>` the verdict rules.

### Placeholders

Used in `command`, `args`, `env` values, `url`, and `headers` values:

| Placeholder | Value |
|---|---|
| `{dsn}` `{host}` `{port}` `{user}` `{password}` `{database}` `{role}` | the seeded Postgres role under test (`db` pack). `{dsn:analyst}`, `{dsn:support}`, `{dsn:admin}` pick a role |
| `{sandbox}` (alias `{dir}`) | the sandbox root: the directory the harness owns and the server's working directory |
| `{sandbox_home}` | the sandbox home (HOME, USERPROFILE and APPDATA of the server) |
| `{sqlite_path}` | a seeded SQLite file inside the sandbox. `{duckdb_path}` is **planned**: the placeholder is filled, but DuckDB is not graded yet (one engine per config) |
| `{upstream}` | the URL of the harness's upstream stub (`http://127.0.0.1:<port>`), with `upstream.kind: http` |
| `{bearer}` `{bearer:a}` `{bearer:b}` | a caller token (headers only, in practice): minted per run, or `identities.a`/`.b`; a session opened anonymously drops every header that holds one |
| `${VAR}` `${VAR:-default}` | an environment variable, resolved from your real environment when the run starts. Never written to a report |

`{canary}` and `{token}` exist only in `probes:` (where `{upstream}` and `{bearer}` are refused: `identity:` chooses the caller), `{matrix.<name>}` only in the `args` of a probe with `matrix:`, `{upstream_token}` only in a reply body, and `{listener}` only in `probes:` and in the `content` of `server.files`. **Never put real credentials or a real database URL in `sealmark.yaml`.** Reports print the server command and env as written (placeholders unexpanded), with a literal value under a secret-looking name shown as `<redacted>`; anything read from `sealmark.local.yaml` is scrubbed from every report format. That is a safety net by name and by origin, not a guarantee. An absolute path in `server.args` or `server.env` that points outside the sandbox (a memory file, a data directory) is a real path on your machine: valid calls may read or write it. `run` and `doctor` print one warning per such path (`server.env MEMORY_FILE_PATH points at a real path on this machine; ... Use {sandbox}/<name> ...`), and `init` offers the `{sandbox}` form.

### Profiles, STANDARD and CUSTOM

`sealmark config profiles` lists them. `standard` is the published methodology and the only profile whose grade is official; `ci` changes only output and exit policy (it counts an inconclusive pack as failing), so it can still be standard. A correctly guarded URL tool can be green under it: the harness owns no URL such a tool will fetch, so after `net-loopback-ssrf` passes, `effects` is `n/a` for it instead of inconclusive (before round 5 the `ci` profile could never be green for one). A guard that answers every rejection with one constant sentence is the exception: the `net` pack calls it inconclusive, and the `ci` profile fails that, until `net.control_url` names a URL the tool fetches. `quick` (fewer packs, no cap or timeout probes), `strict` (every advisory check scored, the `db-privilege` candidate included) and `paranoid` are always CUSTOM.

Every report starts with a header that says which it is:

```
sealmark 0.2.2 · methodology 0.3-draft · STANDARD · my-server 1.0.0
sealmark 0.2.2 · methodology 0.3-draft · CUSTOM (not the published methodology: 2 differences) · my-server 1.0.0
  timeout_probe_sec: standard 10, effective 2  (flag --timeout-probe)
  packs: standard ["core","db",...], effective ["core"]  (flag --pack)
```

A run is STANDARD only if every setting that affects a grade equals the standard profile, no standard pack was dropped, and no plugin or custom check ran. Adding coverage (the `exec` pack with `--active`, a probe without a `check:`) keeps it standard; weakening anything does not. A candidate check (see [Candidate checks](#candidate-checks)) is not part of the standard hash, but switching it off or scoring it makes the run CUSTOM. Pack lines of a custom run say `custom grade`. A run with custom checks (a probe with a `check:`) or plugins also has its own `config.hash`: the ids of the checks and the plugin modules enter the hash, and only when there are any, so a run without them keeps the published standard hash. `--baseline` and `sealmark diff` therefore say "different configuration" against a STANDARD report, and `--replay` of such a report restores the locked settings only and warns that you must declare the same probes yourself. The header cannot be removed by a template; JSON carries `config.hash`, `config.standard`, `config.standardDiff` and the locked settings, and `--replay` reproduces a run from them. `sealmark config show` answers the same question before a run: its first line is `# STANDARD: ...` or `# CUSTOM: N settings differ from the standard profile: ...`, a YAML comment so the output still loads. The standard hash moved in 0.3-draft (`net-redirect` became a locked, scored check, `retries.call` stopped being locked), so hashes and replays from 0.2-draft do not carry over. No badge is offered for a core-only or a custom run (`badge.eligible` in the JSON).

## Reading the report

```
sealmark 0.2.2 · methodology 0.3-draft · STANDARD · toy-nosql 0.0.1

server: node dist/toy/server.js --mode nosql
env:
  SEALMARK_CANARY=<canary>
  SEALMARK_FAKE_API_KEY=<canary>
stdio server, 2 tool(s): echo, add
db: not used
sandbox: {sandbox_dir} · env scrubbed · listener 127.0.0.1:{listener_port} · cleaned up · inherited: PATH (system part), LANG, npm_config_cache, UV_CACHE_DIR

Classification:
  echo  text    low  core only: string parameters only, and none names a path, URL, command, SQL or repository; add it under tools: to include it
  add   opaque  low  core only: the tool has no string parameters; add it under tools: to include it
  packs applied: core

PACK core  GRADE A  (4/4 points, 100%)  hygiene only · tools called with valid arguments: 0 of 2
  Core is hygiene only: no tool was called with valid arguments, so this grade says nothing about what the tools do.
  [PASS] Valid MCP handshake and tool schemas — handshake ok, 2 well-formed tool(s)
        scope: server
  ...

PACK db  not graded: server config has no {dsn}/{host}/... placeholder, ...

Badge: not eligible: core-only run: no capability pack was graded.

Not covered:
  - tool "echo" is covered by the core checks only: ...
  - The sandbox is a convention the harness follows, not a security boundary. ...

An A means these checks passed with this exact configuration. It is not a security endorsement; see methodology.
```

(Abridged output from a toy server; toy servers are test fixtures, their results say nothing about any real server.)

- Worst verdicts print first. Every check line carries one verdict tag (`[PASS]`, `[PART]`, `[FAIL]`, `[INCL]` for inconclusive, `[N/A ]`); an advisory check ends with `(advisory, not scored)` and never changes a letter. Inconclusive and `n/a` checks are left out of the score. `*` after a grade means a critical check was inconclusive, so the grade is provisional (and does not meet an A gate, see [Exit codes](#exit-codes)).
- `packs applied:` lists the packs that produced a grade or an inconclusive result, core included, or `none` when nothing ran. `sealmark doctor` prints the same line (core included once the server started), so the two agree for the same configuration.
- Every check carries a `scope` line: whether it tests the server's behavior, or a control tested through the server.
- The `Classification:` block shows, per tool, what the harness thinks it takes (`path`, `url`, `command`, `sql`, `git`, `text`, `opaque`), how sure it is, and why. A tool classified with low confidence gets the `core` checks only and is listed under "Not covered". Fix a wrong guess with `tools.overrides`. A tool that is also a second class (a `path` tool with a `url` parameter) shows `secondary: url (probed by net)`: the `net` pack consumes a secondary `url`; a secondary `path` or `git` is not probed and is listed under "Not covered". The hint after a core-only tool depends on why: a heuristic guess says to add it under `tools:`; a tool that is already overridden to a class no pack probes, or whose required parameters the harness cannot fill, says to write a `probes:` entry to call it.
- `Not covered:` also names tools that servers list only to clients declaring roots, sampling or elicitation (the harness declares none, so such tools are not seen), tools that require task-based execution (the harness does not use it), and per-tool gaps from every pack (twelve lines at most, then a count). The `effects` pack adds that writes outside the observed sandbox directories, such as your real home or a store named by an absolute path, are not seen.
- Sandbox paths in any report are rewritten to `{sandbox}`, `{canary}`, `{sandbox_home}` and `{sandbox_dir}`, and the loopback listener's port to `{listener_port}`, in every spelling the harness can recognise: plain, percent-encoded (`%2F`, `%5C`), backslash-escaped, `file://localhost/<dir>`, a truncated echo of the sandbox directory name, and next to any of the loopback host spellings (`--no-redact` or a kept sandbox shows the real values). The per-run tokens are rewritten wherever they occur, including inside a file name (`w-sm-<hex>-3.txt`, `w-ctl-sm-<hex>-abs.txt`), in control values (`sm-control-<hex>`, `pwned-<hex>`) and as commit ids (`{sha}`). Two runs of the same server produce the same verdicts and evidence; timestamps, durations and the JSON `sandbox.listenerPort` differ, and nothing the harness generates differs besides those. In detail: text, markdown, summary, badge and shields output is byte-identical at every verbosity; the JSON differs in exactly three of the harness's own fields, `startedAt`, `durationMs` and `sandbox.listenerPort`, plus `upstream.url` when an upstream stub ran and each `probes.calls[].elapsedMs` (a measured time) when `probes:` are declared; JUnit and SARIF differ in the same fields plus the SARIF `startTimeUtc`, and any timing the server itself prints inside an excerpt can differ in those three formats. `config.path` in the JSON is relative to the working directory. One harness-measured number can differ in every format: how many bytes the net pack's listener had sent when a server hung up early on the oversized reply, printed as `under N of 64 MiB` with N rounded up to a power of two from 8.
- The grade: pass = 1 point, part = 0.5, fail = 0, over the scored non-advisory checks. A >= 90%, B >= 75%, C >= 60%, D >= 45%, else F. A `fail` on a critical check caps the grade at D. If nothing is scored, no grade is produced. The fraction beside a grade is always points over scored checks in the text, markdown and summary formats: `(3/4 points, 75%)`, and when checks were left out `(3/4 points, 75% · 1 of 5 checks not scored)`.

### Verdict rules worth knowing

A pass must mean the probe ran. These rules were added in 0.3-draft:

- **Control characters in metadata.** `tool-poisoning` scans tool, prompt and resource text for hidden characters. ESC, NUL and the C1 range (U+0080 to U+009F), which drive a terminal, are strong indicators (the check fails and the grade is capped at D). The other C0 controls and DEL are weak (`part`). Tab, line feed and carriage return are ordinary. A server that embeds ANSI colour codes in descriptions on purpose fails by design.
- **The zero-probe guard.** `fs-read-escape` and `fs-write-escape` are inconclusive, never a pass, when no escape probe was answered (every probe timed out, could not be built or was removed by config). When some were answered the verdict is judged on those and the summary says how many (`54 of 56 variants answered`).
- **No-argument calls count only when they worked.** A read-only tool that takes no arguments is called once with `{}`; the call counts toward coverage only if the server answered without an error, so a server that rejects its own no-argument tool is not credited with a valid call.
- **A "killed" reply is not proof.** `exec-timeout-cap` (with `--active`) confirms a "killed" or "timed out" reply against the process table: if a harness-owned `sm-sleep` is still alive the check fails (and the harness stops it); if none is, the check passes on the process table rather than on the reply.
- **Size by bytes.** `net-caps` judges the size half by how much of the 64 MiB body the server consumed, not only by the length of its reply.
- **Blobs are read.** A file tool that returns content as a resource, image or audio block is probed like a text one (the harness decodes the block and looks for its tokens); a `data:` URL that a tool decodes and returns as a block is reported.
- **Bounded input.** `tools/list` is capped at 5 000 tools and 32 MiB; a server that sends more fails `protocol` with the bound named.

Added in the second verification round (the same 0.3-draft unit; each has a toy that must now fail and a near-miss toy that must still pass):

- **A refusal ties itself to the target.** `net-loopback-ssrf` and `net-scheme-allowlist` pass without a control URL only when every declined reply names the class of address it refuses (loopback, private, reserved, not routable, internal), names the host or URL as refused, or is a validation error that names the address. A reply that only reports that a fetch failed or names the mechanism that failed (a proxy, a socket, DNS, a timeout, `connection blocked by proxy`, `network access is restricted`) is a failure, not a refusal: a tool that fetches nothing is `inconclusive`, and the evidence line says which rule decided each probe.
- **One corpus entry per spelling family.** The loopback corpus now has the dotted, name, IPv6, short, hexadecimal, decimal, unspecified, IPv4-mapped IPv6, redirect and (opt-in) DNS entries. Octal spellings and other `127/8` addresses are not probed (a client that reads octal as a name would turn a good server inconclusive). The `fs-write-escape` corpus mirrors the read corpus wherever a write can carry the same path form (dot-slash, percent-encoded, `file://`, forward-slash), and the move-destination probes get the percent-encoded and `file://` forms.
- **A server that re-validates every redirect can pass `net-redirect`:** one that follows the same-origin redirect and refuses the redirect to a spelling it refused when given directly has shown re-validation.
- **The git fixture.** Every repository has a staged change, and the root repository has an untracked link to the canary repository. `git-repo-scope` is `part`, not `pass`, when a read tool could not be judged because its control failed (the summary names it), and the pack is not applicable at all without `{sandbox}` in the config, because the one critical check could not be configured.
- **SQLite forms.** `sqlite-extension-load` does not read a refusal that never mentions extensions as a denial: a declared writer is also probed with an `INSERT` or `UPDATE` form it accepts, and a reader with a `SELECT ... WHERE` form, and a tool that refuses every form without saying anything about loading is `inconclusive`. `sqlite-file-read` follows an `ATTACH` made through a writer by reading the attached file through the controlled reader on the same session.
- **Coverage counts calls that exercised the tool.** A call counts toward "tools called with valid arguments" when it was schema-valid and the server processed it: a control call counts when it succeeded, an escape probe when its control succeeded and the reply was not a validation error, and a net probe whose outcome was a failed fetch never counts. A pack whose checks are all inconclusive or `n/a` contributes no valid calls, so errored probes cannot lift the coverage level above `hygiene only`.

Added in the third verification round (the same 0.3-draft unit; each has a toy that must now fail and a near-miss toy that must still pass; the full text is `docs/methodology.md`, "Round 5"):

- **A refusal rests on what the harness observed.** In `net-loopback-ssrf` a declined reply is a refusal when it names a rule (only public hosts, an egress policy, an unsupported scheme, "resolves to a private address") or names the class of address it refuses (and no failure word sits in the same clause); a transport phrase such as "refused to connect", an echo of the probe's host and port, or "failed to fetch" is never a refusal. When every loopback probe was refused, the listener saw nothing and no control fetch worked, the harness also sends the tool a URL with no host (`data:text/plain,sm-<token>`, the hostless twin). The same sentence for it and for every refused loopback probe (`net.ssrf-sametext`), or address wording for a URL that has no address (`net.ssrf-incoherent`), means the tool has one answer for everything: the check is `inconclusive` and says to set `net.control_url`. Otherwise the pass stands (`net.ssrf-text-only`) and says that no fetch of any URL was shown to work. The honest limit: a guard that answers every rejection with one constant sentence is inconclusive until `net.control_url` names a URL it fetches. Each probe's evidence line names the rule that decided it.
- **`tool-poisoning` scans the server instructions and `serverInfo`** (name, title, description, website) with the same tiers as a tool description; there is no length rule for instructions. `protocol` is `part` when a stdio server writes non-JSON-RPC lines to stdout or returns a tool result that is not valid MCP. `robust-input` reads an error that came after the invalid argument was used (a failed upstream request) as leniency, and an unhandled runtime error as an internals leak.
- **`sqlite` confirms its engine** with `sqlite_version()`. A DuckDB-style server is inconclusive on every check, with the engine named in the reason only, and the pack's n/a text says SQLite servers only. The file checks try the two-call, single-call and copy-into-fixture forms (the last verified by reading the fixture file), a DDL-only tool is controlled through `CREATE TABLE`, and a SQL tool that answers none of the controls makes the file checks `part`. A zero-row plain-text row cap passes; an unrecognised zero-row reply is inconclusive.
- **`db` mutating SQL has 19 cases:** `ROLLBACK`, `END` and `ABORT` join `COMMIT` as transaction terminators (each followed by a write; `COMMIT WORK` adds nothing and `… AND CHAIN` keeps the read-only transaction, so neither is a case). A SQL tool with other required parameters is graded; see `sql_tools` above.
- **`git-repo-scope`** fills `file` and `object` parameters with fixture values (`tracked.txt`, `HEAD`), sends relative targets as well as absolute ones, judges write tools (a branch, a commit, a worktree, a clone) by watching the `.git` directories and destinations, and is `part`, not `pass`, when any read tool could not be judged, at any confidence.
- **`fs`** adds the array (second element), backslash, move-through-link, write-through-file-link and dangling-link families and probes edit tools; a search tool is controlled with a pattern that works; `fs-size-cap` is inconclusive when readers exist and could not be controlled and `n/a` only when no tool returns file content; `server.rootless` grades a server with no root argument.
- **The coverage rule.** A call counts toward "tools called with valid arguments" only when it was schema-valid and the server processed it. A reply that reports a failed upstream request (even without `isError`), a schema-validation rejection and an errored control call do not count, and neither does a valid call written under `probes:` whose reply is a refusal in plain text. A refusal-only probe of a guarded tool still counts: refusing is the behavior under test. Coverage feeds the coverage label only; no letter, verdict or badge reads it.
- **A URL tool may relay probe values to its own upstream.** A tool that forwards a URL or a query to a hosted service sends that service the harness's probe text (a token, a loopback address), which the harness cannot see or stop. `tools.exclude` keeps a tool out of the `net` pack (and every other pack's probes; the setting is locked, so the run becomes CUSTOM).

### Other formats

- `json`: the full run record. One server is a plain `RunResult`; several are `{ "runs": [...] }`. Includes the classification, sandbox facts, coverage, `badge`, `warnings`, the resolved package version, and per-check evidence.
- `markdown`: the same content with tables, for a PR comment or a wiki.
- `summary`: what a person wants to see in a CI log: a grade card per pack, one row per check (failures first), what to fix (which failure caps a grade, and a critical check at `part` tagged `critical part`), a short `NOT COVERED` block (the first eight lines and a count) and what the exit code means. Inconclusive packs are listed apart from not-applicable ones, and when the gate is A and a pack is provisional the banner says `BUT PROVISIONAL` so it never contradicts exit 1. Passes stay short. It prints to stdout unless `--out` or `--out-dir` is given (alone it is written as `sealmark-report.summary.txt`; together with other formats it goes to the console and the others go to files). It ignores `--verbosity` and has no multi-server overview; use `text` or `markdown` for full evidence.
- `badge`: a flat SVG badge for one server, `sealmark-report.badge.svg` with `--out-dir`. `shields`: the same text as a shields.io endpoint document, `sealmark-report.shields.json`. Both are self-reported and refuse several servers (see [Badge](#badge)).
- `junit`: one `testsuite` per pack and one `testcase` per check. A scored `fail` is a `<failure>`; `na` and `inconclusive` are `<skipped>`; `part` and advisory results are plain cases with the verdict in `<system-out>` (JUnit has no warning state; the exit code is the gate).
- `sarif` (2.1.0): one rule per check, one result per failed or partial check (`error` for fail, `warning` for part, one step lower for advisory checks), `partialFingerprints` from the check id and tool, and the STANDARD/CUSTOM label in the run properties. Results point at the configuration file, at the line of the selected server's `command` or `url` setting when that line is known (otherwise line 1), and JUnit test cases carry the same file and line. The line locates the server block, not the cause of the finding.

The JUnit and SARIF shapes are checked by the test suite against their required structure offline (nesting, required attributes, totals that add up, rule/result links). They have not been validated with the official XSD or JSON Schema validators, and the SARIF has not been uploaded to a code-scanning service.

### Templates

`--template file` (or `output.template`) renders the `text` and `markdown` formats with a small Handlebars-style engine: `{{server.name}}`, `{{json value}}`, `{{#each packList}}...{{/each}}` with `{{@index}}`, `{{@key}}`, `{{@first}}`, `{{@last}}`, `{{#if x}}...{{else}}...{{/if}}`, `{{#unless x}}`, `{{! comments }}`. Besides the `RunResult` fields the context has `header`, `standardLabel`, `summary` and `packList` (each pack with its status, grade and sorted checks). Templates only read data; the integrity header and the closing sentence are always added around the output.

## Badge

`--format badge` writes a flat SVG, `--format shields` a [shields.io endpoint](https://shields.io/endpoint) document. Both are rendered locally from one run and are **self-reported**: Sealmark does not host a badge or vouch for one, and anyone can edit a file they commit.

- **Label** `sealmark 0.3-draft`: the methodology version is always on the badge.
- **Message** when the run is badge-eligible: one letter per graded pack, in pack order, then `self-reported`, for example `core A · db B · fs A · self-reported` (a run with a provisional grade is not eligible, see below). There is no overall letter; the weakest pack stays visible. The colour follows the worst letter (A bright green, B green, C yellow, D orange, F red).
- **No badge** for a run that is not eligible, in light grey and never with a letter. There are six messages: `no badge: custom run`, `no badge: core only` (no capability pack was graded; it read `hygiene only` before this round, and the report's `(hygiene only)` coverage tag is separate and unchanged), `no badge: provisional` (a grade rests on a critical check nobody could answer), `no badge: nothing graded`, `no badge: server failed`, and `no badge: not eligible` for any other reason (for example a library caller whose run loaded no configuration). This is the same `badge.eligible` the JSON and the text report carry.
- **One server.** With several servers the run exits 2 (`run with --server <name>`).
- Nothing the server wrote reaches the badge: not its name, not a tool name. Only pack ids and letters.

```bash
npx sealmark run --format badge --out-dir badge          # badge/sealmark-report.badge.svg
npx sealmark run --format shields --out-dir badge        # badge/sealmark-report.shields.json
```

Commit the SVG and reference it from your README, or commit the JSON and let shields.io draw it (replace `<owner>` and `<repo>`):

```markdown
![sealmark](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/<owner>/<repo>/main/badge/sealmark-report.shields.json)
```

Commit a fresh badge from CI on your main branch rather than by hand, so it tracks the code.

## Multiple servers and baselines

With `servers:` in the config, `run` goes through the servers one after another (not in parallel) and prints one block per server and a `Matrix:` summary; JSON is `{ "runs": [...] }`. A server that cannot start does not stop the others; it appears as a failed run and the exit code is 4.

A baseline ratchets quality: write one with `--write-baseline base.json`, then run with `--baseline base.json`. A **regression** is a check whose verdict rank dropped (pass > part > fail; `na` and `inconclusive` have no rank and are only noted), a pack whose letter dropped, or a pack that was graded in the baseline and is not graded now. New checks and improvements are never regressions. Regressions print as `regression: ...` on stderr and exit 1. `--fail-on regressions` ignores `--fail-under`, so a server that is already at F can be held at F while it is fixed. `--write-baseline` refuses to overwrite a baseline with a run that regressed. Servers are matched by name; a baseline graded under a different configuration hash is noted.

### Tool-surface drift

A baseline also records what the server offers an agent: `server.surface` in the JSON has, per tool, a hash of the description (the text itself is not stored: it is server-controlled), a hash of the input schema, the required parameters, the type of every parameter and the annotations. Comparing a later run with it prints one `drift:` line per change, after the `baseline:` notes. A description never appears in a line; it says `description changed (sha 3f1a… → 9c02…, 240 → 310 chars)`.

| Severity | Changes |
|---|---|
| breaking | a tool removed, a required parameter added, a parameter removed, a parameter's type changed |
| notable | a tool added, a description changed (the "rug pull": same name, different text for the agent), an annotation hint changed, a schema changed in a way no other kind explains |
| info | an optional parameter added, the server version changed |

Drift is not a grade and never a regression, so by default it only prints, with a `note:` that it does not affect the exit code. `--fail-on drift` makes a breaking or notable change exit 1 (`--fail-on regressions,drift` keeps the regression rule; `--fail-on any,drift` also keeps the gate). `sealmark diff before.json after.json` compares two reports without starting a server, prints `regression:`, `improved:` and `drift:` lines (`--json` for a machine-readable `sealmark.diff/1`) and exits 1 on a regression or a breaking or notable drift. A baseline written by 0.2.0 has no `server.surface`: drift then falls back to tool names and annotations and says so.

```bash
npx sealmark run --write-baseline base.json         # on the version you reviewed
npx sealmark run --baseline base.json --fail-on regressions,drift
npx sealmark diff base.json later.json              # no server is started
```

## CI

**The short version: one command, no config file.** `sealmark init --ci gitlab` (or `github`) prints a job and writes nothing. Edit the `--start` command and `--url`, and paste it:

```yaml
sealmark:
  stage: test
  image: node:24
  script:
    # first, install your server with its own "- ..." line (for example: - npm ci)
    - >
      npx -y sealmark@0.2.2 run
      --start "my-server --port 8000"
      --url http://localhost:8000/mcp
  artifacts:
    when: always
    reports:
      junit: sealmark-report/sealmark-report.junit.xml
```

The command is a YAML folded block (`>`) with one flag per line. To add a flag, add one line below `--url` at the same indentation: `--bearer '${MCP_TOKEN}'`, `--soft-fail`, `--start-timeout 120`, `--header "X-Api-Key: ${KEY}"`. Inside a folded block nothing needs YAML quoting; on a one-line `- npx ...` entry a header such as `--header "Authorization: Bearer x"` is not valid YAML (the `: ` turns the line into a mapping). The printed version (`0.2.1` here) is the version of Sealmark that printed the job: it is pinned on purpose, so bump it when you want a newer one. The GitHub job is the same command as a `run: >` step with `env: MCP_TOKEN: ${{ secrets.MCP_TOKEN }}`.

What the flags do:

- **`--start` + `--url`: launch, wait, test, stop.** Sealmark starts your server, waits until the URL answers, tests it, and stops it. Install your server first; Sealmark does not. `--start` is not run through a shell, so no `&&` and no `VAR=value` prefix (use `sh -c '...'`). Ready means the URL gave a real answer: a 401 counts as up, a 404 (wrong path or another service on the port) or a 5xx (still starting) does not. Something already answering at the URL before the start is an error, so a leftover server is never graded by mistake. A server that exits or never answers within `--start-timeout` (default 60 s) fails the run (exit 4) and shows its last output; Sealmark never carries on after a timeout.
- **A server that is already running: just `--url`.** Auth: `--bearer '${MCP_TOKEN}'` sends `Authorization: Bearer <token>`. Put it in single quotes: Sealmark itself reads `${MCP_TOKEN}` from the environment (`MCP_TOKEN` is a masked CI variable or secret), so the value never appears in the process list or in a report. Other headers: `--header 'Name: ${VAR}'`, repeatable.
- **CI is detected.** When `CI=true` (or `1`; GitLab, GitHub and most CI set it) the `ci` profile is used, and the log says so: a readable summary in the job log (grade cards, a table of checks, what to fix) and JUnit and JSON files in `./sealmark-report/`. The `ci` profile sets no gate of its own: the default gate is A in every profile (next bullet), so a pipeline whose server earns a B now fails. It does count an inconclusive pack as failing (`treat_inconclusive_as: fail`), so a pack that could not be judged fails the job too. The opt-outs are asking for something else: a profile (`--profile standard`, or `profile:` in a file or `SEALMARK_PROFILE`), or any of `--out`, `--format` or `--out-dir`. Gate flags (`--fail-under`, `--soft-fail`) are not opt-outs: they change the exit code, not the output.
- **The default gate is A.** Any graded pack below an A exits 1 and fails the job; so does a provisional `A*`, because a critical check was never answered. To relax it use `--fail-under B` (or C, D, F); to turn the gate off use `--fail-under none`. (Before 0.2.0 there was no gate unless you asked for one.)
- **`--soft-fail`: warn, do not fail.** A grade below the gate prints a warning and exits 0. Config errors, nothing graded and server failures (exit 2, 3, 4) still fail the job. No `allow_failure` is needed in the CI file.
- **`--start` and `--url` must come from the same place** (both flags, both in the same file, or both environment variables). A URL from somewhere else never turns a stdio server into a launched one, and the error says which two to put together.
- **A started server is not sandboxed.** It inherits the whole job environment, so its own settings are plain variables in the CI job (`variables:` / `env:`). Sealmark still injects canary secrets and checks they are not echoed. `http-bind` is not examined for a server Sealmark started itself (a container binding 0.0.0.0 is normal there).
- **Everything above can also live in `sealmark.yaml`** (`server: { command, args, url, headers, start_timeout_sec }`); the file is optional. Config settings also have `SEALMARK_*` environment variables, but flags do not all have one: `--start`, `--header` and `--bearer` are flag or file only (see [Configuration](#configuration)).

### Full control: baselines and your own database

For a ratchet against an earlier report, or a server that needs the seeded database (`db` pack), write the job yourself. No Docker is needed; the default database is an embedded Postgres process. GitHub Actions:

```yaml
name: sealmark
on: [pull_request]
jobs:
  grade:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 24 }
      - run: npm ci                  # installs your server
      - run: npx -y sealmark@0.2.2 run --profile ci --baseline sealmark-baseline.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: sealmark-report, path: sealmark-report/ }
```

The `ci` profile prints the log summary and writes JUnit and JSON into `./sealmark-report/` (with `CI=true` it is chosen for you; naming it keeps the job the same on a laptop). `--baseline` exits 2 when the file does not exist, so create it once on a clean main and commit it: `npx sealmark run --profile ci --write-baseline sealmark-baseline.json`. From then on a pull request fails if any graded pack is below the gate (A by default; add `--fail-under B` to relax it) or regresses against that file; add `--fail-on regressions` to gate on regressions only. To update the baseline after an intended change, run the same `--write-baseline` command again and commit the result. The jobs printed by `init --ci` are checked as valid YAML by the test suite; the project has not run them on a hosted runner yet.

Postgres refuses to run as root, and that only matters when the `db` pack runs (the short `--url` form does not use it: the run output says `db: not used`). With the `db` pack on a GitLab runner whose image runs as root, either use a non-root user, or point at a disposable service container: `--pg "postgres://postgres:ci-only@postgres:5432/postgres" --yes`.

## How the sandbox works

Packs that probe a directory, a repository or a URL run the server inside a disposable sandbox the harness owns: `<tmp>/sealmark-<random>/{root, root-evil, canary, home, tmp, bin}` with the server's working directory set to `root`. The directory is created with mode 0700 on POSIX, so another local user cannot read the canary files or the private HOME (Windows ignores the mode). Canary files live outside `root` and their path is never given to the server. The environment is built from scratch (PATH with the sandbox `bin` first, HOME, USERPROFILE, APPDATA and TEMP pointed into the sandbox, the Windows essentials, then your `server.env` and two canary variables); the one thing inherited is the system PATH, plus `LANG` and shared package-manager caches (`npm_config_cache`, `UV_CACHE_DIR`) so `npx` and `uvx` do not re-download the server for every pack; the sandbox line in the text and markdown reports lists exactly what was inherited (`inherited: PATH (system part), LANG, ...`). Observers snapshot the sandbox directories before and after each probe, a loopback listener records connections, and a process observer finds strays. Cleanup runs on exit and on Ctrl-C, SIGTERM or SIGHUP (a locked file is retried, then reported as `cleaned up: false` with the path). After a signal the harness first stops what is running: it closes the sessions, stops the server, waits up to three seconds for the running pack, starts no further server (the `db` pack does not start the next role), then removes the sandbox, the seed database and the embedded Postgres, including a Postgres that was still starting (its data directory and password file), and sweeps a second time. Every embedded Postgres start is registered from the moment its data directory exists, so a signal during the start is found too: the postmaster is stopped with SIGINT (fast shutdown), then SIGQUIT, and only then SIGKILL, and before its data directory is removed the shared-memory segment named on line 7 of its `postmaster.pid` is released with `ipcrm -m <id>` if it is still there (POSIX; macOS allows 32 SysV segments, and leaked ones would eventually stop every embedded start with "could not create shared memory segment"). Cleanup is bounded (under 12 s); if a directory is still there, or the 15 s limit is reached, it prints `cleanup did not finish: <path> (remove it by hand)`. `sealmark doctor` lists orphaned segments (yours, no attached process, dead creator) and the command to remove them; it removes nothing. A hard kill (SIGKILL) can still leave a temp directory and a segment behind. `--keep-sandbox` skips deletion. `server.files` stages files into it before the server starts (see [Configuration](#configuration)), and `sealmark run --fixture fs|git|sqlite --into <dir>` writes the same layout into a directory you choose, so you can point a server at it by hand and see what the packs see.

**The sandbox is a convention the harness follows, not a security boundary. A malicious server runs with your user's privileges, sees the real file system and network, and can ignore cwd, HOME and PATH. Run untrusted servers in a throwaway VM or container.**

## How the db pack works

1. **Database.** By default the harness starts a real Postgres on `127.0.0.1` (free port, temporary directory, random admin password) using the `embedded-postgres` package, and stops and deletes it at the end. With `--pg <dsn> --yes` it uses your instance instead.
2. **Seed.** It creates `sealmark_seed` (2 tenants with row-level security, 100 customers with synthetic emails, a 200,000-row table, scratch tables) and three roles, `sm_analyst`, `sm_support`, `sm_admin`. There is no bring-your-own-schema.
3. **One server per role.** It starts your server once per role, with `{dsn}` and friends filled in for that role.
4. **Controls first.** Before judging, it checks that each SQL tool can run a basic read and that `SELECT current_user` says `sm_admin`. If it cannot, the affected checks are inconclusive, not passes; tools that fail every control are listed as not covered.
5. **Probes.** Fixed SQL through the SQL tool(s): plain writes, a 19-case mutating-SQL corpus (stacked statements, a transaction-terminator escape for each of `COMMIT`, `ROLLBACK`, `END` and `ABORT`, obfuscation, writable CTEs, a function with side effects in the select list and in the `FROM` clause, `DO` blocks, DDL, `PREPARE`/`EXECUTE` as two calls and as one, session state, `EXPLAIN ANALYZE` of a write), cross-tenant reads as the support role, an email read as the analyst role, a read of the masked view, a 200,000-row select, and a `pg_sleep` past the timeout.
6. **Verification.** Writes and mutations are checked in the database directly over the harness's own superuser connection, not from the server's reply. RLS, masking and the row cap are judged from what the server returned.
7. **Privilege.** The advisory `db-privilege` check opens the three instances one at a time and compares the database backends each one created (and `SELECT current_user`) with the role it was given. A server that reuses a cached connection string connects as the wrong role: the check fails and names the instance, instead of the run reporting only that every check was inconclusive.

`rls` and `pii` test whether the server **defeats** a control the database enforces (for example by connecting as the table owner). A pass does not mean the server implements row filtering or masking itself.

## Safety notes

- **The harness runs your server command**, with your user's privileges, once for `core`, once per role for `db`, and once per other pack. The sandbox confines nothing by force; see above. Do not point sealmark at a server you do not trust outside a throwaway VM.
- **Core sends schema-invalid calls to up to 25 tools** (missing required arguments, wrong types). A tool that does not validate its input may act on the coerced values.
- **Valid-looking arguments go only to targets the harness owns**: the sandbox, canary files, the loopback listener, the seeded database. A tool the classifier cannot classify never gets a well-formed argument. Link-local and private-range addresses are never contacted. A URL tool may still relay the probe values (a token, a loopback address) to the service it wraps, which the harness cannot see: `tools.exclude` keeps such a tool out of the `net` pack.
- **`exec` is opt-in.** It asks a command-running tool to run harness-owned programs from the sandbox `bin`, and runs only with `--active` on the command line (a file or an environment variable cannot switch it on). The CLI prints a warning first.
- **`--pg` runs administrative SQL on your Postgres** and therefore needs a superuser and `--yes`: it runs `DROP DATABASE IF EXISTS sealmark_seed WITH (FORCE)`, creates or alters roles `sm_analyst`, `sm_support` and `sm_admin` with a random per-run password, and terminates any session connected to it. At the end it makes a best-effort attempt to drop them again. The roles are cluster-wide. Use a throwaway or dedicated instance, never a shared or production one.
- **Reports are redacted by default** (sandbox paths, secret-looking values, anything from `sealmark.local.yaml`). Review a report before you share it anyway.
- Do not publish a result for a named third-party server that shows a failure before its maintainer has seen it (see the [disclosure policy](https://sealmark.dev/docs/disclosure/)).

## Troubleshooting

Start with `sealmark doctor`. It checks `node`, `npx`, `uvx` and `git`, resolves your command, starts the server the way `run` does and prints its stderr, runs `initialize` and `tools/list`, prints the classification, and tells you for every pack whether it would run and why not.

**The server fails to start (exit 4).** The message includes the last lines of the server's stderr, and with `--out` the full text is saved to `<out>.stderr.log`. Common causes: the command is not found; the server needs an environment variable that only your shell has (put it in `server.env`: the server gets a scrubbed environment); a first `npx -y ...` has to download the package and the wait is `--connect-timeout` (60 s by default; `doctor` waits 10 s unless you pass the flag, and 60 s for an `npx` or `uvx` launcher whose cache is empty, and says so). The message then reads `the server did not answer initialize within <n> s (--connect-timeout)` and says to run the command once by hand, pin the version, or raise the limit; the same wording is used by `run` and `doctor`; for a server that Sealmark started with `--start` + `--url`, how long the URL gets to answer is `--start-timeout` (60 s by default); a placeholder is misspelled. If the stderr shows `ModuleNotFoundError`, `ImportError` or `Cannot find module`, the hint says the server's dependencies may have drifted and how to pin them.

**A pack says "not graded".** Read the reason. `no tool is classified as taking a file path with medium confidence or higher` means the harness could not tell what the tools take: add `tools.overrides`, or accept that the server gets the `core` checks only. `the sandbox is off` means `--no-sandbox`. The `fs` and `git` packs also need `{sandbox}` in the server config (for `git`, pass `{sandbox}/repo` as the repository argument): a server given a real directory or repository would reach every other one legitimately, so the scope checks could not be measured and the pack says so instead of grading on what is left. A path server that takes no root argument at all has one honest configuration: `server.rootless: true` says its working directory is its root (a server that then reads any path fails the escape checks, which is what it does). A server that answers `sqlite_version()` with another engine's error (a DuckDB-style server) is not graded by the `sqlite` pack; every check is inconclusive and the reason names the engine.

**"no tool takes a SQL string" / "server config has no {dsn}...".** Set `sql_tools` explicitly, and add a placeholder where your server takes its connection string. Without a placeholder the db pack is `n/a` and the exit code is not 3 when `core` graded.

**A check is inconclusive: "control read failed".** The harness ran a basic read that any working setup should answer and did not get the expected result, so it cannot tell a secure server from a broken connection. Look at the evidence line. Inconclusive checks are left out of the score, and an inconclusive critical check marks the grade provisional (`*`). A `net` check that is inconclusive with "a reply that only reports a failed fetch ... is not read as a refusal" means every probe was declined with a message about the mechanism (a proxy, a socket, DNS, "refused to connect") and none said the target was refused: the tool probably cannot fetch at all in this environment, so there is nothing to grade. One that says "a data: URL with no host got the same reply word for word" (`net.ssrf-sametext`) means the tool answered a URL with no address exactly as it answered the loopback ones, so its refusals describe nothing: if the tool is a real fetcher with one constant rejection sentence, set `net.control_url` to a URL it can reach and the harness will see it fetch.

**Embedded Postgres will not start.** The `embedded-postgres` package must be installed (an optional dependency), and Postgres cannot run as root: in a root container use a non-root user or `--pg` with a service Postgres. If the log says "could not create shared memory segment" or "No space left on device", orphaned SysV shared-memory segments from earlier interrupted runs (or a hard kill) are the usual cause: list them with `ipcs -m` and remove yours with `ipcrm -m <id>`; `sealmark doctor` lists the ones that look orphaned (nothing attached, creator gone, under 1 KiB) and removes nothing.

**The fs link check is n/a on Windows.** Creating a file symlink needs Developer Mode or an elevated shell; the junction check always runs.

**`serverInfo.version ... differs from config version`.** The version in your config is a label; the report warns when the server reports another one and, for `npx` and `uvx` servers, shows the package version it found in the package-manager cache (read from files; nothing is executed). The cache can hold several versions of an unpinned package, and Sealmark does not guess which one ran: with one version in the cache that is the one shown; with several, the version the server announced in `serverInfo.version` is used only if it is one of them, and otherwise the report says `resolved package: <name> unknown (several versions in the cache: a, b; the server announced <z>; pin the version)`. When the one cached version differs from a package-style version the server announced, it is still printed with a warning that the cache entry may not be the one that ran. Pin the version in the command to remove the doubt.

## Layout

```
cli/src/cli.ts            command line (thin: parse, load config, call run, render, exit code)
cli/src/commands.ts       init, doctor, config, list-checks, explain, describe, --fixture
cli/src/cli-spec.ts       the table of commands, flags and exit codes (usage text and `describe --json`)
cli/src/run.ts            orchestration: database, sandbox, classification, packs, grading
cli/src/classify.ts       what kind of argument each tool takes
cli/src/sandbox.ts        the disposable sandbox, observers/ for files, listener and processes
cli/src/config/           layered configuration, profiles, integrity (STANDARD/CUSTOM), importer, wizard
cli/src/packs/            core, db, sqlite, fs, git, net, http, effects, exec, custom
cli/src/surface.ts        the tool surface (hashes and types) a run records for drift detection
cli/src/diff.ts           `sealmark diff`: two JSON reports compared without running anything
cli/src/fixtures.ts       `--fixture fs|git|sqlite`; staged-files.ts writes `server.files` into the sandbox
cli/src/report.ts         text and JSON reports; report/ has markdown, junit, sarif, badge, template, redact, baseline, drift, exit
cli/src/toy/              deliberately good and bad toy MCP servers for testing the harness
```

The `dist/toy` directory in the package holds the synthetic servers the test suite uses; they are fixtures, not part of the product surface. Their results say nothing about any real server.

License: Apache-2.0 (see `LICENSE`). The repository is private for now.
