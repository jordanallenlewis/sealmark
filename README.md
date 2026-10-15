# Sealmark

**Every row where it belongs.**

Sealmark is a behavioral conformance test harness for MCP servers. It starts your server, calls its tools with fixed inputs (no LLM in the loop), checks what actually happened, and prints a letter grade per area with the evidence behind every check.

An agent-facing server is easy to configure and hard to trust: read-only flags, row-level security, path checks and masking are set once and assumed to hold. Sealmark tests whether they do, the way an agent would use them.

> **An A means the server passed these specific, published probes with this exact configuration. It is not a security endorsement.** Every report says what was not covered.

Status: CLI 0.2.2, methodology `0.3-draft` (checks and thresholds can still change before 1.0; 0.3-draft is not released yet, and a 0.2-draft report cannot be replayed under it). Source repo is private for now.

What 0.3-draft changes. It is one methodology change, regenerated in one commit so it can be accepted or rejected as one unit (see [`docs/methodology.md`](docs/methodology.md), "What changed in 0.3-draft"):

- **Verdicts:** `net-redirect` is a scored, non-critical standard check. `tool-poisoning` flags terminal control characters (ESC, NUL and C1 strong; other C0 controls and DEL weak). `fs-read-escape` and `fs-write-escape` are inconclusive when no escape probe was answered. `exec-timeout-cap` confirms a "killed" reply against the process table. A refused no-argument call no longer counts as a valid call. The `db` mutating-SQL corpus has 19 cases (the transaction terminators `COMMIT`, `ROLLBACK`, `END` and `ABORT` are all probed), and the advisory candidate `db-privilege` checks that each instance connects as the role it was given.
- **Exit policy:** the `ci` profile counts an inconclusive pack as failing, and a provisional `A*` does not meet `--fail-under A`.
- **Reports and config:** one tag per check line (advisory checks end with `(advisory, not scored)`), one score fraction (points over scored checks) in every format, `{listener_port}` in the text sandbox line, and `sealmark config show` opens with `# STANDARD` or `# CUSTOM`. `retries.call` is accepted and ignored.
- **Second verification round (the same unit):** `net-loopback-ssrf` and `net-scheme-allowlist` accept a refusal only when it ties itself to the target (a reply that only reports a failed fetch, such as a proxy, socket or DNS error, is not a refusal), and the loopback corpus gains an IPv4-mapped IPv6 spelling. The `fs-write-escape` corpus mirrors the read corpus (percent-encoded, `file://` and dot-slash forms). The `git` fixture stages a change and plants a link, and the `git` pack needs `{sandbox}` in the config, like `fs`. `sqlite-extension-load` retries with a form the tool accepts, and `sqlite-file-read` follows a writer's `ATTACH` through the controlled reader. Coverage counts only calls the server processed (a reply that reports a failed upstream request, a schema-validation rejection and an errored control call do not count). A run with custom checks or plugins gets its own `config.hash`. A resolved package version is reported as `unknown` rather than guessed.
- **Third verification round (the same unit):** a refusal now rests on what the harness observed more than on words. A transport failure such as "refused to connect" is never a refusal; a tool whose loopback probes were all refused with nothing observed behind them is also sent a URL with no host, and if that gets the same sentence the check is inconclusive until `net.control_url` names a URL the tool fetches. `tool-poisoning` scans the server instructions and `serverInfo`, and `protocol` reports non-JSON-RPC output on stdout. The `sqlite` pack confirms the engine with `sqlite_version()` and says so when a server is not SQLite (DuckDB is not graded), and its file checks try the single-call, stacked and copy-into-fixture forms. The `db` pack grades a SQL tool that has another required parameter (`sql_tools[].args` fills the ones a token cannot satisfy). `git-repo-scope` probes with relative paths and judges write tools by observation, and an unjudged read tool makes it `part` at any confidence. The `fs` corpus gains array, backslash, move-through-link, dangling-link and edit-tool families, and `server.rootless: true` grades a server that takes no root argument. A correctly guarded URL tool can now be green under the `ci` profile: `effects` is `n/a` for it. See [`docs/methodology.md`](docs/methodology.md), "Round 5".
- **Also in this build (CLI 0.2.2):** tool-surface drift detection (`--fail-on drift`, `sealmark diff`), a self-reported README badge (`--format badge`), `--fixture fs|git|sqlite`, and the classifier and corpus fixes for `fs`, `git`, `net` and `sqlite`.

The `dist/toy` directory in the npm package holds the synthetic servers the test suite uses; they are fixtures, not part of the product surface.

## Quickstart

Requires Node 22.13 or newer. No Docker, no account.

```bash
npx sealmark init     # imports servers from your MCP clients, or writes a template
npx sealmark doctor   # can Sealmark start your server? which packs would run?
npx sealmark run      # grade it
```

In CI, one command is enough: `npx sealmark run --fail-under B`. See [`cli/README.md`](cli/README.md) for every command and flag.

## What it checks

Sealmark runs `core` on any server, and deeper packs when it can give the server a target it owns:

| Pack | Looks at |
|---|---|
| `core` | handshake and schemas, tool-poisoning indicators, malformed-input survival, secret echo (hygiene only) |
| `db`, `sqlite` | read-only by default, row-level security, mutating SQL (a 19-case corpus), personal-data masking, row cap and timeout; `db` also checks, as an advisory candidate, that each instance connects as the role it was given |
| `fs`, `git` | path and link escapes, repository scope, argument injection |
| `net` | loopback SSRF, scheme allowlist, response caps, redirect re-validation |
| `http` | origin, auth, protocol version, sessions, CORS |
| `effects` | whether `readOnlyHint` and `openWorldHint` are honest |
| `scope`, `sql-guard`, `upstream` (candidate packs) | for a server that fronts a backend, through a harness-owned upstream stub: identifiers outside a declared scope, forbidden SQL and out-of-scope references reaching the backend, the row cap, whose credential reaches the backend, tokens in replies and logs, relayed error bodies, a slow backend. Scored in their own pack, not part of the standard profile or the badge |
| `exec` (opt-in `--active`), `custom`, plugins | command injection; your own probes and packs |

## How it works

```
 config (flags, env, files) ──▶ STANDARD or CUSTOM
                                      │
   seed database ◀── run ──▶ sandbox (temp tree, scrubbed env, loopback listener)
        │              │                    │
        │              ▼                    │
        │     server under test ◀── classifier: what kind of argument does each tool take?
        │              │                    │
        └── observers: database state · file diff · listener hits · process list · upstream requests · server log ──┘
                       │
                  packs ask, observers answer ──▶ verdicts ──▶ grade ──▶ reports + exit code
```

1. **The harness owns the world the server runs in**: a seeded Postgres (or SQLite) database with row-level security and three roles, a temporary file tree with a canary the server is never told about, a loopback listener, and, for a server that fronts a backend, a loopback upstream stub that plays the backend and records every request. Nothing real is touched.
2. **A classifier decides which tools each pack may probe.** It looks at parameter names, types and descriptions. Low-confidence tools only receive schema-invalid input; the harness never sends a valid-looking call to a tool it could not classify.
3. **Packs send fixed probes; observers record what happened.** The verdict comes from side effects: a database read over a separate connection, a before-and-after diff of the sandbox, a connection to the listener. A server that says "rejected" and still writes the row fails.
4. **Grading is a small pure function.** Pass is 1 point, partial 0.5, fail 0. A, B, C and D start at 90, 75, 60 and 45 percent. A failed critical check caps the grade at D. Checks the harness could not judge are left out and mark the grade provisional (`A*`), and a provisional A does not meet an A gate. Nothing scored means no grade, never an invented one.
5. **Every run records its configuration.** A run is STANDARD only if every grade-affecting setting equals the published profile; anything else is CUSTOM, with the differences listed.

## Why it is built this way

- **No LLM in the loop**, so the same server version and configuration give the same result anywhere, and a maintainer can reproduce any line of evidence. Two runs of the same server produce the same verdicts and evidence. Text, markdown, summary, badge and shields output is byte-identical at every verbosity. In the JSON exactly three of the harness's own fields differ, `startedAt`, `durationMs` and `sandbox.listenerPort` (four with an upstream stub: `upstream.url`; and each valid call's measured `elapsedMs` when `probes:` are declared); JUnit and SARIF differ in the same fields plus the SARIF `startTimeUtc`, and any timing the server itself prints inside an excerpt can differ in those three formats. One harness-measured number can differ in every format: how many bytes the net pack's listener had sent when a server hung up early on the oversized reply, printed as `under N of 64 MiB` with N rounded up to a power of two from 8. The harness's per-run random tokens (also inside a file name or a control value), commit ids, sandbox paths (including a truncated echo and the `file://localhost/` and percent-encoded forms) and listener port appear as `{token}`, `{sha}`, `{sandbox}`, `{listener_port}` and similar names in redacted reports, in every spelling and position (`--no-redact` keeps the real values).
- **Run the server, don't read its schema.** A schema says what a tool accepts. Only a call shows whether read-only mode stopped the write.
- **Observe, don't trust.** Responses are the easiest thing for a faulty server to get wrong; database state, file diffs and network hits are not.
- **Own the world, stay safe.** Probes only point at resources the harness created, so a probe cannot damage anything real and canaries are recognizable anywhere they leak.
- **Honest labels over big numbers.** Provisional grades, a coverage level, STANDARD versus CUSTOM, and a printed list of what was not covered.
- **Simple for a normal engineer.** One command, optional config, every setting reachable by flag, environment variable or file, errors that say what to type next.
- **Modular.** Each area is a pack with the same three-method interface; new coverage does not touch the engine.

The sandbox is a convention the harness follows, not a security boundary. A malicious server runs with your privileges, so run unfamiliar servers in a throwaway VM or container. A URL tool may also relay the probe values (a token, a loopback address) to the service it wraps, which the harness cannot see; `tools.exclude` keeps a tool out of the `net` pack. A run stopped by Ctrl-C cleans up first (including the embedded Postgres and its shared-memory segment) and ends with `sealmark exit 130: interrupted`.

For the full design (run lifecycle, components, verdict model, trust model, and the alternatives that were rejected and why), read **[`docs/architecture.md`](docs/architecture.md)**.

## Repository layout

| Path | What |
|---|---|
| `cli/` | The harness and the `sealmark` command (TypeScript, Node 22.13+) |
| `action/` | The composite GitHub Action that runs Sealmark in a workflow |
| `docs/` | Architecture, methodology and CI design |

Develop: `cd cli && npm run typecheck && npm test`.

The website, its docs and the published results live at [sealmark.dev](https://sealmark.dev).

## Documents

- [Architecture](docs/architecture.md): how it works and why
- [Methodology](docs/methodology.md): what every check does, its probes and known blind spots
- [CI design](docs/ci-design.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
