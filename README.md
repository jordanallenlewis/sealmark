<p align="center">
  <a href="https://sealmark.dev/?utm_source=github&utm_medium=readme&utm_campaign=sealmark"><img src="assets/logo.svg" alt="Sealmark logo" width="96" height="96"></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/sealmark"><img src="https://img.shields.io/npm/v/sealmark?label=npm" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/sealmark"><img src="https://img.shields.io/npm/dw/sealmark" alt="npm downloads per week"></a>
  <a href="https://github.com/jordanallenlewis/sealmark/actions/workflows/cli.yml"><img src="https://github.com/jordanallenlewis/sealmark/actions/workflows/cli.yml/badge.svg?branch=main" alt="CLI tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
</p>

# Sealmark

**Every row where it belongs.**

Sealmark is a behavioral conformance test harness for MCP servers. It starts your server, calls its tools with fixed inputs (no LLM in the loop), checks what actually happened, and prints a letter grade per area with the evidence behind every check.

An agent-facing server is easy to configure and hard to trust: read-only flags, row-level security, path checks and masking are set once and assumed to hold. Sealmark tests whether they do, the way an agent would use them.

> **An A means the server passed these specific, published probes with this exact configuration. It is not a security endorsement.** Every report says what was not covered.

Status: CLI 1.0.0, methodology `0.3-draft` (not released yet: checks and thresholds can still change before methodology 1.0, and a 0.2-draft report cannot be replayed under it). What changed: [`CHANGELOG.md`](CHANGELOG.md).

## Quickstart

Requires Node 22.13 or newer. No Docker, no account.

```bash
npx sealmark init     # imports servers from your MCP clients, or writes a template
npx sealmark doctor   # can Sealmark start your server? which packs would run?
npx sealmark run      # grade it
```

In CI, one command is enough: `npx sealmark run --fail-under B`. See [`cli/README.md`](cli/README.md) for every command and flag.

## What a report looks like

```
sealmark 1.0.0 · methodology 0.3-draft · STANDARD · toy-nosql 0.0.1

stdio server, 2 tool(s): echo, add
sandbox: {sandbox_dir} · env scrubbed · listener 127.0.0.1:{listener_port} · cleaned up

PACK core  GRADE A  (4/4 points, 100%)  hygiene only · tools called with valid arguments: 0 of 2
  [PASS] Valid MCP handshake and tool schemas — handshake ok, 2 well-formed tool(s)
  ...

PACK db  not graded: server config has no {dsn}/{host}/... placeholder, ...

Badge: not eligible: core-only run: no capability pack was graded.

Not covered:
  - tool "echo" is covered by the core checks only: ...
```

Abridged, from one of the test suite's toy servers (a fixture: its result says nothing about any real server). Worst verdicts print first; every line has a tag (`[PASS]`, `[PART]`, `[FAIL]`, `[INCL]`, `[N/A ]`) and its evidence. Real results for public servers, with the full evidence, are at [sealmark.dev/results](https://sealmark.dev/results/). How to read every part: [Reading the report](cli/README.md#reading-the-report).

## Quick answers

- **What is Sealmark?** An open-source (Apache-2.0) command-line tool that tests how an MCP server behaves: it starts the server, calls its tools with fixed inputs, checks what happened, and grades each test suite A to F with evidence. No language model is involved.
- **How do I run it?** `npx sealmark run --start "<command that starts your server>"` (Node 22.13 or newer).
- **How is it different from the MCP Inspector or the official conformance framework?** Those are made by the MCP project: the Inspector is for exploring a server interactively, the conformance framework checks protocol compliance. Sealmark grades what a server's tools do (writes, SQL, files, network, secrets). They complement each other; the [comparison](https://sealmark.dev/compare/) says where Sealmark is weaker.
- **Can I run it in CI?** Yes: `sealmark run --fail-under B` sets the exit code, and the [GitHub Action](action/README.md) uploads SARIF to code scanning.
- **Where are real results?** [sealmark.dev/results](https://sealmark.dev/results/): one page per graded public server, each re-tested automatically.
- **Does an A mean the server is secure?** No. It means these published probes passed with this configuration.

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

## Usage counter (off by default)

Sealmark sends nothing unless you set `SEALMARK_TELEMETRY=1`. With it set, each command sends one ping when it finishes, and prints the exact JSON to stderr first:

```json
{"schema":1,"sealmark":"1.0.1","command":"run","node":22,"os":"linux","ci":false}
```

That is the CLI version, the command name, the Node major version, the OS family and whether `CI` is set. It never includes the server under test, its tools, your config, paths, results, hostnames or any identifier. The ping goes to `https://sealmark.dev/api/ping` (override with `SEALMARK_TELEMETRY_URL`), times out after 2 seconds, and a failure never changes the exit code. `DO_NOT_TRACK=1` turns it off even when `SEALMARK_TELEMETRY=1` is set. The code is `cli/src/telemetry.ts`.

## Repository layout

| Path | What |
|---|---|
| `cli/` | The harness and the `sealmark` command (TypeScript, Node 22.13+) |
| `action/` | The composite GitHub Action that runs Sealmark in a workflow |
| `docs/` | Architecture, methodology and CI design |
| `CHANGELOG.md` | What changed in each CLI release and methodology draft |

The `dist/toy` directory in the npm package holds the synthetic servers the test suite uses; they are fixtures, not part of the product surface.

Develop: `cd cli && npm run typecheck && npm test`.

The website, its docs and the published results live at [sealmark.dev](https://sealmark.dev/?utm_source=github&utm_medium=readme&utm_campaign=sealmark).

## Documents

- [Architecture](docs/architecture.md): how it works and why
- [Methodology](docs/methodology.md): what every check does, its probes and known blind spots
- [CI design](docs/ci-design.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
