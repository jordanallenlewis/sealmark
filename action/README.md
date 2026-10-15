# Sealmark GitHub Action

Runs Sealmark against an MCP server in a job, writes the summary, JSON, JUnit and SARIF reports, uploads the SARIF to code scanning and the report directory as a workflow artifact, and fails the job exactly when the CLI does.

It is a composite action: `action.yml` plus `run.mjs` (plain Node, no dependencies). Nothing here is published; the files live in the repository only.

## Use it

```yaml
name: sealmark
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for the SARIF upload; drop it with upload-sarif: 'false'

jobs:
  sealmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a commit SHA
      - uses: <owner>/sealmark/action@main
        with:
          start: npx -y my-mcp-server
          pack: core
```

Two things must be true before this works for anyone:

- The repository must be public. A `uses:` line cannot reach an action in a private repository of another owner.
- The pinned `version` input (default `0.2.2`) must be on npm first. The action runs `npx -y sealmark@<version>`, so `uses:` fails until that version is on npm. Set `version` to one that is. The default tracks `cli/package.json`; whenever the owner bumps the CLI version label (for methodology 0.3-draft the recommended label is `0.3.0`), the `version` default in `action.yml` and the `0.2.1` in the table below move with it.

With neither `start`, `url` nor `config` the action exits 2 and says `sealmark action: set start and url (or config)`.

## Inputs

All inputs are optional. A flag the CLI has a default for keeps that default when you leave the input empty.

| Input | Default | What it does |
|---|---|---|
| `version` | `0.2.2` | Sealmark version run through `npx -y sealmark@<version>`. |
| `start` | | Command that starts the server (`--start`). |
| `url` | | URL of a Streamable HTTP server (`--url`). |
| `config` | | Path to a `sealmark.yaml` (`--config`). |
| `pack` | | Packs to run, comma separated: `core,fs` becomes `--pack core --pack fs`. |
| `fail-under` | | Lowest passing letter, or `none` (`--fail-under`). The CLI default is A. |
| `soft-fail` | `false` | `true` adds `--soft-fail`: a grade below the gate warns and exits 0. |
| `baseline` | | Earlier JSON report to compare with (`--baseline`). |
| `write-baseline` | | Write the JSON report here for the next run (`--write-baseline`). |
| `fail-on` | | What decides the exit code with a baseline: `any`, `regressions`, `drift`, comma separated (`--fail-on`). |
| `bearer-env` | | The name of an environment variable that holds a bearer token. See below. |
| `args` | | Extra Sealmark flags, split on whitespace; `"double"` and `'single'` quotes group words. Never run through a shell. |
| `report-dir` | `sealmark-report` | Directory for the report files, relative to `working-directory`. |
| `upload-sarif` | `true` | Upload the SARIF file to code scanning. |
| `artifact` | `true` | Keep the report directory as an artifact named `sealmark-report`. |
| `node-version` | `24` | Node version for `actions/setup-node`. Sealmark needs 22.13 or newer. |
| `working-directory` | `.` | Directory to run in. |

The action always adds `--format summary,json,junit,sarif --out-dir <report-dir>`. The summary prints in the job log; the other three are files: `sealmark-report.json`, `sealmark-report.junit.xml` and `sealmark-report.sarif`.

## Outputs

| Output | Value |
|---|---|
| `exit-code` | The exit code of `sealmark run`. |
| `report-dir` | Absolute path of the report directory. |
| `json` | Absolute path of the JSON report; empty when it was not written. |
| `sarif` | Absolute path of the SARIF report; empty when it was not written. |
| `junit` | Absolute path of the JUnit report; empty when it was not written. |
| `summary` | One line of graded packs, for example `core A · db B`. Several servers read `a: core A | b: core B`; a server that did not start reads `failed`. |

The one-line summary is also appended to the job summary page under `## Sealmark`.

## Permissions

```yaml
permissions:
  contents: read
  security-events: write
```

`security-events: write` is only for the SARIF upload. On a private repository, code scanning needs GitHub Code Security. Without it the upload step fails; the JUnit and JSON files and the artifact still work. Set `upload-sarif: 'false'` to skip the step, and use the artifact or a JUnit reporter instead.

## A bearer token without a token in the log

`bearer-env` is the name of a variable, never its value:

```yaml
- uses: <owner>/sealmark/action@main
  env:
    MCP_TOKEN: ${{ secrets.MCP_TOKEN }}
  with:
    url: https://mcp.example.com/mcp
    bearer-env: MCP_TOKEN
```

The action passes the literal text `--bearer ${MCP_TOKEN}` and Sealmark reads the variable from its own environment. The token is never in a command line, and the action never prints an environment value. A name that is not a plain variable name (a pasted token, for instance) is refused with exit 2 without echoing it.

## Exit codes

The job fails exactly when the CLI does: the step exits with Sealmark's own code (0 pass, 1 grade below the gate or a regression, 2 usage or config error, 3 nothing graded, 4 server or harness failure; a signal counts as 4). `soft-fail: 'true'` softens exit 1 the way `--soft-fail` does. The report files are written either way, and the SARIF and artifact steps run after a failure (`if: always()`).

## Not verified

No network and no GitHub runner were available when this was written.

- The `upload-sarif` step, the `security-events: write` permission and the private-repository requirement are as GitHub documents them, not tested here.
- `codeql-action/upload-sarif@v3` and `upload-artifact@v4` are tags, not commit SHAs, because a SHA cannot be looked up offline and must not be invented. Pin both before relying on the action (an owner action: it needs network access to resolve the SHAs). `setup-node` uses the SHA the CLI workflow already uses.
- `run.mjs` is tested locally against the toy servers through `SEALMARK_ACTION_BIN` (the tests in `cli/src/test/action.test.ts`), not through `npx` and not on Windows (it calls npm's `npx-cli.js` there, since Node cannot spawn `npx.cmd` without a shell).
- `--format summary` next to other formats prints to the console and writes no `sealmark-report.summary.txt`, so the job summary page holds the one-line grade, not the full text.
- A Marketplace listing needs `action.yml` at the root of a separate public repository. This directory does not do that.
