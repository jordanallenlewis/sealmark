# Sealmark GitHub Action

Runs Sealmark against an MCP server in a job, writes the summary, JSON, JUnit and SARIF reports, uploads the SARIF to code scanning and the report directory as a workflow artifact, and fails the job exactly when the CLI does.

It is a composite action: `action.yml` plus `run.mjs` (plain Node, no dependencies). It is used straight from this repository (`uses: jordanallenlewis/sealmark/action@<tag>`); it is not listed on the GitHub Marketplace.

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
      - uses: jordanallenlewis/sealmark/action@v1.0.1   # or pin a commit SHA
        with:
          start: npx -y my-mcp-server
          pack: core
```

One thing must be true before this works:

- The pinned `version` input (default `1.0.1`) must be on npm first. The action runs `npx -y sealmark@<version>`, so `uses:` fails until that version is on npm. Set `version` to one that is. The default tracks `cli/package.json`: when the CLI version moves, the `version` default in `action.yml` and in the table below move with it.

With neither `start`, `url` nor `config` the action exits 2 and says `sealmark action: set start and url (or config)`.

## Inputs

All inputs are optional. A flag the CLI has a default for keeps that default when you leave the input empty.

| Input | Default | What it does |
|---|---|---|
| `version` | `1.0.1` | Sealmark version run through `npx -y sealmark@<version>`. |
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
| `badge` | `auto` | `auto` also writes the self-reported badge (`sealmark-report.badge.svg`, `sealmark-report.shields.json`) when the run grades one server: `start` or `url` without `config`, or `--server <name>` in `args`. `true` always asks for them (the CLI exits 2 for several servers); `false` never. See [Badge](#badge). |
| `badge-id` | | A sealmark.dev server id (`https://sealmark.dev/results/<id>/`): fills the `badge-markdown`, `badge-html` and `badge-rst` outputs and the job summary with that badge. Nothing is fetched. |
| `comment` | `false` | `true` writes a pull request comment to `sealmark-report.comment.md` and, on a `pull_request` event, posts it or updates the one this action posted before. See [PR comment](#pr-comment). |
| `github-token` | `${{ github.token }}` | Token for the PR comment. Only the comment step gets it, after Sealmark and the server have exited. |
| `node-version` | `24` | Node version for `actions/setup-node`. Sealmark needs 22.13 or newer. |
| `working-directory` | `.` | Directory to run in. |

The action always adds `--format summary,json,junit,sarif --out-dir <report-dir>` (with `badge,shields` added to the list when `badge` is on). The summary prints in the job log; the other three are files: `sealmark-report.json`, `sealmark-report.junit.xml` and `sealmark-report.sarif`.

## Outputs

| Output | Value |
|---|---|
| `exit-code` | The exit code of `sealmark run`. |
| `report-dir` | Absolute path of the report directory. |
| `json` | Absolute path of the JSON report; empty when it was not written. |
| `sarif` | Absolute path of the SARIF report; empty when it was not written. |
| `junit` | Absolute path of the JUnit report; empty when it was not written. |
| `summary` | One line of graded packs, for example `core A · db B`. Several servers read `a: core A | b: core B`; a server that did not start reads `failed`. |
| `badge` | Absolute path of the self-reported badge SVG; empty when it was not written. |
| `shields` | Absolute path of the self-reported shields.io endpoint document; empty when it was not written. |
| `badge-text` | What this run's self-reported badge says, for example `sealmark 0.3-draft: core A · fs B · self-reported` or `sealmark 0.3-draft: no badge: core only` (the label carries the methodology of the pinned CLI); empty when this run wrote none. |
| `badge-markdown` | With `badge-id`: the Markdown snippet for the sealmark.dev badge. Empty otherwise. |
| `badge-html` | With `badge-id`: the HTML snippet. Empty otherwise. |
| `badge-rst` | With `badge-id`: the reStructuredText snippet (three lines). Empty otherwise. |
| `comment` | With `comment`: absolute path of the comment Markdown. Empty otherwise. |
| `comment-url` | With `comment` on a pull request: the URL of the posted or updated comment. Empty when nothing was posted. |

The one-line summary is also appended to the job summary page under `## Sealmark`, followed by a `### Badge` section when there is a badge to show.

## Badge

Two different badges, never mixed:

- **Self-reported** (`badge`): the run's own badge, the same SVG and shields.io document as `sealmark run --format badge,shields`. Its message ends in `self-reported`, and a run that is not badge-eligible gets a grey `no badge: <reason>`. It lands in the report directory and the artifact; to show it in a README, commit one from a run on your main branch (the CLI README, "Badge", has the snippet). `badge-text` says what it reads. Old badge files in the report directory are removed before the run, so the outputs always describe this run.
- **sealmark.dev** (`badge-id`): the badge the public fleet's grade earns at `https://sealmark.dev/results/<id>/`. The snippets are the ones that page's copy buttons give (and `sealmark badge --id <id>` prints from the next CLI release). The image exists only while that server's latest fleet run earns a badge (the results page then shows one); for any other server, a graded one with a core-only or provisional result included, it is a 404. The action builds the text and fetches nothing, so check the page first.

```yaml
- uses: jordanallenlewis/sealmark/action@v1.0.1
  id: sealmark
  with:
    start: npx -y my-mcp-server
    badge-id: my-mcp-server
- run: echo "$BADGE_TEXT"   # through env, never ${{ }} inside run:
  env:
    BADGE_TEXT: ${{ steps.sealmark.outputs.badge-text }}
```

The `badge` and `badge-id` inputs are newer than the `v1.0.1` tag the examples pin: until a tag that includes them exists, pin a commit SHA of `main` to use them.

## PR comment

`comment: 'true'` puts the result on the pull request, so a reviewer sees it without opening the job:

```yaml
on: pull_request

permissions:
  contents: read
  pull-requests: write   # for the comment

jobs:
  sealmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a commit SHA
        with:
          persist-credentials: false   # keeps the token out of .git/config, where the server could read it
      - uses: jordanallenlewis/sealmark/action@v1.0.1
        with:
          start: npx -y my-mcp-server
          comment: 'true'
          upload-sarif: 'false'
          baseline: sealmark-baseline.json   # optional: a JSON report committed from main
```

The comment holds a table of each server and its graded packs, what the exit code means, and with `baseline` a count and the lines of every regression, improvement, note and tool-surface change (what `sealmark diff --json <baseline> <this run>` says). It ends with a link to the job and says the grades are self-reported, from this job's own run, not the sealmark.dev fleet grade.

- **One comment per pull request.** Its first line is `<!-- sealmark-action:comment -->`; a later run updates that comment in place. The action only edits a comment that starts with that line and was written by its own token (with the default token, a bot account such as `github-actions[bot]`); a person's comment that quotes the line is left alone.
- **One comment per job step.** Two Sealmark steps with `comment: 'true'` on the same pull request (a matrix, or two servers in two steps) update the same comment and the last one wins. Grade several servers in one step with a `config` instead: the comment has a row for each.
- **It never changes the exit code.** A token that may not comment (a pull request from a fork gets a read-only token, or `pull-requests: write` is missing) prints a warning and the job keeps Sealmark's own exit code. The body is always written to `sealmark-report.comment.md`, so a separate job with more rights can post it.
- **Not on a pull request** (`push`, `schedule`): the body is written, nothing is posted.
- **Keep the token away from the server.** Sealmark and the server under test run in a step without the token. A separate step, which runs only with `comment: 'true'` and after they have exited, gets `github-token` and posts the file. This is not a sandbox against a hostile server: a process the server starts in a new session, with a working directory outside the sandbox, can outlive the run step and the CLI's cleanup. It runs as the same user, so it can read the comment step's environment, and it can change files under the action's directory before that step runs them. For a server you do not trust, run the comment in a separate job: upload the `sealmark-report` directory as an artifact in the job that runs the server, and let a second job (which never starts the server) download it and run the comment step. The same holds for a personal access token passed as `github-token`: it is exposed to the same degree as the default token. Check out with `persist-credentials: false` as above: otherwise `actions/checkout` leaves the same token in `.git/config`, where the server can read it, and `pull-requests: write` goes with it.
- **Server text stays inert.** Server, tool and check names come from the server under test. In the comment they only appear inside code, cut to one line, so they cannot mention anyone, add a link or an image, or break the table.
- **Never on `pull_request_target`.** It runs with the base repository's rights, and grading a fork's server code there would hand them to it; the action writes the body and posts nothing on that event. For forks, post the file from a separate `workflow_run` job that does not run the fork's code.

The `comment` input is newer than the `v1.0.1` tag the examples pin: until a tag that includes it exists, pin a commit SHA of `main` to use it.

## Badge job

A workflow you can copy into your own repository (for example `.github/workflows/sealmark-badge.yml`): it grades the server on every push to `main` and once a week, and keeps the self-reported badge on a branch of its own, so your README always shows the latest run. Two jobs: the one that runs the server can only read the repository, and the one that can push runs no server code.

```yaml
name: sealmark-badge
on:
  push:
    branches: [main]
  schedule:
    - cron: '17 4 * * 1'
  workflow_dispatch:

permissions:
  contents: read

concurrency: sealmark-badge

jobs:
  grade:
    runs-on: ubuntu-latest
    outputs:
      badge: ${{ steps.sealmark.outputs.badge }}
    steps:
      - uses: actions/checkout@v4   # pin to a commit SHA
        with:
          persist-credentials: false   # no token on disk while the server runs
      - uses: jordanallenlewis/sealmark/action@v1.0.1
        id: sealmark
        with:
          start: npx -y my-mcp-server
          badge: 'true'
          fail-under: none          # publish whatever the grade is
          upload-sarif: 'false'
          artifact: 'false'
      - uses: actions/upload-artifact@v4   # pin to a commit SHA
        if: steps.sealmark.outputs.badge != ''
        with:
          name: sealmark-badge
          path: |
            ${{ steps.sealmark.outputs.badge }}
            ${{ steps.sealmark.outputs.shields }}

  publish:
    needs: grade
    if: needs.grade.outputs.badge != ''
    runs-on: ubuntu-latest
    permissions:
      contents: write   # pushes the badge; this job runs no server code
    steps:
      - uses: actions/checkout@v4   # pin to a commit SHA
      - uses: actions/download-artifact@v4   # pin to a commit SHA
        with:
          name: sealmark-badge
          path: ${{ runner.temp }}/badge
      - name: Publish the badge
        env:
          GIT_AUTHOR_NAME: github-actions[bot]
          GIT_AUTHOR_EMAIL: 41898282+github-actions[bot]@users.noreply.github.com
          GIT_COMMITTER_NAME: github-actions[bot]
          GIT_COMMITTER_EMAIL: 41898282+github-actions[bot]@users.noreply.github.com
        run: |
          if git fetch --depth=1 origin sealmark-badge; then git switch -c sealmark-badge FETCH_HEAD; else git switch --orphan sealmark-badge; fi
          cp "$RUNNER_TEMP"/badge/sealmark-report.badge.svg "$RUNNER_TEMP"/badge/sealmark-report.shields.json .
          git add sealmark-report.badge.svg sealmark-report.shields.json
          git diff --cached --quiet && exit 0   # the same badge as last time
          git commit -q -m "sealmark badge"
          git push origin sealmark-badge
```

Then, in the README (replace `OWNER/REPO`):

```markdown
![Sealmark](https://raw.githubusercontent.com/OWNER/REPO/sealmark-badge/sealmark-report.badge.svg)
```

or, through shields.io: `https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/sealmark-badge/sealmark-report.shields.json`.

- `fail-under: none` keeps the job green whatever the letter, so the badge always says what the last run found, a bad grade included. Keep a separate gated job for pull requests.
- The branch holds only the two badge files, one commit per change; nothing else belongs on it.
- A run that is not badge-eligible (a custom configuration, a core-only result) gets the grey `no badge: <reason>` image. That is the honest result, not a failure of the job.
- Keep `persist-credentials: false` and `contents: read` on the job that runs the server: with the default checkout, the job token sits in `.git/config` where the server could read it.
- `badge: 'true'` needs one server: `start` or `url`, or `--server <name>` in `args` with a `config`.

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
- uses: jordanallenlewis/sealmark/action@v1.0.1
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
- The PR comment is tested against a stand-in for the GitHub REST API (`cli/src/test/action.comment.test.ts`), not on a real pull request, and the badge job above has not run on GitHub.
- `run.mjs` is tested locally against the toy servers through `SEALMARK_ACTION_BIN` (the tests in `cli/src/test/action.test.ts`), not through `npx` and not on Windows (it calls npm's `npx-cli.js` there, since Node cannot spawn `npx.cmd` without a shell).
- `--format summary` next to other formats prints to the console and writes no `sealmark-report.summary.txt`, so the job summary page holds the one-line grade, not the full text.
- A Marketplace listing needs `action.yml` at the root of a separate public repository. This directory does not do that.
