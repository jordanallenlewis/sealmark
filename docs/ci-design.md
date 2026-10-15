# CI ergonomics: design (2026-10-09)

Principle (owner): a normal person configures Sealmark in CI **without AI help and without extra files**.
The whole setup lives in the CI file. A `sealmark.yaml` stays optional for people who want everything in one place.
Simple by default, every setting still reachable.

## What 13 comparable tools do (official docs; research notes, not Sealmark behaviour)

| Question | Finding | Sources |
|---|---|---|
| Shortest job | Semgrep `semgrep ci` (3 lines), Schemathesis (1 script line + options), Playwright GitLab (7 lines) | docs.semgrep.dev/semgrep-ci/sample-ci-configs, schemathesis.readthedocs.io guides/cicd, playwright.dev/docs/ci |
| Start vs attach | Playwright `webServer.command` + `url`, Lighthouse CI `collect.startServerCommand`, Dredd `--server`. Conformance runner, Hurl, k6, Schemathesis only attach | playwright.dev/docs/test-webserver, googlechrome.github.io/lighthouse-ci/docs/configuration.html, dredd.org |
| Readiness | Playwright: URL answering 2xx/3xx/400-403 counts as ready (so an auth-gated endpoint's 401 is fine), default 60 s. Lighthouse: stdout regex, and it **continues after the timeout** (a trap). Dredd: fixed sleep (weak). Schemathesis `--wait-for-schema 60` polls the real artifact | same |
| Gating | One soften flag is common: Checkov `--soft-fail`, Newman `-x`, ZAP `-I`. Lighthouse `off/warn/error` per assertion. Schemathesis and Hurl keep "could not run" (exit 2/3) apart from "found a problem" (exit 1/4) | checkov.io, github.com/postmanlabs/newman, zaproxy.org/docs/docker/baseline-scan, schemathesis cli reference |
| Log output | Human summary on the console by default, machine reports as extra files (Playwright, Hurl, Checkov, Trivy). Failures get detail; passes stay short | playwright.dev/docs/test-reporters |
| Secrets | Reference an env var, never type the value (Schemathesis `$API_TOKEN`, Semgrep `SEMGREP_APP_TOKEN`) | docs above |
| Wizard | Only Dredd (`dredd init`) and Playwright (`npm init playwright`) write CI config | dredd.org, playwright.dev/docs/intro |
| SARIF | None of the 13 document SARIF output; JUnit is the GitLab bridge (`artifacts:reports:junit`) | docs.gitlab.com/ci/testing/unit_test_reports |

## Decisions

1. **Everything is reachable from the CI file alone: as a flag, and every config setting also has an env var.** New flags: `--url`, `--header "Name: value"` (repeatable), `--bearer <token>`, `--start "<command line>"`, `--start-timeout <sec>`, `--soft-fail`, `--name`. Not every flag has an env var: only flags that map onto a config setting do (`--url` is `SEALMARK_SERVER__URL`, `--start-timeout` is `SEALMARK_SERVER__START_TIMEOUT_SEC`, `--soft-fail` is `SEALMARK_OUTPUT__EXIT_POLICY__SOFT_FAIL`). `--start` has none (`SEALMARK_SERVER__COMMAND` is one program name and is not split; use it with `SEALMARK_SERVER__ARGS=a,b`), and a header from the environment keeps `_` in its name (`SEALMARK_SERVER__HEADERS__X_API_KEY` is sent as `x_api_key`), so hyphenated headers need `--header` or a file. An earlier draft of this line claimed every flag had an env var; that was wrong.
2. **No file needed.** `sealmark run --url ...` works with no `sealmark.yaml`. With no server given by file, flag or env var, the error shows three one-line examples instead of "Cannot read sealmark.yaml".
3. **`--start` + `--url` = launch, wait, test, stop** (Playwright's model). Ready means the URL gives a real answer: any status except 404 (wrong path or another service on the port) and 5xx (not ready yet); a 401 counts as up. Never continue after a timeout (Lighthouse's trap): fail with exit 4 and the server's last output. `--start` alone keeps today's meaning (a stdio server).
4. **CI is detected.** When `CI=true` (GitLab and GitHub both set it) and no `--profile` is given, `run` uses the `ci` profile and says so in the log. `--profile standard` overrides. (`semgrep ci` pattern, without a second command to learn.)
5. **A readable summary is printed by default in CI** (`--format summary`: grade cards, a check table, what to fix, what the exit code means). Machine reports (JUnit, JSON) are extra files.
6. **`--soft-fail`**: a grade below the gate prints a clear warning and exits 0. Config errors, nothing graded and server failures (2, 3, 4) still fail the job. No `allow_failure` trick in the CI file.
7. **`sealmark init --ci gitlab|github`** prints a ready-to-paste job and writes nothing.
8. **`http-bind` is not asked when Sealmark started the server itself** (a container binding 0.0.0.0 is normal there and the red line confuses the person this is designed for).
9. **Same-layer rule (after the Opus review of 0.1.3).** `server.command` and `server.url` together mean "launch", and config layers merge key by key, so a `url` from the environment could silently turn a stdio server from a file into a launched one. Both must come from the same layer (both flags, the same file, or both env vars); otherwise it is a configuration error (exit 2) and says to set both in the same place.
10. **Stale-server refusal.** If the URL already answers before Sealmark starts the server, the run fails with a message (stop it or use another port), so a leftover server is never graded instead of yours. A launched process is stopped on Ctrl+C, SIGTERM and exit, including its children.
11. **404 and 5xx are not "ready".** Playwright counts only 2xx/3xx/400-403 as ready; Sealmark counts any other answer, so an auth-gated endpoint's 401 is fine, but a 404 (wrong path) or a 5xx (half started) keeps it waiting and then fails. Errors that waiting cannot fix (bad URL, certificate, unknown host) fail at once. `--start-timeout` defaults to 60 s and is separate from `--connect-timeout` (the `initialize` call, 60 s for `run`, 10 s for `doctor`).
12. **CI auto-detection has opt-outs.** `CI=true` (or `1`) selects the `ci` profile only when nobody asked for something else: an explicit profile (flag, env or file) wins, and so do `--out`, `--format`, `--out-dir` and `--fail-under`. The log says when the profile was chosen for you. The `ci` profile adds a B gate, so a pipeline that used to pass with a C can fail after upgrading to 0.1.3.
13. **`--bearer <token>` is the auth flag in the snippets.** It sets `Authorization: Bearer <token>`; `${VAR}` inside single quotes is read from the environment by Sealmark itself (not the shell), so the secret stays out of the process list and reports and works the same under PowerShell. The printed jobs show `--bearer '${MCP_TOKEN}'`. The jobs print the command as a YAML folded block (`- >` / `run: >`) with one flag per line, because the earlier advice to append `--header "Authorization: Bearer ..."` to a one-line plain scalar broke the YAML (`: ` starts a mapping). Optional flags are not printed as commented-out lines inside the block: a `#` line in a block scalar is text for the shell, not a YAML comment.
14. Inherent, not absorbed: installing the server under test (Playwright and Lighthouse do not abstract that either).

## Target job

```yaml
sealmark:
  image: node:24
  script:
    - >
      sealmark run
      --url http://localhost:8000/mcp
      --start "my-server --port 8000"
      --bearer '${TOKEN}'
  artifacts:
    when: always
    reports:
      junit: sealmark-report/sealmark-report.junit.xml
```
