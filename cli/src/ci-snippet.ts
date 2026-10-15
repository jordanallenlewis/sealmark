/** `sealmark init --ci <provider>`: a ready-to-paste CI job. Prints, never writes. Kept to a handful of lines on purpose. */
export const CI_PROVIDERS = ["gitlab", "github"] as const;
export type CiProvider = (typeof CI_PROVIDERS)[number];

/**
 * The command is a YAML folded block (`>`) with one flag per line. A folded block is plain text to YAML, so adding a flag
 * (even one holding `: ` or quotes, like --header "Name: value") never needs YAML quoting. Optional flags are NOT printed as
 * commented-out lines inside the block, because a `#` line inside a block is text, not a YAML comment: the comment above the
 * block tells the person which line to add.
 */
/**
 * What the project's configuration declares for round 6 (the upstream stub, caller identities, a scope): the lines the CI job needs so it
 * does the same as `sealmark run` locally. Absent or empty means the job is the plain one.
 */
export interface CiDeclared {
  /** upstream.kind is set: the server must be pointed at {upstream}, and the stub started with --upstream. */
  upstream?: boolean;
  /** server.headers uses {bearer}: the job passes the same header. */
  bearer?: boolean;
  scopeTools?: { tool: string; param: string }[];
  scopeAllow?: string[];
  scopeDeny?: string[];
}

/** A value that is one shell word as written; anything else is double-quoted. */
const word = (v: string): string => (/^[A-Za-z0-9_.:/=@%+,-]+$/.test(v) ? v : `"${v.replace(/(["\\])/g, "\\$1")}"`);

const RUN = (version: string, indent: string, d: CiDeclared = {}) =>
  [
    `npx -y sealmark@${version} run`,
    `--start "my-server --port 8000${d.upstream ? " --backend {upstream}" : ""}"`,
    `--url http://localhost:8000/mcp`,
    ...(d.upstream ? ["--upstream"] : []),
    ...(d.bearer ? [`--header "Authorization: Bearer {bearer}"`] : []),
    ...(d.scopeTools ?? []).map((t) => `--scope-tool ${word(`${t.tool}=${t.param}`)}`),
    ...(d.scopeAllow ?? []).map((a) => `--scope-allow ${word(a)}`),
    ...(d.scopeDeny ?? []).map((a) => `--scope-deny ${word(a)}`),
  ]
    .map((l) => indent + l)
    .join("\n");

export function ciSnippet(provider: CiProvider, version: string, declared: CiDeclared = {}): string {
  if (provider === "gitlab") {
    return `# Paste into .gitlab-ci.yml, then edit the install step, the --start command and --url.
sealmark:
  stage: test
  image: node:24
  script:
    # 1. Install your server with its own "- ..." line here (for example: npm ci  or  pip install .). Sealmark does not install it.
    # 2. Sealmark starts it, waits until the URL answers, grades it, stops it.
    # To add a flag, add one line to the block below, same indentation. No YAML quoting is needed:
    #   auth:                       --bearer '\${MCP_TOKEN}'   (MCP_TOKEN is a masked CI variable; single quotes)
    #   anything below an A fails (default); relax: --fail-under B, warn: --soft-fail
    #   wait longer than 60 s:      --start-timeout 120
    #   stdio server (no HTTP URL): drop the --url line and keep --start "npx -y your-server"
    - >
${RUN(version, "      ", declared)}
  artifacts:
    when: always
    reports:
      junit: sealmark-report/sealmark-report.junit.xml
`;
  }
  return `# Paste into .github/workflows/sealmark.yml, then edit the install step, the --start command and --url.
name: sealmark
on: [push, pull_request]
jobs:
  sealmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      # Install your server here (for example: run: npm ci). Sealmark does not install it.
      # Then Sealmark starts it, waits until the URL answers, grades it, stops it.
      # To add a flag, add one line to the block below, same indentation. No YAML quoting is needed:
      #   auth:                       --bearer '\${MCP_TOKEN}'   (single quotes; create a repository secret named MCP_TOKEN)
      #   anything below an A fails (default); relax: --fail-under B, warn: --soft-fail
      #   wait longer than 60 s:      --start-timeout 120
      #   stdio server (no HTTP URL): drop the --url line and keep --start "npx -y your-server"
      - run: >
${RUN(version, "          ", declared)}
        env:
          MCP_TOKEN: \${{ secrets.MCP_TOKEN }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sealmark-report
          path: sealmark-report/
`;
}
