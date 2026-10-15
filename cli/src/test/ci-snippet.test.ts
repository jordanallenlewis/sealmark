import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parse } from "yaml";
import { CI_PROVIDERS, ciSnippet, type CiProvider } from "../ci-snippet.js";
import { explainCheck, listChecks, renderExplain } from "../explain.js";

const VERSION = "9.8.7";
const BASE = `npx -y sealmark@${VERSION} run --start "my-server --port 8000" --url http://localhost:8000/mcp`;

/** The extra flag lines a person adds: each one goes on its own line right after the --url line, with the same indentation. */
const EXTRA_LINES = ["--bearer '${MCP_TOKEN}'", "--soft-fail", "--start-timeout 120", `--header "X-Api-Key: abc"`, `--header "Authorization: Bearer abc"`];

function addLines(text: string, lines: string[]): string {
  return text
    .split("\n")
    .flatMap((l) => (/^\s+--url /.test(l) ? [l, ...lines.map((x) => l.match(/^\s*/)![0] + x)] : [l]))
    .join("\n");
}

/** The command string the CI system hands to the shell, parsed from the YAML. */
function command(provider: CiProvider, text: string): string {
  const doc = parse(text) as Record<string, any>;
  if (provider === "gitlab") {
    const script = doc.sealmark.script as unknown[];
    assert.equal(script.length, 1, "one script entry");
    assert.equal(typeof script[0], "string", "a script entry must be a string, not a mapping");
    return script[0] as string;
  }
  const run = (doc.jobs.sealmark.steps as Record<string, unknown>[]).find((s) => s.run !== undefined);
  assert.equal(typeof run?.run, "string", "run: must be a string");
  return run!.run as string;
}

describe("init --ci snippets are valid YAML, with and without the optional flag lines added", () => {
  for (const provider of CI_PROVIDERS) {
    it(`${provider}: the printed job parses and the command is one line without any comment text`, () => {
      const text = ciSnippet(provider, VERSION);
      assert.equal(command(provider, text).trim(), BASE);
      assert.ok(!command(provider, text).includes("#"), "comments above the block must not leak into the command");
    });

    it(`${provider}: adding --bearer, --soft-fail, --start-timeout and --header lines keeps it valid and puts each flag in the command`, () => {
      const text = addLines(ciSnippet(provider, VERSION), EXTRA_LINES);
      const cmd = command(provider, text).trim();
      assert.equal(cmd, `${BASE} ${EXTRA_LINES.join(" ")}`);
      assert.ok(!cmd.includes("\n"), "a folded block joins the lines with spaces");
    });

    it(`${provider}: each optional line also works alone`, () => {
      for (const extra of EXTRA_LINES) assert.equal(command(provider, addLines(ciSnippet(provider, VERSION), [extra])).trim(), `${BASE} ${extra}`);
    });
  }

  it("the old advice (appending --header \"Authorization: Bearer ...\" to a one-line plain scalar) really was invalid, so the block form is what makes the edit safe", () => {
    const old = `sealmark:\n  script:\n    - ${BASE} --header "Authorization: Bearer abc"\n`;
    const script = (parse(old) as any).sealmark.script as unknown[];
    assert.notEqual(typeof script[0], "string");
    assert.throws(() => parse(`steps:\n  - run: ${BASE} --header "Authorization: Bearer abc"\n`));
  });

  it("the snippets show the --bearer line, the env mapping for the secret, and the artifacts", () => {
    const gl = ciSnippet("gitlab", VERSION);
    assert.match(gl, /--bearer '\$\{MCP_TOKEN\}'/);
    assert.match(gl, /junit: sealmark-report\/sealmark-report\.junit\.xml/);
    assert.match(gl, /image: node:24/);
    const gh = ciSnippet("github", VERSION);
    assert.match(gh, /--bearer '\$\{MCP_TOKEN\}'/);
    assert.match(gh, /MCP_TOKEN: \$\{\{ secrets\.MCP_TOKEN \}\}/);
    assert.match(gh, /node-version: 24/);
    assert.doesNotMatch(gh + gl, /--header/, "the printed advice uses --bearer; --header belongs to other headers");
  });

  it("a GitHub step has the run string, env and nothing else in one mapping", () => {
    const steps = (parse(ciSnippet("github", VERSION)) as any).jobs.sealmark.steps as Record<string, any>[];
    const step = steps.find((s) => s.run);
    assert.deepEqual(Object.keys(step!).sort(), ["env", "run"]);
    assert.equal(step!.env.MCP_TOKEN, "${{ secrets.MCP_TOKEN }}");
  });
});

describe("explain and list-checks say http-bind is not examined for a server Sealmark started", () => {
  it("explain http-bind names the launch case and lists server.command as an affecting setting", () => {
    const text = renderExplain(explainCheck("http-bind"));
    assert.match(text, /not examined when Sealmark started the server itself/);
    assert.match(text, /server\.command/);
    const row = listChecks({ pack: "http" }).find((r) => r.id === "http-bind");
    assert.match(row?.scope ?? "", /started the server itself/);
  });
});
