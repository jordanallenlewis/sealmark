import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CLI_COMMANDS, flagsFor } from "../cli-spec.js";
import { ConfigError, displaySpec, loadEffectiveConfig, renderShow, type EffectiveConfig, type LoadOptions } from "../config/index.js";
import { shellSyntaxIn } from "../config/flags.js";

let root: string;
let counter = 0;
before(() => {
  root = mkdtempSync(join(tmpdir(), "sealmark-flags-"));
});
after(() => rmSync(root, { recursive: true, force: true }));

function proj(files: Record<string, string> = {}): string {
  const dir = join(root, `p${counter++}`);
  mkdirSync(dir, { recursive: true });
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}

const load = (dir: string, o: Partial<LoadOptions> = {}): EffectiveConfig => loadEffectiveConfig({ cwd: dir, isolated: true, env: {}, ...o });

function failure(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `expected a ConfigError, got ${String(e)}`);
    return (e as Error).message;
  }
  assert.fail("expected a ConfigError, but nothing was thrown");
}

const URL_OK = "http://localhost:8000/mcp";
const FILE = (server: string) => `schema_version: 1\nname: x\n${server}`;

describe("--bearer", () => {
  it("sets the Authorization header, and adds to --header instead of replacing the others", () => {
    const d = proj();
    assert.deepEqual(load(d, { flags: { url: URL_OK, bearer: "abc123" } }).server.headers, { Authorization: "Bearer abc123" });
    const c = load(d, { flags: { url: URL_OK, header: ["X-Team: demo"], bearer: "abc123" } });
    assert.deepEqual(c.server.headers, { "X-Team": "demo", Authorization: "Bearer abc123" });
    assert.equal(c.origins["/server/headers/Authorization"].source, "flag --bearer");
    assert.equal(c.origins["/server/headers/X-Team"].source, "flag --header");
  });

  it("reads ${VAR} from the environment, and an unset one is an error that names the variable", () => {
    const d = proj();
    assert.equal(load(d, { flags: { url: URL_OK, bearer: "${MCP_TOKEN}" }, env: { MCP_TOKEN: "tok" } }).server.headers?.Authorization, "Bearer ${MCP_TOKEN}");
    const msg = failure(() => load(d, { flags: { url: URL_OK, bearer: "${MCP_TOKEN}" } }));
    assert.match(msg, /\$\{MCP_TOKEN\} is not set \(used in server\.headers\.Authorization\)\. Set it as a CI variable, or give a default: \$\{MCP_TOKEN:-fallback\}/);
  });

  it("refuses an empty token, a token that already says Bearer, and a second Authorization from --header", () => {
    const d = proj();
    assert.match(failure(() => load(d, { flags: { url: URL_OK, bearer: "  " } })), /--bearer: expected a token/);
    assert.match(failure(() => load(d, { flags: { url: URL_OK, bearer: "Bearer abc" } })), /--bearer takes the token only/);
    assert.match(failure(() => load(d, { flags: { url: URL_OK, bearer: "t", header: ["authorization: Bearer u"] } })), /--bearer and --header authorization both set the Authorization header/);
  });

  it("is accepted by run, doctor and config show, and described", () => {
    for (const c of ["run", "doctor", "config show"]) assert.ok(flagsFor(c).some((f) => f.name === "bearer"), c);
    const run = CLI_COMMANDS.find((c) => c.name === "run")!;
    assert.match(run.usage, /--bearer <token>/);
  });
});

describe("headers", () => {
  it("rejects a header name that is not an RFC 7230 token (flag and file), naming the name", () => {
    const d = proj();
    assert.match(failure(() => load(d, { flags: { url: URL_OK, header: ["Bad Name: x"] } })), /^--header: "Bad Name" is not a valid HTTP header name/);
    const f = proj({ "sealmark.yaml": FILE(`server:\n  url: ${URL_OK}\n  headers:\n    "Bad Name": x\n`) });
    assert.match(failure(() => load(f)), /sealmark\.yaml:\d+: server\.headers: "Bad Name" is not a valid HTTP header name/);
  });

  it("rejects a value fetch would refuse (newline, control character, non-Latin-1) without printing it", () => {
    const d = proj();
    for (const bad of ["s3cr3tTOKENvalue\nrest", "s3cr3tTOKENvalue\u0001x", "s3cr3tTOKENvalue\u2192x"]) {
      const msg = failure(() => load(d, { flags: { url: URL_OK, header: ["Authorization: Bearer ${MYTOK}"] }, env: { MYTOK: bad } }));
      assert.match(msg, /server\.headers\.Authorization: the value contains a character HTTP does not allow/);
      assert.ok(!msg.includes("s3cr3tTOKENvalue"), "the value is never printed");
    }
    const lit = failure(() => load(d, { flags: { url: URL_OK, header: ["X-A: bad\u2192value"] } }));
    assert.ok(!lit.includes("bad"), "a literal value is not printed either");
    assert.equal(load(d, { flags: { url: URL_OK, header: ["X-A: tab\there caf\u00e9"] } }).server.headers?.["X-A"], "tab\there caf\u00e9");
  });

  it("treats header names as case-insensitive: the higher layer wins, and one layer cannot hold two", () => {
    const f = proj({ "sealmark.yaml": FILE(`server:\n  url: ${URL_OK}\n  headers:\n    Authorization: Bearer filetoken1234567\n`) });
    assert.deepEqual(load(f, { flags: { header: ["authorization: Bearer flagtok"] } }).server.headers, { authorization: "Bearer flagtok" });
    assert.deepEqual(load(f, { env: { SEALMARK_SERVER__HEADERS__AUTHORIZATION: "Bearer envtok" } }).server.headers, { Authorization: "Bearer envtok" }, "an upper-cased variable name keeps the file's spelling");
    assert.deepEqual(load(f, { env: { SEALMARK_SERVER__HEADERS__AUTHORIZATION: "Bearer envtok" }, flags: { header: ["authorization: Bearer flagtok"] } }).server.headers, { authorization: "Bearer flagtok" });
    const two = failure(() => load(proj(), { flags: { url: URL_OK, header: ["authorization: Bearer a", "Authorization: Bearer b"] } }));
    assert.match(two, /server\.headers has "authorization" and "Authorization", the same header in different case/);
    assert.ok(!two.includes("Bearer a"));
  });

  it("warns when --header, --bearer or --start-timeout are given to a stdio server, and not to an HTTP one", () => {
    const d = proj();
    const stdio = load(d, { flags: { start: "my-server --stdio", header: ["X-A: b"], "start-timeout": "5" } });
    assert.equal(stdio.warnings.length, 1);
    assert.match(stdio.warnings[0], /server\.headers and server\.start_timeout_sec only apply to an HTTP server \(url\)/);
    assert.match(load(d, { flags: { start: "my-server --stdio", bearer: "t" } }).warnings.join("\n"), /server\.headers only apply to an HTTP server/);
    assert.deepEqual(load(d, { flags: { url: URL_OK, header: ["X-A: b"], "start-timeout": "5" } }).warnings, []);
    assert.deepEqual(load(d, { flags: { start: "my-server --port 8000", url: URL_OK, header: ["X-A: b"], "start-timeout": "5" } }).warnings, []);
  });
});

describe("server.url", () => {
  it("must parse, be http(s) and have a host (flag, server and servers.*)", () => {
    const d = proj();
    for (const bad of ["notaurl", "http://", "localhost:8000/mcp", "ftp://127.0.0.1/mcp", "file:///etc/passwd", "ws://127.0.0.1:1/mcp", "   "]) {
      assert.match(failure(() => load(d, { flags: { url: bad } })), /server\.url (must start with http:\/\/ or https:\/\/|is not a valid URL)/, bad);
    }
    assert.match(failure(() => load(proj({ "sealmark.yaml": FILE("server:\n  url: 'http://'\n") }))), /sealmark\.yaml:\d+: server\.url is not a valid URL \(got "http:\/\/"\); it needs a scheme and a host/);
    assert.match(failure(() => load(proj({ "sealmark.yaml": FILE("servers:\n  a: { url: 'http://' }\n") }))), /servers\.a\.url is not a valid URL/);
    assert.equal(load(d, { flags: { url: "https://example.com:8443/mcp?x=1" } }).server.url, "https://example.com:8443/mcp?x=1");
  });

  it("is checked after ${VAR} is filled in, and skipped while a {placeholder} remains", () => {
    const d = proj();
    assert.match(failure(() => load(d, { flags: { url: "${MCP_URL}" }, env: { MCP_URL: "not a url" } })), /server\.url is not a valid URL \(got "\$\{MCP_URL\}"\)/);
    assert.equal(load(d, { flags: { url: "${MCP_URL}" }, env: { MCP_URL: URL_OK } }).server.url, "${MCP_URL}");
    assert.equal(load(d, { flags: { url: "http://localhost:{port}/mcp" } }).server.url, "http://localhost:{port}/mcp");
  });
});

describe("unset ${VAR}", () => {
  const cfg = (body: string) => proj({ "sealmark.yaml": FILE(body) });

  it("is a ConfigError in headers, url, args and env, naming the variable and the setting", () => {
    const hdr = failure(() => load(cfg(`server:\n  url: ${URL_OK}\n  headers:\n    Authorization: "Bearer \${MYTOK}"\n`)));
    assert.match(hdr, /sealmark\.yaml:\d+: \$\{MYTOK\} is not set \(used in server\.headers\.Authorization\)\. Set it as a CI variable, or give a default: \$\{MYTOK:-fallback\}/);
    assert.match(failure(() => load(proj(), { flags: { url: "http://${UNSETH}:8000/mcp" } })), /\$\{UNSETH\} is not set \(used in server\.url\)/);
    assert.match(failure(() => load(cfg("server:\n  command: my-server\n  args: ['--key', '${KEYARG}']\n"))), /\$\{KEYARG\} is not set \(used in server\.args\)/);
    assert.match(failure(() => load(cfg("servers:\n  a:\n    command: my-server\n    env: { API_KEY: '${APIK}' }\n"))), /\$\{APIK\} is not set \(used in servers\.a\.env\.API_KEY\)/);
  });

  it("reports every unset variable at once, and keeps ${VAR:-default}, ${VAR:-} and a set variable working", () => {
    const msg = failure(() => load(proj(), { flags: { url: "http://${H1}:${P1}/mcp" } }));
    assert.match(msg, /\$\{H1\} is not set/);
    assert.match(msg, /\$\{P1\} is not set/);
    const ok = load(cfg("server:\n  command: my-server\n  args: ['--a', '${A:-x}', '--b', '${B:-}', '--c', '${C}']\n"), { env: { C: "1" } });
    assert.deepEqual(ok.server.args, ["--a", "${A:-x}", "--b", "${B:-}", "--c", "${C}"]);
  });

  it("with several servers, only the ones that will run need their variables", () => {
    const two = cfg("servers:\n  a:\n    url: http://localhost:1/mcp\n    headers: { Authorization: 'Bearer ${A_TOKEN}' }\n  b:\n    url: http://localhost:2/mcp\n    headers: { Authorization: 'Bearer ${B_TOKEN}' }\n");
    const env = { A_TOKEN: "a" };
    assert.deepEqual(load(two, { env, flags: { server: "a" } }).servers.map((s) => s.name), ["a"]);
    assert.match(failure(() => load(two, { env, flags: { server: "b" } })), /\$\{B_TOKEN\} is not set \(used in servers\.b\.headers\.Authorization\)/);
    assert.match(failure(() => load(two, { env })), /\$\{B_TOKEN\} is not set/);
    assert.equal(load(two, { env: { A_TOKEN: "a", B_TOKEN: "b" } }).servers.length, 2);
  });

  it("does not touch a harness {placeholder}", () => {
    assert.deepEqual(load(cfg("server:\n  command: my-server\n  args: ['{sandbox}']\n")).server.args, ["{sandbox}"]);
  });
});

describe("--start is not run through a shell", () => {
  const start = (line: string) => failure(() => load(proj(), { flags: { start: line } }));

  it("rejects shell operators and a leading VAR=value, pointing at sh -c", () => {
    for (const line of ["cd x && node s.js", "node s.js || true", "node s.js ; echo", "node s.js | cat", "node s.js > log.txt", "node s.js >> log.txt", "node s.js &", "node s.js < in.txt", "node s.js 2>&1", "node s.js >log.txt", "cd x&&node s.js"]) {
      assert.match(start(line), /^--start is not run through a shell, so ".+" would not work as in a shell; wrap it: --start "sh -c '\.\.\.'"/, line);
    }
    const env = start("FOO=1 node s.js");
    assert.match(env, /^--start is not run through a shell, so the leading FOO=\.\.\. would not work as in a shell; wrap it: --start "sh -c '\.\.\.'"/);
    assert.match(env, /env NAME=value command/);
  });

  it("accepts the same characters when they are quoted, and a plain command line", () => {
    const d = proj();
    assert.deepEqual(load(d, { flags: { start: "sh -c 'cd x && node s.js'" } }).server.args, ["-c", "cd x && node s.js"]);
    assert.deepEqual(load(d, { flags: { start: 'node s.js --sep ";" --out ">"' } }).server.args, ["s.js", "--sep", ";", "--out", ">"]);
    assert.deepEqual(load(d, { flags: { start: "node s.js --url http://h/p?a=1&b=2 --x=y" } }).server.args, ["s.js", "--url", "http://h/p?a=1&b=2", "--x=y"]);
    assert.deepEqual(load(d, { flags: { start: "env FOO=1 node s.js" } }).server.command, "env");
  });

  it("finds the first unquoted operator", () => {
    assert.equal(shellSyntaxIn("a && b"), "&&");
    assert.equal(shellSyntaxIn("a '&&' b"), undefined);
    assert.equal(shellSyntaxIn('a "x y" b'), undefined);
  });
});

describe("no server", () => {
  it("leads with 'No server is configured', shows the three examples, then points at init", () => {
    const msg = failure(() => load(proj()));
    const lines = msg.split("\n");
    assert.equal(lines[0], "No server is configured. Name it on the command line, no file needed:");
    assert.equal(lines.length, 5);
    assert.match(lines[1], /^ {2}sealmark run --url http:\/\/localhost:8000\/mcp /);
    assert.match(lines[2], /^ {2}sealmark run --start "my-server --port 8000" --url /);
    assert.match(lines[3], /^ {2}sealmark run --start "npx -y some-mcp-server"/);
    assert.equal(lines[4], 'or run "sealmark init" to write a sealmark.yaml.');
  });

  it("does the same, and names the flag, when only --header / --bearer / --start-timeout were given and there is no file", () => {
    const d = proj();
    assert.match(failure(() => load(d, { flags: { header: ["X-A: b"] } })), /^No server is configured \(--header or --bearer only add to a server; name one with --url or --start\)\./);
    assert.match(failure(() => load(d, { flags: { "start-timeout": "5" } })), /^No server is configured \(--start-timeout only add/);
    const msg = failure(() => load(d, { flags: { header: ["X-A: b"] } }));
    assert.ok(!msg.includes(d), "no path of a file that does not exist");
    assert.match(failure(() => load(d, { flags: { name: "foo" } })), /^No server is configured\./);
  });
});

describe("flags together with `servers:` in the file", () => {
  const f = () => proj({ "sealmark.yaml": FILE(`servers:\n  a: { url: ${URL_OK} }\n  b: { command: node, args: [x.mjs] }\n`) });

  it("names the flag and says what to do, instead of blaming the file", () => {
    for (const flags of [{ url: URL_OK }, { start: "node x.mjs" }, { header: ["X-A: b"] }]) {
      const msg = failure(() => load(f(), { flags }));
      assert.match(msg, /^flag --(url|start|header|header, --start) set "server", but sealmark\.yaml(?::\d+)? defines "servers" \(a, b\)\. They cannot be combined\./, JSON.stringify(flags));
      assert.match(msg, /use --server <name>/);
    }
    assert.match(failure(() => load(f(), { env: { SEALMARK_SERVER__URL: URL_OK } })), /^env SEALMARK_SERVER__URL set "server"/);
  });

  it("keeps the old message when both are in files", () => {
    const both = proj({ "sealmark.yaml": FILE(`server: { command: x }\nservers:\n  a: { command: y }\n`) });
    assert.match(failure(() => load(both)), /sealmark\.yaml(?::\d+)?: set either server or servers, not both/);
  });
});

describe("config show", () => {
  it("accepts the server flags and the output flags", () => {
    for (const name of ["url", "start", "header", "bearer", "start-timeout", "name", "soft-fail", "format", "fail-under", "pack", "out"]) {
      assert.ok(flagsFor("config show").some((f) => f.name === name), `--${name}`);
    }
    for (const name of ["url", "start", "header", "start-timeout", "name"]) assert.ok(flagsFor("doctor").some((f) => f.name === name), `doctor --${name}`);
  });

  it("really runs: `config show --url ... --origins` prints the flag origin", () => {
    const cli = join(dirname(fileURLToPath(import.meta.url)), "..", "cli.js");
    const d = proj();
    const r = spawnSync(process.execPath, [cli, "config", "show", "--url", URL_OK, "--header", "X-A: b", "--bearer", "tok", "--name", "svc", "--soft-fail", "--origins"], { cwd: d, encoding: "utf8", env: { PATH: process.env.PATH ?? "", SEALMARK_USER_CONFIG: "none" } });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /url: http:\/\/localhost:8000\/mcp {3}# flag --url/);
    assert.match(r.stdout, /Authorization: "?<redacted>"?/);
    assert.match(r.stdout, /name: svc {3}# flag --name/);
    assert.ok(!r.stdout.includes("tok\n"));
  });

  it("shows the profile in effect and where it came from under CI=true", () => {
    const d = proj({ "sealmark.yaml": FILE("server: { command: my-server }\n") });
    const ci = load(d, { env: { CI: "true" } });
    assert.equal(ci.value.profile, "ci");
    assert.equal(ci.origins["/profile"].source, "env CI=true");
    const shown = renderShow(ci, { origins: true });
    assert.match(shown, /^profile: ci {3}# env CI=true$/m);
    assert.match(renderShow(load(d), { origins: true }), /^profile: standard {3}# default$/m);
    const explicit = load(d, { env: { CI: "true" }, flags: { profile: "standard" } });
    assert.equal(explicit.value.profile, "standard");
    assert.match(renderShow(explicit, { origins: true }), /^profile: standard {3}# flag --profile$/m);
  });
});

describe("usage lines", () => {
  it("run and doctor name the new flags", () => {
    const usage = (n: string) => CLI_COMMANDS.find((c) => c.name === n)!.usage;
    for (const flag of ["--url", "--start", "--header", "--bearer", "--start-timeout", "--name", "--soft-fail"]) assert.ok(usage("run").includes(flag), `run ${flag}`);
    for (const flag of ["--url", "--start", "--header", "--bearer", "--start-timeout", "--profile"]) assert.ok(usage("doctor").includes(flag), `doctor ${flag}`);
    for (const flag of ["--url", "--start", "--header", "--bearer", "--name"]) assert.ok(usage("config show").includes(flag), `config show ${flag}`);
  });

  it("does not claim that every flag has an environment variable", () => {
    for (const f of flagsFor("run")) assert.ok(!/every flag has an env/i.test(f.description), f.name);
  });
});

describe("report name", () => {
  it("comes from the command or the url host when nothing sets it, and an explicit name wins", () => {
    const d = proj();
    const url = load(d, { flags: { url: "https://api.example.com:8443/mcp" } });
    assert.equal(url.name, "api.example.com");
    assert.equal(url.value.name, "api.example.com");
    assert.equal(url.servers[0].name, "api.example.com");
    assert.equal(url.origins["/name"].source, "default (from server.url)");
    assert.equal(load(d, { flags: { start: "my-server --port 8000" } }).name, "my-server");
    assert.equal(load(d, { flags: { start: "/opt/bin/my-server.exe --port 8000" } }).name, "my-server");
    assert.equal(load(d, { flags: { start: "npx -y @scope/pkg-x@1.2.3" } }).name, "pkg-x");
    assert.equal(load(d, { flags: { start: "node ./dist/search.js --port 8000" } }).name, "search");
    assert.equal(load(d, { flags: { start: 'node -e "setInterval(()=>{},1000)"' } }).name, "node");
    assert.equal(load(d, { flags: { start: "my-server --port 8000", url: URL_OK } }).name, "my-server", "the command names a launched server, not localhost");
    assert.equal(load(d, { flags: { url: URL_OK, name: "svc" } }).name, "svc");
    assert.equal(load(proj({ "sealmark.yaml": FILE("server: { command: other }\n") })).name, "x", "a name in the file is kept");
  });

  it("rejects an empty --name", () => {
    assert.match(failure(() => load(proj(), { flags: { url: URL_OK, name: "" } })), /--name: must not be empty/);
  });
});

describe("secret-looking query parameters in the shown url", () => {
  it("masks their values in displaySpec and config show, keeps the rest and placeholders", () => {
    const shown = displaySpec({ url: "http://127.0.0.1:9/mcp?token=QUERYsecretTOK55&x=1&api_key=k-123&sig=abcdef&auth=Zm9v&env=${E}&password=${P}" }).command;
    assert.equal(shown, "http://127.0.0.1:9/mcp?token=<redacted>&x=1&api_key=<redacted>&sig=<redacted>&auth=<redacted>&env=${E}&password=${P}");
    const c = load(proj(), { flags: { url: "http://127.0.0.1:9/mcp?token=QUERYsecretTOK55&x=1" } });
    const text = renderShow(c, { origins: true });
    assert.ok(!text.includes("QUERYsecretTOK55"));
    assert.match(text, /url: http:\/\/127\.0\.0\.1:9\/mcp\?token=<redacted>&x=1/);
    assert.equal(displaySpec({ url: "http://u:pw@h/mcp?page=2" }).command, "http://h/mcp?page=2");
  });
});

describe("SEALMARK_INPUT_* variables", () => {
  it("are values for `${SEALMARK_INPUT_<ID>}` references, not settings", () => {
    const f = proj({ "sealmark.yaml": FILE("server:\n  command: my-server\n  args: ['${SEALMARK_INPUT_DATA_DIR}']\n") });
    assert.deepEqual(load(f, { env: { SEALMARK_INPUT_DATA_DIR: "/data" } }).server.args, ["${SEALMARK_INPUT_DATA_DIR}"]);
    assert.match(failure(() => load(f)), /\$\{SEALMARK_INPUT_DATA_DIR\} is not set/);
  });
});
