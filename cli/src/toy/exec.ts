// Toy MCP server for the exec pack. It runs programs, and each mode does it in one known way.
// Run: node dist/toy/exec.js --mode <good|shelly|wander|deny> [--timeout <sec=5>] [--max-bytes <n=1048576>] [--tools run|shell|both]
// Not part of the product surface; the expected verdicts are in the design notes and test/exec.test.ts.
//
// Tools: `run{program,args}` (spawn style) and `shell{command}` (one command line).
//   good    no shell. Only the harness programs sm-echo, sm-sleep and sm-spew are allowed (an allowlist), they run in the
//           server's own cwd, a run past --timeout is killed, and output is cut at --max-bytes.
//   shelly  like good, but every command goes through a shell (`shell: true`) and the arguments are joined into one line,
//           so a `;`, `&&`, `|`, `$()` or backtick in an argument is interpreted. No allowlist.
//   deny    refuses every program (a control that cannot succeed: the pack must say inconclusive).
//   wander  no shell, but it starts programs in the user's home directory, has no timeout and no output cap, no allowlist.
//
// The tool names and descriptions stay free of file, path, sql and url words so the classifier reads them as command tools.
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const EXEC_MODES = ["good", "shelly", "wander", "deny"] as const;
type Mode = (typeof EXEC_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });

const WIN = process.platform === "win32";
/** The harness programs `good` allows. sm-canary is deliberately missing: that is what the allowlist check looks for. */
const ALLOWED = new Set(["sm-echo", "sm-sleep", "sm-spew"]);

function usage(msg: string): never {
  process.stderr.write(`toy exec server: ${msg}\nusage: exec.js --mode <${EXEC_MODES.join("|")}> [--timeout <sec>] [--max-bytes <n>] [--tools run|shell|both]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, timeout: { type: "string" }, "max-bytes": { type: "string" }, tools: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!EXEC_MODES.includes(mode)) usage(`--mode must be one of ${EXEC_MODES.join(", ")}`);
const timeoutSec = values.timeout === undefined ? 5 : Number(values.timeout);
if (!(timeoutSec > 0)) usage("--timeout must be a positive number of seconds");
const maxBytes = values["max-bytes"] === undefined ? 1024 * 1024 : Number(values["max-bytes"]);
if (!(maxBytes > 0)) usage("--max-bytes must be a positive number");

const capped = mode === "good" || mode === "shelly";

/**
 * Kill a child and everything under it. On Windows the direct child of a shell is cmd.exe, so killing only that
 * process orphans the real program (a sleeping node); taskkill /T takes the tree. On POSIX the child leads its own group.
 */
function killTree(child: ChildProcess): void {
  if (!child.pid) return;
  if (WIN) {
    spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
    return;
  }
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
}

interface Ran {
  stdout: string;
  stderr: string;
  code: number | null;
  timedOut: boolean;
  truncated: boolean;
  error?: string;
}

function runChild(file: string, args: string[], o: { shell: boolean; cwd: string }): Promise<Ran> {
  return new Promise((resolve) => {
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let size = 0;
    let timedOut = false;
    let truncated = false;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const child = spawn(file, args, { cwd: o.cwd, shell: o.shell, windowsHide: true, detached: !WIN, stdio: ["ignore", "pipe", "pipe"] });
    const finish = (code: number | null, error?: string) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), code, timedOut, truncated, error });
    };
    if (capped) {
      timer = setTimeout(() => {
        timedOut = true;
        killTree(child);
      }, timeoutSec * 1000);
    }
    child.stdout!.on("data", (d: Buffer) => {
      if (capped && size >= maxBytes) return;
      const room = capped ? maxBytes - size : d.length;
      const part = d.length > room ? d.subarray(0, room) : d;
      out.push(part);
      size += part.length;
      if (capped && size >= maxBytes && !truncated) {
        truncated = true;
        killTree(child);
      }
    });
    child.stderr!.on("data", (d: Buffer) => err.push(d.subarray(0, 4096)));
    child.on("error", (e) => finish(null, e.message));
    child.on("close", (code) => finish(code));
  });
}

/** `good` only: the allowlisted harness program, found on PATH. A `.cmd` shim cannot be spawned without a shell, so on Windows its `.cjs` sibling runs under node. */
function resolveAllowed(name: string): { file: string; args: string[] } | undefined {
  if (!ALLOWED.has(name)) return undefined;
  if (!WIN) return { file: name, args: [] };
  for (const dir of (process.env.PATH ?? process.env.Path ?? "").split(delimiter)) {
    const cjs = dir ? join(dir, `${name}.cjs`) : "";
    if (cjs && existsSync(cjs)) return { file: process.execPath, args: [cjs] };
  }
  return undefined;
}

const cwdFor = (): string => (mode === "wander" ? homedir() : process.cwd());

function present(r: Ran): Reply {
  if (r.error) return fail(`could not start the program: ${r.error}`);
  const text = [
    r.stdout.trimEnd(),
    r.stderr.trim() ? `[stderr] ${r.stderr.trim()}` : "",
    r.truncated ? `[output truncated at ${maxBytes} bytes]` : "",
    r.timedOut ? `[killed: still running after ${timeoutSec} s]` : "",
  ]
    .filter(Boolean)
    .join("\n");
  return r.timedOut || (r.code !== 0 && !r.truncated) ? fail(text || `exit code ${r.code}`) : ok(text);
}

async function runProgram(program: string, args: string[]): Promise<Reply> {
  if (mode === "shelly") return present(await runChild([program, ...args].join(" "), [], { shell: true, cwd: cwdFor() }));
  if (mode === "wander") return present(await runChild(program, args, { shell: false, cwd: cwdFor() }));
  const target = /[\\/]/.test(program) ? undefined : resolveAllowed(program);
  if (!target) return fail(`program "${program}" is not allowed; allowed programs: ${[...ALLOWED].join(", ")}`);
  return present(await runChild(target.file, [...target.args, ...args], { shell: false, cwd: cwdFor() }));
}

async function runLine(command: string): Promise<Reply> {
  if (mode === "shelly") return present(await runChild(command, [], { shell: true, cwd: cwdFor() }));
  if (mode === "wander") return present(await runChild(command, [], { shell: true, cwd: cwdFor() }));
  // good: no shell. Split on spaces and apply the same allowlist as `run`.
  const [program, ...rest] = command.trim().split(/\s+/);
  return runProgram(program ?? "", rest);
}

const which = values.tools ?? "both";
if (!["run", "shell", "both"].includes(which)) usage("--tools must be run, shell or both");

const allTools = [
  {
    name: "run",
    description: "Run a program with a list of arguments and return what it prints.",
    inputSchema: {
      type: "object" as const,
      properties: {
        program: { type: "string", description: "Program to run" },
        args: { type: "array", items: { type: "string" }, description: "Arguments to pass to the program" },
      },
      required: ["program"],
    },
  },
  {
    name: "shell",
    description: "Run one command line and return what it prints.",
    inputSchema: { type: "object" as const, properties: { command: { type: "string", description: "The command line" } }, required: ["command"] },
  },
];
const tools = allTools.filter((t) => which === "both" || t.name === which);

const server = new Server({ name: `sealmark-toy-exec-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  try {
    if (mode === "deny") return fail("running programs is disabled on this server");
    if (req.params.name === "run") {
      if (typeof a.program !== "string" || (a.args !== undefined && !(Array.isArray(a.args) && a.args.every((x) => typeof x === "string"))))
        return fail("program must be a string and args a list of strings");
      return await runProgram(a.program, (a.args as string[] | undefined) ?? []);
    }
    if (req.params.name === "shell") {
      if (typeof a.command !== "string") return fail("command must be a string");
      return await runLine(a.command);
    }
    return fail(`unknown tool ${req.params.name}`);
  } catch (e) {
    return fail((e as Error).message);
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
