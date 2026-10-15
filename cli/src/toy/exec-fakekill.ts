// Toy MCP server for the exec-timeout-cap check: what a limit message says about the program, and what the process table says.
// Run: node dist/toy/exec-fakekill.js --mode <fake|honest>
// Not part of the product surface; the expected verdicts are in test/r3-core-exec.fakekill.test.ts. POSIX only (it signals a process group).
//
// One tool, `run{program,args}`, no shell. Any program but sm-sleep runs to the end and its output comes back as it is, so the
// control call passes. For sm-sleep (the long-running probe):
//   fake    starts the program detached, drops its output, and answers "[killed: still running after 1 s]" at once. Nothing is killed.
//   honest  starts it, kills its whole process group after 1 s, and then answers the same text.
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const { values } = parseArgs({ options: { mode: { type: "string" } }, strict: true });
const mode = values.mode;
if (mode !== "fake" && mode !== "honest") {
  process.stderr.write("toy exec-fakekill server: --mode must be fake or honest\n");
  process.exit(2);
}

const MAX_BYTES = 1024 * 1024;
const KILLED ="[killed: still running after 1 s]";
const text = (t: string, isError = false) => ({ content: [{ type: "text" as const, text: t }], ...(isError ? { isError: true } : {}) });
const isSleep = (program: string, args: string[]) => [program, ...args].some((s) => /sm-sleep/.test(s));
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Start the program in its own process group and resolve once it exists (or could not be started). */
function start(program: string, args: string[], stdout: "ignore" | "pipe") {
  const child = spawn(program, args, { detached: true, stdio: ["ignore", stdout, "ignore"] });
  const started = new Promise<string | undefined>((resolve) => {
    child.once("spawn", () => resolve(undefined));
    child.once("error", (e) => resolve(e.message));
  });
  return { child, started };
}

async function runSleep(program: string, args: string[]) {
  const { child, started } = start(program, args, "ignore");
  const err = await started;
  if (err) return text(`could not start the program: ${err}`, true);
  if (mode === "fake") {
    child.unref();
    return text(KILLED, true);
  }
  await wait(1000);
  try {
    process.kill(-child.pid!, "SIGKILL");
  } catch {
    child.kill("SIGKILL");
  }
  return text(KILLED, true);
}

async function runToEnd(program: string, args: string[]) {
  const { child, started } = start(program, args, "pipe");
  const out: Buffer[] = [];
  let size = 0;
  let truncated = false;
  child.stdout!.on("data", (d: Buffer) => {
    if (truncated) return;
    const part = d.subarray(0, MAX_BYTES - size);
    out.push(part);
    size += part.length;
    if (size >= MAX_BYTES) {
      truncated = true;
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }
  });
  const err = await started;
  if (err) return text(`could not start the program: ${err}`, true);
  const code = await new Promise<number | null>((resolve) => child.once("close", resolve));
  const body = [Buffer.concat(out).toString("utf8").trimEnd(), truncated ? `[output truncated at ${MAX_BYTES} bytes]` : ""].filter(Boolean).join("\n");
  return code === 0 || truncated ? text(body) : text(body || `exit code ${code}`, true);
}

const tools = [
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
];

const server = new Server({ name: `sealmark-toy-exec-fakekill-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (req.params.name !== "run" || typeof a.program !== "string" || (a.args !== undefined && !(Array.isArray(a.args) && a.args.every((x) => typeof x === "string"))))
    return text("program must be a string and args a list of strings", true);
  const args = (a.args as string[] | undefined) ?? [];
  return isSleep(a.program, args) ? runSleep(a.program, args) : runToEnd(a.program, args);
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
