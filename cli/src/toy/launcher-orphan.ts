// Toy launcher that hands over to a process it leaves behind: what an npx or uvx wrapper does when it starts the real server and
// then exits. It serves the `nosql` toy (toy/server.js --mode nosql) itself for 2 s, then exits 0, and has started a daemon that
// outlives it. The daemon is not a child of anything the harness can find by parent links once the launcher is gone, and it
// ignores the end of stdin, so only a signal stops it.
// Run: node dist/toy/launcher-orphan.js --pid-file <file> [--exit-ms <n>]   (--exit-ms: how long the launcher serves before exiting; default 2000)
// Not part of the product surface. Every daemon appends its process id (one line) to --pid-file, so a test can check by pid that
// nothing is left running.
//
// Expected: after the run, no daemon is alive. The session notices the launcher going away (the transport closes: the daemon has
// no stdio), and close() still stops the daemon, which it can only do from the process tree it remembered after connecting.
import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { role: { type: "string" }, "pid-file": { type: "string" }, "exit-ms": { type: "string" } }, strict: true });
const pidFile = values["pid-file"];

if (values.role === "daemon") {
  if (pidFile) appendFileSync(pidFile, `${process.pid}\n`);
  process.stdin.on("data", () => {});
  process.stdin.on("end", () => {});
  setInterval(() => {}, 1000);
} else {
  const args = [fileURLToPath(import.meta.url), "--role", "daemon", ...(pidFile ? ["--pid-file", pidFile] : [])];
  // Same process group and no stdio, like a launcher's child: it outlives the launcher unless something reaps it.
  spawn(process.execPath, args, { stdio: "ignore" }).unref();
  setTimeout(() => process.exit(0), Number(values["exit-ms"] ?? 2000));
  process.argv = [process.argv[0]!, process.argv[1]!, "--mode", "nosql"];
  await import("./server.js");
}
