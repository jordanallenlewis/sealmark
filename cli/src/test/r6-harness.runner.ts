// Not a test file (no .test suffix): a tiny program that r6-harness.signal.test.ts starts and interrupts. It runs the harness on the HTTP toy that
// Sealmark launches itself, with the upstream stub on, and prints every progress line to stderr, so the test can see the stub's URL and signal it.
// Usage: node dist/test/r6-harness.runner.js <toy port> <sandbox parent dir>
import { fileURLToPath } from "node:url";
import { runHarness } from "../run.js";
import type { SealmarkConfig } from "../types.js";
import { effectiveFor } from "./packctx.js";

const [port, parent] = process.argv.slice(2) as [string, string];
const HTTP_TOY = fileURLToPath(new URL("../toy/http.js", import.meta.url));
const config: SealmarkConfig = {
  name: "r6-runner",
  version: "0.0.1",
  server: {
    command: process.execPath,
    args: [HTTP_TOY, "--mode", "good", "--port", port, "--backend", "{upstream}"],
    url: `http://127.0.0.1:${port}/mcp`,
    headers: { Authorization: "Bearer {bearer}" },
    start_timeout_sec: 60,
  },
};
const effective = effectiveFor(config, ["core"], { dir: parent, parent }, { upstream: { kind: "http", responses: [], default_reply: { status: 200, json: {} } } } as never);
const r = await runHarness({ config, effective, packs: ["core"], packsExplicit: true, timeoutProbeSec: 2, log: (l) => process.stderr.write(`${l}\n`) });
process.stderr.write(`finished: ${Object.keys(r.packs).join(",")}\n`);
