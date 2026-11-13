import { inCi } from "./config/index.js";

/**
 * Opt-in usage counter. OFF unless SEALMARK_TELEMETRY=1. DO_NOT_TRACK=1 always wins.
 * It sends one small JSON ping after a command finishes and never changes the exit code.
 * Nothing about the server under test, its tools, the config, paths, results or the machine is included.
 */
export const TELEMETRY_URL = "https://sealmark.dev/api/ping";

export interface Ping {
  schema: 1;
  sealmark: string;
  command: string;
  node: number;
  os: string;
  ci: boolean;
}

const on = (v: string | undefined): boolean => v !== undefined && /^(1|true|yes)$/i.test(v.trim());

export function telemetryEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (on(env.DO_NOT_TRACK)) return false;
  return on(env.SEALMARK_TELEMETRY);
}

export function buildPing(version: string, command: string): Ping {
  const os = process.platform;
  return { schema: 1, sealmark: version, command, node: Number(process.versions.node.split(".")[0]), os, ci: inCi(process.env) };
}

/** Send the ping if the user opted in. Prints the exact payload to stderr first. Never throws; gives up after 2 s. */
export async function sendPing(version: string, command: string | undefined, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  if (!command || !telemetryEnabled(env)) return;
  const url = env.SEALMARK_TELEMETRY_URL?.trim() || TELEMETRY_URL;
  const body = JSON.stringify(buildPing(version, command));
  process.stderr.write(`sealmark: usage ping (SEALMARK_TELEMETRY=1) to ${url}: ${body}\n`);
  try {
    await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(2000) });
  } catch {
    /* a failed ping is silent by design */
  }
}
