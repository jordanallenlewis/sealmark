import { redactDeep } from "./report/redact.js";

/**
 * The JSON-RPC wire log behind `run --trace <file>` (sealmark#27): the messages that went through the MCP client's transport, both
 * ways, in order, one JSON object per line. It is a debugging aid for the maintainer reproducing a verdict; it is written next to the
 * report and never read back, so it changes no check, verdict or grade.
 *
 * Not in it: requests a pack sends over raw HTTP outside the client (the http and oauth packs' own JSON-RPC), and stdout lines the
 * client could not parse as JSON-RPC (the protocol check counts those).
 */
export interface WireEvent {
  /** Which server session the message belongs to: 0 is the first server start, each later start (a pack's own session) counts up. */
  session: number;
  /** "send": harness to server. "recv": server to harness. */
  dir: "send" | "recv";
  message: unknown;
}

/** A whole run's trace stays bounded: once the kept messages reach this many bytes, later messages are counted, not kept. */
export const MAX_TRACE_BYTES = 32 * 1024 * 1024;

export class TraceRecorder {
  /** Each kept entry as JSON, not yet redacted: the rewrite depends on the run's result (its sandbox path and ports), known only at the end. */
  private readonly raw: string[] = [];
  private bytes = 0;
  private seq = 0;
  private dropped = 0;
  private readonly t0 = Date.now();

  /** @param maxBytes the cap on the kept entries, measured as UTF-8 before redaction, newlines included. */
  constructor(private readonly maxBytes: number = MAX_TRACE_BYTES) {}

  /** Keeps one message (a copy). Never throws: a trace must never take the session down. */
  record(e: WireEvent): void {
    const seq = ++this.seq;
    if (this.dropped) {
      this.dropped++;
      return;
    }
    const head = { seq, ms: Date.now() - this.t0, session: e.session, dir: e.dir };
    let line: string;
    try {
      line = JSON.stringify({ ...head, message: e.message });
    } catch (err) {
      line = JSON.stringify({ ...head, unserialisable: String((err as Error)?.message ?? err) });
    }
    const size = Buffer.byteLength(line) + 1;
    if (this.bytes + size > this.maxBytes) {
      this.dropped++;
      return;
    }
    this.raw.push(line);
    this.bytes += size;
  }

  /**
   * The file content, every string rewritten by `rewrite` (the report's redaction for this run): one line per kept message, then one
   * `{"truncated": true, ...}` line when the cap dropped any.
   */
  text(rewrite: (s: string) => string = (s) => s): string {
    const lines = this.raw.map((l) => JSON.stringify(redactDeep(JSON.parse(l) as unknown, rewrite)));
    if (this.dropped) lines.push(JSON.stringify({ truncated: true, dropped: this.dropped, limit_bytes: this.maxBytes }));
    return lines.length ? `${lines.join("\n")}\n` : "";
  }
}
