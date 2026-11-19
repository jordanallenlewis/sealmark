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

  /**
   * Keeps one message (a copy) and returns its line number (`seq`), or undefined when the cap dropped it, so nothing links to a line
   * the file will not have. Never throws: a trace must never take the session down.
   */
  record(e: WireEvent): number | undefined {
    const seq = ++this.seq;
    if (this.dropped) {
      this.dropped++;
      return undefined;
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
      return undefined;
    }
    this.raw.push(line);
    this.bytes += size;
    return seq;
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

/** One tools/call request in the trace file (its `seq`), in a session, and the line of its reply when the trace kept one. */
export interface TraceCall {
  session: number;
  request: number;
  response?: number;
}

/** A piece of evidence's link into the trace file: the tools/call requests with its tool and arguments, at most MAX_LINKED_CALLS. */
export interface EvidenceTrace {
  calls: TraceCall[];
  /** How many more matching requests there were past the first MAX_LINKED_CALLS. */
  more?: number;
}

export const MAX_LINKED_CALLS = 10;

/** JSON with object keys sorted, so `{a, b}` and `{b, a}` are the same arguments; undefined for a value JSON cannot hold. */
function canonical(v: unknown): string | undefined {
  try {
    const plain = JSON.stringify(v);
    if (plain === undefined) return undefined;
    return JSON.stringify(JSON.parse(plain) as unknown, (_k, x: unknown) =>
      x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x,
    );
  } catch {
    return undefined;
  }
}

/**
 * A request id in one session. The SDK matches a reply to its request with `Number(id)`, so `"3"` and `3` are the same id here too;
 * any other string stays a string.
 */
function idKeyOf(session: number, id: unknown): string | undefined {
  if (typeof id === "number") return `${session}\u0000${id}`;
  if (typeof id === "string") return /^\d+$/.test(id) ? `${session}\u0000${Number(id)}` : `${session}\u0000s:${id}`;
  return undefined;
}

/**
 * `run --trace` (sealmark#27, slice 3): every tools/call request the trace kept, by session, tool and arguments, with the line of its
 * reply. A check's evidence that names a tool and the arguments it sent is linked to the matching requests in the check's own sessions.
 * The match is on content: when the same call went out more than once in those sessions (a db role's or an identity's own session
 * included), every one is listed, and evidence whose arguments are shown differently from what was sent (sandbox or canary
 * placeholders, a custom probe's `{...}`) matches nothing. Changes no check, verdict or grade.
 */
export class CallIndex {
  /** session -> "tool\u0000canonical args" -> the calls, in order. */
  private readonly bySession = new Map<number, Map<string, TraceCall[]>>();
  /** "session\u0000id" -> the call still waiting for its reply. */
  private readonly pending = new Map<string, TraceCall>();

  /** Sees one wire event and the line the recorder gave it (undefined when the trace did not keep it). Never throws. */
  observe(e: WireEvent, seq: number | undefined): void {
    try {
      const m = e.message as { id?: unknown; method?: unknown; params?: { name?: unknown; arguments?: unknown; requestId?: unknown }; result?: unknown; error?: unknown } | null;
      if (!m || typeof m !== "object") return;
      // A request the harness gave up on (the SDK sends notifications/cancelled on a timeout) gets no reply link, even if one comes late.
      if (e.dir === "send" && m.method === "notifications/cancelled") {
        const gone = idKeyOf(e.session, m.params?.requestId);
        if (gone) this.pending.delete(gone);
        return;
      }
      if (seq === undefined) return;
      const idKey = idKeyOf(e.session, m.id);
      if (e.dir === "send") {
        if (m.method !== "tools/call" || !idKey || typeof m.params?.name !== "string") return;
        const args = canonical(m.params.arguments ?? {});
        if (args === undefined) return;
        const call: TraceCall = { session: e.session, request: seq };
        let calls = this.bySession.get(e.session);
        if (!calls) this.bySession.set(e.session, (calls = new Map()));
        const key = `${m.params.name}\u0000${args}`;
        const same = calls.get(key);
        if (same) same.push(call);
        else calls.set(key, [call]);
        this.pending.set(idKey, call);
        return;
      }
      // A reply has no method; a server's own request to the client (sampling, roots) has one and is never the reply.
      if (!idKey || m.method !== undefined || !("result" in m || "error" in m)) return;
      const call = this.pending.get(idKey);
      if (!call) return;
      call.response = seq;
      this.pending.delete(idKey);
    } catch {
      /* a trace must never take the run down */
    }
  }

  /** The requests in `sessions` (in session order, then file order) with this tool and these arguments, or undefined for none. */
  find(sessions: readonly number[], tool: string, args: unknown): EvidenceTrace | undefined {
    if (args === undefined) return undefined;
    const a = canonical(args);
    if (a === undefined) return undefined;
    const key = `${tool}\u0000${a}`;
    const all: TraceCall[] = [];
    for (const s of [...sessions].sort((x, y) => x - y)) all.push(...(this.bySession.get(s)?.get(key) ?? []));
    if (!all.length) return undefined;
    const calls = all.slice(0, MAX_LINKED_CALLS).map((c) => ({ ...c }));
    return all.length > MAX_LINKED_CALLS ? { calls, more: all.length - MAX_LINKED_CALLS } : { calls };
  }
}
