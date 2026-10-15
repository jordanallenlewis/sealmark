import type { LogMark, LogObserver } from "../types.js";

/**
 * The log observer: what the server under test printed. Two sources feed one capture: the stdout and
 * stderr of a server Sealmark launched ("launched") and the stderr of stdio sessions ("stderr"). The capture keeps the last 1 MiB;
 * a mark is a position counted from the start of the run, so it stays valid while old text falls off the front.
 */
export const LOG_KEEP = 1024 * 1024;

export type LogSource = "launched" | "stderr";

export function createLogObserver(keep: number = LOG_KEEP): LogObserver & { push(chunk: string, source: LogSource): void } {
  let text = "";
  /** Characters dropped from the front so far: the position of text[0]. */
  let dropped = 0;
  const sources = new Set<LogSource>();
  const at = (mark: LogMark): number => Math.max(0, mark - dropped);
  return {
    get sources(): LogSource[] {
      return [...sources];
    },
    push(chunk, source) {
      sources.add(source);
      text += chunk;
      if (text.length > keep) {
        dropped += text.length - keep;
        text = text.slice(text.length - keep);
      }
    },
    mark: () => dropped + text.length,
    since: (mark) => text.slice(at(mark)),
    all: () => text,
    find(needle, mark = 0) {
      if (!needle) return -1;
      const i = text.indexOf(needle, at(mark));
      return i < 0 ? -1 : i + dropped;
    },
  };
}
