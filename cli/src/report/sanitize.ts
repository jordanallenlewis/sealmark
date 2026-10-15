/**
 * Making server-controlled text inert, and measuring it in terminal columns.
 *
 * Anything a server (or a probe of it) can influence - names, versions, tool and parameter names, check summaries, evidence,
 * error text - may carry ESC/CSI/OSC sequences, CR, backspace, newlines, bidi overrides or zero-width characters. In a CI log those
 * forge rows (`[ PASS ]` on a line of its own), move the cursor over a FAIL row, or turn the rest of the log into a hyperlink.
 * `inert` removes every such effect: whitespace of any kind (newline, CR, tab, NEL, U+2028) becomes one space, and every other
 * control, format, private-use, lone-surrogate and invisible character is shown as a visible escape (`\u001b`). Our own colors are
 * added after this, never before. Every function here is linear in the length of its input.
 */

/** The longest any single field may be, in UTF-16 units, before it is cut and marked with an ellipsis. */
export const MAX_FIELD = 1000;

/** The same, for the text and markdown reports: verbose-mode evidence excerpts are capped at 4 KiB upstream, so they survive whole. */
export const MAX_REPORT_FIELD = 4096;

// Cc (C0, DEL, C1), Cf (bidi, zero-width, BOM, soft hyphen, tag characters), Co, Cs (lone surrogates), plus the invisible
// fillers and variation selectors that are not in those categories.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}͏ᅟᅠㅤﾠ\u{e0100}-\u{e01ef}]/gu;
const SPACES = /[\s\u0085]+/g;

const escapeChar = (c: string) => {
  const cp = c.codePointAt(0)!;
  return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, "0")}`;
};

/** Cut to at most `n` UTF-16 units without leaving half a surrogate pair. */
function cutUnits(s: string, n: number): string {
  if (s.length <= n) return s;
  const hi = s.charCodeAt(n - 1);
  return s.slice(0, hi >= 0xd800 && hi <= 0xdbff ? n - 1 : n);
}

/** One physical line of safe text, at most `max` units long (an ellipsis marks a cut). */
export function inert(value: unknown, max = MAX_FIELD): string {
  const raw = typeof value === "string" ? value : String(value ?? "");
  // Bound the work first: the rest of this function only ever sees a prefix.
  let s = cutUnits(raw, max + 1).replace(SPACES, " ").replace(UNSAFE, escapeChar).trim();
  if (raw.length > max || s.length > max) s = `${cutUnits(s, max - 1).trimEnd()}…`;
  return s;
}

/** `value` with every string (and every object key) made inert. Numbers, booleans and structure are untouched. */
export function inertDeep<T>(value: T, max = MAX_FIELD): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return inert(v, max);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [inert(k, 200), walk(x)]));
    return v;
  };
  return walk(value) as T;
}

/** The most lines `inertLines` keeps; the rest are replaced by one marker line. */
export const MAX_LINES = 200;

/** Multi-line text (a server's last output) with every line made inert: the line structure and leading spaces (stack-trace indentation) stay, nothing else a terminal could act on. */
export function inertLines(value: unknown, max = MAX_LINES): string {
  const raw = typeof value === "string" ? value : String(value ?? "");
  // Bound the work first: only the first `max` lines are ever split out.
  const lines: string[] = [];
  let start = 0;
  while (lines.length < max) {
    const nl = raw.indexOf("\n", start);
    const line = raw.slice(start, nl < 0 ? raw.length : nl);
    const text = inert(line);
    lines.push(text && " ".repeat(Math.min(line.length - line.trimStart().length, 16)) + text);
    if (nl < 0) return lines.join("\n");
    start = nl + 1;
  }
  const more = raw.slice(start).split("\n").length;
  return `${lines.join("\n")}\n… (${more} more line${more === 1 ? "" : "s"})`;
}

// ---------------------------------------------------------------------------------------------------------
// Display width
// ---------------------------------------------------------------------------------------------------------

const MARK = /^[\p{Mn}\p{Me}]$/u;
const EMOJI = /^\p{Emoji_Presentation}$/u;

const inRanges = (cp: number, ranges: number[]) => {
  for (let i = 0; i < ranges.length; i += 2) if (cp >= ranges[i] && cp <= ranges[i + 1]) return true;
  return false;
};

// East Asian Wide and Fullwidth (UAX #11), the blocks that matter in practice.
const WIDE = [
  0x1100, 0x115f, 0x2329, 0x232a, 0x2e80, 0x303e, 0x3041, 0x33ff, 0x3400, 0x4dbf, 0x4e00, 0xa4cf, 0xa960, 0xa97f, 0xac00, 0xd7a3, 0xf900, 0xfaff, 0xfe10, 0xfe19, 0xfe30,
  0xfe6f, 0xff00, 0xff60, 0xffe0, 0xffe6, 0x1b000, 0x1b2ff, 0x1f200, 0x1f2ff, 0x1f300, 0x1f64f, 0x1f900, 0x1f9ff, 0x20000, 0x3fffd,
];

/** Terminal columns taken by one code point: 0 for combining marks, 2 for wide and emoji, else 1. */
export function charWidth(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if (cp < 0x300) return 1;
  if (MARK.test(ch)) return 0;
  if (inRanges(cp, WIDE)) return 2;
  if (cp >= 0x1f1e6 && cp <= 0x1f1ff) return 1; // regional indicators: a flag is two of them, two columns
  return cp >= 0x231a && EMOJI.test(ch) ? 2 : 1;
}

export function displayWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += charWidth(ch);
  return w;
}

/** Split `s` into the longest head that fits `n` columns (at least one code point) and the rest. Never splits a surrogate pair. */
export function takeWidth(s: string, n: number): [string, string] {
  let w = 0;
  let i = 0;
  for (const ch of s) {
    const cw = charWidth(ch);
    if (i > 0 && w + cw > n && cw > 0) break;
    w += cw;
    i += ch.length;
  }
  return [s.slice(0, i), s.slice(i)];
}

/** Fit `s` into `n` columns, ending in an ellipsis when it was cut. */
export function clipWidth(s: string, n: number): string {
  let w = 0;
  let cut = 0;
  let i = 0;
  for (const ch of s) {
    w += charWidth(ch);
    i += ch.length;
    if (w > n) return `${s.slice(0, cut)}…`;
    if (w <= n - 1) cut = i;
  }
  return s;
}

/** Greedy word wrap of already-inert text (single spaces). A word wider than `width` is broken. Linear in the text. */
export function wrapWidth(text: string, width: number): string[] {
  const lines: string[] = [];
  let line = "";
  let lw = 0;
  for (const word of text.split(" ")) {
    if (!word) continue;
    let rest = word;
    let ww = displayWidth(rest);
    while (ww > width) {
      if (line) {
        lines.push(line);
        line = "";
        lw = 0;
      }
      const [head, tail] = takeWidth(rest, width);
      lines.push(head);
      rest = tail;
      ww = displayWidth(rest);
    }
    if (!rest) continue;
    if (line && lw + 1 + ww > width) {
      lines.push(line);
      line = "";
      lw = 0;
    }
    line = line ? `${line} ${rest}` : rest;
    lw = lw ? lw + 1 + ww : ww;
  }
  if (line) lines.push(line);
  return lines;
}
