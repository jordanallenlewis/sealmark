import { isDeepStrictEqual } from "node:util";

export type PathSeg = string | number;

export const isPlainObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export const deepEqual = (a: unknown, b: unknown): boolean => isDeepStrictEqual(a, b);

export function deepClone<T>(v: T): T {
  return v === undefined ? v : (structuredClone(v) as T);
}

/** Human path: checks.fs-size-cap.file_mib, sql_tools[0].arg. */
export function dotted(path: readonly PathSeg[]): string {
  let out = "";
  for (const seg of path) out += typeof seg === "number" ? `[${seg}]` : out ? `.${seg}` : seg;
  return out;
}

/** RFC 6901 JSON pointer. */
export function pointer(path: readonly PathSeg[]): string {
  return path.map((s) => `/${String(s).replace(/~/g, "~0").replace(/\//g, "~1")}`).join("");
}

export function getIn(obj: unknown, path: readonly PathSeg[]): unknown {
  let cur: unknown = obj;
  for (const seg of path) {
    if (Array.isArray(cur)) cur = cur[Number(seg)];
    else if (isPlainObject(cur)) cur = cur[String(seg)];
    else return undefined;
  }
  return cur;
}

export function setIn(obj: Record<string, unknown>, path: readonly string[], value: unknown): void {
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const next = cur[path[i]];
    if (!isPlainObject(next)) cur[path[i]] = {};
    cur = cur[path[i]] as Record<string, unknown>;
  }
  cur[path[path.length - 1]] = value;
}

export function deleteIn(obj: Record<string, unknown>, path: readonly string[]): void {
  let cur: unknown = obj;
  for (let i = 0; i < path.length - 1; i++) {
    if (!isPlainObject(cur)) return;
    cur = cur[path[i]];
  }
  if (isPlainObject(cur)) delete cur[path[path.length - 1]];
}

/** JSON with object keys sorted at every level: the same value always serialises to the same bytes. */
export function canonicalJson(v: unknown): string {
  const norm = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(norm);
    if (isPlainObject(x)) return Object.fromEntries(Object.keys(x).sort().map((k) => [k, norm(x[k])]));
    return x;
  };
  return JSON.stringify(norm(v));
}

/** Optimal string alignment distance (Damerau-Levenshtein with adjacent transpositions). */
export function osaDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

const norm = (s: string) => s.toLowerCase().replace(/-/g, "_");

/** Closest candidate within Damerau-Levenshtein distance 2 (1 for very short names), comparing case-insensitively with `-` equal to `_`. */
export function didYouMean(name: string, candidates: Iterable<string>): string | undefined {
  const n = norm(name);
  const max = n.length <= 3 ? 1 : 2;
  let best: string | undefined;
  let bestD = max + 1;
  for (const c of candidates) {
    const dist = osaDistance(n, norm(c));
    if (dist < bestD) {
      best = c;
      bestD = dist;
    }
  }
  return best;
}

export function describeValue(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "a list";
  if (isPlainObject(v)) return "a mapping";
  if (typeof v === "string") return `string ${JSON.stringify(v.length > 60 ? `${v.slice(0, 57)}...` : v)}`;
  return `${typeof v} ${String(v)}`;
}

export function uniqueBy<T>(items: readonly T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const it of items) {
    const key = canonicalJson(it);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(it);
    }
  }
  return out;
}
