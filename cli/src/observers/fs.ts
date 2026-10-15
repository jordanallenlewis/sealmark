// File-system observer: snapshot a set of harness-owned directories and diff two snapshots.
// Nothing here follows links (a junction to the canary directory is recorded as a link, not walked),
// and nothing outside the directories it was given is ever read.
import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import { join } from "node:path";

export type FsKind = "file" | "dir" | "link" | "other";

export interface FsEntry {
  kind: FsKind;
  size: number;
  mtimeMs: number;
  /** sha256 of the content, for regular files up to HASH_LIMIT bytes. Larger files compare by size and mtime. */
  hash?: string;
  /** Link target as stored (links only). */
  target?: string;
}

/** Key: `<label>/<relative path with forward slashes>`, for example `canary/secret.txt` or `root/sub/a.txt`. */
export type FsSnapshot = Record<string, FsEntry>;

export interface FsDiff {
  added: string[];
  removed: string[];
  /** Content changed (hash differs; size or mtime for files too big to hash), or kind/link target changed. */
  changed: string[];
  /** Same content, newer mtime. A server touching a file is not a write. Directories are never listed here. */
  touched: string[];
  /** True when anything was added, removed or changed. */
  any: boolean;
}

export interface FsObserver {
  /** Observed directories by label (root, root-evil, canary, home, tmp). */
  readonly dirs: Readonly<Record<string, string>>;
  snapshot(labels?: string[]): Promise<FsSnapshot>;
  diff(before: FsSnapshot, after: FsSnapshot): FsDiff;
  /** Snapshot now and diff against `before`. */
  diffSince(before: FsSnapshot, labels?: string[]): Promise<FsDiff>;
  /** Absolute path of a snapshot key. */
  resolve(key: string): string;
}

export const HASH_LIMIT = 8 * 1024 * 1024;
const BATCH = 32;

async function walk(label: string, base: string, rel: string, out: FsSnapshot): Promise<void> {
  const abs = rel ? join(base, ...rel.split("/")) : base;
  let names: string[];
  try {
    names = await readdir(abs);
  } catch {
    return; // vanished or unreadable: absence is reported by the diff
  }
  const files: { key: string; abs: string; size: number }[] = [];
  const dirs: string[] = [];
  for (const name of names) {
    const childRel = rel ? `${rel}/${name}` : name;
    const key = `${label}/${childRel}`;
    const p = join(abs, name);
    let st;
    try {
      st = await lstat(p);
    } catch {
      continue;
    }
    if (st.isSymbolicLink()) {
      let target = "";
      try {
        target = await readlink(p);
      } catch {
        /* ignore */
      }
      out[key] = { kind: "link", size: 0, mtimeMs: st.mtimeMs, target };
    } else if (st.isDirectory()) {
      out[key] = { kind: "dir", size: 0, mtimeMs: st.mtimeMs };
      dirs.push(childRel);
    } else if (st.isFile()) {
      out[key] = { kind: "file", size: st.size, mtimeMs: st.mtimeMs };
      if (st.size <= HASH_LIMIT) files.push({ key, abs: p, size: st.size });
    } else {
      out[key] = { kind: "other", size: st.size, mtimeMs: st.mtimeMs };
    }
  }
  for (let i = 0; i < files.length; i += BATCH) {
    await Promise.all(
      files.slice(i, i + BATCH).map(async (f) => {
        try {
          out[f.key]!.hash = createHash("sha256").update(await readFile(f.abs)).digest("hex");
        } catch {
          /* locked or removed mid-read: compare by size and mtime */
        }
      }),
    );
  }
  for (const d of dirs) await walk(label, base, d, out);
}

export function diffSnapshots(before: FsSnapshot, after: FsSnapshot): FsDiff {
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  const touched: string[] = [];
  for (const [k, a] of Object.entries(after)) {
    const b = before[k];
    if (!b) {
      added.push(k);
      continue;
    }
    if (a.kind !== b.kind) {
      changed.push(k);
      continue;
    }
    if (a.kind === "dir") continue; // directory mtimes move whenever a child is added or removed
    if (a.kind === "link") {
      if (a.target !== b.target) changed.push(k);
      continue;
    }
    if (a.hash !== undefined && b.hash !== undefined) {
      if (a.hash !== b.hash) changed.push(k);
      else if (a.mtimeMs !== b.mtimeMs) touched.push(k);
    } else if (a.size !== b.size || a.hash !== b.hash) changed.push(k);
    else if (a.mtimeMs !== b.mtimeMs) changed.push(k); // too big to hash: mtime is the only signal
  }
  for (const k of Object.keys(before)) if (!(k in after)) removed.push(k);
  for (const l of [added, removed, changed, touched]) l.sort();
  return { added, removed, changed, touched, any: added.length + removed.length + changed.length > 0 };
}

/** Keep only the entries under one label (for example `canary`). */
export function diffFor(d: FsDiff, label: string): FsDiff {
  const pick = (l: string[]) => l.filter((k) => k.startsWith(`${label}/`));
  const added = pick(d.added);
  const removed = pick(d.removed);
  const changed = pick(d.changed);
  return { added, removed, changed, touched: pick(d.touched), any: added.length + removed.length + changed.length > 0 };
}

export function createFsObserver(dirs: Record<string, string>): FsObserver {
  const frozen = Object.freeze({ ...dirs });
  const snapshot = async (labels?: string[]): Promise<FsSnapshot> => {
    const out: FsSnapshot = {};
    for (const [label, dir] of Object.entries(frozen)) {
      if (labels && !labels.includes(label)) continue;
      await walk(label, dir, "", out);
    }
    return out;
  };
  return {
    dirs: frozen,
    snapshot,
    diff: diffSnapshots,
    diffSince: async (before, labels) => {
      const keep = labels ? Object.fromEntries(Object.entries(before).filter(([k]) => labels.includes(k.slice(0, k.indexOf("/"))))) : before;
      return diffSnapshots(keep, await snapshot(labels));
    },
    resolve(key) {
      const i = key.indexOf("/");
      const base = frozen[key.slice(0, i)];
      if (!base || i < 0) throw new Error(`unknown snapshot key ${key}`);
      return join(base, ...key.slice(i + 1).split("/"));
    },
  };
}

// ---------------------------------------------------------------------------------------------------------
// Settling: a server may write after it has replied
// ---------------------------------------------------------------------------------------------------------

/** The least time to wait after a reply before concluding that a call changed nothing (exec and custom probes wait the same). */
export const SETTLE_MS = 300;

/** SETTLE_MS, longer on a slow setup: one twentieth of timeout_probe_sec, at most 1.5 s. */
export function settleMsFor(timeoutProbeSec?: number): number {
  const sec = typeof timeoutProbeSec === "number" && timeoutProbeSec > 0 ? timeoutProbeSec : 10;
  return Math.min(1500, Math.max(SETTLE_MS, Math.round((sec * 1000) / 20)));
}

/** Everything either diff saw. A file created and removed again within the window still shows in the first. */
export function mergeDiffs(a: FsDiff, b: FsDiff): FsDiff {
  const union = (x: string[], y: string[]) => [...new Set([...x, ...y])].sort();
  const added = union(a.added, b.added);
  const removed = union(a.removed, b.removed);
  const changed = union(a.changed, b.changed);
  return { added, removed, changed, touched: union(a.touched, b.touched), any: added.length + removed.length + changed.length > 0 };
}

/**
 * Diff against `before` right after a call returned and again after `settleMs`, and return both unioned, so a write
 * the server queues, logs or flushes after sending its reply is still seen. `done` ends the wait early when the
 * immediate diff already shows what the caller was looking for (a positive needs no settling).
 */
export async function settledDiff(fs: FsObserver, before: FsSnapshot, labels: string[] | undefined, settleMs: number, done?: (d: FsDiff) => boolean): Promise<FsDiff> {
  const first = await fs.diffSince(before, labels);
  if (done?.(first)) return first;
  await new Promise<void>((r) => setTimeout(r, settleMs));
  return mergeDiffs(first, await fs.diffSince(before, labels));
}
