import { lstatSync, mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { ConfigError } from "./config/model.js";
import { expand, type TemplateCtx } from "./config/placeholders.js";

export interface StagedFile {
  path: string;
  content: string;
}

/** True when `p` is `root` or lies below it (a sibling that only shares the prefix, like `root-evil`, is outside). */
function inside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** The nearest ancestor of `p` (or `p` itself) that exists, so a link on the way can be resolved before anything is created below it. */
function existingAncestor(p: string): string {
  let at = p;
  while (!lstatSync(at, { throwIfNoEntry: false })) {
    const up = dirname(at);
    if (up === at) break;
    at = up;
  }
  return at;
}

/**
 * Writes `server.files` inside the sandbox before the server starts and returns the absolute paths written. Only the sandbox
 * root and the sandbox home are writable: a path that leaves them lexically (`..`) or through a link in the layout (`link-dir`
 * leads to the canary directory) is a ConfigError. A file the harness already made, such as ok.txt, is never overwritten.
 */
export function stageFiles(files: readonly StagedFile[] | undefined, ctx: TemplateCtx, roots: { sandbox: string; home: string }, log: (s: string) => void): string[] {
  if (!files?.length) return [];
  const bases = [roots.sandbox, roots.home].map((r) => resolve(r));
  const real = bases.map((r) => realpathSync.native(r));
  const written: string[] = [];
  for (const f of files) {
    const expanded = expand(f.path, ctx);
    if (expanded.includes("{")) throw new ConfigError(`server.files: ${f.path} still has a placeholder that has no value here; use {sandbox} or {sandbox_home} at the start`);
    const abs = resolve(expanded);
    const i = roots.sandbox && expanded.startsWith(roots.sandbox) && inside(bases[0], abs) ? 0 : roots.home && expanded.startsWith(roots.home) && inside(bases[1], abs) ? 1 : -1;
    if (i < 0) throw new ConfigError(`server.files: ${f.path} resolves outside the sandbox`);
    // Resolve the deepest directory that exists before creating anything below it: a link in the layout must not carry the file out.
    if (!inside(real[i], realpathSync.native(existingAncestor(dirname(abs))))) throw new ConfigError(`server.files: ${f.path} resolves outside the sandbox`);
    if (lstatSync(abs, { throwIfNoEntry: false }) || written.includes(abs)) throw new ConfigError(`server.files: ${f.path} is a file the harness owns`);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, expand(f.content, ctx), { mode: 0o644 });
    written.push(abs);
  }
  log(`staged ${written.length} file(s) in the sandbox`);
  return written;
}
