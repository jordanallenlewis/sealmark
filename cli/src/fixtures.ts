import { appendFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { UsageError, type CommandOutput } from "./commands.js";
import { ensureGitFixture, gitAvailable } from "./packs/git.js";
import { createLayout, type Layout } from "./sandbox.js";
import { SQLITE_SEED, createSqliteFixture, sqliteUnavailable } from "./sqlite-fixtures.js";

const WIN = process.platform === "win32";

/**
 * Writes the fixture the sandbox generates, for hand runs: `sealmark run --fixture fs|git|sqlite --into ./dir`.
 * Building the git repositories is asynchronous, so this returns a promise. A bad name or an unavailable fixture is still thrown at once,
 * as a UsageError, before anything is written.
 */
export function writeFixture(name: string, into: string | undefined, log: (s: string) => void): Promise<CommandOutput> {
  if (!["fs", "git", "sqlite", "duckdb"].includes(name)) throw new UsageError(`--fixture must be fs, git, sqlite or duckdb, got "${name}"`);
  if (name === "duckdb") throw new UsageError("--fixture duckdb: not available in this build yet (DuckDB fixtures are planned); available: fs, git, sqlite");
  if (name === "fs" || name === "git") return writeLayoutFixture(name, into, log);
  const unavailable = sqliteUnavailable();
  if (unavailable) throw new UsageError(`--fixture sqlite: ${unavailable}`);
  const dir = resolve(into ?? "sealmark-fixtures");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "fixture.sqlite");
  if (existsSync(path)) throw new UsageError(`${path} already exists; choose another --into directory or delete it`);
  createSqliteFixture(path);
  log(`wrote ${path} (seed ${SQLITE_SEED}: tenants, customers, orders, big_table, probe_t, audit_probe, customers_masked)`);
  log("This is the file the sandbox generates for {sqlite_path}; point your server at it by hand to explore what the sqlite pack sees.");
  return Promise.resolve({ code: 0 });
}

/** What a run gives the version-control tool: nothing from the real environment except PATH, LANG and the Windows essentials; home and temp point into the layout. */
function fixtureEnv(l: Layout): Record<string, string> {
  const real = process.env;
  const e: Record<string, string> = { PATH: real.PATH ?? "", HOME: l.home, TEMP: l.tmp, TMP: l.tmp, TMPDIR: l.tmp, LANG: real.LANG ?? "C.UTF-8" };
  if (WIN) {
    e.USERPROFILE = l.home;
    e.APPDATA = l.home;
    e.LOCALAPPDATA = l.home;
    for (const k of ["SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT"]) if (real[k] !== undefined) e[k] = real[k]!;
  }
  return e;
}

/**
 * `--fixture fs` writes the sandbox layout into `into`; `--fixture git` adds the four repositories the git pack builds with its own
 * `ensureGitFixture`, so the fixture cannot drift from what a run builds.
 */
async function writeLayoutFixture(name: "fs" | "git", into: string | undefined, log: (s: string) => void): Promise<CommandOutput> {
  const dir = resolve(into ?? "sealmark-fixtures");
  // Checked before anything is written, so a failed run leaves the target as it was and can simply be repeated.
  if (name === "git" && !gitAvailable()) throw new UsageError("--fixture git needs git on PATH");
  mkdirSync(dir, { recursive: true });
  if (existsSync(join(dir, "root"))) throw new UsageError(`${join(dir, "root")} already exists; choose another --into directory or delete it`);
  const l = createLayout(dir, log);
  const link = (s: Layout["links"]["dir"]) => (s.ok ? `${s.path}: ${s.kind}` : `${s.path}: not created (${s.reason})`);
  const doc = join(dir, "SEALMARK-FIXTURE.txt");
  const note = `This is what the sandbox builds for {sandbox}; point your server at ${l.root} by hand to explore what the fs pack sees. The real run always uses a fresh sandbox.`;
  writeFileSync(
    doc,
    [
      `SEALMARK-FIXTURE: written by \`sealmark run --fixture ${name}\`.`,
      "",
      "paths",
      `  root:       ${l.root}  ({sandbox}; the allowed root)`,
      `  root-evil:  ${l.rootEvil}  (a sibling whose name has the root as a prefix)`,
      `  canary:     ${l.canary}  (never given to the server through config)`,
      `  home:       ${l.home}  ({sandbox_home})`,
      `  tmp:        ${l.tmp}`,
      `  bin:        ${l.bin}  (${Object.keys(l.bins).join(", ")})`,
      "",
      "files",
      `  ${l.files.ok}`,
      `  ${l.files.evil}`,
      `  ${l.files.canary}`,
      "",
      "tokens",
      `  control token: ${l.tokens.control}  (root/ok.txt)`,
      `  evil token: ${l.tokens.evil}  (root-evil/secret.txt)`,
      `  canary token: ${l.tokens.canary}  (canary/secret.txt)`,
      "",
      "links",
      `  link-dir: ${link(l.links.dir)}`,
      `  link.txt: ${link(l.links.file)}`,
      "",
    ].join("\n"),
  );
  if (name === "git") {
    let fx;
    try {
      fx = await ensureGitFixture({ root: l.root, canary: l.canary, rootEvil: l.rootEvil, tmp: l.tmp, env: () => fixtureEnv(l) }, { snapshot: false });
    } catch (e) {
      const why = (e as Error).message.trim().split("\n").slice(-3).join(" ");
      throw new UsageError(`--fixture git: could not build the repositories: ${why}`);
    }
    appendFileSync(
      doc,
      [
        "git repositories (one commit each, a modified file and a staged staged.txt, a tag and a remote; the branch, the tag, the commit message and the staged file carry the token)",
        `  root repository: ${fx.rootRepo}`,
        `  canary repository: ${fx.canaryRepo}`,
        `  evil repository: ${fx.evilRepo}`,
        `  repository root/repo-evil: ${fx.prefixRepo}  (the prefix sibling of the root repository, which the scope probe uses)`,
        `  link inside the root repository: ${fx.linkout.ok ? `${fx.linkout.path}  (points at the canary repository; untracked)` : `not created (${fx.linkout.reason ?? "unknown reason"})`}`,
        `  git root token: ${fx.tokens.root}`,
        `  git canary token: ${fx.tokens.canary}`,
        `  git evil token: ${fx.tokens.evil}`,
        `  git prefix token: ${fx.tokens.prefix}`,
        "",
      ].join("\n"),
    );
    log(`wrote the git repositories: ${fx.rootRepo}, ${fx.canaryRepo}, ${fx.evilRepo}, ${fx.prefixRepo}`);
  }
  appendFileSync(doc, `${note}\n`);
  log(`wrote ${dir}: root, root-evil, canary, home, tmp, bin and SEALMARK-FIXTURE.txt (every path and token is listed there)`);
  log(`tokens: control ${l.tokens.control}, canary ${l.tokens.canary}, evil ${l.tokens.evil}`);
  log(note);
  return { code: 0 };
}
