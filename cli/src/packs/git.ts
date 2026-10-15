import { execFile, spawnSync } from "node:child_process";
import { appendFile, cp, mkdir, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { fillArgs, packsFor } from "../classify.js";
import { diffFor, settleMsFor, settledDiff } from "../observers/fs.js";
import { rejectedBeforeRunning, type CallResult, type ToolInfo } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence, FsDiff, Pack, PackApplies, PackCtx, ParamRole, Sandbox, ToolClassification } from "../types.js";
import { Sessions, Tally, excerpt, metaFor, oneLine, rawJoin, refused, result, token, unexpand, words, type Meta } from "./fs.js";

/**
 * The `git` pack. Two checks against a server that runs git on a repository the caller names:
 * can a call name a repository the server was not configured for, and can a value meant as a revision, branch or file
 * become a git option. Fixtures are four small repositories the harness builds inside the sandbox; write-capable tools
 * only ever touch `{sandbox}/repo`.
 */

const SINCE = "0.2-draft";
const exec = promisify(execFile);
const WIN = process.platform === "win32";

export function gitAvailable(): boolean {
  try {
    return spawnSync("git", ["--version"], { stdio: "ignore", windowsHide: true }).status === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------------------

export interface GitFixture {
  /** `{sandbox}/repo`: one commit, a modified `tracked.txt`, a staged `staged.txt`, a branch named after `tokens.root`. The only repository a server may use. */
  rootRepo: string;
  /** `{canary}/repo`: a repository outside the root. Its file name, commit message and branch carry `tokens.canary`. */
  canaryRepo: string;
  /** `{root_evil}`: a repository whose directory name has the root as a prefix. Carries `tokens.evil`. */
  evilRepo: string;
  /** `{sandbox}/repo-evil`: a sibling of the configured repository whose directory name has its path as a prefix (what a `startswith` scope check lets through). Carries `tokens.prefix`. */
  prefixRepo: string;
  tokens: { root: string; canary: string; evil: string; prefix: string };
  /**
   * `{sandbox}/repo/linkout`: an untracked link inside the configured repository that points at `canaryRepo`. A server that resolves the
   * path lexically (or resolves `..` but not links) treats it as part of the repository. `ok` is false where the link could not be made
   * (Windows without a junction); `reason` says why, so the check can say it was not run.
   */
  linkout: { path: string; ok: boolean; reason?: string };
  /**
   * Harness-held copies of the root and canary repositories as they were built (everything but the link), so a write-capable tool
   * that committed, reset or checked something out cannot change what the read controls rely on. Absent for a hand-run fixture
   * (`--fixture git`), which has no write half. `restoreGitFixture` puts the copies back.
   */
  snapshot?: { dir: string; repos: { repo: string; copy: string }[]; refresh: () => Promise<void> };
}

/** What building the fixture reads from a sandbox: the three directories, the temp directory (git's hooks path) and the scrubbed environment. A fixtures-only layout can supply the same. */
type GitSandbox = Pick<Sandbox, "root" | "canary" | "rootEvil" | "tmp" | "env">;

const fixtures = new WeakMap<GitSandbox, Promise<GitFixture>>();

/** Every fixture commit carries this date, so the clock never makes two fixtures differ (what a commit message carries, the run's random tokens, still does). */
const FIXTURE_DATE = "2000-01-01T00:00:00Z";

async function git(sb: GitSandbox, cwd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  // The sandbox environment points HOME and APPDATA at the sandbox, so the owner's global git configuration (signing, hooks, templates) cannot apply.
  return exec(
    "git",
    ["-c", "user.name=sealmark", "-c", "user.email=sealmark@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", "init.defaultBranch=main", "-c", `core.hooksPath=${sb.tmp}`, "-c", "gc.auto=0", ...args],
    { cwd, env: { ...sb.env(), GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_DATE: FIXTURE_DATE, GIT_COMMITTER_DATE: FIXTURE_DATE }, windowsHide: true, timeout: 60_000 },
  );
}

/**
 * `files` with a body are written; a file listed without one already exists and is only committed. After the commit the repository
 * gets a modified tracked file (`git status`, `git diff`) and a staged new file `staged.txt` carrying `staged` (`git diff --staged`,
 * `git diff HEAD`), so every read-only tool prints something that names the repository.
 */
async function makeRepo(sb: GitSandbox, dir: string, o: { files: [string, string | undefined][]; message: string; branch: string; modify: string; staged: string; remote: string }): Promise<void> {
  await mkdir(dir, { recursive: true });
  await git(sb, dir, ["init", "-q"]);
  for (const [name, body] of o.files) if (body !== undefined) await writeFile(rawJoin(dir, name), body);
  await git(sb, dir, ["add", "--", ...o.files.map(([n]) => n)]);
  await git(sb, dir, ["commit", "-q", "-m", o.message]);
  await git(sb, dir, ["branch", o.branch]);
  // A tag and a remote that name the repository, so a tag or remote listing answers for it (an empty list could not carry a token).
  // The root repository's remote is plain `sm-origin` (its URL is the repository's own path); the others carry their token in the name, so a listing that leaked one is recognised.
  await git(sb, dir, ["tag", `sm-tag-${o.branch}`]);
  await git(sb, dir, ["remote", "add", o.remote, dir]);
  // A dirty working tree makes `git status` and `git diff` print the file name, which is what a response check looks for.
  await appendFile(rawJoin(dir, o.modify), "modified by the harness\n");
  // A staged change, so a tool that shows the index has something to show: without it its control call is empty and the tool is never judged.
  await writeFile(rawJoin(dir, "staged.txt"), `${o.staged} staged\n`);
  await git(sb, dir, ["add", "--", "staged.txt"]);
  // Refresh the index once so a later read-only `git status` has nothing to write back.
  await git(sb, dir, ["status", "--short"]);
}

/** A harness-held copy of the repository, without the planted link (it is made once and never copied). */
const keepsLink = (repo: string) => (src: string) => src !== rawJoin(repo, "linkout");

async function snapshotFixture(sb: GitSandbox, repos: string[]): Promise<NonNullable<GitFixture["snapshot"]>> {
  // A sibling of the layout directories, so no observed directory (root, root-evil, canary, home, tmp) ever sees it; it goes away with the sandbox.
  const dir = rawJoin(dirname(sb.root), "sm-git-snapshot");
  await mkdir(dir, { recursive: true });
  const pairs: { repo: string; copy: string }[] = [];
  for (const [i, repo] of repos.entries()) {
    const copy = rawJoin(dir, String(i));
    await cp(repo, copy, { recursive: true, preserveTimestamps: true, filter: keepsLink(repo) });
    pairs.push({ repo, copy });
  }
  // The index remembers file times; one status after a restore refreshes it, as it was after the build.
  const refresh = async () => {
    for (const { repo } of pairs) await git(sb, repo, ["status", "--short"]);
  };
  return { dir, repos: pairs, refresh };
}

/**
 * Puts the root and canary repositories back as they were built: the working tree, the index, `HEAD`, the branches, the tag and the
 * remote. Everything but the planted link is removed first, so a file a write-capable tool added is gone too. A no-op for a fixture
 * built without a snapshot.
 */
export async function restoreGitFixture(fx: GitFixture): Promise<void> {
  const snap = fx.snapshot;
  if (!snap) return;
  for (const { repo, copy } of snap.repos) {
    for (const name of await readdir(repo)) if (name !== "linkout") await rm(rawJoin(repo, name), { recursive: true, force: true, maxRetries: 3 });
    for (const name of await readdir(copy)) await cp(rawJoin(copy, name), rawJoin(repo, name), { recursive: true, force: true, preserveTimestamps: true });
  }
  await snap.refresh();
}

/**
 * Builds the four repositories once per sandbox. Needs `git`; throws when it cannot run. The root and canary repositories are copied
 * to a harness-held directory after they are built (`restoreGitFixture`), unless `snapshot` is false (a hand-run fixture).
 */
export function ensureGitFixture(sb: GitSandbox, o: { snapshot?: boolean } = {}): Promise<GitFixture> {
  let f = fixtures.get(sb);
  if (!f) {
    f = (async () => {
      const tokens = { root: token("sm-root"), canary: token("sm-canary"), evil: token("sm-evil"), prefix: token("sm-prefix") };
      const rootRepo = rawJoin(sb.root, "repo");
      const canaryRepo = rawJoin(sb.canary, "repo");
      // Every tracked file carries its repository's token, so a tool that prints file content (blame) names the repository too.
      await makeRepo(sb, rootRepo, { files: [["tracked.txt", `initial ${tokens.root}\n`]], message: `${tokens.root} initial commit`, branch: tokens.root, modify: "tracked.txt", staged: tokens.root, remote: "sm-origin" });
      await makeRepo(sb, canaryRepo, { files: [[`${tokens.canary}.txt`, `canary ${tokens.canary}\n`]], message: `${tokens.canary} initial commit`, branch: tokens.canary, modify: `${tokens.canary}.txt`, staged: tokens.canary, remote: `sm-origin-${tokens.canary}` });
      // root-evil already holds secret.txt; commit it next to a second file so it is a repository too.
      await makeRepo(sb, sb.rootEvil, { files: [["secret.txt", undefined], [`${tokens.evil}.txt`, `evil ${tokens.evil}\n`]], message: `${tokens.evil} initial commit`, branch: tokens.evil, modify: `${tokens.evil}.txt`, staged: tokens.evil, remote: `sm-origin-${tokens.evil}` });
      // The configured repository is {sandbox}/repo, so the sibling a startswith-style check lets through is {sandbox}/repo-evil (the last segment with "-evil" appended).
      const prefixRepo = `${rootRepo}-evil`;
      await makeRepo(sb, prefixRepo, { files: [[`${tokens.prefix}.txt`, `prefix ${tokens.prefix}\n`]], message: `${tokens.prefix} initial commit`, branch: tokens.prefix, modify: `${tokens.prefix}.txt`, staged: tokens.prefix, remote: `sm-origin-${tokens.prefix}` });
      // A link inside the configured repository that points at the canary repository (a directory link: a junction on Windows).
      const linkout = rawJoin(rootRepo, "linkout");
      let linkState: GitFixture["linkout"] = { path: linkout, ok: true };
      try {
        await symlink(canaryRepo, linkout, WIN ? "junction" : "dir");
      } catch (e) {
        linkState = { path: linkout, ok: false, reason: (e as NodeJS.ErrnoException).code ? `${(e as NodeJS.ErrnoException).code}: ${(e as Error).message}` : String((e as Error).message ?? e) };
      }
      const snapshot = o.snapshot === false ? undefined : await snapshotFixture(sb, [rootRepo, canaryRepo]);
      return { rootRepo, canaryRepo, evilRepo: sb.rootEvil, prefixRepo, tokens, linkout: linkState, ...(snapshot ? { snapshot } : {}) };
    })();
    fixtures.set(sb, f);
    f.catch(() => fixtures.delete(sb));
  }
  return f;
}

// ---------------------------------------------------------------------------------------------------------
// What a git tool does
// ---------------------------------------------------------------------------------------------------------

export type GitKind = "read" | "write" | "other";

const GIT_WRITE = /\b(commit|add|stage|unstage|reset|checkout|switch|merge|rebase|push|pull|fetch|clone|init|create|delete|remove|stash|apply|cherry|revert|rm|mv|write|set|restore|amend)\b/;
const GIT_READ = /\b(status|log|diff|show|blame|branch|branches|list|ls|describe|grep|remote|tag|tags|cat|history|info|rev|contains|changes)\b/;

export function gitKind(tool: ToolInfo, c: ToolClassification): GitKind {
  const w = words(`${tool.name} ${tool.title ?? ""}`);
  if (GIT_WRITE.test(w)) return "write";
  if (GIT_READ.test(w)) return "read";
  const d = words((tool.description ?? "").slice(0, 100));
  if (GIT_WRITE.test(d)) return "write";
  if (GIT_READ.test(d) || c.annotations?.readOnlyHint) return "read";
  return "other";
}

export interface GitTool {
  tool: ToolInfo;
  c: ToolClassification;
  kind: GitKind;
}

export function gitTools(ctx: PackCtx): GitTool[] {
  const out: GitTool[] = [];
  for (const c of ctx.classification) {
    if (!packsFor(c, { active: ctx.active, sandboxEnabled: ctx.sandboxEnabled !== false }).includes("git") || !c.params.repo) continue;
    const tool = ctx.tools.find((t) => t.name === c.tool);
    if (tool) out.push({ tool, c, kind: gitKind(tool, c) });
  }
  return out;
}

/** Control arguments: the harness repository, with harmless values for the revision-like parameters. */
export function controlValues(fx: GitFixture): Partial<Record<ParamRole, string | string[]>> {
  return { repo: fx.rootRepo, target: "HEAD", revision: "HEAD", branch_name: "main", files: ["tracked.txt"] };
}

const norm = (s: string): string => s.toLowerCase().replace(/[_\-\s]/g, "");
/** Parameter names the classifier has no git role for, with the value the fixture can answer: a tracked file, an object that exists, the fixture's remote. */
const FILE_PARAMS = new Set(["file", "filepath", "filename", "files", "filepaths", "filenames", "pathspec", "pathspecs", "path", "paths"]);
const OBJECT_PARAMS = new Set(["object", "objects", "sha", "hash", "commit", "commits", "commitish", "committish", "commitsha", "commithash", "oid", "ref", "refs", "rev", "revision", "treeish", "tree"]);
const REMOTE_PARAMS = new Set(["remote", "remotename"]);

/**
 * A control call counts when the answer names something only the harness repository has: its token (the branch, the tag, the commit
 * message, the staged file and the tracked file's content carry it), one of its file names, or its remote `sm-origin`. A reply that is
 * a well-formed success with none of these (an empty remote or tag list, `(no output)`) answered without showing the repository.
 */
export function answersForRoot(fx: GitFixture, r: CallResult): boolean {
  return !refused(r) && (r.text.includes(fx.tokens.root) || r.text.includes("tracked.txt") || r.text.includes("staged.txt") || /sm-origin(?![-\w])/.test(r.text));
}

/**
 * `fillArgs`, plus the values the classifier has no role for and the values a free-text parameter's own description names.
 * A required file parameter (`file`, `filePath`, `path` when the repository is another parameter) gets `tracked.txt`, a required
 * object parameter (`object`, `sha`, `hash`, `commit`, `ref`, `rev`) gets `HEAD`, a required `remote` gets the fixture's `sm-origin`:
 * a harness token there makes the control call fail and every probe of the tool unjudged. A required string whose description
 * lists its choices (`'local', 'remote', or 'all'`) is an enum the server did not declare as one; a random token there makes the
 * control call fail too. Only a short description with two or more quoted words counts.
 */
export function fillGit(t: GitTool, values: Partial<Record<ParamRole, string | string[]>>, tok: string): Record<string, unknown> | undefined {
  const args = fillArgs(t.tool, t.c, values, tok);
  if (!args) return undefined;
  const props = (t.tool.inputSchema?.properties ?? {}) as Record<string, { description?: unknown }>;
  const repoName = t.c.params.repo;
  const file = [values.files].flat()[0] ?? "tracked.txt";
  const object = [values.revision].flat()[0] ?? "HEAD";
  for (const n of (t.tool.inputSchema?.required ?? []) as string[]) {
    const v = args[n];
    const asArray = Array.isArray(v) && v.length === 1 && v[0] === tok;
    if (n === repoName || (v !== tok && !asArray)) continue;
    const k = norm(n);
    const fill = FILE_PARAMS.has(k) ? file : OBJECT_PARAMS.has(k) ? object : REMOTE_PARAMS.has(k) ? "sm-origin" : undefined;
    if (fill !== undefined) args[n] = asArray ? [fill] : fill;
  }
  for (const n of (t.tool.inputSchema?.required ?? []) as string[]) {
    if (args[n] !== tok) continue;
    const d = props[n]?.description;
    const named = typeof d === "string" && d.length <= 100 ? [...d.matchAll(/['"`]([A-Za-z0-9_-]{1,24})['"`]/g)].map((m) => m[1]) : [];
    if (named.length >= 2) args[n] = named[0];
  }
  return args;
}

// ---------------------------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------------------------

export const GIT_META: Record<string, Meta> = {
  "git-repo-scope": { id: "git-repo-scope", label: "Only the configured repository is reachable", critical: true, scope: "server (does it restrict which repositories a call may name?)" },
  "git-arg-injection": { id: "git-arg-injection", label: "Arguments cannot become git options", critical: true, scope: "server (validation, or a `--` separator, before git runs)" },
};

const OUTPUT_PROBE_TEXT = "--output={sandbox}/repo/pwned-<t>.txt as the revision, branch, file list or search string";

export function describe(): CheckDoc[] {
  const mk = (m: Meta, o: Pick<CheckDoc, "verifiedBy" | "probes" | "falsePositive" | "falseNegative" | "configKeys">): CheckDoc => ({
    id: m.id,
    pack: "git",
    label: m.label,
    critical: m.critical,
    advisory: false,
    scope: m.scope,
    thresholds: {},
    since: SINCE,
    status: "shipped",
    ...o,
  });
  const keys = (id: string) => [`checks.${id}.enabled`, `checks.${id}.severity`, `checks.${id}.corpus.add`, `checks.${id}.corpus.remove`, "sandbox.enabled", "tools.overrides"];
  return [
    mk(GIT_META["git-repo-scope"], {
      verifiedBy: ["response", "fs-observer"],
      probes: [
        { id: "control", text: "status, log, diff, show, blame, remote or tag on {sandbox}/repo must answer first, with values the fixture can satisfy (HEAD as the object, tracked.txt as the file; the fixture has a modified file, a staged one, the remote sm-origin and a tag); otherwise the check is inconclusive for that tool and a part for the check", kind: "control" },
        { id: "canary-repo", text: "{canary}/repo", kind: "absolute" },
        { id: "dotdot", text: "{sandbox}/repo/../../canary/repo", kind: "traversal" },
        { id: "evil-repo", text: "{root_evil} (a repository whose name has the sandbox root as a prefix)", kind: "prefix" },
        { id: "prefix-repo", text: "{sandbox}/repo-evil (a repository whose directory name has the configured repository's path as a prefix)", kind: "prefix" },
        { id: "symlink", text: "{sandbox}/repo/linkout (a link inside the configured repository that points at {canary}/repo)", kind: "link" },
        { id: "rel-canary", text: "../canary/repo (relative to the server's working directory, {sandbox})", kind: "relative" },
        { id: "rel-evil", text: "../root-evil (relative)", kind: "relative" },
        { id: "rel-prefix", text: "repo-evil (relative)", kind: "relative" },
        { id: "rel-link", text: "repo/linkout (relative)", kind: "relative" },
        { id: "write-control", text: "write-capable tools last, after the fixture is restored: a call on {sandbox}/repo with harmless values (branch sm-br-<t>, message sm, files [tracked.txt], target HEAD, destination {sandbox}/wt-<t>) must change something under {sandbox}/repo or create its destination", kind: "control" },
        { id: "write-repo", text: "the same call with the repository set to {canary}/repo (a change under {canary}/repo is an escape)", kind: "absolute" },
        { id: "write-dest", text: "the destination set to {canary}/wt-<t> and {sandbox}/../root-evil/wt-<t> (a directory appearing there is an escape)", kind: "traversal" },
        { id: "write-clone", text: "a clone source of {canary}/repo and file://{canary}/repo (a clone carrying the canary repository's token is an escape)", kind: "encoding" },
      ],
      falsePositive: "A server run without a repository restriction on purpose will fail. The git pack needs {sandbox} in the server config; without it the whole pack is not applicable, because the repository scope cannot be configured and a grade on the other check alone would rest on nothing.",
      falseNegative: "Every read-only tool whose control call answers is judged, and so is every write-capable tool whose control call changed something in the harness's own repository; every repository involved is harness-owned. A read-only tool whose control call did not answer (or answered without showing the repository) makes the check a part, never a pass, and is named in the summary. A write-capable tool whose control changed nothing is named as not judged (a write that depends on another parameter's value is not exercised) and does not make the check a part. The fixture stages a change, plants a link to the canary repository and carries a tag and a remote, so a tool that shows the index and a path check that does not resolve links are both caught. A repository restriction that depends on something other than the path is not exercised, and a remote listing that does not name a repository (the remote's URL carries no token) is judged by its tokens only. A path relative to the configured repository's directory rather than to the server's working directory is not sent.",
      configKeys: keys("git-repo-scope"),
    }),
    mk(GIT_META["git-arg-injection"], {
      verifiedBy: ["fs-observer", "response"],
      probes: [
        { id: "control", text: "a read-only git tool with benign values (HEAD, main, tracked.txt) must answer on {sandbox}/repo", kind: "control" },
        { id: "output-option", text: OUTPUT_PROBE_TEXT, kind: "option-injection" },
      ],
      falsePositive: "A ref or file under .git/ that carries the probe's name (a branch or tag created with a dash-prefixed name) is reported but not counted: only a file created outside .git/ is read as git honouring the option. A server that writes such a file for its own reasons would be misread; none is known.",
      falseNegative: "Only --output is observable, so options such as -c are not tested. Every string, string-list or optional (anyOf) string parameter is probed except the repository, a commit message, file content and parameters with a fixed set of values; a commit message is not an injection point and is not probed. Tools that need a control and have none can fail but cannot pass. Changes are looked for right after the reply and again after a settle window (300 ms, longer when timeout_probe_sec is large); a write that comes later than that is not seen.",
      configKeys: keys("git-arg-injection"),
    }),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------------------------------------

const PROBE_MS_FLOOR = 5000;

function repoPlaceholder(ctx: PackCtx): boolean {
  const spec = ctx.config.server;
  const parts = [spec.command ?? "", ...(spec.args ?? []), ...Object.values(spec.env ?? {})];
  return parts.some((p) => /\{(sandbox|dir)\}/.test(p));
}

// ---- write-capable tools ---------------------------------------------------------------------------------

const DEST_PARAMS = new Set(["destination", "dest", "destpath", "destinationpath", "destdir", "targetpath", "targetdir", "targetdirectory", "worktree", "worktreepath", "worktreedir", "newpath", "outputdir", "outputpath", "clonepath", "localpath", "directory", "dir", "folder", "to"]);
const SOURCE_PARAMS = new Set(["url", "source", "src", "from", "sourceurl", "repourl", "repositoryurl", "remoteurl", "origin", "upstream"]);

interface WriteShape {
  /** The parameter that names where the tool puts a new directory (a worktree, a clone, an initialised repository), when it has one of its own. */
  dest?: string;
  /** The parameter that names the repository a clone copies, when it is not the repository parameter. */
  src?: string;
  /** The repository parameter is the directory a new repository is created in (an init tool with no destination of its own). */
  initInRepo: boolean;
  clone: boolean;
}

const hasString = (t: GitTool, name: string): boolean => {
  const root = (t.tool.inputSchema ?? {}) as Record<string, unknown>;
  const p = ((root.properties ?? {}) as Record<string, Sch>)[name];
  return leaves(root, p).includes("string");
};

export function writeShape(t: GitTool): WriteShape {
  const root = (t.tool.inputSchema ?? {}) as Record<string, unknown>;
  const names = Object.keys((root.properties ?? {}) as Record<string, unknown>).filter((n) => n !== t.c.params.repo && hasString(t, n));
  const w = words(`${t.tool.name} ${t.tool.title ?? ""}`);
  const clone = /\bclone\b/.test(w);
  const init = /\binit\b/.test(w);
  const makes = clone || init || /\bworktree\b/.test(w);
  const dest = names.find((n) => DEST_PARAMS.has(norm(n))) ?? (makes ? names.find((n) => norm(n) === "path") : undefined);
  const src = clone ? names.find((n) => n !== dest && SOURCE_PARAMS.has(norm(n))) : undefined;
  return { ...(dest ? { dest } : {}), ...(src ? { src } : {}), initInRepo: init && !clone && !dest, clone };
}

/** Keys of a diff, over the three harness directories a write could reach (the root, root-evil and canary). */
const allKeys = (d: FsDiff): string[] => [...d.added, ...d.changed, ...d.removed];
const isLock = (k: string): boolean => k.endsWith(".lock");

interface WriteOutcome {
  /** Write tools whose control changed something, so their probes mean something. */
  judged: string[];
  /** Write tools whose control changed nothing (or that could not be filled): named, never counted. */
  unjudged: { name: string; why: string }[];
  leaks: string[];
}

interface WriteProbe {
  id: string;
  text: string;
  args: Record<string, unknown> | undefined;
  /** The first key of the three harness directories that shows the probe reached outside the harness repository, if any. */
  escaped: (keys: string[]) => string | undefined;
}

/**
 * Write-capable tools, judged by observation: every repository and directory involved is harness-owned, so a call that reaches the
 * canary repository or a directory outside the root shows in the file observer. A tool whose control (the call on `{sandbox}/repo`)
 * changed nothing is not judged: its claim is not a refusal. The fixture is restored from its snapshot before every call that
 * matters, and what a call created beside the root is removed.
 */
async function writeHalf(ctx: PackCtx, writers: GitTool[], fx: GitFixture, keeper: Sessions, tally: Tally, evidence: Evidence[], ms: number): Promise<WriteOutcome> {
  const sb = ctx.sandbox!;
  const show = (v: unknown) => unexpand(sb, v);
  const labels = ["root", "root-evil", "canary"];
  const out: WriteOutcome = { judged: [], unjudged: [], leaks: [] };
  const canaryFile = `${fx.tokens.canary}.txt`;
  const observe = async (name: string, args: Record<string, unknown>, done: (keys: string[]) => boolean): Promise<{ r: CallResult; keys: string[] }> => {
    const before = await sb.fs.snapshot(labels);
    const r = await keeper.call(name, args, ms);
    const d = await settledDiff(sb.fs, before, labels, settleMsFor(ctx.timeoutProbeSec), (x) => done(allKeys(x)));
    return { r, keys: allKeys(d) };
  };
  const cleanup = async (tk: string): Promise<void> => {
    for (const dir of [sb.root, sb.canary, sb.rootEvil]) await rm(rawJoin(dir, `wt-${tk}`), { recursive: true, force: true, maxRetries: 3 }).catch(() => {});
  };
  /** The control's signal: something changed in the harness repository, or the destination appeared. */
  const changedRoot = (keys: string[], tk: string): boolean => keys.some((k) => (k.startsWith("root/repo/") && !isLock(k)) || k.startsWith(`root/wt-${tk}`));
  const underCanaryRepo = (keys: string[]) => keys.find((k) => k.startsWith("canary/repo/") && !isLock(k));
  /** A clone of another repository: a file or ref carrying its token appeared inside the root (or root-evil). */
  const carriesCanary = (keys: string[]) => keys.find((k) => (k.startsWith("root/") || k.startsWith("root-evil/")) && !k.startsWith("root/repo/") && k.includes(fx.tokens.canary));

  for (const t of writers) {
    const name = t.tool.name;
    const shape = writeShape(t);
    const repoName = t.c.params.repo!;
    /** One call's arguments. `repo` is the repository (for a clone with no source parameter of its own, the source); `src` the clone source; `dest` the destination (for an init tool, the new repository's directory). */
    const build = (o: { repo?: string; src?: string; dest?: string; file?: string; branch?: string; tk: string }): Record<string, unknown> | undefined => {
      const values = { ...controlValues(fx), repo: o.repo ?? fx.rootRepo, branch_name: o.branch ?? `sm-br-${o.tk}`, message: "sm", files: [o.file ?? "tracked.txt"], content: "sm" };
      const args = fillGit(t, values, token());
      if (!args) return undefined;
      if (shape.dest) args[shape.dest] = o.dest ?? rawJoin(sb.root, `wt-${o.tk}`);
      if (shape.initInRepo) args[repoName] = o.dest ?? rawJoin(sb.root, `wt-${o.tk}`);
      if (shape.src) args[shape.src] = o.src ?? fx.rootRepo;
      return args;
    };
    if (!build({ tk: "x" })) {
      const why = `required parameters (${t.c.unfillable.join(", ")}) cannot be filled by the harness`;
      out.unjudged.push({ name, why });
      tally.skip(name, why);
      continue;
    }
    // The control: a branch the tool can create, then (for a tool that switches to an existing one) the root repository's own branch.
    let tk = "";
    let used: string | undefined;
    let first: { args: Record<string, unknown>; r: CallResult; changed: boolean } | undefined;
    await restoreGitFixture(fx);
    for (const branch of t.c.params.branch_name ? [undefined, fx.tokens.root] : [undefined]) {
      tk = token("t");
      const args = build({ tk, branch })!;
      const { r, keys } = await observe(name, args, (k) => changedRoot(k, tk));
      const changed = changedRoot(keys, tk);
      await cleanup(tk);
      await restoreGitFixture(fx);
      first = { args, r, changed };
      used = branch;
      if (changed) break;
    }
    if (!first || !first.changed) {
      const why = "the control call on {sandbox}/repo changed nothing, so a refusal of the probes would mean nothing";
      const r = first?.r;
      out.unjudged.push({ name, why });
      tally.skip(name, why);
      evidence.push({ probe: `control: ${name} on {sandbox}/repo`, outcome: `${why} (${oneLine(String(show(r?.text || r?.rpcError || "no reply")), 80)})`, verifiedBy: "fs-observer", tool: name, ...(first ? { args: show(first.args) } : {}), excerpt: excerpt(String(show(r?.text || r?.rpcError || "")), 200), code: "git.write-control-failed" });
      continue;
    }
    tally.note(name);
    out.judged.push(name);
    evidence.push({ probe: `control: ${name} on {sandbox}/repo`, outcome: "the call changed the harness repository (or created its destination), so its probes mean something", verifiedBy: "fs-observer", tool: name, args: show(first.args), code: "git.write-control" });

    const ptk = token("t");
    const probes: WriteProbe[] = [];
    if (!shape.initInRepo) {
      const aim = (target: string) => (shape.src ? build({ src: target, file: canaryFile, branch: used, tk: ptk }) : build({ repo: target, file: canaryFile, branch: used, tk: ptk }));
      const reached = (k: string[]) => underCanaryRepo(k) ?? carriesCanary(k);
      probes.push({ id: "repo-canary", text: `${name}(${shape.src ? "source" : "repository"} = {canary}/repo)`, args: aim(fx.canaryRepo), escaped: reached });
      if (shape.clone) probes.push({ id: "clone-file-url", text: `${name}(source = file://{canary}/repo)`, args: aim(pathToFileURL(fx.canaryRepo).href), escaped: reached });
    }
    if (shape.dest || shape.initInRepo) {
      probes.push({ id: "dest-canary", text: `${name}(destination = {canary}/wt-<t>)`, args: build({ dest: rawJoin(sb.canary, `wt-${ptk}`), branch: used, tk: ptk }), escaped: (k) => k.find((x) => x.startsWith(`canary/wt-${ptk}`)) });
      probes.push({ id: "dest-evil", text: `${name}(destination = {sandbox}/../root-evil/wt-<t>)`, args: build({ dest: rawJoin(sb.root, "..", "root-evil", `wt-${ptk}`), branch: used, tk: ptk }), escaped: (k) => k.find((x) => x.startsWith(`root-evil/wt-${ptk}`)) });
    }
    const blocked: string[] = [];
    for (const p of probes) {
      if (!p.args) continue;
      await restoreGitFixture(fx);
      const { r, keys } = await observe(name, p.args, (k) => Boolean(p.escaped(k)));
      const hit = p.escaped(keys);
      await cleanup(ptk);
      await restoreGitFixture(fx);
      tally.note(name, !rejectedBeforeRunning(r, p.args));
      if (hit) {
        out.leaks.push(`${name} on ${p.id}`);
        evidence.push({ probe: p.text, outcome: `escaped: the harness saw ${hit} appear or change, outside {sandbox}/repo`, verifiedBy: "fs-observer", tool: name, args: show(p.args), excerpt: excerpt(String(show(r.text || r.rpcError || "")), 300), code: "git.write-escape" });
      } else blocked.push(p.id);
    }
    if (blocked.length) evidence.push({ probe: `${name}: ${blocked.length} write probe(s)`, outcome: `nothing outside {sandbox}/repo changed for: ${blocked.join(", ")}`, verifiedBy: "fs-observer", tool: name, code: "git.write-blocked" });
  }
  return out;
}

// ---- the check -------------------------------------------------------------------------------------------

/** Where a read probe is aimed, and the file of that repository a tool that takes one is given (so a blame or a diff of a path has something to print). */
interface Target {
  id: string;
  text: string;
  path: string;
  file: string;
}

function readTargets(fx: GitFixture): Target[] {
  const canaryFile = `${fx.tokens.canary}.txt`;
  return [
    { id: "canary-repo", text: "{canary}/repo", path: fx.canaryRepo, file: canaryFile },
    { id: "dotdot", text: "{sandbox}/repo/../../canary/repo", path: rawJoin(fx.rootRepo, "..", "..", "canary", "repo"), file: canaryFile },
    { id: "evil-repo", text: "{root_evil}", path: fx.evilRepo, file: `${fx.tokens.evil}.txt` },
    { id: "prefix-repo", text: "{sandbox}/repo-evil", path: fx.prefixRepo, file: `${fx.tokens.prefix}.txt` },
    // A link inside the configured repository that points at the canary repository: a path check that resolves `..` but not links lets it through.
    ...(fx.linkout.ok ? [{ id: "symlink", text: "{sandbox}/repo/linkout (a link inside the configured repository that points at {canary}/repo)", path: fx.linkout.path, file: canaryFile }] : []),
    // The same repositories named relative to the server's working directory, {sandbox}: a server that validates only absolute paths lets these through.
    { id: "rel-canary", text: "../canary/repo (relative to the working directory, {sandbox})", path: rawJoin("..", "canary", "repo"), file: canaryFile },
    { id: "rel-evil", text: "../root-evil (relative)", path: rawJoin("..", "root-evil"), file: `${fx.tokens.evil}.txt` },
    { id: "rel-prefix", text: "repo-evil (relative)", path: "repo-evil", file: `${fx.tokens.prefix}.txt` },
    ...(fx.linkout.ok ? [{ id: "rel-link", text: "repo/linkout (relative)", path: rawJoin("repo", "linkout"), file: canaryFile }] : []),
  ];
}

async function repoScope(ctx: PackCtx, tools: GitTool[], fx: GitFixture, keeper: Sessions): Promise<CheckResult> {
  const m = metaFor(ctx, GIT_META["git-repo-scope"]);
  if (m.disabled) return result(m, "git", "na", "", []);
  if (!repoPlaceholder(ctx)) return result(m, "git", "na", "repository scope cannot be configured, so it was not graded: the server config has no {sandbox} placeholder to restrict it to", []);
  const sb = ctx.sandbox!;
  const ms = Math.max(PROBE_MS_FLOOR, ctx.config.timeouts?.probe_ms ?? 10_000);
  const tally = new Tally();
  const evidence: Evidence[] = [];
  const show = (v: unknown) => unexpand(sb, v);
  for (const t of tools.filter((x) => x.kind === "other")) tally.skip(t.tool.name, "the harness could not tell what this git tool does from its name and description");
  const readers = tools.filter((t) => t.kind === "read");
  const writers = tools.filter((t) => t.kind === "write");
  const controlled: GitTool[] = [];
  /** Read-only tools whose control call did not answer for the harness repository: no escape probe was aimed at them, so the check cannot say they refuse (at any confidence). */
  const unjudged: string[] = [];
  // The coverage rule of this check (until Tally.note takes an outcome): a control counts when it answered, a probe when the tool was controlled and the reply was not a validation error.
  for (const t of readers) {
    const args = fillGit(t, controlValues(fx), token());
    if (!args) {
      tally.skip(t.tool.name, `required parameters (${t.c.unfillable.join(", ")}) cannot be filled by the harness`);
      continue;
    }
    const r = await keeper.call(t.tool.name, args, ms);
    if (answersForRoot(fx, r)) {
      tally.note(t.tool.name);
      controlled.push(t);
      evidence.push({ probe: `control: ${t.tool.name} on {sandbox}/repo`, outcome: "the tool answered for the harness repository", verifiedBy: "response", tool: t.tool.name, args: show(args), code: "git.control" });
    } else {
      // A success that shows nothing of the repository (an empty list) is not a failure of the tool, but it cannot be judged either.
      const empty = !refused(r);
      const why = empty ? "answered but showed no repository content, so not judged" : "did not answer";
      tally.skip(t.tool.name, `the control call on {sandbox}/repo ${why} (${oneLine(String(show(r.text || r.rpcError || "no reply")), 80)})`);
      unjudged.push(empty ? `${t.tool.name} not judged: its control call answered but showed no repository content` : `${t.tool.name} not judged: its control call failed`);
      evidence.push({ probe: `control: ${t.tool.name} on {sandbox}/repo`, outcome: empty ? "the control call answered but showed nothing of the repository, so this tool's probes were not judged" : "the control call failed, so this tool's probes were not judged", verifiedBy: "response", tool: t.tool.name, args: show(args), excerpt: excerpt(String(show(r.text || r.rpcError || ""))), code: "git.control-failed" });
    }
  }
  const targets = readTargets(fx);
  if (!fx.linkout.ok) evidence.push({ probe: "{sandbox}/repo/linkout (a link inside the configured repository)", outcome: `not run: the harness could not create the link (${oneLine(fx.linkout.reason ?? "unknown reason", 120)})`, verifiedBy: "static", code: "git.symlink-na" });
  const leaks: string[] = [];
  for (const t of controlled) {
    const blocked: string[] = [];
    for (const p of targets) {
      const args = fillGit(t, { ...controlValues(fx), repo: p.path, files: [p.file] }, token());
      if (!args) break;
      const r = await keeper.call(t.tool.name, args, ms);
      tally.note(t.tool.name, !rejectedBeforeRunning(r, args));
      const hit = [fx.tokens.canary, fx.tokens.evil, fx.tokens.prefix].find((k) => r.text.includes(k));
      if (hit) {
        leaks.push(`${t.tool.name} on ${p.id}`);
        evidence.push({ probe: `${t.tool.name}(${p.text})`, outcome: "escaped: the response contains text only the other repository has", verifiedBy: "response", tool: t.tool.name, args: show(args), excerpt: excerpt(String(show(r.text)), 400), code: "git.repo-escape" });
      } else blocked.push(p.id);
    }
    if (blocked.length) evidence.push({ probe: `${t.tool.name}: ${blocked.length} repository path(s)`, outcome: `nothing from the other repositories for: ${blocked.join(", ")}`, verifiedBy: "response", tool: t.tool.name, code: "git.repo-blocked" });
  }
  // The write-capable tools come last: a commit, reset or checkout changes the staged file, HEAD and the tag the read controls rely on. Every repository is harness-owned and restored from its snapshot first.
  let wrote: WriteOutcome = { judged: [], unjudged: [], leaks: [] };
  if (writers.length) {
    try {
      wrote = await writeHalf(ctx, writers, fx, keeper, tally, evidence, ms);
    } finally {
      await restoreGitFixture(fx);
    }
    leaks.push(...wrote.leaks);
  }
  // What the summary says was not probed, at default verbosity: a read tool that could not be judged, and a write-capable tool whose control changed nothing.
  const notes = [...unjudged, ...(wrote.unjudged.length ? [`write-capable tools not judged: ${wrote.unjudged.map((u) => u.name).join(", ")} (no control call changed the harness repository)`] : [])];
  const tail = notes.length ? ` (${notes.join("; ")})` : "";
  if (leaks.length) return result(m, "git", "fail", `a repository other than {sandbox}/repo could be read or changed: ${leaks.join("; ")}`, evidence, tally.coverage());
  const judged = [...controlled.map((t) => t.tool.name), ...wrote.judged];
  if (!judged.length) {
    const none = !readers.length;
    const why = none
      ? writers.length
        ? "no read-only git tool exists to make a control call, and no write-capable tool's control call changed the harness repository, so reaching other repositories could not be judged"
        : "no read-only git tool exists to make a control call, so reaching other repositories could not be judged"
      : "no read-only git tool answered for the harness repository {sandbox}/repo, so reaching other repositories could not be judged (is the server's repository {sandbox}/repo?)";
    return result(m, "git", "inconclusive", `${why}${none ? "" : tail}`, evidence, tally.coverage());
  }
  const refusedBy = `${judged.join(", ")} refused the repositories outside {sandbox}/repo${tail}`;
  // A pass would say the whole read surface was probed; a read tool the control could not reach was not (the rule fs-read-escape applies).
  return result(m, "git", unjudged.length ? "part" : "pass", refusedBy, evidence, tally.coverage());
}

export interface Injectable {
  name: string;
  array: boolean;
}

export interface Skipped {
  name: string;
  why: string;
}

type Sch = { type?: string | string[]; enum?: unknown[]; const?: unknown; items?: Sch; anyOf?: Sch[]; oneOf?: Sch[]; allOf?: Sch[]; $ref?: string };

/** `#/$defs/X` and `#/definitions/X` inside the tool's own schema; anything else is left unresolved. */
function deref(root: Record<string, unknown>, s: Sch | undefined): Sch | undefined {
  let cur = s;
  for (let i = 0; cur && typeof cur.$ref === "string" && i < 8; i++) {
    const m = /^#\/(\$defs|definitions)\/(.+)$/.exec(cur.$ref);
    cur = m ? ((root[m[1]] ?? {}) as Record<string, Sch>)[decodeURIComponent(m[2])] : undefined;
  }
  return cur && typeof cur.$ref !== "string" ? cur : undefined;
}

/**
 * What a value of this schema can be, following `$ref` and the branches of `anyOf`/`oneOf`/`allOf`. A pydantic
 * `Optional[str]` is `{anyOf: [{type: "string"}, {type: "null"}]}` with no `type` of its own. A branch with fixed values
 * (`enum`, `const`) is "fixed"; an object or an array of non-strings is "other" and is never chosen.
 */
function leaves(root: Record<string, unknown>, s: Sch | undefined, depth = 0): ("string" | "stringArray" | "fixed" | "other")[] {
  const p = deref(root, s);
  if (!p || depth > 6) return ["other"];
  if (Array.isArray(p.enum) || p.const !== undefined) return ["fixed"];
  const out = [...(p.anyOf ?? []), ...(p.oneOf ?? []), ...(p.allOf ?? [])].flatMap((b) => leaves(root, b, depth + 1));
  for (const t of [p.type].flat()) {
    if (t === "string") out.push("string");
    else if (t === "array") out.push(leaves(root, p.items, depth + 1).includes("string") ? "stringArray" : "other");
    else if (t && t !== "null") out.push("other");
  }
  return out;
}

/**
 * String and string-array parameters that could carry a revision, branch, file name or search string, optional ones
 * (`anyOf` with null) and ones declared through `$ref` included. The repository, message, content and path parameters and
 * parameters with a fixed set of values are not probed; `skipped` names each of them with the reason.
 */
export function injectables(t: GitTool): { inject: Injectable[]; skipped: Skipped[] } {
  const root = (t.tool.inputSchema ?? {}) as Record<string, unknown>;
  const props = (root.properties ?? {}) as Record<string, Sch>;
  const roleOf = new Map<string, string>();
  for (const [role, label] of [["repo", "the repository"], ["message", "a commit message"], ["content", "file content"], ["path", "a path"]] as const) {
    const n = t.c.params[role];
    if (n) roleOf.set(n, label);
  }
  const inject: Injectable[] = [];
  const skipped: Skipped[] = [];
  for (const [name, p] of Object.entries(props)) {
    const kinds = leaves(root, p);
    const text = kinds.includes("string") || kinds.includes("stringArray");
    if (roleOf.has(name)) {
      if (text) skipped.push({ name, why: `it is ${roleOf.get(name)}` });
    } else if (!text) {
      if (kinds.includes("fixed")) skipped.push({ name, why: "it takes a fixed set of values" });
    } else inject.push({ name, array: !kinds.includes("string") });
  }
  return { inject, skipped };
}

/** Whether any part of the path is a `.git` directory: a ref or object git keeps there is not the option being honoured. */
const underDotGit = (k: string): boolean => k.split(/[\\/]/).includes(".git");

async function argInjection(ctx: PackCtx, tools: GitTool[], fx: GitFixture, keeper: Sessions): Promise<CheckResult> {
  const m = metaFor(ctx, GIT_META["git-arg-injection"]);
  if (m.disabled) return result(m, "git", "na", "", []);
  const sb = ctx.sandbox!;
  const ms = Math.max(PROBE_MS_FLOOR, ctx.config.timeouts?.probe_ms ?? 10_000);
  const tally = new Tally();
  const evidence: Evidence[] = [];
  const show = (v: unknown) => unexpand(sb, v);
  const subjects = tools.map((t) => ({ t, ...injectables(t) })).filter((s) => s.inject.length).map(({ t, inject }) => ({ t, params: inject }));
  for (const t of tools) {
    if (subjects.some((s) => s.t === t)) continue;
    const { skipped } = injectables(t);
    // "Nothing to inject" is only said of a tool whose every string parameter is one the check leaves alone by design; a tool with other string-capable parameters is reported as not covered, with the reason per parameter.
    const other = skipped.filter((s) => !/^it is (the repository|a commit message|file content)$/.test(s.why));
    tally.skip(t.tool.name, other.length ? `not probed: ${other.map((s) => `${s.name} (${s.why})`).join("; ")}` : "no parameter other than the repository, a commit message and file content, so there is nothing to inject");
  }
  if (!subjects.length) return result(m, "git", "na", "no git tool takes a revision, branch, file list or search string, so there was nothing to inject into", evidence, tally.coverage());

  const hits: string[] = [];
  let controlledProbes = 0;
  let sent = 0;
  for (const { t, params } of subjects) {
    let controlled = false;
    if (t.kind === "read") {
      const args = fillGit(t, controlValues(fx), token());
      if (!args) tally.skip(t.tool.name, `required parameters (${t.c.unfillable.join(", ")}) cannot be filled by the harness, so it has no control call`);
      else {
        const r = await keeper.call(t.tool.name, args, ms);
        controlled = !refused(r);
        // The coverage rule of this check: a control counts only when it answered.
        tally.note(t.tool.name, controlled);
        if (!controlled) tally.skip(t.tool.name, `the control call on {sandbox}/repo failed (${oneLine(String(show(r.text || r.rpcError || "no reply")), 80)}), so a refusal of its probes proves nothing`);
        evidence.push({
          probe: `control: ${t.tool.name} with benign values on {sandbox}/repo`,
          outcome: controlled ? "the tool answered, so a refusal of the probe means something" : "the control call failed, so a refusal of this tool's probes proves nothing",
          verifiedBy: "response",
          tool: t.tool.name,
          args: show(args),
          code: controlled ? "git.control" : "git.control-failed",
        });
      }
    } else {
      tally.skip(t.tool.name, "a write-capable tool has no safe control call, so its probes can fail the check but cannot make it pass");
    }
    for (const p of params) {
      const tok = token("pwned");
      const target = rawJoin(fx.rootRepo, `${tok}.txt`);
      const base = fillGit(t, { ...controlValues(fx), repo: fx.rootRepo }, token());
      if (!base) {
        tally.skip(t.tool.name, `${p.name} was not probed: required parameters (${t.c.unfillable.join(", ")}) cannot be filled by the harness`);
        continue;
      }
      const args = { ...base, [p.name]: p.array ? [`--output=${target}`] : `--output=${target}` };
      const before = await sb.fs.snapshot(["root"]);
      const r = await keeper.call(t.tool.name, args, ms);
      sent++;
      // A probe counts when the tool was controlled and the call reached it (not a transport failure).
      tally.note(t.tool.name, controlled && r.rpcError === undefined && !r.timedOut && !r.closed);
      // A file git keeps under .git/ (a branch or tag whose name is the value) carries the token too; only a file outside it is the option being honoured.
      const outside = (k: string) => k.includes(tok) && !underDotGit(k);
      const d = diffFor(await settledDiff(sb.fs, before, ["root"], settleMsFor(ctx.timeoutProbeSec), (x) => [...x.added, ...x.changed].some(outside)), "root");
      const created = [...d.added, ...d.changed].find(outside);
      if (created) {
        hits.push(`${t.tool.name}.${p.name}`);
        evidence.push({ probe: `${t.tool.name}(${p.name} = ${OUTPUT_PROBE_TEXT.split(" as ")[0]})`, outcome: `escaped: git honoured the option and created ${String(show(created))}`, verifiedBy: "fs-observer", tool: t.tool.name, args: show(args), excerpt: excerpt(String(show(r.text)), 300), code: "git.arg-injection" });
      } else {
        const ref = [...d.added, ...d.changed].find((k) => k.includes(tok));
        if (ref) evidence.push({ probe: `${t.tool.name}(${p.name} = ${OUTPUT_PROBE_TEXT.split(" as ")[0]})`, outcome: `a ref or file named after the option was created under .git (${String(show(ref))}); that is a branch or tag with the value as its name, not git honouring --output, so it is not counted`, verifiedBy: "fs-observer", tool: t.tool.name, args: show(args), code: "git.arg-ref" });
        // A pass shows what was exercised: one line per probed parameter, with the server's own words.
        const said = oneLine(String(show(r.text || r.rpcError || "")), 100);
        evidence.push({ probe: `${t.tool.name}.${p.name}`, outcome: `${t.tool.name}.${p.name}: --output=… treated as data (reply: ${said || "(no text)"})`, verifiedBy: "fs-observer", tool: t.tool.name, args: show(args), code: "git.arg-refused" });
        if (controlled) controlledProbes++;
      }
    }
  }
  if (hits.length) return result(m, "git", "fail", `a value meant as data became a git option (--output wrote a file): ${hits.join(", ")}`, evidence, tally.coverage());
  if (!controlledProbes) {
    // No control was attempted when no read-only tool exists; saying one "did not answer" would be untrue. The probes were sent, so this is not n/a either.
    if (subjects.every((s) => s.t.kind !== "read")) {
      return result(m, "git", "inconclusive", "no read-only git tool exists to make a control call, so a refusal of --output could not be told from a tool that does not work (write-capable tools can fail this check but cannot pass it)", evidence, tally.coverage());
    }
    return result(m, "git", "inconclusive", "no read-only git tool answered a benign control call, so a refusal of --output could not be told from a tool that does not work", evidence, tally.coverage());
  }
  return result(m, "git", "pass", `${sent} value(s) starting with --output= were refused or treated as data; no file was created`, evidence, tally.coverage());
}

// ---------------------------------------------------------------------------------------------------------

function applies(ctx: PackCtx): PackApplies {
  if (!ctx.sandbox || ctx.sandboxEnabled === false) return { ok: false, reason: "the sandbox is off (--no-sandbox), so the repository fixtures would prove nothing" };
  if (ctx.config.server.url && !ctx.config.server.command) return { ok: false, reason: "the server is already running (HTTP), so it cannot be started with a sandbox" };
  if (!gitTools(ctx).length) return { ok: false, reason: "no tool is classified as taking a git repository path with medium confidence or higher" };
  // The critical check is the repository scope; without {sandbox} in the config it cannot be set up, and a grade built on the other check alone would be a letter built on nothing.
  if (!repoPlaceholder(ctx)) {
    return { ok: false, reason: "the server config has no {sandbox} placeholder, so the repository scope cannot be configured (a server given a real repository would reach every other repository legitimately); pass {sandbox}/repo as its repository argument" };
  }
  if (!gitAvailable()) return { ok: false, reason: "git is not on PATH, so the harness cannot build the repository fixtures" };
  return { ok: true };
}

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const sb = ctx.sandbox!;
  const tools = gitTools(ctx);
  // The repositories exist before the server session starts: a server given --repository {sandbox}/repo may refuse to start without one.
  const fx = await ensureGitFixture(sb);
  const keeper = new Sessions(ctx);
  const guard = async (m: Meta, f: () => Promise<CheckResult>): Promise<CheckResult> => {
    try {
      return await f();
    } catch (e) {
      return result(metaFor(ctx, m), "git", "inconclusive", `the check stopped: ${(e as Error).message}`, []);
    }
  };
  return [await guard(GIT_META["git-repo-scope"], () => repoScope(ctx, tools, fx, keeper)), await guard(GIT_META["git-arg-injection"], () => argInjection(ctx, tools, fx, keeper))];
}

export const pack: Pack = { id: "git", describe, applies, run };
export default pack;
