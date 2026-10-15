// Toy file-system MCP server for the round 5 fs corpus families. Each mode has one flaw, or is the near-miss that must still pass.
// Run: node dist/toy/fs-r5.js --mode <m> [--root <dir>] [--trace <file>] [--edit-shape strs|edits]
// Not part of the product surface. The expected verdicts are in the design notes (G9).
//
//   safe            every tool resolves the path (links and dangling links included) and holds it inside the root. Expected: all pass.
//   arrayonly       read_multiple_files validates paths[0] only. Expected: fs-read-escape fails through array-second.
//   arrayall-safe   read_multiple_files validates every element. Expected: pass.
//   bslash          read_file and write_file hold the path inside the root, then turn \ into / (a path that was one file name when it was
//                   checked). Expected: fs-read-escape and fs-write-escape fail through the backslash forms.
//   bslash-safe     the same tools treat \ as an ordinary character. Expected: pass.
//   movelink        move_file and copy_file check the path lexically and never resolve links. Expected: fs-link-escape fails through
//                   move-dest-link (and, for the copy tool, move-src-link); the plain write checks hold.
//   move-safe       move_file and copy_file resolve links before the check. Expected: pass.
//   editonly        edit_file is the only unvalidated tool. Expected: fs-write-escape fails.
//   edit-safe       edit_file validates like the others. Expected: pass.
//   linkfile        write_file resolves directory links (the directory of the path) but not a link to an existing file. Expected: fs-link-escape
//                   fails through link-file-write; the dangling link is refused.
//   dangling        write_file resolves links that exist, and treats a link whose target is missing as a new file inside the root. Expected:
//                   fs-link-escape fails through dangling-link-write.
//   search-substr   search_files matches a substring of the file name (no glob, no regex) and holds its path inside the root. Expected: judged.
//   search-open     the same search tool with no path check. Expected: fs-read-escape fails.
//   search-regexfail  search_files hands every pattern to a regex engine that rejects it. Expected: the control is listed as rejected as a regex; inconclusive.
//   search-nodep    search_files shells out to a program that is not installed. Expected: inconclusive, a dependency of the server is missing.
//   rootless        no root argument: the server works in its working directory and reads and writes any path. Expected: fs F when
//                   server.rootless is set.
//
// --edit-shape strs (default): edit_file takes path, old_str, new_str. edits: edit_file takes path and edits: [{oldText, newText}].
import { appendFileSync } from "node:fs";
import { copyFile, lstat, readFile, readdir, readlink, realpath, rename, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const FS_R5_MODES = ["safe", "arrayonly", "arrayall-safe", "bslash", "bslash-safe", "movelink", "move-safe", "editonly", "edit-safe", "linkfile", "dangling", "search-substr", "search-open", "search-regexfail", "search-nodep", "rootless"] as const;
type Mode = (typeof FS_R5_MODES)[number];

interface Reply {
  [x: string]: unknown;
  content: { type: "text"; text: string }[];
  isError?: boolean;
}
const ok = (text: string): Reply => ({ content: [{ type: "text", text }] });
const fail = (text: string): Reply => ({ content: [{ type: "text", text }], isError: true });
class Refused extends Error {}

function usage(msg: string): never {
  process.stderr.write(`toy fs-r5 server: ${msg}\nusage: fs-r5.js --mode <${FS_R5_MODES.join("|")}> [--root <dir>] [--trace <file>] [--edit-shape strs|edits]\n`);
  process.exit(2);
}

const { values } = parseArgs({ options: { mode: { type: "string" }, root: { type: "string" }, trace: { type: "string" }, "edit-shape": { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!FS_R5_MODES.includes(mode)) usage(`--mode must be one of ${FS_R5_MODES.join(", ")}`);
const editShape = values["edit-shape"] ?? "strs";
if (!["strs", "edits"].includes(editShape)) usage("--edit-shape must be strs or edits");
if (mode !== "rootless" && !values.root) usage("--root is required");
// The rootless server has no root argument: whatever directory it was started in is the only boundary it knows, and it holds nothing to it.
const rootArg = resolve(values.root ?? process.cwd());
let realRoot = rootArg;

/** Every mode caps a read at 8 MiB, so the size check passes and does not move 64 MiB through the transport. */
const READ_CAP = 8 * 1024 * 1024;
async function readCapped(p: string): Promise<string> {
  const st = await stat(p);
  if (st.size > READ_CAP) throw new Refused(`File too large: ${st.size} bytes exceeds the ${READ_CAP} byte limit`);
  return readFile(p, "utf8");
}

const within = (child: string, parent: string) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

/** The real path of `p`, following a link that points nowhere by hand; a missing tail is joined to its nearest existing ancestor. */
async function realOrParent(p: string, depth = 0): Promise<string> {
  try {
    return await realpath(p);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR") throw e;
    try {
      if ((await lstat(p)).isSymbolicLink() && depth < 16) return await realOrParent(resolve(dirname(p), await readlink(p)), depth + 1);
    } catch {
      /* not a link: a file that is about to be created */
    }
    const parent = dirname(p);
    if (parent === p) throw e;
    return join(await realOrParent(parent, depth), basename(p));
  }
}

/** The ordinary check: resolve, follow every link, hold the result inside the root. */
async function safe(input: unknown, what = "path"): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused(`${what} must be a non-empty string`);
  const real = await realOrParent(resolve(rootArg, input));
  if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return real;
}

/** The lexical check: no link is ever resolved. */
function lexical(input: unknown, what = "path"): string {
  if (typeof input !== "string" || !input) throw new Refused(`${what} must be a non-empty string`);
  const abs = resolve(rootArg, input);
  if (!within(abs, rootArg)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  return abs;
}

/** The old fallback: a path that does not exist is judged by its nearest existing ancestor, and a dangling link counts as a missing file. */
async function parentFallback(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  const abs = resolve(rootArg, input);
  let cur = abs;
  const tail: string[] = [];
  for (;;) {
    try {
      const real = join(await realpath(cur), ...tail);
      if (!within(real, realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
      return abs;
    } catch (e) {
      if (e instanceof Refused) throw e;
      const parent = dirname(cur);
      if (parent === cur) throw e;
      tail.unshift(basename(cur));
      cur = parent;
    }
  }
}

/** Directory links are resolved (the directory of the path is held inside the root); a link to an existing file is not, a link to nothing is refused. */
async function dirOnly(input: unknown): Promise<string> {
  if (typeof input !== "string" || !input) throw new Refused("path must be a non-empty string");
  const abs = resolve(rootArg, input);
  if (!within(await realOrParent(dirname(abs)), realRoot)) throw new Refused(`Access denied: ${input} is outside the allowed directory`);
  const st = await lstat(abs).catch(() => undefined);
  // A file that is not there yet is a new file; a link whose target is not there is refused.
  if (st?.isSymbolicLink() && !(await realpath(abs).then(() => true, () => false))) throw new Refused(`Access denied: ${input} is a link to nothing`);
  return abs;
}

/** Holds the path inside the root, then turns backslashes into slashes: a path that was one file name when it was checked. */
async function backslashAfter(input: unknown): Promise<string> {
  return (await safe(input)).replace(/\\/g, "/");
}

const none = (input: unknown): string => resolve(rootArg, String(input ?? ""));

type Check = (input: unknown) => Promise<string> | string;

/** What read_file and the other single-path tools use, per mode. */
function readCheck(): Check {
  return mode === "bslash" ? backslashAfter : mode === "rootless" ? none : (p) => safe(p);
}
function writeCheck(): Check {
  if (mode === "bslash") return backslashAfter;
  if (mode === "linkfile") return dirOnly;
  if (mode === "dangling") return parentFallback;
  return mode === "rootless" ? none : (p) => safe(p);
}
function moveCheck(): Check {
  return mode === "movelink" ? (p) => lexical(p) : (p) => safe(p);
}
function editCheck(): Check {
  return mode === "editonly" ? none : (p) => safe(p);
}
function searchCheck(): Check {
  return mode === "search-open" ? none : (p) => safe(p);
}

async function handle(name: string, args: Record<string, unknown>): Promise<Reply> {
  switch (name) {
    case "read_file": {
      const p = await readCheck()(args.path);
      return ok(await readCapped(p));
    }
    case "read_multiple_files": {
      if (!Array.isArray(args.paths)) return fail("paths must be an array");
      const outs: string[] = [];
      for (const [i, q] of args.paths.entries()) {
        // The flaw: only the first element is held inside the root.
        const p = mode === "arrayonly" && i > 0 ? none(q) : await safe(q);
        outs.push(`${String(q)}:\n${await readCapped(p)}`);
      }
      return ok(outs.join("\n---\n"));
    }
    case "write_file": {
      const p = await writeCheck()(args.path);
      if (typeof args.content !== "string") return fail("content must be a string");
      await writeFile(p, args.content);
      return ok(`Wrote ${Buffer.byteLength(args.content)} bytes`);
    }
    case "list_dir": {
      const p = await readCheck()(args.path);
      const entries = await readdir(p, { withFileTypes: true });
      return ok(entries.map((e) => `${e.isDirectory() ? "[DIR]" : "[FILE]"} ${e.name}`).join("\n"));
    }
    case "move_file":
    case "copy_file": {
      const check = moveCheck();
      const src = await check(args.source);
      const dest = await check(args.destination);
      if (name === "move_file") await rename(src, dest);
      else await copyFile(src, dest);
      return ok(`${name === "move_file" ? "Moved" : "Copied"} ${String(args.source)} to ${String(args.destination)}`);
    }
    case "edit_file": {
      const p = await editCheck()(args.path);
      const pairs: { oldText: string; newText: string }[] =
        editShape === "edits"
          ? (Array.isArray(args.edits) ? args.edits : []).map((e) => ({ oldText: String((e as Record<string, unknown>).oldText), newText: String((e as Record<string, unknown>).newText) }))
          : [{ oldText: String(args.old_str), newText: String(args.new_str) }];
      let text = await readFile(p, "utf8");
      for (const e of pairs) {
        if (!text.includes(e.oldText)) return fail(`Could not find the text to replace: ${e.oldText.slice(0, 40)}`);
        text = text.replace(e.oldText, e.newText);
      }
      await writeFile(p, text);
      return ok(`Edited ${String(args.path)}`);
    }
    case "search_files": {
      if (mode === "search-regexfail") return fail("Error: regex parse error: invalid regular expression (nothing to repeat)");
      if (mode === "search-nodep") return fail("Error: spawn rg ENOENT: rg: command not found");
      const p = await searchCheck()(args.path);
      if (typeof args.pattern !== "string") return fail("pattern must be a string");
      const hits: string[] = [];
      const walk = async (d: string): Promise<void> => {
        for (const e of await readdir(d, { withFileTypes: true })) {
          if (e.name.includes(String(args.pattern))) hits.push(join(d, e.name));
          if (e.isDirectory() && !(await lstat(join(d, e.name))).isSymbolicLink()) await walk(join(d, e.name));
        }
      };
      if ((await stat(p)).isDirectory()) await walk(p);
      return ok(hits.length ? hits.join("\n") : "No matches found");
    }
    default:
      return fail(`unknown tool ${name}`);
  }
}

// ---- tool list -------------------------------------------------------------------------------------------

interface ToolDef {
  name: string;
  description: string;
  inputSchema: { type: "object"; properties: Record<string, unknown>; required: string[] };
  annotations?: Record<string, boolean>;
}
const str = (description: string) => ({ type: "string", description });
const pathProp = { path: str("Path of the file or directory") };
const reader = { readOnlyHint: true, openWorldHint: false };
const writer = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };

function tools(): ToolDef[] {
  const list: ToolDef[] = [
    { name: "read_file", description: "Read the complete contents of a file as text.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: reader },
    { name: "write_file", description: "Create a new file or overwrite an existing file with the given content.", inputSchema: { type: "object", properties: { ...pathProp, content: str("Text to write") }, required: ["path", "content"] }, annotations: writer },
    { name: "list_dir", description: "List the entries of a directory.", inputSchema: { type: "object", properties: pathProp, required: ["path"] }, annotations: reader },
  ];
  if (mode === "arrayonly" || mode === "arrayall-safe") {
    list.push({ name: "read_multiple_files", description: "Read the contents of several files at once.", inputSchema: { type: "object", properties: { paths: { type: "array", items: { type: "string" }, description: "Files to read" } }, required: ["paths"] }, annotations: reader });
  }
  if (mode === "movelink" || mode === "move-safe") {
    const two = { source: str("File to take"), destination: str("Where it goes") };
    list.push(
      { name: "move_file", description: "Move or rename a file.", inputSchema: { type: "object", properties: two, required: ["source", "destination"] }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false } },
      { name: "copy_file", description: "Copy a file.", inputSchema: { type: "object", properties: two, required: ["source", "destination"] }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } },
    );
  }
  if (mode === "editonly" || mode === "edit-safe") {
    const props =
      editShape === "edits"
        ? { ...pathProp, edits: { type: "array", description: "The replacements", items: { type: "object", properties: { oldText: str("Text to find"), newText: str("Text to put in its place") }, required: ["oldText", "newText"] } } }
        : { ...pathProp, old_str: str("Text to find"), new_str: str("Text to put in its place") };
    list.push({ name: "edit_file", description: "Replace text in an existing file.", inputSchema: { type: "object", properties: props, required: editShape === "edits" ? ["path", "edits"] : ["path", "old_str", "new_str"] }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false } });
  }
  if (mode === "search-substr" || mode === "search-open" || mode === "search-regexfail" || mode === "search-nodep") {
    // The two broken search modes are search-only servers: nothing else reads, and nothing writes.
    if (mode === "search-regexfail" || mode === "search-nodep") list.length = 0;
    list.push({ name: "search_files", description: "Search for files whose name contains a pattern.", inputSchema: { type: "object", properties: { ...pathProp, pattern: str("Part of the file name") }, required: ["path", "pattern"] }, annotations: reader });
  }
  return list;
}

const toolList = tools();
const server = new Server({ name: `sealmark-toy-fs-r5-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolList }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (values.trace) appendFileSync(values.trace, `${JSON.stringify({ tool: req.params.name, args })}\n`);
  try {
    return await handle(req.params.name, args);
  } catch (e) {
    if (e instanceof Refused) return fail(e.message);
    const code = (e as NodeJS.ErrnoException).code;
    return fail(code ? `${code}: ${(e as Error).message}` : String((e as Error).message ?? e));
  }
});

try {
  realRoot = await realpath(rootArg);
} catch {
  /* the root may not exist yet when the harness only lists tools */
}
for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
