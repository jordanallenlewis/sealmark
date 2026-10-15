import { readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { posix, win32 } from "node:path";
import type { ServerSpec } from "../types.js";
import { allPlaceholders, looksSecret } from "./placeholders.js";

/**
 * Readers for the MCP client configuration files `sealmark init` offers to import:
 * Claude Desktop, Claude Code, Cursor, VS Code and the GitHub Copilot CLI. Everything here is a pure function of
 * an `ImportEnv` (platform, home, cwd, a file reader), so tests run the Windows rules on any machine.
 *
 * Translation rules, from the design:
 * - `${VAR}`, `${env:VAR}`, `${VAR:-x}`: kept as a Sealmark environment reference, `${VAR}` / `${VAR:-x}`. It is resolved from
 *   the real environment when a run starts and is never written into a file or a report.
 * - `${workspaceFolder}` and `${cwd}`: the project directory. `${userHome}`: the home directory (nothing in sealmark
 *   expands a bare `~`, and neither does spawn, so the resolved path is written; the server is flagged machine-specific).
 * - `${input:id}`: asked for during init; the value goes to sealmark.local.yaml and the project file keeps `${SEALMARK_INPUT_ID}`.
 * - A literal value under a secret-looking name (and a URL password, a `--api-key=...` argument, a well-known token shape)
 *   goes to sealmark.local.yaml; the project file keeps an environment reference in its place.
 */

export const CLIENT_IDS = ["claude-desktop", "claude-code", "cursor", "vscode", "copilot-cli"] as const;
export type ClientId = (typeof CLIENT_IDS)[number];

export const CLIENT_LABELS: Record<SourceClient, string> = {
  manual: "command line",
  "claude-desktop": "Claude Desktop",
  "claude-code": "Claude Code",
  cursor: "Cursor",
  vscode: "VS Code",
  "copilot-cli": "GitHub Copilot CLI",
};

/** A server that did not come from a client file: `init --from` and `--from-url`. */
export type SourceClient = ClientId | "manual";

export interface ImportEnv {
  platform: NodeJS.Platform;
  home: string;
  /** The project directory: where `.mcp.json`, `.cursor/mcp.json` and `.vscode/mcp.json` are looked up and what `${workspaceFolder}` becomes. */
  cwd: string;
  env: Record<string, string | undefined>;
  /** UTF-8 text of a file, or undefined when it does not exist or cannot be read. */
  read(path: string): string | undefined;
  /** File names in a directory, or [] when it cannot be listed. */
  list(dir: string): string[];
}

/** An ImportEnv backed by the real file system and process. Pass `over` to replace parts of it. */
export function nodeImportEnv(over: Partial<ImportEnv> = {}): ImportEnv {
  return {
    platform: process.platform,
    home: homedir(),
    cwd: process.cwd(),
    env: process.env,
    read(path) {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    list(dir) {
      try {
        return readdirSync(dir);
      } catch {
        return [];
      }
    },
    ...over,
  };
}

export interface Candidate {
  client: ClientId;
  label: string;
  path: string;
  scope: "user" | "project";
  /** `claude-json` is ~/.claude.json: top-level mcpServers plus projects[<cwd>].mcpServers. */
  shape: "servers" | "claude-json";
  /** The location is expected from the client's documentation but has not been verified on a real install. */
  assumed?: boolean;
}

const pathModule = (platform: NodeJS.Platform) => (platform === "win32" ? win32 : posix);

/** Every file `init` looks at, in the order servers are listed. */
export function candidates(e: ImportEnv, only?: readonly ClientId[]): Candidate[] {
  const P = pathModule(e.platform);
  const out: Candidate[] = [];
  const add = (c: Candidate) => {
    if (!only || only.includes(c.client)) out.push(c);
  };
  const win = e.platform === "win32";
  const mac = e.platform === "darwin";
  const appData = win ? (e.env.APPDATA || P.join(e.home, "AppData", "Roaming")) : mac ? P.join(e.home, "Library", "Application Support") : (e.env.XDG_CONFIG_HOME || P.join(e.home, ".config"));

  add({ client: "claude-desktop", label: "Claude Desktop", path: P.join(appData, "Claude", "claude_desktop_config.json"), scope: "user", shape: "servers" });
  if (win) {
    const local = e.env.LOCALAPPDATA || P.join(e.home, "AppData", "Local");
    const packages = P.join(local, "Packages");
    for (const n of e.list(packages).filter((x) => /^Claude_/i.test(x))) {
      add({ client: "claude-desktop", label: "Claude Desktop (Microsoft Store install)", path: P.join(packages, n, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"), scope: "user", shape: "servers", assumed: true });
    }
  }

  add({ client: "claude-code", label: "Claude Code (user and local scope)", path: P.join(e.env.CLAUDE_CONFIG_DIR || e.home, ".claude.json"), scope: "user", shape: "claude-json" });
  add({ client: "claude-code", label: "Claude Code (project .mcp.json)", path: P.join(e.cwd, ".mcp.json"), scope: "project", shape: "servers" });

  add({ client: "cursor", label: "Cursor (user)", path: P.join(e.home, ".cursor", "mcp.json"), scope: "user", shape: "servers" });
  add({ client: "cursor", label: "Cursor (project)", path: P.join(e.cwd, ".cursor", "mcp.json"), scope: "project", shape: "servers" });

  add({ client: "vscode", label: "VS Code (project)", path: P.join(e.cwd, ".vscode", "mcp.json"), scope: "project", shape: "servers" });
  for (const dir of ["Code", "Code - Insiders"]) {
    add({ client: "vscode", label: `${dir === "Code" ? "VS Code" : "VS Code Insiders"} (user profile)`, path: P.join(appData, dir, "User", "mcp.json"), scope: "user", shape: "servers", assumed: true });
  }

  add({ client: "copilot-cli", label: "GitHub Copilot CLI", path: P.join(e.home, ".copilot", "mcp-config.json"), scope: "user", shape: "servers" });
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// JSON with comments
// ---------------------------------------------------------------------------------------------------------

/** Parses JSON that may carry a BOM, // and /* *\/ comments and trailing commas (VS Code and Cursor files do). */
export function parseJsonc(text: string): unknown {
  const src = text.replace(/^﻿/, "");
  let stripped = "";
  let inStr = false;
  for (let i = 0; i < src.length; ) {
    const c = src[i];
    if (inStr) {
      stripped += c;
      if (c === "\\") {
        stripped += src[i + 1] ?? "";
        i += 2;
        continue;
      }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') {
      inStr = true;
      stripped += c;
      i++;
    } else if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++;
    } else if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
    } else {
      stripped += c;
      i++;
    }
  }
  let out = "";
  inStr = false;
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i];
    if (inStr) {
      out += c;
      if (c === "\\") out += stripped[++i] ?? "";
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === ",") {
      let j = i + 1;
      while (j < stripped.length && /\s/.test(stripped[j])) j++;
      if (stripped[j] === "}" || stripped[j] === "]") continue; // trailing comma
      out += c;
    } else out += c;
  }
  return JSON.parse(out);
}

// ---------------------------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------------------------

export interface InputDef {
  id: string;
  description?: string;
  /** VS Code `password: true`: the value is a secret. */
  password?: boolean;
}

/** Values that must not be in the project file. Merged over it by the local file: maps key-wise, args and url as a whole. */
export interface LocalOverrides {
  /** The complete argument list with the literal secrets in place (lists replace across layers). */
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  headers?: Record<string, string>;
}

export interface ImportedServer {
  /** `claude-code/user/github`: stable within one scan, unique across clients and scopes. */
  id: string;
  /** The name the client calls it. */
  name: string;
  client: SourceClient;
  /** The file it came from ("command line" for init --from). */
  file: string;
  /** `user`, `project`, or `local (<project key>)` for Claude Code's per-project entries. */
  scope: string;
  transport: "stdio" | "http" | "sse";
  /** Safe to write to sealmark.yaml and to print: secrets are replaced by environment references. */
  spec: ServerSpec;
  /** What belongs in sealmark.local.yaml. Never print this. */
  local: LocalOverrides;
  /** Where secrets went, for display: `env.API_KEY`, `args[3]`, `headers.Authorization`. Names only, never values. */
  routed: string[];
  /** `${input:...}` variables the server references. */
  inputs: InputDef[];
  /** The client marks the server disabled. */
  disabled: boolean;
  /** Contains an absolute path of this machine (from ${workspaceFolder} or ${userHome}). */
  machineSpecific: boolean;
  warnings: string[];
}

export interface FileReport {
  path: string;
  client: ClientId;
  label: string;
  found: boolean;
  /** The file exists but could not be read as JSON. */
  error?: string;
  servers: number;
  assumed?: boolean;
}

export interface ScanResult {
  servers: ImportedServer[];
  files: FileReport[];
  /** Entries that are not servers sealmark can start (no command and no url). */
  skipped: { name: string; file: string; reason: string }[];
}

export interface ScanOptions {
  clients?: readonly ClientId[];
  /** Answers for `${input:id}` variables. */
  inputs?: Record<string, string | undefined>;
}

// ---------------------------------------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------------------------------------

const fwd = (p: string) => p.replace(/\\/g, "/");
const snake = (s: string) => s.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase() || "X";
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const baseName = (p: string) => fwd(p).replace(/\/+$/, "").split("/").pop() ?? "";

export interface TranslateCtx {
  projectDir: string;
  home: string;
  inputs: Record<string, string | undefined>;
}

interface Translated {
  /** Safe text: input variables are references. */
  main: string;
  /** Text with answered input variables filled in. Equal to `main` when there are none. */
  local: string;
  inputIds: string[];
  machine: boolean;
  warnings: string[];
}

/** A `D:\x\y` value, or `--root=D:\x\y`, becomes forward slashes; nothing else is touched (a regex or a message may contain backslashes). */
export function slashes(v: string): string {
  if (/^[A-Za-z]:\\/.test(v)) return v.replace(/\\/g, "/");
  const m = /^(--?[\w.-]+=)([A-Za-z]:\\.*)$/.exec(v);
  return m ? m[1] + m[2].replace(/\\/g, "/") : v;
}

/** Translates the client's interpolation syntax in one string (see the file header). Exported for tests. */
export function translate(s: string, tc: TranslateCtx): Translated {
  const inputIds: string[] = [];
  const warnings: string[] = [];
  let machine = false;
  const both = (re: RegExp, f: (m: RegExpExecArray) => [string, string]) => {
    let main = "";
    let local = "";
    let last = 0;
    for (const m of s.matchAll(re)) {
      const [a, b] = f(m as RegExpExecArray);
      main += s.slice(last, m.index) + a;
      local += s.slice(last, m.index) + b;
      last = (m.index ?? 0) + m[0].length;
    }
    return { main: main + s.slice(last), local: local + s.slice(last) };
  };
  const { main, local } = both(/\$\{([^}]*)\}/g, (m) => {
    const inner = m[1].trim();
    const same = (x: string): [string, string] => [x, x];
    if (inner === "workspaceFolder" || inner === "cwd") {
      machine = true;
      return same(fwd(tc.projectDir));
    }
    if (inner === "workspaceFolderBasename") return same(baseName(tc.projectDir));
    if (inner === "userHome") {
      machine = true;
      return same(fwd(tc.home));
    }
    if (inner === "pathSeparator" || inner === "/") return same("/");
    const env = /^env:([A-Za-z_][A-Za-z0-9_]*)(?::-(.*))?$/.exec(inner);
    if (env) return same(env[2] !== undefined ? `\${${env[1]}:-${env[2]}}` : `\${${env[1]}}`);
    const input = /^input:(.+)$/.exec(inner);
    if (input) {
      const id = input[1].trim();
      inputIds.push(id);
      const ref = `\${SEALMARK_INPUT_${snake(id)}}`;
      const given = tc.inputs[id];
      return [ref, given !== undefined ? given : ref];
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*(?::-.*)?$/.test(inner)) return same(m[0]);
    const kind = inner.split(":")[0];
    const w = `\${${kind}:...} is not translated (sealmark has no equivalent) and is passed to the server as written`;
    if (!warnings.includes(w)) warnings.push(w);
    return same(m[0]);
  });
  return { main: slashes(main), local: slashes(local), inputIds, machine, warnings };
}

const TOKEN_SHAPES = [/^sk-[A-Za-z0-9_-]{16,}$/, /^gh[pousr]_[A-Za-z0-9]{20,}$/, /^github_pat_[A-Za-z0-9_]{20,}$/, /^xox[abprs]-[A-Za-z0-9-]{10,}$/, /^AKIA[A-Z0-9]{16}$/, /^AIza[A-Za-z0-9_-]{30,}$/, /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./];

const isLiteral = (v: string) => v !== "" && !/\$\{[A-Za-z_]/.test(v) && !allPlaceholders().test(v);

/** `${NAME}` when NAME is a legal variable name. */
const ref = (name: string) => `\${${IDENT.test(name) ? name : snake(name)}}`;

/**
 * Finds a secret inside a literal value that does not sit under a secret-looking name: a password in URL userinfo, a
 * secret-looking query parameter, a well-known token shape. Returns the safe text and whether anything was replaced.
 */
export function scrubLiteral(v: string, refBase: string): { safe: string; secret: boolean } {
  if (!isLiteral(v) && !/^\w+:\/\//.test(v)) return { safe: v, secret: false };
  if (TOKEN_SHAPES.some((r) => r.test(v))) return { safe: ref(refBase), secret: true };
  const url = /^([a-z][a-z0-9+.-]*:\/\/)([^/@\s:]*):([^/@\s]+)@(.*)$/i.exec(v);
  let safe = v;
  let secret = false;
  if (url && isLiteral(url[3])) {
    safe = `${url[1]}${url[2]}:${ref(`${refBase}_PASSWORD`)}@${url[4]}`;
    secret = true;
  }
  const q = safe.indexOf("?");
  if (q >= 0 && /^[a-z][a-z0-9+.-]*:\/\//i.test(safe)) {
    const [path, rest] = [safe.slice(0, q), safe.slice(q + 1)];
    let hash = "";
    let query = rest;
    const h = rest.indexOf("#");
    if (h >= 0) {
      hash = rest.slice(h);
      query = rest.slice(0, h);
    }
    let changed = false;
    const parts = query.split("&").map((kv) => {
      const eq = kv.indexOf("=");
      if (eq < 0) return kv;
      const k = kv.slice(0, eq);
      const val = kv.slice(eq + 1);
      if (looksSecret(k) && isLiteral(val)) {
        changed = true;
        return `${k}=${ref(`${refBase}_${snake(k)}`)}`;
      }
      return kv;
    });
    if (changed) {
      safe = `${path}?${parts.join("&")}${hash}`;
      secret = true;
    }
  }
  return { safe, secret };
}

// ---------------------------------------------------------------------------------------------------------
// One server entry
// ---------------------------------------------------------------------------------------------------------

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);

/** Keys that carry meaning sealmark cannot honour. Listed in warnings; everything else (autoApprove, timeout, icons) is ignored quietly. */
const IGNORED_WITH_WARNING: Record<string, string> = {
  cwd: "cwd is ignored: the harness starts the server in its own sandbox directory",
  envFile: "envFile is not read: put the variables under env, or in sealmark.local.yaml",
  headersHelper: "headersHelper is not run: put the headers under headers, or in sealmark.local.yaml",
  oauth: "oauth settings are ignored: sealmark cannot complete an interactive sign-in, so a server that needs one cannot be graded",
  auth: "auth settings are ignored: sealmark cannot complete an interactive sign-in",
};

interface Raw {
  name: string;
  body: Json;
}

function convert(raw: Raw, cand: { client: SourceClient; path: string }, scope: string, e: ImportEnv, inputDefs: InputDef[], answers: Record<string, string | undefined>): ImportedServer | { skipped: string } {
  const b = raw.body;
  const command = typeof b.command === "string" ? b.command : undefined;
  const url = typeof b.url === "string" ? b.url : undefined;
  if (!command && !url) return { skipped: "it has neither a command nor a url" };
  const type = String(b.type ?? b.transport ?? "").toLowerCase();
  const transport: ImportedServer["transport"] = command ? "stdio" : type === "sse" ? "sse" : "http";
  const tc: TranslateCtx = { projectDir: e.cwd, home: e.home, inputs: answers };
  const key = snake(raw.name);
  const warnings: string[] = [];
  const routed: string[] = [];
  const inputIds = new Set<string>();
  let machine = false;
  const note = (t: Translated) => {
    t.inputIds.forEach((i) => inputIds.add(i));
    machine ||= t.machine;
    for (const w of t.warnings) if (!warnings.includes(w)) warnings.push(w);
  };
  const local: LocalOverrides = {};
  const spec: ServerSpec = {};

  if (command) {
    const t = translate(command, tc);
    note(t);
    spec.command = t.main;
    if (t.main !== t.local) {
      // A command that depends on an answered input cannot be split between files: keep the reference and say so.
      warnings.push("the command contains an ${input:...} variable; set SEALMARK_INPUT_* in the environment");
    }
  }

  if (Array.isArray(b.args)) {
    const mains: string[] = [];
    const locals: string[] = [];
    let flag: string | undefined; // previous argument when it is a secret-looking flag waiting for its value
    (b.args as unknown[]).forEach((raw0, i) => {
      const t = translate(String(raw0), tc);
      note(t);
      let main = t.main;
      let loc = t.local;
      let secret = main !== loc;
      if (!secret) {
        const eq = /^(--?[\w.-]+)=(.*)$/s.exec(main);
        if (eq && looksSecret(eq[1]) && isLiteral(eq[2])) {
          main = `${eq[1]}=${ref(`SEALMARK_${key}_${snake(eq[1])}`)}`;
          secret = true;
        } else if (flag !== undefined && !main.startsWith("-") && isLiteral(main)) {
          main = ref(`SEALMARK_${key}_${snake(flag)}`);
          secret = true;
        } else {
          const s = scrubLiteral(main, `SEALMARK_${key}_ARG${i}`);
          if (s.secret) {
            main = s.safe;
            secret = true;
          }
        }
      }
      flag = !secret && /^--?[\w.-]+$/.test(t.main) && looksSecret(t.main) ? t.main : undefined;
      if (secret) routed.push(`args[${i}]`);
      mains.push(main);
      locals.push(loc);
    });
    spec.args = mains;
    if (routed.some((r) => r.startsWith("args["))) local.args = locals;
  } else if (command) spec.args = [];

  if (isObj(b.env)) {
    spec.env = {};
    for (const [k, v] of Object.entries(b.env)) {
      const t = translate(String(v), tc);
      note(t);
      let main = t.main;
      let secret = main !== t.local;
      if (!secret && looksSecret(k) && isLiteral(main)) {
        main = ref(k);
        secret = true;
      } else if (!secret) {
        const s = scrubLiteral(main, k);
        if (s.secret) {
          main = s.safe;
          secret = true;
        }
      }
      spec.env[k] = main;
      if (secret) {
        (local.env ??= {})[k] = t.local;
        routed.push(`env.${k}`);
      }
    }
  }

  if (url) {
    const t = translate(url, tc);
    note(t);
    let main = t.main;
    let secret = main !== t.local;
    if (!secret) {
      const s = scrubLiteral(main, `SEALMARK_${key}_URL`);
      if (s.secret) {
        main = s.safe;
        secret = true;
      }
    }
    spec.url = main;
    if (secret) {
      local.url = t.local;
      routed.push("url");
    }
  }

  if (isObj(b.headers)) {
    spec.headers = {};
    for (const [k, v] of Object.entries(b.headers)) {
      const t = translate(String(v), tc);
      note(t);
      let main = t.main;
      let secret = main !== t.local;
      if (!secret && looksSecret(k) && isLiteral(main)) {
        main = ref(`SEALMARK_${key}_${snake(k)}`);
        secret = true;
      } else if (!secret) {
        const s = scrubLiteral(main, `SEALMARK_${key}_${snake(k)}`);
        if (s.secret) {
          main = s.safe;
          secret = true;
        }
      }
      spec.headers[k] = main;
      if (secret) {
        (local.headers ??= {})[k] = t.local;
        routed.push(`headers.${k}`);
      }
    }
  }

  if (transport === "sse") warnings.push("legacy SSE transport: sealmark connects with Streamable HTTP, so this server may not answer; the http pack applies only partially");
  for (const [k, msg] of Object.entries(IGNORED_WITH_WARNING)) if (k in b) warnings.push(msg);
  const unanswered = [...inputIds].filter((id) => answers[id] === undefined);
  if (unanswered.length) warnings.push(`input variable(s) ${unanswered.map((i) => `"${i}"`).join(", ")} were not answered; set ${unanswered.map((i) => `SEALMARK_INPUT_${snake(i)}`).join(", ")} in the environment or in sealmark.local.yaml`);

  return {
    id: `${cand.client}/${scope.split(" ")[0]}/${raw.name}`,
    name: raw.name,
    client: cand.client,
    file: cand.path,
    scope,
    transport,
    spec,
    local,
    routed,
    inputs: [...inputIds].map((id) => inputDefs.find((d) => d.id === id) ?? { id }),
    disabled: b.disabled === true || b.enabled === false,
    machineSpecific: machine,
    warnings,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------------------

const normKey = (p: string, platform: NodeJS.Platform) => {
  const s = p.replace(/\\/g, "/").replace(/\/+$/, "");
  return platform === "linux" ? s : s.toLowerCase();
};

function serversOf(doc: unknown): Json {
  if (!isObj(doc)) return {};
  if (isObj(doc.mcpServers)) return doc.mcpServers;
  if (isObj(doc.servers)) return doc.servers;
  return {};
}

function inputsOf(doc: unknown): InputDef[] {
  if (!isObj(doc) || !Array.isArray(doc.inputs)) return [];
  return doc.inputs.flatMap((i) => (isObj(i) && typeof i.id === "string" ? [{ id: i.id, ...(typeof i.description === "string" ? { description: i.description } : {}), ...(i.password === true ? { password: true } : {}) }] : []));
}

/** Reads every known client file and returns the servers found, translated. Missing files are reported, not errors. */
export function scanClients(e: ImportEnv, o: ScanOptions = {}): ScanResult {
  const result: ScanResult = { servers: [], files: [], skipped: [] };
  const answers = o.inputs ?? {};
  for (const cand of candidates(e, o.clients)) {
    const rep: FileReport = { path: cand.path, client: cand.client, label: cand.label, found: false, servers: 0, ...(cand.assumed ? { assumed: true } : {}) };
    result.files.push(rep);
    const text = e.read(cand.path);
    if (text === undefined) continue;
    rep.found = true;
    let doc: unknown;
    try {
      doc = parseJsonc(text);
    } catch (err) {
      rep.error = `not valid JSON: ${(err as Error).message}`;
      continue;
    }
    const groups: { scope: string; servers: Json }[] = [];
    if (cand.shape === "claude-json") {
      if (isObj(doc) && isObj(doc.mcpServers)) groups.push({ scope: "user", servers: doc.mcpServers });
      if (isObj(doc) && isObj(doc.projects)) {
        const want = normKey(e.cwd, e.platform);
        for (const [k, p] of Object.entries(doc.projects)) {
          if (normKey(k, e.platform) === want && isObj(p) && isObj(p.mcpServers)) groups.push({ scope: `local (project ${k})`, servers: p.mcpServers });
        }
      }
    } else groups.push({ scope: cand.scope, servers: serversOf(doc) });
    const defs = inputsOf(doc);
    for (const g of groups) {
      for (const [name, body] of Object.entries(g.servers)) {
        if (!isObj(body)) {
          result.skipped.push({ name, file: cand.path, reason: "the entry is not an object" });
          continue;
        }
        const c = convert({ name, body }, cand, g.scope, e, defs, answers);
        if ("skipped" in c) result.skipped.push({ name, file: cand.path, reason: c.skipped });
        else {
          result.servers.push(c);
          rep.servers++;
        }
      }
    }
  }
  const seen = new Map<string, number>();
  for (const s of result.servers) {
    const n = (seen.get(s.id) ?? 0) + 1;
    seen.set(s.id, n);
    if (n > 1) s.id = `${s.id}#${n}`;
  }
  return result;
}

/** The full configuration with the local overrides applied: what the harness will actually run. Contains secrets; never print or write it to a shared file. */
export function fullSpec(s: ImportedServer): ServerSpec {
  return {
    ...s.spec,
    ...(s.local.args ? { args: s.local.args } : {}),
    ...(s.local.url ? { url: s.local.url } : {}),
    ...(s.spec.env || s.local.env ? { env: { ...s.spec.env, ...s.local.env } } : {}),
    ...(s.spec.headers || s.local.headers ? { headers: { ...s.spec.headers, ...s.local.headers } } : {}),
  };
}

/** One display line, `name  (client)  command|url`, safe to print (secrets are references). */
export function describeServer(s: ImportedServer): string {
  const what = s.spec.url ?? [s.spec.command, ...(s.spec.args ?? [])].join(" ");
  return `${s.name}  (${CLIENT_LABELS[s.client]}${s.scope === "user" || s.scope === "project" ? "" : `, ${s.scope}`})  ${what}${s.disabled ? "  [disabled in the client]" : ""}`;
}

/** Picks servers by id, by `client/name`, or by name when it is unique. "all" takes every server. Unknown or ambiguous queries are returned in `problems`. */
export function selectServers(all: readonly ImportedServer[], queries: readonly string[]): { chosen: ImportedServer[]; problems: string[] } {
  if (queries.length === 1 && queries[0] === "all") return { chosen: [...all], problems: [] };
  const chosen: ImportedServer[] = [];
  const problems: string[] = [];
  for (const q of queries) {
    const hits = all.filter((s) => s.id === q || `${s.client}/${s.name}` === q || s.name === q);
    if (hits.length === 1) {
      if (!chosen.includes(hits[0])) chosen.push(hits[0]);
    } else if (hits.length === 0) problems.push(`no imported server matches "${q}"`);
    else problems.push(`"${q}" matches ${hits.length} servers (${hits.map((h) => h.id).join(", ")}); use one of those ids`);
  }
  return { chosen, problems };
}

/** One config key per server: the client's name, made unique with the client then a number when two clients use the same one. */
export function uniqueNames(servers: readonly ImportedServer[]): Map<string, string> {
  const used = new Set<string>();
  const names = new Map<string, string>();
  const dupes = (n: string) => servers.filter((s) => s.name === n).length > 1;
  for (const s of servers) {
    let base = s.name.trim().replace(/\s+/g, "-") || "server";
    if (dupes(s.name)) base = `${base}-${s.client}`;
    let n = base;
    for (let i = 2; used.has(n); i++) n = `${base}-${i}`;
    used.add(n);
    names.set(s.id, n);
  }
  return names;
}

/** Builds a server from a command line or URL the user typed (`init --from`, `--from-url`), through the same secret handling as a client file. */
export function importManual(raw: { name: string; command?: string; args?: string[]; url?: string; env?: Record<string, string>; headers?: Record<string, string> }, e: ImportEnv, inputs: Record<string, string | undefined> = {}): ImportedServer {
  const body: Json = { ...(raw.command ? { command: raw.command, args: raw.args ?? [] } : {}), ...(raw.url ? { url: raw.url } : {}), ...(raw.env ? { env: raw.env } : {}), ...(raw.headers ? { headers: raw.headers } : {}) };
  const c = convert({ name: raw.name, body }, { client: "manual", path: "command line" }, "command line", e, [], inputs);
  if ("skipped" in c) throw new Error("a server needs a command or a url");
  return c;
}
