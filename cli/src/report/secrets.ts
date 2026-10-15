import { allPlaceholders, expandEnvRefs, looksSecret, secretShaped } from "../config/placeholders.js";
import type { EffectiveConfig } from "../config/index.js";
import { isModeWord } from "./redact.js";

/**
 * Literal strings that must never appear in a report (they are scrubbed by report/redact.ts).
 *
 * - values under secret-looking names in a server's `env` and `headers`, as written and with `${VAR}` references resolved,
 * - the password of a URL (`https://user:pass@host`) in `server.url` and `--pg`,
 * - the values of secret-looking flags in a server's arguments (`--token abc`, `--api-key=abc`), from every layer: a CI file
 *   or a `--start "srv --token $TOKEN"` flag puts the expanded secret on the command line, which a report would print,
 * - the values of secret-looking query parameters of `server.url` (`?token=...`, `?api_key=...`),
 * - what `sealmark.local.yaml` supplies for a server: its env, headers and url, and the arguments that look like secrets.
 *
 * sealmark.local.yaml is an ordinary configuration layer (it can set `packs`, `profile`, paths), so only the places a secret
 * can live are harvested from it, never every string it happens to contain. A value that is only a placeholder or an
 * environment reference is not a secret.
 */

const MIN = 4;
const URL_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^/@\s:]*:([^/@\s]+)@/i;
/** Query parameters that carry a credential but whose names looksSecret does not know (signed URLs, session ids). */
const QUERY_SECRET_NAME = /^(?:sig|signature|jwt|sid|session(?:[_-]?id)?)$/i;
const isReference = (v: string) => allPlaceholders().test(v) || /\$\{[A-Za-z_]/.test(v);

const decode = (s: string): string => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

/** Raw and decoded values of the query parameters that look like credentials by name or by shape. */
function queryCredentials(url: string): string[] {
  const q = /\?([^#]*)/.exec(url)?.[1];
  if (!q) return [];
  const out: string[] = [];
  for (const pair of q.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 1) continue;
    const name = decode(pair.slice(0, eq).replace(/\+/g, " "));
    const raw = pair.slice(eq + 1);
    const value = decode(raw.replace(/\+/g, " "));
    if (looksSecret(name) || QUERY_SECRET_NAME.test(name) || secretShaped(value)) out.push(raw, value);
  }
  return out;
}

const unpointer = (ptr: string): string[] => ptr.split("/").slice(1).map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));

function getAt(root: unknown, path: readonly string[]): unknown {
  let cur = root;
  for (const seg of path) {
    if (Array.isArray(cur)) cur = cur[Number(seg)];
    else if (cur && typeof cur === "object") cur = (cur as Record<string, unknown>)[seg];
    else return undefined;
  }
  return cur;
}

export function secretLiterals(cfg: Pick<EffectiveConfig, "servers" | "db" | "origins" | "value" | "env"> & Partial<Pick<EffectiveConfig, "sandbox">>): string[] {
  const out = new Set<string>();
  const add = (v: unknown) => {
    // A mode word (`true`, `none`, `required`) under a secret-looking name is a setting, not a secret: scrubbing it would mangle the report.
    if (typeof v === "string" && v.length >= MIN && !isReference(v) && !isModeWord(v)) out.add(v);
  };

  const takeArgs = (args: readonly unknown[]): void => {
    args.forEach((a, i) => {
      if (typeof a !== "string") return;
      const eq = a.indexOf("=");
      const prev = i > 0 ? args[i - 1] : undefined;
      let value: string | undefined;
      if (a.startsWith("-") && eq > 0 && looksSecret(a.slice(0, eq))) {
        add(a);
        value = a.slice(eq + 1);
      } else if (typeof prev === "string" && prev.startsWith("-") && !prev.includes("=") && looksSecret(prev)) value = a;
      if (value === undefined) return;
      add(value);
      add(expandEnvRefs(value, cfg.env));
    });
  };

  for (const { spec } of cfg.servers) {
    for (const m of [spec.env, spec.headers]) {
      for (const [k, v] of Object.entries(m ?? {})) {
        // The password of a URL is a secret under any name (DATABASE_URL), and so is a value shaped like a credential.
        const pwd = URL_PASSWORD.exec(v);
        if (pwd) add(decode(pwd[1]));
        if (!looksSecret(k) && !secretShaped(v)) continue;
        add(v);
        // A reference like ${API_KEY} resolves to the real secret from the environment.
        const resolved = expandEnvRefs(v, cfg.env);
        add(resolved);
        // "Bearer <token>": a server that echoes only the token (not the scheme) must be scrubbed too.
        const scheme = /^(?:bearer|basic|token|digest|apikey)\s+(\S+)$/i.exec(resolved);
        if (scheme) add(scheme[1]);
        const rpwd = URL_PASSWORD.exec(resolved);
        if (rpwd) add(decode(rpwd[1]));
      }
    }
    const pw = spec.url ? URL_PASSWORD.exec(spec.url) : null;
    if (pw) add(decode(pw[1]));
    if (spec.url) for (const v of queryCredentials(spec.url)) add(v);
    // A secret on the command line: `--token abc` and `--api-key=abc`, whichever layer supplied the arguments.
    takeArgs(spec.args ?? []);
  }
  // identities.a / identities.b (round 6) are tokens the harness sends and the stub, a log or a reply may echo: as written and read from the environment.
  const identities = getAt(cfg.value, ["identities"]);
  for (const name of ["a", "b"]) {
    const v = getAt(identities, [name]);
    if (typeof v !== "string") continue;
    add(v);
    add(expandEnvRefs(v, cfg.env));
  }
  const pg = cfg.db.pg ? URL_PASSWORD.exec(cfg.db.pg) : null;
  if (pg) add(decode(pg[1]));

  // A stdio server started with the real environment (--no-sandbox, sandbox.scrub_env: false) can echo any of it back, so
  // the environment itself is scrubbed from the report. Only values that are plausibly secret: 8+ characters, not a path.
  // The few variables sandbox.keep_env lets through a scrubbed sandbox are always included.
  // A server Sealmark starts itself with --start + --url (command and url) always runs with the real environment: no sandbox.
  const launched = cfg.servers.some((s) => s.spec.url && s.spec.command);
  const stdio = cfg.servers.some((s) => !s.spec.url) || launched;
  const inherited = launched || (stdio && cfg.sandbox !== undefined && (!cfg.sandbox.enabled || !cfg.sandbox.scrub_env));
  const kept = new Set((cfg.sandbox?.keep_env ?? []).map((k) => k.toLowerCase()));
  if (stdio) {
    for (const [name, v] of Object.entries(cfg.env ?? {})) {
      if (typeof v !== "string" || v.length < 8 || isReference(v)) continue;
      if (inherited && /^[A-Za-z]+$/.test(v) && !looksSecret(name)) continue; // a plain word (production, Windows) would mangle ordinary report text
      if (inherited ? looksSecret(name) || secretShaped(v) || !/[\\/]/.test(v) : kept.has(name.toLowerCase())) add(v);
    }
  }

  // What the local file supplies for a server: `server.*` or `servers.<name>.*`.
  const seen = new Set<string>();
  for (const [ptr, origin] of Object.entries(cfg.origins)) {
    if (origin.layer !== "local") continue;
    const segs = unpointer(ptr);
    const base = segs[0] === "server" ? ["server"] : segs[0] === "servers" && segs.length > 2 ? ["servers", segs[1]] : undefined;
    if (!base) continue;
    const field = segs[base.length];
    const key = `${base.join("/")}/${field}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const value = getAt(cfg.value, [...base, field]);
    if (field === "env" || field === "headers") {
      if (value && typeof value === "object") for (const v of Object.values(value as Record<string, unknown>)) add(v);
    } else if (field === "url") add(value);
    else if (field === "args" && Array.isArray(value)) takeArgs(value);
  }
  return [...out];
}
