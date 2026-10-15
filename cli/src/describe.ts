import { readFileSync } from "node:fs";
import { cliSpecJson } from "./cli-spec.js";
import { CANDIDATE_CHECKS, CHECKS, METHODOLOGY, PACK_IDS, SCHEMA, SCHEMA_VERSION, STANDARD_PACKS, describeProfiles, type Leaf } from "./config/index.js";
import { describeAll } from "./packs/index.js";
import { CANDIDATE_PACKS, type CheckDoc } from "./types.js";

/**
 * `sealmark describe --json`: everything a docs generator, the website and other tooling need to know about
 * this build without running it. The object is validated against DESCRIBE_SCHEMA (below) by the tests; the
 * schema is the contract, so a field added here without a schema entry fails the `additionalProperties` rule.
 */

export const DESCRIBE_FORMAT = "sealmark.describe/1";

export type Severity = "critical" | "scored" | "advisory";

/** A CheckDoc plus what the registry alone cannot say: severity, whether the standard profile locks it, and every setting that affects it. */
export interface DescribedCheck extends CheckDoc {
  severity: Severity;
  /** Every setting that can change this check's behaviour is locked by the standard profile when true. */
  standardLocked: boolean;
  /** The check's pack runs in the standard profile. false for opt-in packs (exec). */
  inStandardPacks: boolean;
  /** Shipped advisory ahead of the standard (a 0.3-draft candidate): its settings are not locked, and turning it off or scoring it makes a run CUSTOM. */
  candidate: boolean;
  /** The check's pack is a candidate pack: it runs when its declaration exists, is scored in its own pack, is labelled in reports and stays off the badge. */
  candidatePack: boolean;
}

export interface ConfigKey {
  path: string;
  type: string;
  default: unknown;
  description: string;
  since: string;
  standardLocked: boolean;
  mergeable: boolean;
  secret: boolean;
  flagOnly: boolean;
  deprecated: boolean;
  /** For a deprecated key: the keys that replace it. */
  replacedBy?: string[];
  enum?: readonly string[];
}

export interface Described {
  format: typeof DESCRIBE_FORMAT;
  sealmark: { version: string; methodology: string; configSchemaVersion: number };
  /** `candidate`: a candidate pack (see `DescribedCheck.candidatePack`). */
  packs: { id: string; standard: boolean; candidate: boolean; checks: string[] }[];
  checks: DescribedCheck[];
  configKeys: ConfigKey[];
  profiles: { name: string; shipped: boolean; standard: boolean; description?: string; extends?: string }[];
  placeholders: { name: string; meaning: string }[];
  cli: ReturnType<typeof cliSpecJson>;
}

/** The CLI version from package.json (the same source run.ts reports). */
export function cliVersion(): string {
  try {
    return String((JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version?: string }).version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}

const PLACEHOLDERS: { name: string; meaning: string }[] = [
  { name: "{dsn}", meaning: "Connection string of the seeded Postgres role under test (db pack). {dsn:analyst}, {dsn:support} and {dsn:admin} pick a role." },
  { name: "{host} {port} {user} {password} {database} {role}", meaning: "The parts of that connection." },
  { name: "{sandbox}", meaning: "The sandbox root: the directory the harness owns, the server's working directory (fs, git, exec, effects, sqlite packs). {dir} is an alias." },
  { name: "{sandbox_home}", meaning: "The sandbox home directory (HOME, USERPROFILE and APPDATA of the server)." },
  { name: "{sqlite_path}", meaning: "A seeded SQLite database file inside the sandbox (sqlite pack)." },
  { name: "{duckdb_path}", meaning: "A seeded DuckDB database file inside the sandbox (sqlite pack, DuckDB engine)." },
  { name: "{listener}", meaning: "Base URL of the harness's loopback listener (probes only)." },
  { name: "{canary}", meaning: "Directory of canary files outside the sandbox root (probes only; never given to the server's own configuration)." },
  { name: "{token}", meaning: "A fresh random token per probe (probes only)." },
  { name: "{upstream}", meaning: "Base URL of the harness's upstream stub, the backend the server under test talks to (server.command, args, env, url, headers and server.files; needs upstream.kind: http). Refused in probes' arguments." },
  { name: "{bearer} {bearer:a} {bearer:b}", meaning: "A per-run credential for one of two identities the harness mints (identities.a and identities.b override them); {bearer} is {bearer:a}. Written in server.headers, for example Authorization: Bearer {bearer}. Refused in probes' arguments: a probe picks the caller with identity: a | b | none." },
  { name: "{upstream_token}", meaning: "Inside a scripted upstream reply only (upstream.responses[].reply and a probe's upstream.reply): a fresh sm-row-<hex> per occurrence, recorded so expect.upstream.token_echoed can tell whether a returned row reached the response." },
  { name: "{matrix.<name>}", meaning: "Inside a probe's args: the current value of that key of the probe's matrix; the probe is expanded into one probe per combination." },
  { name: "${VAR}  ${VAR:-default}", meaning: "A reference to an environment variable, filled in from your real environment when the run starts. Never written to reports. A variable that is not set and has no :-default is a configuration error (exit 2) in server.url, args, env and headers; write ${VAR:-} to allow empty." },
];

function severityOf(d: CheckDoc): Severity {
  return d.critical ? "critical" : d.advisory ? "advisory" : "scored";
}

function leafInfo(l: Leaf): ConfigKey {
  return {
    path: l.path,
    type: l.type,
    default: l.default ?? l.documentedDefault ?? null,
    description: l.description,
    since: l.since,
    standardLocked: Boolean(l.standardLocked),
    mergeable: Boolean(l.mergeable),
    secret: Boolean(l.secret),
    flagOnly: Boolean(l.flagOnly),
    deprecated: Boolean(l.deprecated),
    ...(l.deprecated ? { replacedBy: [...l.deprecated.to] } : {}),
    ...(l.enum ? { enum: [...l.enum] } : {}),
  };
}

/** Schema leaves that configure one check: `checks.<id>.*`. */
export function checkSettings(id: string): Leaf[] {
  return SCHEMA.filter((l) => l.path.startsWith(`checks.${id}.`));
}

/** Registry docs with severity, lock state and the full list of settings that affect each check. */
export function describeChecks(docs: CheckDoc[] = describeAll()): DescribedCheck[] {
  return docs.map((d) => {
    const own = checkSettings(d.id);
    const keys = [...new Set([...d.configKeys, ...own.map((l) => l.path)])].sort();
    const affecting = keys.map((k) => SCHEMA.find((l) => l.path === k)).filter((l): l is Leaf => Boolean(l));
    return {
      ...d,
      configKeys: keys,
      severity: severityOf(d),
      // A check with no settings at all is locked trivially; one with an unlocked setting is not.
      standardLocked: affecting.every((l) => l.standardLocked),
      inStandardPacks: STANDARD_PACKS.includes(d.pack),
      candidate: (CANDIDATE_CHECKS as readonly string[]).includes(d.id),
      candidatePack: CANDIDATE_PACKS.includes(d.pack),
    };
  });
}

export function describeAllJson(): Described {
  const checks = describeChecks();
  const packIds = [...new Set([...PACK_IDS, ...checks.map((c) => c.pack)])];
  return {
    format: DESCRIBE_FORMAT,
    sealmark: { version: cliVersion(), methodology: METHODOLOGY, configSchemaVersion: SCHEMA_VERSION },
    packs: packIds.map((id) => ({ id, standard: STANDARD_PACKS.includes(id), candidate: CANDIDATE_PACKS.includes(id), checks: checks.filter((c) => c.pack === id).map((c) => c.id) })),
    checks,
    configKeys: SCHEMA.map(leafInfo),
    profiles: describeProfiles().map((p) => ({ name: p.name, shipped: p.shipped, standard: p.standard, ...(p.description ? { description: p.description } : {}), ...(p.extends ? { extends: p.extends } : {}) })),
    placeholders: PLACEHOLDERS,
    cli: cliSpecJson(),
  };
}

/** Text for `sealmark describe --json`. */
export function renderDescribe(d: Described = describeAllJson()): string {
  return `${JSON.stringify(d, null, 2)}\n`;
}

// ---------------------------------------------------------------------------------------------------------
// Consistency between the check registry (the packs' describe()) and the configuration's table of check ids
// ---------------------------------------------------------------------------------------------------------

export interface Consistency {
  /** Check ids the configuration can address but no pack documents (a pack has not shipped its describe(), or an id is stale). */
  inConfigNotRegistry: string[];
  /** Check ids a pack documents that the configuration cannot address (so `checks.<id>.severity` would be rejected). */
  inRegistryNotConfig: string[];
  /** Ids whose pack differs between the two tables. */
  packMismatch: { id: string; registry: string; config: string }[];
  /** Ids documented twice. */
  duplicates: string[];
  /** Docs whose scope does not start with server, database or environment. */
  badScope: string[];
  /** `replaces` entries that name an id the configuration does not know even as a deprecated alias. */
  badReplaces: { id: string; replaces: string }[];
}

export function checkConsistency(docs: CheckDoc[] = describeAll()): Consistency {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const d of docs) (seen.has(d.id) ? dup : seen).add(d.id);
  const registry = new Map(docs.map((d) => [d.id, d]));
  const config = new Map(CHECKS.map((c) => [c.id, c]));
  const deprecated = new Set(SCHEMA.filter((l) => l.deprecated && l.path.startsWith("checks.")).map((l) => l.path.split(".")[1]));
  return {
    inConfigNotRegistry: CHECKS.filter((c) => !registry.has(c.id)).map((c) => c.id),
    inRegistryNotConfig: docs.filter((d) => !config.has(d.id) && !String(d.pack).startsWith("plugin:") && d.pack !== "custom").map((d) => d.id),
    packMismatch: docs.filter((d) => config.has(d.id) && config.get(d.id)!.pack !== d.pack).map((d) => ({ id: d.id, registry: d.pack, config: config.get(d.id)!.pack })),
    duplicates: [...dup],
    badScope: docs.filter((d) => !/^(server|database|environment)\b/.test(d.scope)).map((d) => d.id),
    badReplaces: docs.flatMap((d) => (d.replaces ?? []).filter((r) => !config.has(r) && !deprecated.has(r) && !registry.has(r)).map((r) => ({ id: d.id, replaces: r }))),
  };
}

// ---------------------------------------------------------------------------------------------------------
// The schema of the describe output, and a small validator for the JSON Schema subset it uses
// ---------------------------------------------------------------------------------------------------------

type JS = { [k: string]: unknown };
const str: JS = { type: "string" };
const bool: JS = { type: "boolean" };
const strs: JS = { type: "array", items: str };
const obj = (properties: Record<string, JS>, required: string[] = Object.keys(properties)): JS => ({ type: "object", properties, required, additionalProperties: false });
const arr = (items: JS): JS => ({ type: "array", items });
const VERIFIED = ["db-state", "response", "protocol", "static", "fs-observer", "listener", "process", "http", "upstream", "log"];

/** JSON Schema (draft-07 subset) for `sealmark describe --json`. */
export const DESCRIBE_SCHEMA: JS = {
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "sealmark describe",
  ...obj({
    format: { type: "string", enum: [DESCRIBE_FORMAT] },
    sealmark: obj({ version: str, methodology: str, configSchemaVersion: { type: "integer" } }),
    packs: arr(obj({ id: str, standard: bool, candidate: bool, checks: strs })),
    checks: arr({
      type: "object",
      required: ["id", "pack", "label", "critical", "advisory", "scope", "verifiedBy", "probes", "thresholds", "falsePositive", "falseNegative", "configKeys", "since", "status", "severity", "standardLocked", "inStandardPacks", "candidate", "candidatePack"],
      properties: {
        id: str,
        pack: str,
        label: str,
        critical: bool,
        advisory: bool,
        scope: str,
        verifiedBy: { type: "array", items: { type: "string", enum: VERIFIED } },
        probes: arr({ type: "object", required: ["id", "text"], properties: { id: str, text: str, core: bool, kind: str }, additionalProperties: false }),
        thresholds: { type: "object", additionalProperties: obj({ default: {}, configKey: str, standardLocked: bool }) },
        falsePositive: str,
        falseNegative: str,
        configKeys: strs,
        since: str,
        status: { type: "string", enum: ["shipped", "planned", "deprecated"] },
        replaces: strs,
        severity: { type: "string", enum: ["critical", "scored", "advisory"] },
        standardLocked: bool,
        inStandardPacks: bool,
        candidate: bool,
        candidatePack: bool,
      },
      additionalProperties: false,
    }),
    configKeys: arr({
      type: "object",
      required: ["path", "type", "default", "description", "since", "standardLocked", "mergeable", "secret", "flagOnly", "deprecated"],
      properties: { path: str, type: str, default: {}, description: str, since: str, standardLocked: bool, mergeable: bool, secret: bool, flagOnly: bool, deprecated: bool, replacedBy: strs, enum: strs },
      additionalProperties: false,
    }),
    profiles: arr({ type: "object", required: ["name", "shipped", "standard"], properties: { name: str, shipped: bool, standard: bool, description: str, extends: str }, additionalProperties: false }),
    placeholders: arr(obj({ name: str, meaning: str })),
    cli: obj({
      commands: arr({
        type: "object",
        required: ["name", "usage", "summary"],
        properties: { name: str, usage: str, summary: str, args: arr(obj({ name: str, required: bool, description: str })) },
        additionalProperties: false,
      }),
      flags: arr({
        type: "object",
        required: ["name", "type", "description", "commands"],
        properties: {
          name: str,
          type: { type: "string", enum: ["string", "boolean", "list"] },
          short: str,
          negatable: bool,
          metavar: str,
          description: str,
          commands: strs,
          schemaPath: str,
          safety: bool,
          status: { type: "string", enum: ["planned"] },
        },
        additionalProperties: false,
      }),
      exitCodes: arr(obj({ code: { type: "integer", enum: [0, 1, 2, 3, 4, 129, 130, 143] }, meaning: str })),
    }),
  }),
};

const typeOf = (v: unknown): string => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);

/**
 * Validates `value` against the JSON Schema subset DESCRIBE_SCHEMA uses: type (integer counts as number), enum,
 * properties, required, additionalProperties (false or a schema), items. Returns one message per problem, empty when valid.
 * A schema `{}` accepts anything.
 */
export function validateSchema(schema: JS, value: unknown, path = "$"): string[] {
  const out: string[] = [];
  const t = schema.type as string | undefined;
  if (t) {
    const actual = typeOf(value);
    const ok = t === actual || (t === "number" && actual === "integer");
    if (!ok) return [`${path}: expected ${t}, got ${actual}`];
  }
  if (Array.isArray(schema.enum) && !(schema.enum as unknown[]).includes(value)) out.push(`${path}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  if (t === "object" && value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    const props = (schema.properties ?? {}) as Record<string, JS>;
    for (const r of (schema.required ?? []) as string[]) if (!(r in o)) out.push(`${path}: missing required "${r}"`);
    for (const [k, v] of Object.entries(o)) {
      if (k in props) out.push(...validateSchema(props[k], v, `${path}.${k}`));
      else if (schema.additionalProperties === false) out.push(`${path}: unexpected property "${k}"`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === "object") out.push(...validateSchema(schema.additionalProperties as JS, v, `${path}.${k}`));
    }
  }
  if (t === "array" && Array.isArray(value) && schema.items) value.forEach((v, i) => out.push(...validateSchema(schema.items as JS, v, `${path}[${i}]`)));
  return out;
}
