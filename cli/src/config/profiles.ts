import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mergeLayers, type Layer, type Merged } from "./layers.js";
import { parseConfigText, type ProfileDef } from "./loader.js";
import { ConfigError } from "./model.js";
import { didYouMean } from "./util.js";

/** Shipped profile names, in display order. Their YAML lives in config/profiles/ and is read-only. */
export const SHIPPED_PROFILES = ["standard", "quick", "ci", "strict", "paranoid"] as const;
/** The shipped profiles whose runs can still be STANDARD (ci changes only output and exit policy). */
export const STANDARD_PROFILES: readonly string[] = ["standard", "ci"];

export interface ProfileRecord {
  name: string;
  shipped: boolean;
  extends?: string;
  description?: string;
  layer: Layer;
}

const dir = fileURLToPath(new URL("./profiles/", import.meta.url));
const cache = new Map<string, ProfileRecord>();

/** Reads and validates one shipped profile. A broken shipped file is a packaging bug, reported as a ConfigError. */
export function shippedProfile(name: string): ProfileRecord {
  const hit = cache.get(name);
  if (hit) return hit;
  const file = `${dir}${name}.yaml`;
  const issues: string[] = [];
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    throw new ConfigError(`shipped profile "${name}" is missing from the installation (${(e as Error).message}); reinstall sealmark or run "npm run build"`);
  }
  const loaded = parseConfigText(text.replace(/^﻿/, ""), `profile:${name}`, "profile", issues, { profileBody: true, source: `profile:${name}` });
  if (issues.length || !loaded) throw new ConfigError(`shipped profile "${name}" is invalid:\n${issues.join("\n")}`);
  loaded.layer.lines.clear();
  const rec: ProfileRecord = { name, shipped: true, extends: loaded.extends, description: loaded.description, layer: loaded.layer };
  cache.set(name, rec);
  return rec;
}

export const isShipped = (name: string): boolean => (SHIPPED_PROFILES as readonly string[]).includes(name);

export function userRecord(def: ProfileDef): ProfileRecord {
  return { name: def.name, shipped: false, extends: def.extends, description: def.description, layer: def.layer };
}

/**
 * The profile chain for `name`, base first. A profile without `extends` builds on `standard`.
 * Cycles and unknown names are reported through `issues`.
 */
export function resolveChain(name: string, user: ReadonlyMap<string, ProfileRecord>, issues: string[], via: string[] = []): ProfileRecord[] {
  if (via.includes(name)) {
    issues.push(`profile cycle: ${[...via, name].join(" -> ")}`);
    return [];
  }
  const rec = user.get(name) ?? (isShipped(name) ? shippedProfile(name) : undefined);
  if (!rec) {
    const known = [...SHIPPED_PROFILES, ...user.keys()];
    const hint = didYouMean(name, known);
    issues.push(`unknown profile "${name}"${via.length ? ` (extended by ${via[via.length - 1]})` : ""}; shipped: ${SHIPPED_PROFILES.join(", ")}${user.size ? `; yours: ${[...user.keys()].join(", ")}` : ""}${hint ? `; did you mean "${hint}"?` : ""}`);
    return [];
  }
  const parent = rec.extends ?? (name === "standard" ? undefined : "standard");
  return [...(parent ? resolveChain(parent, user, issues, [...via, name]) : []), rec];
}

/** Merged values (defaults included) of a profile chain. */
export function mergeChain(chain: readonly ProfileRecord[]): Merged {
  return mergeLayers(chain.map((r) => r.layer));
}

let standardCache: Merged | undefined;
/** Defaults overlaid with the shipped `standard` profile: the reference every run is compared against. */
export function standardMerged(): Merged {
  return (standardCache ??= mergeLayers([shippedProfile("standard").layer]));
}
