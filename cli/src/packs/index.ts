import { describe as describeCore, runCore } from "./core.js";
import { describe as describeDb, runDb } from "./db.js";
import { pack as custom } from "./custom.js";
import { pack as effects } from "./effects.js";
import { pack as exec } from "./exec.js";
import { pack as fs } from "./fs.js";
import { pack as git } from "./git.js";
import { pack as http } from "./http.js";
import { pack as net } from "./net.js";
import { pack as scope } from "./scope.js";
import { pack as sqlGuard } from "./sql-guard.js";
import { pack as sqlite } from "./sqlite.js";
import { pack as upstream } from "./upstream.js";
import type { CheckDoc, Pack, PackCtx, PackId } from "../types.js";

/**
 * `core` as a Pack. run.ts calls runCore directly because it reuses the discovery session; this wrapper is for the
 * registry (describe, listing) and for callers that build a PackCtx by hand.
 */
export const corePack: Pack = {
  id: "core",
  describe: describeCore,
  applies: () => ({ ok: true }),
  async run(ctx: PackCtx) {
    const session = await ctx.open();
    try {
      return await runCore({ session, canaries: ctx.canaries ?? [], seen: [], hangMs: ctx.hangMs });
    } finally {
      await session.close();
    }
  },
};

/** `db` as a Pack; needs `ctx.db` (the seeded database and a way to open the server as each role). */
export const dbPack: Pack = {
  id: "db",
  describe: describeDb,
  applies(ctx: PackCtx) {
    if (!ctx.db) return { ok: false, reason: "no seeded database is available" };
    if (!ctx.sqlTools?.length) return { ok: false, reason: "no tool takes a SQL string" };
    return { ok: true };
  },
  async run(ctx: PackCtx) {
    if (!ctx.db || !ctx.sqlTools) return [];
    return runDb({ target: ctx.db.target, sqlTools: ctx.sqlTools, open: ctx.db.openAs, timeoutSec: ctx.timeoutProbeSec, log: ctx.log });
  },
};

/** Every built-in pack. Replacing a placeholder means overwriting its file; this list never changes. */
export const REGISTRY: Pack[] = [corePack, dbPack, http, fs, git, net, sqlite, exec, scope, sqlGuard, upstream, effects, custom];

/**
 * Order in which run.ts executes the packs that follow `core` and `db`.
 * `effects` comes after the packs whose calls it audits, the candidate packs (`scope`, `sql-guard`, `upstream`) included.
 */
export const RUN_ORDER: PackId[] = ["http", "fs", "git", "net", "sqlite", "exec", "scope", "sql-guard", "upstream", "effects", "custom"];

export function getPack(id: PackId): Pack | undefined {
  return REGISTRY.find((p) => p.id === id);
}

/** Check docs of every built-in pack, in registry order (what `sealmark describe` and `list-checks` print). */
export function describeAll(packs: Pack[] = REGISTRY): CheckDoc[] {
  return packs.flatMap((p) => p.describe());
}
