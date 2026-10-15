// The `upstream` pack: what does the server do with the caller's credential and with its backend's replies?
// Candidate pack: scored inside itself, off the badge. It needs the harness-owned upstream stub (`upstream.kind: http`, `{upstream}` in the
// server config). Checks: upstream-credential, upstream-credential-echo, log-secret, upstream-error-leak, upstream-slow.
//
// The pack re-makes the valid calls (probes: entries without `check`) itself, because it has to make them as identity a, as identity b,
// anonymously, and while the stub answers in `error` or `slow` mode. Nothing here parses SQL or proxies anything.
import type { McpSession } from "../mcp.js";
import { planContext, runProbe, validateProbes, type PlannedProbe, type ProbeOutcome } from "../probes.js";
import { NO_UPSTREAM_STUB, NO_VALID_CALL } from "./shared.js";
import type { CheckDoc, CheckResult, Evidence, IdentityName, Pack, PackApplies, PackCtx, PackId, UpstreamRequest, Verdict } from "../types.js";

const PACK: PackId = "upstream";

const SINCE = "0.3-draft";
const SCOPE = "server (what the harness's upstream stub received from the server, and what the server printed or relayed)";
const NO_STUB = NO_UPSTREAM_STUB;
const NO_BEARER = "the server's headers carry no {bearer}: set `server.headers.Authorization: Bearer {bearer}`";
const STDIO = "a stdio server has no per-caller credential to pass: this check needs an HTTP server whose headers use {bearer}";
const MAX_ERROR_LEG = 12;

interface Meta { id: string; label: string; critical: boolean }
const META = {
  credential: { id: "upstream-credential", label: "Each caller's own credential reaches the upstream", critical: true },
  echo: { id: "upstream-credential-echo", label: "Replies never contain a caller's credential", critical: false },
  log: { id: "log-secret", label: "The server's log never contains a caller's credential", critical: false },
  errorLeak: { id: "upstream-error-leak", label: "Upstream error bodies are not relayed with the credential", critical: false },
  slow: { id: "upstream-slow", label: "A slow upstream does not hang the server", critical: false },
} satisfies Record<string, Meta>;

export function describe(): CheckDoc[] {
  const keys = (id: string, extra: string[] = []) => [`checks.${id}.enabled`, `checks.${id}.severity`, ...extra, "upstream.kind", "upstream.credential_header", "identities.a", "identities.b"];
  const mk = (m: Meta, o: Pick<CheckDoc, "verifiedBy" | "probes" | "falsePositive" | "falseNegative" | "configKeys"> & Partial<Pick<CheckDoc, "thresholds">>): CheckDoc => ({
    id: m.id,
    pack: PACK,
    label: m.label,
    critical: m.critical,
    advisory: false,
    scope: SCOPE,
    thresholds: {},
    since: SINCE,
    status: "shipped",
    ...o,
  });
  return [
    mk(META.credential, {
      verifiedBy: ["upstream"],
      probes: [
        { id: "identity-a", text: "every valid call (a `probes:` entry without `check`) as identity a ({bearer:a}); the stub records the credential header of each request the server makes", kind: "control" },
        { id: "identity-b", text: "the same calls as identity b ({bearer:b}); a request that carries identity a's token (a cached credential) or a credential that is neither identity's (a static one) fails", kind: "corpus" },
        { id: "anonymous", text: "the same calls with every header that holds {bearer} dropped; a refusal is fine, a request that reaches the upstream with a credential header fails", kind: "corpus" },
      ],
      falsePositive: "A server that validates the tokens it receives refuses the minted ones, so nothing reaches the stub: the check is inconclusive, never a fail (set identities.a and identities.b to real tokens). A server that deliberately uses its own service credential for some tools fails on those tools.",
      falseNegative: "Only the harness's valid calls are observed; a tool the harness did not call can still use a shared credential. A request that carries no credential at all is reported but is not a fail.",
      configKeys: keys(META.credential.id),
    }),
    mk(META.echo, {
      verifiedBy: ["response"],
      probes: [{ id: "replies", text: "the replies to the valid calls under identities a and b are searched for either minted token", kind: "corpus" }],
      falsePositive: "None known: the tokens are random strings the harness minted for this run.",
      falseNegative: "A token echoed only for arguments the harness did not send is not seen. An encoded or truncated echo is not seen.",
      configKeys: keys(META.echo.id),
    }),
    mk(META.log, {
      verifiedBy: ["log"],
      probes: [{ id: "log", text: "the server's stdout and stderr, as Sealmark captured them, are searched for either minted token and for the upstream error canary", kind: "corpus" }],
      falsePositive: "None known for a server Sealmark started or ran over stdio. A server that logs to a file or a collector is not seen.",
      falseNegative: "Only the last 1 MiB of output is kept. A server that logs a hash or a truncated token is not seen.",
      configKeys: keys(META.log.id),
    }),
    mk(META.errorLeak, {
      verifiedBy: ["upstream", "response"],
      probes: [{ id: "error-mode", text: "the stub answers every request with HTTP 500 and a body that carries the error canary and the credential header it received; the valid calls run as identity a", kind: "corpus" }],
      falsePositive: "A server that relays the raw error body is relaying the credential the stub echoed: that is what is measured. A relay of the error canary alone is evidence, not a fail.",
      falseNegative: "A server that relays only part of an error body (without the canary), or only for other tools, is not seen. A credential in a reply without the error body is the server's own echo: upstream-credential-echo grades it, not this check.",
      configKeys: keys(META.errorLeak.id),
    }),
    mk(META.slow, {
      verifiedBy: ["upstream", "response"],
      probes: [{ id: "slow-mode", text: "the stub holds every reply for expected_sec + 5 s; the first valid call that reaches it is made with a timeout of expected_sec + 2 s", kind: "corpus" }],
      thresholds: { expected_sec: { default: "timeout_probe_sec", configKey: "checks.upstream-slow.expected_sec", standardLocked: false } },
      falsePositive: "A server that answers an error within expected_sec + 2 s passes. A server that needs longer than that to give up is a fail by the bound the config states.",
      falseNegative: "Only the first call that reaches the stub is held; a tool with a different backend timeout is not seen.",
      configKeys: keys(META.slow.id, ["checks.upstream-slow.expected_sec", "timeout_probe_sec"]),
    }),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Check results with checks.<id>.enabled and .severity applied (the pattern of packs/http.ts)
// ---------------------------------------------------------------------------------------------------------

function result(ctx: PackCtx, m: Meta, verdict: Verdict, summary: string, evidence: Evidence[], scrub: (s: string) => string, coverage?: CheckResult["coverage"]): CheckResult {
  const c = ctx.config?.checks?.[m.id];
  const origin = ctx.config?.origins?.[`/checks/${m.id}/enabled`]?.source ?? "config";
  const sev = c?.severity ?? null;
  const critical = sev === "critical" ? true : sev === "scored" || sev === "advisory" ? false : m.critical;
  const base: CheckResult = {
    id: m.id,
    pack: PACK,
    label: m.label,
    critical,
    ...(sev === "advisory" ? { advisory: true } : {}),
    scope: SCOPE,
    verdict,
    summary: scrub(summary),
    evidence: evidence.map((e) => ({ ...e, probe: scrub(e.probe), outcome: scrub(e.outcome), ...(e.excerpt !== undefined ? { excerpt: scrub(e.excerpt) } : {}) })),
    ...(coverage ? { coverage } : {}),
  };
  return c && c.enabled === false ? { ...base, verdict: "na", summary: `disabled by config (${origin})`, evidence: [] } : base;
}

export const pack: Pack = {
  id: PACK,
  describe,
  applies(ctx: PackCtx): PackApplies {
    return ctx.upstream ? { ok: true } : { ok: false, reason: NO_STUB };
  },
  run,
};
export default pack;

// ---------------------------------------------------------------------------------------------------------
// Valid calls
// ---------------------------------------------------------------------------------------------------------

interface Leg {
  /** Why no session could be opened (a server that refuses the minted token, or every anonymous caller). */
  openError?: string;
  outcomes: ProbeOutcome[];
  requests: UpstreamRequest[];
  /** Every reply text and error, for the echo scan. */
  texts: string[];
  /** True when every call was refused, errored or never made. */
  allRefused: boolean;
}

const CALL_CAP = 8;

function planProbes(ctx: PackCtx): { probes: PlannedProbe[]; problem?: string } {
  const specs = (ctx.config.probes ?? []).filter((p) => p && typeof p === "object" && p.check === undefined);
  if (!specs.length) return { probes: [], problem: NO_VALID_CALL };
  try {
    // Planned as the harness plans the valid calls: SQL is allowed on a SQL tool because the stub is the only backend the server has.
    const plan = validateProbes(specs, { tools: ctx.tools, classification: ctx.classification, sandbox: ctx.sandbox, defaultTimeoutMs: ctx.config.timeouts?.probe_ms, ...planContext(ctx.config, ctx.upstream) });
    const probes = plan.probes.filter((p) => !p.check && !p.usesDb && p.schemaProblems.length === 0 && (!p.active || ctx.active)).slice(0, CALL_CAP);
    return probes.length ? { probes } : { probes: [], problem: `${NO_VALID_CALL} (the existing entries are active-only, use a database placeholder or do not match the tool's schema)` };
  } catch (e) {
    return { probes: [], problem: `the valid-call probes could not be planned: ${(e as Error).message.split("\n")[0]}` };
  }
}

/**
 * Runs the valid calls in one fresh session. `until` ends the loop early (the slow leg stops at the first call that reached the stub).
 * `timeoutMs` replaces each probe's own timeout.
 */
async function runLeg(ctx: PackCtx, open: () => Promise<McpSession>, probes: PlannedProbe[], o: { timeoutMs?: number; stopAtFirstReach?: boolean } = {}): Promise<Leg> {
  const stub = ctx.upstream!;
  const mark = stub.mark();
  const out: Leg = { outcomes: [], requests: [], texts: [], allRefused: true };
  let session: McpSession;
  try {
    session = await open();
  } catch (e) {
    out.openError = (e as Error).message.split("\n")[0]!.slice(0, 200);
    return out;
  }
  try {
    for (const p of probes) {
      const planned = o.timeoutMs ? { ...p, timeoutMs: o.timeoutMs } : p;
      const before = stub.requests(mark).length;
      let oc: ProbeOutcome;
      try {
        oc = await runProbe(planned, { session, sandbox: ctx.sandbox, active: ctx.active, listenerReachable: true });
      } catch (e) {
        out.texts.push(String((e as Error).message));
        continue;
      }
      out.outcomes.push(oc);
      if (oc.text) out.texts.push(oc.text);
      if (oc.called && !oc.isError && !oc.timedOut) out.allRefused = false;
      if (o.stopAtFirstReach && stub.requests(mark).length > before) break;
    }
  } finally {
    await session.close().catch(() => {});
  }
  out.requests = stub.requests(mark);
  return out;
}

// ---------------------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------------------

const hasBearerHeader = (headers: Record<string, string> | undefined): boolean => Object.values(headers ?? {}).some((v) => typeof v === "string" && /\{bearer[:}]/.test(v));

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const stub = ctx.upstream;
  const log = ctx.serverLog;
  const identity = ctx.identity;
  if (!stub) return [];

  const idents = identity?.identities ?? [];
  const bearer = (n: IdentityName): string => idents.find((i) => i.name === n)?.bearer ?? "";
  // Evidence never holds a minted token: it is rewritten before it reaches a summary, an outcome or an excerpt (the report scrubber is the backstop).
  const scrub = (s: string): string => {
    let t = s;
    for (const i of idents) if (i.bearer) t = t.split(i.bearer).join(`{bearer:${i.name}}`);
    return t;
  };
  const cred = (ctx.config.upstream?.credential_header || "authorization").toLowerCase();
  const res = (m: Meta, verdict: Verdict, summary: string, evidence: Evidence[] = [], coverage?: CheckResult["coverage"]) => result(ctx, m, verdict, summary, evidence, scrub, coverage);

  const http = Boolean(ctx.config.server.url);
  const usesBearer = hasBearerHeader(ctx.config.server.headers);
  const identNa = !http ? STDIO : !usesBearer ? NO_BEARER : !identity ? "the harness opened no per-caller identities for this run" : undefined;

  const { probes, problem } = planProbes(ctx);
  const off = (m: Meta): boolean => ctx.config?.checks?.[m.id]?.enabled === false;
  const out: CheckResult[] = [];
  const reset = () => {
    try {
      stub.setMode("normal");
    } catch {
      // the stub is closed: nothing to reset
    }
  };

  const openA = (): Promise<McpSession> => (identity && !identNa ? identity.openAs("a") : ctx.open());
  // The probes' ctx.open() fallback is for the slow leg on stdio servers only; the identity legs are gated by identNa.

  // ---- legs a, b and anonymous (feed upstream-credential and upstream-credential-echo) ----
  let legA: Leg | undefined;
  let legB: Leg | undefined;
  let legN: Leg | undefined;
  const mark0Log = log?.mark();
  if (!problem && !identNa && identity && (!off(META.credential) || !off(META.echo))) {
    legA = await runLeg(ctx, () => identity.openAs("a"), probes);
    legB = await runLeg(ctx, () => identity.openAs("b"), probes);
    legN = await runLeg(ctx, () => identity.openAs(null), probes);
  }

  // ---- upstream-credential ----
  out.push(
    (() => {
      const m = META.credential;
      if (off(m)) return res(m, "na", "disabled by config");
      if (identNa) return res(m, "na", identNa);
      if (problem) return res(m, "inconclusive", problem);
      const evidence: Evidence[] = [];
      const fails: string[] = [];
      const seenOwn: IdentityName[] = [];
      const headerOf = (r: UpstreamRequest): string | undefined => r.headers[cred];
      const holds = (r: UpstreamRequest, token: string): boolean => Boolean(token) && Object.values(r.headers).some((v) => v.includes(token));
      for (const [name, leg, other] of [["a", legA!, "b"], ["b", legB!, "a"]] as const) {
        const own = bearer(name);
        const foreign = bearer(other);
        const reached = leg.requests.length;
        const ownHits = leg.requests.filter((r) => holds(r, own));
        const swapped = leg.requests.filter((r) => holds(r, foreign));
        const stat = leg.requests.filter((r) => !holds(r, own) && !holds(r, foreign) && Boolean(headerOf(r)?.trim()));
        const bare = leg.requests.filter((r) => !holds(r, own) && !holds(r, foreign) && !headerOf(r)?.trim());
        if (leg.openError) evidence.push({ probe: `open the server as identity ${name}`, outcome: `refused: ${leg.openError}`, verifiedBy: "response", code: "upstream.identity-refused" });
        evidence.push({
          probe: `valid calls as identity ${name} ({bearer:${name}}), ${leg.outcomes.length} call(s)`,
          outcome: `${reached} request(s) reached the upstream: ${ownHits.length} with the caller's own credential${swapped.length ? `, ${swapped.length} with identity ${other}'s` : ""}${stat.length ? `, ${stat.length} with a credential that is neither identity's` : ""}${bare.length ? `, ${bare.length} with no credential header` : ""}`,
          verifiedBy: "upstream",
          code: ownHits.length ? "upstream.credential" : "upstream.no-credential",
        });
        if (ownHits.length) seenOwn.push(name);
        if (swapped.length) {
          fails.push(`a call as identity ${name} reached the upstream with identity ${other}'s credential (a cached credential)`);
          evidence.push({ probe: `credential seen for identity ${name}'s call`, outcome: `${cred}: {bearer:${other}}`, verifiedBy: "upstream", code: "upstream.credential-swapped" });
        }
        if (stat.length) {
          fails.push(`a call as identity ${name} reached the upstream with a credential that is neither identity's (a static credential)`);
          evidence.push({ probe: `credential seen for identity ${name}'s call`, outcome: `${cred} header present, ${(headerOf(stat[0]!) ?? "").length} characters, not a minted token`, verifiedBy: "upstream", code: "upstream.static-credential" });
        }
      }
      // The anonymous leg: a refusal is fine (http-auth grades it); reaching the upstream with a credential is not.
      const anonWith = legN!.requests.filter((r) => Boolean(r.headers[cred]?.trim()));
      evidence.push({
        probe: "valid calls with every {bearer} header dropped",
        outcome: legN!.openError ? `refused: ${legN!.openError}` : legN!.allRefused && !legN!.requests.length ? "every call was refused before the upstream" : `${legN!.requests.length} request(s) reached the upstream, ${anonWith.length} with a credential header`,
        verifiedBy: "upstream",
        code: anonWith.length ? "upstream.anonymous-credential" : "upstream.anonymous",
      });
      if (anonWith.length) fails.push("an anonymous call reached the upstream carrying a credential (the server substitutes its own)");
      const coverage = { probed: [...new Set(legA!.outcomes.filter((o) => o.called && !o.isError).map((o) => o.tool))], notCovered: [], validCalls: legA!.outcomes.filter((o) => o.called && !o.isError && o.schemaValid).length };
      if (fails.length) return res(m, "fail", fails.join("; "), evidence, coverage);
      if (!seenOwn.length) {
        const refused = legA!.openError || legB!.openError || (legA!.allRefused && legB!.allRefused);
        return res(
          m,
          "inconclusive",
          refused
            ? "every call was refused: the server rejects minted tokens; set identities.a and identities.b to real tokens"
            : legA!.requests.length + legB!.requests.length
              ? "the upstream received requests, but none carried the caller's credential (nothing to compare)"
              : "no valid call reached the upstream; check that the server uses {upstream} and that a probes: entry calls a tool that queries it",
          evidence,
        );
      }
      return res(m, "pass", `each caller's own credential reached the upstream (${seenOwn.map((n) => `identity ${n}`).join(", ")}), no other credential was seen, and an anonymous call carried none`, evidence, coverage);
    })(),
  );

  // ---- upstream-credential-echo ----
  out.push(
    (() => {
      const m = META.echo;
      if (off(m)) return res(m, "na", "disabled by config");
      if (identNa) return res(m, "na", identNa);
      if (problem) return res(m, "inconclusive", problem);
      const hits: string[] = [];
      const evidence: Evidence[] = [];
      for (const [name, leg] of [["a", legA!], ["b", legB!], ["anonymous", legN!]] as const) {
        for (const t of leg.texts) {
          for (const i of idents) {
            if (i.bearer && t.includes(i.bearer)) {
              hits.push(`a reply to a call as identity ${name} contains {bearer:${i.name}}`);
              evidence.push({ probe: `reply to a valid call as identity ${name}`, outcome: `contains {bearer:${i.name}}`, verifiedBy: "response", code: "upstream.credential-echo", excerpt: t.slice(0, 600) });
            }
          }
        }
      }
      const replies = legA!.texts.length + legB!.texts.length + legN!.texts.length;
      if (hits.length) return res(m, "fail", [...new Set(hits)].join("; "), evidence);
      if (!replies) return res(m, "inconclusive", legA!.openError ? "no reply was received: the server refused the minted token; set identities.a and identities.b to real tokens" : NO_VALID_CALL, []);
      return res(m, "pass", `${replies} reply(ies) to calls as identities a and b held neither token`, [{ probe: "search the replies for the minted tokens", outcome: `${replies} reply(ies) searched, none held a token`, verifiedBy: "response", code: "upstream.no-echo" }]);
    })(),
  );

  // ---- upstream-error-leak (stub mode error) ----
  out.push(
    await (async () => {
      const m = META.errorLeak;
      if (off(m)) return res(m, "na", "disabled by config");
      if (identNa) return res(m, "na", identNa);
      if (problem) return res(m, "inconclusive", problem);
      try {
        stub.setMode("error");
        const leg = await runLeg(ctx, openA, probes.slice(0, MAX_ERROR_LEG));
        const evidence: Evidence[] = [];
        if (!leg.requests.length) return res(m, "inconclusive", leg.openError ? `the server refused the minted token (${leg.openError}); set identities.a` : "no valid call reached the upstream while it answered with errors", evidence);
        // A relay of the error body is what is measured: the reply must carry the error canary and a credential. A credential in a reply
        // without the error body is the server's own echo, which upstream-credential-echo grades (so one defect is not counted twice).
        const leaked = leg.texts.filter((t) => t.includes(stub.errorCanary) && idents.some((i) => i.bearer && t.includes(i.bearer)));
        const canary = leg.texts.some((t) => t.includes(stub.errorCanary));
        evidence.push({ probe: "valid calls while the upstream answers HTTP 500 with an error body", outcome: `${leg.requests.length} request(s) reached the upstream; ${canary ? "the upstream error body is relayed raw (the error canary appears in a reply)" : "the upstream error body was not relayed"}`, verifiedBy: "upstream", code: canary ? "upstream.error-relayed" : "upstream.error-contained" });
        if (leaked.length) {
          evidence.push({ probe: "reply under error mode", outcome: "contains the caller's credential", verifiedBy: "response", code: "upstream.error-leak", excerpt: leaked[0]!.slice(0, 600) });
          return res(m, "fail", "the server relays the upstream's error body, and with it the caller's credential", evidence);
        }
        return res(m, "pass", canary ? "an upstream error body was relayed, but it held no credential" : "upstream errors are not relayed to the caller", evidence);
      } finally {
        reset();
      }
    })(),
  );

  // ---- upstream-slow (stub mode slow) ----
  out.push(
    await (async () => {
      const m = META.slow;
      if (off(m)) return res(m, "na", "disabled by config");
      if (problem) return res(m, "inconclusive", problem);
      const configured = ctx.config?.checks?.[m.id]?.expected_sec;
      const expectedSec = typeof configured === "number" && configured > 0 ? configured : ctx.timeoutProbeSec;
      const delayMs = expectedSec * 1000 + 5000;
      const limitMs = (expectedSec + 2) * 1000;
      try {
        stub.setMode("slow", { delayMs });
        const leg = await runLeg(ctx, openA, probes, { timeoutMs: limitMs, stopAtFirstReach: true });
        const reached = leg.requests.length > 0;
        const hung = leg.outcomes.find((o) => o.timedOut);
        const evidence: Evidence[] = [
          { probe: `valid call while the upstream holds every reply for ${(delayMs / 1000).toFixed(0)} s (probe timeout ${(limitMs / 1000).toFixed(0)} s)`, outcome: hung ? `no reply within ${(limitMs / 1000).toFixed(0)} s` : leg.outcomes.length ? `replied${leg.outcomes.at(-1)?.isError ? " with an error" : ""} within ${(limitMs / 1000).toFixed(0)} s` : "no call was made", verifiedBy: "upstream", code: hung ? "upstream.slow-hang" : "upstream.slow-bounded" },
        ];
        if (!reached) return res(m, "inconclusive", leg.openError ? `the server refused the minted token (${leg.openError}); set identities.a` : "no valid call reached the upstream while it was slow", evidence);
        if (hung) return res(m, "fail", `the server did not answer within ${(limitMs / 1000).toFixed(0)} s while its upstream was slow (expected_sec ${expectedSec}): it waits on its backend without a timeout`, evidence);
        return res(m, "pass", `the server answered within ${(limitMs / 1000).toFixed(0)} s while its upstream held every reply for ${(delayMs / 1000).toFixed(0)} s`, evidence);
      } finally {
        reset();
      }
    })(),
  );

  // ---- log-secret ----
  out.push(
    (() => {
      const m = META.log;
      if (off(m)) return res(m, "na", "disabled by config");
      if (identNa) return res(m, "na", identNa);
      if (!log) return res(m, "na", "no server log: Sealmark did not start this server (launched HTTP) or run it over stdio, so its output was not captured");
      if (problem) return res(m, "inconclusive", problem);
      const since = mark0Log ?? 0;
      const needles: { label: string; value: string }[] = [
        ...idents.filter((i) => i.bearer).map((i) => ({ label: `{bearer:${i.name}}`, value: i.bearer })),
        { label: "the upstream error canary", value: stub.errorCanary },
      ];
      const text = log.since(since);
      const hits = needles.filter((n) => log.find(n.value, since) >= 0);
      if (hits.length) {
        const line = (text.split("\n").find((l) => hits.some((h) => l.includes(h.value))) ?? "").trim().slice(0, 300);
        return res(m, "fail", `the server's log contains ${hits.map((h) => h.label).join(" and ")}`, [{ probe: "search the server's output for the minted tokens", outcome: `found ${hits.map((h) => h.label).join(", ")} in ${log.sources.join("+")} output`, verifiedBy: "log", code: "log.secret", excerpt: line }]);
      }
      return res(m, "pass", `${text.length} byte(s) of server output held no minted token`, [{ probe: "search the server's output for the minted tokens", outcome: `${text.length} byte(s) searched (${log.sources.join("+")}), none found`, verifiedBy: "log", code: "log.clean" }]);
    })(),
  );

  return order(out);
}

/** Registry order of the five checks, whatever order they were computed in. */
function order(out: CheckResult[]): CheckResult[] {
  const ids = Object.values(META).map((m) => m.id) as string[];
  return [...out].sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
}
