import { fillArgs, packsFor } from "../classify.js";
import { diffFor, settleMsFor, settledDiff } from "../observers/fs.js";
import type { CallResult, ToolInfo } from "../mcp.js";
import type { CheckDoc, CheckResult, Evidence, FsDiff, Pack, PackApplies, PackCtx, ParamRole, ToolClassification } from "../types.js";
import { controlValues, ensureGitFixture, fillGit, gitAvailable, gitKind } from "./git.js";
import { Sessions, Tally, excerpt, metaFor, oneLine, pathKind, rawJoin, refused, result, token, unexpand, type FsKind, type Meta } from "./fs.js";

/**
 * The `effects` pack: do a tool's annotations match what the sandbox observed during the
 * harness's own benign calls? It is separate from `core` because "declares versus does" applies to every class of tool,
 * and folding it into core would change frozen results.
 *
 * The pack makes its own control call per tool: a snapshot of the sandbox directories, one call with a harness-owned
 * argument (the control file, the harness repository, a loopback URL), a second snapshot. Other packs' evidence cannot
 * supply the "before" half, so `ctx.prior` is not used.
 */

const SINCE = "0.2-draft";
const SCOPE = "server (annotations vs what the sandbox observed during the harness's own benign calls)";

const UNOBSERVED = "writes outside the sandbox (the real home, a store named by an absolute path in server.env or args) are not observed";

export const EFFECTS_META: Record<string, Meta> = {
  "annotation-honesty": { id: "annotation-honesty", label: "Read-only tools change nothing", critical: true, scope: SCOPE },
  "openworld-honesty": { id: "openworld-honesty", label: "Closed-world tools stay on the machine", critical: false, scope: SCOPE },
  "undeclared-writes": { id: "undeclared-writes", label: "Unannotated tools leave the sandbox unchanged", critical: false, advisory: true, scope: SCOPE },
};

export function describe(): CheckDoc[] {
  const keys = (id: string) => [`checks.${id}.enabled`, `checks.${id}.severity`, "sandbox.enabled", "tools.overrides"];
  const mk = (m: Meta, o: Pick<CheckDoc, "verifiedBy" | "probes" | "falsePositive" | "falseNegative">): CheckDoc => ({
    id: m.id,
    pack: "effects",
    label: m.label,
    critical: m.critical,
    advisory: Boolean(m.advisory),
    scope: m.scope,
    thresholds: {},
    configKeys: keys(m.id),
    since: SINCE,
    status: "shipped",
    ...o,
  });
  return [
    mk(EFFECTS_META["annotation-honesty"], {
      verifiedBy: ["fs-observer"],
      probes: [
        { id: "control-read", text: "a path tool declared readOnlyHint: true reads {sandbox}/ok.txt (list tools list {sandbox}); snapshot of {sandbox}, {canary}, the sandbox home and temp directory before and after", kind: "control" },
        { id: "control-git", text: "a git tool declared readOnlyHint: true runs on {sandbox}/repo", kind: "control" },
        { id: "control-url", text: "a URL tool declared readOnlyHint: true fetches {listener}/t/<token>; a tool that refused it and was shown to refuse every loopback target by net-loopback-ssrf is n/a (no harness-owned control URL exists for it)", kind: "control" },
        { id: "control-noarg", text: "a tool declared readOnlyHint: true with no required parameter (any class) is called with {}", kind: "control" },
      ],
      falsePositive: "A read-only tool that refreshes a lock or index file (for example git) is a part at most: changes under .git/index and *.lock are ignored for git tools. Cache files in the sandbox home or temp directory are a part, not a fail.",
      falseNegative: "Only the harness's benign control call is observed; a tool that writes only for other arguments passes. A tool with required parameters outside the classes the harness can fill (a path, a repository, a URL) is not called. Writes outside the observed directories (the real home, other drives) are not seen. Changes are looked for right after the reply and again after a settle window (300 ms, longer when timeout_probe_sec is large); a write that comes later than that is not seen.",
    }),
    mk(EFFECTS_META["openworld-honesty"], {
      verifiedBy: ["listener"],
      probes: [{ id: "control", text: "each tool declared openWorldHint: false is called with its control argument; the loopback listener records any connection", kind: "control" }],
      falsePositive: "None known: a tool that connects to the harness's loopback listener while claiming a closed world is open-world.",
      falseNegative: "Path and git tools cannot be pointed at the listener, so for them this confirms only that nothing connected out during the control call. Only URL tools can contradict the annotation.",
    }),
    mk(EFFECTS_META["undeclared-writes"], {
      verifiedBy: ["fs-observer"],
      probes: [{ id: "control", text: "an unannotated read-style tool is called with its control argument; the sandbox is compared before and after (it runs when no tool carries annotations, too)", kind: "control" }],
      falsePositive: "A tool that legitimately caches is listed. The result is advisory and unscored.",
      falseNegative: "Write-style tools are not called without an annotation (they are expected to write). Only listed, never graded.",
    }),
  ];
}

// ---------------------------------------------------------------------------------------------------------

interface Subject {
  tool: ToolInfo;
  c: ToolClassification;
  args: Record<string, unknown>;
  ro: boolean;
  closed: boolean;
  /** No annotations at all and a read-style call: reported by undeclared-writes. */
  undeclared: boolean;
  isGit: boolean;
}

interface Observed {
  s: Subject;
  r: CallResult;
  outside: string[];
  cache: string[];
  listener: number;
  /** Why this tool was not judged (it is listed in the coverage instead), when the harness has no control call that could show anything for it. */
  na?: string;
}

const ignorableGit = (k: string) => /\/\.git\/(?:index|[^/]*\.lock)$/.test(k);
const keysOf = (d: FsDiff, label: string, ignore: (k: string) => boolean): string[] => {
  const x = diffFor(d, label);
  return [...x.added, ...x.changed, ...x.removed].filter((k) => !ignore(k));
};

/**
 * A tool declared read-only that takes no required parameter, whatever its class: `{}` is its control call. The classifier reads such a
 * tool as opaque (nothing in its schema names a path, a repository or a URL), so no pack probes it; this is the only call that observes it.
 */
function noArgReadOnly(tool: ToolInfo, c: ToolClassification): boolean {
  if (c.excluded || c.annotations?.readOnlyHint !== true) return false;
  return ((tool.inputSchema?.required ?? []) as string[]).length === 0;
}

/**
 * True when net-loopback-ssrf passed for this URL tool and every one of its loopback probes was explicitly refused: the tool refuses
 * loopback targets, so the harness's listener URL can never be its control (the refusal is the tool working, not the control failing).
 */
function refusesLoopback(ctx: PackCtx, tool: string): boolean {
  const ssrf = ctx.prior?.find((c) => c.id === "net-loopback-ssrf");
  if (ssrf?.verdict !== "pass") return false;
  const mine = ssrf.evidence.filter((e) => e.tool === tool && e.code?.startsWith("net.ssrf-"));
  // The hostless twin the net pack sends when the refusals rest on wording ("net.ssrf-text-only": the pass stands) is part of the pass, not a probe that got through.
  const probes = mine.filter((e) => e.code !== "net.ssrf-text-only");
  return probes.length > 0 && probes.every((e) => e.code === "net.ssrf-refused");
}

const LOOPBACK_NA = "the tool refuses loopback targets (net-loopback-ssrf passed), so no harness-owned control URL exists";

/** What to call each tool with, or why it cannot be called. */
async function controlFor(ctx: PackCtx, tool: ToolInfo, c: ToolClassification): Promise<{ args: Record<string, unknown>; readStyle: boolean; isGit: boolean } | { why: string }> {
  const sb = ctx.sandbox!;
  const tok = token();
  const fill = (values: Partial<Record<ParamRole, string | string[]>>) => fillArgs(tool, c, values, tok);
  if (c.class === "path") {
    const kind: FsKind = pathKind(tool, c);
    let values: Partial<Record<ParamRole, string | string[]>> | undefined;
    let readStyle = true;
    if (kind === "read" || kind === "stat") values = { path: sb.files.ok, paths: [sb.files.ok] };
    else if (kind === "list") values = { path: sb.root, paths: [sb.root] };
    else if (kind === "write") {
      values = { path: rawJoin(sb.root, `ann-${tok}.txt`), content: tok };
      readStyle = false;
    } else if (kind === "mkdir") {
      values = { path: rawJoin(sb.root, `ann-${tok}`) };
      readStyle = false;
    }
    if (!values) return { why: `${/^[aeiou]/.test(kind) ? "an" : "a"} ${kind} tool has no harmless control call` };
    const args = fill(values);
    return args ? { args, readStyle, isGit: false } : { why: `required parameters (${c.unfillable.join(", ")}) cannot be filled by the harness` };
  }
  if (c.class === "git") {
    if (!c.params.repo) return { why: "no repository parameter" };
    if (gitKind(tool, c) !== "read") return { why: "a write-capable or unrecognised git tool has no harmless control call" };
    if (!gitAvailable()) return { why: "git is not on PATH" };
    const fx = await ensureGitFixture(sb);
    // fillGit, not a bare token: a required free-text string whose description names its choices ('local', 'remote', 'all') must get one of them, or the control call fails.
    const args = fillGit({ tool, c, kind: "read" }, controlValues(fx), tok);
    return args ? { args, readStyle: true, isGit: true } : { why: `required parameters (${c.unfillable.join(", ")}) cannot be filled by the harness` };
  }
  if (c.class === "url") {
    const args = fill({ url: `${sb.listener.url}/t/${tok}` });
    return args ? { args, readStyle: true, isGit: false } : { why: `required parameters (${c.unfillable.join(", ")}) cannot be filled by the harness` };
  }
  return { why: `class ${c.class} has no harness-owned control argument` };
}

const worstOf = (v: ("pass" | "part" | "fail")[]) => (v.includes("fail") ? "fail" : v.includes("part") ? "part" : "pass");

async function run(ctx: PackCtx): Promise<CheckResult[]> {
  const sb = ctx.sandbox!;
  const ms = Math.max(5000, ctx.config.timeouts?.probe_ms ?? 10_000);
  const keeper = new Sessions(ctx);
  const show = (v: unknown) => unexpand(sb, v);
  const notCalled: { tool: string; reason: string }[] = [];
  const subjects: Subject[] = [];

  for (const c of ctx.classification) {
    if (c.excluded) continue;
    const tool = ctx.tools.find((t) => t.name === c.tool);
    if (!tool) continue;
    const own = packsFor(c, { active: ctx.active, sandboxEnabled: true }).includes("effects");
    if (!own && !noArgReadOnly(tool, c)) continue;
    const a = c.annotations;
    const ro = a?.readOnlyHint === true;
    const closed = a?.openWorldHint === false;
    const unannotated = a === undefined;
    if (!ro && !closed && !unannotated) continue;
    let plan: Awaited<ReturnType<typeof controlFor>> = own ? await controlFor(ctx, tool, c) : { args: {}, readStyle: true, isGit: false };
    // A read-only tool that takes nothing is called with nothing, whatever else the harness could not give it.
    if ("why" in plan && noArgReadOnly(tool, c)) plan = { args: {}, readStyle: true, isGit: false };
    if ("why" in plan) {
      notCalled.push({ tool: tool.name, reason: plan.why });
      continue;
    }
    // An unannotated tool is called only in a read style: a write tool is expected to write.
    const undeclared = unannotated && plan.readStyle && c.class !== "url";
    if (!ro && !closed && !undeclared) {
      notCalled.push({ tool: tool.name, reason: "no annotations and not a read-style tool, so it is expected to change state" });
      continue;
    }
    subjects.push({ tool, c, args: plan.args, ro, closed, undeclared, isGit: plan.isGit });
  }

  // One session, opened before the first snapshot so server start-up writes are not blamed on a call.
  const observed: Observed[] = [];
  let failure: string | undefined;
  try {
    await keeper.get();
    for (const s of subjects) {
      const before = await sb.fs.snapshot();
      const reqs = sb.listener.requests().length + sb.listener.connections().length;
      const r = await keeper.call(s.tool.name, s.args, ms);
      const d = await settledDiff(sb.fs, before, undefined, settleMsFor(ctx.timeoutProbeSec));
      const ignore = s.isGit ? ignorableGit : () => false;
      const outside = [...keysOf(d, "root", ignore), ...keysOf(d, "root-evil", ignore), ...keysOf(d, "canary", ignore)];
      const cache = [...keysOf(d, "home", ignore), ...keysOf(d, "tmp", ignore)];
      const listener = sb.listener.requests().length + sb.listener.connections().length - reqs;
      // A URL tool that refused the listener URL and is known to refuse every loopback target has no control that could show anything: it is not judged, never "every control call failed".
      const na = s.c.class === "url" && refused(r) && !outside.length && !cache.length && !listener && refusesLoopback(ctx, s.tool.name) ? LOOPBACK_NA : undefined;
      observed.push({ s, r, outside, cache, listener, ...(na ? { na } : {}) });
    }
  } catch (e) {
    failure = (e as Error).message;
  }

  /** `declared` picks the tools a check is about; a tool the harness could not judge (no loopback control) is listed under the checks that tool is declared for. */
  const tallyFor = (list: Observed[], extra: { tool: string; reason: string }[] = [], declared: (o: Observed) => boolean = () => true): Tally => {
    const t = new Tally();
    for (const o of list) t.note(o.s.tool.name);
    for (const n of [...extra, ...notCalled]) t.skip(n.tool, n.reason);
    for (const o of observed) if (o.na && declared(o)) t.skip(o.s.tool.name, o.na);
    return t;
  };
  const evidenceFor = (o: Observed, outcome: string, by: Evidence["verifiedBy"], code: string): Evidence => ({
    probe: `control: ${o.s.tool.name}`,
    outcome,
    verifiedBy: by,
    tool: o.s.tool.name,
    args: show(o.s.args),
    ...(o.r.text ? { excerpt: excerpt(String(show(o.r.text)), 300) } : {}),
    code,
  });
  const names = (list: string[]) => list.slice(0, 3).map((k) => String(show(k))).join(", ");

  // ---- annotation-honesty ----
  const ann = (() => {
    const m = metaFor(ctx, EFFECTS_META["annotation-honesty"]);
    if (m.disabled) return result(m, "effects", "na", "", []);
    if (failure && !observed.length) return result(m, "effects", "inconclusive", `the server could not be called: ${failure}`, []);
    const list = observed.filter((o) => o.s.ro && !o.na);
    const tally = tallyFor(list, [], (o) => o.s.ro);
    if (!list.length) {
      const guarded = observed.filter((o) => o.s.ro && o.na);
      if (guarded.length) return result(m, "effects", "na", `${guarded.map((o) => o.s.tool.name).join(", ")}: ${LOOPBACK_NA}`, [], tally.coverage());
      const declared = ctx.classification.filter((c) => c.annotations?.readOnlyHint === true).map((c) => c.tool);
      const why = notCalled.filter((n) => declared.includes(n.tool)).slice(0, 3).map((n) => `${n.tool}: ${n.reason}`).join("; ");
      return result(m, "effects", "na", declared.length ? `no tool declared readOnlyHint: true could be given a harness-owned control argument${why ? ` (${why})` : ""}` : "no tool declares readOnlyHint: true", [], tally.coverage());
    }
    // The observer's blind spot is a property of the check, not of a tool: it is a line of its own (no tool prefix), not a "tool not covered" entry.
    const evidence: Evidence[] = [{ probe: "observed directories", outcome: UNOBSERVED, verifiedBy: "static", code: "effects.observer-na" }];
    const per: ("pass" | "part" | "fail")[] = [];
    let judged = 0;
    for (const o of list) {
      if (o.outside.length) {
        per.push("fail");
        evidence.push(evidenceFor(o, `declared read-only, but the harness saw ${names(o.outside)} change`, "fs-observer", "effects.readonly-write"));
      } else if (o.cache.length) {
        per.push("part");
        judged++;
        evidence.push(evidenceFor(o, `declared read-only; only the sandbox home or temp directory changed (${names(o.cache)})`, "fs-observer", "effects.readonly-cache"));
      } else {
        judged += refused(o.r) ? 0 : 1;
        per.push("pass");
        evidence.push(evidenceFor(o, refused(o.r) ? "nothing changed, but the control call itself failed" : "nothing changed in the root, the canary directory, the home or the temp directory", "fs-observer", "effects.readonly-clean"));
      }
    }
    const v = worstOf(per);
    if (v === "pass" && !judged) return result(m, "effects", "inconclusive", "every control call failed, so the read-only annotation could not be checked", evidence, tally.coverage());
    const bad = list.filter((o) => o.outside.length).map((o) => o.s.tool.name);
    const cached = list.filter((o) => !o.outside.length && o.cache.length).map((o) => o.s.tool.name);
    // A tool whose control call failed was not judged: it is named as such and never counted among the tools that "changed nothing".
    const failedControl = list.filter((o) => !o.outside.length && !o.cache.length && refused(o.r)).map((o) => o.s.tool.name);
    const clean = list.filter((o) => !failedControl.includes(o.s.tool.name) && !bad.includes(o.s.tool.name) && !cached.includes(o.s.tool.name)).map((o) => o.s.tool.name);
    const notJudged = failedControl.length ? ` (${failedControl.join(", ")} not judged: the control call failed)` : "";
    const summary =
      v === "fail"
        ? `declared read-only but changed the sandbox: ${bad.join(", ")}${notJudged}`
        : v === "part"
          ? `declared read-only; only caches changed (sandbox home or temp): ${cached.join(", ")}${notJudged}`
          : `${clean.join(", ")} declared read-only and changed nothing in the observed directories during a benign call${notJudged}`;
    return result(m, "effects", v, summary, evidence, tally.coverage());
  })();

  // ---- openworld-honesty ----
  const open = (() => {
    const m = metaFor(ctx, EFFECTS_META["openworld-honesty"]);
    if (m.disabled) return result(m, "effects", "na", "", []);
    if (failure && !observed.length) return result(m, "effects", "inconclusive", `the server could not be called: ${failure}`, []);
    const list = observed.filter((o) => o.s.closed && !o.na);
    const tally = tallyFor(list, [], (o) => o.s.closed);
    if (!list.length) {
      const guarded = observed.filter((o) => o.s.closed && o.na);
      if (guarded.length) return result(m, "effects", "na", `${guarded.map((o) => o.s.tool.name).join(", ")}: ${LOOPBACK_NA}`, [], tally.coverage());
      return result(m, "effects", "na", "no tool declares openWorldHint: false that could be given a harness-owned control argument", [], tally.coverage());
    }
    const evidence: Evidence[] = list.map((o) =>
      evidenceFor(o, o.listener ? `declared closed-world, but the loopback listener saw ${o.listener} connection(s)` : "no connection reached the loopback listener", "listener", o.listener ? "effects.openworld-contact" : "effects.openworld-clean"),
    );
    const bad = list.filter((o) => o.listener).map((o) => o.s.tool.name);
    if (bad.length) return result(m, "effects", "fail", `declared closed-world but contacted the loopback listener: ${bad.join(", ")}`, evidence, tally.coverage());
    if (list.every((o) => refused(o.r))) return result(m, "effects", "inconclusive", "every control call failed, so the closed-world annotation could not be checked", evidence, tally.coverage());
    const urlTools = list.filter((o) => o.s.c.class === "url").length;
    return result(
      m,
      "effects",
      "pass",
      urlTools
        ? `${list.length} closed-world tool(s) called; none reached out beyond what was asked`
        : `${list.length} closed-world tool(s) called; nothing connected to the loopback listener (path and git tools cannot be pointed at it, so this confirms only that nothing connected out during the call)`,
      evidence,
      tally.coverage(),
    );
  })();

  // ---- undeclared-writes ----
  const undeclared = (() => {
    const m = metaFor(ctx, EFFECTS_META["undeclared-writes"]);
    if (m.disabled) return result(m, "effects", "na", "", []);
    if (failure && !observed.length) return result(m, "effects", "inconclusive", `the server could not be called: ${failure}`, []);
    const list = observed.filter((o) => o.s.undeclared);
    // Only the tools this check is about are listed as not covered: a tool that carries annotations is the other checks' business.
    const unannotated = (tool: string) => ctx.classification.find((c) => c.tool === tool)?.annotations === undefined;
    const tally = new Tally();
    for (const o of list) tally.note(o.s.tool.name);
    for (const n of notCalled) if (unannotated(n.tool)) tally.skip(n.tool, n.reason);
    if (!list.length) {
      const any = ctx.classification.some((c) => !c.excluded && c.annotations === undefined && packsFor(c, { active: ctx.active, sandboxEnabled: true }).includes("effects"));
      return result(m, "effects", "na", any ? "no unannotated read-style tool could be given a harness-owned control argument" : "every tool carries annotations, nothing to check", [], tally.coverage());
    }
    const changed = list.filter((o) => o.outside.length || o.cache.length);
    const evidence = list.map((o) =>
      o.outside.length || o.cache.length
        ? evidenceFor(o, `no annotations, and the harness saw ${names([...o.outside, ...o.cache])} change`, "fs-observer", "effects.undeclared-write")
        : evidenceFor(o, "no annotations, and nothing changed", "fs-observer", "effects.undeclared-clean"),
    );
    return result(
      m,
      "effects",
      changed.length ? "part" : "pass",
      changed.length ? `unannotated tools that changed sandbox state during a benign call (listed, not scored): ${changed.map((o) => o.s.tool.name).join(", ")}` : `${list.map((o) => o.s.tool.name).join(", ")} carry no annotations and changed nothing`,
      evidence,
      tally.coverage(),
    );
  })();

  if (failure) ann.summary += ` (the run stopped early: ${oneLine(failure)})`;
  return [ann, open, undeclared];
}

/**
 * The two classification reasons effects does not apply, or undefined when it does. run, doctor and applies() all read this one wording.
 * The pack applies when some tool takes a harness-owned target (or is a read-only tool with nothing to fill), and when either some tool carries
 * annotations (the honesty checks) or an unannotated path or repository tool exists (undeclared-writes, which needs no annotation at all).
 * The gate reads classifications only; the run decides which unannotated tools are read-style and says so when none is.
 */
export function effectsGateReason(classification: ToolClassification[], o: { active: boolean; sandboxEnabled: boolean }): string | undefined {
  const usable = classification.filter((c) => !c.excluded && (packsFor(c, { active: o.active, sandboxEnabled: o.sandboxEnabled }).includes("effects") || (c.annotations?.readOnlyHint === true && Object.keys(c.params).length === 0)));
  if (!usable.length) return "no tool takes a harness-owned target (file path, repository or URL) with medium confidence or higher, and none is a read-only tool with no required parameter";
  if (!usable.some((c) => c.annotations) && !usable.some((c) => c.annotations === undefined && c.class !== "url")) return "no tool declares annotations and none is an unannotated path or repository tool, so there is nothing to compare with what the sandbox observed";
  return undefined;
}

function applies(ctx: PackCtx): PackApplies {
  if (!ctx.sandbox || ctx.sandboxEnabled === false) return { ok: false, reason: "the sandbox is off (--no-sandbox), so the sandbox cannot be observed" };
  if (ctx.config.server.url && !ctx.config.server.command) return { ok: false, reason: "the server is already running (HTTP), so it cannot be started inside the sandbox" };
  const reason = effectsGateReason(ctx.classification, { active: ctx.active, sandboxEnabled: true });
  return reason ? { ok: false, reason } : { ok: true };
}

export const pack: Pack = { id: "effects", describe, applies, run };
export default pack;
