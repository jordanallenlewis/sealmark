import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fillArgs } from "../classify.js";
import type { CallResult, McpSession, ToolInfo } from "../mcp.js";
import type { BinName, CheckDoc, CheckResult, Evidence, Pack, PackCtx, PackId, Sandbox, ToolClassification, Verdict } from "../types.js";

/**
 * The `exec` pack. It asks a command-running tool to run the four programs the harness put in
 * `<sandbox>/bin` and watches what happens: `sm-echo` records its argv and cwd, `sm-canary` writes a file outside the root
 * (so a shell that interpreted an argument is caught by the file system observer), `sm-sleep` and `sm-spew` measure caps.
 * No real system command is ever sent. Opt-in: the pack runs only with --active, which only the command line can set.
 */

const ID: PackId = "exec";
const SINCE = "0.2-draft";

/** Same wording as the gate in run.ts, so a hand-built ctx and a full run agree. */
export const EXEC_NEEDS_ACTIVE = "the exec pack runs only with --active";

const SLEEP_EXTRA_SEC = 20;
const WAIT_EXTRA_SEC = 8;
const SPEW_MIB = 64;
const OUTPUT_PASS_BYTES = 16 * 1024 * 1024;
const SETTLE_MS = 300;
const GONE_POLL_MS = 1500;

/** The shell-metacharacter variants of one argument. `{t}` is the probe's token, so an observation maps to one probe. */
const INJECTION_VARIANTS = ["{t}; sm-canary", "{t} && sm-canary", "{t} | sm-canary", "{t}$(sm-canary)", "{t}`sm-canary`", "{t} & sm-canary"];

type Form = "bare" | "node";
type V = Verdict;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const token = () => `sm-${randomBytes(6).toString("hex")}`;
const norm = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "");
const fold = (p: string) => (process.platform === "win32" ? norm(p).toLowerCase() : norm(p));
const within = (p: string, dir: string) => fold(p) === fold(dir) || fold(p).startsWith(`${fold(dir)}/`);

/**
 * A reply that says "no" without being an MCP error: a leading refusal word, as in `Error: program not allowed`. This approximates the
 * anchored REFUSAL rule; import `refused()` from packs/shared.ts once it exists.
 */
const REFUSAL = /^\s*(?:\[?(?:error|err)\]?\s*[:\-]|error\b|refused|rejected|denied|blocked|forbidden|disallowed|not (?:allowed|permitted|supported)|invalid\b|unsafe\b|cannot\b|can't\b|unable to\b)/i;
const refused = (r: CallResult) => !r.closed && (r.isError || r.rpcError !== undefined || REFUSAL.test(r.text.slice(0, 300)));
const LIMIT_TEXT = /time[d ]?-?out|timed out|killed|terminat|signal|exceed|limit|too (?:long|large|big)|truncat/i;

const excerpt = (r: CallResult, n = 300) => (r.text || r.rpcError || "(empty reply)").replace(/\s+/g, " ").slice(0, n);

// ---------------------------------------------------------------------------------------------------------
// Check docs
// ---------------------------------------------------------------------------------------------------------

const SHARED = { pack: ID, since: SINCE, status: "shipped" as const };

export function describe(): CheckDoc[] {
  return [
    {
      ...SHARED,
      id: "exec-injection",
      label: "Arguments are not interpreted by a shell",
      critical: true,
      advisory: false,
      scope: "server (no shell in argument passing; shell-style tools that take one command line are not tested, they are a shell by design)",
      verifiedBy: ["fs-observer", "response"],
      probes: INJECTION_VARIANTS.map((v, i) => ({ id: `inj-${i + 1}`, text: `program sm-echo, one argument: ${v.replace("{t}", "<token>")}`, kind: "shell-metacharacter" })),
      thresholds: {},
      falsePositive: "A server that deliberately runs argument lists through a shell is reported as failing; that is the finding.",
      falseNegative: "On Windows a shell does not treat `;`, `$()` or backticks as separators, so only `&&`, `&` and `|` can fire there. Interpreters other than the platform shell are not exercised.",
      configKeys: ["checks.exec-injection.enabled", "checks.exec-injection.severity", "checks.exec-injection.corpus.add", "checks.exec-injection.corpus.remove", "active"],
    },
    {
      ...SHARED,
      id: "exec-cwd",
      label: "Programs run inside the configured root",
      critical: false,
      advisory: false,
      scope: "server (working directory of started programs)",
      verifiedBy: ["fs-observer"],
      probes: [{ id: "cwd", text: "program sm-echo records its working directory; it must be inside the sandbox root" }],
      thresholds: {},
      falsePositive: "A server configured to start programs elsewhere on purpose is reported as failing; give it {sandbox} as its root.",
      falseNegative: "A server that changes directory per call is only seen for the call the harness made.",
      configKeys: ["checks.exec-cwd.enabled", "checks.exec-cwd.severity", "active"],
    },
    {
      ...SHARED,
      id: "exec-timeout-cap",
      label: "Run time and output are capped",
      critical: false,
      advisory: false,
      scope: "server (time and output limits on started programs)",
      verifiedBy: ["process", "response"],
      probes: [
        {
          id: "sleep",
          text: `program sm-sleep for timeout_probe_sec + ${SLEEP_EXTRA_SEC} seconds; it must return within timeout_probe_sec + ${WAIT_EXTRA_SEC} s and the program must be gone`,
          kind: "time",
        },
        { id: "spew", text: `program sm-spew writes ${SPEW_MIB} MiB; the reply must be at most 16 MiB or say it was truncated`, kind: "output" },
      ],
      thresholds: { timeout_probe_sec: { default: 10, configKey: "timeout_probe_sec", standardLocked: true } },
      falsePositive: "A server whose limits are above the probe sizes (more than timeout_probe_sec + 8 s, more than 16 MiB) fails by design of the thresholds.",
      falseNegative: "Memory and CPU use are not measured; a reply that is cut by the transport is reported as a failure, not as a cap.",
      configKeys: ["timeout_probe_sec", "checks.exec-timeout-cap.enabled", "checks.exec-timeout-cap.severity", "active"],
    },
    {
      ...SHARED,
      id: "exec-allowlist",
      label: "Only allowed programs run",
      critical: false,
      advisory: true,
      scope: "server (which programs the tool will start)",
      verifiedBy: ["fs-observer", "response"],
      probes: [{ id: "unlisted", text: "program sm-canary, a harmless program that is not one the server could have listed; running it means there is no allowlist" }],
      thresholds: {},
      falsePositive: "A general-purpose command tool has no allowlist by design; this is advice, not a defect, and it is not scored.",
      falseNegative: "An allowlist that happens to include the harness program name would read as 'no allowlist'.",
      configKeys: ["checks.exec-allowlist.enabled", "checks.exec-allowlist.severity", "active"],
    },
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------------------------------------

interface Target {
  tool: ToolInfo;
  cls: ToolClassification;
  style: "spawn" | "shell";
  /** How the harness programs are named for this tool, found by the control call. */
  form?: Form;
  /** Working directory the control program reported. */
  cwd?: string;
  note?: string;
}

/** Tools classified as running a command with high or explicit confidence, whose program can be set. */
function targetsOf(ctx: Partial<PackCtx>): Target[] {
  const out: Target[] = [];
  for (const c of ctx.classification ?? []) {
    if (c.class !== "command" || c.excluded) continue;
    if (c.confidence !== "high" && c.confidence !== "explicit") continue;
    if (!c.params.command || c.unfillable.length) continue;
    const tool = ctx.tools?.find((t) => t.name === c.tool);
    if (tool) out.push({ tool, cls: c, style: c.params.args ? "spawn" : "shell" });
  }
  return out;
}

export const pack: Pack = {
  id: ID,
  describe,
  applies(ctx: PackCtx) {
    if (!ctx.active) return { ok: false, reason: EXEC_NEEDS_ACTIVE };
    if (ctx.sandboxEnabled === false || !ctx.sandbox) return { ok: false, reason: "the sandbox is off (--no-sandbox), so there is no harness-owned place to start programs" };
    if (!targetsOf(ctx).length) return { ok: false, reason: "no tool is classified as running a command with high confidence" };
    return { ok: true };
  },
  run: runExec,
};
export default pack;

// ---------------------------------------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------------------------------------

interface Observed {
  r: CallResult;
  /** Files `sm-canary` wrote (snapshot keys). */
  executed: string[];
  /** What `sm-echo` recorded. */
  argv: { argv: string[]; cwd: string }[];
}

type Acc = { evidence: Evidence[]; calls: number; probed: Set<string>; notCovered: { tool: string; reason: string }[] };
const acc = (): Acc => ({ evidence: [], calls: 0, probed: new Set(), notCovered: [] });

async function runExec(ctx: PackCtx): Promise<CheckResult[]> {
  const docs = describe();
  const meta = (id: string) => docs.find((d) => d.id === id)!;
  const sb = ctx.sandbox as Sandbox | undefined;
  const make = (id: string, verdict: V, summary: string, a: Acc = acc()): CheckResult => {
    const d = meta(id);
    const cc = ctx.config?.checks?.[id];
    let critical = d.critical;
    let advisory = d.advisory;
    if (cc?.severity === "advisory") [critical, advisory] = [false, true];
    else if (cc?.severity === "critical") [critical, advisory] = [true, false];
    else if (cc?.severity === "scored") [critical, advisory] = [false, false];
    const base = { id, pack: ID, label: d.label, critical, ...(advisory ? { advisory: true } : {}), scope: d.scope };
    if (cc && cc.enabled === false) {
      const o = ctx.config?.origins?.[`/checks/${id}/enabled`];
      return { ...base, verdict: "na", summary: `disabled by config${o ? ` (${o.source}${o.line ? `:${o.line}` : ""})` : ""}`, evidence: [] };
    }
    return { ...base, verdict, summary, evidence: a.evidence, coverage: { probed: [...a.probed], notCovered: a.notCovered, validCalls: a.calls } };
  };
  const all = (verdict: V, summary: string) => docs.map((d) => make(d.id, verdict, summary));

  if (!ctx.active) return all("na", EXEC_NEEDS_ACTIVE);
  if (!sb || ctx.sandboxEnabled === false) return all("na", "the sandbox is off (--no-sandbox), so there is no harness-owned place to start programs");
  const targets = targetsOf(ctx);
  if (!targets.length) return all("na", "no tool is classified as running a command with high confidence");

  ctx.log(`--active: the exec pack will ask ${targets.map((t) => t.tool.name).join(", ")} to run harness-owned programs from ${sb.bin}. Only for servers you trust or inside a throwaway VM.`);

  const T = ctx.timeoutProbeSec;
  const waitMs = (T + WAIT_EXTRA_SEC) * 1000;
  const callMs = Math.max(10_000, ctx.config?.timeouts?.probe_ms ?? 10_000);
  // One session per tool, so the time and output caps of several tools can be measured at once. A session that was dropped is replaced.
  const sessions = new Map<Target, McpSession>();
  const sess = async (t: Target): Promise<McpSession> => {
    let s = sessions.get(t);
    if (!s || s.closed) {
      s = await ctx.open();
      sessions.set(t, s);
    }
    return s;
  };

  const progFor = (form: Form, name: BinName) => (form === "bare" ? { program: name, args: [] as string[] } : { program: sb.bins[name].program, args: sb.bins[name].args });
  const argsFor = (t: Target, form: Form, name: BinName, argv: string[], tok: string): Record<string, unknown> | undefined => {
    const p = progFor(form, name);
    if (t.style === "spawn") return fillArgs(t.tool, t.cls, { command: p.program, args: [...p.args, ...argv] }, tok);
    const q = (s: string) => (/\s/.test(s) ? `"${s}"` : s);
    return fillArgs(t.tool, t.cls, { command: [q(p.program), ...p.args.map(q), ...argv].join(" ") }, tok);
  };
  const formText = (t: Target, name: BinName, form: Form) => (form === "bare" ? name : `${name} (started as node plus its script; the bare name did not resolve through ${t.tool.name})`);

  /** One call, with the file system watched for what the harness programs do. */
  const observed = async (call: () => Promise<CallResult>): Promise<Observed> => {
    const before = await sb.fs.snapshot(["root", "canary"]);
    const r = await call();
    await sleep(SETTLE_MS);
    const d = sb.fs.diff(before, await sb.fs.snapshot(["root", "canary"]));
    const executed = [...d.added, ...d.changed].filter((k) => /^canary\/executed-[^/]+\.txt$/.test(k));
    const argv: Observed["argv"] = [];
    for (const k of d.added.filter((x) => /^root\/argv-[^/]+\.txt$/.test(x))) {
      try {
        const j = JSON.parse(await readFile(sb.fs.resolve(k), "utf8")) as { argv?: unknown; cwd?: unknown };
        if (Array.isArray(j.argv) && typeof j.cwd === "string") argv.push({ argv: j.argv.map(String), cwd: j.cwd });
      } catch {
        /* half-written or removed: no signal */
      }
    }
    return { r, executed, argv };
  };

  const call = async (t: Target, name: BinName, argv: string[], form: Form, a: Acc, ms = callMs): Promise<Observed | undefined> => {
    const tok = token();
    const args = argsFor(t, form, name, argv, tok);
    if (!args) return undefined;
    a.calls++;
    a.probed.add(t.tool.name);
    return observed(async () => {
      const r = await (await sess(t)).call(t.tool.name, args, ms);
      // A session can die after the check that overran it has finished (a flood from an uncapped program overruns the transport buffer
      // late), and the next call then fails with "Not connected" without the server ever seeing it. Ask again on a fresh session.
      return r.closed && r.rpcError !== undefined ? (await sess(t)).call(t.tool.name, args, ms) : r;
    });
  };

  // ---- control: can the harness program be started through this tool at all? Bare name first, then node plus the script. ----
  const controlAcc = acc();
  for (const t of targets) {
    const notes: string[] = [];
    for (const form of ["bare", "node"] as Form[]) {
      const tok = token();
      const o = await call(t, "sm-echo", [`ctl-${tok}`], form, controlAcc);
      if (!o) {
        notes.push("the tool needs an argument the harness cannot fill");
        break;
      }
      const hit = o.argv.find((x) => x.argv.some((y) => y.includes(`ctl-${tok}`)));
      if (hit) {
        t.form = form;
        t.cwd = hit.cwd;
        break;
      }
      notes.push(`${form === "bare" ? "bare name" : "node form"}: ${excerpt(o.r, 160)}`);
    }
    if (!t.form) t.note = notes.join(" | ");
  }
  const controlled = targets.filter((t) => t.form);
  const uncontrolled = (what: string): string =>
    `the harness program sm-echo could not be started through ${targets
      .filter((t) => !t.form)
      .map((t) => `${t.tool.name} (${t.note})`)
      .join("; ")}, so ${what} was not measured`;
  const noControl = (id: string, what: string): CheckResult | undefined => {
    if (controlled.length) return undefined;
    const a = acc();
    for (const t of targets)
      a.evidence.push({
        probe: `${t.tool.name}: control call, sm-echo with one plain argument`,
        outcome: t.note ?? "no record",
        verifiedBy: "fs-observer",
        tool: t.tool.name,
        code: "exec.control.failed",
      });
    return make(id, "inconclusive", uncontrolled(what), a);
  };

  // sm-sleep programs a server left running. Tools are measured at once, so the listing is shared while it is in flight, and every pid
  // stopped so far is remembered (a second tool whose call ends later would otherwise find nothing left to report).
  const reaped = new Set<number>();
  let reaping: Promise<void> | undefined;
  const reapSleepers = (): Promise<void> =>
    (reaping ??= (async () => {
      try {
        const mine = (await sb.proc.list()).filter((p) => /sm-sleep/.test(p.cmd ?? "") && fold(p.cmd ?? "").includes(fold(sb.bin)));
        for (const p of mine) {
          reaped.add(p.pid);
          await sb.proc.killTree(p.pid);
        }
      } catch {
        /* listing is best effort */
      }
    })().finally(() => {
      reaping = undefined;
    }));

  /**
   * Is this pid still one of the harness's own sm-sleep programs? The pid comes from the server's reply, and an operating system
   * hands a freed pid to the next process that starts (on Windows within milliseconds), so a pid alone proves nothing: it is only
   * trusted, and only ever killed, when the process table shows an sm-sleep started from this sandbox's bin directory under it.
   */
  const ownedSleeper = async (pid: number): Promise<boolean> => {
    if (!Number.isInteger(pid) || pid <= 0 || !sb.proc.isAlive(pid)) return false;
    try {
      return (await sb.proc.list()).some((p) => p.pid === pid && /sm-sleep/.test(p.cmd ?? "") && fold(p.cmd ?? "").includes(fold(sb.bin)));
    } catch {
      return false;
    }
  };

  /**
   * The harness's own sm-sleep programs still alive that were started with this exact duration argument (every tool is given its own
   * duration, so a sleeper another tool is still measuring is never taken for this one). Polled until none is left or GONE_POLL_MS passes.
   */
  const lingering = async (arg: string): Promise<number[]> => {
    const own = new RegExp(`(?:^|[\\s"'])${arg.replace(/\./g, "\\.")}["']?\\s*$`);
    const find = async (): Promise<number[]> => {
      try {
        return (await sb.proc.list()).filter((p) => /sm-sleep/.test(p.cmd ?? "") && fold(p.cmd ?? "").includes(fold(sb.bin)) && own.test((p.cmd ?? "").trim())).map((p) => p.pid);
      } catch {
        return [];
      }
    };
    const deadline = Date.now() + GONE_POLL_MS;
    let left = await find();
    while (left.length && Date.now() < deadline) {
      await sleep(150);
      left = await find();
    }
    return left;
  };

  /** all pass -> pass, all fail -> fail, otherwise part; any inconclusive keeps a pass from being claimed. */
  const fold2 = (vs: V[]): V => {
    const c = vs.filter((v) => v !== "inconclusive");
    if (!c.length) return "inconclusive";
    if (c.every((v) => v === "pass")) return vs.includes("inconclusive") ? "inconclusive" : "pass";
    if (c.every((v) => v === "fail")) return "fail";
    return "part";
  };

  // ---- exec-injection ----
  const results: CheckResult[] = [];

  {
    const a = acc();
    const spawnTargets = controlled.filter((t) => t.style === "spawn");
    for (const t of targets.filter((x) => x.style === "shell"))
      a.notCovered.push({ tool: t.tool.name, reason: "takes one command line, so it is a shell by design and has no argument boundary to test" });
    if (!targets.some((t) => t.style === "spawn")) {
      results.push(
        make(
          "exec-injection",
          "na",
          `${targets.map((t) => t.tool.name).join(", ")} take${targets.length === 1 ? "s" : ""} one command line, which is a shell by design, so there is no argument boundary to test`,
          a,
        ),
      );
    } else if (!spawnTargets.length) {
      results.push(make("exec-injection", "inconclusive", uncontrolled("argument handling"), a));
    } else {
      let injected = 0;
      let decided = 0;
      const outcomes: string[] = [];
      for (const t of spawnTargets) {
        for (const variant of INJECTION_VARIANTS) {
          const tok = token();
          const arg = variant.replace("{t}", `x-${tok}`);
          const o = await call(t, "sm-echo", [arg], t.form!, a);
          if (!o) continue;
          let kind: "injected" | "literal" | "split" | "refused" | "nosignal";
          const rec = o.argv.find((x) => x.argv.some((y) => y.includes(`x-${tok}`)));
          if (o.executed.length) kind = "injected";
          else if (rec) kind = rec.argv.includes(arg) ? "literal" : "split";
          else kind = refused(o.r) ? "refused" : "nosignal";
          if (kind === "injected") injected++;
          if (kind !== "nosignal") decided++;
          outcomes.push(kind);
          const how = formText(t, "sm-echo", t.form!);
          a.evidence.push({
            probe: `${t.tool.name}: ${how} with the single argument ${JSON.stringify(arg)}`,
            outcome:
              kind === "injected"
                ? `the shell ran sm-canary: ${o.executed.map((k) => k.replace(/^canary\//, "")).join(", ")} appeared outside the root`
                : kind === "literal"
                  ? "sm-echo received the argument unchanged; nothing else ran"
                  : kind === "split"
                    ? `sm-echo received ${JSON.stringify(rec!.argv)} (the argument was re-split) but nothing else ran`
                    : kind === "refused"
                      ? `refused: ${excerpt(o.r, 160)}`
                      : `no sm-echo record and no refusal: ${excerpt(o.r, 160)}`,
            verifiedBy: kind === "refused" ? "response" : "fs-observer",
            tool: t.tool.name,
            args: { program: formText(t, "sm-echo", t.form!), argument: arg },
            excerpt: o.r.text.slice(0, 1000),
            code: `exec.injection.${kind}`,
          });
        }
      }
      if (injected) results.push(make("exec-injection", "fail", `${injected} of ${outcomes.length} metacharacter probes ran a second program: the tool passes its arguments through a shell`, a));
      else if (outcomes.includes("nosignal"))
        results.push(
          make(
            "exec-injection",
            "inconclusive",
            `${outcomes.filter((k) => k === "nosignal").length} of ${outcomes.length} probes gave no signal (the program neither ran nor was refused), so the result is not claimed`,
            a,
          ),
        );
      else
        results.push(
          make("exec-injection", "pass", `${decided} metacharacter probes: arguments reached the program as data${outcomes.includes("refused") ? " or were refused" : ""}; no second program ran`, a),
        );
    }
  }

  // ---- exec-cwd ----
  {
    const a = acc();
    const none = noControl("exec-cwd", "the working directory");
    if (none) results.push(none);
    else {
      const verdicts: V[] = [];
      for (const t of controlled) {
        a.probed.add(t.tool.name);
        const inside = within(t.cwd!, sb.root);
        verdicts.push(inside ? "pass" : "fail");
        a.evidence.push({
          probe: `${t.tool.name}: sm-echo records its working directory`,
          outcome: inside ? "inside the sandbox root" : `outside the sandbox root: ${within(t.cwd!, sb.home) ? "the sandbox home directory" : "another directory"}`,
          verifiedBy: "fs-observer",
          tool: t.tool.name,
          code: inside ? "exec.cwd.inside" : "exec.cwd.outside",
        });
      }
      const v = fold2(verdicts);
      results.push(
        make(
          "exec-cwd",
          v,
          v === "pass"
            ? "programs start inside the configured root"
            : v === "fail"
              ? "programs start outside the configured root"
              : "programs start inside the root for some tools and outside it for others",
          a,
        ),
      );
    }
  }

  // ---- exec-timeout-cap ----
  {
    const a = acc();
    const none = noControl("exec-timeout-cap", "the time and output caps");
    if (none) results.push(none);
    else {
      // The tools are measured at once (each has its own session); evidence is added in tool order afterwards.
      const measured = await Promise.all(
        controlled.map(async (t, ti): Promise<{ v: V; evs: Evidence[] }> => {
          const evs: Evidence[] = [];
          const form = t.form!;
          // Time: a program that sleeps far longer than the probe allows. The server should stop it, and the harness checks it is gone.
          let sleepV: V;
          {
            const tok = token();
            // A hundredth of a second per tool tells the sleepers of tools measured at the same time apart in the process table (the first tool gets a whole number).
            const sleepArg = ti ? (T + SLEEP_EXTRA_SEC + ti / 100).toFixed(2) : String(T + SLEEP_EXTRA_SEC);
            const args = argsFor(t, form, "sm-sleep", [sleepArg], tok);
            const s = await sess(t);
            a.calls++;
            a.probed.add(t.tool.name);
            const r = args ? await s.call(t.tool.name, args, waitMs) : undefined;
            const probe = `${t.tool.name}: ${formText(t, "sm-sleep", form)} for ${T + SLEEP_EXTRA_SEC} s, waiting ${T + WAIT_EXTRA_SEC} s`;
            const ev = (outcome: string, code: string, verifiedBy: Evidence["verifiedBy"] = "process") =>
              evs.push({ probe, outcome, verifiedBy, tool: t.tool.name, ...(r ? { excerpt: r.text.slice(0, 600) } : {}), code });
            if (!r) {
              sleepV = "inconclusive";
              ev("the tool needs an argument the harness cannot fill", "exec.time.unfillable", "static");
            } else if (r.timedOut) {
              // Find and stop the program the server left running (the harness owns it; nothing else is touched).
              await reapSleepers();
              const left = reaped.size ? `; sm-sleep was still running (pid ${[...reaped].join(", ")}) and was stopped by the harness` : "";
              sleepV = "fail";
              ev(`no reply within ${T + WAIT_EXTRA_SEC} s: the tool has no run-time cap that stops a ${T + SLEEP_EXTRA_SEC} s program${left}`, "exec.time.no-cap");
            } else if (r.closed) {
              sleepV = "inconclusive";
              ev(`the server went away during the call (${excerpt(r, 160)})`, "exec.time.closed", "response");
            } else {
              const pid = /sm-sleep pid=(\d+)/.exec(r.text)?.[1];
              let alive = false;
              if (pid) {
                const deadline = Date.now() + GONE_POLL_MS;
                alive = await ownedSleeper(Number(pid));
                while (alive && Date.now() < deadline) {
                  await sleep(150);
                  alive = await ownedSleeper(Number(pid));
                }
                if (alive) await sb.proc.killTree(Number(pid)).catch(() => {});
              }
              if (pid && alive) {
                sleepV = "fail";
                ev(`replied after ${r.elapsedMs} ms but the program (pid ${pid}) was still running`, "exec.time.left-running");
              } else if (pid) {
                sleepV = "pass";
                ev(`replied after ${r.elapsedMs} ms and the program (pid ${pid}) was gone`, "exec.time.capped");
              } else {
                // No pid in the reply. A reply is the weakest evidence, so the process table decides: a sleeper still alive here ran and was not stopped.
                const left = await lingering(sleepArg);
                for (const p of left) await sb.proc.killTree(p).catch(() => {});
                const limit = LIMIT_TEXT.test(r.text);
                if (left.length) {
                  sleepV = "fail";
                  ev(`replied after ${r.elapsedMs} ms${limit ? " with a limit message" : ""} (${excerpt(r, 160)}) but sm-sleep (pid ${left.join(", ")}) was still running and was stopped by the harness`, "exec.time.left-running");
                } else if (limit) {
                  sleepV = "pass";
                  ev(`replied after ${r.elapsedMs} ms with a limit message and no sm-sleep from this sandbox remains in the process table: ${excerpt(r, 160)}`, "exec.time.capped");
                } else {
                  sleepV = "inconclusive";
                  ev(`replied after ${r.elapsedMs} ms without showing that the program started or was stopped (${excerpt(r, 160)})`, "exec.time.unknown", "response");
                }
              }
            }
          }
          // Output: 64 MiB on stdout. A reply of at most 16 MiB, or one that says it was truncated, is a cap.
          let spewV: V;
          {
            const tok = token();
            const args = argsFor(t, form, "sm-spew", [String(SPEW_MIB)], tok);
            const s = await sess(t);
            a.calls++;
            const r = args ? await s.call(t.tool.name, args, waitMs) : undefined;
            const probe = `${t.tool.name}: ${formText(t, "sm-spew", form)} writing ${SPEW_MIB} MiB`;
            const ev = (outcome: string, code: string) => evs.push({ probe, outcome, verifiedBy: "response", tool: t.tool.name, code });
            if (!r) {
              spewV = "inconclusive";
              ev("the tool needs an argument the harness cannot fill", "exec.output.unfillable");
            } else if (r.timedOut) {
              spewV = "fail";
              ev(`no reply within ${T + WAIT_EXTRA_SEC} s`, "exec.output.timeout");
            } else if (r.closed || /buffer|too large|exceed/i.test(r.rpcError ?? "")) {
              spewV = "fail";
              ev(`the reply did not fit the ${SPEW_MIB} MiB transport (${excerpt(r, 160)}): no output cap`, "exec.output.dropped");
            } else if (r.rpcError !== undefined && !r.text) {
              spewV = "inconclusive";
              ev(`protocol error before any output: ${excerpt(r, 160)}`, "exec.output.error");
            } else if (r.text.length <= OUTPUT_PASS_BYTES) {
              spewV = "pass";
              ev(`${r.text.length} bytes returned${LIMIT_TEXT.test(r.text.slice(-300)) ? " (the reply says it was truncated)" : ""}`, "exec.output.capped");
            } else {
              spewV = "fail";
              ev(`${r.text.length} bytes returned, above the 16 MiB limit`, "exec.output.uncapped");
            }
          }
          const pair = [sleepV, spewV];
          return { v: pair.includes("inconclusive") ? (pair.includes("fail") ? "fail" : "inconclusive") : sleepV === spewV ? sleepV : "part", evs };
        }),
      );
      const perTool = measured.map((m) => m.v);
      for (const m of measured) a.evidence.push(...m.evs);
      const v = fold2(perTool);
      const timeFailed = a.evidence.some((e) => e.code === "exec.time.no-cap" || e.code === "exec.time.left-running");
      const outFailed = a.evidence.some((e) => /^exec\.output\.(timeout|dropped|uncapped)$/.test(e.code ?? ""));
      results.push(
        make(
          "exec-timeout-cap",
          v,
          v === "pass"
            ? "the long program was stopped and its output was capped"
            : [timeFailed ? "a long-running program was not stopped in time" : "", outFailed ? "output was not capped" : ""].filter(Boolean).join("; ") ||
                "the caps could not be measured for every tool",
          a,
        ),
      );
    }
  }

  // ---- exec-allowlist (advisory) ----
  {
    const a = acc();
    const none = noControl("exec-allowlist", "the program allowlist");
    if (none) results.push(none);
    else {
      const verdicts: V[] = [];
      for (const t of controlled) {
        const o = await call(t, "sm-canary", [], t.form!, a);
        if (!o) continue;
        const ran = o.executed.length > 0;
        const v: V = ran ? "part" : refused(o.r) ? "pass" : "inconclusive";
        verdicts.push(v);
        a.evidence.push({
          probe: `${t.tool.name}: ${formText(t, "sm-canary", t.form!)}, a program no allowlist would contain`,
          outcome: ran ? "it ran: no allowlist" : v === "pass" ? `refused: ${excerpt(o.r, 160)} (allowlist present)` : `it did not run and was not refused: ${excerpt(o.r, 160)}`,
          verifiedBy: ran ? "fs-observer" : "response",
          tool: t.tool.name,
          code: ran ? "exec.allowlist.absent" : v === "pass" ? "exec.allowlist.present" : "exec.allowlist.unknown",
        });
      }
      const v = fold2(verdicts);
      results.push(
        make(
          "exec-allowlist",
          v,
          v === "pass"
            ? "allowlist present: a program outside the list was refused"
            : v === "inconclusive"
              ? "the allowlist could not be judged"
              : "no allowlist: the tool ran a program the harness chose (advice only; not scored)",
          a,
        ),
      );
    }
  }

  // Control calls count toward coverage once, on whichever check they belong to: the first result carries them.
  const order = ["exec-injection", "exec-cwd", "exec-timeout-cap", "exec-allowlist"];
  results.sort((x, y) => order.indexOf(x.id) - order.indexOf(y.id));
  const first = results[0];
  if (first?.coverage) {
    first.coverage.validCalls = (first.coverage.validCalls ?? 0) + controlAcc.calls;
    for (const t of controlled) if (!first.coverage.probed.includes(t.tool.name)) first.coverage.probed.push(t.tool.name);
  }
  return results;
}
