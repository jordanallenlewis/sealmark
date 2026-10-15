// net-redirect: does a URL tool re-validate the target of a redirect? A scored, non-critical check
// of the net pack, part of the standard profile since the 0.3-draft promotion (`since` stays 0.2-draft).
//
// This module and net.ts import each other. That is safe only while nothing here runs at module load: `describeRedirect` is a function
// declaration that builds its document on each call (net.ts calls it while it loads), and everything imported from net.ts is used only
// inside functions here.
import { pathToFileURL } from "node:url";
import { fillArgs } from "../classify.js";
import { redirectTargetProblem } from "../observers/listener.js";
import type { CheckDoc, CheckResult, Evidence, PackCtx } from "../types.js";
import { checkSettings, excerpt, expandTemplate, listenerPorts, makeResult, newToken, outcomeOf, targetProblem, type Caller, type SsrfOutcome } from "./net.js";

export function describeRedirect(): CheckDoc[] {
  return [
    {
      id: "net-redirect",
      pack: "net",
      label: "Redirects are re-validated",
      critical: false,
      advisory: false,
      scope: "server (does a URL tool re-validate the target of a redirect? observable only when the server already fetches the harness listener)",
      verifiedBy: ["listener", "response"],
      probes: [
        { id: "follow", text: "/redir/<token> on the listener: a 302 to a path on the same origin", kind: "redirect" },
        { id: "hop", text: "/redir-to/<token> on the listener: a 302 to the loopback spelling the server refused when given directly (localhost when it refused none), and a second one to http://[::1]:<port6>/t/<token> when the host has an IPv6 loopback listener", kind: "redirect" },
        { id: "scheme-file", text: "/redir-to/<token> on the listener: a 302 to a file: URL of the sandbox canary", kind: "scheme" },
        { id: "scheme-raw", text: "/redir-to/<token> on the listener: a 302 to a gopher: URL on the listener's own port", kind: "scheme" },
      ],
      thresholds: {},
      falsePositive: "A server that follows redirects to loopback on purpose (a developer tool) fails by design. Only redirects served by the harness listener are used.",
      falseNegative: "A server that follows redirects passes only when the hop probe shows it re-validates: the redirect to a spelling it refused when given directly was not followed (a server that accepts loopback targets directly has refused nothing to compare with: re-validation cannot be measured and the check is inconclusive). A second hop goes to the IPv6 loopback spelling when the host has an IPv6 loopback listener. Redirects from a public host to loopback are not tested: the harness contacts only its own listener. DNS rebinding is not tested. A server that blocks loopback outright is never measured (n/a).",
      configKeys: ["checks.net-redirect.enabled", "checks.net-redirect.severity"],
      since: "0.2-draft",
      status: "shipped",
    },
  ];
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A Host header or URL host reduced to the bare host: lower case, no brackets, no port. */
function bareHost(h: string): string {
  const t = h.trim().toLowerCase();
  const m = /^\[([^\]]*)\](?::\d+)?$/.exec(t);
  return m ? m[1]! : t.replace(/:\d+$/, "");
}
/** The base URL ("http://host:port") of an expanded corpus URL (what capsCheck does). */
const stripPath = (url: string): string => url.replace(/\/(?:t|redir)\/.*$/, "");
/** The host of a base URL as it was spelled ("localhost", "[::1]", "0x7f000001"), without scheme and port. */
const spelled = (base: string): string => base.replace(/^[a-z]+:\/\//i, "").replace(/:\d+$/, "");
/** The host an HTTP client sends for a base URL: the URL parser turns 127.1 and 0x7f000001 into 127.0.0.1. */
function sentHost(base: string): string {
  try {
    return bareHost(new URL(base).host);
  } catch {
    return bareHost(spelled(base));
  }
}

/**
 * The spelling the hop probe redirects to: the first one net-loopback-ssrf saw the server refuse that the Host header can tell apart
 * from the one it fetched (a spelling the URL parser rewrites to the same host could not be told from a plain follow) and that the
 * listener will serve. When there is none: localhost, which counts as a followed redirect and never as a hop.
 */
function pickOther(ssrf: SsrfOutcome, v: { port: number; port6?: number; canaryDir: string; canaryFile: string }, base: string): { base: string; refused: boolean } {
  const ports = [v.port, ...(v.port6 !== undefined ? [v.port6] : [])];
  for (const r of ssrf.refused) {
    const other = stripPath(expandTemplate(r.template, { ...v, token: "" }));
    if (redirectTargetProblem(`${other}/t/x`, { ports }) !== undefined) continue;
    if (sentHost(other) === sentHost(base)) continue;
    return { base: other, refused: true };
  }
  return { base: sentHost(base) === "localhost" ? `http://127.0.0.1:${v.port}` : `http://localhost:${v.port}`, refused: false };
}

/** Redirect re-validation: after a URL tool has fetched a harness URL, does it follow a 302 blindly? Advisory, loopback-only. */
export async function redirectCheck(ctx: PackCtx, caller: Caller, ssrf: SsrfOutcome, ssrfRan: boolean): Promise<CheckResult> {
  const d = describeRedirect()[0]!;
  const s = checkSettings(ctx, d.id);
  if (s.disabled) return makeResult(ctx, d, "na", "", []);
  if (!ssrfRan) return makeResult(ctx, d, "na", "net-loopback-ssrf did not run, so no loopback URL is known to be fetchable", []);
  if (!ssrf.allowed) {
    return makeResult(ctx, d, "na", "the server refused or never reached the loopback listener, so redirect handling could not be observed (a server that blocks loopback cannot be sent a redirect it would follow)", []);
  }
  const sb = ctx.sandbox!;
  const l = sb.listener;
  const { port, port6 } = listenerPorts(ctx);
  const ports = [port, ...(port6 !== undefined ? [port6] : [])];
  const allowDns = Boolean(ctx.config?.net?.allow_dns);
  const vars = { port, port6, canaryDir: sb.canary, canaryFile: sb.files.canary };
  const base = stripPath(expandTemplate(ssrf.allowed.template, { ...vars, token: "" }));
  const other = pickOther(ssrf, vars, base);
  const otherSpelling = spelled(other.base);
  const { tool, cls, urlParam } = ssrf.allowed.target;
  const evidence: Evidence[] = [];
  let sent = 0;

  /** Sends one probe and waits for what the listener saw. `to` is the redirect target the URL carries; it passes the same gate. */
  const send = async (id: string, url: string, to: string | undefined, token: string) => {
    const label = `${tool.name} ${id}: ${url}`;
    const problem = [url, ...(to ? [to] : [])].map((u) => targetProblem(u, { sandboxDir: sb.dir, ports, allowDns })).find((p) => p !== undefined);
    if (problem) {
      evidence.push({ probe: label, outcome: `not sent: ${problem}`, verifiedBy: "static", tool: tool.name });
      return undefined;
    }
    const args = fillArgs(tool, cls, { url }, token);
    if (!args) {
      evidence.push({ probe: label, outcome: "not sent: the arguments could not be built", verifiedBy: "static", tool: tool.name });
      return undefined;
    }
    const connsBefore = l.connections().length;
    const r = await caller.call(tool.name, args, 15_000);
    await l.waitForHit(token, 400);
    // A call counts as one that exercised the tool when it was answered or refused, or when the listener saw its request; an errored call does not.
    if (outcomeOf(r, url) !== "failed" || l.hopsFor(token).length > 0) sent++;
    return { label, r, connsBefore, common: { tool: tool.name, args: { ...args, [urlParam]: url } } };
  };
  /** The redirecting request of a token and the first `t` request after it. A server may follow after it has replied: `sweep` waits a little. */
  const hops = async (token: string, first: "redir" | "redir-to", sweep: boolean) => {
    const look = () => {
      const all = l.hopsFor(token);
      const redirect = all.find((r) => r.route === first);
      return { redirect, next: redirect ? all.find((r) => r.route === "t" && r.id > redirect.id) : undefined };
    };
    let seen = look();
    if (sweep && !seen.next) {
      await sleep(500);
      seen = look();
    }
    return seen;
  };
  const refusedByListener = (label: string, rec: { refusedTarget?: boolean } | undefined, common: object): boolean => {
    if (!rec?.refusedTarget) return false;
    evidence.push({ ...common, probe: label, outcome: "the listener refused its own redirect target (a harness bug, not a server result)", verifiedBy: "listener", code: "net.redirect-refused-target" });
    return true;
  };

  // ---- follow: a 302 to a path on the same origin ----
  const followToken = newToken();
  const follow = await send("follow", `${base}/redir/${followToken}`, undefined, followToken);
  if (!follow) return makeResult(ctx, d, "inconclusive", "the redirect probe could not be sent", evidence, { probed: [], notCovered: [], validCalls: sent });
  const f = await hops(followToken, "redir", true);
  if (!f.redirect) {
    evidence.push({ ...follow.common, probe: follow.label, outcome: "the listener never saw the redirecting request", verifiedBy: "listener", excerpt: excerpt(follow.r.text || follow.r.rpcError || "", 400) });
    return makeResult(ctx, d, "inconclusive", "the listener did not see the redirect probe, so redirect handling could not be observed", evidence, { probed: [tool.name], notCovered: [], validCalls: sent });
  }
  const followed = f.next !== undefined;
  evidence.push(
    followed
      ? { ...follow.common, probe: follow.label, outcome: `the server followed the 302 to /t/${followToken} on the same origin`, verifiedBy: "listener", code: "net.redirect-followed" }
      : { ...follow.common, probe: follow.label, outcome: "the listener answered 302 and the server did not request the Location (it stopped at the redirect)", verifiedBy: "listener", code: "net.redirect-stopped" },
  );

  // ---- hop: a 302 to a loopback spelling (the one the server refused when given directly, when there is one) ----
  /** One hop probe: a URL that answers 302 to `otherBase`; `refusedDirectly` says whether the server refused that spelling when it was given directly. */
  const tryHop = async (id: string, otherBase: string, refusedDirectly: boolean) => {
    const token = newToken();
    const target = `${otherBase}/t/${token}`;
    const spelling = spelled(otherBase);
    const out = { sent: false, spelling, redirectSeen: false, followed: false, refused: false };
    const hop = await send(id, `${base}/redir-to/${token}?to=${encodeURIComponent(target)}`, target, token);
    if (!hop) return out;
    out.sent = true;
    const h = await hops(token, "redir-to", true);
    if (refusedByListener(hop.label, h.redirect, hop.common)) return out;
    out.redirectSeen = Boolean(h.redirect);
    if (!h.redirect) {
      evidence.push({ ...hop.common, probe: hop.label, outcome: "the listener never saw the redirecting request", verifiedBy: "listener" });
    } else if (h.next) {
      out.followed = true;
      // A hop only when the request that followed names the spelling the server refused; any other Host is a plain follow.
      out.refused = refusedDirectly && bareHost(h.next.host) === sentHost(otherBase);
      evidence.push(
        out.refused
          ? { ...hop.common, probe: hop.label, outcome: `the server followed the 302 to ${spelling}, a spelling it refused when given directly (Host: ${excerpt(h.next.host, 60)})`, verifiedBy: "listener", code: "net.redirect-hop" }
          : { ...hop.common, probe: hop.label, outcome: `the server followed the 302 to ${spelling} (Host: ${excerpt(h.next.host, 60)}); ${refusedDirectly ? "the Host header does not show that spelling" : "it did not refuse this spelling directly"}`, verifiedBy: "listener", code: "net.redirect-followed" },
      );
    } else {
      evidence.push({ ...hop.common, probe: hop.label, outcome: `the listener answered 302 to ${spelling} and the server did not request it`, verifiedBy: "listener", code: "net.redirect-stopped" });
    }
    return out;
  };
  const mainHop = await tryHop("hop", other.base, other.refused);
  const hop = mainHop.sent;
  const hopFollowed = mainHop.followed;
  const hopRefused = mainHop.refused;
  /** The listener saw the redirecting request of the hop probe (the server fetched the URL that answers 302 to the refused spelling). */
  const hopRedirectSeen = mainHop.redirectSeen;
  // The IPv6 loopback family: a second hop, to [::1], when the listener has an IPv6 socket and the first hop is not already there.
  const v6Base = port6 !== undefined ? `http://[::1]:${port6}` : undefined;
  let hop6: Awaited<ReturnType<typeof tryHop>> | undefined;
  if (v6Base && redirectTargetProblem(`${v6Base}/t/x`, { ports }) === undefined && sentHost(other.base) !== "::1" && sentHost(base) !== "::1") {
    hop6 = await tryHop("hop6", v6Base, ssrf.refused.some((r) => r.id === "ipv6"));
  } else if (v6Base === undefined) {
    evidence.push({ probe: `${tool.name} hop6: http://[::1]:<port>/t/<token>`, outcome: "not sent: this host has no IPv6 loopback listener", verifiedBy: "static", tool: tool.name });
  }
  const family = v6Base === undefined ? "; the IPv6 loopback family was not tried (this host has no IPv6 loopback listener)" : "";

  // ---- scheme-file: a 302 to the sandbox canary as a file: URL ----
  l.allowFileRedirectsUnder(sb.dir);
  const fileToken = newToken();
  const fileTarget = pathToFileURL(sb.files.canary).href;
  const file = await send("scheme-file", `${base}/redir-to/${fileToken}?to=${encodeURIComponent(fileTarget)}`, fileTarget, fileToken);
  let fileRead = false;
  if (file) {
    const h = await hops(fileToken, "redir-to", false);
    if (!refusedByListener(file.label, h.redirect, file.common)) {
      fileRead = Boolean(h.redirect) && file.r.text.includes(sb.tokens.canary);
      const text = excerpt(file.r.text || file.r.rpcError || "", 400);
      evidence.push(
        fileRead
          ? { ...file.common, probe: file.label, outcome: "the server followed a 302 to a file: URL and the sandbox canary came back in the response", verifiedBy: "response", code: "net.redirect-file-read", excerpt: text }
          : h.redirect
            ? { ...file.common, probe: file.label, outcome: "the listener answered 302 to a file: URL and the canary did not come back", verifiedBy: "response", code: "net.redirect-stopped", excerpt: text }
            : { ...file.common, probe: file.label, outcome: "the listener never saw the redirecting request", verifiedBy: "listener", excerpt: text },
      );
    }
  }

  // ---- scheme-raw: a 302 to a gopher: URL on the listener's own port ----
  const rawToken = newToken();
  const rawTarget = `gopher://127.0.0.1:${port}/_${rawToken}`;
  const raw = await send("scheme-raw", `${base}/redir-to/${rawToken}?to=${encodeURIComponent(rawTarget)}`, rawTarget, rawToken);
  let rawTcp = false;
  if (raw) {
    const rawConns = () => l.connections().slice(raw.connsBefore).filter((c) => c.httpRequests === 0);
    let h = await hops(rawToken, "redir-to", false);
    if (h.redirect && !rawConns().length) {
      await sleep(500);
      h = await hops(rawToken, "redir-to", false);
    }
    const conns = rawConns();
    if (!refusedByListener(raw.label, h.redirect, raw.common)) {
      rawTcp = Boolean(h.redirect) && conns.length > 0;
      evidence.push(
        rawTcp
          ? { ...raw.common, probe: raw.label, outcome: "the server followed a 302 to a gopher: URL and opened a raw TCP connection to the listener", verifiedBy: "listener", code: "net.redirect-raw-tcp", excerpt: excerpt(conns[0]!.firstBytes, 200) }
          : h.redirect
            ? { ...raw.common, probe: raw.label, outcome: "the listener answered 302 to a gopher: URL and saw no raw connection", verifiedBy: "listener", code: "net.redirect-stopped", excerpt: excerpt(raw.r.text || raw.r.rpcError || "", 400) }
            : { ...raw.common, probe: raw.label, outcome: "the listener never saw the redirecting request", verifiedBy: "listener" },
      );
    }
  }

  const coverage = { probed: [tool.name], notCovered: [], validCalls: sent };
  const fails: string[] = [];
  if (hopRefused) fails.push(`the server followed a redirect to a target it refused when given directly (${otherSpelling})`);
  if (hop6?.refused) fails.push(`the server followed a redirect to a target it refused when given directly (${hop6.spelling})`);
  if (fileRead) fails.push("the server followed a redirect to a file: URL and returned the sandbox canary");
  if (rawTcp) fails.push("the server followed a redirect to a gopher: URL and opened a raw connection");
  if (fails.length) return makeResult(ctx, d, "fail", fails.join("; "), evidence, coverage);
  // A server that follows a redirect and refuses the redirect to a spelling it refused when given directly has shown what this check is named for:
  // the target of a redirect is re-validated. That needs the hop probe sent, its redirecting request seen, and the spelling really refused before.
  if (followed && other.refused && hop && hopRedirectSeen && !hopFollowed) {
    return makeResult(ctx, d, "pass", `redirects are followed and the redirect to ${otherSpelling}, which the server refused when given directly, was not: the target is re-validated${family}`, evidence, coverage);
  }
  if (followed || hopFollowed) {
    // A server that accepted every loopback spelling directly has nothing to re-validate against: the property cannot be measured, and half a point for it would be inflation.
    if (!other.refused) {
      return makeResult(ctx, d, "inconclusive", `redirects are followed; re-validation cannot be measured on a server that accepts loopback targets directly (it accepted every spelling the harness tried, so a refused hop has nothing to be compared with)${family}`, evidence, coverage);
    }
    const summary = hopFollowed
      ? `redirects are followed; the request after the redirect to ${otherSpelling} did not carry that Host, so the target could not be told apart from a plain follow`
      : `redirects are followed; the redirect probe to ${otherSpelling} could not be sent, or the listener did not see its redirecting request, so re-validation could not be told apart from a stop`;
    return makeResult(ctx, d, "part", `${summary}${family}`, evidence, coverage);
  }
  return makeResult(ctx, d, "pass", `redirects are not followed: the server fetched the redirecting URL and stopped at the 302${family}`, evidence, coverage);
}
