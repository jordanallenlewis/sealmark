/**
 * Why a server could not start, as one of a few kinds an author can act on (sealmark#9).
 *
 * A start failure used to be one opaque line ("could not start or talk to the server: Connection closed"); the cause sat in the
 * server's stderr. The kind is read from the error message and the end of stderr, where a dying process writes its last word.
 * It is advice, not a verdict: it never changes a grade, and the original message is kept as the detail.
 */
import { isConnectTimeout } from "./launch.js";

export type StartFailureKind = "dependency-resolution" | "needs-credentials" | "missing-runtime" | "bad-launch" | "initialize-timeout" | "unknown";

export interface StartFailure {
  kind: StartFailureKind;
  /** One line telling the author what to do about this kind. */
  advice: string;
}

export const START_FAILURE_ADVICE: Record<StartFailureKind, string> = {
  "dependency-resolution": "the server's package or one of its dependencies could not be installed or imported; check that the versions it pins still exist (the server stderr names the one that failed).",
  "needs-credentials": "the server wants a credential (an API key, a token or a sign-in) before it starts; give it a test one in the server's env in sealmark.yaml.",
  "missing-runtime": "the launcher or runtime the command needs is missing on this machine, or is the wrong version (node, python, uvx, npx, docker); install it or change the command.",
  "bad-launch": "the server ran but rejected how it was launched (its arguments, entry file, file permissions or a required setting); check the command and its env.",
  "initialize-timeout": "the server did not answer initialize or tools/list in time and said nothing more specific; run the command once by hand to see it start, then raise --connect-timeout (or --start-timeout for --start) if it is only slow.",
  unknown: "the cause is not one Sealmark recognizes; read the first error in the server's stderr (saved next to the report).",
};

/** Only the end of stderr is read: that is where the fatal line is, and it keeps a flood of output cheap. */
const STDERR_TAIL = 64 * 1024;

// Every pattern is bounded ({0,n}, no nested repeats), so a hostile stderr cannot make a match slow.
const RULES: ReadonlyArray<readonly [StartFailureKind, RegExp]> = [
  // The command itself is not there, or is the wrong version for the package.
  ["missing-runtime", /\bspawn \S{1,200} ENOENT\b/],
  ["missing-runtime", /(?:^|\n)[^\n:]{0,40}sh: (?:\d{1,6}: )?[^\s:]{1,200}: (?:command )?not found/],
  ["missing-runtime", /\bcommand not found\b|is not recognized as an internal or external command/i],
  // npm's EBADENGINE is only a warning unless npm stops on it (engine-strict), so only its error form counts.
  ["missing-runtime", /current Python version \([^)\n]{0,40}\) does not satisfy|requires a different Python|npm (?:ERR!|error) (?:code )?EBADENGINE\b|The engine "node" is incompatible/i],
  ["missing-runtime", /Cannot connect to the Docker daemon/i],
  // A module given by path (the entry file) is a launch problem; a module given by name is a dependency problem (next rule).
  ["bad-launch", /Cannot find module ['"](?:\/|\.{1,2}\/|[A-Za-z]:\\)/],
  [
    "dependency-resolution",
    /No solution found when resolving|ResolutionImpossible|Could not find a version that satisfies|No matching distribution found|npm (?:ERR!|error) code (?:E404|ETARGET|ERESOLVE|ENOVERSIONS)\b|No matching version found for|404 Not Found - GET https?:\/\/|is not in this registry|ModuleNotFoundError|ImportError: (?:No module named|cannot import name)|Cannot find package ['"]|Cannot find module ['"][^'"./\\]/,
  ],
  // An env-style name for a secret (upper case), then a word that says it is missing, on the same line.
  ["needs-credentials", /\b[A-Z][A-Z0-9_]{0,60}(?:API_?KEY|TOKEN|SECRET|ACCESS_KEY|PASSWORD)\b[^\n]{0,60}?\b(?:required|missing|not (?:set|provided|found|configured|defined)|must be (?:set|provided)|invalid|expired)\b/],
  ["needs-credentials", /\b(?:api[ _-]?key|access[ _-]?token|auth(?:entication)?[ _-]?token|bearer token|credentials?|client[ _-]?secret|personal access token|secret key)\b[^\n]{0,60}?\b(?:required|missing|not (?:set|provided|found|configured|defined)|must be (?:set|provided)|invalid|expired)\b/i],
  ["needs-credentials", /\b(?:missing|no)\s{1,3}(?:api[ _-]?key|access[ _-]?token|credentials)\b|\b(?:requires?|needs?)\b[^\n]{0,30}?\b(?:api[ _-]?key|access[ _-]?token|credentials)\b/i],
  ["needs-credentials", /\bnot (?:signed|logged) in\b|\bnot authenticated\b|\bunauthenticated\b/i],
  // The process ran and refused its arguments, its entry file or a setting.
  ["bad-launch", /(?:^|\n)usage: |unrecognized arguments?\b|\bunknown (?:option|argument|command|flag)\b|\binvalid (?:option|argument)\b|the following arguments are required/i],
  ["bad-launch", /\bPermission denied\b|\bEACCES\b|\bEISDIR\b|\bis a directory\b/i],
  ["bad-launch", /environment variable\b[^\n]{0,60}?\b(?:required|not set|missing|must be set)\b|\b[A-Z][A-Z0-9]{0,40}_[A-Z0-9_]{1,60} (?:is required|must be set|is not set)\b/],
];

/** A line logged at warning level or below (`WARNING: X_API_KEY not set, some tools disabled`, `npm warn ...`) is not why a process died. */
const NOT_FATAL = /^\s{0,8}(?:\S{0,40}\d\S{0,40}\s{1,4})?(?:npm\s{1,4})?\[?(?:warn(?:ing)?|info|debug|notice|trace)\]?(?::|\s)/i;

/** True for a start that ran out of time: the SDK's initialize timeout, or an HTTP server whose URL never answered. */
const timedOut = (message: string): boolean => isConnectTimeout(message) || /did not answer (?:initialize )?within \d+ s\b/.test(message);

/**
 * The rule whose match ends latest wins (a process says why it died last, after any earlier noise); on a tie, the earlier rule.
 * The message goes after stderr: it is the harness's own last word (and the SDK's message repeats the last stderr lines).
 */
export function classifyStartFailure(input: { message: string; stderr?: string }): StartFailure {
  const stderr = input.stderr ?? "";
  const tail = stderr.length > STDERR_TAIL ? stderr.slice(-STDERR_TAIL) : stderr;
  const text = `${tail}\n${input.message}`
    .split("\n")
    .filter((line) => !NOT_FATAL.test(line))
    .join("\n");
  let best: { kind: StartFailureKind; end: number } | undefined;
  for (const [kind, re] of RULES) {
    const all = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
    let end = -1;
    for (let m = all.exec(text); m; m = all.exec(text)) {
      end = m.index + m[0].length;
      if (m[0].length === 0) all.lastIndex++;
    }
    if (end >= 0 && (!best || end > best.end)) best = { kind, end };
  }
  const kind: StartFailureKind = best ? best.kind : timedOut(input.message) ? "initialize-timeout" : "unknown";
  return { kind, advice: START_FAILURE_ADVICE[kind] };
}
