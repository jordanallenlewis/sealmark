// Replays the regression corpus against the built CLI and checks each manifest's `expect`. Sandbox only:
// it launches third-party server code. corpus.yml runs it on a fresh runner with no secrets.
// Usage: node scripts/corpus-replay.mjs [id ...]   (from cli/, after npm run build)
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
const L = "FDCBA";
const dir = new URL("../corpus/", import.meta.url).pathname;
const want = process.argv.slice(2);
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json") && (!want.length || want.includes(f.slice(0, -5))));
let bad = 0;
for (const f of files) {
  const m = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  const out = path.join(process.env.RUNNER_TEMP ?? "/tmp", `corpus-${m.id}.json`);
  const t0 = Date.now();
  const r = spawnSync("node", ["dist/cli.js", "run", "--start", m.launch, "--format", "json", "--out", out, "--fail-under", "none"], { encoding: "utf8", timeout: (m.expect.maxSeconds ?? 420) * 1000 });
  const secs = Math.round((Date.now() - t0) / 1000);
  const problems = [];
  let rep = null;
  try { rep = JSON.parse(fs.readFileSync(out, "utf8")); } catch {}
  const crashed = r.status === null || /TypeError|ReferenceError|RangeError|Unhandled/.test(r.stderr ?? "") || (rep == null && m.expect.noCrash);
  if (m.expect.noCrash && crashed) problems.push("crash or no report");
  if (m.expect.maxSeconds && secs > m.expect.maxSeconds) problems.push(`took ${secs}s`);
  for (const [id, verdict] of Object.entries(m.expect.checks ?? {})) {
    const c = (rep?.checks ?? []).find((x) => x.id === id);
    if ((c?.verdict ?? "missing") !== verdict) problems.push(`check ${id}: ${c?.verdict ?? "missing"}, expected ${verdict}`);
  }
  if (m.expect.worstAtLeast && rep) {
    const worst = Object.values(rep.packs ?? {}).map((p) => p.grade?.letter).filter(Boolean).sort((a, b) => L.indexOf(a) - L.indexOf(b))[0];
    if (!worst || L.indexOf(worst) < L.indexOf(m.expect.worstAtLeast)) problems.push(`worst grade ${worst ?? "none"}, expected at least ${m.expect.worstAtLeast}`);
  }
  console.log(`${problems.length ? "FAIL" : "ok  "} ${m.id} (${secs}s)${problems.length ? ": " + problems.join("; ") : ""}`);
  if (problems.length) bad += 1;
}
console.log(`${files.length} corpus server(s), ${bad} failing`);
process.exit(bad ? 1 : 0);
