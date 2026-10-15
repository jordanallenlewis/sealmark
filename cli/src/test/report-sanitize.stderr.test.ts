import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { renderDoctor, type DoctorReport } from "../doctor.js";
import { cliKit } from "./helpers.js";

let dir: string;
before(() => {
  dir = mkdtempSync(join(tmpdir(), "sealmark-rs-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const { sealmark, writeConfig } = cliKit(() => dir);
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f]/;
const ESC = "\x1b";

/** A "server" that prints escape sequences to stderr and exits at once. */
function badServer(): string {
  const file = join(dir, "esc-server.mjs");
  writeFileSync(file, `process.stderr.write("fatal\\x1b[2K\\x1b[1;32mALL GOOD\\x1b]8;;http://evil.example\\x07link\\x1b]8;;\\x07\\n  at main (x.js:1)\\n");\nprocess.exit(1);\n`);
  return file;
}

describe("report-sanitize: stderr of a failed run and doctor", { timeout: 120_000 }, () => {
  it("run: the harness failure printed on stderr has no raw escape, and still says what the server printed", () => {
    const r = sealmark(["run", "--start", `${process.execPath} ${badServer()}`, "--pack", "core", "--timeout-probe", "2", "--fail-under", "none"]);
    assert.notEqual(r.code, 0, r.err);
    assert.ok(r.err.includes("harness failure"), r.err);
    assert.ok(!r.err.includes(ESC) && !CONTROL.test(r.err.replace(/\n/g, "")), JSON.stringify(r.err));
    assert.ok(r.err.includes("ALL GOOD"), "the text is shown, not dropped");
    assert.ok(!r.out.includes(ESC), "the text report on stdout too");
  });

  it("run: the stderr log file is the machine copy and keeps the server's bytes", () => {
    const out = join(dir, "r.json");
    sealmark(["run", "--start", `${process.execPath} ${badServer()}`, "--pack", "core", "--timeout-probe", "2", "--fail-under", "none", "--format", "json", "--out", out]);
    // A file, not a screen: the capture is kept as the server wrote it (the JSON report beside it escapes it as JSON does).
    assert.ok(readFileSync(`${out}.stderr.log`, "utf8").includes(ESC));
  });

  it("doctor: a server that prints escapes to stderr produces text with none", () => {
    const r = sealmark(["doctor", "--config", writeConfig("esc.yaml", process.execPath, [badServer()])]);
    assert.equal(r.code, 4, r.out + r.err);
    assert.ok(r.out.includes("server stderr:"), r.out);
    assert.ok(r.out.includes("ALL GOOD"), r.out);
    assert.ok(!CONTROL.test(r.out.replace(/\n/g, "")), JSON.stringify(r.out));
    assert.ok(!CONTROL.test(r.err.replace(/\n/g, "")), JSON.stringify(r.err));
  });

  it("doctor --json keeps the raw values like the JSON run report", () => {
    const r = sealmark(["doctor", "--json", "--config", writeConfig("esc-json.yaml", process.execPath, [badServer()])]);
    const json = JSON.parse(r.out) as DoctorReport;
    assert.ok(json.servers[0].stderr.includes(ESC));
  });

  it("renderDoctor: a hand-built report with escapes in stderr, an item, a name and the classification prints none", () => {
    const bad = `x${ESC}[2K${ESC}]8;;http://evil.example\x07y\r z`;
    const report: DoctorReport = {
      ok: false,
      exitCode: 4,
      environment: [{ id: "node", status: "ok", title: `node ${bad}`, detail: bad }],
      servers: [
        {
          name: bad,
          transport: "stdio",
          display: bad,
          items: [{ id: "start", status: "fail", title: bad, detail: bad }],
          stderr: `${bad}\n    at deep (x.js:1)\n${bad}`,
          classification: [],
          classificationText: ["Classification:", `  ${bad}     text   low   ← ${bad}`, "  packs applied: none"],
          packs: [{ pack: "core", requested: true, applies: true, reason: bad }],
        },
      ],
      summary: { failures: 1, warnings: 0 },
    };
    const text = renderDoctor(report);
    assert.ok(!CONTROL.test(text.replace(/\n/g, "")), JSON.stringify(text));
    assert.ok(!text.includes(" "));
    assert.ok(text.includes("x\\u001b[2K"));
    assert.ok(text.includes("    |     at deep (x.js:1)"), "stderr indentation survives");
    assert.ok(/ {5}text {3}low {3}← /.test(text), "the classification columns keep their spacing");
  });
});
