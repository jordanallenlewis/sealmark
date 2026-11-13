import assert from "node:assert/strict";
import { createServer } from "node:http";
import { describe, it } from "node:test";
import { buildPing, sendPing, telemetryEnabled } from "../telemetry.js";

describe("telemetry (opt-in usage counter)", () => {
  it("is off by default and off for any value but 1/true/yes", () => {
    assert.equal(telemetryEnabled({}), false);
    assert.equal(telemetryEnabled({ SEALMARK_TELEMETRY: "0" }), false);
    assert.equal(telemetryEnabled({ SEALMARK_TELEMETRY: "1" }), true);
  });
  it("DO_NOT_TRACK always wins", () => {
    assert.equal(telemetryEnabled({ SEALMARK_TELEMETRY: "1", DO_NOT_TRACK: "1" }), false);
  });
  it("the payload has exactly the documented fields", () => {
    const p = buildPing("9.9.9", "run");
    assert.deepEqual(Object.keys(p).sort(), ["ci", "command", "node", "os", "schema", "sealmark"]);
    assert.equal(p.sealmark, "9.9.9");
  });
  it("sends nothing when off, one POST when on, and never throws", async () => {
    let hits = 0;
    let body = "";
    const srv = createServer((req, res) => {
      hits++;
      req.on("data", (c) => (body += c));
      req.on("end", () => res.end("ok"));
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(srv.address() as { port: number }).port}/p`;
    await sendPing("1.0.0", "run", { SEALMARK_TELEMETRY_URL: url });
    assert.equal(hits, 0);
    await sendPing("1.0.0", undefined, { SEALMARK_TELEMETRY: "1", SEALMARK_TELEMETRY_URL: url });
    assert.equal(hits, 0);
    await sendPing("1.0.0", "run", { SEALMARK_TELEMETRY: "1", SEALMARK_TELEMETRY_URL: url });
    assert.equal(hits, 1);
    assert.equal(JSON.parse(body).command, "run");
    srv.close();
    await sendPing("1.0.0", "run", { SEALMARK_TELEMETRY: "1", SEALMARK_TELEMETRY_URL: "http://127.0.0.1:1/x" });
  });
});
