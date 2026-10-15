import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createLogObserver } from "../observers/log.js";

describe("log observer", () => {
  it("collects both sources, marks a position, and reads what came after it", () => {
    const log = createLogObserver();
    assert.deepEqual(log.sources, []);
    log.push("boot line\n", "launched");
    const m = log.mark();
    log.push("Authorization: Bearer sm-bearer-a-abc\n", "launched");
    log.push("stderr line\n", "stderr");
    assert.deepEqual([...log.sources].sort(), ["launched", "stderr"]);
    assert.equal(log.since(m), "Authorization: Bearer sm-bearer-a-abc\nstderr line\n");
    assert.equal(log.all(), "boot line\nAuthorization: Bearer sm-bearer-a-abc\nstderr line\n");
    assert.equal(log.since(log.mark()), "");
  });

  it("find returns the first position after the mark, or -1", () => {
    const log = createLogObserver();
    log.push("needle early\n", "stderr");
    const m = log.mark();
    log.push("padding needle late\n", "stderr");
    assert.equal(log.find("needle"), 0);
    assert.equal(log.find("needle", m), m + "padding ".length);
    assert.equal(log.find("absent", m), -1);
    assert.equal(log.find("", m), -1);
  });

  it("keeps only the last `keep` characters, and a mark taken earlier still reads correctly", () => {
    const log = createLogObserver(100);
    log.push("A".repeat(60), "launched");
    const m = log.mark();
    log.push("B".repeat(60), "launched");
    // 120 pushed, 100 kept: the first 20 characters are gone.
    assert.equal(log.all().length, 100);
    assert.equal(log.since(m), "B".repeat(60));
    // A mark that fell off the front reads from the oldest text still held.
    assert.equal(log.since(0).length, 100);
    log.push("C".repeat(100), "launched");
    assert.equal(log.since(m), "C".repeat(100), "the mark is older than everything held: the capture starts where it can");
    assert.equal(log.mark(), 220);
    assert.equal(log.find("C", 0), 120);
  });

  it("the default capture keeps 1 MiB", () => {
    const log = createLogObserver();
    log.push("x".repeat(1024 * 1024 + 10), "stderr");
    assert.equal(log.all().length, 1024 * 1024);
  });
});
