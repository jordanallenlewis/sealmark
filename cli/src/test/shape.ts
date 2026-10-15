/** Offline shape checks for the report formats (no XML or JSON Schema validator is available without a dependency). Used by report.test.ts and cli.test.ts. */
import assert from "node:assert/strict";

export interface XmlNode {
  name: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  text: string;
}

/** A strict little XML parser: tags must nest, attributes must be quoted and unique, text must not contain a bare `<` or `&`. Throws on anything else. */
export function parseXml(xml: string): XmlNode {
  const root: XmlNode = { name: "#doc", attrs: {}, children: [], text: "" };
  const stack = [root];
  const re = /<!--([\s\S]*?)-->|<\?xml[^>]*\?>|<\/([A-Za-z][\w.-]*)\s*>|<([A-Za-z][\w.-]*)((?:\s+[A-Za-z_][\w.:-]*="[^"<]*")*)\s*(\/?)>|([^<]+)|(<)/g;
  for (let m = re.exec(xml); m; m = re.exec(xml)) {
    if (m[7]) throw new Error(`stray < at ${m.index}: ${xml.slice(m.index, m.index + 40)}`);
    if (m[1] !== undefined) {
      if (/--/.test(m[1])) throw new Error("-- inside a comment");
    } else if (m[2]) {
      const top = stack.pop()!;
      if (top.name !== m[2]) throw new Error(`</${m[2]}> closes <${top.name}>`);
    } else if (m[3]) {
      const attrs: Record<string, string> = {};
      for (const a of m[4].matchAll(/([A-Za-z_][\w.:-]*)="([^"]*)"/g)) {
        if (a[1] in attrs) throw new Error(`duplicate attribute ${a[1]}`);
        attrs[a[1]] = a[2];
      }
      const node: XmlNode = { name: m[3], attrs, children: [], text: "" };
      stack[stack.length - 1].children.push(node);
      if (!m[5]) stack.push(node);
    } else if (m[6] !== undefined) {
      if (/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);)/i.test(m[6])) throw new Error(`bare & in text near ${m[6].slice(0, 40)}`);
      stack[stack.length - 1].text += m[6];
    }
  }
  if (stack.length !== 1) throw new Error(`unclosed <${stack[stack.length - 1].name}>`);
  assert.equal(root.children.length, 1, "exactly one root element");
  return root.children[0];
}

export const kids = (n: XmlNode, name: string) => n.children.filter((c) => c.name === name);

/** The Ant/Jenkins JUnit layout: names, required attributes, nesting, and totals that add up. */
export function validateJunit(xml: string): XmlNode {
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>\n/);
  const root = parseXml(xml);
  assert.equal(root.name, "testsuites");
  let tests = 0;
  let failures = 0;
  let errors = 0;
  let skipped = 0;
  for (const s of root.children) {
    assert.equal(s.name, "testsuite");
    for (const a of ["name", "tests", "failures", "errors", "skipped", "time"]) assert.ok(a in s.attrs, `testsuite lacks ${a}`);
    const cases = kids(s, "testcase");
    assert.equal(Number(s.attrs.tests), cases.length, `testsuite ${s.attrs.name}: tests attribute`);
    assert.equal(Number(s.attrs.failures), cases.filter((c) => kids(c, "failure").length).length);
    assert.equal(Number(s.attrs.errors), cases.filter((c) => kids(c, "error").length).length);
    assert.equal(Number(s.attrs.skipped), cases.filter((c) => kids(c, "skipped").length).length);
    for (const c of s.children) assert.ok(["properties", "testcase", "system-out", "system-err"].includes(c.name), `unexpected <${c.name}> in testsuite`);
    for (const c of cases) {
      assert.ok(c.attrs.name && c.attrs.classname && "time" in c.attrs, "testcase name, classname, time");
      for (const k of c.children) assert.ok(["failure", "error", "skipped", "system-out", "system-err"].includes(k.name));
      assert.ok(kids(c, "failure").length + kids(c, "error").length + kids(c, "skipped").length <= 1, "at most one outcome per testcase");
      for (const f of kids(c, "failure")) assert.ok("message" in f.attrs);
    }
    tests += cases.length;
    failures += Number(s.attrs.failures);
    errors += Number(s.attrs.errors);
    skipped += Number(s.attrs.skipped);
  }
  assert.equal(Number(root.attrs.tests), tests);
  assert.equal(Number(root.attrs.failures), failures);
  assert.equal(Number(root.attrs.errors), errors);
  assert.equal(Number(root.attrs.skipped), skipped);
  return root;
}

/** The parts of the SARIF 2.1.0 schema a code-scanning consumer relies on. Not the full JSON Schema: no validator is available offline. */
export function validateSarifShape(text: string) {
  const sarif = JSON.parse(text);
  assert.equal(sarif.version, "2.1.0");
  assert.match(sarif.$schema, /sarif-2\.1\.0/);
  assert.ok(Array.isArray(sarif.runs) && sarif.runs.length >= 1);
  for (const run of sarif.runs) {
    assert.equal(typeof run.tool.driver.name, "string");
    const rules: { id: string }[] = run.tool.driver.rules ?? [];
    assert.equal(new Set(rules.map((r) => r.id)).size, rules.length, "rule ids unique");
    for (const r of rules) assert.equal(typeof r.id, "string");
    for (const res of run.results) {
      assert.ok(typeof res.message.text === "string" && res.message.text.length);
      assert.ok(["none", "note", "warning", "error"].includes(res.level));
      assert.ok(rules.some((r) => r.id === res.ruleId), `result rule ${res.ruleId} is declared`);
      if (res.ruleIndex !== undefined) assert.equal(rules[res.ruleIndex].id, res.ruleId, "ruleIndex points at ruleId");
      for (const l of res.locations ?? []) {
        assert.equal(typeof l.physicalLocation.artifactLocation.uri, "string");
        assert.ok(!/^[A-Za-z]:|\\/.test(l.physicalLocation.artifactLocation.uri), "uri is relative and uses forward slashes");
        assert.ok(l.physicalLocation.region.startLine >= 1);
      }
      for (const v of Object.values(res.partialFingerprints ?? {})) assert.equal(typeof v, "string");
    }
  }
  return sarif;
}

