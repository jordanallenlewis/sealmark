import { CLOSING_LINE, headerBlock, orderedPackIds, sortChecks, standardLabel, summaryLine } from "./common.js";
import { MAX_REPORT_FIELD, inertDeep } from "./sanitize.js";
import type { RunResult } from "../types.js";

/**
 * A small Handlebars-style template engine for `output.template` (packs-design 6.7). No dependency, no code execution:
 *
 *   {{path.to.value}}           value (objects print as JSON; missing prints nothing)
 *   {{json path}}               the value as indented JSON
 *   {{#each list}} ... {{/each}}   {{this}}, {{@index}}, {{@key}}, {{@first}}, {{@last}} inside
 *   {{#if path}} ... {{else}} ... {{/if}}      {{#unless path}} ... {{/unless}}
 *   {{! a comment }}
 *
 * A name that is not found in the current block is looked up in the enclosing blocks, so `{{id}}` inside a check loop
 * can still reach `{{server.name}}`. Templates only read the result; they cannot change it, and the renderer adds the
 * STANDARD/CUSTOM header (and the closing sentence) around whatever a template produced.
 */

type Node =
  | { t: "text"; v: string }
  | { t: "var"; path: string; json: boolean }
  | { t: "each" | "if" | "unless"; path: string; body: Node[]; other: Node[] };

interface Tok {
  kind: "text" | "tag";
  v: string;
}

function tokenize(src: string): Tok[] {
  const toks: Tok[] = [];
  const re = /\{\{\{?([\s\S]*?)\}?\}\}/g;
  let last = 0;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    if (m.index > last) toks.push({ kind: "text", v: src.slice(last, m.index) });
    toks.push({ kind: "tag", v: m[1].trim() });
    last = m.index + m[0].length;
  }
  if (last < src.length) toks.push({ kind: "text", v: src.slice(last) });
  return toks;
}

export class TemplateError extends Error {}

function parse(src: string): Node[] {
  const root: Node[] = [];
  const stack: { node?: Extract<Node, { body: Node[] }>; list: Node[]; name?: string }[] = [{ list: root }];
  const top = () => stack[stack.length - 1];
  for (const tok of tokenize(src)) {
    if (tok.kind === "text") {
      top().list.push({ t: "text", v: tok.v });
      continue;
    }
    const v = tok.v;
    if (v.startsWith("!")) continue;
    const open = /^#(each|if|unless)\s+(\S+)$/.exec(v);
    if (open) {
      const node = { t: open[1] as "each" | "if" | "unless", path: open[2], body: [] as Node[], other: [] as Node[] };
      top().list.push(node);
      stack.push({ node, list: node.body, name: open[1] });
      continue;
    }
    if (v === "else") {
      const f = top();
      if (!f.node || f.name === "each") throw new TemplateError("{{else}} is only allowed inside {{#if}} or {{#unless}}");
      f.list = f.node.other;
      continue;
    }
    const close = /^\/(each|if|unless)$/.exec(v);
    if (close) {
      if (stack.length === 1 || top().name !== close[1]) throw new TemplateError(`unexpected {{/${close[1]}}}`);
      stack.pop();
      continue;
    }
    if (v.startsWith("#")) throw new TemplateError(`unknown block {{${v}}} (supported: #each, #if, #unless)`);
    const json = /^json\s+(\S+)$/.exec(v);
    top().list.push({ t: "var", path: json ? json[1] : v, json: Boolean(json) });
  }
  if (stack.length > 1) throw new TemplateError(`{{#${stack[stack.length - 1].name}}} is never closed`);
  return root;
}

interface Frame {
  value: unknown;
  vars: Record<string, unknown>;
}

function lookup(path: string, frames: Frame[]): unknown {
  if (path === "this" || path === ".") return frames[frames.length - 1].value;
  if (path.startsWith("@")) return frames[frames.length - 1].vars[path.slice(1)];
  const segs = path.split(".");
  for (let i = frames.length - 1; i >= 0; i--) {
    let cur: unknown = frames[i].value;
    let found = true;
    for (const s of segs) {
      if (cur !== null && typeof cur === "object" && (Object.hasOwn(cur as object, s) || (s === "length" && Array.isArray(cur)))) cur = (cur as Record<string, unknown>)[s];
      else {
        found = false;
        break;
      }
    }
    if (found) return cur;
  }
  return undefined;
}

const truthy = (v: unknown): boolean => {
  if (Array.isArray(v)) return v.length > 0;
  if (v && typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
};

const show = (v: unknown): string => {
  if (v === undefined || v === null) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
};

function run(nodes: Node[], frames: Frame[], out: string[], depth: number): void {
  if (depth > 20) throw new TemplateError("template blocks are nested too deeply");
  for (const n of nodes) {
    if (n.t === "text") out.push(n.v);
    else if (n.t === "var") {
      const v = lookup(n.path, frames);
      out.push(n.json ? JSON.stringify(v, null, 2) ?? "" : show(v));
    } else if (n.t === "each") {
      const v = lookup(n.path, frames);
      const entries: [string, unknown][] = Array.isArray(v) ? v.map((x, i) => [String(i), x]) : v && typeof v === "object" ? Object.entries(v) : [];
      entries.forEach(([k, x], i) => run(n.body, [...frames, { value: x, vars: { index: i, key: k, first: i === 0, last: i === entries.length - 1 } }], out, depth + 1));
    } else {
      const yes = truthy(lookup(n.path, frames));
      run(n.t === "if" ? (yes ? n.body : n.other) : yes ? n.other : n.body, frames, out, depth + 1);
    }
  }
}

export function renderTemplate(template: string, context: unknown): string {
  const out: string[] = [];
  run(parse(template), [{ value: context, vars: {} }], out, 0);
  return out.join("");
}

/** Everything a template can read: the RunResult plus derived, read-only helpers. */
export function templateContext(r: RunResult): Record<string, unknown> {
  return {
    ...r,
    header: headerBlock(r).join("\n"),
    standardLabel: standardLabel(r) ?? "",
    summary: summaryLine(r),
    packList: orderedPackIds(r).map((id) => ({ id, ...r.packs[id], checks: sortChecks(r.checks.filter((c) => c.pack === id)) })),
  };
}

/** Renders `template` over `run` and wraps the result in the integrity header and the closing sentence. */
export function applyTemplate(template: string, input: RunResult, _kind: "text" | "markdown"): string {
  // The template is the user's, but every value it can print is the server's: inert, so a template cannot bring raw text back.
  const run = inertDeep(input, MAX_REPORT_FIELD);
  const body = renderTemplate(template, templateContext(run)).replace(/\s+$/, "");
  return `${headerBlock(run).join("\n")}\n\n${body}\n\n${body.includes(CLOSING_LINE) ? "" : `${CLOSING_LINE}\n`}`;
}
