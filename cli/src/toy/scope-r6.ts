// Toy stdio MCP server for the round 6 `scope` pack. One tool that takes a table identifier, describe_table{table},
// and a scope rule over it. Every call the guard lets through is appended to --trace as {tool, args}, so a test can assert which corpus
// identifiers "got through" without an upstream stub. Each mode has one flaw, or is a near miss that must still pass.
// Run: node dist/toy/scope-r6.js --mode <m> [--allow <entry>]... [--deny <entry>]... [--trace <file>]
//   --allow defaults to sales.public.orders (an entry that ends with "." is a prefix; pass --allow sales.public. for a prefix scope); --deny defaults to hr.private.salaries.
// Not part of the product surface. Expected verdicts of scope-escape:
//   good           identifier must be a plain name matching an allow entry (exact, or by prefix) and no deny entry; case-insensitive. Expected: pass.
//   strict-case    the same, but case-sensitive: SALES.PUBLIC.ORDERS is refused. Expected: pass, with the case-control note (never a fail).
//   prefix-loose   a prefix entry is compared without its separator (sales.publicx.t passes). Expected: fail through prefix-abuse.
//   container      a bare container of an allowed name (sales.public, sales) is accepted. Expected: fail through container.
//   partial        a name that is the start of an allowed name (sales.public.ord) is accepted. Expected: fail through partial.
//   encoded        %2E, / and quotes are normalised to the plain name before the check. Expected: fail through separator-encoded or quoted.
//   refuse-all     every call is refused ("forbidden"). Expected: every control fails; inconclusive, never pass.
//   deadend        the good rule, but every refusal says only "forbidden". Expected: scope-escape pass; refusal-quality (core advisory) fails.
import { appendFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

export const SCOPE_R6_MODES = ["good", "strict-case", "prefix-loose", "container", "partial", "encoded", "refuse-all", "deadend"] as const;
type Mode = (typeof SCOPE_R6_MODES)[number];

const { values } = parseArgs({ options: { mode: { type: "string" }, allow: { type: "string", multiple: true }, deny: { type: "string", multiple: true }, trace: { type: "string" } }, strict: true });
const mode = values.mode as Mode;
if (!SCOPE_R6_MODES.includes(mode)) {
  process.stderr.write(`toy scope-r6: --mode must be one of ${SCOPE_R6_MODES.join(", ")}\n`);
  process.exit(2);
}
const ALLOW = values.allow?.length ? values.allow : ["sales.public.orders"];
const DENY = values.deny?.length ? values.deny : ["hr.private.salaries"];
const SEP = ".";
const trace = values.trace;

const fold = (s: string): string => (mode === "strict-case" ? s : s.toLowerCase());
const isPrefix = (e: string): boolean => e.endsWith(SEP);

/** The mode's scope rule: true when the identifier may be served. */
function allowed(raw: string): boolean {
  if (mode === "refuse-all") return false;
  let id = raw;
  if (mode === "encoded") id = id.replace(/%2E/gi, ".").replace(/\//g, ".").replace(/"/g, "");
  else if (/["'`\s%]|\.\./.test(id) || id.includes("/") || id.includes("\\")) return false;
  const f = fold(id);
  if (DENY.some((d) => (isPrefix(d) ? f.startsWith(fold(d)) : f === fold(d)))) return false;
  for (const a of ALLOW) {
    const e = fold(a);
    if (isPrefix(a)) {
      if (mode === "prefix-loose" ? f.startsWith(e.slice(0, -SEP.length)) : f.startsWith(e)) return true;
    } else if (f === e) return true;
    if (mode === "container" && e.startsWith(`${f}${SEP}`)) return true;
    if (mode === "partial" && f.length >= 3 && e.startsWith(f)) return true;
  }
  return false;
}

const refusal = (id: string): string =>
  mode === "deadend" || mode === "refuse-all" ? "forbidden" : `${id} is not available through this server. Available tables: sales.public.orders (call list_tables for the rest). Retrying with the same name will not help.`;

const tools = [
  {
    name: "describe_table",
    description: "Describes the columns of one table. The table must be one of the allowed tables (see list_tables).",
    inputSchema: { type: "object" as const, properties: { table: { type: "string", description: "Fully qualified table name, for example sales.public.orders" } }, required: ["table"] },
  },
];

const server = new Server({ name: `sealmark-toy-scope-r6-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, unknown>;
  if (req.params.name !== "describe_table" || typeof a.table !== "string") return { content: [{ type: "text" as const, text: "table must be a string" }], isError: true };
  if (!allowed(a.table)) return { content: [{ type: "text" as const, text: refusal(a.table) }], isError: true };
  if (trace) appendFileSync(trace, `${JSON.stringify({ tool: req.params.name, args: a })}\n`);
  return { content: [{ type: "text" as const, text: `columns of ${a.table}: id, name, created_at` }] };
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
