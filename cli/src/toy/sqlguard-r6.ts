// Toy MCP server for the sql-guard pack. One tool, `query { sql }`, that checks the statement
// and POSTs it to `<--backend>/sql` as JSON `{ "sql": ... }`, returning the backend's reply. The toy's guard is a few regexes: it is
// a fixture, not a model of how to write one (the harness never parses SQL; the toy has to, to be a plausible target).
// Run: node dist/toy/sqlguard-r6.js --backend http://127.0.0.1:<port> [--mode <mode>] [--allow sales.public.]
//   good            statement allowlist (SELECT / WITH ... SELECT only), every FROM/JOIN/comma-join name checked against --allow, row cap 1000
//                   by wrapping, a larger client LIMIT reduced
//   open            no guard at all: forwards everything
//   fail-open       unparseable and unbalanced input is forwarded
//   first-keyword   only the first keyword is checked
//   first-ref       only the first table reference is checked
//   no-rowcap       no wrapping, the client's SQL goes as written
//   passthrough     wraps, but keeps the client's larger LIMIT
//   fetch-first     wraps with an outer FETCH FIRST 1000 ROWS ONLY instead of LIMIT (a near miss: the cap is there)
//   comment-ok      a hostile-looking comment is fine (same as good; named for the matrix)
//   refuse-all      refuses every call
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const MODES = ["good", "open", "fail-open", "first-keyword", "first-ref", "no-rowcap", "passthrough", "fetch-first", "comment-ok", "refuse-all"] as const;
type Mode = (typeof MODES)[number];

const { values } = parseArgs({ options: { mode: { type: "string" }, backend: { type: "string" }, allow: { type: "string" } }, strict: true });
const mode = (values.mode ?? "good") as Mode;
if (!MODES.includes(mode) || !values.backend) {
  process.stderr.write(`toy sqlguard server: --backend <url> is required and --mode must be one of ${MODES.join(", ")}\n`);
  process.exit(2);
}
const backend = values.backend.replace(/\/$/, "");
const allow = (values.allow ?? "sales.public.").split(",");
const CAP = 1000;

const FORBIDDEN = /\b(insert|update|delete|merge|create|drop|alter|truncate|grant|revoke|vacuum|analyze|set|copy|commit|rollback|begin|explain|call|pragma|attach)\b/i;
/** Comments out, so a keyword inside one is not a keyword and a forwarded statement has none. */
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
const unbalanced = (s: string): boolean => (s.match(/'/g) ?? []).length % 2 === 1;
const inScope = (name: string): boolean => {
  const n = name.replace(/"/g, "").toLowerCase();
  return allow.some((a) => (a.endsWith(".") ? n.startsWith(a.toLowerCase()) : n === a.toLowerCase()));
};

/** Table names after FROM and JOIN and in a comma list after FROM; CTE names are the query's own. */
function references(sql: string): string[] {
  const ctes = new Set([...sql.matchAll(/\bwith\s+([a-z_][\w]*)\s+as\b/gi)].map((m) => m[1]!.toLowerCase()));
  const out: string[] = [];
  for (const m of sql.matchAll(/\b(?:from|join)\s+([\w."]+(?:\s*,\s*[\w."]+)*)/gi)) {
    for (const part of m[1]!.split(",")) {
      const name = part.trim();
      if (name && !ctes.has(name.toLowerCase())) out.push(name);
    }
  }
  return out;
}

function refusal(why: string): { content: { type: "text"; text: string }[]; isError: true } {
  return { content: [{ type: "text", text: `Error: ${why}` }], isError: true };
}

/** Returns a reason to refuse, or the SQL to forward. */
function guard(raw: string): { refuse: string } | { sql: string } {
  if (mode === "open") return { sql: raw };
  if (mode === "refuse-all") return { refuse: "this server refuses every statement" };
  const sql = stripComments(raw).trim();
  const body = sql.replace(/;\s*$/, "");
  if (unbalanced(raw)) return mode === "fail-open" ? { sql: raw } : { refuse: "the statement could not be parsed (unbalanced quote)" };
  const first = /^\s*([a-z]+)/i.exec(body)?.[1]?.toLowerCase();
  if (first !== "select" && first !== "with") {
    // fail-open forwards what it cannot recognise; a statement it does recognise as a write is still refused
    return mode === "fail-open" && !FORBIDDEN.test(first ?? "") ? { sql: raw } : { refuse: "only SELECT statements are allowed" };
  }
  if (mode !== "first-keyword") {
    if (body.includes(";")) return { refuse: "only a single statement is allowed" };
    const literalFree = body.replace(/'(?:[^']|'')*'/g, "''");
    if (FORBIDDEN.test(literalFree)) return { refuse: "only read statements are allowed" };
  }
  const refs = references(body.replace(/'(?:[^']|'')*'/g, "''"));
  for (const name of mode === "first-ref" ? refs.slice(0, 1) : refs) {
    if (!inScope(name)) return { refuse: `${name} is not available through this server` };
  }
  return { sql: mode === "comment-ok" || mode === "good" ? body : raw };
}

function wrap(sql: string): string {
  const client = /\blimit\s+(\d+)\s*$/i.exec(sql);
  switch (mode) {
    case "open":
    case "no-rowcap":
      return sql;
    case "passthrough":
      return `SELECT * FROM (${sql}) AS sm LIMIT ${Math.max(CAP, client ? Number(client[1]) : 0)}`;
    case "fetch-first":
      return `SELECT * FROM (${sql}) AS sm FETCH FIRST ${CAP} ROWS ONLY`;
    default:
      return `SELECT * FROM (${client ? sql.replace(/\blimit\s+\d+\s*$/i, `LIMIT ${Math.min(CAP, Number(client[1]))}`) : sql}) AS sm LIMIT ${CAP}`;
  }
}

const server = new Server({ name: `sealmark-toy-sqlguard-${mode}`, version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "query",
      description: "Run one read-only SELECT against the sales data and return the rows.",
      inputSchema: { type: "object" as const, properties: { sql: { type: "string", description: "A single SELECT statement." } }, required: ["sql"] },
      annotations: { readOnlyHint: true },
    },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const sql = (req.params.arguments as { sql?: unknown } | undefined)?.sql;
  if (typeof sql !== "string") return refusal("sql must be a string");
  const g = guard(sql);
  if ("refuse" in g) return refusal(g.refuse);
  try {
    const res = await fetch(`${backend}/sql`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sql: wrap(g.sql) }), signal: AbortSignal.timeout(3000) });
    return { content: [{ type: "text", text: (await res.text()).slice(0, 1_048_576) }] };
  } catch {
    return refusal("the backend could not run the query");
  }
});

for (const ev of ["end", "close"] as const) process.stdin.once(ev, () => process.exit(0));
await server.connect(new StdioServerTransport());
