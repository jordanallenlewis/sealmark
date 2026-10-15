// The published corpus of the `sql-guard` pack and the two pure text helpers the pack reads the
// wire with. No SQL parser lives here or anywhere in the pack: a statement is judged by whether its token reached the upstream stub.
//
// Placeholders in a `sql` template:
//   {token}  a fresh hex token per probe. Every template carries it twice, as the identifier `sm_{token}` and as the literal
//            `'sm-{token}'` (or inside a comment where the statement has no natural place for a literal), so a forwarded copy is
//            found whichever spelling the server's rewriting kept.
//   {table}  the first exact `scope.allow` entry when one is declared, else a made-up name under the first prefix entry, else
//            `sm_{token}` (so the only reason to refuse a write is that it is a write, not that its table is out of scope).
//   {a}, {o} references only: an in-scope name and an out-of-scope name (`<container>.outside_sm_{token}`).

export interface CorpusEntry {
  id: string;
  sql: string;
  /** A near miss: reaching the upstream is allowed (it is valid SQL that only looks hostile), so it never counts as a leak. */
  nearMiss?: boolean;
}

/** Statements no read-only guard may forward. Order is the published order. */
export const STATEMENT_CORPUS: readonly CorpusEntry[] = [
  { id: "insert", sql: "INSERT INTO {table} (sm_{token}) VALUES ('sm-{token}')" },
  { id: "update", sql: "UPDATE {table} SET sm_{token} = 'sm-{token}' WHERE 1 = 0" },
  { id: "delete", sql: "DELETE FROM {table} WHERE sm_{token} = 'sm-{token}'" },
  { id: "merge", sql: "MERGE INTO {table} AS sm_{token} USING (SELECT 'sm-{token}' AS v) AS s ON 1 = 0 WHEN NOT MATCHED THEN INSERT (v) VALUES ('sm-{token}')" },
  { id: "create", sql: "CREATE TABLE sm_{token} (v text DEFAULT 'sm-{token}')" },
  { id: "drop", sql: "DROP TABLE IF EXISTS sm_{token} /* sm-{token} */" },
  { id: "alter", sql: "ALTER TABLE {table} ADD COLUMN sm_{token} text DEFAULT 'sm-{token}'" },
  { id: "truncate", sql: "TRUNCATE TABLE {table} /* sm_{token} sm-{token} */" },
  { id: "grant", sql: "GRANT SELECT ON {table} TO sm_{token} /* sm-{token} */" },
  { id: "vacuum", sql: "VACUUM {table} /* sm_{token} sm-{token} */" },
  { id: "analyze", sql: "ANALYZE {table} /* sm_{token} sm-{token} */" },
  { id: "set-session", sql: "SET SESSION sm_{token} = 'sm-{token}'; SELECT 1" },
  { id: "copy", sql: "COPY {table} (sm_{token}) TO '/tmp/sm-{token}'" },
  { id: "stacked", sql: "SELECT 'sm-{token}'; DROP TABLE sm_{token}" },
  { id: "cte-dml", sql: "WITH d AS (DELETE FROM {table} WHERE sm_{token} = 'sm-{token}' RETURNING *) SELECT * FROM d" },
  { id: "explain-analyze-write", sql: "EXPLAIN ANALYZE INSERT INTO {table} (sm_{token}) VALUES ('sm-{token}')" },
  { id: "obfuscated", sql: "/*x*/ iNsErT INTO {table} (sm_{token}) VALUES ('sm-{token}')" },
  { id: "terminator", sql: "COMMIT; INSERT INTO {table} (sm_{token}) VALUES ('sm-{token}')" },
  { id: "unparseable", sql: "SELEC T 1 sm_{token} 'sm-{token}'" },
  { id: "unbalanced", sql: "SELECT 1 AS sm_{token}, 'sm-{token}" },
  { id: "comment-hidden", sql: "SELECT 1 AS sm_{token} -- ; DROP TABLE sm_{token} 'sm-{token}'", nearMiss: true },
];

/** Ways to name something out of scope inside an otherwise valid SELECT. Placeholders `{a}` (in scope) and `{o}` (out of scope). */
export const REFERENCE_CORPUS: readonly CorpusEntry[] = [
  { id: "from", sql: "SELECT * FROM {o} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "join", sql: "SELECT * FROM {a} JOIN {o} ON 1 = 1 WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "comma-join", sql: "SELECT * FROM {a}, {o} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "subquery-from", sql: "SELECT * FROM (SELECT * FROM {o}) AS t WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "subquery-where", sql: "SELECT * FROM {a} WHERE x IN (SELECT x FROM {o}) AND 'sm-{token}' = 'sm-{token}'" },
  { id: "scalar-subquery", sql: "SELECT (SELECT max(x) FROM {o}) AS sm_{token} FROM {a} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "exists", sql: "SELECT * FROM {a} WHERE EXISTS (SELECT 1 FROM {o}) AND 'sm-{token}' = 'sm-{token}'" },
  { id: "cte", sql: "WITH c AS (SELECT * FROM {o}) SELECT * FROM c WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "union", sql: "SELECT * FROM {a} UNION SELECT * FROM {o} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "quoted", sql: "SELECT * FROM {o:quoted} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "cased", sql: "SELECT * FROM {o:upper} WHERE 'sm-{token}' = 'sm-{token}'" },
  { id: "alias-hidden", sql: "SELECT * FROM {o} AS {a:last} WHERE 'sm-{token}' = 'sm-{token}'" },
];

/** The huge client LIMIT the row-cap probe appends to the control statement. */
export const HUGE_LIMIT = 1_000_000;
export const DEFAULT_ROW_CAP = 10_000;

export const CONTROL_DEFAULT = "SELECT 1 AS sm_{token}";
export const CONTROL_SCOPED = "SELECT * FROM {table} WHERE 'sm-{token}' = 'sm-{token}'";

// ---------------------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------------------

export interface Names {
  /** In-scope identifier (or a made-up name under a prefix entry). */
  inScope: string;
  /** Out-of-scope identifier, ending in `outside_sm_<token>`. */
  outOfScope: string;
  /** What `{table}` stands for in the statement corpus. */
  table: string;
  separator: string;
}

const lastSegment = (name: string, sep: string): string => name.split(sep).pop() ?? name;
const quoteAll = (name: string, sep: string): string => name.split(sep).map((s) => `"${s}"`).join(sep);

/** Fill a template: `{token}`, `{table}`, `{a}`, `{o}` and the `:quoted`, `:upper`, `:last` forms. Unknown braces are left alone. */
export function render(template: string, token: string, names: Names): string {
  return template
    .replaceAll("{o:quoted}", quoteAll(names.outOfScope, names.separator))
    .replaceAll("{o:upper}", names.outOfScope.toUpperCase())
    .replaceAll("{a:last}", lastSegment(names.inScope, names.separator))
    .replaceAll("{o}", names.outOfScope)
    .replaceAll("{a}", names.inScope)
    .replaceAll("{table}", names.table)
    .replaceAll("{token}", token);
}

/** Is `name` covered by an `allow` list (an entry ending in the separator is a prefix, any other is exact; case-insensitive)? */
export function covered(name: string, allow: readonly string[], separator: string): boolean {
  const n = name.toLowerCase();
  return allow.some((a) => (a.endsWith(separator) ? n.startsWith(a.toLowerCase()) : n === a.toLowerCase()));
}

/**
 * Names for a probe. `allow` entries ending in the separator are prefixes. The out-of-scope name sits in the nearest container
 * of the first entry that no entry covers (`sales.public.orders` gives `sales.public.outside_sm_<tok>`; the prefix `sales.public.`
 * gives `sales.outside_sm_<tok>`, since a name under the prefix is in scope), which is where a server's guard has to tell names apart.
 */
export function namesFor(allow: readonly string[], separator: string, token: string): Names {
  const exact = allow.find((a) => !a.endsWith(separator));
  const first = allow[0];
  const prefix = allow.find((a) => a.endsWith(separator));
  const outside = `outside_sm_${token}`;
  let outOfScope = outside;
  if (first !== undefined) {
    const segments = (first.endsWith(separator) ? first.slice(0, -separator.length) : first).split(separator);
    // an exact entry: its container is everything but the last segment; a prefix: the prefix itself is the container, which it covers
    for (let keep = first.endsWith(separator) ? segments.length : segments.length - 1; keep >= 0; keep--) {
      const candidate = [...segments.slice(0, keep), outside].join(separator);
      if (!covered(candidate, allow, separator)) {
        outOfScope = candidate;
        break;
      }
    }
  }
  return {
    inScope: exact ?? (prefix !== undefined ? `${prefix}sm_ctl_${token}` : `sm_ctl_${token}`),
    outOfScope,
    table: exact ?? (prefix !== undefined ? `${prefix}sm_${token}` : `sm_${token}`),
    separator,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Reading the wire
// ---------------------------------------------------------------------------------------------------------

/**
 * The SQL text the upstream received: every string value of a JSON body that holds `needle` (so a client LIMIT inside the
 * statement is seen and the JSON escaping is not), else the raw path, query and body, URL-decoded when that works.
 */
export function forwardedSql(req: { path: string; query: string; body: string }, needle: string): string {
  const n = needle.toLowerCase();
  try {
    const found: string[] = [];
    const walk = (v: unknown): void => {
      if (typeof v === "string") {
        if (v.toLowerCase().includes(n)) found.push(v);
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (v !== null && typeof v === "object") Object.values(v).forEach(walk);
    };
    walk(JSON.parse(req.body));
    if (found.length) return found.join("\n");
  } catch {
    // not JSON: fall through to the raw text
  }
  const raw = `${req.path}${req.query}\n${req.body}`;
  try {
    const decoded = decodeURIComponent(raw.replace(/\+/g, " "));
    return decoded.toLowerCase().includes(n) ? decoded : raw;
  } catch {
    return raw;
  }
}

/** Comments removed and string literals emptied, so a number inside either never counts as a limit. */
function blank(sql: string): string {
  let out = "";
  for (let i = 0; i < sql.length; ) {
    const c = sql[i]!;
    if (c === "-" && sql[i + 1] === "-") {
      while (i < sql.length && sql[i] !== "\n") i++;
    } else if (c === "/" && sql[i + 1] === "*") {
      const end = sql.indexOf("*/", i + 2);
      i = end < 0 ? sql.length : end + 2;
      out += " ";
    } else if (c === "'") {
      i++;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") i += 2;
        else if (sql[i] === "'") {
          i++;
          break;
        } else i++;
      }
      out += "''";
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * The row limit a forwarded statement carries, read with a heuristic and no parser: `LIMIT n` (also MySQL `LIMIT off, n`),
 * `FETCH FIRST|NEXT n ROWS ONLY` and `TOP n`. Where the statement nests (a wrapper around the client's query), the limits of the
 * outermost level that has one count and the smallest of them wins. `null` when no limit of any kind is written.
 */
export function effectiveLimit(sql: string): number | null {
  const text = blank(sql);
  const depth: number[] = new Array(text.length);
  let d = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ")") d = Math.max(0, d - 1);
    depth[i] = d;
    if (text[i] === "(") d++;
  }
  const hits: { depth: number; n: number }[] = [];
  const take = (re: RegExp, group: (m: RegExpExecArray) => string | undefined): void => {
    for (const m of text.matchAll(re)) {
      const g = group(m as RegExpExecArray);
      if (g !== undefined) hits.push({ depth: depth[m.index ?? 0] ?? 0, n: Number(g) });
    }
  };
  take(/\blimit\s+(\d+)(?:\s*,\s*(\d+))?/gi, (m) => m[2] ?? m[1]);
  take(/\bfetch\s+(?:first|next)\s+(\d+)\s+rows?\s+only\b/gi, (m) => m[1]);
  take(/\btop\s+(\d+)\b/gi, (m) => m[1]);
  if (!hits.length) return null;
  const outer = Math.min(...hits.map((h) => h.depth));
  return Math.min(...hits.filter((h) => h.depth === outer).map((h) => h.n));
}
