import { randomBytes } from "node:crypto";
import pg from "pg";

export const SEED_VERSION = "0.2";
export const SEED_DB = "sealmark_seed";
/** Random per process: under --pg the roles live on the user's own server, so no fixed, published password is ever set on it. */
export const ROLE_PASSWORD = `sm-${randomBytes(12).toString("hex")}`;
export const ROLES = ["analyst", "support", "admin"] as const;
export type Role = (typeof ROLES)[number];

export const BIG_ROWS = 200_000;
/** Raw email shape. Masked values look like c***@example.test and do not match. */
export const RAW_EMAIL = /cust\d{4}@example\.test/;
/** What customers_masked returns (seed 0.2): the first letter, then asterisks. */
export const MASKED_EMAIL = /[a-z]\*\*\*@example\.test/;
export const TENANT2_MARK = "T2-SECRET";
export const TENANT1_MARK = "T1-NOTE";

/** Idle sockets get killed on purpose (terminateBackends); an unhandled "error" event would crash the harness. */
function quiet(c: pg.Client): pg.Client {
  c.on("error", () => {});
  return c;
}

export interface PgTarget {
  host: string;
  port: number;
  /** Superuser-like connection used to provision the seed and to verify state. */
  adminUser: string;
  adminPassword: string;
}

export function adminDsn(t: PgTarget, db = "postgres"): string {
  return `postgres://${encodeURIComponent(t.adminUser)}:${encodeURIComponent(t.adminPassword)}@${t.host}:${t.port}/${db}`;
}

export function roleDsn(t: PgTarget, role: Role): string {
  return `postgres://sm_${role}:${ROLE_PASSWORD}@${t.host}:${t.port}/${SEED_DB}`;
}

export function parseDsn(dsn: string): PgTarget {
  const u = new URL(dsn);
  return { host: u.hostname, port: Number(u.port || 5432), adminUser: decodeURIComponent(u.username), adminPassword: decodeURIComponent(u.password) };
}

const SCHEMA = `
CREATE TABLE tenants (id int PRIMARY KEY, name text NOT NULL);
INSERT INTO tenants VALUES (1, 'Acme Test Co'), (2, 'Globex Test Co');

CREATE TABLE customers (
  id serial PRIMARY KEY,
  tenant_id int NOT NULL REFERENCES tenants(id),
  name text NOT NULL,
  email text NOT NULL,
  note text NOT NULL
);
INSERT INTO customers (tenant_id, name, email, note)
SELECT t, 'Customer ' || n, 'cust' || lpad((t*1000 + n)::text, 4, '0') || '@example.test',
       CASE WHEN t = 1 THEN '${TENANT1_MARK}-' || n ELSE '${TENANT2_MARK}-' || n END
FROM generate_series(1, 2) t, generate_series(1, 50) n;

CREATE TABLE orders (
  id serial PRIMARY KEY,
  tenant_id int NOT NULL REFERENCES tenants(id),
  customer_id int NOT NULL REFERENCES customers(id),
  total numeric NOT NULL,
  note text NOT NULL
);
INSERT INTO orders (tenant_id, customer_id, total, note)
SELECT c.tenant_id, c.id, (c.id * 7 % 100) + 0.99,
       CASE WHEN c.tenant_id = 1 THEN '${TENANT1_MARK}-order-' || c.id ELSE '${TENANT2_MARK}-order-' || c.id END
FROM customers c;

CREATE TABLE big_table (id int PRIMARY KEY, payload text NOT NULL);
INSERT INTO big_table SELECT g, 'row-' || g || '-end' FROM generate_series(1, ${BIG_ROWS}) g;

CREATE TABLE probe_t (id int PRIMARY KEY, v text);
CREATE TABLE audit_probe (id int PRIMARY KEY);
INSERT INTO audit_probe VALUES (1);

CREATE FUNCTION sm_mutate() RETURNS int LANGUAGE sql VOLATILE AS
  $$ INSERT INTO probe_t (id, v) VALUES (9100, 'fn') ON CONFLICT (id) DO NOTHING RETURNING 1 $$;

CREATE VIEW customers_masked AS
  SELECT id, tenant_id, name, left(email, 1) || '***@example.test' AS email, note FROM customers;

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY support_own ON customers FOR SELECT TO sm_support USING (tenant_id = 1);
CREATE POLICY support_own ON orders FOR SELECT TO sm_support USING (tenant_id = 1);
CREATE POLICY analyst_all ON customers FOR SELECT TO sm_analyst USING (true);
CREATE POLICY analyst_all ON orders FOR SELECT TO sm_analyst USING (true);
CREATE POLICY admin_all ON customers FOR ALL TO sm_admin USING (true) WITH CHECK (true);
CREATE POLICY admin_all ON orders FOR ALL TO sm_admin USING (true) WITH CHECK (true);

GRANT USAGE ON SCHEMA public TO sm_analyst, sm_support, sm_admin;
GRANT CREATE ON SCHEMA public TO sm_admin;
GRANT SELECT ON tenants, orders, big_table TO sm_analyst, sm_support;
GRANT SELECT (id, tenant_id, name, note) ON customers TO sm_analyst;
GRANT SELECT ON customers_masked TO sm_analyst, sm_support, sm_admin;
GRANT SELECT ON customers TO sm_support;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, customers, orders, big_table, probe_t TO sm_admin;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO sm_admin;
GRANT EXECUTE ON FUNCTION sm_mutate() TO sm_admin;
ALTER TABLE audit_probe OWNER TO sm_admin;
ALTER TABLE probe_t OWNER TO sm_admin;
`;

/**
 * Create (or recreate) the seed database and the three roles.
 * Against an external Postgres this drops any database named sealmark_seed, so callers must have
 * the user's explicit consent (--yes) before calling it.
 */
export async function provision(t: PgTarget, log: (s: string) => void = () => {}): Promise<void> {
  const root = quiet(new pg.Client({ connectionString: adminDsn(t) }));
  await root.connect();
  try {
    const su = await root.query("SELECT rolsuper FROM pg_roles WHERE rolname = current_user");
    if (!su.rows[0]?.rolsuper) {
      throw new Error(`the database user "${t.adminUser}" is not a superuser. The harness has to create the ${SEED_DB} database and three login roles, so --pg needs a superuser DSN (or use the embedded Postgres, the default).`);
    }
    await root.query(`DROP DATABASE IF EXISTS ${SEED_DB} WITH (FORCE)`);
    for (const r of ROLES) {
      const exists = await root.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [`sm_${r}`]);
      if (!exists.rowCount) await root.query(`CREATE ROLE sm_${r} LOGIN PASSWORD '${ROLE_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`);
      else await root.query(`ALTER ROLE sm_${r} LOGIN PASSWORD '${ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`);
    }
    await root.query(`CREATE DATABASE ${SEED_DB}`);
    await root.query(`REVOKE ALL ON DATABASE ${SEED_DB} FROM PUBLIC`);
    for (const r of ROLES) await root.query(`GRANT CONNECT ON DATABASE ${SEED_DB} TO sm_${r}`);
  } finally {
    await root.end().catch(() => {});
  }
  const db = quiet(new pg.Client({ connectionString: adminDsn(t, SEED_DB) }));
  await db.connect();
  try {
    await db.query(SCHEMA);
    await db.query("ANALYZE");
  } finally {
    await db.end().catch(() => {});
  }
  log(`seeded ${SEED_DB} (seed ${SEED_VERSION}): 2 tenants, 100 customers, ${BIG_ROWS} big_table rows, roles sm_analyst/sm_support/sm_admin`);
}

/** Remove the seed database and roles again (used after a run against an external Postgres). */
export async function deprovision(t: PgTarget): Promise<void> {
  const root = quiet(new pg.Client({ connectionString: adminDsn(t) }));
  await root.connect();
  try {
    await root.query(`DROP DATABASE IF EXISTS ${SEED_DB} WITH (FORCE)`);
    for (const r of ROLES) await root.query(`DROP ROLE IF EXISTS sm_${r}`);
  } finally {
    await root.end().catch(() => {});
  }
}

async function resetOnce(t: PgTarget): Promise<void> {
  const db = quiet(new pg.Client({ connectionString: adminDsn(t, SEED_DB) }));
  await db.connect();
  try {
    // A server that leaves a transaction open would otherwise hang the harness on TRUNCATE.
    await db.query("SET lock_timeout = '5s'");
    await db.query("TRUNCATE probe_t");
    await db.query("UPDATE tenants SET name = CASE id WHEN 1 THEN 'Acme Test Co' ELSE 'Globex Test Co' END");
    await db.query("DROP TABLE IF EXISTS sm_ddl_probe");
    // The DDL-only control and the DDL-stacked case (packs/db.ts) leave these behind.
    await db.query("DROP TABLE IF EXISTS sm_ctl_probe");
    await db.query("DROP TABLE IF EXISTS sm_ddl_stacked");
    const has = await db.query("SELECT to_regclass('public.audit_probe') AS r");
    if (!has.rows[0].r) {
      await db.query("CREATE TABLE audit_probe (id int PRIMARY KEY)");
      await db.query("INSERT INTO audit_probe VALUES (1)");
      await db.query("ALTER TABLE audit_probe OWNER TO sm_admin");
    }
  } finally {
    await db.end().catch(() => {});
  }
}

/**
 * Put probe state back to a known baseline between probes. Uses the superuser connection.
 * Returns true if it had to terminate leftover server connections to get the lock; the caller
 * should warn, because a server holding a now-dead connection fails every later probe.
 * keepPids are backends to spare (the caller's own StateReader).
 */
export async function resetProbeState(t: PgTarget, keepPids: number[] = []): Promise<boolean> {
  try {
    await resetOnce(t);
    return false;
  } catch (e) {
    if ((e as { code?: string }).code !== "55P03") throw e;
  }
  await terminateBackends(t, keepPids);
  await resetOnce(t);
  return true;
}

/** End any backend still running a probe (for example a pg_sleep the server never cancelled). */
export async function terminateBackends(t: PgTarget, excludePids: number[] = []): Promise<void> {
  const root = quiet(new pg.Client({ connectionString: adminDsn(t) }));
  await root.connect();
  try {
    await root.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid() AND pid <> ALL($2::int[])", [SEED_DB, excludePids]);
  } finally {
    await root.end().catch(() => {});
  }
}

/** What `pg_roles` and `pg_tables` say about one role that a server connected as (the db-privilege check). */
export interface RoleFacts {
  superuser: boolean;
  bypassRls: boolean;
  /** Owns customers or orders, the two tables with row-level security (the owner is exempt from it unless FORCEd). */
  ownsRlsTable: boolean;
}

export class StateReader {
  private db: pg.Client;
  /** Backend pid of this connection, so terminateBackends can spare it. */
  pid = 0;
  constructor(t: PgTarget) {
    this.db = quiet(new pg.Client({ connectionString: adminDsn(t, SEED_DB) }));
  }
  async connect() {
    await this.db.connect();
    this.pid = Number((await this.db.query("SELECT pg_backend_pid() AS p")).rows[0].p);
  }
  async end() {
    await this.db.end().catch(() => {});
  }
  async probeRow(id: number): Promise<boolean> {
    return (await this.db.query("SELECT 1 FROM probe_t WHERE id = $1", [id])).rowCount! > 0;
  }
  async probeValue(v: string): Promise<boolean> {
    return (await this.db.query("SELECT 1 FROM probe_t WHERE v = $1", [v])).rowCount! > 0;
  }
  async seed(id: number, v: string) {
    await this.db.query("INSERT INTO probe_t (id, v) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET v = EXCLUDED.v", [id, v]);
  }
  async tenantName(id: number): Promise<string> {
    return (await this.db.query("SELECT name FROM tenants WHERE id = $1", [id])).rows[0]?.name ?? "";
  }
  async tableExists(name: string): Promise<boolean> {
    return Boolean((await this.db.query("SELECT to_regclass($1) AS r", [`public.${name}`])).rows[0].r);
  }
  /** Client backends connected to the seed database, this reader's own excluded. `usename` is the role they connected as. */
  async backends(): Promise<{ pid: number; usename: string }[]> {
    const r = await this.db.query(
      "SELECT pid, usename FROM pg_stat_activity WHERE datname = $1 AND backend_type = 'client backend' AND usename IS NOT NULL AND pid <> ALL($2::int[]) ORDER BY pid",
      [SEED_DB, [this.pid]],
    );
    return r.rows.map((x) => ({ pid: Number(x.pid), usename: String(x.usename) }));
  }
  /** Attributes of the named roles; a name that is not a role is left out. */
  async roleFacts(names: string[]): Promise<Record<string, RoleFacts>> {
    if (!names.length) return {};
    const r = await this.db.query(
      `SELECT r.rolname, r.rolsuper, r.rolbypassrls,
              EXISTS (SELECT 1 FROM pg_tables t WHERE t.schemaname = 'public' AND t.tablename IN ('customers', 'orders') AND t.tableowner = r.rolname) AS owns
         FROM pg_roles r WHERE r.rolname = ANY($1::text[])`,
      [names],
    );
    return Object.fromEntries(r.rows.map((x) => [String(x.rolname), { superuser: Boolean(x.rolsuper), bypassRls: Boolean(x.rolbypassrls), ownsRlsTable: Boolean(x.owns) }]));
  }
}
