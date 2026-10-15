import { loadEffectiveConfig, toSealmarkConfig } from "./config/index.js";
import type { SealmarkConfig } from "./types.js";

/**
 * Compatibility surface for code written before the layered configuration (config/). New code should call
 * loadEffectiveConfig({ cwd, flags, env }) from "./config/index.js" and receive an EffectiveConfig.
 */
export { ConfigError } from "./config/model.js";
export { displaySpec, expand, placeholdersUsed, usesPlaceholders, type TemplateCtx } from "./config/placeholders.js";
export type { SealmarkConfig } from "./types.js";

/**
 * Loads one project file the way 0.1 did: that file (plus a sealmark.local.yaml beside it), validated strictly,
 * with no user-level file and no environment layer. Returns the 0.1 view.
 */
export function loadConfig(path: string): SealmarkConfig {
  return toSealmarkConfig(loadEffectiveConfig({ cwd: process.cwd(), flags: { config: path }, env: {}, isolated: true }));
}

/** The command the template ships. It is not a real program: `run` and `doctor` refuse it until it is replaced. */
export const TEMPLATE_COMMAND = "your-mcp-server";

/**
 * The editor hint `init` writes. The path resolves only where `node_modules/sealmark/schema/sealmark.schema.json` exists beside the file,
 * so `init` writes it only then (see schemaLineWanted in config/wizard.ts) and the comment below otherwise. The hosted URL is an owner gate.
 */
export const SCHEMA_MODELINE = "# yaml-language-server: $schema=./node_modules/sealmark/schema/sealmark.schema.json";

/** What `init` writes in place of the modeline when the schema file is not installed: a plain comment, so no editor reports an unresolved reference. */
export const SCHEMA_HINT =
  "# Editor schema: npm i -D sealmark adds ./node_modules/sealmark/schema/sealmark.schema.json; the hosted copy is https://sealmark.dev/schema/v1/sealmark.schema.json after the next site deploy";

export const INIT_TEMPLATE = `${SCHEMA_MODELINE}
# sealmark.yaml  (the hosted schema URL is planned; until then the schema ships in the npm package)
schema_version: 1
name: my-server
version: 1.0.0

# How to start the MCP server under test.
# Placeholders are filled in when the packs run:
#   {dsn} {host} {port} {user} {password} {database}   the database role being tested (db pack)
#   {dsn:analyst} {dsn:support} {dsn:admin}            a specific role
#   {sandbox} {sandbox_home}                           a disposable directory the harness owns (fs, git packs)
#   {sqlite_path} {duckdb_path}                        a seeded embedded database (sqlite pack)
server:
  # REPLACE THIS. "${TEMPLATE_COMMAND}" is a placeholder, not a program: sealmark run and sealmark doctor refuse it until you
  # put the command that starts the MCP server you want to grade here (a server you built, or one you may test).
  command: ${TEMPLATE_COMMAND}
  args: []
  # Examples of the shape (pick the real command and package for your server):
  #   command: npx
  #   args: ["-y", "<package-of-your-mcp-server>", "{dsn}"]      # a database server: {dsn} is the connection string
  #   args: ["<path-to-your-server>", "{sandbox}"]               # a file server: {sandbox} is a disposable directory
  # env:
  #   DATABASE_URL: "{dsn}"
  # url: http://localhost:8000/mcp     # use instead of command for an already-running HTTP server

# Optional. Which tools take SQL. Auto-detected when omitted.
# sql_tools:
#   - { tool: query, arg: sql }

# Optional. Default: the published standard packs. A subset or a custom setting makes the run CUSTOM, not STANDARD.
# packs: [core, db]
# profile: standard      # standard | quick | ci | strict | paranoid | one you define under profiles:
# Show every effective value and where it came from:  sealmark config show --effective --origins
`;

/** The init template, with the `SCHEMA_HINT` comment in place of the `$schema` modeline when the modeline would not resolve. */
export const initTemplate = (schemaLine = true): string => (schemaLine ? INIT_TEMPLATE : `${SCHEMA_HINT}\n${INIT_TEMPLATE.slice(INIT_TEMPLATE.indexOf("\n") + 1)}`);
