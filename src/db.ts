import { Pool } from "pg";
export const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;
export async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenants (api_key TEXT PRIMARY KEY, id TEXT NOT NULL, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'FREE', monthly_quota INT NOT NULL DEFAULT 5000, usage_count INT NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit_logs (hash TEXT PRIMARY KEY, prev_hash TEXT NOT NULL, timestamp TIMESTAMPTZ NOT NULL, trace_id TEXT NOT NULL, agent_id TEXT NOT NULL, tool_name TEXT NOT NULL, decision TEXT NOT NULL, matched_rule_id TEXT, reason TEXT, latency_ms REAL NOT NULL, sanitized_arguments JSONB NOT NULL);
  `);
}
