import crypto from "node:crypto";
import { pool } from "./db";
export interface AuditEntry { timestamp: string; traceId: string; agentId: string; toolName: string; decision: string; matchedRuleId?: string; reason?: string; latencyMs: number; sanitizedArguments: Record<string, any>; prevHash: string; hash: string; }
let lastHash = "0".repeat(64);
const memoryLogs: AuditEntry[] = [];
export async function loadAuditFromDb() {
  if (!pool) return;
  const { rows } = await pool.query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200");
  for (const r of rows.reverse()) {
    const e: AuditEntry = { timestamp: r.timestamp.toISOString(), traceId: r.trace_id, agentId: r.agent_id, toolName: r.tool_name, decision: r.decision, matchedRuleId: r.matched_rule_id, reason: r.reason, latencyMs: r.latency_ms, sanitizedArguments: r.sanitized_arguments, prevHash: r.prev_hash, hash: r.hash };
    memoryLogs.unshift(e); lastHash = e.hash;
  }
}
export function recordAudit(entry: Omit<AuditEntry, "timestamp" | "prevHash" | "hash">): AuditEntry {
  const timestamp = new Date().toISOString();
  const hash = crypto.createHash("sha256").update(JSON.stringify({ timestamp, ...entry, prevHash: lastHash })).digest("hex");
  const full: AuditEntry = { timestamp, ...entry, prevHash: lastHash, hash };
  lastHash = hash; memoryLogs.unshift(full); if (memoryLogs.length > 200) memoryLogs.pop();
  if (pool) pool.query("INSERT INTO audit_logs(hash,prev_hash,timestamp,trace_id,agent_id,tool_name,decision,matched_rule_id,reason,latency_ms,sanitized_arguments) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", [hash, full.prevHash, timestamp, full.traceId, full.agentId, full.toolName, full.decision, full.matchedRuleId || null, full.reason || null, full.latencyMs, JSON.stringify(full.sanitizedArguments)]).catch(console.error);
  return full;
}
export function getAuditLogs() { return memoryLogs; }
