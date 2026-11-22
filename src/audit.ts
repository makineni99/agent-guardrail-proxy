import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface AuditEntry {
  timestamp: string;
  traceId: string;
  agentId: string;
  toolName: string;
  decision: string;
  matchedRuleId?: string;
  reason?: string;
  latencyMs: number;
  sanitizedArguments: Record<string, any>;
  prevHash: string;
  hash: string;
}

const LOG_FILE = path.join(process.cwd(), "audit-log.jsonl");
let lastHash = "0".repeat(64);
const memoryLogs: AuditEntry[] = [];

if (fs.existsSync(LOG_FILE)) {
  const lines = fs.readFileSync(LOG_FILE, "utf-8").trim().split("\n").filter(Boolean);
  for (const line of lines) {
    try {
      const parsed: AuditEntry = JSON.parse(line);
      memoryLogs.push(parsed);
      lastHash = parsed.hash;
    } catch {}
  }
}

export function recordAudit(entry: Omit<AuditEntry, "timestamp" | "prevHash" | "hash">): AuditEntry {
  const timestamp = new Date().toISOString();
  const payload = JSON.stringify({ timestamp, ...entry, prevHash: lastHash });
  const hash = crypto.createHash("sha256").update(payload).digest("hex");
  const fullEntry: AuditEntry = { timestamp, ...entry, prevHash: lastHash, hash };
  lastHash = hash;
  memoryLogs.unshift(fullEntry);
  if (memoryLogs.length > 200) memoryLogs.pop();
  fs.appendFileSync(LOG_FILE, JSON.stringify(fullEntry) + "\n");
  return fullEntry;
}

export function getAuditLogs(): AuditEntry[] {
  return memoryLogs;
}