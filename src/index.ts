import Fastify from "fastify";
import fs from "node:fs";
import path from "node:path";
import { evaluatePolicy, PolicyRule, ToolCallRequest } from "./engine";
import { recordAudit, getAuditLogs } from "./audit";
import { authenticateTenant, createTenant, listTenants } from "./tenants";

const app = Fastify({ logger: true });

app.addHook("onRequest", async (req, reply) => {
  const protectedPaths = ["/dashboard", "/v1/audit", "/v1/policies"];
  const isAdminGetTenants = req.url === "/v1/tenants" && req.method === "GET";
  if (protectedPaths.some(p => req.url.startsWith(p)) || isAdminGetTenants) {
    const adminPass = process.env.ADMIN_PASSWORD || "admin123";
    const auth = req.headers.authorization || "";
    const expected = "Basic " + Buffer.from("admin:" + adminPass).toString("base64");
    if (auth !== expected) {
      reply.header("WWW-Authenticate", "Basic realm=\"Admin Control Plane\"");
      return reply.status(401).send({ error: "Admin authentication required" });
    }
  }
});

let activePolicies: PolicyRule[] = [
  { id: "block-destructive-db", toolPattern: "db_drop_*", action: "BLOCK", enabled: true, reason: "Destructive DB operations prohibited." },
  { id: "cap-stripe-refunds", toolPattern: "stripe_refund", action: "BLOCK", enabled: true, conditions: [{ param: "amount", operator: "gt", value: 500 }], reason: "Refunds over $500 require approval." },
  { id: "redact-pii", toolPattern: "*", action: "REDACT", enabled: true, redactFields: ["ssn", "credit_card", "password", "api_key"], reason: "PII stripped before tool execution." }
];

app.post("/mock-tool", async (req) => ({ executed: true, receivedPayload: req.body }));
app.get("/v1/audit", async () => ({ logs: getAuditLogs() }));
app.get("/v1/policies", async () => ({ policies: activePolicies }));
app.get("/v1/tenants", async () => ({ tenants: listTenants() }));
app.post<{ Body: { name: string; plan?: string } }>("/v1/tenants", async (req) => ({ ok: true, tenant: createTenant(req.body.name || "Workspace", req.body.plan || "PRO") }));
app.post<{ Body: PolicyRule }>("/v1/policies", async (req) => { activePolicies.unshift({ ...req.body, enabled: true }); return { ok: true, policies: activePolicies }; });

app.post<{ Body: ToolCallRequest & { targetUrl?: string } }>("/v1/proxy/execute", async (request, reply) => {
  const tenant = authenticateTenant(request.headers["x-api-key"] as string | undefined);
  if (!tenant) return reply.status(401).send({ error: "Invalid x-api-key" });
  tenant.usageCount++;
  const start = performance.now();
  const { traceId = crypto.randomUUID(), agentId = tenant.id, toolName, arguments: args = {}, targetUrl = "http://localhost:8080/mock-tool" } = request.body;
  const result = evaluatePolicy({ traceId, agentId, toolName, arguments: args }, activePolicies);
  const latencyMs = Math.round((performance.now() - start) * 100) / 100;
  const audit = recordAudit({ traceId, agentId, toolName, decision: result.decision, matchedRuleId: result.matchedRuleId, reason: result.reason, latencyMs, sanitizedArguments: result.sanitizedArguments });
  if (result.decision === "BLOCK") return reply.status(403).send({ status: "BLOCKED", traceId, auditHash: audit.hash, ruleId: result.matchedRuleId, latencyMs, error: result.reason });
  const up = await fetch(targetUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ toolName, arguments: result.sanitizedArguments }) });
  return reply.send({ status: result.decision, traceId, auditHash: audit.hash, latencyMs, data: await up.json() });
});

app.post<{ Body: any }>("/v1/mcp", async (request, reply) => {
  const tenant = authenticateTenant(request.headers["x-api-key"] as string | undefined);
  if (!tenant) return reply.status(401).send({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" } });
  const { jsonrpc = "2.0", id = 1, method, params = {} } = request.body || {};
  if (method === "tools/call") {
    tenant.usageCount++;
    const start = performance.now();
    const toolName = params.name || "mcp_tool", args = params.arguments || {}, traceId = crypto.randomUUID();
    const result = evaluatePolicy({ traceId, agentId: "mcp:" + tenant.id, toolName, arguments: args }, activePolicies);
    const latencyMs = Math.round((performance.now() - start) * 100) / 100;
    const audit = recordAudit({ traceId, agentId: "mcp:" + tenant.id, toolName, decision: result.decision, matchedRuleId: result.matchedRuleId, reason: result.reason, latencyMs, sanitizedArguments: result.sanitizedArguments });
    if (result.decision === "BLOCK") return reply.send({ jsonrpc, id, result: { isError: true, content: [{ type: "text", text: "[BLOCKED] " + result.reason }] } });
    return reply.send({ jsonrpc, id, result: { content: [{ type: "text", text: JSON.stringify({ executed: true, tool: toolName, sanitizedArgs: result.sanitizedArguments, auditHash: audit.hash }) }] } });
  }
  return reply.send({ jsonrpc, id, result: { protocolVersion: "2025-03-26", serverInfo: { name: "agent-guardrail-mcp", version: "0.2.0" } } });
});

app.get("/", async (_, reply) => reply.type("text/html").send(fs.readFileSync(path.join(process.cwd(), "public", "index.html"), "utf-8")));
app.get("/dashboard", async (_, reply) => reply.type("text/html").send(fs.readFileSync(path.join(process.cwd(), "public", "dashboard.html"), "utf-8")));
app.listen({ port: 8080, host: "0.0.0.0" }, (err) => { if (err) process.exit(1); });
