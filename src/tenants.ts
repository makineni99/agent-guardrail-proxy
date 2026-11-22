import crypto from "node:crypto";
import { pool } from "./db";
export interface Tenant { id: string; name: string; apiKey: string; plan: string; monthlyQuota: number; usageCount: number; }
const tenants = new Map<string, Tenant>();
const demo: Tenant = { id: "ws_demo_01", name: "Acme AI Engineering", apiKey: "agp_live_demo_987654321", plan: "PRO", monthlyQuota: 100000, usageCount: 0 };
tenants.set(demo.apiKey, demo);
export async function loadTenantsFromDb() {
  if (!pool) return;
  const { rows } = await pool.query("SELECT * FROM tenants");
  for (const r of rows) tenants.set(r.api_key, { id: r.id, name: r.name, apiKey: r.api_key, plan: r.plan, monthlyQuota: r.monthly_quota, usageCount: r.usage_count });
}
export function createTenant(name: string, plan = "PRO"): Tenant {
  const apiKey = "agp_live_" + crypto.randomBytes(12).toString("hex");
  const quota = plan === "BUSINESS" ? 1000000 : plan === "PRO" ? 100000 : 5000;
  const t = { id: "ws_" + crypto.randomBytes(3).toString("hex"), name, apiKey, plan, monthlyQuota: quota, usageCount: 0 };
  tenants.set(apiKey, t);
  if (pool) pool.query("INSERT INTO tenants(api_key,id,name,plan,monthly_quota,usage_count) VALUES($1,$2,$3,$4,$5,0)", [apiKey, t.id, name, plan, quota]).catch(console.error);
  return t;
}
export function authenticateTenant(k?: string) {
  const t = !k ? demo : tenants.get(k);
  if (t && pool) pool.query("UPDATE tenants SET usage_count=$1 WHERE api_key=$2", [t.usageCount + 1, t.apiKey]).catch(console.error);
  return t || null;
}
export function listTenants() { return Array.from(tenants.values()); }
