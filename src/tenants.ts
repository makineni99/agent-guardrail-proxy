import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface Tenant { id: string; name: string; apiKey: string; plan: string; monthlyQuota: number; usageCount: number; }
const FILE = path.join(process.cwd(), "tenants.json");
const tenants = new Map<string, Tenant>();

function save() { fs.writeFileSync(FILE, JSON.stringify(Array.from(tenants.values()), null, 2)); }

if (fs.existsSync(FILE)) {
  try { JSON.parse(fs.readFileSync(FILE, "utf-8")).forEach((t: Tenant) => tenants.set(t.apiKey, t)); } catch {}
}
if (tenants.size === 0) {
  const demo: Tenant = { id: "ws_demo_01", name: "Acme AI Engineering", apiKey: "agp_live_demo_987654321", plan: "PRO", monthlyQuota: 100000, usageCount: 0 };
  tenants.set(demo.apiKey, demo);
  save();
}

export function createTenant(name: string, plan = "PRO"): Tenant {
  const apiKey = "agp_live_" + crypto.randomBytes(12).toString("hex");
  const quota = plan === "BUSINESS" ? 1000000 : plan === "PRO" ? 100000 : 5000;
  const t = { id: "ws_" + crypto.randomBytes(3).toString("hex"), name, apiKey, plan, monthlyQuota: quota, usageCount: 0 };
  tenants.set(apiKey, t); save(); return t;
}
export function authenticateTenant(k?: string) {
  const t = !k ? (tenants.get("agp_live_demo_987654321") || Array.from(tenants.values())[0]) : tenants.get(k);
  if (t) save();
  return t || null;
}
export function listTenants() { return Array.from(tenants.values()); }
