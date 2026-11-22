export type Decision = "ALLOW" | "BLOCK" | "REDACT";

export interface PolicyRule {
  id: string;
  toolPattern: string;
  action: Decision;
  enabled?: boolean;
  conditions?: { param: string; operator: "gt" | "lt" | "contains" | "regex"; value: string | number }[];
  redactFields?: string[];
  reason?: string;
}

export interface ToolCallRequest {
  traceId: string;
  agentId: string;
  toolName: string;
  arguments: Record<string, any>;
}

export interface EvaluationResult {
  decision: Decision;
  matchedRuleId?: string;
  reason?: string;
  sanitizedArguments: Record<string, any>;
}

export function evaluatePolicy(request: ToolCallRequest, rules: PolicyRule[]): EvaluationResult {
  const sanitizedArguments = structuredClone(request.arguments);

  for (const rule of rules) {
    if (rule.enabled === false) continue;
    const regex = new RegExp("^" + rule.toolPattern.replace(/\*/g, ".*") + "$");
    if (!regex.test(request.toolName)) continue;

    let conditionsMet = true;
    if (rule.conditions && rule.conditions.length > 0) {
      conditionsMet = rule.conditions.every((cond) => {
        const argVal = sanitizedArguments[cond.param];
        if (argVal === undefined) return false;
        switch (cond.operator) {
          case "gt": return Number(argVal) > Number(cond.value);
          case "lt": return Number(argVal) < Number(cond.value);
          case "contains": return String(argVal).includes(String(cond.value));
          case "regex": return new RegExp(String(cond.value)).test(String(argVal));
          default: return false;
        }
      });
    }
    if (!conditionsMet) continue;

    if (rule.action === "BLOCK") {
      return { decision: "BLOCK", matchedRuleId: rule.id, reason: rule.reason || "Blocked by policy", sanitizedArguments };
    }

    if (rule.action === "REDACT" && rule.redactFields) {
      let count = 0;
      for (const field of rule.redactFields) {
        if (field in sanitizedArguments && sanitizedArguments[field] !== undefined) {
          sanitizedArguments[field] = "[REDACTED_BY_POLICY]";
          count++;
        }
      }
      if (count > 0) {
        return { decision: "REDACT", matchedRuleId: rule.id, reason: rule.reason || "PII Redacted", sanitizedArguments };
      }
    }
  }
  return { decision: "ALLOW", sanitizedArguments };
}