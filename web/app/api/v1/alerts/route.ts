import { apiJson, withApi } from "@/lib/apitokens";
import { SEVERITIES } from "@/lib/labels";
import { listAlerts, type AlertFilter } from "@/lib/queries/alerts";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => {
    const p = new URL(request.url).searchParams;
    const status = p.get("status") ?? "";
    const severity = p.get("severity") ?? "";
    const days = Number(p.get("days") ?? 0);
    const limit = Math.min(Math.max(Number(p.get("limit")) || 100, 1), 1000);
    const filter: AlertFilter = {
      status: (["open", "ack", "resolved", "active"].includes(status) ? status : "") as AlertFilter["status"],
      severity: (SEVERITIES as readonly string[]).includes(severity) ? severity : "",
      rule: (p.get("rule") ?? "").slice(0, 60),
      q: (p.get("q") ?? "").slice(0, 100),
      days: Number.isInteger(days) && days > 0 && days <= 3650 ? days : 0,
      assignee: (p.get("assignee") ?? "").slice(0, 40),
    };
    const alerts = await listAlerts(filter, limit);
    return apiJson({ count: alerts.length, alerts });
  });
}
