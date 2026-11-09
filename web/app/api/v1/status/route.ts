import { apiJson, withApi } from "@/lib/apitokens";
import { setting } from "@/lib/db";
import { alertCounts } from "@/lib/queries/alerts";
import { overviewCounts } from "@/lib/queries/overview";
import { listSensors, sensorState } from "@/lib/queries/system";
import { trafficTotals } from "@/lib/queries/traffic";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => {
    const [live, counts, alerts, sensors, traffic] = await Promise.all([
      setting<boolean>("live", true),
      overviewCounts(),
      alertCounts(),
      listSensors(),
      trafficTotals("1h").catch(() => null),
    ]);
    return apiJson({
      live,
      time: new Date().toISOString(),
      alerts: {
        active: counts.alerts_open,
        new_24h: counts.alerts_today,
        by_severity: Object.fromEntries(alerts.map((a) => [a.severity, { open: a.open, ack: a.ack }])),
      },
      devices: { total: counts.devices, active_1h: counts.devices_active, new_24h: counts.devices_new, unapproved: counts.devices_unapproved },
      sensors: sensors.map((s) => ({ id: s.id, name: s.name, state: sensorState(s), last_seen: s.last_seen })),
      traffic_1h: traffic && { bytes_in: traffic.inB, bytes_out: traffic.outB, bytes_internal: traffic.intB, flows: traffic.flows },
    });
  });
}
