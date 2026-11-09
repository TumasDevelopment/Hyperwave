import { apiJson, withApi } from "@/lib/apitokens";
import { listDevices, type DeviceFilter } from "@/lib/queries/devices";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => {
    const p = new URL(request.url).searchParams;
    const status = p.get("status") ?? "";
    const limit = Math.min(Math.max(Number(p.get("limit")) || 1000, 1), 10000);
    const devices = await listDevices(
      {
        q: (p.get("q") ?? "").slice(0, 100),
        type: (p.get("type") ?? "").slice(0, 60),
        vlan: Math.max(0, Math.min(4094, Number(p.get("vlan")) || 0)),
        status: (["new", "unapproved", "active", "inactive", "alerts"].includes(status) ? status : "") as DeviceFilter["status"],
        sort: "ip",
      },
      limit,
    );
    return apiJson({ count: devices.length, devices });
  });
}
