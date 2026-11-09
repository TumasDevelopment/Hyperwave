import { audit } from "@/lib/audit";
import { getUser } from "@/lib/auth";
import { csvResponse, stamp, toCsv } from "@/lib/csv";
import { listDevices } from "@/lib/queries/devices";

export const dynamic = "force-dynamic";

export async function GET() {
  const user = await getUser();
  if (!user || user.mustChange) return new Response("Sessione scaduta", { status: 401 });
  const rows = await listDevices({ q: "", type: "", vlan: 0, status: "", sort: "ip" }, 100_000);
  await audit(user, "export.devices", `${rows.length} righe`);
  return csvResponse(
    `dispositivi-${stamp()}.csv`,
    toCsv(
      ["id", "nome", "hostname", "ip", "altri_ip", "mac", "produttore", "sistema", "tipo", "vlan", "sensore", "prima_vista", "ultima_vista",
        "byte", "flussi", "responsabile", "posizione", "etichette", "criticita", "approvato", "approvato_da", "allarmi_aperti", "servizi", "note"],
      rows.map((d) => [d.id, d.name, d.hostname, d.ip, d.ips.filter((ip) => ip !== d.ip).join(" "), d.mac, d.vendor, d.os, d.type, d.vlan,
        d.sensor, d.first_seen, d.last_seen, d.bytes, d.flows, d.owner, d.location, d.tags.join(" "), d.criticality, d.approved ? "sì" : "no",
        d.approved_by, d.open_alerts, d.services, d.notes]),
    ),
  );
}
