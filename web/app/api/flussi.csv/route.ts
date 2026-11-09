import { audit } from "@/lib/audit";
import { getUser } from "@/lib/auth";
import { csvResponse, stamp, toCsv } from "@/lib/csv";
import { parseFlowFilter, searchFlows } from "@/lib/queries/flows";

export const dynamic = "force-dynamic";

const MAX_ROWS = 100_000;

export async function GET(request: Request) {
  const user = await getUser();
  if (!user || user.mustChange) return new Response("Sessione scaduta", { status: 401 });
  const params = Object.fromEntries(new URL(request.url).searchParams);
  const filter = parseFlowFilter(params);
  try {
    const rows = await searchFlows(filter, MAX_ROWS);
    await audit(user, "export.flows", `${rows.length} righe`, { ...params });
    return csvResponse(
      `flussi-${stamp()}.csv`,
      toCsv(
        ["inizio_utc", "fine_utc", "sensore", "vlan", "protocollo", "origine", "porta_origine", "nome_origine", "destinazione", "porta_destinazione",
          "nome_destinazione", "dominio", "direzione", "applicazione", "byte_inviati", "byte_ricevuti", "pacchetti_inviati", "pacchetti_ricevuti",
          "flag", "riuscito", "rtt_ms", "ritrasmissioni", "paese", "asn", "organizzazione"],
        rows.map((r) => [r.ts, r.ts_end, r.sensor_id, r.vlan, r.proto, r.src, r.sport, r.src_name, r.dst, r.dport, r.dst_name, r.domain,
          r.direction, r.app, r.bytes_out, r.bytes_in, r.pkts_out, r.pkts_in, r.flags, r.est, r.rtt, r.retrans, r.country, r.asn, r.as_org]),
      ),
    );
  } catch (error) {
    console.error("Export dei flussi:", error);
    return new Response("Export non riuscito", { status: 500 });
  }
}
