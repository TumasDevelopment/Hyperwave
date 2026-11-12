import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";
import { audit } from "@/lib/audit";
import { getUser } from "@/lib/auth";
import { db } from "@/lib/db";
import { canPcap, getPcapRequest } from "@/lib/queries/pcap";

export const dynamic = "force-dynamic";

/** I pezzi si leggono uno alla volta: un file da centinaia di MB non passa tutto in memoria. */
async function* chunks(id: number) {
  for (let seq = 0; ; seq++) {
    const { rows } = await db().query<{ data: Buffer }>("SELECT data FROM pcap_chunks WHERE request_id = $1 AND seq = $2", [id, seq]);
    if (rows.length === 0) return;
    yield rows[0].data;
  }
}

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUser();
  if (!user || user.mustChange) return new Response("Sessione scaduta", { status: 401 });
  if (!(await canPcap(user))) return new Response("Non hai i permessi per scaricare pacchetti", { status: 403 });
  const id = Number((await params).id);
  if (!Number.isSafeInteger(id) || id <= 0) return new Response("Richiesta non valida", { status: 400 });
  const req = await getPcapRequest(id);
  if (!req || req.status !== "done") return new Response("Estrazione non disponibile", { status: 404 });

  await audit(user, "pcap.download", `estrazione ${id}`, { sensor: req.sensor, packets: req.packets, bytes: req.bytes, sha256: req.sha256 });
  // nel database il pcap è compresso: si decomprime mentre si invia
  const stream = Readable.from(chunks(id)).pipe(createGunzip());
  return new Response(Readable.toWeb(stream) as ReadableStream, {
    headers: {
      "Content-Type": "application/vnd.tcpdump.pcap",
      "Content-Length": String(req.bytes),
      "Content-Disposition": `attachment; filename="hyperwave-pacchetti-${id}.pcap"`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Checksum-SHA256": req.sha256,
    },
  });
}
