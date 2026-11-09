import { audit } from "@/lib/audit";
import { can, getUser } from "@/lib/auth";
import { csvResponse, stamp, toCsv } from "@/lib/csv";
import { listAudit } from "@/lib/queries/system";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const user = await getUser();
  if (!user || user.mustChange) return new Response("Sessione scaduta", { status: 401 });
  if (!can(user, "admin")) return new Response("Non autorizzato", { status: 403 });
  const p = new URL(request.url).searchParams;
  const days = Math.min(Math.max(Number(p.get("days")) || 90, 1), 3650);
  const rows = await listAudit({ q: (p.get("q") ?? "").slice(0, 100), action: (p.get("action") ?? "").slice(0, 40), days }, 200_000);
  await audit(user, "export.audit", `${rows.length} righe`, { days });
  return csvResponse(
    `registro-${stamp()}.csv`,
    toCsv(["data_utc", "utente", "azione", "oggetto", "indirizzo", "dettagli"], rows.map((r) => [r.ts, r.username, r.action, r.target, r.ip, JSON.stringify(r.detail)])),
  );
}
