import { audit } from "@/lib/audit";
import { can, getUser } from "@/lib/auth";
import { db } from "@/lib/db";
import { getReport } from "@/lib/queries/reports";

export const dynamic = "force-dynamic";

const FILE_NAMES = { executive: "direzione", technical: "tecnico", compliance: "evidenze-nis2-iso27001" } as const;

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getUser();
  if (!user || user.mustChange) return new Response("Sessione scaduta", { status: 401 });
  if (!can(user, "analyst")) return new Response("Non hai i permessi per scaricare i rapporti", { status: 403 });
  const id = Number((await params).id);
  if (!Number.isSafeInteger(id) || id <= 0) return new Response("Richiesta non valida", { status: 400 });
  const report = await getReport(id);
  if (!report || report.status !== "done") return new Response("Rapporto non disponibile", { status: 404 });
  if (report.kind === "compliance" && !can(user, "admin")) return new Response("Rapporto riservato agli amministratori", { status: 403 });

  const { rows } = await db().query<{ pdf: Buffer }>("SELECT pdf FROM reports WHERE id = $1", [id]);
  if (!rows[0]?.pdf) return new Response("Rapporto non disponibile", { status: 404 });
  await audit(user, "report.download", `rapporto ${id}`, { kind: report.kind });
  const day = new Date(report.period_from).toISOString().slice(0, 10);
  return new Response(new Uint8Array(rows[0].pdf), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Length": String(rows[0].pdf.length),
      "Content-Disposition": `attachment; filename="hyperwave-${FILE_NAMES[report.kind]}-${day}.pdf"`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
