import { apiError, apiJson, readJson, rowId, withApi } from "@/lib/apitokens";
import { audit } from "@/lib/audit";
import { db, transaction } from "@/lib/db";
import { isUniqueViolation } from "@/lib/form";
import { RESOLUTIONS, STATUS_LABELS } from "@/lib/labels";
import { alertNotes, getAlert } from "@/lib/queries/alerts";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export function GET(request: Request, { params }: Ctx) {
  return withApi(request, "viewer", async () => {
    const id = rowId((await params).id);
    if (!id) return apiError(400, "Identificativo non valido.");
    const alert = await getAlert(id);
    if (!alert) return apiError(404, "Allarme non trovato.");
    return apiJson({ alert, notes: await alertNotes(id) });
  });
}

/** JSON: { status?, resolution?, assignee?, note? } */
export function POST(request: Request, { params }: Ctx) {
  return withApi(request, "analyst", async (caller) => {
    const id = rowId((await params).id);
    if (!id) return apiError(400, "Identificativo non valido.");
    const body = await readJson(request);
    if (!body) return apiError(400, "Corpo JSON non valido.");
    const status = typeof body.status === "string" ? body.status : undefined;
    const resolution = typeof body.resolution === "string" ? body.resolution : "";
    const assignee = typeof body.assignee === "string" ? body.assignee.slice(0, 40) : undefined;
    const note = typeof body.note === "string" ? body.note.trim().slice(0, 4000) : "";
    if (status !== undefined && !(status in STATUS_LABELS)) return apiError(400, "status: open, ack oppure resolved.");
    if (status === "resolved" && !(resolution in RESOLUTIONS)) {
      return apiError(400, `resolution obbligatoria per chiudere: ${Object.keys(RESOLUTIONS).join(", ")}.`);
    }
    if (assignee) {
      const { rowCount } = await db().query("SELECT 1 FROM users WHERE username = $1 AND NOT disabled AND role <> 'viewer'", [assignee]);
      if (!rowCount) return apiError(400, "assignee: utente inesistente o senza permessi.");
    }
    if (status === undefined && assignee === undefined && !note) return apiError(400, "Niente da fare: indica status, assignee o note.");

    try {
      const found = await transaction(async (client) => {
        const { rowCount } = await client.query("SELECT 1 FROM alerts WHERE id = $1 FOR UPDATE", [id]);
        if (!rowCount) return false;
        if (status !== undefined) {
          await client.query(
            `UPDATE alerts SET status = $2, resolution = CASE WHEN $2 = 'resolved' THEN $3 ELSE '' END,
                    resolved_by = CASE WHEN $2 = 'resolved' THEN $4 ELSE '' END,
                    resolved_at = CASE WHEN $2 = 'resolved' THEN now() END
             WHERE id = $1`,
            [id, status, resolution, caller.username],
          );
          const label = status === "resolved" ? `${STATUS_LABELS[status]}: ${RESOLUTIONS[resolution]}` : STATUS_LABELS[status];
          await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'status', $3)", [id, caller.username, label]);
        }
        if (assignee !== undefined) {
          await client.query("UPDATE alerts SET assignee = $2 WHERE id = $1", [id, assignee]);
          await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'assign', $3)", [
            id,
            caller.username,
            assignee ? `Assegnato a ${assignee}` : "Assegnazione tolta",
          ]);
        }
        if (note) {
          await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'note', $3)", [id, caller.username, note]);
        }
        return true;
      });
      if (!found) return apiError(404, "Allarme non trovato.");
    } catch (error) {
      if (isUniqueViolation(error)) return apiError(409, "Esiste già un allarme aperto identico.");
      throw error;
    }
    const action = status !== undefined ? "alert.status" : assignee !== undefined ? "alert.assign" : "alert.note";
    await audit(caller, action, String(id), { status, resolution, assignee, api: true });
    return apiJson({ alert: await getAlert(id), notes: await alertNotes(id) });
  });
}
