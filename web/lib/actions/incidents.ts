"use server";

import { revalidatePath } from "next/cache";
import type { PoolClient } from "pg";
import { audit } from "../audit";
import { actionUser } from "../auth";
import { db, transaction } from "../db";
import { failure, isUniqueViolation, text, type FormState } from "../form";
import { INCIDENT_STATUS_LABELS, RESOLUTIONS, STATUS_LABELS } from "../labels";

const id = (value: FormDataEntryValue | null) => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("Identificativo non valido.");
  return n;
};

const NOT_FOUND = "Incidente non trovato.";

function known(error: unknown): FormState {
  if (error instanceof Error && (error.message === NOT_FOUND || error.message === "Identificativo non valido.")) return { error: error.message };
  return failure(error);
}

function refresh(incidentId: number) {
  revalidatePath(`/incidenti/${incidentId}`);
  revalidatePath("/incidenti");
}

const note = (client: PoolClient, incidentId: number, username: string, kind: string, body: string) =>
  client.query("INSERT INTO incident_notes (incident_id, username, kind, text) VALUES ($1, $2, $3, $4)", [incidentId, username, kind, body]);

export async function setIncidentStatus(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const incidentId = id(form.get("id"));
    const status = text(form, "status");
    const resolution = text(form, "resolution");
    const comment = text(form, "note", 4000);
    const closeAlerts = form.get("close_alerts") === "on";
    if (!(status in INCIDENT_STATUS_LABELS)) return { error: "Stato non valido." };
    if (status === "closed" && !(resolution in RESOLUTIONS)) return { error: "Scegli l'esito prima di chiudere l'incidente." };
    let closed = 0;
    await transaction(async (client) => {
      const { rowCount } = await client.query(
        `UPDATE incidents SET status = $2,
                resolution = CASE WHEN $2 = 'closed' THEN $3 ELSE '' END,
                closed_by = CASE WHEN $2 = 'closed' THEN $4 ELSE '' END,
                closed_at = CASE WHEN $2 = 'closed' THEN now() END,
                assignee = CASE WHEN $2 = 'investigating' AND assignee = '' THEN $4 ELSE assignee END,
                updated_at = now()
         WHERE id = $1`,
        [incidentId, status, resolution, user.username],
      );
      if (!rowCount) throw new Error(NOT_FOUND);
      const label = status === "closed" ? `${INCIDENT_STATUS_LABELS.closed}: ${RESOLUTIONS[resolution]}` : INCIDENT_STATUS_LABELS[status];
      if (status === "closed" && closeAlerts) {
        // gli allarmi ancora aperti si chiudono con lo stesso esito, ognuno con la sua nota
        const { rows } = await client.query<{ id: number }>(
          `UPDATE alerts SET status = 'resolved', resolution = $2, resolved_by = $3, resolved_at = now()
           WHERE incident_id = $1 AND status <> 'resolved' RETURNING id::int AS id`,
          [incidentId, resolution, user.username],
        );
        closed = rows.length;
        if (closed)
          await client.query(
            `INSERT INTO alert_notes (alert_id, username, kind, text) SELECT unnest($1::bigint[]), $2, 'status', $3`,
            [rows.map((r) => r.id), user.username, `${STATUS_LABELS.resolved}: ${RESOLUTIONS[resolution]}. Chiuso con l'incidente n. ${incidentId}.`],
          );
      }
      await note(client, incidentId, user.username, "status", `${label}${closed ? ` (chiusi anche ${closed} allarmi)` : ""}${comment ? `. ${comment}` : ""}`);
    });
    await audit(user, "incident.status", String(incidentId), { status, resolution, closed_alerts: closed });
    refresh(incidentId);
    revalidatePath("/allarmi");
    return { ok: true, message: closed ? `Stato aggiornato; chiusi anche ${closed} allarmi.` : "Stato aggiornato." };
  } catch (error) {
    if (isUniqueViolation(error)) return { error: "Lo stesso dispositivo ha già un altro incidente aperto: lavora su quello." };
    return known(error);
  }
}

export async function assignIncident(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const incidentId = id(form.get("id"));
    let assignee = text(form, "assignee", 40);
    if (assignee === "@me") assignee = user.username;
    if (assignee) {
      const { rowCount } = await db().query("SELECT 1 FROM users WHERE username = $1 AND NOT disabled AND role <> 'viewer'", [assignee]);
      if (!rowCount) return { error: "Utente non valido: si può assegnare solo ad analisti e amministratori attivi." };
    }
    await transaction(async (client) => {
      const { rowCount } = await client.query(
        `UPDATE incidents SET assignee = $2, status = CASE WHEN status = 'open' AND $2 <> '' THEN 'investigating' ELSE status END,
                updated_at = now() WHERE id = $1`,
        [incidentId, assignee],
      );
      if (!rowCount) throw new Error(NOT_FOUND);
      await note(client, incidentId, user.username, "assign", assignee ? `Assegnato a ${assignee}` : "Assegnazione tolta");
    });
    await audit(user, "incident.assign", String(incidentId), { assignee });
    refresh(incidentId);
    return { ok: true, message: assignee ? `Assegnato a ${assignee}.` : "Assegnazione tolta." };
  } catch (error) {
    return known(error);
  }
}

export async function addIncidentNote(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const incidentId = id(form.get("id"));
    const body = text(form, "note", 4000);
    if (!body) return { error: "Scrivi la nota." };
    await transaction(async (client) => {
      const { rowCount } = await client.query("UPDATE incidents SET updated_at = now() WHERE id = $1", [incidentId]);
      if (!rowCount) throw new Error(NOT_FOUND);
      await note(client, incidentId, user.username, "note", body);
    });
    await audit(user, "incident.note", String(incidentId));
    refresh(incidentId);
    return { ok: true, message: "Nota aggiunta." };
  } catch (error) {
    return known(error);
  }
}

/** Toglie un allarme che non c'entra: il correlatore non lo riaggiunge più. */
export async function removeIncidentAlert(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const incidentId = id(form.get("id"));
    const alertId = id(form.get("alert_id"));
    await transaction(async (client) => {
      const { rows } = await client.query<{ title: string }>(
        "UPDATE alerts SET incident_id = NULL, incident_skip = true WHERE id = $1 AND incident_id = $2 RETURNING title",
        [alertId, incidentId],
      );
      if (!rows[0]) throw new Error(NOT_FOUND);
      await client.query(
        `UPDATE incidents i SET alert_count = s.n, rule_count = s.r, techniques = s.t,
                first_seen = coalesce(s.f, i.first_seen), last_seen = coalesce(s.l, i.last_seen), updated_at = now()
         FROM (SELECT count(*)::int AS n, count(DISTINCT rule)::int AS r, min(first_seen) AS f, max(last_seen) AS l,
                      coalesce(array_agg(DISTINCT mitre ORDER BY mitre) FILTER (WHERE mitre <> ''), '{}') AS t
               FROM alerts WHERE incident_id = $1) s
         WHERE i.id = $1`,
        [incidentId],
      );
      await note(client, incidentId, user.username, "note", `Tolto l'allarme n. ${alertId} (${rows[0].title}): non fa parte dell'incidente.`);
    });
    await audit(user, "incident.remove_alert", String(incidentId), { alert: alertId });
    refresh(incidentId);
    revalidatePath(`/allarmi/${alertId}`);
    return { ok: true, message: "Allarme tolto dall'incidente." };
  } catch (error) {
    return known(error);
  }
}
