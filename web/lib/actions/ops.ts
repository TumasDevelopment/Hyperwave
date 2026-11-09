"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { audit } from "../audit";
import { actionUser } from "../auth";
import { db, transaction } from "../db";
import { failure, isIpOrCidr, isUniqueViolation, text, type FormState } from "../form";
import { RESOLUTIONS, SEVERITIES, STATUS_LABELS } from "../labels";
import { notifyHub } from "../nats";

const id = (value: FormDataEntryValue | null) => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("Identificativo non valido.");
  return n;
};
const ids = (form: FormData) =>
  [...new Set(form.getAll("id").map(Number))].filter((n) => Number.isSafeInteger(n) && n > 0).slice(0, 1000);

// ---------------------------------------------------------------------- allarmi

export async function setAlertStatus(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const alertId = id(form.get("id"));
    const status = text(form, "status");
    const resolution = text(form, "resolution");
    const note = text(form, "note", 4000);
    if (!(status in STATUS_LABELS)) return { error: "Stato non valido." };
    if (status === "resolved" && !(resolution in RESOLUTIONS)) return { error: "Scegli l'esito prima di chiudere l'allarme." };
    await transaction(async (client) => {
      const { rows } = await client.query<{ status: string }>(
        `UPDATE alerts SET status = $2,
                resolution = CASE WHEN $2 = 'resolved' THEN $3 ELSE '' END,
                resolved_by = CASE WHEN $2 = 'resolved' THEN $4 ELSE '' END,
                resolved_at = CASE WHEN $2 = 'resolved' THEN now() END,
                assignee = CASE WHEN $2 = 'ack' AND assignee = '' THEN $4 ELSE assignee END
         WHERE id = $1 RETURNING status`,
        [alertId, status, resolution, user.username],
      );
      if (!rows[0]) throw new Error("Allarme non trovato.");
      const label = status === "resolved" ? `${STATUS_LABELS[status]}: ${RESOLUTIONS[resolution]}` : STATUS_LABELS[status];
      await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'status', $3)", [
        alertId,
        user.username,
        note ? `${label}. ${note}` : label,
      ]);
    });
    await audit(user, "alert.status", String(alertId), { status, resolution });
    revalidatePath(`/allarmi/${alertId}`);
    revalidatePath("/allarmi");
    return { ok: true, message: "Stato aggiornato." };
  } catch (error) {
    if (isUniqueViolation(error)) return { error: "C'è già un allarme aperto identico: lavora su quello invece di riaprire questo." };
    if (error instanceof Error && error.message === "Allarme non trovato.") return { error: error.message };
    return failure(error);
  }
}

export async function assignAlert(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const alertId = id(form.get("id"));
    let assignee = text(form, "assignee", 40);
    if (assignee === "@me") assignee = user.username;
    if (assignee) {
      const { rowCount } = await db().query("SELECT 1 FROM users WHERE username = $1 AND NOT disabled AND role <> 'viewer'", [assignee]);
      if (!rowCount) return { error: "Utente non valido: si può assegnare solo ad analisti e amministratori attivi." };
    }
    await transaction(async (client) => {
      const { rowCount } = await client.query(
        "UPDATE alerts SET assignee = $2, status = CASE WHEN status = 'open' AND $2 <> '' THEN 'ack' ELSE status END WHERE id = $1",
        [alertId, assignee],
      );
      if (!rowCount) throw new Error("Allarme non trovato.");
      await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'assign', $3)", [
        alertId,
        user.username,
        assignee ? `Assegnato a ${assignee}` : "Assegnazione tolta",
      ]);
    });
    await audit(user, "alert.assign", String(alertId), { assignee });
    revalidatePath(`/allarmi/${alertId}`);
    return { ok: true, message: assignee ? `Assegnato a ${assignee}.` : "Assegnazione tolta." };
  } catch (error) {
    return failure(error);
  }
}

export async function addAlertNote(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const alertId = id(form.get("id"));
    const note = text(form, "note", 4000);
    if (!note) return { error: "Scrivi la nota." };
    await db().query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'note', $3)", [alertId, user.username, note]);
    await audit(user, "alert.note", String(alertId));
    revalidatePath(`/allarmi/${alertId}`);
    return { ok: true, message: "Nota aggiunta." };
  } catch (error) {
    return failure(error);
  }
}

/** Più allarmi insieme: prendi in carico, chiudi con un esito, assegna a me. */
export async function bulkAlerts(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const list = ids(form);
    const op = text(form, "op");
    const resolution = text(form, "resolution");
    if (list.length === 0) return { error: "Seleziona almeno un allarme." };
    let sql: string;
    let note: string;
    const params: unknown[] = [list, user.username];
    switch (op) {
      case "ack":
        sql = "UPDATE alerts SET status = 'ack', assignee = CASE WHEN assignee = '' THEN $2 ELSE assignee END WHERE id = ANY($1) AND status = 'open'";
        note = STATUS_LABELS.ack;
        break;
      case "mine":
        sql = "UPDATE alerts SET assignee = $2, status = CASE WHEN status = 'open' THEN 'ack' ELSE status END WHERE id = ANY($1) AND status <> 'resolved'";
        note = `Assegnato a ${user.username}`;
        break;
      case "resolve":
        if (!(resolution in RESOLUTIONS)) return { error: "Scegli l'esito per chiudere gli allarmi." };
        params.push(resolution);
        sql = "UPDATE alerts SET status = 'resolved', resolution = $3, resolved_by = $2, resolved_at = now() WHERE id = ANY($1) AND status <> 'resolved'";
        note = `${STATUS_LABELS.resolved}: ${RESOLUTIONS[resolution]}`;
        break;
      default:
        return { error: "Operazione non valida." };
    }
    const changed = await transaction(async (client) => {
      const res = await client.query(`${sql} RETURNING id`, params);
      const touched = res.rows.map((r: { id: string }) => r.id);
      if (touched.length) {
        await client.query(
          "INSERT INTO alert_notes (alert_id, username, kind, text) SELECT unnest($1::bigint[]), $2, $3, $4",
          [touched, user.username, op === "mine" ? "assign" : "status", note],
        );
      }
      return touched.length;
    });
    await audit(user, "alert.bulk", `${changed} allarmi`, { op, resolution, ids: list.slice(0, 50) });
    revalidatePath("/allarmi");
    return { ok: true, message: `Allarmi aggiornati: ${changed}.` };
  } catch (error) {
    return failure(error);
  }
}

// ------------------------------------------------------------------ dispositivi

export async function updateDevice(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const deviceId = id(form.get("id"));
    const criticality = text(form, "criticality");
    if (!["low", "normal", "high", "critical"].includes(criticality)) return { error: "Criticità non valida." };
    const tags = [
      ...new Set(
        text(form, "tags", 500)
          .split(",")
          .map((t) => t.trim().toLowerCase())
          .filter(Boolean),
      ),
    ].slice(0, 20);
    if (tags.some((t) => t.length > 40)) return { error: "Ogni etichetta può avere al massimo 40 caratteri." };
    const approved = form.get("approved") === "on";
    const { rows } = await db().query<{ ip: string }>(
      `UPDATE devices SET name = $2, owner = $3, location = $4, notes = $5, tags = $6, criticality = $7,
              approved = $8,
              approved_by = CASE WHEN $8 AND NOT approved THEN $9 WHEN NOT $8 THEN '' ELSE approved_by END,
              approved_at = CASE WHEN $8 AND NOT approved THEN now() WHEN NOT $8 THEN NULL ELSE approved_at END
       WHERE id = $1 RETURNING ip`,
      [
        deviceId,
        text(form, "name", 100),
        text(form, "owner", 100),
        text(form, "location", 100),
        text(form, "notes", 4000),
        tags,
        criticality,
        approved,
        user.username,
      ],
    );
    if (!rows[0]) return { error: "Dispositivo non trovato." };
    await audit(user, "device.update", rows[0].ip || String(deviceId), { criticality, approved, tags });
    revalidatePath(`/dispositivi/${deviceId}`);
    return { ok: true, message: "Dispositivo salvato." };
  } catch (error) {
    return failure(error);
  }
}

export async function approveDevices(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const list = ids(form);
    if (list.length === 0) return { error: "Seleziona almeno un dispositivo." };
    const res = await db().query(
      "UPDATE devices SET approved = true, approved_by = $2, approved_at = now() WHERE id = ANY($1) AND NOT approved",
      [list, user.username],
    );
    await audit(user, list.length === 1 ? "device.approve" : "device.bulk_approve", `${res.rowCount ?? 0} dispositivi`, {
      ids: list.slice(0, 50),
    });
    revalidatePath("/dispositivi");
    return { ok: true, message: `Dispositivi approvati: ${res.rowCount ?? 0}.` };
  } catch (error) {
    return failure(error);
  }
}

export async function deleteDevice(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const { rows } = await db().query<{ ip: string; mac: string }>("DELETE FROM devices WHERE id = $1 RETURNING ip, mac", [id(form.get("id"))]);
    if (!rows[0]) return { error: "Dispositivo non trovato." };
    await audit(user, "device.delete", rows[0].ip || rows[0].mac);
    revalidatePath("/dispositivi");
  } catch (error) {
    return failure(error);
  }
  // la scheda non esiste più: si torna all'elenco (redirect fuori dal try, lancia un'eccezione apposita)
  redirect("/dispositivi");
}

// --------------------------------------------------------- regole ed eccezioni

export async function updateRule(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const ruleId = text(form, "id", 60);
    const { rows } = await db().query<{ params: Record<string, unknown> }>("SELECT params FROM rule_catalog WHERE id = $1", [ruleId]);
    if (!rows[0]) return { error: "Regola non trovata." };
    const severity = text(form, "severity");
    if (severity && !(SEVERITIES as readonly string[]).includes(severity)) return { error: "Gravità non valida." };
    const custom: Record<string, number> = {};
    for (const [key, def] of Object.entries(rows[0].params)) {
      const raw = text(form, `p_${key}`, 30).replace(",", ".");
      if (raw === "") continue;
      const value = Number(raw);
      if (!Number.isFinite(value) || value < 0) return { error: `Valore non valido per «${key}».` };
      if (value !== def) custom[key] = value;
    }
    const enabled = form.get("enabled") === "on";
    await db().query(
      `INSERT INTO rules (id, enabled, severity, params, updated_at, updated_by) VALUES ($1, $2, nullif($3, ''), $4, now(), $5)
       ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, severity = EXCLUDED.severity, params = EXCLUDED.params,
         updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [ruleId, enabled, severity, JSON.stringify(custom), user.username],
    );
    await audit(user, "rule.update", ruleId, { enabled, severity, params: custom });
    await notifyHub("rules");
    revalidatePath("/regole");
    return { ok: true, message: "Regola salvata: l'hub la applica dal prossimo giro." };
  } catch (error) {
    return failure(error);
  }
}

export async function createSuppression(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const rule = text(form, "rule", 60);
    const src = text(form, "src", 60);
    const dst = text(form, "dst", 60);
    const reason = text(form, "reason", 500);
    const days = Number(form.get("days") || 0);
    if (rule) {
      const { rowCount } = await db().query("SELECT 1 FROM rule_catalog WHERE id = $1", [rule]);
      if (!rowCount) return { error: "Regola non valida." };
    }
    if (src && !isIpOrCidr(src)) return { error: "Origine: indirizzo IP o rete CIDR." };
    if (dst && !isIpOrCidr(dst)) return { error: "Destinazione: indirizzo IP o rete CIDR." };
    if (!src && !dst && !rule) return { error: "Un'eccezione senza regola, origine e destinazione nasconderebbe tutto." };
    if (!src && !dst) return { error: "Indica almeno l'origine o la destinazione." };
    if (!reason) return { error: "Scrivi il motivo: servirà a chi rivede le eccezioni." };
    if (![0, 1, 7, 30, 90, 365].includes(days)) return { error: "Durata non valida." };

    const alertId = form.get("alert_id") ? id(form.get("alert_id")) : 0;
    await transaction(async (client) => {
      await client.query(
        `INSERT INTO suppressions (rule, src, dst, reason, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::int > 0 THEN now() + make_interval(days => $6::int) END)`,
        [rule, src, dst, reason, user.username, days],
      );
      if (alertId && form.get("resolve") === "on") {
        await client.query(
          "UPDATE alerts SET status = 'resolved', resolution = 'benign', resolved_by = $2, resolved_at = now() WHERE id = $1 AND status <> 'resolved'",
          [alertId, user.username],
        );
        await client.query("INSERT INTO alert_notes (alert_id, username, kind, text) VALUES ($1, $2, 'status', $3)", [
          alertId,
          user.username,
          `${STATUS_LABELS.resolved}: ${RESOLUTIONS.benign}. Eccezione creata: ${reason}`,
        ]);
      }
    });
    await audit(user, "suppression.create", [rule || "tutte", src || "*", dst || "*"].join(" "), { reason, days });
    await notifyHub("rules");
    revalidatePath("/regole");
    if (alertId) revalidatePath(`/allarmi/${alertId}`);
    return { ok: true, message: "Eccezione creata: gli allarmi corrispondenti non verranno più aperti." };
  } catch (error) {
    return failure(error);
  }
}

export async function deleteSuppression(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const { rows } = await db().query<{ rule: string; src: string; dst: string }>(
      "DELETE FROM suppressions WHERE id = $1 RETURNING rule, src, dst",
      [id(form.get("id"))],
    );
    if (!rows[0]) return { error: "Eccezione non trovata." };
    await audit(user, "suppression.delete", [rows[0].rule || "tutte", rows[0].src || "*", rows[0].dst || "*"].join(" "));
    await notifyHub("rules");
    revalidatePath("/regole");
    return { ok: true, message: "Eccezione eliminata." };
  } catch (error) {
    return failure(error);
  }
}
