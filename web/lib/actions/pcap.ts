"use server";

import { revalidatePath } from "next/cache";
import { audit } from "../audit";
import { actionUser, can } from "../auth";
import { db } from "../db";
import { failure, isIpOrCidr, text, type FormState } from "../form";
import { fmtDateTime } from "../format";
import { canPcap, pcapSensors } from "../queries/pcap";
import { fromLocalInput } from "../zoned";

const MAX_WINDOW_MS = 6 * 3600_000;
const PROTOS = ["", "tcp", "udp", "icmp"];
const DENIED = "Non hai i permessi per estrarre pacchetti: chiedi a un amministratore.";

async function pcapUser() {
  const user = await actionUser("viewer");
  if (!(await canPcap(user))) throw new Error(DENIED);
  return user;
}

const isPlainIp = (v: string) => isIpOrCidr(v) && !v.includes("/");

export async function requestPcap(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await pcapUser();
    const sensorId = Number(form.get("sensor"));
    const a = text(form, "a", 60);
    const b = text(form, "b", 60);
    const portText = text(form, "port", 5);
    const proto = text(form, "proto", 4);
    const reason = text(form, "reason", 500);
    const alertId = Number(form.get("alert") || 0);
    const from = fromLocalInput(text(form, "from", 25));
    const to = fromLocalInput(text(form, "to", 25));

    if (!isPlainIp(a)) return { error: "Indica un indirizzo IP valido (senza /rete)." };
    if (b && !isPlainIp(b)) return { error: "La controparte deve essere un indirizzo IP valido, oppure vuota." };
    if (b && b === a) return { error: "I due indirizzi sono uguali." };
    const port = portText ? Number(portText) : null;
    if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) return { error: "Porta non valida (1-65535)." };
    if (!PROTOS.includes(proto)) return { error: "Protocollo non valido." };
    if (from === null || to === null) return { error: "Indica inizio e fine del periodo." };
    if (to <= from) return { error: "La fine deve venire dopo l'inizio." };
    if (to - from > MAX_WINDOW_MS) return { error: "Il periodo può essere al massimo di 6 ore." };
    if (reason.length < 5) return { error: "Scrivi il motivo della richiesta: finisce nel registro delle attività." };

    const sensor = (await pcapSensors()).find((s) => s.id === sensorId);
    if (!sensor) return { error: "Scegli un sensore che conserva i pacchetti." };
    if (!sensor.online) return { error: `Il sensore ${sensor.name} non comunica con l'hub: la richiesta resterebbe in attesa.` };
    if (!sensor.from || to < sensor.from) {
      return { error: `Pacchetti non più disponibili: il buffer di ${sensor.name} parte da ${sensor.from ? fmtDateTime(sensor.from) : "—"}.` };
    }
    if (from > Date.now() + 60_000) return { error: "Il periodo è nel futuro." };

    const { rows } = await db().query<{ id: number }>(
      `INSERT INTO pcap_requests (sensor_id, ip_a, ip_b, port, proto, t_from, t_to, reason, alert_id, requested_by)
       VALUES ($1, $2, $3, $4, $5, to_timestamp($6 / 1000.0), to_timestamp($7 / 1000.0), $8,
               (SELECT id FROM alerts WHERE id = $9), $10)
       RETURNING id::int AS id`,
      [sensor.id, a, b || null, port, proto, from, to, reason, alertId > 0 ? alertId : null, user.username],
    );
    const id = rows[0].id;
    await audit(user, "pcap.request", `estrazione ${id}`, {
      sensor: sensor.name, a, b: b || undefined, port: port ?? undefined, proto: proto || undefined,
      from: new Date(from).toISOString(), to: new Date(to).toISOString(), reason, alert: alertId > 0 ? alertId : undefined,
    });
    revalidatePath("/pacchetti");
    const clipped = from < sensor.from ? " Il buffer non copre l'inizio del periodo: avrai solo i pacchetti dalla sua prima ora disponibile." : "";
    return { ok: true, message: `Richiesta n. ${id} inviata: il sensore la riceve entro pochi secondi.${clipped}` };
  } catch (error) {
    return failure(error);
  }
}

/** Cancella subito il file estratto (resta la riga, per il registro). Chi l'ha chiesto o un amministratore. */
export async function deletePcap(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await pcapUser();
    const id = Number(form.get("id"));
    if (!Number.isSafeInteger(id) || id <= 0) return { error: "Identificativo non valido." };
    const { rows } = await db().query<{ requested_by: string; status: string }>("SELECT requested_by, status FROM pcap_requests WHERE id = $1", [id]);
    const row = rows[0];
    if (!row) return { error: "Estrazione non trovata." };
    if (row.requested_by !== user.username && !can(user, "admin")) return { error: "Può cancellarla solo chi l'ha chiesta o un amministratore." };
    await db().query(
      `WITH upd AS (UPDATE pcap_requests SET status = CASE WHEN status IN ('pending', 'running') THEN 'failed' ELSE 'expired' END,
                      error = CASE WHEN status IN ('pending', 'running') THEN 'annullata da ' || $2 ELSE error END,
                      expires_at = now(), finished_at = coalesce(finished_at, now())
                    WHERE id = $1 RETURNING id)
       DELETE FROM pcap_chunks WHERE request_id IN (SELECT id FROM upd)`,
      [id, user.username],
    );
    await audit(user, "pcap.delete", `estrazione ${id}`, { status: row.status });
    revalidatePath("/pacchetti");
    return { ok: true, message: row.status === "done" ? "File cancellato." : "Richiesta annullata." };
  } catch (error) {
    return failure(error);
  }
}
