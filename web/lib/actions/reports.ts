"use server";

import { revalidatePath } from "next/cache";
import { audit } from "../audit";
import { actionUser, can } from "../auth";
import { db } from "../db";
import { failure, type FormState } from "../form";
import { type ReportKind, REPORT_KINDS } from "../reports/build";
import { reportPeriod, REPORT_PERIODS, type ReportPeriod } from "../reports/periods";
import { kickReportWorker, startReportWorker } from "../reports/worker";

const isKind = (v: unknown): v is ReportKind => typeof v === "string" && v in REPORT_KINDS;

/** Chiede un rapporto: lo genera in sottofondo il primo processo del sito libero. */
export async function requestReport(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const kind = form.get("kind");
    const period = String(form.get("period") ?? "") as ReportPeriod;
    if (!isKind(kind)) return { error: "Tipo di rapporto non valido." };
    if (!(period in REPORT_PERIODS)) return { error: "Periodo non valido." };
    if (kind === "compliance" && !can(user, "admin")) return { error: "Le evidenze per NIS2 e ISO 27001 contengono utenti e accessi: solo per gli amministratori." };
    const { rows: busy } = await db().query<{ n: number }>(
      "SELECT count(*)::int AS n FROM reports WHERE requested_by = $1 AND status IN ('pending', 'running')",
      [user.username],
    );
    if (busy[0].n >= 3) return { error: "Hai già tre rapporti in preparazione: aspetta che finiscano." };
    const { from, to } = reportPeriod(period, Date.now());
    const { rows } = await db().query<{ id: number }>(
      `INSERT INTO reports (kind, period_from, period_to, requested_by)
       VALUES ($1, to_timestamp($2 / 1000.0), to_timestamp($3 / 1000.0), $4) RETURNING id::int AS id`,
      [kind, from, to, user.username],
    );
    await audit(user, "report.request", `rapporto ${rows[0].id}`, { kind, from: new Date(from).toISOString(), to: new Date(to).toISOString() });
    startReportWorker();
    kickReportWorker();
    revalidatePath("/rapporti");
    return { ok: true, message: `${REPORT_KINDS[kind].title}: in preparazione, di solito bastano pochi secondi.` };
  } catch (error) {
    return failure(error);
  }
}

export async function deleteReport(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const id = Number(form.get("id"));
    if (!Number.isSafeInteger(id) || id <= 0) return { error: "Identificativo non valido." };
    const { rows } = await db().query<{ kind: string; requested_by: string; scheduled: boolean }>(
      "SELECT kind, requested_by, scheduled FROM reports WHERE id = $1",
      [id],
    );
    const row = rows[0];
    if (!row) return { error: "Rapporto non trovato." };
    if (!can(user, "admin") && (row.scheduled || row.requested_by !== user.username)) {
      return { error: "Può eliminarlo solo chi l'ha chiesto o un amministratore." };
    }
    await db().query("DELETE FROM reports WHERE id = $1", [id]);
    await audit(user, "report.delete", `rapporto ${id}`, { kind: row.kind });
    revalidatePath("/rapporti");
    return { ok: true, message: "Rapporto eliminato." };
  } catch (error) {
    return failure(error);
  }
}

/** Tipi di rapporto generati ogni lunedì per la settimana precedente. */
export async function saveReportSchedule(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const kinds = form.getAll("kind").filter(isKind);
    await db().query(
      `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('report_schedule', $1, now(), $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [JSON.stringify(kinds), user.username],
    );
    await audit(user, "settings.reports", "", { kinds });
    revalidatePath("/rapporti");
    return { ok: true, message: kinds.length ? "Pianificazione salvata: i rapporti escono ogni lunedì." : "Pianificazione spenta." };
  } catch (error) {
    return failure(error);
  }
}
