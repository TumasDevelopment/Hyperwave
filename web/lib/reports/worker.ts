import "server-only";
import { createHash } from "node:crypto";
import { db } from "../db";
import { startOfWeek } from "../zoned";
import { buildReport, type ReportKind, REPORT_KINDS } from "./build";

// Generazione dei rapporti in sottofondo, dentro il processo del sito. Con più istanze del sito
// ognuna prova a prendere i rapporti in attesa con FOR UPDATE SKIP LOCKED: ciascuno lo genera
// una sola istanza. La pianificazione settimanale inserisce con ON CONFLICT DO NOTHING
// (indice unico su tipo e settimana), quindi anche lì nessun doppione.

const TICK_MS = 30_000;
const STALE_MINUTES = 15; // un rapporto "in corso" da più tempo è di un'istanza fermata a metà
const KEEP_DAYS = 400;

let started = false;
let running = false;
let lastSchedule = 0;
let lastCleanup = 0;

export function startReportWorker() {
  if (started) return;
  started = true;
  setTimeout(() => void tick(), 5_000).unref();
  setInterval(() => void tick(), TICK_MS).unref();
}

/** Prova subito a generare i rapporti in attesa (dopo una richiesta dalla pagina). */
export function kickReportWorker() {
  setImmediate(() => void tick());
}

async function tick() {
  if (running) return;
  running = true;
  try {
    const now = Date.now();
    if (now - lastSchedule > 10 * 60_000) {
      lastSchedule = now;
      await schedule(now);
    }
    if (now - lastCleanup > 3600_000) {
      lastCleanup = now;
      await db().query(
        `UPDATE reports SET status = 'failed', error = 'generazione interrotta', finished_at = now()
          WHERE status = 'running' AND started_at < now() - make_interval(mins => $1)`,
        [STALE_MINUTES],
      );
      await db().query(`DELETE FROM reports WHERE created_at < now() - make_interval(days => $1)`, [KEEP_DAYS]);
    }
    for (let i = 0; i < 5 && (await generateNext()); i++);
  } catch (error) {
    // il database può non essere ancora pronto (prima migrazione dell'hub): si riprova al giro dopo
    console.error("Rapporti:", error instanceof Error ? error.message : error);
  } finally {
    running = false;
  }
}

/** Il lunedì (o appena possibile dopo) crea i rapporti pianificati della settimana precedente. */
async function schedule(now: number) {
  const { rows } = await db().query<{ value: unknown }>("SELECT value FROM settings WHERE key = 'report_schedule'");
  const kinds = (Array.isArray(rows[0]?.value) ? rows[0].value : []).filter((k): k is ReportKind => typeof k === "string" && k in REPORT_KINDS);
  if (kinds.length === 0) return;
  const to = startOfWeek(now);
  const from = startOfWeek(to - 3 * 86400_000);
  if (now - to < 30 * 60_000) return; // mezz'ora di margine: gli ultimi dati della domenica arrivano in ritardo
  await db().query(
    `INSERT INTO reports (kind, period_from, period_to, scheduled)
     SELECT k, to_timestamp($2 / 1000.0), to_timestamp($3 / 1000.0), true FROM unnest($1::text[]) AS k
     ON CONFLICT (kind, period_from) WHERE scheduled DO NOTHING`,
    [kinds, from, to],
  );
}

async function generateNext(): Promise<boolean> {
  const { rows } = await db().query<{ id: number; kind: ReportKind; from: number; to: number; requested_by: string }>(
    `UPDATE reports SET status = 'running', started_at = now()
      WHERE id = (SELECT id FROM reports WHERE status = 'pending' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
      RETURNING id::int AS id, kind, extract(epoch FROM period_from)::float8 * 1000 AS "from",
                extract(epoch FROM period_to)::float8 * 1000 AS "to", requested_by`,
  );
  const job = rows[0];
  if (!job) return false;
  try {
    const { pdf, pages } = await buildReport({ kind: job.kind, from: job.from, to: job.to, requestedBy: job.requested_by });
    await db().query(
      `UPDATE reports SET status = 'done', pdf = $2, pages = $3, bytes = $4, sha256 = $5, finished_at = now(), error = ''
        WHERE id = $1 AND status = 'running'`,
      [job.id, pdf, pages, pdf.length, createHash("sha256").update(pdf).digest("hex")],
    );
  } catch (error) {
    console.error(`Rapporto ${job.id} non generato:`, error);
    const message = error instanceof Error ? error.message : String(error);
    await db().query(`UPDATE reports SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, [job.id, message.slice(0, 300)]);
  }
  return true;
}
