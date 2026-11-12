import "server-only";
import { db } from "../db";
import type { ReportKind } from "../reports/build";

export interface ReportRow {
  id: number;
  kind: ReportKind;
  period_from: Date;
  period_to: Date;
  status: "pending" | "running" | "done" | "failed";
  scheduled: boolean;
  requested_by: string;
  created_at: Date;
  finished_at: Date | null;
  pages: number;
  bytes: number;
  sha256: string;
  error: string;
}

const SELECT = `SELECT id::int AS id, kind, period_from, period_to, status, scheduled, requested_by, created_at, finished_at,
  pages, bytes::float8 AS bytes, sha256, error FROM reports`;

export async function listReports(limit = 200): Promise<ReportRow[]> {
  const { rows } = await db().query<ReportRow>(`${SELECT} ORDER BY created_at DESC LIMIT $1`, [limit]);
  return rows;
}

export async function getReport(id: number): Promise<ReportRow | null> {
  const { rows } = await db().query<ReportRow>(`${SELECT} WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

export async function reportSchedule(): Promise<ReportKind[]> {
  const { rows } = await db().query<{ value: unknown }>("SELECT value FROM settings WHERE key = 'report_schedule'");
  return Array.isArray(rows[0]?.value) ? (rows[0].value as ReportKind[]) : [];
}

export const REPORT_STATUS_LABELS: Record<ReportRow["status"], string> = {
  pending: "In coda",
  running: "In preparazione",
  done: "Pronto",
  failed: "Non riuscito",
};
