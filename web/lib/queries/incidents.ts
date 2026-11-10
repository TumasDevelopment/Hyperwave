import "server-only";
import { db } from "../db";

export interface IncidentRow {
  id: number;
  key_entity: string;
  device_id: number | null;
  device_name: string;
  title: string;
  severity: string;
  status: string;
  resolution: string;
  assignee: string;
  techniques: string[];
  alert_count: number;
  rule_count: number;
  open_alerts: number;
  first_seen: Date;
  last_seen: Date;
  created_at: Date;
  updated_at: Date;
  closed_by: string;
  closed_at: Date | null;
}

const SELECT = `
  SELECT i.id::int AS id, i.key_entity, i.device_id::int AS device_id,
         coalesce(nullif(d.name, ''), nullif(d.hostname, ''), '') AS device_name,
         i.title, i.severity, i.status, i.resolution, i.assignee, i.techniques, i.alert_count, i.rule_count,
         (SELECT count(*)::int FROM alerts a WHERE a.incident_id = i.id AND a.status <> 'resolved') AS open_alerts,
         i.first_seen, i.last_seen, i.created_at, i.updated_at, i.closed_by, i.closed_at
  FROM incidents i LEFT JOIN devices d ON d.id = i.device_id`;

export interface IncidentFilter {
  status: string; // "" = non chiusi, "all" = tutti
  q: string;
}

export async function listIncidents(f: IncidentFilter, limit = 300): Promise<IncidentRow[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  const p = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  if (!f.status) where.push("i.status <> 'closed'");
  else if (f.status !== "all") where.push(`i.status = ${p(f.status)}`);
  if (f.q) {
    const like = p(`%${f.q.replace(/[\\%_]/g, "\\$&")}%`);
    where.push(`(i.key_entity ILIKE ${like} OR i.title ILIKE ${like} OR d.name ILIKE ${like} OR d.hostname ILIKE ${like})`);
  }
  const { rows } = await db().query<IncidentRow>(
    `${SELECT} ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
     ORDER BY (i.status = 'closed'), array_position(ARRAY['critical','high','medium','low','info'], i.severity), i.last_seen DESC
     LIMIT ${p(limit)}`,
    params,
  );
  return rows;
}

export async function incidentCounts(): Promise<Record<string, number>> {
  const { rows } = await db().query<{ status: string; n: number }>("SELECT status, count(*)::int AS n FROM incidents GROUP BY status");
  return Object.fromEntries(rows.map((r) => [r.status, r.n]));
}

export async function getIncident(id: number): Promise<IncidentRow | null> {
  const { rows } = await db().query<IncidentRow>(`${SELECT} WHERE i.id = $1`, [id]);
  return rows[0] ?? null;
}

export interface IncidentNote {
  id: number;
  ts: Date;
  username: string;
  kind: string;
  text: string;
}

export async function incidentNotes(id: number): Promise<IncidentNote[]> {
  const { rows } = await db().query<IncidentNote>(
    "SELECT id::int AS id, ts, username, kind, text FROM incident_notes WHERE incident_id = $1 ORDER BY ts, id",
    [id],
  );
  return rows;
}
