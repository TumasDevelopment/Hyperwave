import "server-only";
import { ch, TS_RANGE } from "../ch";
import { db } from "../db";
import { FLOW_COLUMNS, type FlowRow } from "./flows";

export interface AlertRow {
  id: number;
  rule: string;
  rule_name: string;
  category: string;
  severity: string;
  title: string;
  summary: string;
  src_ip: string;
  dst_ip: string;
  device_id: number | null;
  device_name: string;
  sensor: string;
  mitre: string;
  detail: Record<string, unknown>;
  first_seen: Date;
  last_seen: Date;
  count: number;
  status: string;
  assignee: string;
  resolved_by: string;
  resolved_at: Date | null;
  resolution: string;
}

export interface AlertFilter {
  status: "" | "open" | "ack" | "resolved" | "active";
  severity: string;
  rule: string;
  q: string;
  days: number;
  assignee: string;
}

const SELECT = `
  SELECT a.id::int AS id, a.rule, coalesce(c.name, a.rule) AS rule_name, coalesce(c.category, '') AS category,
         a.severity, a.title, a.summary, a.src_ip, a.dst_ip, a.device_id::int AS device_id,
         coalesce(nullif(d.name, ''), nullif(d.hostname, ''), '') AS device_name, coalesce(s.name, '') AS sensor,
         a.mitre, a.detail, a.first_seen, a.last_seen, a.count, a.status, a.assignee, a.resolved_by, a.resolved_at, a.resolution
  FROM alerts a
  LEFT JOIN rule_catalog c ON c.id = a.rule
  LEFT JOIN devices d ON d.id = a.device_id
  LEFT JOIN sensors s ON s.id = a.sensor_id`;

const SEV_ORDER = "array_position(ARRAY['critical','high','medium','low','info'], a.severity)";

export async function listAlerts(f: AlertFilter, limit = 300): Promise<AlertRow[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  const p = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  if (f.status === "active") where.push("a.status <> 'resolved'");
  else if (f.status) where.push(`a.status = ${p(f.status)}`);
  if (f.severity) where.push(`a.severity = ${p(f.severity)}`);
  if (f.rule) where.push(`a.rule = ${p(f.rule)}`);
  if (f.assignee) where.push(`a.assignee = ${p(f.assignee)}`);
  if (f.days) where.push(`a.last_seen > now() - make_interval(days => ${p(f.days)}::int)`);
  if (f.q) {
    const like = p(`%${f.q.replace(/[\\%_]/g, "\\$&")}%`);
    where.push(`(a.src_ip ILIKE ${like} OR a.dst_ip ILIKE ${like} OR a.title ILIKE ${like} OR a.summary ILIKE ${like}
                 OR d.name ILIKE ${like} OR d.hostname ILIKE ${like})`);
  }
  const { rows } = await db().query<AlertRow>(
    `${SELECT} ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
     ORDER BY (a.status = 'resolved'), ${SEV_ORDER}, a.last_seen DESC LIMIT ${p(limit)}`,
    params,
  );
  return rows;
}

export async function alertCounts() {
  const { rows } = await db().query<{ severity: string; open: number; ack: number; today: number }>(
    `SELECT severity, count(*) FILTER (WHERE status = 'open')::int AS open, count(*) FILTER (WHERE status = 'ack')::int AS ack,
            count(*) FILTER (WHERE first_seen > now() - interval '24 hours')::int AS today
     FROM alerts GROUP BY severity`,
  );
  return rows;
}

export async function getAlert(id: number): Promise<AlertRow | null> {
  const { rows } = await db().query<AlertRow>(`${SELECT} WHERE a.id = $1`, [id]);
  return rows[0] ?? null;
}

export interface NoteRow {
  id: number;
  ts: Date;
  username: string;
  kind: string;
  text: string;
}

export async function alertNotes(id: number): Promise<NoteRow[]> {
  const { rows } = await db().query<NoteRow>(
    "SELECT id::int AS id, ts, username, kind, text FROM alert_notes WHERE alert_id = $1 ORDER BY ts",
    [id],
  );
  return rows;
}

/** Altri allarmi dello stesso indirizzo di origine negli ultimi 30 giorni. */
export async function relatedAlerts(alert: AlertRow): Promise<AlertRow[]> {
  if (!alert.src_ip) return [];
  const { rows } = await db().query<AlertRow>(
    `${SELECT} WHERE a.id <> $1 AND (a.src_ip = $2 OR a.dst_ip = $2) AND a.last_seen > now() - interval '30 days'
     ORDER BY a.last_seen DESC LIMIT 20`,
    [alert.id, alert.src_ip],
  );
  return rows;
}

/** I flussi tra origine e destinazione dell'allarme, nel periodo in cui è stato attivo (con un margine). */
export async function alertFlows(alert: AlertRow, limit = 200): Promise<FlowRow[]> {
  if (!alert.src_ip) return [];
  const t0 = Math.floor(new Date(alert.first_seen).getTime() / 1000) - 600;
  const t1 = Math.min(Math.floor(new Date(alert.last_seen).getTime() / 1000) + 600, t0 + 3 * 86400);
  const params: Record<string, string | number> = { t0, t1, src: alert.src_ip, lim: limit };
  let cond = "(src = {src:String} OR dst = {src:String})";
  if (alert.dst_ip && /^[0-9a-f.:]+$/i.test(alert.dst_ip)) {
    params.dst = alert.dst_ip;
    cond = "((src = {src:String} AND dst = {dst:String}) OR (src = {dst:String} AND dst = {src:String}))";
  }
  return ch<FlowRow>(
    `SELECT ${FLOW_COLUMNS} FROM flows WHERE ${TS_RANGE} AND ${cond} ORDER BY ts DESC LIMIT {lim:UInt32}`,
    params,
    45,
  );
}

export async function assignableUsers(): Promise<string[]> {
  const { rows } = await db().query<{ username: string }>(
    "SELECT username FROM users WHERE NOT disabled AND role IN ('admin', 'analyst') ORDER BY lower(username)",
  );
  return rows.map((r) => r.username);
}

export async function ruleOptions() {
  const { rows } = await db().query<{ id: string; name: string }>("SELECT id, name FROM rule_catalog ORDER BY category, name");
  return rows;
}

export async function deviceAlerts(deviceId: number, ips: string[], limit = 30): Promise<AlertRow[]> {
  const { rows } = await db().query<AlertRow>(
    `${SELECT} WHERE a.device_id = $1 OR a.src_ip = ANY($2) OR a.dst_ip = ANY($2)
     ORDER BY (a.status = 'resolved'), a.last_seen DESC LIMIT $3`,
    [deviceId, ips, limit],
  );
  return rows;
}
