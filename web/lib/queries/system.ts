import "server-only";
import { ch } from "../ch";
import { db, setting } from "../db";
import { hasSecretKey } from "../secretbox.mjs";

export interface SensorRow {
  id: number;
  name: string;
  site: string;
  enabled: boolean;
  created_at: Date;
  created_by: string;
  last_seen: Date | null;
  last_ingest: Date | null;
  version: string;
  mode: string;
  hostname: string;
  stats: Record<string, number>;
  records: number;
}

export async function listSensors(): Promise<SensorRow[]> {
  const { rows } = await db().query<SensorRow>(
    `SELECT id::int AS id, name, site, enabled, created_at, created_by, last_seen, last_ingest, version, mode, hostname,
            stats, records::float8 AS records
     FROM sensors ORDER BY name`,
  );
  return rows;
}

export type SensorState = "online" | "late" | "offline" | "never" | "disabled";
export function sensorState(s: Pick<SensorRow, "enabled" | "last_seen">, now = Date.now()): SensorState {
  if (!s.enabled) return "disabled";
  if (!s.last_seen) return "never";
  const age = (now - new Date(s.last_seen).getTime()) / 1000;
  if (age < 45) return "online";
  if (age < 120) return "late";
  return "offline";
}

export const SENSOR_STATE_LABELS: Record<SensorState, string> = {
  online: "In linea",
  late: "In ritardo",
  offline: "Non raggiungibile",
  never: "Mai collegato",
  disabled: "Disattivato",
};

export interface RuntimeConfig {
  internal_nets?: string;
  sensitive_nets?: string;
  learning_hours?: number;
  timezone?: string;
}

export async function systemSettings() {
  const [live, config, vigil, cursor] = await Promise.all([
    setting<boolean>("live", true),
    setting<RuntimeConfig>("config", {}),
    setting<{ ok?: boolean; checked?: string; error?: string } | null>("vigil", null),
    setting<number | null>("engine_cursor", null),
  ]);
  const { rows } = await db().query<{ updated_at: Date; updated_by: string }>(
    "SELECT updated_at, updated_by FROM settings WHERE key = 'live'",
  );
  return { live, config, vigil, cursor, liveChanged: rows[0] ?? null };
}

/** Stato dell'hub letto dal suo /healthz. */
export async function hubHealth(): Promise<Record<string, unknown> | null> {
  const base = (process.env.HW_HUB_URL || "http://127.0.0.1:3121").replace(/\/+$/, "");
  try {
    const res = await fetch(`${base}/healthz`, { cache: "no-store", signal: AbortSignal.timeout(3000) });
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Spazio occupato in ClickHouse per tabella. */
export async function storageUsage() {
  return ch<{ table: string; rows: number; bytes: number; compressed: number; oldest: string }>(
    `SELECT table, sum(rows) AS rows, sum(data_uncompressed_bytes) AS bytes, sum(data_compressed_bytes) AS compressed,
            toString(min(min_time)) AS oldest
     FROM system.parts WHERE active AND database = currentDatabase()
     GROUP BY table ORDER BY compressed DESC`,
  );
}

export async function pgSize() {
  const { rows } = await db().query<{ bytes: number }>("SELECT pg_database_size(current_database())::float8 AS bytes");
  return rows[0]?.bytes ?? 0;
}

export interface RuleRow {
  id: string;
  name: string;
  category: string;
  description: string;
  default_severity: string;
  mitre: string;
  params: Record<string, unknown>;
  param_help: Record<string, string>;
  enabled: boolean;
  severity: string | null;
  custom: Record<string, unknown>;
  updated_at: Date | null;
  updated_by: string;
  alerts_30d: number;
  open: number;
  last_error: string;
}

export async function listRules(): Promise<RuleRow[]> {
  const { rows } = await db().query<RuleRow>(
    `SELECT c.id, c.name, c.category, c.description, c.default_severity, c.mitre, c.params, c.param_help,
            coalesce(r.enabled, true) AS enabled, r.severity, coalesce(r.params, '{}') AS custom, r.updated_at,
            coalesce(r.updated_by, '') AS updated_by,
            (SELECT count(*)::int FROM alerts a WHERE a.rule = c.id AND a.first_seen > now() - interval '30 days') AS alerts_30d,
            (SELECT count(*)::int FROM alerts a WHERE a.rule = c.id AND a.status <> 'resolved') AS open,
            coalesce(cr.last_error, '') AS last_error
     FROM rule_catalog c LEFT JOIN rules r ON r.id = c.id
     LEFT JOIN custom_rules cr ON c.id = 'custom:' || cr.id
     ORDER BY c.id LIKE 'custom:%', c.category, c.name`,
  );
  return rows;
}

export interface SuppressionRow {
  id: number;
  rule: string;
  rule_name: string;
  src: string;
  dst: string;
  reason: string;
  created_by: string;
  created_at: Date;
  expires_at: Date | null;
  hits: number;
  last_hit: Date | null;
}

export async function listSuppressions(): Promise<SuppressionRow[]> {
  const { rows } = await db().query<SuppressionRow>(
    `SELECT s.id::int AS id, s.rule, coalesce(c.name, '') AS rule_name, s.src, s.dst, s.reason, s.created_by, s.created_at,
            s.expires_at, s.hits::float8 AS hits, s.last_hit
     FROM suppressions s LEFT JOIN rule_catalog c ON c.id = s.rule
     ORDER BY (s.expires_at IS NOT NULL AND s.expires_at < now()), s.created_at DESC`,
  );
  return rows;
}

export interface UserRow {
  id: number;
  username: string;
  display_name: string;
  email: string;
  role: string;
  disabled: boolean;
  must_change: boolean;
  totp_enabled: boolean;
  created_at: Date;
  last_login: Date | null;
  sessions: number;
}

export async function listUsers(): Promise<UserRow[]> {
  const { rows } = await db().query<UserRow>(
    `SELECT u.id::int AS id, u.username, u.display_name, u.email, u.role, u.disabled, u.must_change, u.totp_enabled,
            u.created_at, u.last_login,
            (SELECT count(*)::int FROM sessions s WHERE s.user_id = u.id AND s.expires_at > now()) AS sessions
     FROM users u ORDER BY lower(u.username)`,
  );
  return rows;
}

export interface TokenRow {
  id: number;
  name: string;
  prefix: string;
  role: string;
  created_by: string;
  created_at: Date;
  expires_at: Date | null;
  last_used: Date | null;
  revoked_at: Date | null;
}

export async function listTokens(): Promise<TokenRow[]> {
  const { rows } = await db().query<TokenRow>(
    `SELECT id::int AS id, name, prefix, role, created_by, created_at, expires_at, last_used, revoked_at
     FROM api_tokens ORDER BY revoked_at IS NOT NULL, created_at DESC`,
  );
  return rows;
}

export interface AuditRow {
  id: number;
  ts: Date;
  username: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
  ip: string;
}

export async function listAudit(f: { q: string; action: string; days: number }, limit = 500): Promise<AuditRow[]> {
  const where: string[] = ["ts > now() - make_interval(days => $1::int)"];
  const params: unknown[] = [f.days || 30];
  if (f.action) {
    params.push(`${f.action}%`);
    where.push(`action LIKE $${params.length}`);
  }
  if (f.q) {
    params.push(`%${f.q.replace(/[\\%_]/g, "\\$&")}%`);
    where.push(`(username ILIKE $${params.length} OR target ILIKE $${params.length} OR ip ILIKE $${params.length})`);
  }
  params.push(limit);
  const { rows } = await db().query<AuditRow>(
    `SELECT id::int AS id, ts, username, action, target, detail, ip FROM audit_log
     WHERE ${where.join(" AND ")} ORDER BY ts DESC LIMIT $${params.length}`,
    params,
  );
  return rows;
}

/** Stato della cifratura dei segreti 2FA: chiave presente e quanti segreti sono ancora in chiaro. */
export async function secretStatus() {
  const { rows } = await db().query<{ total: number; plain: number }>(
    "SELECT count(*)::int AS total, count(*) FILTER (WHERE totp_secret NOT LIKE 'enc:v1:%')::int AS plain FROM users WHERE totp_secret IS NOT NULL",
  );
  return { key: hasSecretKey(), total: rows[0]?.total ?? 0, plain: rows[0]?.plain ?? 0 };
}
