import "server-only";
import { db } from "../db";

/** Numeri della panoramica che stanno in PostgreSQL. */
export async function overviewCounts() {
  const { rows } = await db().query<{
    devices: number;
    devices_active: number;
    devices_new: number;
    devices_unapproved: number;
    alerts_open: number;
    alerts_critical: number;
    alerts_high: number;
    alerts_today: number;
    sensors: number;
    sensors_online: number;
  }>(
    `SELECT
       (SELECT count(*)::int FROM devices) AS devices,
       (SELECT count(*)::int FROM devices WHERE last_seen > now() - interval '1 hour') AS devices_active,
       (SELECT count(*)::int FROM devices WHERE first_seen > now() - interval '24 hours') AS devices_new,
       (SELECT count(*)::int FROM devices WHERE NOT approved) AS devices_unapproved,
       (SELECT count(*)::int FROM alerts WHERE status <> 'resolved') AS alerts_open,
       (SELECT count(*)::int FROM alerts WHERE status <> 'resolved' AND severity = 'critical') AS alerts_critical,
       (SELECT count(*)::int FROM alerts WHERE status <> 'resolved' AND severity = 'high') AS alerts_high,
       (SELECT count(*)::int FROM alerts WHERE first_seen > now() - interval '24 hours') AS alerts_today,
       (SELECT count(*)::int FROM sensors WHERE enabled) AS sensors,
       (SELECT count(*)::int FROM sensors WHERE enabled AND last_seen > now() - interval '45 seconds') AS sensors_online`,
  );
  return rows[0];
}

export async function newDevices(limit = 8) {
  const { rows } = await db().query<{ id: number; ip: string; mac: string; label: string; vendor: string; type: string; first_seen: Date; approved: boolean }>(
    `SELECT id::int AS id, ip, mac, coalesce(nullif(name, ''), nullif(hostname, ''), '') AS label, vendor, type, first_seen, approved
     FROM devices ORDER BY first_seen DESC LIMIT $1`,
    [limit],
  );
  return rows;
}

/** Allarmi aperti per giorno negli ultimi 14 giorni, per gravità. */
export async function alertTrend() {
  const { rows } = await db().query<{ day: number; critical: number; high: number; medium: number; low: number }>(
    `SELECT extract(epoch FROM d)::int AS day,
            count(a.*) FILTER (WHERE a.severity = 'critical')::int AS critical,
            count(a.*) FILTER (WHERE a.severity = 'high')::int AS high,
            count(a.*) FILTER (WHERE a.severity = 'medium')::int AS medium,
            count(a.*) FILTER (WHERE a.severity IN ('low', 'info'))::int AS low
     FROM generate_series(date_trunc('day', now()) - interval '13 days', date_trunc('day', now()), interval '1 day') d
     LEFT JOIN alerts a ON a.first_seen >= d AND a.first_seen < d + interval '1 day'
     GROUP BY d ORDER BY d`,
  );
  return rows;
}
