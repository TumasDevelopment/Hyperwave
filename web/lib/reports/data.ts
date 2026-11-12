import "server-only";
import { ch, TS_RANGE } from "../ch";
import { db } from "../db";
import { TZ } from "../format";
import { INT_EXPR, IN_EXPR, OUT_EXPR } from "../queries/traffic";

// Dati dei rapporti per un periodo qualsiasi [t0, t1) in secondi. Le query di traffico vanno
// su ClickHouse: se non risponde, il rapporto esce lo stesso con un avviso (vedi `traffic`).

export type Period = { t0: number; t1: number };

const PG_RANGE = (col: string) => `${col} >= to_timestamp($1) AND ${col} < to_timestamp($2)`;
const SEV_ORDER = "array_position(ARRAY['critical','high','medium','low','info'], severity)";
const MIN_RANGE = "minute >= toDateTime({t0:UInt32}, 'UTC') AND minute < toDateTime({t1:UInt32}, 'UTC')";
const HOUR_RANGE = "hour >= toDateTime({t0:UInt32}, 'UTC') AND hour < toDateTime({t1:UInt32}, 'UTC')";

const q = async <T>(sql: string, params: unknown[] = []) => (await db().query<T & Record<string, unknown>>(sql, params)).rows as T[];

// -------------------------------------------------------------------------- allarmi

export async function alertsBySeverity(p: Period): Promise<Record<string, number>> {
  const rows = await q<{ severity: string; n: number }>(
    `SELECT severity, count(*)::int AS n FROM alerts WHERE ${PG_RANGE("first_seen")} GROUP BY severity`,
    [p.t0, p.t1],
  );
  return Object.fromEntries(rows.map((r) => [r.severity, r.n]));
}

export async function openAlertsBySeverity(): Promise<Record<string, number>> {
  const rows = await q<{ severity: string; n: number }>(`SELECT severity, count(*)::int AS n FROM alerts WHERE status <> 'resolved' GROUP BY severity`);
  return Object.fromEntries(rows.map((r) => [r.severity, r.n]));
}

/** Allarmi nuovi per giorno (ora locale) e gravità. */
export async function alertsDaily(p: Period) {
  return q<{ day: string; severity: string; n: number }>(
    `SELECT to_char(first_seen AT TIME ZONE $3, 'YYYY-MM-DD') AS day, severity, count(*)::int AS n
       FROM alerts WHERE ${PG_RANGE("first_seen")} GROUP BY 1, 2`,
    [p.t0, p.t1, TZ],
  );
}

export async function alertsByRule(p: Period) {
  return q<{ rule: string; name: string; category: string; severity: string; n: number; open: number; sources: number }>(
    `SELECT a.rule, coalesce(c.name, a.rule) AS name, coalesce(c.category, '') AS category,
            (array_agg(a.severity ORDER BY array_position(ARRAY['critical','high','medium','low','info'], a.severity)))[1] AS severity,
            count(*)::int AS n, count(*) FILTER (WHERE a.status <> 'resolved')::int AS open, count(DISTINCT a.src_ip)::int AS sources
       FROM alerts a LEFT JOIN rule_catalog c ON c.id = a.rule
      WHERE ${PG_RANGE("a.first_seen")}
      GROUP BY a.rule, c.name, c.category
      ORDER BY n DESC LIMIT 40`,
    [p.t0, p.t1],
  );
}

export async function topAlerts(p: Period, limit = 25) {
  return q<{ id: number; severity: string; title: string; src_ip: string; dst_ip: string; count: number; status: string; first_seen: Date }>(
    `SELECT id::int AS id, severity, title, src_ip, dst_ip, count, status, first_seen
       FROM alerts WHERE ${PG_RANGE("first_seen")}
      ORDER BY ${SEV_ORDER}, count DESC, first_seen DESC LIMIT $3`,
    [p.t0, p.t1, limit],
  );
}

/** Tempi di chiusura degli allarmi chiusi nel periodo, in secondi (mediana e 90° percentile). */
export async function resolutionTimes(p: Period) {
  return q<{ severity: string; n: number; median: number; p90: number }>(
    `SELECT severity, count(*)::int AS n,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM resolved_at - first_seen))::float8 AS median,
            percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM resolved_at - first_seen))::float8 AS p90
       FROM alerts WHERE status = 'resolved' AND resolved_at IS NOT NULL AND ${PG_RANGE("resolved_at")}
      GROUP BY severity ORDER BY ${SEV_ORDER}`,
    [p.t0, p.t1],
  );
}

/** Chi ha generato più allarmi gravi: indirizzo, nome del dispositivo, conteggi. */
export async function riskiestSources(p: Period, limit = 10) {
  return q<{ ip: string; name: string; n: number; critical: number; high: number }>(
    `SELECT a.src_ip AS ip, coalesce(max(nullif(d.name, '')), max(nullif(d.hostname, '')), '') AS name, count(*)::int AS n,
            count(*) FILTER (WHERE a.severity = 'critical')::int AS critical, count(*) FILTER (WHERE a.severity = 'high')::int AS high
       FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
      WHERE ${PG_RANGE("a.first_seen")} AND a.src_ip <> ''
      GROUP BY a.src_ip
      ORDER BY count(*) FILTER (WHERE a.severity IN ('critical', 'high')) DESC, n DESC LIMIT $3`,
    [p.t0, p.t1, limit],
  );
}

// ------------------------------------------------------------------------ incidenti

export async function incidents(p: Period, limit = 30) {
  return q<{ id: number; title: string; severity: string; status: string; alert_count: number; first_seen: Date; closed_at: Date | null; assignee: string }>(
    `SELECT id::int AS id, title, severity, status, alert_count, first_seen, closed_at, assignee
       FROM incidents
      WHERE ${PG_RANGE("created_at")} OR (status <> 'closed' AND created_at < to_timestamp($2)) OR ${PG_RANGE("closed_at")}
      ORDER BY status = 'closed', ${SEV_ORDER}, last_seen DESC LIMIT $3`,
    [p.t0, p.t1, limit],
  );
}

export async function incidentCounts(p: Period) {
  const [row] = await q<{ opened: number; closed: number; open_now: number; serious_open: number }>(
    `SELECT count(*) FILTER (WHERE ${PG_RANGE("created_at")})::int AS opened,
            count(*) FILTER (WHERE ${PG_RANGE("closed_at")})::int AS closed,
            count(*) FILTER (WHERE status <> 'closed')::int AS open_now,
            count(*) FILTER (WHERE status <> 'closed' AND severity IN ('critical', 'high'))::int AS serious_open
       FROM incidents`,
    [p.t0, p.t1],
  );
  return row;
}

// ----------------------------------------------------------------------- dispositivi

export async function deviceCounts(p: Period) {
  const [row] = await q<{ total: number; approved: number; new_in_period: number; active: number; critical: number }>(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE approved)::int AS approved,
            count(*) FILTER (WHERE ${PG_RANGE("first_seen")})::int AS new_in_period,
            count(*) FILTER (WHERE last_seen >= to_timestamp($1))::int AS active,
            count(*) FILTER (WHERE criticality IN ('high', 'critical'))::int AS critical
       FROM devices`,
    [p.t0, p.t1],
  );
  return row;
}

export async function newDevicesIn(p: Period, limit = 30) {
  return q<{ ip: string; mac: string; name: string; vendor: string; type: string; first_seen: Date; approved: boolean }>(
    `SELECT ip, mac, coalesce(nullif(name, ''), hostname) AS name, vendor, type, first_seen, approved
       FROM devices WHERE ${PG_RANGE("first_seen")} ORDER BY first_seen DESC LIMIT $3`,
    [p.t0, p.t1, limit],
  );
}

export async function unapprovedDevices(limit = 25) {
  return q<{ ip: string; mac: string; name: string; vendor: string; type: string; first_seen: Date; last_seen: Date }>(
    `SELECT ip, mac, coalesce(nullif(name, ''), hostname) AS name, vendor, type, first_seen, last_seen
       FROM devices WHERE NOT approved ORDER BY last_seen DESC LIMIT $1`,
    [limit],
  );
}

export async function devicesByType() {
  return q<{ type: string; n: number; approved: number }>(
    `SELECT coalesce(nullif(type, ''), 'sconosciuto') AS type, count(*)::int AS n, count(*) FILTER (WHERE approved)::int AS approved
       FROM devices GROUP BY 1 ORDER BY n DESC LIMIT 20`,
  );
}

/** Servizi dei dispositivi interni raggiunti anche da internet. */
export async function exposedServices(limit = 40) {
  return q<{ ip: string; name: string; proto: string; port: number; app: string; first_seen: Date; last_seen: Date; flows: number }>(
    `SELECT d.ip, coalesce(nullif(d.name, ''), d.hostname) AS name, s.proto, s.port, s.app, s.first_seen, s.last_seen, s.flows::float8 AS flows
       FROM device_services s JOIN devices d ON d.id = s.device_id
      WHERE s.external ORDER BY s.last_seen DESC LIMIT $1`,
    [limit],
  );
}

// -------------------------------------------------------------------------- sensori

export async function sensors() {
  return q<{ name: string; site: string; mode: string; enabled: boolean; last_seen: Date | null; version: string; records: number; drops: number }>(
    `SELECT name, site, mode, enabled, last_seen, version, records::float8 AS records,
            coalesce((stats->>'kernel_drops')::float8, 0) + coalesce((stats->>'dropped_records')::float8, 0) AS drops
       FROM sensors ORDER BY name`,
  );
}

// ------------------------------------------------------------------- accessi e registro

export async function users() {
  return q<{ username: string; role: string; mfa: boolean; disabled: boolean; last_login: Date | null; created_at: Date }>(
    `SELECT username, role, totp_secret IS NOT NULL AS mfa, disabled, last_login, created_at FROM users ORDER BY role, username`,
  );
}

export async function apiTokens() {
  return q<{ name: string; role: string; created_by: string; expires_at: Date | null; last_used: Date | null }>(
    `SELECT name, role, created_by, expires_at, last_used FROM api_tokens
      WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) ORDER BY name`,
  );
}

export async function auditCounts(p: Period) {
  return q<{ action: string; n: number; users: number }>(
    `SELECT action, count(*)::int AS n, count(DISTINCT username)::int AS users FROM audit_log
      WHERE ${PG_RANGE("ts")} GROUP BY action ORDER BY n DESC`,
    [p.t0, p.t1],
  );
}

const PRIVILEGED = ["settings.%", "user.%", "sensor.%", "apitoken.%", "2fa.reset", "session.revoke", "live.%", "rule.%", "suppression.%", "pcap.%", "intel.%", "report.delete"];

export async function privilegedActions(p: Period, limit = 60) {
  return q<{ ts: Date; username: string; action: string; target: string; ip: string }>(
    `SELECT ts, username, action, target, ip FROM audit_log
      WHERE ${PG_RANGE("ts")} AND action LIKE ANY ($3::text[]) ORDER BY ts DESC LIMIT $4`,
    [p.t0, p.t1, PRIVILEGED, limit],
  );
}

export async function failedLogins(p: Period) {
  const [row] = await q<{ n: number; locked: number }>(
    `SELECT count(*) FILTER (WHERE action IN ('login.failed', 'login.2fa_failed'))::int AS n, count(*) FILTER (WHERE action = 'login.locked')::int AS locked
       FROM audit_log WHERE ${PG_RANGE("ts")}`,
    [p.t0, p.t1],
  );
  return row;
}

export async function pcapRequests(p: Period) {
  return q<{ id: number; requested_by: string; created_at: Date; ip_a: string; ip_b: string | null; reason: string; status: string }>(
    `SELECT id::int AS id, requested_by, created_at, host(ip_a) AS ip_a, host(ip_b) AS ip_b, reason, status
       FROM pcap_requests WHERE ${PG_RANGE("created_at")} ORDER BY created_at DESC LIMIT 50`,
    [p.t0, p.t1],
  ).catch(() => []);
}

// ------------------------------------------------------------------ regole e minacce

export async function ruleCounts() {
  const [row] = await q<{ total: number; enabled: number; custom: number }>(
    `SELECT count(*)::int AS total, count(*) FILTER (WHERE coalesce(r.enabled, true))::int AS enabled,
            (SELECT count(*)::int FROM custom_rules) AS custom
       FROM rule_catalog c LEFT JOIN rules r ON r.id = c.id`,
  ).catch(() => [{ total: 0, enabled: 0, custom: 0 }]);
  return row;
}

export async function disabledRules() {
  return q<{ name: string; updated_by: string; updated_at: Date }>(
    `SELECT c.name, r.updated_by, r.updated_at FROM rules r JOIN rule_catalog c ON c.id = r.id WHERE NOT r.enabled ORDER BY c.name`,
  );
}

export async function activeSuppressions() {
  return q<{ rule: string; src: string; dst: string; reason: string; created_by: string; created_at: Date; expires_at: Date | null; hits: number }>(
    `SELECT coalesce(c.name, nullif(s.rule, ''), 'tutte') AS rule, s.src, s.dst, s.reason, s.created_by, s.created_at, s.expires_at, s.hits::float8 AS hits
       FROM suppressions s LEFT JOIN rule_catalog c ON c.id = s.rule
      WHERE s.expires_at IS NULL OR s.expires_at > now() ORDER BY s.hits DESC`,
  );
}

export async function intelFeeds() {
  return q<{ name: string; enabled: boolean; entries: number; last_ok: Date | null; last_error: string }>(
    `SELECT name, enabled, entries::float8 AS entries, last_ok, last_error FROM intel_feeds WHERE kind <> 'manual' ORDER BY enabled DESC, name`,
  ).catch(() => []);
}

export async function networkConfig() {
  const [row] = await q<{ value: Record<string, unknown> }>(`SELECT value FROM settings WHERE key = 'config'`);
  return (row?.value ?? {}) as { internal_nets?: string; sensitive_nets?: string };
}

// ------------------------------------------------------------------------- traffico

export interface TrafficData {
  ok: boolean;
  totals: { inB: number; outB: number; intB: number; flows: number };
  daily: { day: string; inB: number; outB: number; intB: number }[];
  apps: { app: string; bytes: number; flows: number }[];
  countries: { country: string; bytes: number; flows: number }[];
  hosts: { ip: string; sent: number; recv: number; flows: number }[];
  destinations: { ip: string; domain: string; country: string; org: string; bytes: number; clients: number }[];
  ports: { proto: string; port: number; app: string; flows: number; bytes: number }[];
}

const EMPTY_TRAFFIC: TrafficData = { ok: false, totals: { inB: 0, outB: 0, intB: 0, flows: 0 }, daily: [], apps: [], countries: [], hosts: [], destinations: [], ports: [] };

export async function trafficTotalsFor(p: Period) {
  const [row] = await ch<TrafficData["totals"]>(
    `SELECT ${IN_EXPR} AS inB, ${OUT_EXPR} AS outB, ${INT_EXPR} AS intB, sum(flows) AS flows FROM traffic_1m WHERE ${MIN_RANGE}`,
    p,
    60,
  );
  return row ?? EMPTY_TRAFFIC.totals;
}

/** Tutto il traffico del periodo. `detail` aggiunge destinazioni e porte (dai flussi grezzi, più lente). */
export async function traffic(p: Period, detail: boolean): Promise<TrafficData> {
  try {
    const [totals, daily, apps, countries, hosts] = await Promise.all([
      trafficTotalsFor(p),
      ch<TrafficData["daily"][number]>(
        `SELECT toString(toDate(minute, {tz:String})) AS day, ${IN_EXPR} AS inB, ${OUT_EXPR} AS outB, ${INT_EXPR} AS intB
           FROM traffic_1m WHERE ${MIN_RANGE} GROUP BY day ORDER BY day`,
        { ...p, tz: TZ },
        60,
      ),
      ch<TrafficData["apps"][number]>(
        `SELECT if(app = '', 'Altro', app) AS app, sum(bytes_out + bytes_in) AS bytes, sum(flows) AS flows
           FROM traffic_1m WHERE ${MIN_RANGE} GROUP BY app ORDER BY bytes DESC LIMIT 12`,
        p,
        60,
      ),
      ch<TrafficData["countries"][number]>(
        `SELECT country, sum(bytes_out + bytes_in) AS bytes, sum(flows) AS flows
           FROM traffic_1m WHERE ${MIN_RANGE} AND direction IN ('outbound', 'inbound') AND country != ''
          GROUP BY country ORDER BY bytes DESC LIMIT 12`,
        p,
        60,
      ),
      ch<TrafficData["hosts"][number]>(
        `SELECT ip, sum(bytes_sent) AS sent, sum(bytes_recv) AS recv, sum(flows_out + flows_in) AS flows
           FROM hosts_1h WHERE ${HOUR_RANGE} GROUP BY ip ORDER BY sent + recv DESC LIMIT 15`,
        p,
        60,
      ),
    ]);
    let destinations: TrafficData["destinations"] = [];
    let ports: TrafficData["ports"] = [];
    if (detail) {
      [destinations, ports] = await Promise.all([
        ch<TrafficData["destinations"][number]>(
          `SELECT dst AS ip, anyIf(domain, domain != '') AS domain, any(country) AS country, any(as_org) AS org,
                  sum(bytes_out + bytes_in) AS bytes, uniq(src) AS clients
             FROM flows WHERE ${TS_RANGE} AND direction = 'outbound' GROUP BY dst ORDER BY bytes DESC LIMIT 20`,
          p,
          120,
        ),
        ch<TrafficData["ports"][number]>(
          `SELECT proto, dport AS port, any(app) AS app, count() AS flows, sum(bytes_out + bytes_in) AS bytes
             FROM flows WHERE ${TS_RANGE} AND est = 1 AND proto IN ('TCP', 'UDP') GROUP BY proto, port ORDER BY flows DESC LIMIT 15`,
          p,
          120,
        ),
      ]);
    }
    return { ok: true, totals, daily, apps, countries, hosts, destinations, ports };
  } catch (error) {
    console.error("Rapporto: traffico non disponibile:", error);
    return EMPTY_TRAFFIC;
  }
}
