import "server-only";
import { db } from "../db";
import { isIpOrCidr } from "../form";
import { normalizeIndicator } from "../intel.mjs";

export interface FeedRow {
  id: number;
  name: string;
  kind: "url" | "manual";
  url: string;
  category: string;
  severity: string;
  description: string;
  enabled: boolean;
  refresh_hours: number;
  preset: string;
  entries: number;
  last_fetch: Date | null;
  last_ok: Date | null;
  last_error: string;
  retro_at: Date | null;
  retro_hits: number | null;
  hits_30d: number;
}

export async function listFeeds(): Promise<FeedRow[]> {
  const { rows } = await db().query<FeedRow>(
    `SELECT f.id::int AS id, f.name, f.kind, f.url, f.category, f.severity, f.description, f.enabled, f.refresh_hours, f.preset,
            f.entries, f.last_fetch, f.last_ok, f.last_error, f.retro_at, f.retro_hits,
            (SELECT count(*)::int FROM alerts a WHERE a.rule = 'threat_intel' AND a.detail->>'feed_id' = f.id::text
                AND a.last_seen > now() - interval '30 days') AS hits_30d
     FROM intel_feeds f
     ORDER BY f.kind = 'manual' DESC, f.enabled DESC, f.name`,
  );
  return rows;
}

export interface ManualIndicatorRow {
  feed_id: number;
  feed_name: string;
  value: string;
  type: string;
  note: string;
  added_by: string;
  added_at: Date;
  expires_at: Date | null;
}

export async function manualIndicators(limit = 300): Promise<{ rows: ManualIndicatorRow[]; total: number }> {
  const [list, count] = await Promise.all([
    db().query<ManualIndicatorRow>(
      `SELECT i.feed_id::int AS feed_id, f.name AS feed_name, i.value, i.type, i.note, i.added_by, i.added_at, i.expires_at
       FROM intel_indicators i JOIN intel_feeds f ON f.id = i.feed_id
       WHERE f.kind = 'manual'
       ORDER BY (i.expires_at IS NOT NULL AND i.expires_at < now()), i.added_at DESC LIMIT $1`,
      [limit],
    ),
    db().query<{ n: number }>("SELECT count(*)::int AS n FROM intel_indicators i JOIN intel_feeds f ON f.id = i.feed_id WHERE f.kind = 'manual'"),
  ]);
  return { rows: list.rows, total: count.rows[0]?.n ?? 0 };
}

export interface LookupRow {
  feed_id: number;
  feed_name: string;
  enabled: boolean;
  severity: string;
  category: string;
  value: string;
  type: string;
  note: string;
  expires_at: Date | null;
}

/** In quali elenchi compare un indirizzo, una rete o un dominio (anche come dominio padre). */
export async function lookupIndicator(raw: string): Promise<{ query: string; rows: LookupRow[] } | null> {
  const ind = normalizeIndicator(raw);
  if (!ind) return null;
  const select = `SELECT f.id::int AS feed_id, f.name AS feed_name, f.enabled, f.severity, f.category, i.value, i.type, i.note, i.expires_at
                  FROM intel_indicators i JOIN intel_feeds f ON f.id = i.feed_id`;
  if (ind.type === "domain") {
    const parts = ind.value.split(".");
    const suffixes = parts.slice(0, -1).map((_, i) => parts.slice(i).join("."));
    const { rows } = await db().query<LookupRow>(`${select} WHERE i.type = 'domain' AND i.value = ANY($1) ORDER BY f.enabled DESC, f.name LIMIT 50`, [
      suffixes,
    ]);
    return { query: ind.value, rows };
  }
  if (!isIpOrCidr(ind.value)) return null;
  const op = ind.type === "cidr" ? "&&" : ">>=";
  const { rows } = await db().query<LookupRow>(
    `${select} WHERE i.type IN ('ip', 'cidr') AND i.value::inet ${op} $1::inet ORDER BY f.enabled DESC, f.name LIMIT 50`,
    [ind.value],
  );
  return { query: ind.value, rows };
}

export async function intelStats() {
  const { rows } = await db().query<{ indicators: number; feeds: number; total_feeds: number; hits_7d: number; open: number }>(
    `SELECT (SELECT coalesce(sum(entries), 0)::int FROM intel_feeds WHERE enabled AND kind = 'url')
            + (SELECT count(*)::int FROM intel_indicators i JOIN intel_feeds f ON f.id = i.feed_id
               WHERE f.enabled AND f.kind = 'manual' AND (i.expires_at IS NULL OR i.expires_at > now())) AS indicators,
            (SELECT count(*)::int FROM intel_feeds WHERE enabled) AS feeds,
            (SELECT count(*)::int FROM intel_feeds) AS total_feeds,
            (SELECT count(*)::int FROM alerts WHERE rule = 'threat_intel' AND last_seen > now() - interval '7 days') AS hits_7d,
            (SELECT count(*)::int FROM alerts WHERE rule = 'threat_intel' AND status = 'open') AS open`,
  );
  return rows[0];
}

export interface IntelAlertRow {
  id: number;
  title: string;
  severity: string;
  status: string;
  last_seen: Date;
  count: number;
  feed: string;
  indicator: string;
  retro: boolean;
}

export async function recentIntelAlerts(limit = 20): Promise<IntelAlertRow[]> {
  const { rows } = await db().query<IntelAlertRow>(
    `SELECT id::int AS id, title, severity, status, last_seen, count, coalesce(detail->>'feed', '') AS feed,
            coalesce(detail->>'indicator', '') AS indicator, coalesce((detail->>'retro')::boolean, false) AS retro
     FROM alerts WHERE rule = 'threat_intel' ORDER BY last_seen DESC LIMIT $1`,
    [limit],
  );
  return rows;
}
