import "server-only";
import { ch, TS_RANGE } from "../ch";
import type { RangeKey } from "../ranges";
import { timeWindow } from "../ranges";

// Traffico in ingresso e in uscita dal punto di vista della rete interna.
// Nei flussi bytes_out è sempre dal client al server: per i flussi "inbound" il client è su internet.
export const IN_EXPR = "sumIf(bytes_in, direction = 'outbound') + sumIf(bytes_out, direction = 'inbound')";
export const OUT_EXPR = "sumIf(bytes_out, direction = 'outbound') + sumIf(bytes_in, direction = 'inbound')";
export const INT_EXPR = "sumIf(bytes_out + bytes_in, direction = 'internal')";

const MIN_RANGE = "minute >= toDateTime({t0:UInt32}, 'UTC') AND minute < toDateTime({t1:UInt32}, 'UTC')";

export interface SeriesPoint {
  t: number;
  inB: number;
  outB: number;
  intB: number;
  flows: number;
}

export interface Series {
  t: number[];
  in: (number | null)[];
  out: (number | null)[];
  internal: (number | null)[];
  bucket: number;
}

/** Banda in bit/s per intervallo, con gli intervalli vuoti a zero. */
export async function trafficSeries(range: RangeKey, sensor = 0): Promise<Series> {
  const { t0, t1, bucket } = timeWindow(range);
  const rows = await ch<SeriesPoint>(
    `SELECT toUnixTimestamp(toStartOfInterval(minute, toIntervalSecond({b:UInt32}))) AS t,
            ${IN_EXPR} AS inB, ${OUT_EXPR} AS outB, ${INT_EXPR} AS intB, sum(flows) AS flows
     FROM traffic_1m WHERE ${MIN_RANGE} AND ({s:UInt32} = 0 OR sensor_id = {s:UInt32})
     GROUP BY t ORDER BY t`,
    { t0, t1, b: bucket, s: sensor },
  );
  const byT = new Map(rows.map((r) => [r.t, r]));
  const out: Series = { t: [], in: [], out: [], internal: [], bucket };
  const start = Math.floor(t0 / bucket) * bucket;
  const last = Math.floor((Date.now() / 1000 - 60) / bucket) * bucket; // l'ultimo minuto è ancora incompleto
  for (let t = start; t < t1; t += bucket) {
    const r = byT.get(t);
    const future = t > last;
    out.t.push(t);
    out.in.push(future && !r ? null : ((r?.inB ?? 0) * 8) / bucket);
    out.out.push(future && !r ? null : ((r?.outB ?? 0) * 8) / bucket);
    out.internal.push(future && !r ? null : ((r?.intB ?? 0) * 8) / bucket);
  }
  return out;
}

export interface Totals {
  inB: number;
  outB: number;
  intB: number;
  flows: number;
}

export async function trafficTotals(range: RangeKey, sensor = 0): Promise<Totals> {
  const { t0, t1 } = timeWindow(range);
  const [row] = await ch<Totals>(
    `SELECT ${IN_EXPR} AS inB, ${OUT_EXPR} AS outB, ${INT_EXPR} AS intB, sum(flows) AS flows
     FROM traffic_1m WHERE ${MIN_RANGE} AND ({s:UInt32} = 0 OR sensor_id = {s:UInt32})`,
    { t0, t1, s: sensor },
  );
  return row ?? { inB: 0, outB: 0, intB: 0, flows: 0 };
}

export interface AppRow {
  app: string;
  bytes: number;
  flows: number;
}

export async function topApps(range: RangeKey, limit = 12, sensor = 0): Promise<AppRow[]> {
  const { t0, t1 } = timeWindow(range);
  return ch<AppRow>(
    `SELECT if(app = '', 'Altro', app) AS app, sum(bytes_out + bytes_in) AS bytes, sum(flows) AS flows
     FROM traffic_1m WHERE ${MIN_RANGE} AND ({s:UInt32} = 0 OR sensor_id = {s:UInt32})
     GROUP BY app ORDER BY bytes DESC LIMIT {n:UInt32}`,
    { t0, t1, n: limit, s: sensor },
  );
}

export interface CountryRow {
  country: string;
  bytes: number;
  flows: number;
}

export async function topCountries(range: RangeKey, limit = 12, sensor = 0): Promise<CountryRow[]> {
  const { t0, t1 } = timeWindow(range);
  return ch<CountryRow>(
    `SELECT country, sum(bytes_out + bytes_in) AS bytes, sum(flows) AS flows
     FROM traffic_1m WHERE ${MIN_RANGE} AND direction IN ('outbound', 'inbound') AND country != ''
       AND ({s:UInt32} = 0 OR sensor_id = {s:UInt32})
     GROUP BY country ORDER BY bytes DESC LIMIT {n:UInt32}`,
    { t0, t1, n: limit, s: sensor },
  );
}

export interface HostRow {
  ip: string;
  sent: number;
  recv: number;
  flows: number;
}

/** Host interni che hanno scambiato più dati: dai flussi grezzi fino a 24 ore, dagli aggregati orari oltre. */
export async function topHosts(range: RangeKey, limit = 10, sensor = 0): Promise<HostRow[]> {
  const { t0, t1 } = timeWindow(range);
  if (t1 - t0 <= 86400) {
    return ch<HostRow>(
      `SELECT ip, sum(s) AS sent, sum(r) AS recv, count() AS flows FROM (
         SELECT src AS ip, bytes_out AS s, bytes_in AS r FROM flows
         WHERE ${TS_RANGE} AND direction IN ('outbound', 'internal') AND ({sn:UInt32} = 0 OR sensor_id = {sn:UInt32})
         UNION ALL
         SELECT dst AS ip, bytes_in AS s, bytes_out AS r FROM flows
         WHERE ${TS_RANGE} AND direction IN ('inbound', 'internal') AND ({sn:UInt32} = 0 OR sensor_id = {sn:UInt32})
       ) GROUP BY ip ORDER BY sent + recv DESC LIMIT {n:UInt32}`,
      { t0, t1, n: limit, sn: sensor },
    );
  }
  return ch<HostRow>(
    `SELECT ip, sum(bytes_sent) AS sent, sum(bytes_recv) AS recv, sum(flows_out + flows_in) AS flows
     FROM hosts_1h WHERE hour >= toDateTime({t0:UInt32}, 'UTC') AND hour < toDateTime({t1:UInt32}, 'UTC')
       AND ({sn:UInt32} = 0 OR sensor_id = {sn:UInt32})
     GROUP BY ip ORDER BY sent + recv DESC LIMIT {n:UInt32}`,
    { t0, t1, n: limit, sn: sensor },
  );
}

export interface DestRow {
  ip: string;
  domain: string;
  country: string;
  org: string;
  bytes: number;
  flows: number;
  clients: number;
}

/** Destinazioni su internet più usate (dai flussi grezzi). */
export async function topDestinations(range: RangeKey, limit = 15, sensor = 0): Promise<DestRow[]> {
  const { t0, t1 } = timeWindow(range);
  return ch<DestRow>(
    `SELECT dst AS ip, anyIf(domain, domain != '') AS domain, any(country) AS country, any(as_org) AS org,
            sum(bytes_out + bytes_in) AS bytes, count() AS flows, uniq(src) AS clients
     FROM flows WHERE ${TS_RANGE} AND direction = 'outbound' AND ({sn:UInt32} = 0 OR sensor_id = {sn:UInt32})
     GROUP BY dst ORDER BY bytes DESC LIMIT {n:UInt32}`,
    { t0, t1, n: limit, sn: sensor },
    45,
  );
}

export interface PortRow {
  proto: string;
  port: number;
  app: string;
  bytes: number;
  flows: number;
}

export async function topPorts(range: RangeKey, limit = 12, sensor = 0): Promise<PortRow[]> {
  const { t0, t1 } = timeWindow(range);
  return ch<PortRow>(
    `SELECT proto, dport AS port, any(app) AS app, sum(bytes_out + bytes_in) AS bytes, count() AS flows
     FROM flows WHERE ${TS_RANGE} AND est = 1 AND proto IN ('TCP', 'UDP') AND ({sn:UInt32} = 0 OR sensor_id = {sn:UInt32})
     GROUP BY proto, port ORDER BY flows DESC LIMIT {n:UInt32}`,
    { t0, t1, n: limit, sn: sensor },
    45,
  );
}

/** Ultimi 15 minuti dei contatori delle interfacce, per far partire il grafico in tempo reale. */
export async function recentRates() {
  return ch<{ t: number; bin: number; bout: number; bint: number }>(
    `SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL 5 SECOND)) AS t,
            sum(bytes_in * 8 / secs) AS bin, sum(bytes_out * 8 / secs) AS bout, sum(bytes_internal * 8 / secs) AS bint
     FROM rates WHERE ts >= now() - INTERVAL 15 MINUTE AND secs > 0 AND secs <= 30
     GROUP BY t ORDER BY t`,
  );
}
