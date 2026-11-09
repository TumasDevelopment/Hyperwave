import "server-only";
import { ch } from "../ch";
import { db } from "../db";

export interface DeviceRow {
  id: number;
  mac: string;
  ip: string;
  ips: string[];
  hostname: string;
  vendor: string;
  os: string;
  type: string;
  vlan: number;
  sensor: string;
  first_seen: Date;
  last_seen: Date;
  bytes: number;
  flows: number;
  name: string;
  owner: string;
  location: string;
  notes: string;
  tags: string[];
  criticality: string;
  approved: boolean;
  approved_by: string;
  approved_at: Date | null;
  open_alerts: number;
  services: number;
}

export interface DeviceFilter {
  q: string;
  type: string;
  vlan: number;
  status: "" | "new" | "unapproved" | "active" | "inactive" | "alerts";
  sort: "last_seen" | "name" | "ip" | "traffic" | "first_seen";
}

const SORTS: Record<DeviceFilter["sort"], string> = {
  last_seen: "d.last_seen DESC",
  first_seen: "d.first_seen DESC",
  name: "lower(coalesce(nullif(d.name, ''), nullif(d.hostname, ''), d.ip)) ASC",
  ip: "inet(nullif(d.ip, '')) ASC NULLS LAST",
  traffic: "(d.bytes_out + d.bytes_in) DESC",
};

const SELECT = `
  SELECT d.id::int AS id, d.mac, d.ip, d.ips, d.hostname, d.vendor, d.os, d.type, d.vlan,
         coalesce(s.name, '') AS sensor, d.first_seen, d.last_seen,
         (d.bytes_out + d.bytes_in)::float8 AS bytes, d.flows::float8 AS flows,
         d.name, d.owner, d.location, d.notes, d.tags, d.criticality, d.approved, d.approved_by, d.approved_at,
         (SELECT count(*)::int FROM alerts a WHERE a.device_id = d.id AND a.status <> 'resolved') AS open_alerts,
         (SELECT count(*)::int FROM device_services v WHERE v.device_id = d.id) AS services
  FROM devices d LEFT JOIN sensors s ON s.id = d.sensor_id`;

export async function listDevices(f: DeviceFilter, limit = 1000): Promise<DeviceRow[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  const add = (sql: string, value: unknown) => {
    params.push(value);
    where.push(sql.replaceAll("$?", `$${params.length}`));
  };
  if (f.q) {
    params.push(`%${f.q.replace(/[\\%_]/g, "\\$&")}%`);
    const like = `$${params.length}`;
    params.push(f.q);
    const exact = `$${params.length}`;
    where.push(
      `(d.ip ILIKE ${like} OR d.mac ILIKE ${like} OR d.hostname ILIKE ${like} OR d.name ILIKE ${like}
        OR d.vendor ILIKE ${like} OR d.owner ILIKE ${like} OR d.location ILIKE ${like} OR d.type ILIKE ${like}
        OR ${exact} = ANY(d.tags) OR ${exact} = ANY(d.ips))`,
    );
  }
  if (f.type) add("d.type = $?", f.type === "-" ? "" : f.type);
  if (f.vlan) add("d.vlan = $?", f.vlan);
  switch (f.status) {
    case "new":
      where.push("d.first_seen > now() - interval '24 hours'");
      break;
    case "unapproved":
      where.push("NOT d.approved");
      break;
    case "active":
      where.push("d.last_seen > now() - interval '1 hour'");
      break;
    case "inactive":
      where.push("d.last_seen < now() - interval '7 days'");
      break;
    case "alerts":
      where.push("EXISTS (SELECT 1 FROM alerts a WHERE a.device_id = d.id AND a.status <> 'resolved')");
      break;
  }
  params.push(limit);
  const { rows } = await db().query<DeviceRow>(
    `${SELECT} ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ${SORTS[f.sort]} LIMIT $${params.length}`,
    params,
  );
  return rows;
}

export async function deviceStats() {
  const { rows } = await db().query<{
    total: number;
    new24: number;
    unapproved: number;
    active: number;
    types: { type: string; n: number }[];
    vlans: number[];
  }>(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE first_seen > now() - interval '24 hours')::int AS new24,
            count(*) FILTER (WHERE NOT approved)::int AS unapproved,
            count(*) FILTER (WHERE last_seen > now() - interval '1 hour')::int AS active,
            coalesce((SELECT json_agg(t ORDER BY t.n DESC) FROM (SELECT type, count(*)::int AS n FROM devices GROUP BY type) t), '[]') AS types,
            coalesce((SELECT array_agg(DISTINCT vlan ORDER BY vlan) FROM devices WHERE vlan > 0), '{}') AS vlans
     FROM devices`,
  );
  return rows[0];
}

export async function getDevice(id: number): Promise<DeviceRow | null> {
  const { rows } = await db().query<DeviceRow>(`${SELECT} WHERE d.id = $1`, [id]);
  return rows[0] ?? null;
}

export interface ServiceRow {
  proto: string;
  port: number;
  app: string;
  first_seen: Date;
  last_seen: Date;
  flows: number;
  external: boolean;
}

export async function deviceServices(id: number): Promise<ServiceRow[]> {
  const { rows } = await db().query<ServiceRow>(
    `SELECT proto, port, app, first_seen, last_seen, flows::float8 AS flows, external
     FROM device_services WHERE device_id = $1 ORDER BY external DESC, port`,
    [id],
  );
  return rows;
}

/** Traffico orario del dispositivo negli ultimi 7 giorni. */
export async function deviceTraffic(ips: string[]) {
  if (ips.length === 0) return [];
  return ch<{ t: number; sent: number; recv: number }>(
    `SELECT toUnixTimestamp(hour) AS t, sum(bytes_sent) AS sent, sum(bytes_recv) AS recv
     FROM hosts_1h WHERE hour >= toStartOfHour(now()) - INTERVAL 7 DAY AND ip IN {ips:Array(String)}
     GROUP BY t ORDER BY t`,
    { ips },
  );
}

export interface PeerRow {
  peer: string;
  name: string;
  domain: string;
  country: string;
  org: string;
  app: string;
  bytes: number;
  flows: number;
  failed: number;
  role: string;
}

/** Con chi ha parlato il dispositivo nelle ultime 24 ore. */
export async function devicePeers(ips: string[], limit = 25): Promise<PeerRow[]> {
  if (ips.length === 0) return [];
  return ch<PeerRow>(
    `SELECT if(src IN {ips:Array(String)}, dst, src) AS peer,
            any(if(src IN {ips:Array(String)}, dst_name, src_name)) AS name,
            anyIf(domain, domain != '') AS domain, any(country) AS country, any(as_org) AS org,
            topK(1)(app)[1] AS app, sum(bytes_out + bytes_in) AS bytes, count() AS flows, countIf(est = 0) AS failed,
            if(countIf(src IN {ips:Array(String)}) >= countIf(dst IN {ips:Array(String)}), 'client', 'server') AS role
     FROM flows WHERE ts >= now() - INTERVAL 1 DAY AND (src IN {ips:Array(String)} OR dst IN {ips:Array(String)})
     GROUP BY peer ORDER BY bytes DESC LIMIT {n:UInt32}`,
    { ips, n: limit },
    45,
  );
}

export async function deviceDomains(ips: string[], limit = 20) {
  if (ips.length === 0) return [];
  return ch<{ domain: string; queries: number; nx: number; last: string }>(
    `SELECT cutToFirstSignificantSubdomain(query) AS domain, count() AS queries, countIf(rcode = 'NXDOMAIN') AS nx, max(ts) AS last
     FROM dns WHERE ts >= now() - INTERVAL 1 DAY AND client IN {ips:Array(String)}
     GROUP BY domain ORDER BY queries DESC LIMIT {n:UInt32}`,
    { ips, n: limit },
  );
}

export async function deviceTypes(): Promise<string[]> {
  const { rows } = await db().query<{ type: string }>("SELECT DISTINCT type FROM devices WHERE type <> '' ORDER BY type");
  return rows.map((r) => r.type);
}
