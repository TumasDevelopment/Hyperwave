import "server-only";
import { ch, TS_RANGE } from "../ch";
import { isIpOrCidr } from "../form";
import { one, parseRange, RANGES, type RangeKey } from "../ranges";

export interface FlowFilter {
  range: RangeKey;
  /** Fine del periodo in secondi; 0 = adesso. Serve per guardare un momento preciso (per esempio un allarme). */
  at: number;
  ip: string;
  peer: string;
  port: number;
  proto: string;
  app: string;
  domain: string;
  country: string;
  direction: string;
  failed: boolean;
  minBytes: number;
  sensor: number;
}

type Params = Record<string, string | string[] | undefined>;

/** Legge e valida i filtri dall'indirizzo della pagina. I valori non validi vengono ignorati. */
export function parseFlowFilter(p: Params): FlowFilter {
  const ip = one(p.ip).trim();
  const peer = one(p.peer).trim();
  const port = Number(one(p.port));
  const proto = one(p.proto).toUpperCase();
  const country = one(p.cc).toUpperCase();
  const direction = one(p.dir);
  const minBytes = Number(one(p.min));
  const at = Number(one(p.at));
  const sensor = Number(one(p.sensor));
  return {
    range: parseRange(p.range, "1h"),
    at: Number.isInteger(at) && at > 1_500_000_000 && at < 4_000_000_000 ? at : 0,
    ip: isIpOrCidr(ip) ? ip : "",
    peer: isIpOrCidr(peer) ? peer : "",
    port: Number.isInteger(port) && port > 0 && port < 65536 ? port : 0,
    proto: ["TCP", "UDP", "ICMP", "ICMPV6"].includes(proto) ? (proto === "ICMPV6" ? "ICMPv6" : proto) : "",
    app: one(p.app).trim().slice(0, 60),
    domain: one(p.domain).trim().toLowerCase().slice(0, 120),
    country: /^[A-Z]{2}$/.test(country) ? country : "",
    direction: ["outbound", "inbound", "internal", "external"].includes(direction) ? direction : "",
    failed: one(p.failed) === "1",
    minBytes: Number.isFinite(minBytes) && minBytes > 0 ? Math.floor(minBytes) : 0,
    sensor: Number.isInteger(sensor) && sensor > 0 ? sensor : 0,
  };
}

/** I filtri come parametri d'indirizzo, per i link e l'export. */
export function flowFilterQuery(f: Partial<FlowFilter>) {
  const q = new URLSearchParams();
  if (f.range) q.set("range", f.range);
  if (f.at) q.set("at", String(f.at));
  if (f.ip) q.set("ip", f.ip);
  if (f.peer) q.set("peer", f.peer);
  if (f.port) q.set("port", String(f.port));
  if (f.proto) q.set("proto", f.proto);
  if (f.app) q.set("app", f.app);
  if (f.domain) q.set("domain", f.domain);
  if (f.country) q.set("cc", f.country);
  if (f.direction) q.set("dir", f.direction);
  if (f.failed) q.set("failed", "1");
  if (f.minBytes) q.set("min", String(f.minBytes));
  if (f.sensor) q.set("sensor", String(f.sensor));
  return q.toString();
}

const addrMatch = (column: string, param: string, value: string) =>
  value.includes("/") ? `isIPAddressInRange(${column}, {${param}:String})` : `${column} = {${param}:String}`;

function where(f: FlowFilter) {
  const end = f.at ? f.at + 60 : Math.ceil(Date.now() / 60_000) * 60;
  const params: Record<string, string | number> = { t0: end - RANGES[f.range].seconds, t1: end };
  const parts = [TS_RANGE];
  if (f.ip) {
    params.ip = f.ip;
    parts.push(`(${addrMatch("src", "ip", f.ip)} OR ${addrMatch("dst", "ip", f.ip)})`);
  }
  if (f.peer) {
    params.peer = f.peer;
    parts.push(`(${addrMatch("src", "peer", f.peer)} OR ${addrMatch("dst", "peer", f.peer)})`);
  }
  if (f.port) {
    params.port = f.port;
    parts.push("(dport = {port:UInt16} OR sport = {port:UInt16})");
  }
  if (f.proto) {
    params.proto = f.proto;
    parts.push("proto = {proto:String}");
  }
  if (f.app) {
    params.app = f.app;
    parts.push("app = {app:String}");
  }
  if (f.domain) {
    params.domain = f.domain;
    parts.push("positionCaseInsensitive(domain, {domain:String}) > 0");
  }
  if (f.country) {
    params.cc = f.country;
    parts.push("country = {cc:String}");
  }
  if (f.direction) {
    params.dir = f.direction;
    parts.push("direction = {dir:String}");
  }
  if (f.failed) parts.push("est = 0");
  if (f.minBytes) {
    params.min = f.minBytes;
    parts.push("bytes_out + bytes_in >= {min:UInt64}");
  }
  if (f.sensor) {
    params.sensor = f.sensor;
    parts.push("sensor_id = {sensor:UInt32}");
  }
  return { sql: parts.join(" AND "), params };
}

export interface FlowRow {
  ts: string;
  ts_end: string;
  sensor_id: number;
  vlan: number;
  proto: string;
  src: string;
  sport: number;
  dst: string;
  dport: number;
  direction: string;
  app: string;
  domain: string;
  bytes_out: number;
  bytes_in: number;
  pkts_out: number;
  pkts_in: number;
  flags: string;
  est: number;
  rtt: number;
  retrans: number;
  country: string;
  asn: number;
  as_org: string;
  src_name: string;
  dst_name: string;
}

export const FLOW_COLUMNS =
  "ts, ts_end, sensor_id, vlan, proto, src, sport, dst, dport, direction, app, domain, bytes_out, bytes_in, pkts_out, pkts_in, flags, est, rtt, retrans, country, asn, as_org, src_name, dst_name";

export async function searchFlows(f: FlowFilter, limit = 500): Promise<FlowRow[]> {
  const w = where(f);
  return ch<FlowRow>(
    `SELECT ${FLOW_COLUMNS} FROM flows WHERE ${w.sql} ORDER BY ts DESC LIMIT {lim:UInt32}`,
    { ...w.params, lim: limit },
    60,
  );
}

export interface FlowSummary {
  flows: number;
  bytes: number;
  hosts: number;
  failed: number;
}

export async function summarizeFlows(f: FlowFilter): Promise<FlowSummary> {
  const w = where(f);
  const [row] = await ch<FlowSummary>(
    `SELECT count() AS flows, sum(bytes_out + bytes_in) AS bytes, uniq(src) AS hosts, countIf(est = 0) AS failed
     FROM flows WHERE ${w.sql}`,
    w.params,
    60,
  );
  return row ?? { flows: 0, bytes: 0, hosts: 0, failed: 0 };
}

/** Elenco delle applicazioni viste, per il filtro. */
export async function knownApps(): Promise<string[]> {
  const rows = await ch<{ app: string }>(
    "SELECT DISTINCT app FROM traffic_1m WHERE minute >= now() - INTERVAL 7 DAY AND app != '' ORDER BY app LIMIT 300",
  );
  return rows.map((r) => r.app);
}
