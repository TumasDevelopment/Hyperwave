import "server-only";
import { can, type Role, type SessionUser } from "../auth";
import { db, setting } from "../db";

/** Ruolo minimo per chiedere e scaricare pacchetti (Impostazioni → Generale). */
export async function pcapRole(): Promise<Role> {
  const role = await setting<string>("pcap_role", "admin").catch(() => "admin");
  return role === "analyst" ? "analyst" : "admin";
}

export async function canPcap(user: Pick<SessionUser, "role">) {
  return can(user, await pcapRole());
}

export interface PcapSensor {
  id: number;
  name: string;
  site: string;
  from: number; // ms, 0 se il buffer è vuoto
  to: number;
  bytes: number;
  online: boolean;
}

/** Sensori che conservano pacchetti, con il periodo disponibile dichiarato nell'ultimo heartbeat. */
export async function pcapSensors(): Promise<PcapSensor[]> {
  const { rows } = await db().query<PcapSensor>(
    `SELECT id::int AS id, name, site,
            coalesce((stats->'pcap'->>'from')::bigint, 0)::float8 AS "from",
            coalesce((stats->'pcap'->>'to')::bigint, 0)::float8 AS "to",
            coalesce((stats->'pcap'->>'bytes')::bigint, 0)::float8 AS bytes,
            coalesce(last_seen > now() - interval '2 minutes', false) AS online
       FROM sensors
      WHERE enabled AND stats ? 'pcap'
      ORDER BY name`,
  );
  return rows;
}

export interface PcapRequest {
  id: number;
  sensor: string;
  status: "pending" | "running" | "done" | "failed" | "expired";
  ip_a: string;
  ip_b: string | null;
  port: number | null;
  proto: string;
  t_from: Date;
  t_to: Date;
  reason: string;
  alert_id: number | null;
  requested_by: string;
  created_at: Date;
  finished_at: Date | null;
  packets: number;
  bytes: number;
  truncated: boolean;
  sha256: string;
  error: string;
  expires_at: Date | null;
}

const SELECT = `SELECT r.id::int AS id, s.name AS sensor, r.status, host(r.ip_a) AS ip_a, host(r.ip_b) AS ip_b, r.port, r.proto,
  r.t_from, r.t_to, r.reason, r.alert_id::int AS alert_id, r.requested_by, r.created_at, r.finished_at,
  r.packets::float8 AS packets, r.bytes::float8 AS bytes, r.truncated, r.sha256, r.error, r.expires_at
  FROM pcap_requests r JOIN sensors s ON s.id = r.sensor_id`;

export async function listPcapRequests(limit = 100): Promise<PcapRequest[]> {
  const { rows } = await db().query<PcapRequest>(`${SELECT} ORDER BY r.created_at DESC LIMIT $1`, [limit]);
  return rows;
}

export async function getPcapRequest(id: number): Promise<PcapRequest | null> {
  const { rows } = await db().query<PcapRequest>(`${SELECT} WHERE r.id = $1`, [id]);
  return rows[0] ?? null;
}

export const PCAP_STATUS_LABELS: Record<PcapRequest["status"], string> = {
  pending: "In attesa del sensore",
  running: "Estrazione in corso",
  done: "Pronto",
  failed: "Non riuscito",
  expired: "Scaduto",
};

/** Sensori consultabili dall'utente: vuoto se non ha i permessi (così le pagine non mostrano il collegamento). */
export async function pcapSensorsFor(user: Pick<SessionUser, "role">): Promise<PcapSensor[]> {
  return (await canPcap(user)) ? pcapSensors().catch(() => []) : [];
}

/**
 * Collegamento alla pagina Pacchetti già compilato, oppure null se nessun sensore in linea
 * ha ancora i pacchetti del periodo. Il periodo si limita alle ultime 6 ore (massimo consentito).
 */
export function pcapLink(
  sensors: PcapSensor[],
  q: { a: string; b?: string; port?: number; proto?: string; from: number; to: number; alert?: number; sensor?: string },
): string | null {
  const usable = sensors.filter((s) => s.online && s.from && s.from <= q.to);
  const s = usable.find((x) => x.name === q.sensor) ?? usable[0];
  if (!s || !q.a) return null;
  const to = Math.min(q.to, Date.now());
  const from = Math.max(q.from, to - 6 * 3600_000);
  const p = new URLSearchParams({ sensor: String(s.id), a: q.a, from: String(Math.floor(from)), to: String(Math.ceil(to)) });
  if (q.b) p.set("b", q.b);
  if (q.port) p.set("port", String(q.port));
  if (q.proto) p.set("proto", q.proto);
  if (q.alert) p.set("alert", String(q.alert));
  return `/pacchetti?${p}`;
}
