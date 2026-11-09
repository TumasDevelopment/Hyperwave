import "server-only";
import { cache } from "react";
import { db } from "./db";

export interface DeviceRef {
  id: number;
  label: string;
}

/** Indirizzo IP -> dispositivo dell'inventario, per dare un nome agli indirizzi nelle tabelle. */
export const deviceNames = cache(async (): Promise<Map<string, DeviceRef>> => {
  const { rows } = await db().query<{ id: string; ip: string; ips: string[]; label: string }>(
    `SELECT id, ip, ips, coalesce(nullif(name, ''), nullif(hostname, ''), '') AS label
     FROM devices ORDER BY last_seen`,
  );
  const map = new Map<string, DeviceRef>();
  for (const row of rows) {
    const ref = { id: Number(row.id), label: row.label };
    for (const ip of row.ips ?? []) map.set(ip, ref);
    if (row.ip) map.set(row.ip, ref);
  }
  return map;
});
