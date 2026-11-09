// Periodi selezionabili nelle pagine di analisi.

export const RANGES = {
  "15m": { label: "15 min", seconds: 900, bucket: 60 },
  "1h": { label: "1 ora", seconds: 3600, bucket: 60 },
  "6h": { label: "6 ore", seconds: 6 * 3600, bucket: 300 },
  "24h": { label: "24 ore", seconds: 86400, bucket: 900 },
  "7d": { label: "7 giorni", seconds: 7 * 86400, bucket: 3600 },
  "30d": { label: "30 giorni", seconds: 30 * 86400, bucket: 4 * 3600 },
} as const;

export type RangeKey = keyof typeof RANGES;

export function parseRange(value: string | string[] | undefined, fallback: RangeKey = "24h"): RangeKey {
  const v = Array.isArray(value) ? value[0] : value;
  return v && v in RANGES ? (v as RangeKey) : fallback;
}

/** Inizio e fine del periodo in secondi, con la fine arrotondata al minuto successivo. */
export function timeWindow(range: RangeKey, now = Date.now()) {
  const t1 = Math.ceil(now / 60_000) * 60;
  const t0 = t1 - RANGES[range].seconds;
  return { t0, t1, bucket: RANGES[range].bucket };
}

export const one = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) ?? "";
