// Colori e formati dei grafici, condivisi dai componenti nel browser.
import { fmtBps, fmtBpsTicks, fmtBytes, fmtCompact, fmtNum, TZ } from "./format";

export const CHART_COLORS = {
  surface: "#0e151d",
  axis: "#8a97a8",
  grid: "rgba(148, 163, 184, 0.10)",
  baseline: "rgba(148, 163, 184, 0.35)",
};

export function withAlpha(hex: string, alpha: number) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

export type ChartUnit = "bps" | "bytes" | "count";

export function fmtValue(value: number, unit: ChartUnit) {
  if (unit === "bps") return fmtBps(value);
  if (unit === "bytes") return fmtBytes(value);
  return fmtNum(Math.round(value));
}

export function fmtTicks(values: number[], unit: ChartUnit) {
  if (unit === "bps") return fmtBpsTicks(values);
  if (unit === "bytes") return values.map((v) => fmtBytes(v));
  return values.map((v) => fmtCompact(v));
}

const hourMinute = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
const dayMonth = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, day: "2-digit", month: "2-digit" });
const dayHour = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, day: "2-digit", month: "2-digit", hour: "2-digit" });

/** Etichetta dell'asse dei tempi: ore e minuti fino a un giorno, poi giorno e ora, poi solo il giorno. */
export function fmtAxisTime(seconds: number, rangeSeconds: number) {
  const d = new Date(seconds * 1000);
  if (rangeSeconds <= 86400) return hourMinute.format(d);
  if (rangeSeconds <= 3 * 86400) return dayHour.format(d).replace(",", "") + ":00";
  return dayMonth.format(d);
}
