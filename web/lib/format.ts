// Formattazione condivisa da server e browser. Le date usano il fuso dell'installazione
// (HW_TZ, predefinito Europe/Rome), così pagina e grafici mostrano la stessa ora.

export const TZ = process.env.NEXT_PUBLIC_HW_TZ || "Europe/Rome";

const num = new Intl.NumberFormat("it-IT");
const dec1 = new Intl.NumberFormat("it-IT", { maximumFractionDigits: 1 });
const dec2 = new Intl.NumberFormat("it-IT", { maximumFractionDigits: 2 });

export const fmtNum = (value: number | null | undefined) => (value === null || value === undefined ? "—" : num.format(value));

export function fmtCompact(value: number) {
  if (value >= 1e9) return `${dec1.format(value / 1e9)} mld`;
  if (value >= 1e6) return `${dec1.format(value / 1e6)} mln`;
  if (value >= 1e4) return `${dec1.format(value / 1e3)} mila`;
  return num.format(Math.round(value));
}

const BYTE_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"];
export function fmtBytes(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  let v = value;
  let i = 0;
  while (v >= 1000 && i < BYTE_UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? num.format(v) : v >= 100 ? num.format(Math.round(v)) : dec1.format(v)} ${BYTE_UNITS[i]}`;
}

const BIT_UNITS = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
export function fmtBps(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  let v = value;
  let i = 0;
  while (v >= 1000 && i < BIT_UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 ? num.format(Math.round(v)) : dec2.format(v)} ${BIT_UNITS[i]}`;
}

/** Tacche dell'asse dei bit/s: stessa unità per tutte, scelta sul valore più alto. */
export function fmtBpsTicks(values: number[]) {
  const top = Math.max(...values.map(Math.abs), 1);
  const i = Math.min(Math.floor(Math.log10(top) / 3), BIT_UNITS.length - 1);
  const div = 1000 ** i;
  return values.map((v) => `${dec1.format(v / div)} ${BIT_UNITS[i].replace("/s", "")}`);
}

const dateTime = new Intl.DateTimeFormat("it-IT", {
  timeZone: TZ,
  day: "2-digit",
  month: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});
const dateTimeSec = new Intl.DateTimeFormat("it-IT", {
  timeZone: TZ,
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});
const timeOnly = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dayOnly = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, day: "2-digit", month: "short", year: "numeric" });

type When = Date | string | number | null | undefined;
const toDate = (value: When) => {
  if (value === null || value === undefined || value === "") return null;
  const d = value instanceof Date ? value : new Date(typeof value === "string" && /^\d{4}-\d\d-\d\d \d/.test(value) ? `${value.replace(" ", "T")}Z` : value);
  return Number.isNaN(d.getTime()) ? null : d;
};

export const fmtDateTime = (value: When) => {
  const d = toDate(value);
  return d ? dateTime.format(d) : "—";
};
export const fmtDateTimeFull = (value: When) => {
  const d = toDate(value);
  return d ? dateTimeSec.format(d) : "—";
};
export const fmtTime = (value: When) => {
  const d = toDate(value);
  return d ? timeOnly.format(d) : "—";
};
export const fmtDay = (value: When) => {
  const d = toDate(value);
  return d ? dayOnly.format(d) : "—";
};

/** "3 min fa", "2 h fa", "5 g fa". */
export function fmtAgo(value: When, now = Date.now()) {
  const d = toDate(value);
  if (!d) return "mai";
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < 0) return "tra poco";
  if (s < 60) return `${s} s fa`;
  if (s < 3600) return `${Math.floor(s / 60)} min fa`;
  if (s < 86400) return `${Math.floor(s / 3600)} h fa`;
  return `${Math.floor(s / 86400)} g fa`;
}

export function fmtDuration(seconds: number) {
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${dec1.format(seconds / 3600)} h`;
  return `${dec1.format(seconds / 86400)} g`;
}

export const fmtPct = (value: number) => `${dec1.format(value)}%`;

/** Bandiera emoji da codice paese ISO a due lettere. */
export function flag(cc: string) {
  if (!/^[A-Z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

const regionNames = typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames(["it"], { type: "region" }) : null;
export function countryName(cc: string) {
  if (!cc) return "Sconosciuto";
  try {
    return regionNames?.of(cc) ?? cc;
  } catch {
    return cc;
  }
}
