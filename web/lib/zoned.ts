// Conversioni tra istanti e ora locale del fuso di Hyperwave (HW_TZ), per i campi datetime-local.
import { TZ } from "./format";

const parts = new Intl.DateTimeFormat("en-CA", {
  timeZone: TZ,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

function wall(ms: number) {
  const p = Object.fromEntries(parts.formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return { y: +p.year, mo: +p.month, d: +p.day, h: +p.hour, mi: +p.minute, s: +p.second };
}

/** Istante → "AAAA-MM-GGTHH:MM:SS" nell'ora locale, per il valore di un campo datetime-local. */
export function toLocalInput(ms: number) {
  const w = wall(ms);
  const two = (n: number) => String(n).padStart(2, "0");
  return `${w.y}-${two(w.mo)}-${two(w.d)}T${two(w.h)}:${two(w.mi)}:${two(w.s)}`;
}

/** "AAAA-MM-GGTHH:MM[:SS]" nell'ora locale → istante in ms, oppure null se non valido. */
export function fromLocalInput(value: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value.trim());
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map((x) => Number(x ?? 0));
  const asUtc = Date.UTC(y, mo - 1, d, h, mi, s || 0);
  if (Number.isNaN(asUtc)) return null;
  // differenza tra l'ora locale e UTC in quel momento; due passi coprono i cambi d'ora
  let guess = asUtc;
  for (let i = 0; i < 2; i++) {
    const w = wall(guess);
    const offset = Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s) - guess;
    guess = asUtc - offset;
  }
  return guess;
}

const two = (n: number) => String(n).padStart(2, "0");

/** Mezzanotte locale del giorno che contiene l'istante, spostata di `days` giorni. */
export function localMidnight(ms: number, days = 0): number {
  const w = wall(ms);
  const d = new Date(Date.UTC(w.y, w.mo - 1, w.d + days));
  return fromLocalInput(`${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}T00:00`) ?? ms;
}

/** Lunedì alle 00:00 (ora locale) della settimana che contiene l'istante. */
export function startOfWeek(ms: number): number {
  const w = wall(ms);
  const dow = new Date(Date.UTC(w.y, w.mo - 1, w.d)).getUTCDay(); // 0 = domenica
  return localMidnight(ms, -((dow + 6) % 7));
}
