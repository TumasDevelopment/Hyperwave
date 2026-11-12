import { TZ } from "../format";
import { localMidnight, startOfWeek } from "../zoned";

export const REPORT_PERIODS = {
  prevweek: "Settimana scorsa (lunedì-domenica)",
  last7: "Ultimi 7 giorni",
  prevmonth: "Mese scorso",
  last30: "Ultimi 30 giorni",
} as const;

export type ReportPeriod = keyof typeof REPORT_PERIODS;

const dayOfMonth = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, day: "numeric" });

/** Mezzanotte locale del primo giorno del mese che contiene l'istante. */
function startOfMonth(ms: number) {
  const day = Number(dayOfMonth.format(new Date(ms)));
  return localMidnight(ms, 1 - day);
}

/** Inizio e fine (ms) del periodo: giorni interi nell'ora locale, tranne "ultimi N giorni". */
export function reportPeriod(period: ReportPeriod, now: number): { from: number; to: number } {
  switch (period) {
    case "prevweek": {
      const to = startOfWeek(now);
      return { from: startOfWeek(to - 3 * 86400_000), to };
    }
    case "prevmonth": {
      const to = startOfMonth(now);
      return { from: startOfMonth(to - 86400_000), to };
    }
    case "last30":
      return { from: now - 30 * 86400_000, to: now };
    default:
      return { from: now - 7 * 86400_000, to: now };
  }
}
