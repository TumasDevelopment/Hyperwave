// Avvio del processo del sito: parte la generazione dei rapporti in sottofondo
// (HW_REPORTS=off la spegne, per esempio sulle istanze che devono solo servire pagine).
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.HW_REPORTS !== "off") {
    const { startReportWorker } = await import("./lib/reports/worker");
    startReportWorker();
  }
}
