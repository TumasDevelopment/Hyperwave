import "server-only";
import { connect, type NatsConnection } from "nats";

// Una sola connessione a NATS per processo: la usano i comandi all'hub e i flussi in tempo reale.
const globalForNats = globalThis as unknown as { hwNats?: Promise<NatsConnection> };

export function nats(): Promise<NatsConnection> {
  if (!globalForNats.hwNats) {
    const servers = (process.env.NATS_URL || "nats://127.0.0.1:4222").replace(/^nats:\/\//, "");
    const pending = connect({
      servers,
      token: process.env.NATS_TOKEN || undefined,
      name: "hyperwave-web",
      maxReconnectAttempts: -1,
      reconnectTimeWait: 2000,
    });
    pending.catch(() => {
      // al prossimo uso si riprova da capo
      globalForNats.hwNats = undefined;
    });
    globalForNats.hwNats = pending;
  }
  return globalForNats.hwNats;
}

/**
 * Avvisa l'hub che qualcosa è cambiato: "settings" (live e configurazione), "rules", "sensors",
 * "intel" (elenchi di minaccia, con un comando facoltativo: {fetch: id} o {retro: id}).
 * Se NATS non risponde non è grave: l'hub rilegge comunque le impostazioni ogni pochi secondi.
 */
export async function notifyHub(what: "settings" | "rules" | "sensors" | "intel", payload?: Record<string, unknown>) {
  try {
    const nc = await nats();
    nc.publish(`hw.control.${what}`, payload ? new TextEncoder().encode(JSON.stringify(payload)) : undefined);
    await nc.flush();
  } catch (error) {
    console.error("Avviso all'hub non inviato:", (error as Error).message);
  }
}
