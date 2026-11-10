import "server-only";
import { clientAddress } from "./auth";
import { db } from "./db";

/**
 * Scrive una riga nel registro delle attività. Non blocca mai l'azione: se il database
 * non risponde, l'errore finisce nel log del sito.
 */
export async function audit(
  actor: { username: string } | null,
  action: string,
  target = "",
  detail: Record<string, unknown> = {},
) {
  try {
    await db().query("INSERT INTO audit_log (username, action, target, detail, ip) VALUES ($1, $2, $3, $4, $5)", [
      actor?.username ?? "",
      action,
      target.slice(0, 200),
      JSON.stringify(detail),
      await clientAddress(),
    ]);
  } catch (error) {
    console.error("Registro delle attività non scritto:", error);
  }
}

export const AUDIT_LABELS: Record<string, string> = {
  "login.ok": "Accesso",
  "login.failed": "Accesso non riuscito",
  "login.locked": "Accesso bloccato",
  "login.2fa_failed": "Codice di accesso errato",
  "login.recovery": "Accesso con codice di recupero",
  logout: "Uscita",
  "password.change": "Cambio password",
  "2fa.enable": "Due fattori attivati",
  "2fa.disable": "Due fattori disattivati",
  "2fa.reset": "Due fattori azzerati",
  "user.create": "Utente creato",
  "user.update": "Utente modificato",
  "user.password": "Password reimpostata",
  "user.delete": "Utente eliminato",
  "session.revoke": "Sessioni chiuse",
  "apitoken.create": "Token API creato",
  "apitoken.revoke": "Token API revocato",
  "live.on": "Live acceso",
  "live.off": "Live spento",
  "settings.config": "Impostazioni di rete",
  "rule.update": "Regola modificata",
  "suppression.create": "Eccezione creata",
  "suppression.delete": "Eccezione eliminata",
  "sensor.create": "Sensore aggiunto",
  "sensor.update": "Sensore modificato",
  "sensor.rotate": "Token del sensore rinnovato",
  "sensor.delete": "Sensore eliminato",
  "alert.status": "Stato di un allarme",
  "alert.assign": "Allarme assegnato",
  "alert.note": "Nota su un allarme",
  "alert.bulk": "Modifica di più allarmi",
  "device.update": "Dispositivo modificato",
  "device.approve": "Dispositivo approvato",
  "device.bulk_approve": "Dispositivi approvati",
  "device.delete": "Dispositivo eliminato",
  "intel.feed.create": "Elenco di minacce aggiunto",
  "intel.feed.update": "Elenco di minacce modificato",
  "intel.feed.delete": "Elenco di minacce eliminato",
  "intel.feed.fetch": "Elenco di minacce aggiornato",
  "intel.feed.retro": "Ricerca di minacce nello storico",
  "intel.indicator.add": "Indicatori di minaccia aggiunti",
  "intel.indicator.delete": "Indicatore di minaccia tolto",
  "customrule.create": "Regola personalizzata creata",
  "customrule.update": "Regola personalizzata modificata",
  "customrule.delete": "Regola personalizzata eliminata",
  "export.flows": "Export dei flussi",
  "export.devices": "Export dei dispositivi",
  "export.audit": "Export del registro",
};
