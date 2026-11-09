// Aiuti per le azioni dei moduli. Stanno fuori dai file "use server", che possono esportare solo funzioni asincrone.

export const text = (form: FormData, key: string, max = 500) => String(form.get(key) ?? "").trim().slice(0, max);
export const isUniqueViolation = (error: unknown) => (error as { code?: string }).code === "23505";

export type FormState =
  | {
      ok?: boolean;
      error?: string;
      message?: string;
      /** Token mostrato una volta sola (sensori, API). */
      token?: string;
      next?: "totp" | "password";
      data?: Record<string, unknown>;
    }
  | undefined;

/** Converte un errore lanciato in un'azione in un messaggio per il modulo. */
export function failure(error: unknown): FormState {
  const message = error instanceof Error ? error.message : String(error);
  if (/sessione|permessi|password dal tuo profilo/i.test(message)) return { error: message };
  console.error("Azione non riuscita:", error);
  return { error: "Operazione non riuscita. Riprova; se continua, controlla il log del sito." };
}

/** Indirizzo IP o rete in notazione CIDR (IPv4 o IPv6). */
export function isIpOrCidr(value: string) {
  const [ip, bits, extra] = value.split("/");
  if (extra !== undefined) return false;
  const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(ip);
  const v6 = !v4 && /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(":") && ip.split("::").length <= 2;
  if (!v4 && !v6) return false;
  if (bits === undefined) return true;
  const n = Number(bits);
  return /^\d{1,3}$/.test(bits) && n >= 0 && n <= (v4 ? 32 : 128);
}

/** Elenco di reti separate da virgole o a capo; restituisce null se una voce non è valida. */
export function parseNets(value: string): string[] | null {
  const items = value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return items.every(isIpOrCidr) ? items : null;
}
