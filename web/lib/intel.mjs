// Indicatori di minaccia inseriti dalle persone: stesse regole dell'hub (internal/hub/intel.go).
import { isIP } from "node:net";

export const INTEL_CATEGORIES = {
  malware: "Malware",
  c2: "Comando e controllo",
  phishing: "Phishing",
  hijacked: "Reti criminali",
  compromised: "Host compromessi",
  scanner: "Scansioni e attacchi",
  tor: "Tor",
  spam: "Spam",
  other: "Altro",
};

const DEFANG = [
  [/\[\.\]|\(\.\)|\{\.\}/g, "."],
  [/\[:\]/g, ":"],
  [/^hxxp/i, "http"],
];

function validDomain(d) {
  if (d.length < 4 || d.length > 253 || !d.includes(".")) return false;
  const labels = d.split(".");
  if (!labels.every((l) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l))) return false;
  const tld = labels[labels.length - 1];
  return tld.length >= 2 && !/^\d+$/.test(tld);
}

/**
 * Riconosce un indicatore: IP, rete CIDR, dominio o URL (se ne prende il nome).
 * Restituisce { value, type } normalizzato oppure null.
 */
export function normalizeIndicator(raw) {
  let s = String(raw ?? "").trim();
  for (const [re, to] of DEFANG) s = s.replace(re, to);
  if (!s || s.length > 2048) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  }
  s = s.replace(/^\[|\]$/g, "");
  const [addr, bits, extra] = s.split("/");
  if (extra === undefined && isIP(addr)) {
    const v6 = isIP(addr) === 6;
    const max = v6 ? 128 : 32;
    if (bits === undefined || Number(bits) === max) {
      if (bits !== undefined && !/^\d+$/.test(bits)) return null;
      return { value: v6 ? addr.toLowerCase() : addr, type: "ip" };
    }
    if (!/^\d{1,3}$/.test(bits)) return null;
    const n = Number(bits);
    if (n > max || n < (v6 ? 16 : 8)) return null;
    // la rete vera (bit dell'host azzerati) la calcola il database
    return { value: `${v6 ? addr.toLowerCase() : addr}/${n}`, type: "cidr" };
  }
  const d = s.toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  if (!validDomain(d)) return null;
  return { value: d, type: "domain" };
}

/**
 * Legge l'elenco scritto nel modulo: una voce per riga, con una nota facoltativa dopo uno
 * spazio o un #. Restituisce le voci valide e le righe scartate.
 */
export function parseIndicatorLines(text, limit = 5000) {
  const items = new Map();
  const rejected = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [token, ...rest] = line.split(/[\s,;]+/);
    const ind = normalizeIndicator(token);
    if (!ind) {
      rejected.push(line.slice(0, 80));
      continue;
    }
    const note = rest.join(" ").replace(/^#\s*/, "").slice(0, 300);
    items.set(ind.value, { ...ind, note });
    if (items.size > limit) break;
  }
  return { items: [...items.values()], rejected };
}
