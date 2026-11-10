import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

// Cifratura dei segreti salvati nel database (oggi: il segreto TOTP dei due fattori).
//
// AES-256-GCM con la chiave HW_SECRET_KEY (32 byte, in esadecimale o base64) presa da .env:
// chi ottiene una copia del database senza .env non può generare i codici di accesso.
// Ogni valore è legato al suo contesto (per esempio "totp:42", l'utente 42): copiato su un
// altro utente non si decifra.
//
// Formato: "enc:v1:<id chiave>:<base64url(iv 12 byte | testo cifrato | tag 16 byte)>".
// Rotazione: la chiave nuova in HW_SECRET_KEY, le vecchie in HW_SECRET_KEY_OLD (separate da
// virgole) finché `npm run utente -- cifra-segreti` non ha ricifrato tutto.
// Un valore senza prefisso è un segreto in chiaro di prima della cifratura: si legge ancora,
// e viene cifrato al primo uso o con lo stesso comando.

const PREFIX = "enc:v1:";

function parseKey(text) {
  const value = text.trim();
  const key = /^[0-9a-fA-F]{64}$/.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64");
  if (key.length !== 32) throw new Error("HW_SECRET_KEY deve essere di 32 byte: 64 caratteri esadecimali (openssl rand -hex 32)");
  return key;
}

const keyId = (key) => createHash("sha256").update("hyperwave secretbox").update(key).digest("hex").slice(0, 8);

let cache = { source: null, keys: null };

/** Chiavi da .env: la prima è quella con cui si cifra. */
function keys() {
  const source = `${process.env.HW_SECRET_KEY ?? ""}|${process.env.HW_SECRET_KEY_OLD ?? ""}`;
  if (cache.source !== source) {
    const list = [process.env.HW_SECRET_KEY ?? "", ...(process.env.HW_SECRET_KEY_OLD ?? "").split(",")]
      .map((k) => k.trim())
      .filter(Boolean)
      .map((k) => {
        const key = parseKey(k);
        return { id: keyId(key), key };
      });
    cache = { source, keys: process.env.HW_SECRET_KEY?.trim() ? list : null };
  }
  return cache.keys;
}

/** true se HW_SECRET_KEY è impostata e valida. */
export function hasSecretKey() {
  try {
    return keys() !== null;
  } catch {
    return false;
  }
}

export const isSealed = (stored) => typeof stored === "string" && stored.startsWith(PREFIX);

/** Cifra un segreto legandolo al contesto. Senza HW_SECRET_KEY si ferma: mai salvare in chiaro. */
export function sealSecret(plain, context) {
  const list = keys();
  if (!list) throw new Error("Manca HW_SECRET_KEY in .env: i segreti non si possono salvare cifrati (deploy/setup.sh la genera).");
  const { id, key } = list[0];
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`hyperwave:${context}`));
  const body = Buffer.concat([iv, cipher.update(String(plain), "utf8"), cipher.final(), cipher.getAuthTag()]);
  return `${PREFIX}${id}:${body.toString("base64url")}`;
}

/** Decifra un segreto. Restituisce anche se va ricifrato (in chiaro o con una chiave vecchia). */
export function openSecret(stored, context) {
  if (!isSealed(stored)) return { value: stored, stale: true };
  const rest = stored.slice(PREFIX.length);
  const colon = rest.indexOf(":");
  const id = rest.slice(0, colon);
  const body = Buffer.from(rest.slice(colon + 1), "base64url");
  const list = keys();
  const index = list ? list.findIndex((k) => k.id === id) : -1;
  if (index < 0) throw new Error(`Segreto cifrato con una chiave non disponibile (${id}): controllare HW_SECRET_KEY e HW_SECRET_KEY_OLD.`);
  if (body.length < 12 + 16) throw new Error("Segreto cifrato non valido.");
  const decipher = createDecipheriv("aes-256-gcm", list[index].key, body.subarray(0, 12));
  decipher.setAAD(Buffer.from(`hyperwave:${context}`));
  decipher.setAuthTag(body.subarray(body.length - 16));
  const value = Buffer.concat([decipher.update(body.subarray(12, body.length - 16)), decipher.final()]).toString("utf8");
  return { value, stale: index > 0 };
}

export const totpContext = (userId) => `totp:${userId}`;
