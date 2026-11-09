import "server-only";
import { createHash, randomBytes } from "node:crypto";

// Senza caratteri che si confondono (0/O, 1/l/I): la password temporanea si detta o si copia a mano.
const ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** Password temporanea di 20 caratteri in gruppi da 5 (circa 115 bit). */
export function newTempPassword() {
  const bytes = randomBytes(40);
  let out = "";
  for (const byte of bytes) {
    // scarta i valori che renderebbero la distribuzione non uniforme
    if (byte >= 256 - (256 % ALPHABET.length)) continue;
    out += ALPHABET[byte % ALPHABET.length];
    if (out.length === 20) break;
  }
  if (out.length < 20) return newTempPassword();
  return out.match(/.{5}/g)!.join("-");
}

/** Token del sensore, nello stesso formato dell'hub: "hws_" + 43 caratteri; nel database resta lo sha256. */
export function newSensorToken() {
  const token = `hws_${randomBytes(32).toString("base64url")}`;
  return { token, hash: createHash("sha256").update(token).digest() };
}

export const MIN_PASSWORD = 12;

/** Controlli minimi su una nuova password; restituisce il messaggio d'errore oppure null. */
export function passwordProblem(password: string, username: string) {
  if (password.length < MIN_PASSWORD) return `La password deve avere almeno ${MIN_PASSWORD} caratteri.`;
  if (password.length > 200) return "La password è troppo lunga.";
  if (username && password.toLowerCase().includes(username.toLowerCase())) return "La password non può contenere il nome utente.";
  if (new Set(password).size < 6) return "La password ha troppi caratteri ripetuti.";
  return null;
}
