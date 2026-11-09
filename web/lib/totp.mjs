// Codici a tempo (TOTP, RFC 6238) per l'accesso con due fattori, compatibili con
// Google Authenticator, Microsoft Authenticator, Aegis, 1Password e simili.
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const STEP_SECONDS = 30;
const DIGITS = 6;
// Un passo prima e uno dopo: copre l'orologio del telefono un po' avanti o indietro
const WINDOW = 1;

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Null se il testo non è base32. Spazi, trattini e minuscole sono ammessi. */
export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hotp(key, counter, digits = DIGITS) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hash = createHmac("sha1", key).update(message).digest();
  const offset = hash[hash.length - 1] & 15;
  const code = (hash.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

export const totpStep = (seconds) => Math.floor(seconds / STEP_SECONDS);

export function totp(key, seconds, digits = DIGITS) {
  return hotp(key, totpStep(seconds), digits);
}

const sameText = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/**
 * Il passo del codice se è giusto, altrimenti null. Un passo già usato (`lastStep`)
 * non vale una seconda volta: chi ha visto il codice non può riusarlo.
 * @param {string} secret
 * @param {unknown} code
 * @param {number} seconds
 * @param {number | string | null} [lastStep]
 * @returns {number | null}
 */
export function verifyTotp(secret, code, seconds, lastStep = null) {
  const key = base32Decode(secret);
  const typed = String(code ?? "").replace(/\s/g, "");
  if (!key || key.length === 0 || !/^\d{6}$/.test(typed)) return null;
  const now = totpStep(seconds);
  for (let delta = -WINDOW; delta <= WINDOW; delta++) {
    const step = now + delta;
    if (lastStep !== null && step <= Number(lastStep)) continue;
    if (sameText(hotp(key, step), typed)) return step;
  }
  return null;
}

export const newTotpSecret = () => base32Encode(randomBytes(20));

export function otpauthUri({ issuer, account, secret }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const query = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${query}`;
}

// Codici di recupero: 10 caratteri senza quelli che si confondono (0/O, 1/I)
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function newRecoveryCodes(count = 8) {
  return Array.from({ length: count }, () => {
    const bytes = randomBytes(10);
    const chars = [...bytes].map((byte) => RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length]).join("");
    return `${chars.slice(0, 5)}-${chars.slice(5)}`;
  });
}

export const normalizeRecoveryCode = (code) => String(code ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");

export const hashRecoveryCode = (code) => createHash("sha256").update(normalizeRecoveryCode(code)).digest();

/** La posizione del codice di recupero tra gli hash salvati, oppure -1. */
export function findRecoveryCode(hashes, code) {
  if (normalizeRecoveryCode(code).length !== 10) return -1;
  const hash = hashRecoveryCode(code);
  return hashes.findIndex((stored) => Buffer.from(stored).length === hash.length && timingSafeEqual(Buffer.from(stored), hash));
}
