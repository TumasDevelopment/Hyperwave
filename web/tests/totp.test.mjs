import assert from "node:assert/strict";
import { test } from "node:test";
import {
  base32Decode,
  base32Encode,
  findRecoveryCode,
  hashRecoveryCode,
  hotp,
  newRecoveryCodes,
  newTotpSecret,
  otpauthUri,
  totp,
  verifyTotp,
} from "../lib/totp.mjs";

// chiave dei vettori di prova di RFC 4226 e RFC 6238 (SHA-1)
const RFC_KEY = Buffer.from("12345678901234567890");

test("HOTP: vettori di RFC 4226", () => {
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  expected.forEach((code, counter) => assert.equal(hotp(RFC_KEY, counter), code));
});

test("TOTP: vettori di RFC 6238 a 8 cifre", () => {
  assert.equal(totp(RFC_KEY, 59, 8), "94287082");
  assert.equal(totp(RFC_KEY, 1111111109, 8), "07081804");
  assert.equal(totp(RFC_KEY, 1234567890, 8), "89005924");
  assert.equal(totp(RFC_KEY, 20000000000, 8), "65353130");
});

test("base32: andata e ritorno, minuscole e spazi", () => {
  const secret = newTotpSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.deepEqual(base32Encode(base32Decode(secret)), secret);
  assert.deepEqual(base32Decode(secret.toLowerCase().replace(/(.{4})/g, "$1 ")), base32Decode(secret));
});

test("verifyTotp: finestra di ±1 passo e niente riuso", () => {
  const secret = base32Encode(RFC_KEY);
  const now = 1_700_000_000;
  const code = totp(RFC_KEY, now);
  const step = verifyTotp(secret, code, now);
  assert.equal(step, Math.floor(now / 30));
  assert.equal(verifyTotp(secret, code.replace(/(\d{3})/, "$1 "), now), step, "gli spazi non contano");
  assert.equal(verifyTotp(secret, code, now + 30), step, "il codice precedente vale ancora");
  assert.equal(verifyTotp(secret, code, now + 120), null, "troppo vecchio");
  assert.equal(verifyTotp(secret, code, now, step), null, "già usato");
  assert.equal(verifyTotp(secret, "12345", now), null);
  assert.equal(verifyTotp(secret, "abcdef", now), null);
  assert.equal(verifyTotp(secret, undefined, now), null);
});

test("codici di recupero: formato, ricerca, maiuscole e trattini", () => {
  const codes = newRecoveryCodes(10);
  assert.equal(codes.length, 10);
  assert.equal(new Set(codes).size, 10);
  for (const c of codes) assert.match(c, /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/);
  const hashes = codes.map(hashRecoveryCode);
  assert.equal(findRecoveryCode(hashes, codes[3]), 3);
  assert.equal(findRecoveryCode(hashes, codes[7].toLowerCase().replace("-", " ")), 7);
  assert.equal(findRecoveryCode(hashes, "AAAAA-AAAAA"), -1);
  assert.equal(findRecoveryCode(hashes, "corto"), -1);
});

test("otpauth: parametri per l'app di autenticazione", () => {
  const uri = new URL(otpauthUri({ issuer: "Hyperwave", account: "mario rossi", secret: "ABCDEFGH" }));
  assert.equal(uri.protocol, "otpauth:");
  assert.equal(uri.searchParams.get("secret"), "ABCDEFGH");
  assert.equal(uri.searchParams.get("digits"), "6");
  assert.equal(uri.searchParams.get("period"), "30");
  assert.match(decodeURIComponent(uri.pathname), /Hyperwave:mario rossi$/);
});
