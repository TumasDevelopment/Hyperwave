import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { beforeEach, test } from "node:test";
import { hasSecretKey, isSealed, openSecret, sealSecret, totpContext } from "../lib/secretbox.mjs";

const hexKey = () => randomBytes(32).toString("hex");

beforeEach(() => {
  delete process.env.HW_SECRET_KEY;
  delete process.env.HW_SECRET_KEY_OLD;
});

test("senza chiave non si cifra (mai salvare in chiaro per sbaglio)", () => {
  assert.equal(hasSecretKey(), false);
  assert.throws(() => sealSecret("JBSWY3DPEHPK3PXP", totpContext(1)), /HW_SECRET_KEY/);
});

test("chiave non valida: rifiutata", () => {
  process.env.HW_SECRET_KEY = "troppo-corta";
  assert.equal(hasSecretKey(), false);
  assert.throws(() => sealSecret("x", "c"), /32 byte/);
});

test("andata e ritorno con chiave esadecimale e base64", () => {
  for (const key of [hexKey(), randomBytes(32).toString("base64")]) {
    process.env.HW_SECRET_KEY = key;
    const sealed = sealSecret("JBSWY3DPEHPK3PXP", totpContext(42));
    assert.ok(isSealed(sealed));
    assert.ok(!sealed.includes("JBSWY3DPEHPK3PXP"));
    assert.deepEqual(openSecret(sealed, totpContext(42)), { value: "JBSWY3DPEHPK3PXP", stale: false });
  }
});

test("ogni cifratura è diversa (IV casuale)", () => {
  process.env.HW_SECRET_KEY = hexKey();
  assert.notEqual(sealSecret("abc", "c"), sealSecret("abc", "c"));
});

test("legato al contesto: copiato su un altro utente non si decifra", () => {
  process.env.HW_SECRET_KEY = hexKey();
  const sealed = sealSecret("JBSWY3DPEHPK3PXP", totpContext(1));
  assert.throws(() => openSecret(sealed, totpContext(2)));
});

test("manomissione: rifiutata", () => {
  process.env.HW_SECRET_KEY = hexKey();
  const sealed = sealSecret("JBSWY3DPEHPK3PXP", "c");
  const body = Buffer.from(sealed.split(":")[3], "base64url");
  body[14] ^= 1;
  const tampered = sealed.split(":").slice(0, 3).join(":") + ":" + body.toString("base64url");
  assert.throws(() => openSecret(tampered, "c"));
  assert.throws(() => openSecret(sealed.slice(0, 20), "c"));
});

test("valore in chiaro di prima della cifratura: leggibile e da ricifrare", () => {
  assert.deepEqual(openSecret("JBSWY3DPEHPK3PXP", "c"), { value: "JBSWY3DPEHPK3PXP", stale: true });
});

test("rotazione: la chiave vecchia legge ancora e segnala la ricifratura", () => {
  const oldKey = hexKey();
  process.env.HW_SECRET_KEY = oldKey;
  const sealed = sealSecret("SEGRETO", "c");

  process.env.HW_SECRET_KEY = hexKey();
  process.env.HW_SECRET_KEY_OLD = ` ${hexKey()}, ${oldKey} `;
  assert.deepEqual(openSecret(sealed, "c"), { value: "SEGRETO", stale: true });
  const resealed = sealSecret("SEGRETO", "c");
  assert.deepEqual(openSecret(resealed, "c"), { value: "SEGRETO", stale: false });

  delete process.env.HW_SECRET_KEY_OLD;
  assert.throws(() => openSecret(sealed, "c"), /chiave non disponibile/);
});
