import assert from "node:assert/strict";
import { test } from "node:test";
import { hashPassword, verifyPassword } from "../lib/password.mjs";

test("scrypt: verifica, sale diverso a ogni hash", async () => {
  const a = await hashPassword("una password lunga e giusta");
  const b = await hashPassword("una password lunga e giusta");
  assert.match(a, /^scrypt\$32768\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.notEqual(a, b);
  assert.equal(await verifyPassword("una password lunga e giusta", a), true);
  assert.equal(await verifyPassword("una password lunga e giustA", a), false);
  assert.equal(await verifyPassword("", a), false);
});

test("hash in formato sconosciuto: rifiutato senza errori", async () => {
  assert.equal(await verifyPassword("x", "md5$abc"), false);
  assert.equal(await verifyPassword("x", ""), false);
});
