import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeIndicator, parseIndicatorLines } from "../lib/intel.mjs";

test("riconosce indirizzi, reti, domini e URL", () => {
  assert.deepEqual(normalizeIndicator("198.51.100.7"), { value: "198.51.100.7", type: "ip" });
  assert.deepEqual(normalizeIndicator("198.51.100.7/32"), { value: "198.51.100.7", type: "ip" });
  assert.deepEqual(normalizeIndicator("198.51.100.0/24"), { value: "198.51.100.0/24", type: "cidr" });
  assert.deepEqual(normalizeIndicator("2001:DB8::/32"), { value: "2001:db8::/32", type: "cidr" });
  assert.deepEqual(normalizeIndicator("Evil.Example."), { value: "evil.example", type: "domain" });
  assert.deepEqual(normalizeIndicator("hxxps://bad[.]example/x.exe"), { value: "bad.example", type: "domain" });
  assert.deepEqual(normalizeIndicator("http://198.51.100.9:8080/a"), { value: "198.51.100.9", type: "ip" });
});

test("scarta voci non valide o troppo ampie", () => {
  for (const bad of ["", "localhost", "1.2", "0.0.0.0/0", "10.0.0.0/7", "198.51.100.1/33", "a..b.example", "-x.example", "versione-2.0"]) {
    assert.equal(normalizeIndicator(bad), null, bad);
  }
});

test("legge le righe del modulo con le note", () => {
  const { items, rejected } = parseIndicatorLines("# commento\n198.51.100.7 server C2 di Mario\nevil.example,phishing\nnon valido!\n198.51.100.7 doppione");
  assert.equal(items.length, 2);
  assert.equal(items[0].value, "198.51.100.7");
  assert.equal(items[0].note, "doppione");
  assert.equal(items[1].note, "phishing");
  assert.deepEqual(rejected, ["non valido!"]);
});
