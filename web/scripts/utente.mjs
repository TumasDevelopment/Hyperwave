// Gestione degli utenti da riga di comando, utile per il primo amministratore o se si perde l'accesso.
// La password generata non viene mai stampata: finisce in un file leggibile solo dal proprietario.
//
//   npm run utente -- aggiungi <nome> [--ruolo admin|analyst|viewer] [--genera-in FILE]
//   npm run utente -- reimposta <nome> [--genera-in FILE]     nuova password temporanea, chiude le sessioni
//   npm run utente -- sblocca <nome>                          riattiva un utente disattivato
//   npm run utente -- togli-2fa <nome>                        disattiva i due fattori (telefono perso)
//   npm run utente -- elenco
//
// Senza --genera-in la password va in ./password-<nome>.txt (permessi 600). Al primo accesso va cambiata.
import { randomInt } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import pg from "pg";
import { hashPassword } from "../lib/password.mjs";

for (const file of [".env", "../.env"]) {
  if (existsSync(file)) process.loadEnvFile(file);
}

const USERNAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,39}$/;
const ROLES = ["admin", "analyst", "viewer"];
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

function fail(message) {
  console.error(message);
  process.exit(1);
}

function tempPassword() {
  let out = "";
  for (let i = 0; i < 20; i++) out += ALPHABET[randomInt(ALPHABET.length)];
  return out.match(/.{5}/g).join("-");
}

function option(args, name) {
  const at = args.indexOf(name);
  if (at === -1) return undefined;
  const value = args[at + 1];
  if (!value || value.startsWith("--")) fail(`Manca il valore di ${name}.`);
  return value;
}

function savePassword(username, password, target) {
  const file = resolve(target || `password-${username}.txt`);
  // wx: non sovrascrive un file esistente, che potrebbe contenere un'altra password.
  try {
    writeFileSync(file, `${password}\n`, { mode: 0o600, flag: "wx" });
  } catch (error) {
    if (error.code === "EEXIST") fail(`Il file ${file} esiste già: cancellalo o scegli un altro percorso con --genera-in.`);
    throw error;
  }
  return file;
}

async function main() {
  const [command, username, ...rest] = process.argv.slice(2);
  if (!process.env.DATABASE_URL) fail("DATABASE_URL non impostata: esegui il comando dalla cartella web con ../.env presente.");
  if (!command || command === "aiuto" || command === "--help") {
    console.log("Uso: utente aggiungi|reimposta|sblocca|togli-2fa <nome> [--ruolo R] [--genera-in FILE] · utente elenco");
    return;
  }
  const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    if (command === "elenco") {
      const { rows } = await client.query(
        "SELECT username, role, disabled, must_change, totp_enabled, last_login FROM users ORDER BY lower(username)",
      );
      if (rows.length === 0) console.log("Nessun utente.");
      for (const u of rows) {
        const flags = [u.disabled && "disattivato", u.must_change && "password temporanea", u.totp_enabled && "2FA"].filter(Boolean);
        console.log(`${u.username.padEnd(24)} ${u.role.padEnd(8)} ${flags.join(", ")}`);
      }
      return;
    }
    if (!username || !USERNAME.test(username)) fail("Nome utente: 2-40 caratteri tra lettere, cifre, punto, trattino e underscore.");

    if (command === "aggiungi") {
      const role = rest.includes("--admin") ? "admin" : option(rest, "--ruolo") || "viewer";
      if (!ROLES.includes(role)) fail(`Ruolo non valido: usa ${ROLES.join(", ")}.`);
      const exists = await client.query("SELECT 1 FROM users WHERE lower(username) = lower($1)", [username]);
      if (exists.rowCount) fail(`L'utente ${username} esiste già. Per una nuova password usa: utente reimposta ${username}`);
      const password = tempPassword();
      const file = savePassword(username, password, option(rest, "--genera-in"));
      await client.query("INSERT INTO users (username, password_hash, role, must_change) VALUES ($1, $2, $3, true)", [
        username,
        await hashPassword(password),
        role,
      ]);
      await client.query("INSERT INTO audit_log (username, action, target, detail) VALUES ('(console)', 'user.create', $1, $2)", [
        username,
        JSON.stringify({ role, cli: true }),
      ]);
      console.log(`Utente ${username} (${role}) creato. Password temporanea salvata in ${file} (solo il proprietario può leggerla).`);
      console.log("Al primo accesso il sito chiede di cambiarla. Poi cancella il file.");
      return;
    }

    const found = await client.query("SELECT id FROM users WHERE lower(username) = lower($1)", [username]);
    if (!found.rowCount) fail(`L'utente ${username} non esiste.`);
    const id = found.rows[0].id;

    if (command === "reimposta") {
      const password = tempPassword();
      const file = savePassword(username, password, option(rest, "--genera-in"));
      await client.query("BEGIN");
      await client.query("UPDATE users SET password_hash = $2, must_change = true WHERE id = $1", [id, await hashPassword(password)]);
      await client.query("DELETE FROM sessions WHERE user_id = $1", [id]);
      await client.query("INSERT INTO audit_log (username, action, target, detail) VALUES ('(console)', 'user.password', $1, $2)", [
        username,
        JSON.stringify({ cli: true }),
      ]);
      await client.query("COMMIT");
      console.log(`Nuova password temporanea per ${username} salvata in ${file}. Le sessioni aperte sono state chiuse.`);
      return;
    }
    if (command === "sblocca") {
      await client.query("UPDATE users SET disabled = false WHERE id = $1", [id]);
      await client.query("INSERT INTO audit_log (username, action, target, detail) VALUES ('(console)', 'user.update', $1, $2)", [
        username,
        JSON.stringify({ disabled: false, cli: true }),
      ]);
      console.log(`Utente ${username} riattivato.`);
      return;
    }
    if (command === "togli-2fa") {
      await client.query(
        "UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_last_step = NULL, recovery_codes = '{}' WHERE id = $1",
        [id],
      );
      await client.query("INSERT INTO audit_log (username, action, target, detail) VALUES ('(console)', '2fa.reset', $1, $2)", [
        username,
        JSON.stringify({ cli: true }),
      ]);
      console.log(`Due fattori disattivati per ${username}: al prossimo accesso basta la password.`);
      return;
    }
    fail(`Comando sconosciuto: ${command}.`);
  } finally {
    await client.end();
  }
}

main().catch((error) => fail(`Errore: ${error.message}`));
