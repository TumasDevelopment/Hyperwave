"use server";

import { revalidatePath } from "next/cache";
import { newApiToken } from "../apitokens";
import { audit } from "../audit";
import { actionUser, type Role } from "../auth";
import { db, transaction } from "../db";
import { failure, isUniqueViolation, parseNets, text, type FormState } from "../form";
import { notifyHub } from "../nats";
import { hashPassword } from "../password.mjs";
import { newSensorToken, newTempPassword } from "../secrets";

const ROLES: Role[] = ["admin", "analyst", "viewer"];
const USERNAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,39}$/;
const id = (form: FormData) => {
  const n = Number(form.get("id"));
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("Identificativo non valido.");
  return n;
};

// ----------------------------------------------------------------------- utenti

export async function createUser(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const username = text(form, "username", 40);
    const role = text(form, "role") as Role;
    const email = text(form, "email", 200);
    if (!USERNAME.test(username)) return { error: "Nome utente: 2-40 caratteri tra lettere, cifre, punto, trattino e underscore." };
    if (!ROLES.includes(role)) return { error: "Ruolo non valido." };
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Indirizzo email non valido." };
    const password = newTempPassword();
    await db().query(
      "INSERT INTO users (username, display_name, email, password_hash, role, must_change) VALUES ($1, $2, $3, $4, $5, true)",
      [username, text(form, "display_name", 100), email, await hashPassword(password), role],
    );
    await audit(actor, "user.create", username, { role });
    revalidatePath("/impostazioni/utenti");
    return {
      ok: true,
      message: `Utente ${username} creato. Consegna la password temporanea in modo sicuro: al primo accesso dovrà cambiarla.`,
      token: password,
    };
  } catch (error) {
    if (isUniqueViolation(error)) return { error: "Esiste già un utente con questo nome." };
    return failure(error);
  }
}

export async function updateUser(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const userId = id(form);
    const role = text(form, "role") as Role;
    const disabled = form.get("disabled") === "on";
    const email = text(form, "email", 200);
    if (!ROLES.includes(role)) return { error: "Ruolo non valido." };
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Indirizzo email non valido." };
    if (userId === actor.id && (disabled || role !== "admin")) return { error: "Non puoi togliere a te stesso il ruolo di amministratore o disattivarti." };
    const username = await transaction(async (client) => {
      const { rows } = await client.query<{ username: string }>(
        "UPDATE users SET display_name = $2, email = $3, role = $4, disabled = $5 WHERE id = $1 RETURNING username",
        [userId, text(form, "display_name", 100), email, role, disabled],
      );
      if (!rows[0]) throw new Error("Utente non trovato.");
      const left = await client.query<{ n: number }>("SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND NOT disabled");
      if ((left.rows[0]?.n ?? 0) < 1) throw new Error("Deve restare almeno un amministratore attivo.");
      if (disabled) await client.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
      return rows[0].username;
    });
    await audit(actor, "user.update", username, { role, disabled });
    revalidatePath("/impostazioni/utenti");
    return { ok: true, message: "Utente salvato." };
  } catch (error) {
    if (error instanceof Error && /amministratore|non trovato/.test(error.message)) return { error: error.message };
    return failure(error);
  }
}

export async function resetUserPassword(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const userId = id(form);
    const password = newTempPassword();
    const { rows } = await db().query<{ username: string }>(
      "UPDATE users SET password_hash = $2, must_change = true WHERE id = $1 RETURNING username",
      [userId, await hashPassword(password)],
    );
    if (!rows[0]) return { error: "Utente non trovato." };
    await db().query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    await audit(actor, "user.password", rows[0].username);
    revalidatePath("/impostazioni/utenti");
    return { ok: true, message: `Nuova password temporanea per ${rows[0].username}. Le sue sessioni sono state chiuse.`, token: password };
  } catch (error) {
    return failure(error);
  }
}

export async function resetUserTotp(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const { rows } = await db().query<{ username: string }>(
      `UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL, recovery_codes = '{}'
       WHERE id = $1 RETURNING username`,
      [id(form)],
    );
    if (!rows[0]) return { error: "Utente non trovato." };
    await audit(actor, "2fa.reset", rows[0].username);
    revalidatePath("/impostazioni/utenti");
    return { ok: true, message: `Due fattori azzerati per ${rows[0].username}.` };
  } catch (error) {
    return failure(error);
  }
}

export async function revokeUserSessions(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const userId = id(form);
    const res = await db().query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    await audit(actor, "session.revoke", String(userId), { sessions: res.rowCount ?? 0 });
    revalidatePath("/impostazioni/utenti");
    return { ok: true, message: `Sessioni chiuse: ${res.rowCount ?? 0}.` };
  } catch (error) {
    return failure(error);
  }
}

export async function deleteUser(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const userId = id(form);
    if (userId === actor.id) return { error: "Non puoi eliminare te stesso." };
    const username = await transaction(async (client) => {
      const { rows } = await client.query<{ username: string }>("DELETE FROM users WHERE id = $1 RETURNING username", [userId]);
      if (!rows[0]) throw new Error("Utente non trovato.");
      const left = await client.query<{ n: number }>("SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND NOT disabled");
      if ((left.rows[0]?.n ?? 0) < 1) throw new Error("Deve restare almeno un amministratore attivo.");
      return rows[0].username;
    });
    await audit(actor, "user.delete", username);
    revalidatePath("/impostazioni/utenti");
    return { ok: true, message: `Utente ${username} eliminato.` };
  } catch (error) {
    if (error instanceof Error && /amministratore|non trovato/.test(error.message)) return { error: error.message };
    return failure(error);
  }
}

// ------------------------------------------------------------------- token API

export async function createApiToken(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const name = text(form, "name", 80);
    const role = text(form, "role") as Role;
    const days = Number(form.get("days"));
    if (!name) return { error: "Dai un nome al token, per esempio il sistema che lo userà." };
    if (!ROLES.includes(role)) return { error: "Ruolo non valido." };
    if (![0, 30, 90, 180, 365].includes(days)) return { error: "Durata non valida." };
    const { token, hash, prefix } = newApiToken();
    await db().query(
      `INSERT INTO api_tokens (name, token_hash, prefix, role, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::int > 0 THEN now() + make_interval(days => $6::int) END)`,
      [name, hash, prefix, role, actor.username, days],
    );
    await audit(actor, "apitoken.create", name, { role, days });
    revalidatePath("/impostazioni/api");
    return { ok: true, message: "Token creato. Copialo adesso: non sarà più visibile.", token };
  } catch (error) {
    return failure(error);
  }
}

export async function revokeApiToken(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const { rows } = await db().query<{ name: string }>(
      "UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING name",
      [id(form)],
    );
    if (!rows[0]) return { error: "Token non trovato o già revocato." };
    await audit(actor, "apitoken.revoke", rows[0].name);
    revalidatePath("/impostazioni/api");
    return { ok: true, message: "Token revocato." };
  } catch (error) {
    return failure(error);
  }
}

// --------------------------------------------------------------------- sensori

const SENSOR_NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,62}$/u;

export async function createSensor(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const name = text(form, "name", 63);
    const site = text(form, "site", 100);
    if (!SENSOR_NAME.test(name)) return { error: "Nome: 1-63 caratteri tra lettere, cifre, spazio, punto, trattino e underscore." };
    const { token, hash } = newSensorToken();
    await db().query("INSERT INTO sensors (name, site, token_hash, created_by) VALUES ($1, $2, $3, $4)", [name, site, hash, actor.username]);
    await audit(actor, "sensor.create", name, { site });
    await notifyHub("sensors");
    revalidatePath("/sensori");
    return { ok: true, message: `Sensore ${name} aggiunto. Metti il token in HW_SENSOR_TOKEN sul server del sensore: non sarà più visibile.`, token };
  } catch (error) {
    if (isUniqueViolation(error)) return { error: "Esiste già un sensore con questo nome." };
    return failure(error);
  }
}

export async function updateSensor(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const enabled = form.get("enabled") === "on";
    const { rows } = await db().query<{ name: string }>(
      "UPDATE sensors SET site = $2, enabled = $3 WHERE id = $1 RETURNING name",
      [id(form), text(form, "site", 100), enabled],
    );
    if (!rows[0]) return { error: "Sensore non trovato." };
    await audit(actor, "sensor.update", rows[0].name, { enabled });
    await notifyHub("sensors");
    revalidatePath("/sensori");
    return { ok: true, message: enabled ? "Sensore salvato." : "Sensore disattivato: l'hub rifiuterà i suoi dati." };
  } catch (error) {
    return failure(error);
  }
}

export async function rotateSensorToken(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const { token, hash } = newSensorToken();
    const { rows } = await db().query<{ name: string }>("UPDATE sensors SET token_hash = $2 WHERE id = $1 RETURNING name", [id(form), hash]);
    if (!rows[0]) return { error: "Sensore non trovato." };
    await audit(actor, "sensor.rotate", rows[0].name);
    await notifyHub("sensors");
    revalidatePath("/sensori");
    return { ok: true, message: `Nuovo token per ${rows[0].name}: il vecchio non vale più. Aggiorna HW_SENSOR_TOKEN e riavvia il sensore.`, token };
  } catch (error) {
    return failure(error);
  }
}

export async function deleteSensor(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const { rows } = await db().query<{ name: string }>("DELETE FROM sensors WHERE id = $1 RETURNING name", [id(form)]);
    if (!rows[0]) return { error: "Sensore non trovato." };
    await audit(actor, "sensor.delete", rows[0].name);
    await notifyHub("sensors");
    revalidatePath("/sensori");
    return { ok: true, message: `Sensore ${rows[0].name} eliminato. I dati già raccolti restano fino alla scadenza.` };
  } catch (error) {
    return failure(error);
  }
}

// ----------------------------------------------------------------- impostazioni

export async function setLive(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const live = form.get("live") === "on";
    await db().query(
      `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('live', $1, now(), $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [JSON.stringify(live), actor.username],
    );
    await audit(actor, live ? "live.on" : "live.off");
    await notifyHub("settings");
    revalidatePath("/", "layout");
    return { ok: true, message: live ? "Live acceso: i sensori riprendono a inviare." : "Live spento: i sensori smettono di inviare dati." };
  } catch (error) {
    return failure(error);
  }
}

export async function saveNetworkConfig(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const actor = await actionUser("admin");
    const internal = parseNets(text(form, "internal_nets", 4000));
    const sensitive = parseNets(text(form, "sensitive_nets", 4000));
    if (!internal) return { error: "Reti interne: una o più voci non sono indirizzi o reti CIDR validi." };
    if (!sensitive) return { error: "Reti sensibili: una o più voci non sono indirizzi o reti CIDR validi." };
    const learning = Number(form.get("learning_hours") || 0);
    if (!Number.isInteger(learning) || learning < 0 || learning > 720) return { error: "Ore di apprendimento: da 0 a 720." };
    const timezone = text(form, "timezone", 60);
    if (timezone) {
      try {
        new Intl.DateTimeFormat("it-IT", { timeZone: timezone });
      } catch {
        return { error: "Fuso orario non valido (esempio: Europe/Rome)." };
      }
    }
    const config = {
      ...(internal.length ? { internal_nets: internal.join(",") } : {}),
      ...(sensitive.length ? { sensitive_nets: sensitive.join(",") } : {}),
      ...(learning ? { learning_hours: learning } : {}),
      ...(timezone ? { timezone } : {}),
    };
    await db().query(
      `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('config', $1, now(), $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [JSON.stringify(config), actor.username],
    );
    await audit(actor, "settings.config", "", config);
    await notifyHub("settings");
    revalidatePath("/impostazioni");
    return { ok: true, message: "Impostazioni salvate: l'hub le applica subito." };
  } catch (error) {
    return failure(error);
  }
}
