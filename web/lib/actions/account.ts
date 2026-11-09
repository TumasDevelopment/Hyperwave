"use server";

import { revalidatePath } from "next/cache";
import { audit } from "../audit";
import { actionUser, createSession, currentSessionHash, getUser } from "../auth";
import { db } from "../db";
import { failure, text, type FormState } from "../form";
import { hashPassword, verifyPassword } from "../password.mjs";
import { passwordProblem } from "../secrets";
import { hashRecoveryCode, newRecoveryCodes, newTotpSecret, otpauthUri, verifyTotp } from "../totp.mjs";

async function checkPassword(userId: number, password: string) {
  const { rows } = await db().query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [userId]);
  return rows[0] ? verifyPassword(password, rows[0].password_hash) : false;
}

/** Cambio della propria password. Funziona anche quando il cambio è obbligatorio. */
export async function changePassword(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await getUser();
    if (!user) return { error: "Sessione scaduta: accedi di nuovo." };
    const current = String(form.get("current") ?? "");
    const next = String(form.get("next") ?? "");
    const confirm = String(form.get("confirm") ?? "");
    if (!(await checkPassword(user.id, current))) return { error: "La password attuale non è corretta." };
    if (next !== confirm) return { error: "Le due password nuove non coincidono." };
    if (next === current) return { error: "La password nuova deve essere diversa da quella attuale." };
    const problem = passwordProblem(next, user.username);
    if (problem) return { error: problem };

    await db().query("UPDATE users SET password_hash = $2, must_change = false WHERE id = $1", [user.id, await hashPassword(next)]);
    // tutte le sessioni, compresa questa, vengono chiuse: se ne apre una nuova qui
    await db().query("DELETE FROM sessions WHERE user_id = $1", [user.id]);
    await createSession(user.id);
    await audit(user, "password.change", user.username);
    revalidatePath("/", "layout");
    return { ok: true, message: "Password cambiata. Le altre sessioni aperte sono state chiuse." };
  } catch (error) {
    return failure(error);
  }
}

/** Primo passo dei due fattori: genera il segreto (non ancora attivo) e lo mostra con il QR. */
export async function startTotp(): Promise<FormState> {
  try {
    const user = await actionUser();
    const secret = newTotpSecret();
    const res = await db().query("UPDATE users SET totp_secret = $2 WHERE id = $1 AND NOT totp_enabled", [user.id, secret]);
    if (!res.rowCount) return { error: "I due fattori sono già attivi." };
    return { ok: true, data: { secret, uri: otpauthUri({ issuer: "Hyperwave", account: user.username, secret }) } };
  } catch (error) {
    return failure(error);
  }
}

export async function confirmTotp(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser();
    const { rows } = await db().query<{ totp_secret: string | null }>(
      "SELECT totp_secret FROM users WHERE id = $1 AND NOT totp_enabled",
      [user.id],
    );
    const secret = rows[0]?.totp_secret;
    if (!secret) return { error: "Riparti dall'inizio: genera un nuovo codice QR." };
    const step = verifyTotp(secret, text(form, "code", 20), Date.now() / 1000);
    if (step === null) return { error: "Codice non corretto: controlla che l'ora del telefono sia giusta e riprova." };
    const codes = newRecoveryCodes(10);
    await db().query(
      "UPDATE users SET totp_enabled = true, totp_last_step = $2, recovery_codes = $3 WHERE id = $1",
      [user.id, step, codes.map((c: string) => hashRecoveryCode(c))],
    );
    await audit(user, "2fa.enable", user.username);
    revalidatePath("/account");
    return { ok: true, message: "Due fattori attivati.", data: { codes } };
  } catch (error) {
    return failure(error);
  }
}

export async function disableTotp(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser();
    if (!(await checkPassword(user.id, String(form.get("password") ?? "")))) return { error: "Password non corretta." };
    await db().query(
      "UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_last_step = NULL, recovery_codes = '{}' WHERE id = $1",
      [user.id],
    );
    await audit(user, "2fa.disable", user.username);
    revalidatePath("/account");
    return { ok: true, message: "Due fattori disattivati." };
  } catch (error) {
    return failure(error);
  }
}

export async function newRecovery(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser();
    if (!(await checkPassword(user.id, String(form.get("password") ?? "")))) return { error: "Password non corretta." };
    const codes = newRecoveryCodes(10);
    const res = await db().query("UPDATE users SET recovery_codes = $2 WHERE id = $1 AND totp_enabled", [
      user.id,
      codes.map((c: string) => hashRecoveryCode(c)),
    ]);
    if (!res.rowCount) return { error: "I due fattori non sono attivi." };
    await audit(user, "2fa.enable", user.username, { recovery_codes: "rigenerati" });
    return { ok: true, message: "Nuovi codici generati: i precedenti non valgono più.", data: { codes } };
  } catch (error) {
    return failure(error);
  }
}

export async function closeOtherSessions(): Promise<FormState> {
  try {
    const user = await actionUser();
    const current = await currentSessionHash();
    const res = await db().query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [user.id, current]);
    await audit(user, "session.revoke", user.username, { sessions: res.rowCount ?? 0 });
    revalidatePath("/account");
    return { ok: true, message: `Sessioni chiuse: ${res.rowCount ?? 0}.` };
  } catch (error) {
    return failure(error);
  }
}

export async function updateProfile(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser();
    const displayName = text(form, "display_name", 100);
    const email = text(form, "email", 200);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Indirizzo email non valido." };
    await db().query("UPDATE users SET display_name = $2, email = $3 WHERE id = $1", [user.id, displayName, email]);
    await audit(user, "user.update", user.username, { display_name: displayName, email });
    revalidatePath("/", "layout");
    return { ok: true, message: "Profilo salvato." };
  } catch (error) {
    return failure(error);
  }
}
