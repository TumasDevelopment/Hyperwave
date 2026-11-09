"use server";

import { randomBytes } from "node:crypto";
import { redirect } from "next/navigation";
import { audit } from "../audit";
import {
  clearLoginChallenge,
  clientAddress,
  createLoginChallenge,
  createSession,
  destroySession,
  getUser,
  spendChallengeAttempt,
} from "../auth";
import { db } from "../db";
import { text, type FormState } from "../form";
import { clearFailures, lockedMinutes, recordFailure } from "../login-limit";
import { hashPassword, verifyPassword } from "../password.mjs";
import { findRecoveryCode, verifyTotp } from "../totp.mjs";

// Con un nome utente inesistente si verifica comunque una password: i tempi di risposta non rivelano chi esiste.
let dummyHash: Promise<string> | null = null;

export async function login(_state: FormState, form: FormData): Promise<FormState> {
  const username = text(form, "username", 100);
  const password = String(form.get("password") ?? "").slice(0, 200);
  if (!username || !password) return { error: "Inserisci nome utente e password." };

  const address = await clientAddress();
  const wait = lockedMinutes(address, username);
  if (wait > 0) {
    await audit({ username }, "login.locked", username);
    return { error: `Troppi tentativi non riusciti. Riprova tra ${wait} ${wait === 1 ? "minuto" : "minuti"}.` };
  }

  const { rows } = await db().query<{ id: string; username: string; password_hash: string; disabled: boolean; totp_enabled: boolean }>(
    "SELECT id, username, password_hash, disabled, totp_enabled FROM users WHERE lower(username) = lower($1)",
    [username],
  );
  const user = rows[0];
  dummyHash ??= hashPassword(randomBytes(16).toString("hex"));
  const valid = await verifyPassword(password, user?.password_hash ?? (await dummyHash));
  if (!user || !valid || user.disabled) {
    recordFailure(address, username);
    await audit({ username }, "login.failed", username, user?.disabled ? { reason: "disabled" } : {});
    return { error: "Nome utente o password non corretti." };
  }
  clearFailures(address, username);

  if (user.totp_enabled) {
    await createLoginChallenge(Number(user.id));
    return { next: "totp" };
  }
  await createSession(Number(user.id));
  await audit({ username: user.username }, "login.ok", user.username);
  redirect("/");
}

/** Secondo passo: codice dell'app di autenticazione oppure codice di recupero. */
export async function verifyCode(_state: FormState, form: FormData): Promise<FormState> {
  const code = text(form, "code", 30);
  const userId = await spendChallengeAttempt();
  if (!userId) {
    await clearLoginChallenge();
    return { error: "Tempo scaduto o troppi tentativi: accedi di nuovo.", next: "password" };
  }
  const { rows } = await db().query<{ username: string; totp_secret: string | null; totp_last_step: string | null; recovery_codes: Buffer[] }>(
    "SELECT username, totp_secret, totp_last_step, recovery_codes FROM users WHERE id = $1 AND NOT disabled AND totp_enabled",
    [userId],
  );
  const user = rows[0];
  if (!user?.totp_secret) {
    await clearLoginChallenge();
    return { error: "Accedi di nuovo.", next: "password" };
  }

  let ok = false;
  let recovery = false;
  if (/^\d{6}$/.test(code.replace(/\s/g, ""))) {
    const step = verifyTotp(user.totp_secret, code, Date.now() / 1000, user.totp_last_step);
    if (step !== null) {
      // l'aggiornamento condizionato impedisce di usare due volte lo stesso codice anche con due richieste insieme
      const res = await db().query(
        "UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
        [userId, step],
      );
      ok = (res.rowCount ?? 0) > 0;
    }
  } else {
    const index = findRecoveryCode(user.recovery_codes ?? [], code);
    if (index >= 0) {
      const res = await db().query(
        "UPDATE users SET recovery_codes = array_remove(recovery_codes, $2::bytea) WHERE id = $1 AND $2::bytea = ANY(recovery_codes)",
        [userId, user.recovery_codes[index]],
      );
      ok = recovery = (res.rowCount ?? 0) > 0;
    }
  }

  if (!ok) {
    await audit({ username: user.username }, "login.2fa_failed", user.username);
    return { error: "Codice non corretto.", next: "totp" };
  }
  await clearLoginChallenge();
  await createSession(userId);
  await audit({ username: user.username }, recovery ? "login.recovery" : "login.ok", user.username, { mfa: true });
  redirect(recovery ? "/account?recupero=1" : "/");
}

export async function cancelLogin(): Promise<FormState> {
  await clearLoginChallenge();
  return { next: "password" };
}

export async function logout() {
  const user = await getUser();
  await destroySession();
  if (user) await audit(user, "logout", user.username);
  redirect("/login");
}
