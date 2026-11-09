import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";
import { db } from "./db";

const COOKIE_NAME = "hw_sessione";
const SESSION_HOURS = 12;
const IDLE_MINUTES = 60;

export type Role = "admin" | "analyst" | "viewer";
export interface SessionUser {
  id: number;
  username: string;
  displayName: string;
  role: Role;
  mustChange: boolean;
}

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };
/** L'utente ha almeno il ruolo indicato? (viewer < analyst < admin) */
export const can = (user: Pick<SessionUser, "role">, role: Role) => RANK[user.role] >= RANK[role];

export const ROLE_LABELS: Record<Role, string> = { admin: "Amministratore", analyst: "Analista", viewer: "Visualizzatore" };

export const hashToken = (token: string) => createHash("sha256").update(token).digest();

async function writeCookie(token: string, expires: Date) {
  (await cookies()).set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" && process.env.HW_INSECURE_COOKIE !== "1",
    sameSite: "lax",
    path: "/",
    expires,
  });
}

/** L'indirizzo del browser: nginx lo mette in X-Real-IP. */
export async function clientAddress() {
  try {
    const list = await headers();
    return list.get("x-real-ip") ?? list.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "";
  } catch {
    return "";
  }
}

export async function createSession(userId: number) {
  const token = randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + SESSION_HOURS * 3_600_000);
  const agent = ((await headers()).get("user-agent") ?? "").slice(0, 300);
  await db().query("INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5)", [
    hashToken(token),
    userId,
    expires,
    await clientAddress(),
    agent,
  ]);
  await db().query("UPDATE users SET last_login = now() WHERE id = $1", [userId]);
  await writeCookie(token, expires);
}

export async function destroySession() {
  const store = await cookies();
  const token = store.get(COOKIE_NAME)?.value;
  if (token) await db().query("DELETE FROM sessions WHERE token_hash = $1", [hashToken(token)]);
  store.delete(COOKIE_NAME);
}

export const getUser = cache(async (): Promise<SessionUser | null> => {
  const token = (await cookies()).get(COOKIE_NAME)?.value;
  if (!token) return null;
  const { rows } = await db().query<SessionUser>(
    `UPDATE sessions s SET last_active = now()
     FROM users u
     WHERE s.token_hash = $1 AND u.id = s.user_id AND NOT u.disabled
       AND s.expires_at > now() AND s.last_active > now() - interval '${IDLE_MINUTES} minutes'
     RETURNING u.id::int AS id, u.username, u.display_name AS "displayName", u.role, u.must_change AS "mustChange"`,
    [hashToken(token)],
  );
  return rows[0] ?? null;
});

/**
 * Per le pagine: senza sessione si va all'accesso. Chi deve cambiare la password
 * viene portato al proprio profilo finché non lo fa.
 */
export async function requireUser(options: { allowMustChange?: boolean } = {}): Promise<SessionUser> {
  const user = await getUser();
  if (!user) redirect("/login");
  if (user.mustChange && !options.allowMustChange) redirect("/account?cambio=1");
  return user;
}

export async function requireRole(role: Role): Promise<SessionUser> {
  const user = await requireUser();
  if (!can(user, role)) redirect("/");
  return user;
}

/** Per le azioni: lancia un errore invece di reindirizzare, così il modulo lo mostra. */
export async function actionUser(role: Role = "viewer"): Promise<SessionUser> {
  const user = await getUser();
  if (!user) throw new Error("Sessione scaduta: accedi di nuovo.");
  if (user.mustChange) throw new Error("Prima cambia la password dal tuo profilo.");
  if (!can(user, role)) throw new Error("Non hai i permessi per questa operazione.");
  return user;
}

// Secondo passo dell'accesso

const CHALLENGE_COOKIE = "hw_2fa";
const CHALLENGE_SECONDS = 300;
const CHALLENGE_ATTEMPTS = 5;

export async function createLoginChallenge(userId: number) {
  const token = randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + CHALLENGE_SECONDS * 1000);
  await db().query("DELETE FROM login_challenges WHERE user_id = $1 OR expires_at < now()", [userId]);
  await db().query("INSERT INTO login_challenges (token_hash, user_id, expires_at) VALUES ($1, $2, $3)", [
    hashToken(token),
    userId,
    expires,
  ]);
  (await cookies()).set(CHALLENGE_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" && process.env.HW_INSECURE_COOKIE !== "1",
    sameSite: "strict",
    path: "/",
    expires,
  });
}

export async function hasLoginChallenge() {
  const token = (await cookies()).get(CHALLENGE_COOKIE)?.value;
  if (!token) return false;
  const { rowCount } = await db().query(
    "SELECT 1 FROM login_challenges WHERE token_hash = $1 AND expires_at > now() AND attempts < $2",
    [hashToken(token), CHALLENGE_ATTEMPTS],
  );
  return (rowCount ?? 0) > 0;
}

export async function spendChallengeAttempt(): Promise<number | null> {
  const token = (await cookies()).get(CHALLENGE_COOKIE)?.value;
  if (!token) return null;
  const { rows } = await db().query<{ user_id: string }>(
    `UPDATE login_challenges SET attempts = attempts + 1
     WHERE token_hash = $1 AND expires_at > now() AND attempts < $2
     RETURNING user_id`,
    [hashToken(token), CHALLENGE_ATTEMPTS],
  );
  return rows[0] ? Number(rows[0].user_id) : null;
}

export async function clearLoginChallenge() {
  const store = await cookies();
  const token = store.get(CHALLENGE_COOKIE)?.value;
  if (token) await db().query("DELETE FROM login_challenges WHERE token_hash = $1", [hashToken(token)]);
  store.delete(CHALLENGE_COOKIE);
}

/** Hash della sessione in uso, per chiudere tutte le altre. */
export async function currentSessionHash() {
  const token = (await cookies()).get(COOKIE_NAME)?.value;
  return token ? hashToken(token) : null;
}
