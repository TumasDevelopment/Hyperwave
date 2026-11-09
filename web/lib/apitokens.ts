import "server-only";
import { randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { can, hashToken, type Role, type SessionUser } from "./auth";
import { db } from "./db";

// Token per l'API v1: "hwk_" + 40 caratteri. Il token vero si mostra una volta sola,
// nel database restano l'hash e il prefisso per riconoscerlo nell'elenco.

const PREFIX = "hwk_";

export function newApiToken() {
  const token = `${PREFIX}${randomBytes(30).toString("base64url")}`;
  return { token, hash: hashToken(token), prefix: token.slice(0, PREFIX.length + 6) };
}

export interface ApiCaller extends SessionUser {
  tokenId: number;
}

export async function apiCaller(request: Request): Promise<ApiCaller | null> {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(hwk_[A-Za-z0-9_-]{20,80})$/.exec(header.trim());
  if (!match) return null;
  const { rows } = await db().query<{ id: string; name: string; role: Role }>(
    `UPDATE api_tokens SET last_used = now()
     WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
     RETURNING id, name, role`,
    [hashToken(match[1])],
  );
  const row = rows[0];
  if (!row) return null;
  return { id: 0, tokenId: Number(row.id), username: `api:${row.name}`, displayName: row.name, role: row.role, mustChange: false };
}

const noStore = { "Cache-Control": "no-store" };
export const apiError = (status: number, error: string) => NextResponse.json({ error }, { status, headers: noStore });
export const apiJson = (data: unknown, status = 200) => NextResponse.json(data, { status, headers: noStore });

/** Controlla token e ruolo, poi esegue. Gli errori imprevisti restano nel log del sito. */
export async function withApi(request: Request, role: Role, handler: (caller: ApiCaller) => Promise<Response>) {
  const caller = await apiCaller(request);
  if (!caller) return apiError(401, "Token API mancante, non valido, scaduto o revocato.");
  if (!can(caller, role)) return apiError(403, "Il ruolo del token non permette questa operazione.");
  try {
    return await handler(caller);
  } catch (error) {
    console.error("API v1:", error);
    return apiError(500, "Errore interno.");
  }
}

export async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Un id da URL o da JSON: intero positivo, altrimenti null. */
export function rowId(value: unknown) {
  const number = typeof value === "string" && /^\d{1,15}$/.test(value) ? Number(value) : value;
  return typeof number === "number" && Number.isSafeInteger(number) && number > 0 ? number : null;
}
