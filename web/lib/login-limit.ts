import "server-only";
import { db } from "./db";

// I conteggi stanno in PostgreSQL: valgono per tutte le istanze dell'interfaccia e restano dopo un riavvio.
const WINDOW_MINUTES = 15;
const MAX_PER_ACCOUNT = 5;
const MAX_PER_ADDRESS = 20;

const accountKey = (address: string, username: string) => `u:${address}:${username.toLowerCase()}`;
const addressKey = (address: string) => `a:${address}`;

/** Minuti da attendere prima di riprovare, oppure 0 se il tentativo è ammesso. */
export async function lockedMinutes(address: string, username: string): Promise<number> {
  const { rows } = await db().query<{ wait: number | null }>(
    `SELECT ceil(extract(epoch FROM max(reset_at) - now()) / 60)::int AS wait
       FROM login_failures
      WHERE reset_at > now()
        AND ((key = $1 AND count >= $3) OR (key = $2 AND count >= $4))`,
    [accountKey(address, username), addressKey(address), MAX_PER_ACCOUNT, MAX_PER_ADDRESS],
  );
  return Math.max(rows[0]?.wait ?? 0, 0);
}

/** Conta un tentativo fallito per la coppia indirizzo-utente e per l'indirizzo, in una sola istruzione atomica. */
export async function recordFailure(address: string, username: string) {
  await db().query(
    `INSERT INTO login_failures AS f (key, count, reset_at)
     SELECT k, 1, now() + make_interval(mins => $2) FROM unnest($1::text[]) AS k
     ON CONFLICT (key) DO UPDATE SET
       count    = CASE WHEN f.reset_at <= now() THEN 1 ELSE f.count + 1 END,
       reset_at = CASE WHEN f.reset_at <= now() THEN EXCLUDED.reset_at ELSE f.reset_at END`,
    [[accountKey(address, username), addressKey(address)], WINDOW_MINUTES],
  );
}

export async function clearFailures(address: string, username: string) {
  await db().query("DELETE FROM login_failures WHERE key = $1", [accountKey(address, username)]);
}
