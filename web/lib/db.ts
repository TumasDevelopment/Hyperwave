import "server-only";
import { Pool, type PoolClient } from "pg";

const globalForPool = globalThis as unknown as { hwPool?: Pool };

export function db(): Pool {
  if (!globalForPool.hwPool) {
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 8, statement_timeout: 30_000 });
    pool.on("error", (error) => console.error("Errore di connessione a PostgreSQL:", error.message));
    globalForPool.hwPool = pool;
  }
  return globalForPool.hwPool;
}

export async function transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await db().connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

/** Legge un'impostazione JSON da settings, oppure il valore predefinito. */
export async function setting<T>(key: string, fallback: T): Promise<T> {
  const { rows } = await db().query<{ value: T }>("SELECT value FROM settings WHERE key = $1", [key]);
  return rows[0]?.value ?? fallback;
}
