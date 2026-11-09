import { ch } from "@/lib/ch";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

/** Stato del sito per i controlli esterni (Vigil, bilanciatori). Non rivela dati: solo sì o no. */
export async function GET() {
  const [pg, clickhouse] = await Promise.all([
    db().query("SELECT 1").then(() => true, () => false),
    ch("SELECT 1 AS ok", {}, 5).then(() => true, () => false),
  ]);
  const ok = pg && clickhouse;
  return Response.json({ ok, postgres: pg, clickhouse }, { status: ok ? 200 : 503, headers: { "Cache-Control": "no-store" } });
}
