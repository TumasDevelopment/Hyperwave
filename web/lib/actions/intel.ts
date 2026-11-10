"use server";

import { revalidatePath } from "next/cache";
import { audit } from "../audit";
import { actionUser } from "../auth";
import { db, transaction } from "../db";
import { failure, isUniqueViolation, text, type FormState } from "../form";
import { INTEL_CATEGORIES, parseIndicatorLines } from "../intel.mjs";
import { SEVERITIES } from "../labels";
import { notifyHub } from "../nats";

const PAGE = "/minacce";
const id = (value: FormDataEntryValue | null) => {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error("Identificativo non valido.");
  return n;
};

function feedFields(form: FormData) {
  const category = text(form, "category");
  const severity = text(form, "severity");
  const hours = Number(text(form, "refresh_hours") || 6);
  if (!(category in INTEL_CATEGORIES)) return { error: "Categoria non valida." } as const;
  if (!(SEVERITIES as readonly string[]).includes(severity)) return { error: "Gravità non valida." } as const;
  if (!Number.isInteger(hours) || hours < 1 || hours > 168) return { error: "Aggiornamento: da 1 a 168 ore." } as const;
  return { category, severity, hours } as const;
}

async function feedName(feedId: number) {
  const { rows } = await db().query<{ name: string; kind: string; preset: string }>("SELECT name, kind, preset FROM intel_feeds WHERE id = $1", [feedId]);
  if (!rows[0]) throw new Error("Elenco non trovato.");
  return rows[0];
}

function known(error: unknown): FormState {
  if (isUniqueViolation(error)) return { error: "Esiste già un elenco con questo nome." };
  if (error instanceof Error && /^(Elenco non trovato|Identificativo non valido)/.test(error.message)) return { error: error.message };
  return failure(error);
}

export async function createFeed(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const name = text(form, "name", 80);
    const kind = text(form, "kind") === "manual" ? "manual" : "url";
    const url = text(form, "url", 1000);
    const f = feedFields(form);
    if ("error" in f) return f;
    if (name.length < 2) return { error: "Dai un nome all'elenco." };
    if (kind === "url") {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return { error: "Indirizzo non valido." };
      }
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return { error: "L'indirizzo deve iniziare con https:// o http://." };
      if (parsed.username || parsed.password) return { error: "Non inserire credenziali nell'indirizzo." };
    }
    const { rows } = await db().query<{ id: number }>(
      `INSERT INTO intel_feeds (name, kind, url, category, severity, description, enabled, refresh_hours, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8) RETURNING id::int AS id`,
      [name, kind, kind === "url" ? url : "", f.category, f.severity, text(form, "description", 500), f.hours, user.username],
    );
    await audit(user, "intel.feed.create", name, { kind, url: kind === "url" ? url : undefined, category: f.category, severity: f.severity });
    await notifyHub("intel", kind === "url" ? { fetch: rows[0].id } : undefined);
    revalidatePath(PAGE);
    return {
      ok: true,
      message: kind === "url" ? `Elenco ${name} creato: l'hub lo scarica adesso e poi ogni ${f.hours} ore.` : `Elenco ${name} creato: aggiungi gli indicatori qui sotto.`,
    };
  } catch (error) {
    return known(error);
  }
}

export async function updateFeed(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const feedId = id(form.get("id"));
    const f = feedFields(form);
    if ("error" in f) return f;
    const enabled = form.get("enabled") === "on";
    const { rows } = await db().query<{ name: string; kind: string; never: boolean }>(
      `UPDATE intel_feeds SET enabled = $2, category = $3, severity = $4, refresh_hours = $5
       WHERE id = $1 RETURNING name, kind, last_ok IS NULL AS never`,
      [feedId, enabled, f.category, f.severity, f.hours],
    );
    if (!rows[0]) return { error: "Elenco non trovato." };
    await audit(user, "intel.feed.update", rows[0].name, { enabled, category: f.category, severity: f.severity, refresh_hours: f.hours });
    await notifyHub("intel", enabled && rows[0].kind === "url" && rows[0].never ? { fetch: feedId } : undefined);
    revalidatePath(PAGE);
    return { ok: true, message: enabled && rows[0].never && rows[0].kind === "url" ? "Elenco attivato: l'hub lo sta scaricando." : "Elenco salvato." };
  } catch (error) {
    return known(error);
  }
}

export async function deleteFeed(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const feedId = id(form.get("id"));
    const feed = await feedName(feedId);
    if (feed.preset) return { error: "Gli elenchi predefiniti non si eliminano: spegnili." };
    await db().query("DELETE FROM intel_feeds WHERE id = $1", [feedId]);
    await audit(user, "intel.feed.delete", feed.name);
    await notifyHub("intel");
    revalidatePath(PAGE);
    return { ok: true, message: `Elenco ${feed.name} eliminato.` };
  } catch (error) {
    return known(error);
  }
}

/** Pulsanti dell'elenco: op=fetch scarica subito, op=retro cerca gli indicatori nello storico. */
export async function feedCommand(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const op = text(form, "op");
    const user = await actionUser(op === "fetch" ? "admin" : "analyst");
    const feedId = id(form.get("id"));
    const feed = await feedName(feedId);
    if (op === "fetch") {
      if (feed.kind !== "url") return { error: "Questo elenco si compila a mano." };
      await audit(user, "intel.feed.fetch", feed.name);
      await notifyHub("intel", { fetch: feedId });
      return { ok: true, message: "Aggiornamento avviato: ricarica la pagina tra qualche secondo." };
    }
    if (op === "retro") {
      await audit(user, "intel.feed.retro", feed.name);
      await notifyHub("intel", { retro: feedId });
      return { ok: true, message: "Ricerca nello storico avviata: le corrispondenze diventano allarmi." };
    }
    return { error: "Operazione sconosciuta." };
  } catch (error) {
    return known(error);
  }
}

export async function addIndicators(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const feedId = id(form.get("feed_id"));
    const days = Number(text(form, "days") || 0);
    if (![0, 1, 7, 30, 90, 365].includes(days)) return { error: "Durata non valida." };
    const { items, rejected } = parseIndicatorLines(text(form, "indicators", 400_000));
    if (items.length === 0) return { error: rejected.length ? `Nessuna voce valida (per esempio: ${rejected[0]}).` : "Scrivi almeno un indirizzo, una rete o un dominio." };
    if (items.length > 5000) return { error: "Al massimo 5000 voci per volta." };
    const common = text(form, "note", 300);
    const feed = await feedName(feedId);
    if (feed.kind !== "manual") return { error: "Gli indicatori a mano vanno in un elenco compilato a mano." };
    await transaction(async (client) => {
      await client.query(
        `INSERT INTO intel_indicators (feed_id, value, type, note, added_by, expires_at)
         SELECT $1, CASE t WHEN 'ip' THEN host(v::inet) WHEN 'cidr' THEN network(v::inet)::text ELSE v END, t, n, $5,
                CASE WHEN $6::int > 0 THEN now() + make_interval(days => $6::int) END
         FROM unnest($2::text[], $3::text[], $4::text[]) AS x(v, t, n)
         ON CONFLICT (feed_id, value) DO UPDATE SET note = EXCLUDED.note, expires_at = EXCLUDED.expires_at, added_by = EXCLUDED.added_by`,
        [feedId, items.map((i) => i.value), items.map((i) => i.type), items.map((i) => i.note || common), user.username, days],
      );
      await client.query("UPDATE intel_feeds SET entries = (SELECT count(*) FROM intel_indicators WHERE feed_id = $1) WHERE id = $1", [feedId]);
    });
    await audit(user, "intel.indicator.add", feed.name, { count: items.length, days, sample: items.slice(0, 5).map((i) => i.value) });
    await notifyHub("intel", { retro: feedId });
    revalidatePath(PAGE);
    const skipped = rejected.length ? ` ${rejected.length} righe scartate (per esempio: ${rejected[0]}).` : "";
    return { ok: true, message: `${items.length} voci salvate in ${feed.name}; l'hub le cerca anche nello storico.${skipped}` };
  } catch (error) {
    return known(error);
  }
}

export async function deleteIndicator(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("analyst");
    const feedId = id(form.get("feed_id"));
    const value = text(form, "value", 300);
    const feed = await feedName(feedId);
    if (feed.kind !== "manual") return { error: "Si possono togliere solo le voci inserite a mano." };
    await transaction(async (client) => {
      await client.query("DELETE FROM intel_indicators WHERE feed_id = $1 AND value = $2", [feedId, value]);
      await client.query("UPDATE intel_feeds SET entries = (SELECT count(*) FROM intel_indicators WHERE feed_id = $1) WHERE id = $1", [feedId]);
    });
    await audit(user, "intel.indicator.delete", feed.name, { value });
    await notifyHub("intel");
    revalidatePath(PAGE);
    return { ok: true, message: `${value} tolto da ${feed.name}.` };
  } catch (error) {
    return known(error);
  }
}
