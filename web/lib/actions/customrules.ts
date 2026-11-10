"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { audit } from "../audit";
import { actionUser } from "../auth";
import type { CustomRuleInput, RuleSpec, RuleTestResult } from "../customrules";
import { db, transaction } from "../db";
import { failure, isUniqueViolation, type FormState } from "../form";
import { SEVERITIES } from "../labels";
import { askHub, notifyHub } from "../nats";

type Result = { ok?: boolean; error?: string; id?: number };

const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const int = (v: unknown, lo: number, hi: number, def: number) => {
  const n = Number(v);
  return Number.isInteger(n) && n >= lo && n <= hi ? n : def;
};

/** Tiene solo i campi attesi, con i tipi giusti: il controllo vero lo fa l'hub. */
function cleanSpec(raw: unknown): RuleSpec {
  const s = (raw ?? {}) as Record<string, unknown>;
  const where = Array.isArray(s.where) ? s.where.slice(0, 20) : [];
  return {
    source: str(s.source, 30),
    where: where.map((c) => {
      const w = (c ?? {}) as Record<string, unknown>;
      const value = Array.isArray(w.value) ? w.value.slice(0, 250).map((v) => str(v, 600)).filter(Boolean) : [];
      return { field: str(w.field, 40), op: str(w.op, 20), value };
    }),
    group_by: Array.isArray(s.group_by) ? s.group_by.slice(0, 5).map((g) => str(g, 40)) : [],
    metric: s.metric === "uniq" || s.metric === "sum" ? s.metric : "count",
    metric_field: str(s.metric_field, 40),
    threshold: Number(s.threshold) || 0,
    window_min: int(s.window_min, 1, 1440, 0),
    every_min: int(s.every_min, 0, 60, 0),
  };
}

async function check(spec: RuleSpec): Promise<string | null> {
  const res = await askHub<RuleTestResult>("customtest", { spec, check: true }, 8000);
  if (!res) return "L'hub non risponde: senza la sua verifica la regola non si può salvare.";
  return res.ok ? null : res.error || "Regola non valida.";
}

export async function saveCustomRule(input: CustomRuleInput): Promise<Result> {
  try {
    const user = await actionUser("admin");
    const name = str(input.name, 120);
    const description = str(input.description, 1000);
    const severity = str(input.severity, 10);
    const mitre = str(input.mitre, 20).toUpperCase();
    if (name.length < 2) return { error: "Dai un nome alla regola." };
    if (!(SEVERITIES as readonly string[]).includes(severity)) return { error: "Gravità non valida." };
    if (mitre && !/^T\d{4}(\.\d{3})?$/.test(mitre)) return { error: "Tecnica ATT&CK: per esempio T1046 o T1110.003." };
    const spec = cleanSpec(input.spec);
    const invalid = await check(spec);
    if (invalid) return { error: invalid };

    let id = Number(input.id) || 0;
    if (id) {
      const { rowCount } = await db().query(
        `UPDATE custom_rules SET name = $2, description = $3, severity = $4, mitre = $5, spec = $6, updated_by = $7, updated_at = now(),
                last_error = '' WHERE id = $1`,
        [id, name, description, severity, mitre, JSON.stringify(spec), user.username],
      );
      if (!rowCount) return { error: "Regola non trovata." };
      await audit(user, "customrule.update", `custom:${id}`, { name, severity, spec });
    } else {
      const { rows } = await db().query<{ id: number }>(
        `INSERT INTO custom_rules (name, description, severity, mitre, spec, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id::int AS id`,
        [name, description, severity, mitre, JSON.stringify(spec), user.username],
      );
      id = rows[0].id;
      await audit(user, "customrule.create", `custom:${id}`, { name, severity, spec });
    }
    await notifyHub("rules");
    revalidatePath("/regole");
    revalidatePath(`/regole/personalizzate/${id}`);
    return { ok: true, id };
  } catch (error) {
    if (isUniqueViolation(error)) return { error: "Esiste già una regola con questo nome." };
    return failure(error) ?? { error: "Operazione non riuscita." };
  }
}

export async function testCustomRule(rawSpec: RuleSpec, hours: number): Promise<RuleTestResult> {
  const empty = { ok: false, windows: 0, groups: 0, more: false, ms: 0 };
  try {
    await actionUser("admin");
    const spec = cleanSpec(rawSpec);
    const res = await askHub<RuleTestResult>("customtest", { spec, hours: int(hours, 1, 168, 24) });
    return res ?? { ...empty, error: "L'hub non ha risposto entro 35 secondi." };
  } catch (error) {
    return { ...empty, error: failure(error)?.error };
  }
}

export async function deleteCustomRule(_state: FormState, form: FormData): Promise<FormState> {
  try {
    const user = await actionUser("admin");
    const id = Number(form.get("id"));
    if (!Number.isSafeInteger(id) || id <= 0) return { error: "Identificativo non valido." };
    const name = await transaction(async (client) => {
      const { rows } = await client.query<{ name: string }>("DELETE FROM custom_rules WHERE id = $1 RETURNING name", [id]);
      await client.query("DELETE FROM rules WHERE id = $1", [`custom:${id}`]);
      return rows[0]?.name;
    });
    if (!name) return { error: "Regola non trovata." };
    await audit(user, "customrule.delete", `custom:${id}`, { name });
    await notifyHub("rules");
    revalidatePath("/regole");
  } catch (error) {
    return failure(error);
  }
  redirect("/regole");
}
