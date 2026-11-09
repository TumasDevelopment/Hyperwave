import { apiError, apiJson, readJson, rowId, withApi } from "@/lib/apitokens";
import { audit } from "@/lib/audit";
import { db } from "@/lib/db";
import { deviceServices, getDevice } from "@/lib/queries/devices";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export function GET(request: Request, { params }: Ctx) {
  return withApi(request, "viewer", async () => {
    const id = rowId((await params).id);
    if (!id) return apiError(400, "Identificativo non valido.");
    const device = await getDevice(id);
    if (!device) return apiError(404, "Dispositivo non trovato.");
    return apiJson({ device, services: await deviceServices(id) });
  });
}

const TEXT_FIELDS: Record<string, number> = { name: 100, owner: 100, location: 100, notes: 4000 };

/** JSON con i soli campi da cambiare: name, owner, location, notes, tags (elenco), criticality, approved. */
export function PATCH(request: Request, { params }: Ctx) {
  return withApi(request, "analyst", async (caller) => {
    const id = rowId((await params).id);
    if (!id) return apiError(400, "Identificativo non valido.");
    const body = await readJson(request);
    if (!body) return apiError(400, "Corpo JSON non valido.");

    const sets: string[] = [];
    const values: unknown[] = [id];
    const param = (value: unknown) => {
      values.push(value);
      return `$${values.length}`;
    };
    for (const [field, max] of Object.entries(TEXT_FIELDS)) {
      if (body[field] === undefined) continue;
      if (typeof body[field] !== "string") return apiError(400, `${field}: deve essere un testo.`);
      sets.push(`${field} = ${param((body[field] as string).trim().slice(0, max))}`);
    }
    if (body.tags !== undefined) {
      if (!Array.isArray(body.tags) || body.tags.some((t) => typeof t !== "string" || t.length > 40)) {
        return apiError(400, "tags: elenco di testi di al massimo 40 caratteri.");
      }
      const tags = [...new Set((body.tags as string[]).map((t) => t.trim().toLowerCase()).filter(Boolean))].slice(0, 20);
      sets.push(`tags = ${param(tags)}`);
    }
    if (body.criticality !== undefined) {
      if (!["low", "normal", "high", "critical"].includes(String(body.criticality))) {
        return apiError(400, "criticality: low, normal, high oppure critical.");
      }
      sets.push(`criticality = ${param(body.criticality)}`);
    }
    if (body.approved !== undefined) {
      if (typeof body.approved !== "boolean") return apiError(400, "approved: true oppure false.");
      const a = param(body.approved);
      const by = param(caller.username);
      sets.push(`approved_by = CASE WHEN ${a} AND NOT approved THEN ${by} WHEN NOT ${a} THEN '' ELSE approved_by END`);
      sets.push(`approved_at = CASE WHEN ${a} AND NOT approved THEN now() WHEN NOT ${a} THEN NULL ELSE approved_at END`);
      sets.push(`approved = ${a}`);
    }
    if (sets.length === 0) return apiError(400, "Nessun campo da aggiornare.");

    const { rowCount } = await db().query(`UPDATE devices SET ${sets.join(", ")} WHERE id = $1`, values);
    if (!rowCount) return apiError(404, "Dispositivo non trovato.");
    await audit(caller, "device.update", String(id), { fields: Object.keys(body), api: true });
    return apiJson({ device: await getDevice(id) });
  });
}
