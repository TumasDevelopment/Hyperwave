import { apiError, apiJson, readJson, withApi } from "@/lib/apitokens";
import { audit } from "@/lib/audit";
import { db, setting } from "@/lib/db";
import { notifyHub } from "@/lib/nats";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => apiJson({ live: await setting<boolean>("live", true) }));
}

export function PUT(request: Request) {
  return withApi(request, "admin", async (caller) => {
    const body = await readJson(request);
    if (!body || typeof body.live !== "boolean") return apiError(400, 'Serve {"live": true} oppure {"live": false}.');
    await db().query(
      `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('live', $1, now(), $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
      [JSON.stringify(body.live), caller.username],
    );
    await audit(caller, body.live ? "live.on" : "live.off", "", { api: true });
    await notifyHub("settings");
    return apiJson({ live: body.live });
  });
}
