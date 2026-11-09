import { apiJson, withApi } from "@/lib/apitokens";
import { listSensors, sensorState } from "@/lib/queries/system";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => {
    const sensors = await listSensors();
    return apiJson({ sensors: sensors.map((s) => ({ ...s, state: sensorState(s) })) });
  });
}
