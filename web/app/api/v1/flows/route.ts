import { apiJson, withApi } from "@/lib/apitokens";
import { parseFlowFilter, searchFlows } from "@/lib/queries/flows";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return withApi(request, "viewer", async () => {
    const p = Object.fromEntries(new URL(request.url).searchParams);
    const limit = Math.min(Math.max(Number(p.limit) || 1000, 1), 10000);
    const filter = parseFlowFilter(p);
    const flows = await searchFlows(filter, limit);
    return apiJson({ count: flows.length, filter, flows });
  });
}
