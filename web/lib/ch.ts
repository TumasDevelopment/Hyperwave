import "server-only";

// ClickHouse via HTTP. I valori arrivano sempre come parametri tipizzati ({nome:Tipo}),
// mai concatenati nel testo della query. Il sito legge soltanto (readonly=2).

type Param = string | number | string[] | number[];

export class ClickHouseError extends Error {}

export async function ch<T>(sql: string, params: Record<string, Param> = {}, timeoutSeconds = 30): Promise<T[]> {
  const url = new URL(process.env.CLICKHOUSE_URL || "http://127.0.0.1:8123");
  url.searchParams.set("database", process.env.CLICKHOUSE_DB || "hyperwave");
  url.searchParams.set("readonly", "2");
  url.searchParams.set("max_execution_time", String(timeoutSeconds));
  url.searchParams.set("output_format_json_quote_64bit_integers", "0");
  url.searchParams.set("output_format_json_quote_64bit_floats", "0");
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(
      `param_${key}`,
      Array.isArray(value) ? `[${value.map((v) => (typeof v === "number" ? String(v) : `'${String(v).replace(/[\\']/g, "\\$&")}'`)).join(",")}]` : String(value),
    );
  }
  const headers: Record<string, string> = { "Content-Type": "text/plain; charset=utf-8" };
  if (process.env.CLICKHOUSE_USER) headers["X-ClickHouse-User"] = process.env.CLICKHOUSE_USER;
  if (process.env.CLICKHOUSE_PASSWORD) headers["X-ClickHouse-Key"] = process.env.CLICKHOUSE_PASSWORD;

  const response = await fetch(url, {
    method: "POST",
    body: `${sql}\nFORMAT JSON`,
    headers,
    cache: "no-store",
    signal: AbortSignal.timeout((timeoutSeconds + 5) * 1000),
  });
  if (!response.ok) {
    const text = (await response.text()).slice(0, 400);
    throw new ClickHouseError(`ClickHouse ${response.status}: ${text}`);
  }
  const json = (await response.json()) as { data: T[] };
  return json.data;
}

/** Condizione sul tempo per le tabelle grezze (colonna ts) con i parametri t0 e t1 in secondi. */
export const TS_RANGE = "ts >= toDateTime({t0:UInt32}, 'UTC') AND ts < toDateTime({t1:UInt32}, 'UTC')";
