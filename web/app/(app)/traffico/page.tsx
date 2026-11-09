import { ChartLegend, TimeSeriesChart } from "@/components/TimeSeriesChart";
import { BarList, Card, Country, Ip, Kpi, LoadError, PageHead, RangePicker, safe } from "@/components/ui";
import { requireUser } from "@/lib/auth";
import { countryName, fmtBps, fmtBytes, fmtNum } from "@/lib/format";
import { SERIES_COLORS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { topApps, topCountries, topDestinations, topHosts, topPorts, trafficSeries, trafficTotals } from "@/lib/queries/traffic";
import { parseRange, RANGES } from "@/lib/ranges";

export const metadata = { title: "Traffico" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

export default async function TrafficPage({ searchParams }: Props) {
  await requireUser();
  const range = parseRange((await searchParams).range, "24h");
  const seconds = RANGES[range].seconds;
  const [totals, series, apps, countries, hosts, dests, ports, names] = await Promise.all([
    safe(trafficTotals(range), { inB: 0, outB: 0, intB: 0, flows: 0 }, "totali"),
    safe(trafficSeries(range), { t: [], in: [], out: [], internal: [], bucket: 60 }, "serie"),
    safe(topApps(range, 15), [], "applicazioni"),
    safe(topCountries(range, 15), [], "paesi"),
    safe(topHosts(range, 15), [], "host"),
    safe(topDestinations(range, 15), [], "destinazioni"),
    safe(topPorts(range, 15), [], "porte"),
    deviceNames(),
  ]);
  const peak = (values: (number | null)[]) => Math.max(0, ...values.map((v) => v ?? 0));
  const flowLink = (extra: string) => `/flussi?range=${range}&${extra}`;

  return (
    <>
      <PageHead title="Traffico" sub="Quanto, verso dove e con quali applicazioni.">
        <RangePicker current={range} base="/traffico" />
      </PageHead>

      <div className="kpis">
        <Kpi label="Da internet" value={fmtBytes(totals.data.inB)} sub={`media ${fmtBps((totals.data.inB * 8) / seconds)} · picco ${fmtBps(peak(series.data.in))}`} />
        <Kpi label="Verso internet" value={fmtBytes(totals.data.outB)} sub={`media ${fmtBps((totals.data.outB * 8) / seconds)} · picco ${fmtBps(peak(series.data.out))}`} />
        <Kpi label="Interno" value={fmtBytes(totals.data.intB)} sub={`picco ${fmtBps(peak(series.data.internal))}`} />
        <Kpi label="Flussi" value={fmtNum(totals.data.flows)} sub={`${fmtNum(Math.round(totals.data.flows / (seconds / 60)))} al minuto`} href={flowLink("")} />
      </div>

      <Card title="Banda media">
        {series.failed ? (
          <LoadError what="la serie del traffico" />
        ) : (
          <>
            <TimeSeriesChart
              t={series.data.t}
              series={[
                { label: "Da internet", color: SERIES_COLORS.in, values: series.data.in },
                { label: "Verso internet", color: SERIES_COLORS.out, values: series.data.out },
                { label: "Interno", color: SERIES_COLORS.internal, values: series.data.internal },
              ]}
              rangeSeconds={seconds}
              unit="bps"
              height={280}
              ariaLabel={`Banda media, ${RANGES[range].label}`}
            />
            <ChartLegend
              items={[
                { label: "Da internet", color: SERIES_COLORS.in },
                { label: "Verso internet", color: SERIES_COLORS.out },
                { label: "Interno", color: SERIES_COLORS.internal },
              ]}
            />
            <p className="muted small">Un punto ogni {series.data.bucket >= 3600 ? `${series.data.bucket / 3600} h` : `${series.data.bucket / 60} min`}: i picchi più brevi sono mediati.</p>
          </>
        )}
      </Card>

      <div className="grid-2">
        <Card title="Applicazioni">
          {apps.failed ? <LoadError what="le applicazioni" /> : (
            <BarList
              rows={apps.data.map((r) => ({ key: r.app, label: r.app, value: r.bytes, extra: `${fmtNum(r.flows)} flussi`, href: flowLink(`app=${encodeURIComponent(r.app)}`) }))}
            />
          )}
        </Card>
        <Card title="Paesi (traffico con internet)">
          {countries.failed ? <LoadError what="i paesi" /> : (
            <BarList
              color={SERIES_COLORS.out}
              rows={countries.data.map((r) => ({
                key: r.country,
                label: (
                  <>
                    <Country cc={r.country} /> <span className="muted">{countryName(r.country)}</span>
                  </>
                ),
                value: r.bytes,
                extra: `${fmtNum(r.flows)} flussi`,
                href: flowLink(`cc=${r.country}`),
              }))}
            />
          )}
        </Card>
        <Card title="Host interni">
          {hosts.failed ? <LoadError what="gli host" /> : (
            <BarList
              color={SERIES_COLORS.internal}
              rows={hosts.data.map((r) => ({
                key: r.ip,
                label: <Ip ip={r.ip} names={names} range={range} />,
                value: r.sent + r.recv,
                extra: `↑ ${fmtBytes(r.sent)} ↓ ${fmtBytes(r.recv)}`,
              }))}
            />
          )}
        </Card>
        <Card title="Destinazioni su internet">
          {dests.failed ? <LoadError what="le destinazioni" /> : (
            <BarList
              color={SERIES_COLORS.out}
              rows={dests.data.map((r) => ({
                key: r.ip,
                label: (
                  <>
                    <Ip ip={r.ip} range={range} name={r.domain} /> <Country cc={r.country} />
                  </>
                ),
                value: r.bytes,
                extra: `${r.org ? `${r.org} · ` : ""}${fmtNum(r.clients)} client`,
              }))}
            />
          )}
        </Card>
      </div>

      <Card title="Servizi più usati (porta di destinazione, connessioni riuscite)">
        {ports.failed ? <LoadError what="le porte" /> : (
          <BarList
            format={(v) => `${fmtNum(v)} flussi`}
            rows={ports.data.map((r) => ({
              key: `${r.proto}${r.port}`,
              label: (
                <>
                  <span className="mono">
                    {r.proto}/{r.port}
                  </span>{" "}
                  <span className="muted">{r.app}</span>
                </>
              ),
              value: r.flows,
              extra: fmtBytes(r.bytes),
              href: flowLink(`port=${r.port}&proto=${r.proto}`),
            }))}
          />
        )}
      </Card>
    </>
  );
}
