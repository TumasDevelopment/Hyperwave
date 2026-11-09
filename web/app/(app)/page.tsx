import Link from "next/link";
import { AutoRefresh } from "@/components/AutoRefresh";
import { LiveOverview } from "@/components/LiveOverview";
import { ChartLegend, TimeSeriesChart } from "@/components/TimeSeriesChart";
import { BarList, Card, Country, Empty, Ip, Kpi, LoadError, PageHead, safe, SeverityBadge, StatusBadge } from "@/components/ui";
import { requireUser } from "@/lib/auth";
import { setting } from "@/lib/db";
import { countryName, fmtAgo, fmtBytes, fmtNum } from "@/lib/format";
import { SERIES_COLORS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { listAlerts } from "@/lib/queries/alerts";
import { newDevices, overviewCounts } from "@/lib/queries/overview";
import { recentRates, topApps, topCountries, topHosts, trafficSeries, trafficTotals } from "@/lib/queries/traffic";

export const metadata = { title: "Panoramica" };

export default async function OverviewPage() {
  await requireUser();
  const [counts, live, alerts, devices, names, totals, series, apps, countries, hosts, rates] = await Promise.all([
    overviewCounts(),
    setting<boolean>("live", true),
    listAlerts({ status: "active", severity: "", rule: "", q: "", days: 0, assignee: "" }, 8),
    newDevices(6),
    deviceNames(),
    safe(trafficTotals("24h"), { inB: 0, outB: 0, intB: 0, flows: 0 }, "totali del traffico"),
    safe(trafficSeries("24h"), { t: [], in: [], out: [], internal: [], bucket: 900 }, "serie del traffico"),
    safe(topApps("24h", 8), [], "applicazioni"),
    safe(topCountries("24h", 8), [], "paesi"),
    safe(topHosts("24h", 8), [], "host"),
    safe(recentRates(), [], "contatori recenti"),
  ]);

  const seed = {
    t: rates.data.map((r) => r.t),
    in: rates.data.map((r) => r.bin),
    out: rates.data.map((r) => r.bout),
    int: rates.data.map((r) => r.bint),
  };
  const chFailed = totals.failed || series.failed;

  return (
    <>
      <AutoRefresh seconds={60} />
      <PageHead title="Panoramica" sub="Cosa sta succedendo in rete adesso e nelle ultime 24 ore." />

      <div className="kpis">
        <Kpi label="Da internet · 24 h" value={fmtBytes(totals.data.inB)} sub={`verso internet ${fmtBytes(totals.data.outB)}`} href="/traffico" />
        <Kpi label="Traffico interno · 24 h" value={fmtBytes(totals.data.intB)} sub={`${fmtNum(totals.data.flows)} flussi in tutto`} href="/flussi?range=24h&dir=internal" />
        <Kpi
          label="Allarmi da gestire"
          value={fmtNum(counts.alerts_open)}
          sub={`${counts.alerts_critical} critici · ${counts.alerts_high} alti · ${counts.alerts_today} nuovi oggi`}
          tone={counts.alerts_critical > 0 ? "bad" : counts.alerts_high > 0 ? "warn" : "ok"}
          href="/allarmi"
        />
        <Kpi
          label="Dispositivi"
          value={fmtNum(counts.devices)}
          sub={`${counts.devices_active} attivi nell'ultima ora · ${counts.devices_new} nuovi`}
          tone={counts.devices_unapproved > 0 ? "accent" : undefined}
          href="/dispositivi"
        />
        <Kpi
          label="Sensori in linea"
          value={`${counts.sensors_online}/${counts.sensors}`}
          sub={live ? "live acceso" : "live spento"}
          tone={counts.sensors > 0 && counts.sensors_online < counts.sensors ? "warn" : !live ? "warn" : "ok"}
          href="/sensori"
        />
      </div>

      <Card title="In tempo reale">
        <LiveOverview seed={seed} initialLive={live} />
      </Card>

      <Card
        title="Banda nelle ultime 24 ore"
        actions={
          <Link href="/traffico?range=24h" className="btn btn--small btn--ghost">
            Dettagli
          </Link>
        }
      >
        {chFailed ? (
          <LoadError what="il traffico" />
        ) : (
          <>
            <TimeSeriesChart
              t={series.data.t}
              series={[
                { label: "Da internet", color: SERIES_COLORS.in, values: series.data.in },
                { label: "Verso internet", color: SERIES_COLORS.out, values: series.data.out },
                { label: "Interno", color: SERIES_COLORS.internal, values: series.data.internal },
              ]}
              rangeSeconds={86400}
              unit="bps"
              ariaLabel="Banda media delle ultime 24 ore"
            />
            <ChartLegend
              items={[
                { label: "Da internet", color: SERIES_COLORS.in },
                { label: "Verso internet", color: SERIES_COLORS.out },
                { label: "Interno", color: SERIES_COLORS.internal },
              ]}
            />
          </>
        )}
      </Card>

      <div className="grid-2">
        <Card
          title="Allarmi da gestire"
          actions={
            <Link href="/allarmi" className="btn btn--small btn--ghost">
              Tutti
            </Link>
          }
        >
          {alerts.length === 0 ? (
            <Empty>Nessun allarme aperto.</Empty>
          ) : (
            <ul className="alert-list">
              {alerts.map((a) => (
                <li key={a.id}>
                  <SeverityBadge severity={a.severity} />
                  <div>
                    <Link href={`/allarmi/${a.id}`}>{a.title}</Link>
                    <div className="muted small">
                      {a.rule_name} · {fmtAgo(a.last_seen)} {a.count > 1 && `· ${fmtNum(a.count)} volte`}
                    </div>
                  </div>
                  <StatusBadge status={a.status} />
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card
          title="Ultimi dispositivi comparsi"
          actions={
            <Link href="/dispositivi?status=unapproved" className="btn btn--small btn--ghost">
              Da approvare: {counts.devices_unapproved}
            </Link>
          }
        >
          {devices.length === 0 ? (
            <Empty>Ancora nessun dispositivo: arriveranno con i primi dati dei sensori.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <Link href={`/dispositivi/${d.id}`}>{d.label || d.ip || d.mac}</Link>
                      <div className="muted small mono">{d.ip || d.mac}</div>
                    </td>
                    <td className="muted">{d.type || d.vendor || "—"}</td>
                    <td className="muted">{fmtAgo(d.first_seen)}</td>
                    <td>{d.approved ? <span className="pill pill--ok">Approvato</span> : <span className="pill pill--accent">Nuovo</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid-3">
        <Card title="Applicazioni · 24 h">
          {apps.failed ? (
            <LoadError what="le applicazioni" />
          ) : (
            <BarList rows={apps.data.map((r) => ({ key: r.app, label: r.app, value: r.bytes, href: `/flussi?range=24h&app=${encodeURIComponent(r.app)}` }))} />
          )}
        </Card>
        <Card title="Paesi · 24 h">
          {countries.failed ? (
            <LoadError what="i paesi" />
          ) : (
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
                href: `/flussi?range=24h&cc=${r.country}`,
              }))}
            />
          )}
        </Card>
        <Card title="Host interni più attivi · 24 h">
          {hosts.failed ? (
            <LoadError what="gli host" />
          ) : (
            <BarList
              color={SERIES_COLORS.internal}
              rows={hosts.data.map((r) => ({ key: r.ip, label: <Ip ip={r.ip} names={names} />, value: r.sent + r.recv }))}
            />
          )}
        </Card>
      </div>
    </>
  );
}
