import Link from "next/link";
import { Card, Country, Direction, Empty, Field, Ip, Kpi, LoadError, PageHead, safe } from "@/components/ui";
import { requireUser } from "@/lib/auth";
import { fmtBytes, fmtDateTimeFull, fmtNum, fmtTime } from "@/lib/format";
import { DIRECTION_LABELS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { flowFilterQuery, knownApps, parseFlowFilter, searchFlows, summarizeFlows } from "@/lib/queries/flows";
import { listSensors } from "@/lib/queries/system";
import { RANGES } from "@/lib/ranges";

export const metadata = { title: "Flussi" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const LIMIT = 500;

export default async function FlowsPage({ searchParams }: Props) {
  await requireUser();
  const f = parseFlowFilter(await searchParams);
  const [flows, summary, apps, names, sensors] = await Promise.all([
    safe(searchFlows(f, LIMIT), [], "flussi"),
    safe(summarizeFlows(f), { flows: 0, bytes: 0, hosts: 0, failed: 0 }, "riepilogo flussi"),
    safe(knownApps(), [], "applicazioni"),
    deviceNames(),
    listSensors(),
  ]);
  const query = flowFilterQuery(f);
  const filtered = query.replace(/(^|&)range=[^&]*/, "") !== "";

  return (
    <>
      <PageHead
        title="Flussi"
        sub={
          f.at ? (
            <>
              Periodo di {RANGES[f.range].label} che termina il {fmtDateTimeFull(f.at * 1000)}.{" "}
              <Link href={`/flussi?${flowFilterQuery({ ...f, at: 0 })}`}>Torna ad adesso</Link>
            </>
          ) : (
            "Ogni connessione vista dai sensori: chi ha parlato con chi, quanto e come è andata."
          )
        }
      >
        <a className="btn btn--small" href={`/api/flussi.csv?${query}`}>
          Esporta CSV
        </a>
      </PageHead>

      <form className="filters" method="get">
        {f.at > 0 && <input type="hidden" name="at" value={f.at} />}
        <Field label="Periodo">
          <select name="range" defaultValue={f.range}>
            {Object.entries(RANGES).map(([key, r]) => (
              <option key={key} value={key}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Indirizzo o rete">
          <input name="ip" defaultValue={f.ip} placeholder="10.10.10.23 o 10.10.20.0/24" spellCheck={false} />
        </Field>
        <Field label="Altro capo">
          <input name="peer" defaultValue={f.peer} placeholder="indirizzo o rete" spellCheck={false} />
        </Field>
        <Field label="Porta">
          <input name="port" type="number" min={1} max={65535} defaultValue={f.port || ""} />
        </Field>
        <Field label="Protocollo">
          <select name="proto" defaultValue={f.proto}>
            <option value="">Tutti</option>
            <option>TCP</option>
            <option>UDP</option>
            <option>ICMP</option>
            <option value="ICMPv6">ICMPv6</option>
          </select>
        </Field>
        <Field label="Applicazione">
          <input name="app" list="apps" defaultValue={f.app} />
          <datalist id="apps">
            {apps.data.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
        </Field>
        <Field label="Dominio contiene">
          <input name="domain" defaultValue={f.domain} spellCheck={false} />
        </Field>
        <Field label="Paese">
          <input name="cc" defaultValue={f.country} maxLength={2} placeholder="IT" className="input--short" />
        </Field>
        <Field label="Direzione">
          <select name="dir" defaultValue={f.direction}>
            <option value="">Tutte</option>
            {Object.entries(DIRECTION_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Byte almeno">
          <input name="min" type="number" min={0} defaultValue={f.minBytes || ""} placeholder="1000000" />
        </Field>
        {sensors.length > 1 && (
          <Field label="Sensore">
            <select name="sensor" defaultValue={f.sensor || ""}>
              <option value="">Tutti</option>
              {sensors.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        <label className="check">
          <input type="checkbox" name="failed" value="1" defaultChecked={f.failed} /> Solo non riusciti
        </label>
        <div className="filters__actions">
          <button type="submit" className="btn btn--primary">
            Cerca
          </button>
          {filtered && (
            <Link href={`/flussi?range=${f.range}`} className="btn btn--ghost">
              Azzera
            </Link>
          )}
        </div>
      </form>

      <div className="kpis kpis--small">
        <Kpi label="Flussi trovati" value={fmtNum(summary.data.flows)} />
        <Kpi label="Dati scambiati" value={fmtBytes(summary.data.bytes)} />
        <Kpi label="Origini diverse" value={fmtNum(summary.data.hosts)} />
        <Kpi label="Non riusciti" value={fmtNum(summary.data.failed)} tone={summary.data.failed > 0 ? "warn" : undefined} />
      </div>

      <Card title={summary.data.flows > LIMIT ? `I ${LIMIT} più recenti` : undefined}>
        {flows.failed ? (
          <LoadError what="i flussi" />
        ) : flows.data.length === 0 ? (
          <Empty>Nessun flusso con questi filtri nel periodo scelto.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--flows">
              <thead>
                <tr>
                  <th>Ora</th>
                  <th>Origine</th>
                  <th>Destinazione</th>
                  <th>Servizio</th>
                  <th>Paese</th>
                  <th className="num">Inviati</th>
                  <th className="num">Ricevuti</th>
                  <th className="num">Durata</th>
                  <th>Esito</th>
                </tr>
              </thead>
              <tbody>
                {flows.data.map((r, i) => {
                  const seconds = (new Date(`${r.ts_end.replace(" ", "T")}Z`).getTime() - new Date(`${r.ts.replace(" ", "T")}Z`).getTime()) / 1000;
                  return (
                    <tr key={`${r.ts}-${r.src}-${r.sport}-${i}`}>
                      <td className="mono nowrap" title={fmtDateTimeFull(r.ts)}>
                        {fmtTime(r.ts)}
                      </td>
                      <td>
                        <Ip ip={r.src} names={names} name={r.src_name} range={f.range} port={r.sport} />
                      </td>
                      <td>
                        <Ip ip={r.dst} names={names} name={r.dst_name || r.domain} range={f.range} port={r.dport} />
                      </td>
                      <td>
                        <span className="mono muted">{r.proto}</span> {r.app}
                        <div className="small">
                          <Direction value={r.direction} />
                          {r.vlan > 0 && <span className="muted"> · VLAN {r.vlan}</span>}
                        </div>
                      </td>
                      <td>
                        <Country cc={r.country} />
                        {r.as_org && <div className="muted small ellipsis">{r.as_org}</div>}
                      </td>
                      <td className="num">{fmtBytes(r.bytes_out)}</td>
                      <td className="num">{fmtBytes(r.bytes_in)}</td>
                      <td className="num muted">{seconds >= 1 ? `${fmtNum(Math.round(seconds))} s` : "<1 s"}</td>
                      <td className="nowrap">
                        {r.est ? <span className="pill pill--ok">Riuscito</span> : <span className="pill pill--warn">Senza risposta</span>}
                        <div className="muted small mono">
                          {r.flags}
                          {r.rtt > 0 && ` · ${fmtNum(Math.round(r.rtt))} ms`}
                          {r.retrans > 0 && ` · ${r.retrans} ritrasm.`}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
