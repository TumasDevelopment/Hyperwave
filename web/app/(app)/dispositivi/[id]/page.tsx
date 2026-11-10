import Link from "next/link";
import { notFound } from "next/navigation";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { ChartLegend, TimeSeriesChart } from "@/components/TimeSeriesChart";
import { Card, Country, Empty, Field, Ip, LoadError, PageHead, safe, SeverityBadge, StatusBadge } from "@/components/ui";
import { deleteDevice, updateDevice } from "@/lib/actions/ops";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtDateTime, fmtNum } from "@/lib/format";
import { CRITICALITY_LABELS, SERIES_COLORS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { deviceAlerts } from "@/lib/queries/alerts";
import { sessionsFor } from "@/lib/queries/analysis";
import { deviceDomains, devicePeers, deviceServices, deviceTraffic, getDevice } from "@/lib/queries/devices";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props) {
  const id = Number((await params).id);
  const d = Number.isSafeInteger(id) && id > 0 ? await getDevice(id) : null;
  return { title: d ? d.name || d.hostname || d.ip || d.mac : "Dispositivo" };
}

export default async function DevicePage({ params }: Props) {
  const user = await requireUser();
  const id = Number((await params).id);
  if (!Number.isSafeInteger(id) || id <= 0) notFound();
  const d = await getDevice(id);
  if (!d) notFound();
  const ips = [...new Set([d.ip, ...d.ips].filter(Boolean))];
  const [services, traffic, peers, domains, alerts, names, sessions] = await Promise.all([
    deviceServices(id),
    safe(deviceTraffic(ips), [], "traffico del dispositivo"),
    safe(devicePeers(ips), [], "interlocutori"),
    safe(deviceDomains(ips), [], "domini"),
    deviceAlerts(id, ips),
    deviceNames(),
    safe(sessionsFor(ips), [], "sessioni"),
  ]);
  const analyst = can(user, "analyst");
  const title = d.name || d.hostname || d.ip || d.mac;

  return (
    <>
      <PageHead
        title={title}
        sub={
          <>
            <Link href="/dispositivi">Dispositivi</Link> · {d.type || "tipo sconosciuto"} · visto {fmtAgo(d.last_seen)}
          </>
        }
      >
        {d.ip && (
          <Link className="btn btn--small" href={`/flussi?range=24h&ip=${encodeURIComponent(d.ip)}`}>
            Flussi delle 24 h
          </Link>
        )}
      </PageHead>

      <div className="grid-2">
        <Card title="Identità">
          <dl className="dl">
            <dt>Indirizzi IP</dt>
            <dd className="mono">{ips.join(", ") || "—"}</dd>
            <dt>MAC</dt>
            <dd className="mono">{d.mac || "—"}</dd>
            <dt>Produttore</dt>
            <dd>{d.vendor || "—"}</dd>
            <dt>Nome in rete</dt>
            <dd>{d.hostname || "—"}</dd>
            <dt>Sistema</dt>
            <dd>{d.os || "—"}</dd>
            <dt>VLAN</dt>
            <dd>{d.vlan || "—"}</dd>
            <dt>Sensore</dt>
            <dd>{d.sensor || "—"}</dd>
            <dt>Prima volta</dt>
            <dd>{fmtDateTime(d.first_seen)}</dd>
            <dt>Ultima volta</dt>
            <dd>{fmtDateTime(d.last_seen)}</dd>
            <dt>Traffico totale</dt>
            <dd>
              {fmtBytes(d.bytes)} in {fmtNum(d.flows)} flussi
            </dd>
            <dt>Approvazione</dt>
            <dd>
              {d.approved ? (
                <>
                  <span className="pill pill--ok">Approvato</span> da {d.approved_by || "—"} il {fmtDateTime(d.approved_at)}
                </>
              ) : (
                <span className="pill pill--accent">Da approvare</span>
              )}
            </dd>
          </dl>
        </Card>

        <Card title="Scheda">
          {analyst ? (
            <ActionForm action={updateDevice} className="form-grid">
              <input type="hidden" name="id" value={d.id} />
              <Field label="Nome">
                <input name="name" defaultValue={d.name} maxLength={100} placeholder={d.hostname || "es. Stampante 2° piano"} />
              </Field>
              <Field label="Responsabile">
                <input name="owner" defaultValue={d.owner} maxLength={100} />
              </Field>
              <Field label="Posizione">
                <input name="location" defaultValue={d.location} maxLength={100} />
              </Field>
              <Field label="Criticità">
                <select name="criticality" defaultValue={d.criticality}>
                  {Object.entries(CRITICALITY_LABELS).map(([key, label]) => (
                    <option key={key} value={key}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Etichette" hint="Separate da virgole" wide>
                <input name="tags" defaultValue={d.tags.join(", ")} maxLength={500} />
              </Field>
              <Field label="Note" wide>
                <textarea name="notes" defaultValue={d.notes} rows={3} maxLength={4000} />
              </Field>
              <label className="check field--wide">
                <input type="checkbox" name="approved" defaultChecked={d.approved} /> Dispositivo conosciuto e approvato
              </label>
              <div className="field--wide">
                <Submit>Salva</Submit>
              </div>
            </ActionForm>
          ) : (
            <dl className="dl">
              <dt>Responsabile</dt>
              <dd>{d.owner || "—"}</dd>
              <dt>Posizione</dt>
              <dd>{d.location || "—"}</dd>
              <dt>Criticità</dt>
              <dd>{CRITICALITY_LABELS[d.criticality]}</dd>
              <dt>Etichette</dt>
              <dd>{d.tags.join(", ") || "—"}</dd>
              <dt>Note</dt>
              <dd className="prewrap">{d.notes || "—"}</dd>
            </dl>
          )}
        </Card>
      </div>

      <Card title="Traffico degli ultimi 7 giorni">
        {traffic.failed ? (
          <LoadError what="il traffico" />
        ) : traffic.data.length === 0 ? (
          <Empty>Nessun traffico registrato negli ultimi 7 giorni.</Empty>
        ) : (
          <>
            <TimeSeriesChart
              t={traffic.data.map((r) => r.t)}
              series={[
                { label: "Inviati", color: SERIES_COLORS.out, values: traffic.data.map((r) => r.sent), kind: "bars" },
                { label: "Ricevuti", color: SERIES_COLORS.in, values: traffic.data.map((r) => r.recv), kind: "bars" },
              ]}
              rangeSeconds={7 * 86400}
              unit="bytes"
              height={200}
              ariaLabel="Byte inviati e ricevuti per ora"
            />
            <ChartLegend
              items={[
                { label: "Inviati (per ora)", color: SERIES_COLORS.out },
                { label: "Ricevuti (per ora)", color: SERIES_COLORS.in },
              ]}
            />
          </>
        )}
      </Card>

      <div className="grid-2">
        <Card title="Con chi ha parlato · 24 h">
          {peers.failed ? (
            <LoadError what="gli interlocutori" />
          ) : peers.data.length === 0 ? (
            <Empty>Nessun flusso nelle ultime 24 ore.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Interlocutore</th>
                    <th>Servizio</th>
                    <th className="num">Dati</th>
                    <th className="num">Flussi</th>
                  </tr>
                </thead>
                <tbody>
                  {peers.data.map((p) => (
                    <tr key={p.peer}>
                      <td>
                        <Ip ip={p.peer} names={names} name={p.name || p.domain} />
                        <div className="muted small">
                          <Country cc={p.country} /> {p.org} {p.role === "server" && "· si collega a questo dispositivo"}
                        </div>
                      </td>
                      <td>{p.app}</td>
                      <td className="num">{fmtBytes(p.bytes)}</td>
                      <td className="num">
                        {fmtNum(p.flows)}
                        {p.failed > 0 && <div className="small text-warn">{fmtNum(p.failed)} senza risposta</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <div className="stack">
          <Card title="Servizi offerti">
            {services.length === 0 ? (
              <Empty>Nessun servizio: il dispositivo non ha risposto a connessioni in ingresso.</Empty>
            ) : (
              <table className="table table--compact">
                <tbody>
                  {services.map((s) => (
                    <tr key={`${s.proto}${s.port}`}>
                      <td className="mono">
                        {s.proto}/{s.port}
                      </td>
                      <td>{s.app}</td>
                      <td>{s.external ? <span className="pill pill--bad">Raggiunto da internet</span> : <span className="muted">solo interno</span>}</td>
                      <td className="num muted">{fmtNum(s.flows)} flussi</td>
                      <td className="muted">{fmtAgo(s.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <Card title="Domini richiesti · 24 h">
            {domains.failed ? (
              <LoadError what="i domini" />
            ) : domains.data.length === 0 ? (
              <Empty>Nessuna richiesta DNS nelle ultime 24 ore.</Empty>
            ) : (
              <table className="table table--compact">
                <tbody>
                  {domains.data.map((r) => (
                    <tr key={r.domain}>
                      <td className="mono">{r.domain || "(radice)"}</td>
                      <td className="num">{fmtNum(r.queries)}</td>
                      <td>{r.nx > 0 && <span className="small text-warn">{fmtNum(r.nx)} inesistenti</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      </div>

      <Card title="Accessi e sessioni · 7 giorni">
        {sessions.failed ? (
          <LoadError what="le sessioni" />
        ) : sessions.data.length === 0 ? (
          <Empty>Nessuna sessione SSH, RDP, SMB, Kerberos o NTLM negli ultimi 7 giorni.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Protocollo</th>
                  <th>Con</th>
                  <th>Utente</th>
                  <th>Dettagli</th>
                  <th className="num">Sessioni</th>
                  <th>Ultima</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.map((s) => (
                  <tr key={`${s.protocol}|${s.peer}|${s.role}|${s.user}`}>
                    <td className="nowrap">
                      {s.protocol.toUpperCase()} <span className="muted small">{s.role === "client" ? "in uscita" : "in entrata"}</span>
                    </td>
                    <td>
                      <Ip ip={s.peer} names={names} />
                    </td>
                    <td className="mono small">{s.user ? (s.domain ? `${s.domain}\\${s.user}` : s.user) : "—"}</td>
                    <td className="small">
                      {s.auth && <span className="muted">{s.auth} · </span>}
                      {s.info}
                      {s.weak && <span className="pill pill--warn">{s.weak}</span>}
                    </td>
                    <td className="num">{fmtNum(s.sessions)}</td>
                    <td className="muted nowrap">{fmtAgo(s.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Allarmi" className="anchor">
        <span id="allarmi" />
        {alerts.length === 0 ? (
          <Empty>Nessun allarme per questo dispositivo.</Empty>
        ) : (
          <table className="table">
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td>
                    <Link href={`/allarmi/${a.id}`}>{a.title}</Link>
                    <div className="muted small">{a.rule_name}</div>
                  </td>
                  <td className="muted">{fmtAgo(a.last_seen)}</td>
                  <td>
                    <StatusBadge status={a.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {can(user, "admin") && (
        <Card title="Zona pericolosa">
          <ActionForm action={deleteDevice} className="row">
            <input type="hidden" name="id" value={d.id} />
            <p className="muted">Elimina il dispositivo dall&apos;inventario (con le note). Se torna attivo ricompare come nuovo.</p>
            <ConfirmSubmit label="Elimina dispositivo" confirmLabel="Conferma eliminazione" />
          </ActionForm>
        </Card>
      )}
    </>
  );
}
