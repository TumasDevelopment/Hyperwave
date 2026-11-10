import Link from "next/link";
import { notFound } from "next/navigation";
import { ActionForm, Submit } from "@/components/forms";
import { Card, Country, Empty, Field, Ip, LoadError, PageHead, safe, SeverityBadge, StatusBadge } from "@/components/ui";
import { addAlertNote, assignAlert, createSuppression, setAlertStatus } from "@/lib/actions/ops";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtDateTime, fmtDateTimeFull, fmtNum, fmtTime } from "@/lib/format";
import { mitreUrl, RESOLUTIONS, STATUS_LABELS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { alertFlows, alertNotes, assignableUsers, getAlert, relatedAlerts } from "@/lib/queries/alerts";
import { flowFilterQuery } from "@/lib/queries/flows";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props) {
  const id = Number((await params).id);
  const a = Number.isSafeInteger(id) && id > 0 ? await getAlert(id) : null;
  return { title: a ? a.title : "Allarme" };
}

const DETAIL_LABELS: Record<string, string> = {
  ports: "Porte provate",
  hosts: "Host raggiunti",
  targets: "Destinazioni",
  attempts: "Tentativi",
  failed: "Non riusciti",
  bytes: "Byte",
  bytes_out: "Byte inviati",
  interval_s: "Intervallo (s)",
  jitter: "Variabilità",
  connections: "Connessioni",
  domains: "Domini",
  queries: "Richieste",
  entropy: "Entropia",
  country: "Paese",
  examples: "Esempi",
  sni: "Nome del server (SNI)",
  version: "Versione",
  expiry: "Scadenza",
  service: "Servizio",
  port: "Porta",
  signature: "Firma",
  category: "Categoria",
};

function DetailValue({ k, v }: { k: string; v: unknown }) {
  if (Array.isArray(v)) return <span className="mono small">{v.slice(0, 30).map(String).join(", ")}{v.length > 30 && ` … (+${v.length - 30})`}</span>;
  if (typeof v === "number") {
    if (/bytes/.test(k)) return <>{fmtBytes(v)}</>;
    if (k === "expiry" && v > 1e9) return <>{fmtDateTime(v * 1000)}</>;
    return <>{fmtNum(Math.round(v * 100) / 100)}</>;
  }
  if (v && typeof v === "object") return <code className="small">{JSON.stringify(v)}</code>;
  return <>{String(v ?? "—")}</>;
}

export default async function AlertPage({ params }: Props) {
  const user = await requireUser();
  const id = Number((await params).id);
  if (!Number.isSafeInteger(id) || id <= 0) notFound();
  const a = await getAlert(id);
  if (!a) notFound();
  const [notes, related, flows, users, names] = await Promise.all([
    alertNotes(id),
    relatedAlerts(a),
    safe(alertFlows(a), [], "flussi dell'allarme"),
    assignableUsers(),
    deviceNames(),
  ]);
  const analyst = can(user, "analyst");
  const mitre = a.mitre ? mitreUrl(a.mitre) : null;
  const at = Math.floor(new Date(a.last_seen).getTime() / 1000) + 600;
  const span = (new Date(a.last_seen).getTime() - new Date(a.first_seen).getTime()) / 1000;
  const flowsHref = `/flussi?${flowFilterQuery({
    range: span > 6 * 3600 ? "24h" : span > 3600 ? "6h" : "1h",
    at,
    ip: a.src_ip,
    peer: /^[0-9a-f.:/]+$/i.test(a.dst_ip) ? a.dst_ip : "",
  })}`;
  const isIp = (v: string) => /^[0-9a-f.:]+$/i.test(v);

  return (
    <>
      <PageHead
        title={a.title}
        sub={
          <>
            <Link href="/allarmi">Allarmi</Link> · n. {a.id} · {a.rule_name}
            {a.incident_id && (
              <>
                {" "}
                · fa parte dell&apos;<Link href={`/incidenti/${a.incident_id}`}>incidente n. {a.incident_id}</Link>
              </>
            )}
          </>
        }
      >
        <SeverityBadge severity={a.severity} /> <StatusBadge status={a.status} />
      </PageHead>

      <div className="grid-2">
        <Card title="Cosa è successo">
          {a.summary && <p className="lead">{a.summary}</p>}
          <dl className="dl">
            <dt>Origine</dt>
            <dd>{a.src_ip ? <Ip ip={a.src_ip} names={names} /> : "—"}</dd>
            <dt>Destinazione</dt>
            <dd>{a.dst_ip ? isIp(a.dst_ip) ? <Ip ip={a.dst_ip} names={names} /> : <span className="mono">{a.dst_ip}</span> : "—"}</dd>
            {a.device_id && (
              <>
                <dt>Dispositivo</dt>
                <dd>
                  <Link href={`/dispositivi/${a.device_id}`}>{a.device_name || "scheda del dispositivo"}</Link>
                </dd>
              </>
            )}
            <dt>Prima volta</dt>
            <dd>{fmtDateTimeFull(a.first_seen)}</dd>
            <dt>Ultima volta</dt>
            <dd>
              {fmtDateTimeFull(a.last_seen)} <span className="muted">({fmtAgo(a.last_seen)})</span>
            </dd>
            <dt>Ripetizioni</dt>
            <dd>{fmtNum(a.count)}</dd>
            {a.sensor && (
              <>
                <dt>Sensore</dt>
                <dd>{a.sensor}</dd>
              </>
            )}
            {a.mitre && (
              <>
                <dt>MITRE ATT&amp;CK</dt>
                <dd>
                  {mitre ? (
                    <a href={mitre} target="_blank" rel="noopener noreferrer" className="mono">
                      {a.mitre}
                    </a>
                  ) : (
                    <span className="mono">{a.mitre}</span>
                  )}
                </dd>
              </>
            )}
            {Object.entries(a.detail ?? {}).map(([k, v]) => (
              <div key={k} className="dl__row">
                <dt>{DETAIL_LABELS[k] ?? k}</dt>
                <dd>
                  <DetailValue k={k} v={v} />
                </dd>
              </div>
            ))}
            {a.status === "resolved" && (
              <>
                <dt>Chiuso</dt>
                <dd>
                  {RESOLUTIONS[a.resolution] ?? a.resolution} · {a.resolved_by} · {fmtDateTime(a.resolved_at)}
                </dd>
              </>
            )}
          </dl>
        </Card>

        <div className="stack">
          {analyst && (
            <Card title="Gestione">
              <ActionForm action={setAlertStatus} className="form-grid">
                <input type="hidden" name="id" value={a.id} />
                <Field label="Stato">
                  <select name="status" defaultValue={a.status === "open" ? "ack" : a.status === "ack" ? "resolved" : "open"}>
                    {Object.entries(STATUS_LABELS).map(([key, label]) => (
                      <option key={key} value={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Esito (per chiudere)">
                  <select name="resolution" defaultValue={a.resolution}>
                    <option value="">—</option>
                    {Object.entries(RESOLUTIONS).map(([key, label]) => (
                      <option key={key} value={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Nota (facoltativa)" wide>
                  <input name="note" maxLength={4000} />
                </Field>
                <div className="field--wide">
                  <Submit>Aggiorna stato</Submit>
                </div>
              </ActionForm>
              <hr />
              <ActionForm action={assignAlert} className="row">
                <input type="hidden" name="id" value={a.id} />
                <select name="assignee" defaultValue={a.assignee} aria-label="Assegna a">
                  <option value="">Nessuno</option>
                  {users.map((u) => (
                    <option key={u}>{u}</option>
                  ))}
                </select>
                <Submit className="btn btn--small">Assegna</Submit>
                {a.assignee !== user.username && (
                  <Submit className="btn btn--small btn--ghost" name="assignee" value="@me">
                    Prendo io
                  </Submit>
                )}
              </ActionForm>
            </Card>
          )}

          <Card title="Cronologia">
            <ol className="timeline">
              <li>
                <span className="timeline__when">{fmtDateTime(a.first_seen)}</span>
                <span>Allarme aperto dal motore di rilevamento</span>
              </li>
              {notes.map((n) => (
                <li key={n.id} className={`timeline--${n.kind}`}>
                  <span className="timeline__when">
                    {fmtDateTime(n.ts)} · {n.username}
                  </span>
                  <span className="prewrap">{n.text}</span>
                </li>
              ))}
            </ol>
            {analyst && (
              <ActionForm action={addAlertNote} resetOnOk className="stack">
                <input type="hidden" name="id" value={a.id} />
                <textarea name="note" rows={2} maxLength={4000} placeholder="Aggiungi una nota: verifiche fatte, contatti, decisioni…" required />
                <div>
                  <Submit className="btn btn--small">Aggiungi nota</Submit>
                </div>
              </ActionForm>
            )}
          </Card>

          {analyst && a.src_ip && (
            <Card title="Non segnalare più">
              <details>
                <summary>Crea un&apos;eccezione per questo caso</summary>
                <ActionForm action={createSuppression} className="form-grid">
                  <input type="hidden" name="alert_id" value={a.id} />
                  <Field label="Regola">
                    <select name="rule" defaultValue={a.rule}>
                      <option value={a.rule}>{a.rule_name}</option>
                      <option value="">Tutte le regole</option>
                    </select>
                  </Field>
                  <Field label="Durata">
                    <select name="days" defaultValue="30">
                      <option value="1">1 giorno</option>
                      <option value="7">7 giorni</option>
                      <option value="30">30 giorni</option>
                      <option value="90">90 giorni</option>
                      <option value="365">1 anno</option>
                      <option value="0">Sempre</option>
                    </select>
                  </Field>
                  <Field label="Origine" hint="Indirizzo o rete CIDR, vuoto = qualsiasi">
                    <input name="src" defaultValue={a.src_ip} />
                  </Field>
                  <Field label="Destinazione" hint="Vuoto = qualsiasi">
                    <input name="dst" defaultValue={isIp(a.dst_ip) ? a.dst_ip : ""} />
                  </Field>
                  <Field label="Motivo" wide>
                    <input name="reason" required maxLength={500} placeholder="es. backup notturno verso il fornitore" />
                  </Field>
                  <label className="check field--wide">
                    <input type="checkbox" name="resolve" defaultChecked /> Chiudi anche questo allarme come attività legittima
                  </label>
                  <div className="field--wide">
                    <Submit>Crea eccezione</Submit>
                  </div>
                </ActionForm>
              </details>
            </Card>
          )}
        </div>
      </div>

      <Card
        title="Flussi collegati"
        actions={
          <Link href={flowsHref} className="btn btn--small btn--ghost">
            Apri nei flussi
          </Link>
        }
      >
        {flows.failed ? (
          <LoadError what="i flussi" />
        ) : flows.data.length === 0 ? (
          <Empty>Nessun flusso tra questi indirizzi nel periodo dell&apos;allarme (potrebbe essere già scaduto).</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Ora</th>
                  <th>Origine</th>
                  <th>Destinazione</th>
                  <th>Servizio</th>
                  <th className="num">Inviati</th>
                  <th className="num">Ricevuti</th>
                  <th>Esito</th>
                </tr>
              </thead>
              <tbody>
                {flows.data.map((r, i) => (
                  <tr key={`${r.ts}-${i}`}>
                    <td className="mono nowrap" title={fmtDateTimeFull(r.ts)}>
                      {fmtTime(r.ts)}
                    </td>
                    <td>
                      <Ip ip={r.src} names={names} port={r.sport} />
                    </td>
                    <td>
                      <Ip ip={r.dst} names={names} name={r.domain} port={r.dport} /> <Country cc={r.country} />
                    </td>
                    <td>
                      <span className="mono muted">{r.proto}</span> {r.app}
                    </td>
                    <td className="num">{fmtBytes(r.bytes_out)}</td>
                    <td className="num">{fmtBytes(r.bytes_in)}</td>
                    <td className="mono small">{r.est ? r.flags : <span className="text-warn">{r.flags || "nessuna risposta"}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {related.length > 0 && (
        <Card title="Altri allarmi dello stesso indirizzo · 30 giorni">
          <table className="table table--compact">
            <tbody>
              {related.map((r) => (
                <tr key={r.id}>
                  <td>
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td>
                    <Link href={`/allarmi/${r.id}`}>{r.title}</Link>
                  </td>
                  <td className="muted">{fmtAgo(r.last_seen)}</td>
                  <td>
                    <StatusBadge status={r.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}
