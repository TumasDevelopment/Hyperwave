import Link from "next/link";
import { notFound } from "next/navigation";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Card, Field, Ip, PageHead, SeverityBadge, StatusBadge } from "@/components/ui";
import { addIncidentNote, assignIncident, removeIncidentAlert, setIncidentStatus } from "@/lib/actions/incidents";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtDateTimeFull, fmtDuration, fmtNum } from "@/lib/format";
import { INCIDENT_STATUS_LABELS, mitreUrl, RESOLUTIONS } from "@/lib/labels";
import { TACTICS, technique } from "@/lib/mitre";
import { deviceNames } from "@/lib/names";
import { assignableUsers, incidentAlerts } from "@/lib/queries/alerts";
import { getIncident, incidentNotes } from "@/lib/queries/incidents";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props) {
  const id = Number((await params).id);
  const i = Number.isSafeInteger(id) && id > 0 ? await getIncident(id) : null;
  return { title: i ? i.title : "Incidente" };
}

export default async function IncidentPage({ params }: Props) {
  const user = await requireUser();
  const id = Number((await params).id);
  if (!Number.isSafeInteger(id) || id <= 0) notFound();
  const inc = await getIncident(id);
  if (!inc) notFound();
  const [alerts, notes, users, names] = await Promise.all([incidentAlerts(id), incidentNotes(id), assignableUsers(), deviceNames()]);
  const analyst = can(user, "analyst");
  const now = Date.now();
  const span = (new Date(inc.last_seen).getTime() - new Date(inc.first_seen).getTime()) / 1000;

  // catena ATT&CK: per ogni fase le tecniche viste e il primo momento in cui compaiono
  const chain = TACTICS.map((t) => {
    const hits = alerts.filter((a) => a.mitre && technique(a.mitre).tactic === t.id);
    return {
      ...t,
      techniques: [...new Set(hits.map((a) => a.mitre))],
      first: hits.length ? hits.reduce((m, a) => (a.first_seen < m ? a.first_seen : m), hits[0].first_seen) : null,
    };
  });
  const other = alerts.filter((a) => !a.mitre || !technique(a.mitre).tactic);
  const rules = [...new Map(alerts.map((a) => [a.rule, a.rule_name])).values()];

  return (
    <>
      <PageHead
        title={inc.title}
        sub={
          <>
            <Link href="/incidenti">Incidenti</Link> · n. {inc.id} · aperto {fmtAgo(inc.created_at, now)}
          </>
        }
      >
        <SeverityBadge severity={inc.severity} /> <span className={`status status--inc-${inc.status}`}>{INCIDENT_STATUS_LABELS[inc.status]}</span>
      </PageHead>

      <div className="grid-2">
        <Card title="Riepilogo">
          <dl className="dl">
            <dt>Dispositivo</dt>
            <dd>
              <Ip ip={inc.key_entity} names={names} />
              {inc.device_id && (
                <>
                  {" "}
                  · <Link href={`/dispositivi/${inc.device_id}`}>scheda</Link>
                </>
              )}
            </dd>
            <dt>Periodo</dt>
            <dd>
              {fmtDateTime(inc.first_seen)} – {fmtDateTime(inc.last_seen)} <span className="muted">({fmtDuration(span)})</span>
            </dd>
            <dt>Allarmi</dt>
            <dd>
              {fmtNum(inc.alert_count)} da {inc.rule_count} {inc.rule_count === 1 ? "regola" : "regole"}
              {inc.open_alerts > 0 && <span className="muted"> · {inc.open_alerts} ancora aperti</span>}
            </dd>
            <dt>Regole</dt>
            <dd>{rules.join(", ") || "—"}</dd>
            <dt>Assegnato</dt>
            <dd>{inc.assignee || "—"}</dd>
            {inc.status === "closed" && (
              <>
                <dt>Chiuso</dt>
                <dd>
                  {RESOLUTIONS[inc.resolution] ?? inc.resolution} · {inc.closed_by} {fmtAgo(inc.closed_at, now)}
                </dd>
              </>
            )}
          </dl>
        </Card>

        {analyst && (
          <Card title="Gestione">
            <ActionForm action={setIncidentStatus} className="form-grid">
              <input type="hidden" name="id" value={inc.id} />
              <Field label="Stato">
                <select
                  name="status"
                  defaultValue={inc.status === "open" ? "investigating" : inc.status === "investigating" ? "contained" : inc.status === "contained" ? "closed" : "open"}
                >
                  {Object.entries(INCIDENT_STATUS_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Esito (per chiudere)">
                <select name="resolution" defaultValue={inc.resolution}>
                  <option value="">—</option>
                  {Object.entries(RESOLUTIONS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
              </Field>
              <label className="check field--wide">
                <input type="checkbox" name="close_alerts" defaultChecked /> Chiudendo, chiudi con lo stesso esito anche gli allarmi ancora aperti
              </label>
              <Field label="Nota (facoltativa)" wide>
                <input name="note" maxLength={4000} />
              </Field>
              <div className="field--wide">
                <Submit>Aggiorna stato</Submit>
              </div>
            </ActionForm>
            <hr />
            <ActionForm action={assignIncident} className="row">
              <input type="hidden" name="id" value={inc.id} />
              <select name="assignee" defaultValue={inc.assignee} aria-label="Assegna a">
                <option value="">Nessuno</option>
                {users.map((u) => (
                  <option key={u}>{u}</option>
                ))}
              </select>
              <Submit className="btn btn--small">Assegna</Submit>
              {inc.assignee !== user.username && (
                <Submit className="btn btn--small btn--ghost" name="assignee" value="@me">
                  Prendo io
                </Submit>
              )}
            </ActionForm>
          </Card>
        )}
      </div>

      <Card title="Catena ATT&CK">
        <ol className="chain">
          {chain.map((s) => (
            <li key={s.id} className={`chain__step ${s.techniques.length ? "chain__step--on" : ""}`}>
              <span className="chain__label">{s.label}</span>
              {s.techniques.map((t) => {
                const url = mitreUrl(t);
                return (
                  <span key={t} className="chain__tech small" title={technique(t).name}>
                    {url ? (
                      <a href={url} target="_blank" rel="noopener noreferrer" className="mono">
                        {t}
                      </a>
                    ) : (
                      <span className="mono">{t}</span>
                    )}{" "}
                    {technique(t).name}
                  </span>
                );
              })}
              {s.first && <span className="muted small">dal {fmtDateTime(s.first)}</span>}
            </li>
          ))}
        </ol>
        {other.length > 0 && (
          <p className="muted small mt">
            {other.length} {other.length === 1 ? "allarme senza tecnica ATT&CK" : "allarmi senza tecnica ATT&CK"} (inventario, politiche, regole
            personalizzate senza tecnica).
          </p>
        )}
      </Card>

      <Card title={`Cronologia degli allarmi (${alerts.length})`}>
        <ol className="timeline">
          {alerts.map((a) => {
            const t = a.mitre ? technique(a.mitre) : null;
            return (
              <li key={a.id}>
                <span className="timeline__when" title={fmtDateTimeFull(a.first_seen)}>
                  {fmtDateTime(a.first_seen)}
                  {a.count > 1 && ` · ${fmtNum(a.count)} volte fino a ${fmtDateTime(a.last_seen)}`}
                </span>
                <span>
                  <SeverityBadge severity={a.severity} />{" "}
                  <Link href={`/allarmi/${a.id}`} className="strong">
                    {a.title}
                  </Link>{" "}
                  <StatusBadge status={a.status} />
                </span>
                <span className="muted small">
                  {a.rule_name}
                  {t?.tactic && ` · ${TACTICS.find((x) => x.id === t.tactic)?.label} (${a.mitre})`}
                </span>
                {a.summary && <span className="small">{a.summary}</span>}
                {analyst && inc.status !== "closed" && (
                  <ActionForm action={removeIncidentAlert} className="row" notices={false}>
                    <input type="hidden" name="id" value={inc.id} />
                    <input type="hidden" name="alert_id" value={a.id} />
                    <ConfirmSubmit label="Non c'entra" confirmLabel="Togli dall'incidente" className="btn btn--small btn--ghost" />
                  </ActionForm>
                )}
              </li>
            );
          })}
        </ol>
      </Card>

      <Card title="Attività e note">
        <ol className="timeline">
          {notes.map((n) => (
            <li key={n.id} className={`timeline--${n.kind}`}>
              <span className="timeline__when">
                {fmtDateTime(n.ts)} · {n.username === "hub" ? "Hyperwave" : n.username}
              </span>
              <span>{n.text}</span>
            </li>
          ))}
        </ol>
        {analyst && (
          <ActionForm action={addIncidentNote} resetOnOk className="stack">
            <input type="hidden" name="id" value={inc.id} />
            <textarea name="note" rows={3} maxLength={4000} placeholder="Cosa hai verificato, cosa hai fatto, cosa resta da fare" aria-label="Nota" />
            <div>
              <Submit className="btn">Aggiungi nota</Submit>
            </div>
          </ActionForm>
        )}
      </Card>
    </>
  );
}
