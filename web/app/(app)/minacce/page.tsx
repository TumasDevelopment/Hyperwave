import Link from "next/link";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Empty, Field, Kpi, PageHead, SeverityBadge, StatusBadge } from "@/components/ui";
import { addIndicators, createFeed, deleteFeed, deleteIndicator, feedCommand, updateFeed } from "@/lib/actions/intel";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { INTEL_CATEGORIES } from "@/lib/intel.mjs";
import { SEVERITIES, SEVERITY_LABELS } from "@/lib/labels";
import { intelStats, listFeeds, lookupIndicator, manualIndicators, recentIntelAlerts, type FeedRow } from "@/lib/queries/intel";

export const metadata = { title: "Minacce note" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };
const CATEGORIES: Record<string, string> = INTEL_CATEGORIES;
const DAYS = [
  [0, "Senza scadenza"],
  [1, "1 giorno"],
  [7, "7 giorni"],
  [30, "30 giorni"],
  [90, "90 giorni"],
  [365, "1 anno"],
] as const;

function feedState(f: FeedRow, now: number) {
  if (!f.enabled) return <Badge>Spento</Badge>;
  if (f.kind === "manual") return <Badge tone="ok">Attivo</Badge>;
  if (f.last_error) return <Badge tone="bad">Errore</Badge>;
  if (!f.last_ok) return <Badge tone="warn">In attesa</Badge>;
  const late = now - new Date(f.last_ok).getTime() > f.refresh_hours * 3 * 3_600_000;
  return late ? <Badge tone="warn">Non aggiornato</Badge> : <Badge tone="ok">Attivo</Badge>;
}

function CategorySelect({ value }: { value?: string }) {
  return (
    <select name="category" defaultValue={value ?? "malware"} aria-label="Categoria">
      {Object.entries(CATEGORIES).map(([k, v]) => (
        <option key={k} value={k}>
          {v}
        </option>
      ))}
    </select>
  );
}

function SeveritySelect({ value }: { value?: string }) {
  return (
    <select name="severity" defaultValue={value ?? "high"} aria-label="Gravità">
      {SEVERITIES.map((s) => (
        <option key={s} value={s}>
          {SEVERITY_LABELS[s]}
        </option>
      ))}
    </select>
  );
}

export default async function IntelPage({ searchParams }: Props) {
  const user = await requireUser();
  const p = await searchParams;
  const q = typeof p.q === "string" ? p.q.trim().slice(0, 300) : "";
  const admin = can(user, "admin");
  const analyst = can(user, "analyst");
  const [stats, feeds, manual, recent, lookup] = await Promise.all([
    intelStats(),
    listFeeds(),
    manualIndicators(),
    recentIntelAlerts(),
    q ? lookupIndicator(q) : Promise.resolve(null),
  ]);
  const manualFeeds = feeds.filter((f) => f.kind === "manual");
  const now = Date.now();

  return (
    <>
      <PageHead
        title="Minacce note"
        sub="Elenchi di indirizzi, reti e domini malevoli. L'hub li confronta con flussi, DNS, TLS e HTTP appena arrivano, e cerca i nuovi indicatori anche nello storico."
      />

      <div className="kpis kpis--small">
        <Kpi label="Indicatori attivi" value={fmtNum(stats.indicators)} />
        <Kpi label="Elenchi accesi" value={`${stats.feeds} su ${stats.total_feeds}`} />
        <Kpi label="Corrispondenze (7 giorni)" value={fmtNum(stats.hits_7d)} tone={stats.hits_7d ? "warn" : undefined} />
        <Kpi label="Allarmi aperti" value={fmtNum(stats.open)} tone={stats.open ? "bad" : "ok"} href="/allarmi?rule=threat_intel" />
      </div>

      <Card title="Cerca un indicatore">
        <form className="row" method="get">
          <input name="q" defaultValue={q} placeholder="Indirizzo, rete o dominio (anche in forma 'disinnescata': evil[.]example)" maxLength={300} aria-label="Indicatore" className="grow" />
          <button className="btn" type="submit">
            Cerca
          </button>
        </form>
        {q && !lookup && <p className="notice notice--error mt">Non è un indirizzo, una rete o un dominio valido.</p>}
        {lookup && lookup.rows.length === 0 && (
          <p className="muted mt">
            <span className="mono">{lookup.query}</span> non compare in nessun elenco.
          </p>
        )}
        {lookup && lookup.rows.length > 0 && (
          <div className="table-wrap mt">
            <table className="table">
              <thead>
                <tr>
                  <th>Elenco</th>
                  <th>Voce</th>
                  <th>Categoria</th>
                  <th>Gravità</th>
                  <th>Nota</th>
                </tr>
              </thead>
              <tbody>
                {lookup.rows.map((r) => (
                  <tr key={`${r.feed_id}-${r.value}`}>
                    <td>
                      {r.feed_name} {!r.enabled && <Badge>Spento</Badge>}
                    </td>
                    <td className="mono">{r.value}</td>
                    <td>{CATEGORIES[r.category] ?? r.category}</td>
                    <td>
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="muted small">
                      {r.note || "—"}
                      {r.expires_at && ` · scade ${fmtDateTime(r.expires_at)}`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Elenchi">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Nome</th>
                <th>Stato</th>
                <th>Categoria</th>
                <th>Gravità</th>
                <th className="num">Voci</th>
                <th>Aggiornato</th>
                <th className="num">Allarmi 30 gg</th>
                {analyst && <th />}
              </tr>
            </thead>
            <tbody>
              {feeds.map((f) => (
                <tr key={f.id}>
                  <td>
                    <strong>{f.name}</strong>
                    {f.description && <div className="muted small">{f.description}</div>}
                    {f.kind === "url" && <div className="muted small mono">{f.url}</div>}
                    {f.last_error && <div className="small text-warn">{f.last_error}</div>}
                    {f.retro_at && (
                      <div className="muted small">
                        Ricerca nello storico {fmtAgo(f.retro_at, now)}: {fmtNum(f.retro_hits ?? 0)} corrispondenze
                      </div>
                    )}
                  </td>
                  <td>{feedState(f, now)}</td>
                  <td>{CATEGORIES[f.category] ?? f.category}</td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="num">{fmtNum(f.entries)}</td>
                  <td title={fmtDateTime(f.last_ok)}>{f.kind === "manual" ? "a mano" : f.last_ok ? fmtAgo(f.last_ok, now) : "mai"}</td>
                  <td className="num">{fmtNum(f.hits_30d)}</td>
                  {analyst && (
                    <td>
                      <details>
                        <summary className="btn btn--small btn--ghost">Gestisci</summary>
                        <div className="stack mt">
                          {admin && (
                            <ActionForm action={updateFeed} className="row">
                              <input type="hidden" name="id" value={f.id} />
                              <label className="check">
                                <input type="checkbox" name="enabled" defaultChecked={f.enabled} /> Acceso
                              </label>
                              <CategorySelect value={f.category} />
                              <SeveritySelect value={f.severity} />
                              {f.kind === "url" ? (
                                <label className="check">
                                  ogni <input type="number" name="refresh_hours" min={1} max={168} defaultValue={f.refresh_hours} className="input--narrow" aria-label="Ore tra gli aggiornamenti" /> ore
                                </label>
                              ) : (
                                <input type="hidden" name="refresh_hours" value={f.refresh_hours} />
                              )}
                              <Submit className="btn btn--small">Salva</Submit>
                            </ActionForm>
                          )}
                          <ActionForm action={feedCommand} className="row">
                            <input type="hidden" name="id" value={f.id} />
                            {admin && f.kind === "url" && (
                              <Submit className="btn btn--small" name="op" value="fetch">
                                Aggiorna ora
                              </Submit>
                            )}
                            <Submit className="btn btn--small" name="op" value="retro">
                              Cerca nello storico
                            </Submit>
                          </ActionForm>
                          {admin && !f.preset && (
                            <ActionForm action={deleteFeed} className="row">
                              <input type="hidden" name="id" value={f.id} />
                              <ConfirmSubmit label="Elimina elenco" confirmLabel="Elimina anche le voci: confermi?" />
                            </ActionForm>
                          )}
                        </div>
                      </details>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small mt">
          Gli elenchi predefiniti sono spenti finché un amministratore non li accende: l&apos;hub li scarica direttamente dalla fonte e controlla che
          non contengano indirizzi privati o domini delle grandi piattaforme. Le connessioni in entrata da indirizzi segnalati contano solo se il
          dispositivo ha risposto.
        </p>
      </Card>

      {analyst && manualFeeds.length > 0 && (
        <Card title="Aggiungi indicatori a mano">
          <ActionForm action={addIndicators} resetOnOk className="form-grid">
            <Field label="Indicatori" hint="Uno per riga: indirizzi, reti (/8 o più strette), domini o URL. Dopo # puoi scrivere una nota." wide>
              <textarea name="indicators" rows={6} required placeholder={"198.51.100.23  # server di comando visto nel ticket 4182\n203.0.113.0/24\nlogin-update.example"} />
            </Field>
            <Field label="Elenco">
              <select name="feed_id" defaultValue={manualFeeds[0].id}>
                {manualFeeds.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Scadenza">
              <select name="days" defaultValue="0">
                {DAYS.map(([d, l]) => (
                  <option key={d} value={d}>
                    {l}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Nota comune" hint="Usata per le righe senza nota propria." wide>
              <input name="note" maxLength={300} />
            </Field>
            <div className="field--wide">
              <Submit>Salva e cerca nello storico</Submit>
            </div>
          </ActionForm>
        </Card>
      )}

      <Card title={`Indicatori inseriti a mano (${fmtNum(manual.total)})`}>
        {manual.rows.length === 0 ? (
          <Empty>Nessun indicatore inserito a mano.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Voce</th>
                  <th>Elenco</th>
                  <th>Nota</th>
                  <th>Aggiunto</th>
                  <th>Scadenza</th>
                  {analyst && <th />}
                </tr>
              </thead>
              <tbody>
                {manual.rows.map((r) => {
                  const expired = r.expires_at && new Date(r.expires_at).getTime() < now;
                  return (
                    <tr key={`${r.feed_id}-${r.value}`} className={expired ? "muted" : undefined}>
                      <td className="mono">{r.value}</td>
                      <td>{r.feed_name}</td>
                      <td className="small">{r.note || "—"}</td>
                      <td className="small" title={fmtDateTime(r.added_at)}>
                        {fmtAgo(r.added_at, now)} da {r.added_by}
                      </td>
                      <td className="small">{r.expires_at ? (expired ? "scaduto" : fmtDateTime(r.expires_at)) : "—"}</td>
                      {analyst && (
                        <td>
                          <ActionForm action={deleteIndicator} className="row" notices={false}>
                            <input type="hidden" name="feed_id" value={r.feed_id} />
                            <input type="hidden" name="value" value={r.value} />
                            <ConfirmSubmit label="Togli" />
                          </ActionForm>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {manual.total > manual.rows.length && <p className="muted small mt">Sono mostrati i {manual.rows.length} più recenti.</p>}
      </Card>

      <Card title="Ultime corrispondenze">
        {recent.length === 0 ? (
          <Empty>Nessuna corrispondenza finora.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Allarme</th>
                  <th>Indicatore</th>
                  <th>Elenco</th>
                  <th>Gravità</th>
                  <th>Stato</th>
                  <th className="num">Volte</th>
                  <th>Ultima</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link href={`/allarmi/${a.id}`} className="strong">
                        {a.title}
                      </Link>
                      {a.retro && <div className="muted small">trovato nello storico</div>}
                    </td>
                    <td className="mono">{a.indicator}</td>
                    <td>{a.feed}</td>
                    <td>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td>
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="num">{fmtNum(a.count)}</td>
                    <td title={fmtDateTime(a.last_seen)}>{fmtAgo(a.last_seen, now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {admin && (
        <Card title="Aggiungi un elenco">
          <div className="grid-2">
            <ActionForm action={createFeed} resetOnOk className="form-grid">
              <input type="hidden" name="kind" value="url" />
              <Field label="Nome">
                <input name="name" required maxLength={80} />
              </Field>
              <Field label="Indirizzo da scaricare" hint="Testo con una voce per riga, file hosts, CSV o JSON per riga." wide>
                <input name="url" type="url" required placeholder="https://" maxLength={1000} />
              </Field>
              <Field label="Categoria">
                <CategorySelect />
              </Field>
              <Field label="Gravità">
                <SeveritySelect />
              </Field>
              <Field label="Aggiorna ogni (ore)">
                <input name="refresh_hours" type="number" min={1} max={168} defaultValue={6} />
              </Field>
              <Field label="Descrizione">
                <input name="description" maxLength={500} />
              </Field>
              <div className="field--wide">
                <Submit>Aggiungi e scarica</Submit>
              </div>
            </ActionForm>
            <ActionForm action={createFeed} resetOnOk className="form-grid">
              <input type="hidden" name="kind" value="manual" />
              <input type="hidden" name="refresh_hours" value="24" />
              <Field label="Nome dell'elenco a mano" hint="Per esempio uno per ogni fornitore o caso aperto." wide>
                <input name="name" required maxLength={80} />
              </Field>
              <Field label="Categoria">
                <CategorySelect value="other" />
              </Field>
              <Field label="Gravità">
                <SeveritySelect />
              </Field>
              <Field label="Descrizione" wide>
                <input name="description" maxLength={500} />
              </Field>
              <div className="field--wide">
                <Submit>Crea elenco</Submit>
              </div>
            </ActionForm>
          </div>
        </Card>
      )}
    </>
  );
}
