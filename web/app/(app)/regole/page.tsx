import Link from "next/link";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Card, Empty, Field, PageHead, SeverityBadge } from "@/components/ui";
import { createSuppression, deleteSuppression, updateRule } from "@/lib/actions/ops";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { mitreUrl, SEVERITIES, SEVERITY_LABELS } from "@/lib/labels";
import { listRules, listSuppressions } from "@/lib/queries/system";

export const metadata = { title: "Regole" };

const CATEGORY_LABELS: Record<string, string> = {
  recon: "Ricognizione",
  access: "Accesso",
  c2: "Comando e controllo",
  exfil: "Esfiltrazione",
  policy: "Politiche e configurazione",
  crypto: "Cifratura",
  inventory: "Inventario",
  ids: "IDS",
  system: "Sistema",
  anomaly: "Anomalie",
  lateral: "Movimento laterale",
};

export default async function RulesPage() {
  const user = await requireUser();
  const [rules, suppressions] = await Promise.all([listRules(), listSuppressions()]);
  const admin = can(user, "admin");
  const analyst = can(user, "analyst");
  const categories = [...new Set(rules.map((r) => r.category))];
  const now = Date.now();

  return (
    <>
      <PageHead
        title="Regole di rilevamento"
        sub="Il motore dell'hub analizza i flussi ogni minuto. Qui scegli quali regole usare, con quale gravità e con quali soglie."
      />
      {rules.length === 0 && <Empty>Il catalogo delle regole compare dopo il primo avvio dell&apos;hub.</Empty>}
      {categories.map((cat) => (
        <Card key={cat} title={CATEGORY_LABELS[cat] ?? cat}>
          <div className="rules">
            {rules
              .filter((r) => r.category === cat)
              .map((r) => {
                const severity = r.severity || r.default_severity;
                const mitre = r.mitre ? mitreUrl(r.mitre) : null;
                return (
                  <details key={r.id} className={`rule ${r.enabled ? "" : "rule--off"}`}>
                    <summary>
                      <span className={`switch-dot ${r.enabled ? "switch-dot--on" : ""}`} aria-label={r.enabled ? "Attiva" : "Spenta"} />
                      <span className="rule__name">{r.name}</span>
                      <SeverityBadge severity={severity} />
                      <span className="rule__stats muted small">
                        {r.alerts_30d > 0 ? (
                          <Link href={`/allarmi?status=all&rule=${r.id}&days=30`}>{fmtNum(r.alerts_30d)} allarmi in 30 g</Link>
                        ) : (
                          "nessun allarme in 30 g"
                        )}
                        {r.open > 0 && ` · ${r.open} da gestire`}
                      </span>
                    </summary>
                    <div className="rule__body">
                      <p>{r.description}</p>
                      <p className="muted small">
                        Codice <span className="mono">{r.id}</span>
                        {r.mitre && (
                          <>
                            {" "}
                            · MITRE ATT&amp;CK{" "}
                            {mitre ? (
                              <a href={mitre} target="_blank" rel="noopener noreferrer" className="mono">
                                {r.mitre}
                              </a>
                            ) : (
                              r.mitre
                            )}
                          </>
                        )}
                        {r.updated_by && ` · modificata da ${r.updated_by} il ${fmtDateTime(r.updated_at)}`}
                      </p>
                      {admin ? (
                        <ActionForm action={updateRule} className="form-grid">
                          <input type="hidden" name="id" value={r.id} />
                          <label className="check">
                            <input type="checkbox" name="enabled" defaultChecked={r.enabled} /> Regola attiva
                          </label>
                          <Field label="Gravità">
                            <select name="severity" defaultValue={r.severity ?? ""}>
                              <option value="">Predefinita ({SEVERITY_LABELS[r.default_severity]})</option>
                              {SEVERITIES.map((s) => (
                                <option key={s} value={s}>
                                  {SEVERITY_LABELS[s]}
                                </option>
                              ))}
                            </select>
                          </Field>
                          {Object.entries(r.params).map(([key, def]) => (
                            <Field key={key} label={r.param_help[key] ?? key} hint={`Predefinito: ${String(def)}`}>
                              <input
                                name={`p_${key}`}
                                inputMode="decimal"
                                defaultValue={r.custom[key] !== undefined ? String(r.custom[key]) : String(def)}
                              />
                            </Field>
                          ))}
                          <div className="field--wide">
                            <Submit>Salva la regola</Submit>
                          </div>
                        </ActionForm>
                      ) : (
                        <dl className="dl">
                          {Object.entries(r.params).map(([key, def]) => (
                            <div key={key} className="dl__row">
                              <dt>{r.param_help[key] ?? key}</dt>
                              <dd>{String(r.custom[key] ?? def)}</dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </div>
                  </details>
                );
              })}
          </div>
        </Card>
      ))}

      <Card title="Eccezioni">
        <p className="muted">
          Un&apos;eccezione impedisce di aprire allarmi per una combinazione di regola, origine e destinazione: serve per le attività legittime
          che una regola scambia per sospette (backup, scanner autorizzati, monitoraggio).
        </p>
        {suppressions.length === 0 ? (
          <Empty>Nessuna eccezione.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Regola</th>
                  <th>Origine</th>
                  <th>Destinazione</th>
                  <th>Motivo</th>
                  <th>Scadenza</th>
                  <th className="num">Allarmi evitati</th>
                  {analyst && <th />}
                </tr>
              </thead>
              <tbody>
                {suppressions.map((s) => {
                  const expired = s.expires_at !== null && new Date(s.expires_at).getTime() < now;
                  return (
                    <tr key={s.id} className={expired ? "row--dim" : undefined}>
                      <td>{s.rule ? s.rule_name || s.rule : <em>Tutte</em>}</td>
                      <td className="mono">{s.src || "qualsiasi"}</td>
                      <td className="mono">{s.dst || "qualsiasi"}</td>
                      <td>
                        {s.reason}
                        <div className="muted small">
                          {s.created_by}, {fmtDateTime(s.created_at)}
                        </div>
                      </td>
                      <td className="nowrap">{s.expires_at ? expired ? <span className="muted">scaduta</span> : fmtDateTime(s.expires_at) : "mai"}</td>
                      <td className="num">
                        {fmtNum(s.hits)}
                        {s.last_hit && <div className="muted small">ultimo {fmtAgo(s.last_hit)}</div>}
                      </td>
                      {analyst && (
                        <td>
                          <ActionForm action={deleteSuppression}>
                            <input type="hidden" name="id" value={s.id} />
                            <ConfirmSubmit label="Elimina" />
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
        {analyst && (
          <details className="mt">
            <summary className="btn btn--small">Nuova eccezione</summary>
            <ActionForm action={createSuppression} resetOnOk className="form-grid mt">
              <Field label="Regola">
                <select name="rule" defaultValue="">
                  <option value="">Tutte le regole</option>
                  {rules.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
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
                <input name="src" spellCheck={false} />
              </Field>
              <Field label="Destinazione" hint="Indirizzo o rete CIDR, vuoto = qualsiasi">
                <input name="dst" spellCheck={false} />
              </Field>
              <Field label="Motivo" wide>
                <input name="reason" required maxLength={500} />
              </Field>
              <div className="field--wide">
                <Submit>Crea eccezione</Submit>
              </div>
            </ActionForm>
          </details>
        )}
      </Card>
    </>
  );
}
