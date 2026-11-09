import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Empty, Field, PageHead, Tabs } from "@/components/ui";
import { createApiToken, revokeApiToken } from "@/lib/actions/admin";
import { requireRole, ROLE_LABELS, type Role } from "@/lib/auth";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { listTokens } from "@/lib/queries/system";
import { SETTINGS_TABS } from "@/lib/settings-tabs";

export const metadata = { title: "Token API" };

const ENDPOINTS: [string, string, string][] = [
  ["GET", "/api/v1/status", "Stato generale: live, sensori, allarmi aperti, traffico dell'ultima ora"],
  ["GET", "/api/v1/alerts", "Allarmi. Filtri: status (open, ack, resolved, active), severity, rule, q, days, limit"],
  ["GET", "/api/v1/alerts/{id}", "Un allarme con note e cronologia"],
  ["POST", "/api/v1/alerts/{id}", "Cambia stato, assegnatario o aggiunge una nota (analista). JSON: status, resolution, assignee, note"],
  ["GET", "/api/v1/devices", "Inventario. Filtri: q, type, vlan, status, limit"],
  ["GET", "/api/v1/devices/{id}", "Un dispositivo con i servizi offerti"],
  ["PATCH", "/api/v1/devices/{id}", "Aggiorna nome, responsabile, posizione, note, etichette, criticità, approvazione (analista)"],
  ["GET", "/api/v1/flows", "Flussi. Stessi filtri della pagina Flussi (range, ip, peer, port, proto, app, domain, cc, dir, failed, min), limit fino a 10000"],
  ["GET", "/api/v1/sensors", "Sensori e loro stato"],
  ["GET", "/api/v1/live", "Stato del live"],
  ["PUT", "/api/v1/live", "Accende o spegne il live (amministratore). JSON: {\"live\": true}"],
];

export default async function ApiTokensPage() {
  await requireRole("admin");
  const tokens = await listTokens();
  const now = Date.now();

  return (
    <>
      <PageHead title="Token API" sub="Per collegare SIEM, ticketing e script: ogni token ha un ruolo e si può revocare in ogni momento." />
      <Tabs current="api" items={SETTINGS_TABS} />

      <Card>
        {tokens.length === 0 ? (
          <Empty>Nessun token.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>Ruolo</th>
                  <th>Creato</th>
                  <th>Scadenza</th>
                  <th>Ultimo uso</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => {
                  const expired = t.expires_at !== null && new Date(t.expires_at).getTime() < now;
                  return (
                    <tr key={t.id} className={t.revoked_at || expired ? "row--dim" : undefined}>
                      <td>
                        <strong>{t.name}</strong>
                        <div className="mono muted small">{t.prefix}…</div>
                      </td>
                      <td>{ROLE_LABELS[t.role as Role] ?? t.role}</td>
                      <td>
                        {fmtDateTime(t.created_at)}
                        <div className="muted small">{t.created_by}</div>
                      </td>
                      <td>{t.expires_at ? fmtDateTime(t.expires_at) : "mai"}</td>
                      <td>{fmtAgo(t.last_used)}</td>
                      <td>
                        {t.revoked_at ? (
                          <Badge tone="off">Revocato</Badge>
                        ) : expired ? (
                          <Badge tone="off">Scaduto</Badge>
                        ) : (
                          <ActionForm action={revokeApiToken}>
                            <input type="hidden" name="id" value={t.id} />
                            <ConfirmSubmit label="Revoca" confirmLabel="Conferma revoca" />
                          </ActionForm>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Nuovo token">
        <ActionForm action={createApiToken} resetOnOk className="form-grid">
          <Field label="Nome" hint="Chi lo usa: per esempio «SIEM» o «script backup»">
            <input name="name" required maxLength={80} />
          </Field>
          <Field label="Ruolo">
            <select name="role" defaultValue="viewer">
              {(Object.keys(ROLE_LABELS) as Role[]).map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Durata">
            <select name="days" defaultValue="365">
              <option value="30">30 giorni</option>
              <option value="90">90 giorni</option>
              <option value="180">180 giorni</option>
              <option value="365">1 anno</option>
              <option value="0">Senza scadenza</option>
            </select>
          </Field>
          <div className="field--wide">
            <Submit>Crea token</Submit>
          </div>
        </ActionForm>
      </Card>

      <Card title="Come si usa">
        <p>
          Ogni richiesta porta il token nell&apos;intestazione <code>Authorization: Bearer hwk_…</code>. Le risposte sono JSON; gli errori hanno la
          forma <code>{`{"error": "…"}`}</code> con il codice HTTP adatto (401 token non valido, 403 ruolo insufficiente, 404, 400).
        </p>
        <pre>{`curl -H "Authorization: Bearer $HW_API_TOKEN" https://hyperwave.example/api/v1/alerts?status=active`}</pre>
        <div className="table-wrap">
          <table className="table table--compact">
            <tbody>
              {ENDPOINTS.map(([method, path, help]) => (
                <tr key={`${method} ${path}`}>
                  <td className="mono nowrap">{method}</td>
                  <td className="mono nowrap">{path}</td>
                  <td className="small">{help}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
