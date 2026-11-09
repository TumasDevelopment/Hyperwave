import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Field, PageHead, Tabs } from "@/components/ui";
import { createUser, deleteUser, resetUserPassword, resetUserTotp, revokeUserSessions, updateUser } from "@/lib/actions/admin";
import { requireRole, ROLE_LABELS, type Role } from "@/lib/auth";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { listUsers } from "@/lib/queries/system";
import { SETTINGS_TABS } from "@/lib/settings-tabs";

export const metadata = { title: "Utenti" };

const ROLE_HELP: Record<Role, string> = {
  viewer: "vede tutto, non modifica nulla",
  analyst: "gestisce allarmi, dispositivi ed eccezioni",
  admin: "anche regole, sensori, utenti e impostazioni",
};

export default async function UsersPage() {
  const me = await requireRole("admin");
  const users = await listUsers();

  return (
    <>
      <PageHead title="Utenti" sub="Chi può accedere e con quale ruolo. Le password temporanee vanno cambiate al primo accesso." />
      <Tabs current="utenti" items={SETTINGS_TABS} />

      <Card>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Utente</th>
                <th>Ruolo</th>
                <th>Sicurezza</th>
                <th>Ultimo accesso</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className={u.disabled ? "row--dim" : undefined}>
                  <td>
                    <strong>{u.username}</strong> {u.id === me.id && <span className="muted small">(tu)</span>}
                    <div className="muted small">{[u.display_name, u.email].filter(Boolean).join(" · ")}</div>
                  </td>
                  <td>
                    {ROLE_LABELS[u.role as Role] ?? u.role}
                    {u.disabled && (
                      <div>
                        <Badge tone="off">Disattivato</Badge>
                      </div>
                    )}
                  </td>
                  <td className="nowrap">
                    {u.totp_enabled ? <Badge tone="ok">Due fattori</Badge> : <Badge tone="warn">Solo password</Badge>}
                    {u.must_change && (
                      <div>
                        <Badge tone="accent">Password temporanea</Badge>
                      </div>
                    )}
                  </td>
                  <td>
                    <span title={fmtDateTime(u.last_login)}>{fmtAgo(u.last_login)}</span>
                    <div className="muted small">{u.sessions} sessioni aperte</div>
                  </td>
                  <td>
                    <details className="menu">
                      <summary className="btn btn--small btn--ghost">Gestisci</summary>
                      <div className="menu__body stack">
                        <ActionForm action={updateUser} className="form-grid">
                          <input type="hidden" name="id" value={u.id} />
                          <Field label="Nome visualizzato">
                            <input name="display_name" defaultValue={u.display_name} maxLength={100} />
                          </Field>
                          <Field label="Email">
                            <input name="email" type="email" defaultValue={u.email} maxLength={200} />
                          </Field>
                          <Field label="Ruolo">
                            <select name="role" defaultValue={u.role}>
                              {(Object.keys(ROLE_LABELS) as Role[]).map((r) => (
                                <option key={r} value={r}>
                                  {ROLE_LABELS[r]}
                                </option>
                              ))}
                            </select>
                          </Field>
                          <label className="check">
                            <input type="checkbox" name="disabled" defaultChecked={u.disabled} /> Disattivato
                          </label>
                          <div className="field--wide">
                            <Submit className="btn btn--small btn--primary">Salva</Submit>
                          </div>
                        </ActionForm>
                        <div className="row">
                          <ActionForm action={resetUserPassword}>
                            <input type="hidden" name="id" value={u.id} />
                            <ConfirmSubmit label="Nuova password temporanea" className="btn btn--small" />
                          </ActionForm>
                          {u.totp_enabled && (
                            <ActionForm action={resetUserTotp}>
                              <input type="hidden" name="id" value={u.id} />
                              <ConfirmSubmit label="Azzera due fattori" className="btn btn--small" />
                            </ActionForm>
                          )}
                          {u.sessions > 0 && (
                            <ActionForm action={revokeUserSessions}>
                              <input type="hidden" name="id" value={u.id} />
                              <Submit className="btn btn--small">Chiudi sessioni</Submit>
                            </ActionForm>
                          )}
                          {u.id !== me.id && (
                            <ActionForm action={deleteUser}>
                              <input type="hidden" name="id" value={u.id} />
                              <ConfirmSubmit label="Elimina" confirmLabel="Conferma eliminazione" />
                            </ActionForm>
                          )}
                        </div>
                      </div>
                    </details>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Nuovo utente">
        <ActionForm action={createUser} resetOnOk className="form-grid">
          <Field label="Nome utente" hint="2-40 caratteri: lettere, cifre, punto, trattino">
            <input name="username" required maxLength={40} pattern="[a-zA-Z0-9][a-zA-Z0-9._\-]{1,39}" autoComplete="off" spellCheck={false} />
          </Field>
          <Field label="Ruolo">
            <select name="role" defaultValue="viewer">
              {(Object.keys(ROLE_LABELS) as Role[]).map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]} — {ROLE_HELP[r]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Nome visualizzato">
            <input name="display_name" maxLength={100} />
          </Field>
          <Field label="Email">
            <input name="email" type="email" maxLength={200} />
          </Field>
          <div className="field--wide">
            <Submit>Crea utente</Submit>
            <p className="muted small">La password temporanea compare una sola volta qui sotto: consegnala in modo sicuro, non per email in chiaro.</p>
          </div>
        </ActionForm>
      </Card>
    </>
  );
}
