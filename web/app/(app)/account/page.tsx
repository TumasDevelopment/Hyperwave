import { ActionForm, Submit } from "@/components/forms";
import { TotpSection } from "@/components/TotpSection";
import { Card, Field, PageHead } from "@/components/ui";
import { changePassword, closeOtherSessions, updateProfile } from "@/lib/actions/account";
import { currentSessionHash, requireUser, ROLE_LABELS } from "@/lib/auth";
import { db } from "@/lib/db";
import { fmtAgo, fmtDateTime } from "@/lib/format";
import { one } from "@/lib/ranges";
import { MIN_PASSWORD } from "@/lib/secrets";

export const metadata = { title: "Account" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

function agentLabel(ua: string) {
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return [browser, os].filter(Boolean).join(" su ") || ua.slice(0, 60) || "Sconosciuto";
}

export default async function AccountPage({ searchParams }: Props) {
  const user = await requireUser({ allowMustChange: true });
  const p = await searchParams;
  const [{ rows: info }, { rows: sessions }, current] = await Promise.all([
    db().query<{ email: string; display_name: string; totp_enabled: boolean; recovery: number; created_at: Date; last_login: Date | null }>(
      "SELECT email, display_name, totp_enabled, coalesce(array_length(recovery_codes, 1), 0) AS recovery, created_at, last_login FROM users WHERE id = $1",
      [user.id],
    ),
    db().query<{ token_hash: Buffer; created_at: Date; last_active: Date; ip: string; user_agent: string }>(
      "SELECT token_hash, created_at, last_active, ip, user_agent FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_active DESC",
      [user.id],
    ),
    currentSessionHash(),
  ]);
  const me = info[0];

  return (
    <>
      <PageHead title="Account" sub={`${user.username} · ${ROLE_LABELS[user.role]}`} />

      {(user.mustChange || one(p.cambio) === "1") && (
        <p className="notice notice--warn">
          Stai usando una password temporanea. Scegline una tua per continuare: almeno {MIN_PASSWORD} caratteri, meglio una frase.
        </p>
      )}
      {one(p.recupero) === "1" && (
        <p className="notice notice--warn">Hai usato un codice di recupero: controlla quanti ne restano e, se hai cambiato telefono, riattiva i due fattori.</p>
      )}

      <div className="grid-2">
        <Card title="Password">
          <ActionForm action={changePassword} resetOnOk className="stack">
            <input type="text" name="username" autoComplete="username" defaultValue={user.username} hidden readOnly />
            <Field label="Password attuale">
              <input type="password" name="current" autoComplete="current-password" required />
            </Field>
            <Field label="Nuova password" hint={`Almeno ${MIN_PASSWORD} caratteri.`}>
              <input type="password" name="next" autoComplete="new-password" required minLength={MIN_PASSWORD} maxLength={200} />
            </Field>
            <Field label="Ripeti la nuova password">
              <input type="password" name="confirm" autoComplete="new-password" required minLength={MIN_PASSWORD} maxLength={200} />
            </Field>
            <div>
              <Submit>Cambia password</Submit>
            </div>
          </ActionForm>
        </Card>

        {!user.mustChange && (
          <Card title="Accesso con due fattori">
            <TotpSection enabled={me?.totp_enabled ?? false} recoveryLeft={me?.recovery ?? 0} />
          </Card>
        )}
      </div>

      {!user.mustChange && (
        <div className="grid-2">
          <Card title="Profilo">
            <ActionForm action={updateProfile} className="stack">
              <Field label="Nome visualizzato">
                <input name="display_name" defaultValue={me?.display_name} maxLength={100} />
              </Field>
              <Field label="Email">
                <input name="email" type="email" defaultValue={me?.email} maxLength={200} />
              </Field>
              <div>
                <Submit>Salva</Submit>
              </div>
            </ActionForm>
            <p className="muted small mt">
              Account creato il {fmtDateTime(me?.created_at)} · ultimo accesso {fmtAgo(me?.last_login)}
            </p>
          </Card>
          <Card title="Sessioni aperte">
            <table className="table table--compact">
              <tbody>
                {sessions.map((s) => {
                  const mine = current !== null && Buffer.compare(s.token_hash, current) === 0;
                  return (
                    <tr key={s.token_hash.toString("hex")}>
                      <td>
                        {agentLabel(s.user_agent)} {mine && <span className="pill pill--accent">Questa</span>}
                        <div className="muted small mono">{s.ip || "—"}</div>
                      </td>
                      <td className="muted">
                        attiva {fmtAgo(s.last_active)}
                        <div className="small">dal {fmtDateTime(s.created_at)}</div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {sessions.length > 1 && (
              <ActionForm action={closeOtherSessions} className="mt">
                <Submit className="btn btn--small">Chiudi le altre sessioni</Submit>
              </ActionForm>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
