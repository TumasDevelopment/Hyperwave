"use client";

import { startTransition, useActionState, useState } from "react";
import { confirmTotp, disableTotp, newRecovery, startTotp } from "@/lib/actions/account";
import { FormNotices, useFormAction } from "./forms";
import { QrCode } from "./QrCode";

function RecoveryCodes({ codes }: { codes: string[] }) {
  return (
    <div className="recovery">
      <p>
        <strong>Codici di recupero.</strong> Ognuno vale una volta sola, se perdi il telefono. Salvali adesso in un posto sicuro
        (un gestore di password): non verranno più mostrati.
      </p>
      <ol className="recovery__list mono">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
    </div>
  );
}

export function TotpSection({ enabled, recoveryLeft }: { enabled: boolean; recoveryLeft: number }) {
  const [setup, begin, starting] = useActionState(startTotp, undefined);
  const confirm = useFormAction(confirmTotp);
  const disable = useFormAction(disableTotp);
  const regen = useFormAction(newRecovery);
  const [showDisable, setShowDisable] = useState(false);

  const codes = (confirm.state?.data?.codes ?? regen.state?.data?.codes) as string[] | undefined;

  if (enabled || confirm.state?.ok) {
    return (
      <div className="stack">
        <p>
          <span className="pill pill--ok">Attivi</span> L&apos;accesso chiede anche il codice dell&apos;app di autenticazione.
          {!codes && <> Codici di recupero rimasti: <strong>{recoveryLeft}</strong>.</>}
        </p>
        {codes && <RecoveryCodes codes={codes} />}
        <FormNotices state={confirm.state?.ok ? confirm.state : undefined} />
        <div className="row">
          <form onSubmit={regen.onSubmit} className="row">
            <input type="password" name="password" placeholder="Password attuale" autoComplete="current-password" required />
            <button type="submit" className="btn btn--small" disabled={regen.pending}>
              Nuovi codici di recupero
            </button>
          </form>
          <button type="button" className="btn btn--small btn--ghost" onClick={() => setShowDisable(!showDisable)}>
            Disattiva…
          </button>
        </div>
        <FormNotices state={regen.state} />
        {showDisable && (
          <form onSubmit={disable.onSubmit} className="row">
            <input type="password" name="password" placeholder="Password attuale" autoComplete="current-password" required />
            <button type="submit" className="btn btn--small btn--danger" disabled={disable.pending}>
              Disattiva i due fattori
            </button>
          </form>
        )}
        <FormNotices state={disable.state} />
      </div>
    );
  }

  const data = setup?.data as { secret: string; uri: string } | undefined;
  if (!data) {
    return (
      <div className="stack">
        <p>
          <span className="pill pill--warn">Non attivi</span> Con i due fattori serve anche un codice dal telefono: una password rubata
          da sola non basta più.
        </p>
        <FormNotices state={setup} />
        <div>
          <button type="button" className="btn" disabled={starting} onClick={() => startTransition(() => begin())}>
            Attiva i due fattori
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="totp-setup">
      <QrCode text={data.uri} label="Codice QR da inquadrare con l'app di autenticazione" />
      <div className="stack">
        <p>
          1. Inquadra il codice con un&apos;app di autenticazione (Aegis, Google o Microsoft Authenticator, 1Password…). Se non puoi
          inquadrarlo, inserisci a mano questa chiave:
        </p>
        <code className="secret-inline">{data.secret.match(/.{1,4}/g)?.join(" ")}</code>
        <p>2. Scrivi il codice di 6 cifre che compare nell&apos;app.</p>
        <form onSubmit={confirm.onSubmit} className="row">
          <input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="\d{6}" maxLength={6} required placeholder="123456" />
          <button type="submit" className="btn btn--primary" disabled={confirm.pending}>
            Conferma
          </button>
        </form>
        <FormNotices state={confirm.state} />
      </div>
    </div>
  );
}
