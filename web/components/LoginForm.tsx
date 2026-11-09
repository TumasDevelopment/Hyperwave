"use client";

import { startTransition, useActionState, useEffect, useState } from "react";
import { cancelLogin, login, verifyCode } from "@/lib/actions/session";
import { FormNotices, useFormAction } from "./forms";

export function LoginForm({ initialStep }: { initialStep: "password" | "totp" }) {
  const [step, setStep] = useState(initialStep);
  const pwd = useFormAction(login);
  const code = useFormAction(verifyCode);
  const [, cancel, cancelling] = useActionState(cancelLogin, undefined);

  useEffect(() => {
    if (pwd.state?.next) setStep(pwd.state.next);
  }, [pwd.state]);
  useEffect(() => {
    if (code.state?.next) setStep(code.state.next);
  }, [code.state]);

  if (step === "totp") {
    return (
      <form onSubmit={code.onSubmit} className="login__form" key="totp">
        <p className="muted">Inserisci il codice di 6 cifre dell&apos;app di autenticazione, oppure uno dei codici di recupero.</p>
        <label className="field">
          <span className="field__label">Codice</span>
          <input name="code" autoComplete="one-time-code" inputMode="text" required autoFocus maxLength={20} spellCheck={false} />
        </label>
        <FormNotices state={code.state} />
        <button type="submit" className="btn btn--primary btn--block" disabled={code.pending}>
          {code.pending ? "Verifica…" : "Verifica"}
        </button>
        <button
          type="button"
          className="btn btn--ghost btn--block"
          disabled={cancelling}
          onClick={() => {
            startTransition(() => cancel());
            setStep("password");
          }}
        >
          Torna indietro
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={pwd.onSubmit} className="login__form" key="password">
      <label className="field">
        <span className="field__label">Nome utente</span>
        <input name="username" autoComplete="username" required autoFocus maxLength={100} spellCheck={false} autoCapitalize="none" />
      </label>
      <label className="field">
        <span className="field__label">Password</span>
        <input name="password" type="password" autoComplete="current-password" required maxLength={200} />
      </label>
      <FormNotices state={code.state?.next === "password" ? code.state : pwd.state} />
      <button type="submit" className="btn btn--primary btn--block" disabled={pwd.pending}>
        {pwd.pending ? "Accesso…" : "Accedi"}
      </button>
    </form>
  );
}
