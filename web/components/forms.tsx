"use client";

import {
  createContext,
  startTransition,
  useActionState,
  useContext,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type MouseEvent,
  type ReactNode,
} from "react";
import type { FormState } from "@/lib/form";

export type Action = (state: FormState, form: FormData) => Promise<FormState>;

/**
 * Invia un'azione senza passare da <form action>, che dopo ogni invio svuota i
 * campi: con un errore di validazione si perderebbe quanto scritto.
 */
export function useFormAction(action: Action) {
  const [state, dispatch, pending] = useActionState(action, undefined);
  const submit = (form: FormData) => startTransition(() => dispatch(form));
  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // il pulsante premuto fa parte dei dati (per esempio op=ack oppure op=resolve)
    const submitter = (event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    submit(new FormData(event.currentTarget, submitter));
  }
  return { state, pending, onSubmit, submit };
}

const Pending = createContext(false);

/**
 * Modulo collegato a un'azione del server. Mostra errori e conferme, e il segreto
 * restituito dall'azione (token o password temporanea) una volta sola.
 */
export function ActionForm({
  action,
  children,
  className,
  resetOnOk = false,
  notices = true,
}: {
  action: Action;
  children: ReactNode;
  className?: string;
  resetOnOk?: boolean;
  notices?: boolean;
}) {
  const { state, pending, onSubmit } = useFormAction(action);
  const ref = useRef<HTMLFormElement>(null);
  useEffect(() => {
    if (state?.ok && resetOnOk) ref.current?.reset();
  }, [state, resetOnOk]);
  return (
    <form ref={ref} onSubmit={onSubmit} className={className} aria-busy={pending}>
      <Pending.Provider value={pending}>{children}</Pending.Provider>
      {notices && <FormNotices state={state} />}
      {state?.token && <SecretReveal value={state.token} />}
    </form>
  );
}

export function Submit({
  children,
  className = "btn btn--primary",
  pendingLabel = "Attendi…",
  name,
  value,
}: {
  children: ReactNode;
  className?: string;
  pendingLabel?: string;
  name?: string;
  value?: string;
}) {
  const pending = useContext(Pending);
  return (
    <button type="submit" className={className} disabled={pending} name={name} value={value}>
      {pending ? pendingLabel : children}
    </button>
  );
}

/** Pulsante in due tempi: il primo clic chiede conferma, il secondo invia il modulo. */
export function ConfirmSubmit({
  label,
  confirmLabel = "Confermi?",
  className = "btn btn--small btn--danger",
  name,
  value,
}: {
  label: string;
  confirmLabel?: string;
  className?: string;
  name?: string;
  value?: string;
}) {
  const pending = useContext(Pending);
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(timer);
  }, [armed]);
  function onClick(event: MouseEvent<HTMLButtonElement>) {
    if (!armed) {
      event.preventDefault();
      setArmed(true);
    } else setTimeout(() => setArmed(false), 0);
  }
  return (
    <button type="submit" className={`${className} ${armed ? "btn--armed" : ""}`} onClick={onClick} disabled={pending} name={name} value={value}>
      {armed ? confirmLabel : label}
    </button>
  );
}

/** Errore o conferma dell'ultimo invio. */
export function FormNotices({ state }: { state: FormState }) {
  return (
    <>
      {state?.error && (
        <div className="notice notice--error" role="alert">
          {state.error}
        </div>
      )}
      {state?.message && (
        <div className="notice notice--ok" role="status">
          {state.message}
        </div>
      )}
    </>
  );
}

/** Segreto mostrato una volta sola, con il pulsante per copiarlo. */
export function SecretReveal({ value, label = "Copia" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // senza HTTPS gli appunti non sono disponibili: il testo resta selezionabile
    }
  }
  return (
    <div className="secret">
      <code>{value}</code>
      <button type="button" className="btn btn--small" onClick={copy}>
        {copied ? "Copiato" : label}
      </button>
    </div>
  );
}

/** Casella che seleziona o deseleziona tutte le caselle name="id" dello stesso modulo. */
export function SelectAll({ label = "Seleziona tutti" }: { label?: string }) {
  return (
    <input
      type="checkbox"
      aria-label={label}
      onChange={(event) => {
        const form = event.currentTarget.form;
        form?.querySelectorAll<HTMLInputElement>('input[type="checkbox"][name="id"]').forEach((box) => {
          box.checked = event.currentTarget.checked;
        });
      }}
    />
  );
}
