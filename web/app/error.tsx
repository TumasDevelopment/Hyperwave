"use client";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="center-page">
      <h1>Qualcosa non ha funzionato</h1>
      <p className="muted">
        La pagina non si è caricata. Di solito un database non risponde: riprova tra poco.
        {error.digest && <> Codice per il log del sito: <code>{error.digest}</code></>}
      </p>
      <button type="button" className="btn btn--primary" onClick={reset}>
        Riprova
      </button>
    </main>
  );
}
