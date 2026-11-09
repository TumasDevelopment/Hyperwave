import Link from "next/link";

export default function NotFound() {
  return (
    <main className="center-page">
      <h1>Pagina non trovata</h1>
      <p className="muted">L&apos;indirizzo non esiste oppure l&apos;elemento è stato eliminato.</p>
      <Link href="/" className="btn">
        Torna alla panoramica
      </Link>
    </main>
  );
}
