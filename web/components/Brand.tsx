/** Logo di Hyperwave: un'onda dentro un quadrato. Decorativo, il nome sta nel testo accanto. */
export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 32 32">
      <rect x="0.5" y="0.5" width="31" height="31" rx="7" fill="#0b1219" stroke="rgba(34,211,238,0.45)" />
      <path
        d="M5 17c2.2 0 2.2-6 4.4-6s2.2 10 4.4 10 2.2-14 4.4-14 2.2 10 4.4 10 2.2-4 4.4-4"
        fill="none"
        stroke="#22d3ee"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Marchio di tumas.net: prompt lime e cursore. */
export function Marchio() {
  return (
    <svg aria-hidden="true" width="18" height="18" viewBox="0 0 32 32">
      <rect x="0.5" y="0.5" width="31" height="31" rx="6" fill="#1D222C" stroke="rgba(230,234,240,0.2)" />
      <path d="M8 10l6 6-6 6" fill="none" stroke="#A8E10C" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="16" y="20" width="9" height="3" rx="1" fill="#E6EAF0" />
    </svg>
  );
}

export function Credito() {
  // La sezione 13 dell'AGPL chiede di offrire il sorgente a chi usa il programma attraverso la rete.
  const sorgente = process.env.SOURCE_URL || "https://github.com/TumasDevelopment/Hyperwave";
  return (
    <p className="credito">
      <Marchio /> Progettata e distribuita da{" "}
      <a href="https://tumas.net" target="_blank" rel="noopener">
        tumas<span className="punto">.</span>net
      </a>
      <span className="credito__sep">·</span>
      <a href={sorgente} target="_blank" rel="noopener">
        Codice sorgente
      </a>{" "}
      · AGPL-3.0
    </p>
  );
}
