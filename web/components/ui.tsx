// Componenti di presentazione senza stato, usati dalle pagine del server.
import Link from "next/link";
import type { ReactNode } from "react";
import { countryName, flag, fmtBytes } from "@/lib/format";
import { DIRECTION_LABELS, SEVERITY_LABELS, STATUS_LABELS } from "@/lib/labels";
import type { DeviceRef } from "@/lib/names";
import { RANGES, type RangeKey } from "@/lib/ranges";

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="muted">{sub}</p>}
      </div>
      {children && <div className="page-head__actions">{children}</div>}
    </header>
  );
}

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card__head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card__actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Kpi({
  label,
  value,
  sub,
  tone,
  href,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: "ok" | "warn" | "bad" | "accent";
  href?: string;
}) {
  const body = (
    <>
      <span className="kpi__label">{label}</span>
      <span className="kpi__value">{value}</span>
      {sub && <span className="kpi__sub">{sub}</span>}
    </>
  );
  const cls = `kpi ${tone ? `kpi--${tone}` : ""}`;
  return href ? (
    <Link href={href} className={cls}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge--${severity}`}>{SEVERITY_LABELS[severity] ?? severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`status status--${status}`}>{STATUS_LABELS[status] ?? status}</span>;
}

export function Badge({ tone = "off", children }: { tone?: "ok" | "warn" | "bad" | "off" | "accent"; children: ReactNode }) {
  return <span className={`pill pill--${tone}`}>{children}</span>;
}

export function Country({ cc }: { cc: string }) {
  if (!cc) return <span className="muted">—</span>;
  return (
    <span title={countryName(cc)}>
      {flag(cc)} {cc}
    </span>
  );
}

export function Direction({ value }: { value: string }) {
  return <span className={`dir dir--${value}`}>{DIRECTION_LABELS[value] ?? value}</span>;
}

/** Indirizzo con il nome del dispositivo (se noto) e il collegamento ai suoi flussi. */
export function Ip({
  ip,
  names,
  name,
  range = "24h",
  port,
}: {
  ip: string;
  names?: Map<string, DeviceRef>;
  name?: string;
  range?: RangeKey;
  port?: number;
}) {
  if (!ip) return <span className="muted">—</span>;
  const device = names?.get(ip);
  const label = device?.label || name;
  return (
    <span className="ip">
      <Link href={`/flussi?range=${range}&ip=${encodeURIComponent(ip)}`} className="mono">
        {ip}
        {port ? <span className="muted">:{port}</span> : null}
      </Link>
      {device ? (
        <Link href={`/dispositivi/${device.id}`} className="ip__name">
          {label || "dispositivo"}
        </Link>
      ) : label ? (
        <span className="ip__name ip__name--plain">{label}</span>
      ) : null}
    </span>
  );
}

export interface BarRow {
  key: string;
  label: ReactNode;
  value: number;
  href?: string;
  extra?: ReactNode;
}

/** Elenco con barre proporzionali al valore più alto. */
export function BarList({
  rows,
  format = fmtBytes,
  color = "var(--accent)",
  empty = "Nessun dato nel periodo.",
}: {
  rows: BarRow[];
  format?: (value: number) => string;
  color?: string;
  empty?: string;
}) {
  if (rows.length === 0) return <Empty>{empty}</Empty>;
  const max = Math.max(...rows.map((r) => r.value), 1);
  return (
    <ul className="barlist">
      {rows.map((row) => (
        <li key={row.key}>
          <div className="barlist__bar" style={{ width: `${Math.max((row.value / max) * 100, 0.5)}%`, background: color }} />
          <span className="barlist__label">{row.href ? <Link href={row.href}>{row.label}</Link> : row.label}</span>
          {row.extra && <span className="barlist__extra">{row.extra}</span>}
          <span className="barlist__value">{format(row.value)}</span>
        </li>
      ))}
    </ul>
  );
}

/** Scelta del periodo: semplici link che mantengono gli altri parametri della pagina. */
export function RangePicker({
  current,
  base,
  params = {},
  options = Object.keys(RANGES) as RangeKey[],
}: {
  current: RangeKey;
  base: string;
  params?: Record<string, string>;
  options?: RangeKey[];
}) {
  return (
    <nav className="range" aria-label="Periodo">
      {options.map((key) => {
        const q = new URLSearchParams({ ...params, range: key });
        return (
          <Link key={key} href={`${base}?${q}`} aria-current={key === current ? "true" : undefined}>
            {RANGES[key].label}
          </Link>
        );
      })}
    </nav>
  );
}

export function Tabs({ items, current }: { items: { key: string; label: string; href: string; count?: number }[]; current: string }) {
  return (
    <nav className="tabs" aria-label="Schede">
      {items.map((item) => (
        <Link key={item.key} href={item.href} aria-current={item.key === current ? "page" : undefined}>
          {item.label}
          {item.count !== undefined && <span className="tabs__count">{item.count}</span>}
        </Link>
      ))}
    </nav>
  );
}

export function Field({ label, hint, children, wide }: { label: string; hint?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <label className={`field ${wide ? "field--wide" : ""}`}>
      <span className="field__label">{label}</span>
      {children}
      {hint && <span className="field__hint">{hint}</span>}
    </label>
  );
}

/** Errore di caricamento di un riquadro: la pagina resta utilizzabile. */
export function LoadError({ what }: { what: string }) {
  return <p className="notice notice--error">Impossibile leggere {what}. Controlla che ClickHouse e PostgreSQL siano attivi.</p>;
}

/** Esegue la query e in caso d'errore restituisce il valore di riserva, annotando il problema nel log. */
export async function safe<T>(promise: Promise<T>, fallback: T, what: string): Promise<{ data: T; failed: boolean }> {
  try {
    return { data: await promise, failed: false };
  } catch (error) {
    console.error(`Lettura di ${what} non riuscita:`, (error as Error).message);
    return { data: fallback, failed: true };
  }
}
