import { Card, Empty, Field, PageHead, Tabs } from "@/components/ui";
import { AUDIT_LABELS } from "@/lib/audit";
import { requireRole } from "@/lib/auth";
import { fmtDateTimeFull } from "@/lib/format";
import { listAudit } from "@/lib/queries/system";
import { one } from "@/lib/ranges";
import { SETTINGS_TABS } from "@/lib/settings-tabs";

export const metadata = { title: "Registro attività" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const GROUPS: Record<string, string> = {
  "": "Tutte",
  login: "Accessi",
  user: "Utenti",
  "2fa": "Due fattori",
  apitoken: "Token API",
  live: "Live",
  settings: "Impostazioni",
  rule: "Regole",
  suppression: "Eccezioni",
  sensor: "Sensori",
  alert: "Allarmi",
  device: "Dispositivi",
  export: "Export",
};

export default async function AuditPage({ searchParams }: Props) {
  await requireRole("admin");
  const p = await searchParams;
  const action = one(p.action) in GROUPS ? one(p.action) : "";
  const days = [1, 7, 30, 90, 365].includes(Number(one(p.days))) ? Number(one(p.days)) : 30;
  const q = one(p.q).trim().slice(0, 100);
  const rows = await listAudit({ q, action, days });
  const exportQuery = new URLSearchParams({ action, days: String(days), q });

  return (
    <>
      <PageHead title="Registro attività" sub="Chi ha fatto cosa, quando e da dove. Le righe non si possono modificare dall'interfaccia.">
        <a className="btn btn--small" href={`/api/registro.csv?${exportQuery}`}>
          Esporta CSV
        </a>
      </PageHead>
      <Tabs current="registro" items={SETTINGS_TABS} />

      <form className="filters" method="get">
        <Field label="Attività">
          <select name="action" defaultValue={action}>
            {Object.entries(GROUPS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Periodo">
          <select name="days" defaultValue={String(days)}>
            <option value="1">24 ore</option>
            <option value="7">7 giorni</option>
            <option value="30">30 giorni</option>
            <option value="90">90 giorni</option>
            <option value="365">1 anno</option>
          </select>
        </Field>
        <Field label="Cerca">
          <input name="q" defaultValue={q} placeholder="utente, oggetto, indirizzo" />
        </Field>
        <div className="filters__actions">
          <button type="submit" className="btn btn--primary">
            Filtra
          </button>
        </div>
      </form>

      <Card title={`${rows.length} righe${rows.length === 500 ? " (le più recenti)" : ""}`}>
        {rows.length === 0 ? (
          <Empty>Nessuna attività con questi filtri.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Quando</th>
                  <th>Utente</th>
                  <th>Attività</th>
                  <th>Oggetto</th>
                  <th>Indirizzo</th>
                  <th>Dettagli</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className={/failed|locked/.test(r.action) ? "row--warn" : undefined}>
                    <td className="mono nowrap">{fmtDateTimeFull(r.ts)}</td>
                    <td>{r.username || "—"}</td>
                    <td>{AUDIT_LABELS[r.action] ?? r.action}</td>
                    <td className="small">{r.target}</td>
                    <td className="mono small">{r.ip}</td>
                    <td className="mono small break">{Object.keys(r.detail ?? {}).length ? JSON.stringify(r.detail) : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
