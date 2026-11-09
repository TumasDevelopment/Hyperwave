import Link from "next/link";
import { AutoRefresh } from "@/components/AutoRefresh";
import { ActionForm, SelectAll, Submit } from "@/components/forms";
import { Card, Empty, Field, Kpi, PageHead, SeverityBadge, StatusBadge } from "@/components/ui";
import { bulkAlerts } from "@/lib/actions/ops";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { RESOLUTIONS, SEVERITIES, SEVERITY_LABELS } from "@/lib/labels";
import { alertCounts, assignableUsers, listAlerts, ruleOptions, type AlertFilter } from "@/lib/queries/alerts";
import { one } from "@/lib/ranges";

export const metadata = { title: "Allarmi" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const STATUS_OPTIONS: Record<string, string> = {
  active: "Da gestire (aperti e in carico)",
  open: "Aperti",
  ack: "In carico",
  resolved: "Risolti",
  all: "Tutti",
};

export default async function AlertsPage({ searchParams }: Props) {
  const user = await requireUser();
  const p = await searchParams;
  const statusParam = one(p.status) || "active";
  const days = Number(one(p.days));
  const filter: AlertFilter = {
    status: statusParam === "all" ? "" : ((["active", "open", "ack", "resolved"].includes(statusParam) ? statusParam : "active") as AlertFilter["status"]),
    severity: (SEVERITIES as readonly string[]).includes(one(p.severity)) ? one(p.severity) : "",
    rule: one(p.rule).slice(0, 60),
    q: one(p.q).trim().slice(0, 100),
    days: [1, 7, 30, 90].includes(days) ? days : 0,
    assignee: one(p.assignee).slice(0, 40),
  };
  const [alerts, counts, rules, users] = await Promise.all([listAlerts(filter, 500), alertCounts(), ruleOptions(), assignableUsers()]);
  const analyst = can(user, "analyst");
  const bySeverity = Object.fromEntries(counts.map((c) => [c.severity, c]));
  const sevQuery = (s: string) => `/allarmi?status=active&severity=${s}`;

  const table = (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {analyst && (
              <th className="check-col">
                <SelectAll />
              </th>
            )}
            <th>Gravità</th>
            <th>Allarme</th>
            <th>Origine</th>
            <th className="num">Volte</th>
            <th>Ultima volta</th>
            <th>Stato</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} className={a.status === "resolved" ? "row--dim" : undefined}>
              {analyst && (
                <td className="check-col">
                  <input type="checkbox" name="id" value={a.id} aria-label={`Seleziona l'allarme ${a.id}`} />
                </td>
              )}
              <td>
                <SeverityBadge severity={a.severity} />
              </td>
              <td>
                <Link href={`/allarmi/${a.id}`} className="strong">
                  {a.title}
                </Link>
                <div className="muted small">
                  {a.rule_name}
                  {a.mitre && <span className="mono"> · {a.mitre}</span>}
                </div>
              </td>
              <td className="small">
                <span className="mono">{a.src_ip || "—"}</span>
                {a.device_name && <div className="muted">{a.device_name}</div>}
              </td>
              <td className="num">{fmtNum(a.count)}</td>
              <td className="nowrap" title={`Prima volta: ${fmtDateTime(a.first_seen)}`}>
                {fmtAgo(a.last_seen)}
              </td>
              <td className="nowrap">
                <StatusBadge status={a.status} />
                {a.assignee && <div className="muted small">{a.assignee}</div>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return (
    <>
      <AutoRefresh seconds={30} />
      <PageHead title="Allarmi" sub="Quello che il motore di rilevamento ha trovato: da valutare, prendere in carico e chiudere con un esito." />

      <div className="kpis kpis--small">
        {SEVERITIES.slice(0, 4).map((s) => {
          const c = bySeverity[s];
          const open = (c?.open ?? 0) + (c?.ack ?? 0);
          return (
            <Kpi
              key={s}
              label={SEVERITY_LABELS[s]}
              value={fmtNum(open)}
              sub={`${c?.open ?? 0} aperti · ${c?.today ?? 0} nuovi oggi`}
              tone={open === 0 ? undefined : s === "critical" ? "bad" : s === "high" ? "warn" : "accent"}
              href={sevQuery(s)}
            />
          );
        })}
      </div>

      <form className="filters" method="get">
        <Field label="Stato">
          <select name="status" defaultValue={statusParam}>
            {Object.entries(STATUS_OPTIONS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Gravità">
          <select name="severity" defaultValue={filter.severity}>
            <option value="">Tutte</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABELS[s]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Regola">
          <select name="rule" defaultValue={filter.rule}>
            <option value="">Tutte</option>
            {rules.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Assegnato a">
          <select name="assignee" defaultValue={filter.assignee}>
            <option value="">Chiunque</option>
            {users.map((u) => (
              <option key={u}>{u}</option>
            ))}
          </select>
        </Field>
        <Field label="Periodo">
          <select name="days" defaultValue={filter.days || ""}>
            <option value="">Sempre</option>
            <option value="1">Ultime 24 ore</option>
            <option value="7">Ultimi 7 giorni</option>
            <option value="30">Ultimi 30 giorni</option>
            <option value="90">Ultimi 90 giorni</option>
          </select>
        </Field>
        <Field label="Cerca">
          <input name="q" defaultValue={filter.q} placeholder="IP, titolo, dispositivo" spellCheck={false} />
        </Field>
        <div className="filters__actions">
          <button type="submit" className="btn btn--primary">
            Filtra
          </button>
        </div>
      </form>

      <Card title={`${fmtNum(alerts.length)} allarmi${alerts.length === 500 ? " (i primi 500)" : ""}`}>
        {alerts.length === 0 ? (
          <Empty>Nessun allarme con questi filtri.</Empty>
        ) : analyst ? (
          <ActionForm action={bulkAlerts}>
            <div className="bulkbar">
              <span className="muted small">Selezionati:</span>
              <Submit className="btn btn--small" name="op" value="ack">
                Prendi in carico
              </Submit>
              <Submit className="btn btn--small" name="op" value="mine">
                Assegna a me
              </Submit>
              <select name="resolution" defaultValue="" aria-label="Esito">
                <option value="">Esito…</option>
                {Object.entries(RESOLUTIONS).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </select>
              <Submit className="btn btn--small" name="op" value="resolve">
                Chiudi
              </Submit>
            </div>
            {table}
          </ActionForm>
        ) : (
          table
        )}
      </Card>
    </>
  );
}
