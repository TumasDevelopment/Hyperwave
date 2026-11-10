import Link from "next/link";
import { AutoRefresh } from "@/components/AutoRefresh";
import { Empty, Kpi, PageHead, SeverityBadge } from "@/components/ui";
import { requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { INCIDENT_STATUS_LABELS } from "@/lib/labels";
import { stages, tacticLabel } from "@/lib/mitre";
import { incidentCounts, listIncidents } from "@/lib/queries/incidents";

export const metadata = { title: "Incidenti" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };
const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : "");

export default async function IncidentsPage({ searchParams }: Props) {
  await requireUser();
  const p = await searchParams;
  const status = one(p.status);
  const q = one(p.q).trim().slice(0, 100);
  const [incidents, counts] = await Promise.all([
    listIncidents({ status: status in INCIDENT_STATUS_LABELS || status === "all" ? status : "", q }),
    incidentCounts(),
  ]);
  const now = Date.now();

  return (
    <>
      <AutoRefresh seconds={30} />
      <PageHead
        title="Incidenti"
        sub="Allarmi collegati: l'hub riunisce quelli di regole diverse che riguardano lo stesso dispositivo interno, così si vede la sequenza di un attacco invece di tanti allarmi separati."
      />
      <div className="kpis kpis--small">
        <Kpi label="Aperti" value={fmtNum(counts.open ?? 0)} tone={counts.open ? "bad" : "ok"} href="/incidenti?status=open" />
        <Kpi label="In indagine" value={fmtNum(counts.investigating ?? 0)} tone={counts.investigating ? "warn" : undefined} href="/incidenti?status=investigating" />
        <Kpi label="Contenuti" value={fmtNum(counts.contained ?? 0)} href="/incidenti?status=contained" />
        <Kpi label="Chiusi" value={fmtNum(counts.closed ?? 0)} href="/incidenti?status=closed" />
      </div>

      <form className="row filters" method="get">
        <select name="status" defaultValue={status} aria-label="Stato">
          <option value="">Da gestire</option>
          {Object.entries(INCIDENT_STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
          <option value="all">Tutti</option>
        </select>
        <input name="q" defaultValue={q} placeholder="Indirizzo o nome del dispositivo" aria-label="Cerca" />
        <button className="btn" type="submit">
          Filtra
        </button>
      </form>

      {incidents.length === 0 ? (
        <Empty>
          {status || q ? "Nessun incidente con questi filtri." : "Nessun incidente da gestire. Si aprono da soli quando un dispositivo accumula allarmi di regole diverse."}
        </Empty>
      ) : (
        <div className="table-wrap card">
          <table className="table">
            <thead>
              <tr>
                <th>Incidente</th>
                <th>Gravità</th>
                <th>Stato</th>
                <th>Fasi dell&apos;attacco</th>
                <th className="num">Allarmi</th>
                <th>Periodo</th>
                <th>Assegnato</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.id} className={i.status === "closed" ? "row--dim" : undefined}>
                  <td>
                    <Link href={`/incidenti/${i.id}`} className="strong">
                      {i.title}
                    </Link>
                    <div className="muted small">
                      n. {i.id} · {i.rule_count} {i.rule_count === 1 ? "regola" : "regole diverse"}
                    </div>
                  </td>
                  <td>
                    <SeverityBadge severity={i.severity} />
                  </td>
                  <td>
                    <span className={`status status--inc-${i.status}`}>{INCIDENT_STATUS_LABELS[i.status]}</span>
                  </td>
                  <td className="small">
                    {stages(i.techniques)
                      .map((s) => s.label)
                      .join(" → ") || (i.techniques.length ? tacticLabel(null) : "—")}
                  </td>
                  <td className="num">
                    {fmtNum(i.alert_count)}
                    {i.open_alerts > 0 && i.status !== "closed" && <div className="muted small">{i.open_alerts} aperti</div>}
                  </td>
                  <td className="small" title={`${fmtDateTime(i.first_seen)} – ${fmtDateTime(i.last_seen)}`}>
                    dal {fmtDateTime(i.first_seen)}
                    <div className="muted">ultimo {fmtAgo(i.last_seen, now)}</div>
                  </td>
                  <td>{i.assignee || <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small mt">
        Le soglie del raggruppamento (finestra, regole diverse necessarie, allarmi critici) si cambiano in{" "}
        <Link href="/regole">Regole</Link> → Correlazione.
      </p>
    </>
  );
}
