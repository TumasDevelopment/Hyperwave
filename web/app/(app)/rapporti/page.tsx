import { AutoRefresh } from "@/components/AutoRefresh";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Empty, Field, PageHead } from "@/components/ui";
import { deleteReport, requestReport, saveReportSchedule } from "@/lib/actions/reports";
import { can, requireRole } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtDateTime, fmtDay, fmtNum } from "@/lib/format";
import { listReports, REPORT_STATUS_LABELS, reportSchedule } from "@/lib/queries/reports";
import { type ReportKind, REPORT_KINDS } from "@/lib/reports/build";
import { REPORT_PERIODS } from "@/lib/reports/periods";

export const metadata = { title: "Rapporti" };

const TONES = { pending: "accent", running: "accent", done: "ok", failed: "bad" } as const;

export default async function ReportsPage() {
  const user = await requireRole("analyst");
  const admin = can(user, "admin");
  const [reports, schedule] = await Promise.all([listReports(), reportSchedule()]);
  const visible = reports.filter((r) => admin || r.kind !== "compliance");
  const busy = visible.some((r) => r.status === "pending" || r.status === "running");
  const kinds = (Object.keys(REPORT_KINDS) as ReportKind[]).filter((k) => admin || k !== "compliance");
  const now = Date.now();

  return (
    <>
      {busy && <AutoRefresh seconds={4} />}
      <PageHead title="Rapporti" sub="Rapporti in PDF per la direzione, per il gruppo tecnico e come evidenza per NIS2 e ISO 27001." />

      <div className="grid-2">
        <Card title="Nuovo rapporto">
          <ActionForm action={requestReport} className="form-grid">
            <Field label="Tipo" wide>
              <select name="kind" defaultValue="executive">
                {kinds.map((k) => (
                  <option key={k} value={k}>
                    {REPORT_KINDS[k].title}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Periodo" wide>
              <select name="period" defaultValue="prevweek">
                {Object.entries(REPORT_PERIODS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
            <div className="field--wide">
              <Submit>Prepara il rapporto</Submit>
            </div>
          </ActionForm>
          <dl className="dl mt">
            {kinds.map((k) => (
              <div key={k} className="dl__row">
                <dt>{REPORT_KINDS[k].title}</dt>
                <dd className="muted small">{REPORT_KINDS[k].description}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card title="Ogni settimana">
          <p className="muted small">
            Il lunedì, poco dopo mezzanotte, Hyperwave prepara i rapporti scelti qui per la settimana appena finita. Restano in questa pagina per 13
            mesi; non vengono inviati a nessuno.
          </p>
          {admin ? (
            <ActionForm action={saveReportSchedule} className="stack">
              {(Object.keys(REPORT_KINDS) as ReportKind[]).map((k) => (
                <label key={k} className="check">
                  <input type="checkbox" name="kind" value={k} defaultChecked={schedule.includes(k)} /> {REPORT_KINDS[k].title}
                </label>
              ))}
              <div>
                <Submit>Salva</Submit>
              </div>
            </ActionForm>
          ) : (
            <p>
              {schedule.length ? schedule.map((k) => REPORT_KINDS[k]?.title ?? k).join(", ") : "Nessun rapporto pianificato."}{" "}
              <span className="muted small">(la scelta spetta agli amministratori)</span>
            </p>
          )}
        </Card>
      </div>

      <Card title="Archivio">
        {visible.length === 0 ? (
          <Empty>Nessun rapporto ancora.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Rapporto</th>
                  <th>Periodo</th>
                  <th>Chiesto</th>
                  <th>Stato</th>
                  <th className="num">Pagine</th>
                  <th className="num">Dimensione</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => (
                  <tr key={r.id}>
                    <td>
                      {REPORT_KINDS[r.kind]?.title ?? r.kind} <span className="muted mono small">n. {r.id}</span>
                    </td>
                    <td className="nowrap">
                      {fmtDay(r.period_from)} – {fmtDay(new Date(r.period_to).getTime() - 1)}
                    </td>
                    <td>
                      <span title={fmtDateTime(r.created_at)}>{fmtAgo(r.created_at, now)}</span> ·{" "}
                      {r.scheduled ? <span className="muted">pianificato</span> : r.requested_by}
                    </td>
                    <td>
                      <Badge tone={TONES[r.status]}>{REPORT_STATUS_LABELS[r.status]}</Badge>
                      {r.error && <div className="muted small">{r.error}</div>}
                    </td>
                    <td className="num">{r.status === "done" ? fmtNum(r.pages) : "—"}</td>
                    <td className="num">{r.status === "done" ? fmtBytes(r.bytes) : "—"}</td>
                    <td className="nowrap">
                      <div className="row">
                        {r.status === "done" && (
                          <a className="btn btn--small" href={`/api/rapporti/${r.id}`} download title={`SHA-256 ${r.sha256}`}>
                            Scarica PDF
                          </a>
                        )}
                        {(admin || (!r.scheduled && r.requested_by === user.username)) && r.status !== "running" && (
                          <ActionForm action={deleteReport} notices={false}>
                            <input type="hidden" name="id" value={r.id} />
                            <ConfirmSubmit label="Elimina" confirmLabel="Confermi?" />
                          </ActionForm>
                        )}
                      </div>
                    </td>
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
