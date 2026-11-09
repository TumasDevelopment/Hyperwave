import Link from "next/link";
import { ActionForm, SelectAll, Submit } from "@/components/forms";
import { Card, Empty, Field, Kpi, PageHead } from "@/components/ui";
import { approveDevices } from "@/lib/actions/ops";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtNum } from "@/lib/format";
import { CRITICALITY_LABELS } from "@/lib/labels";
import { one } from "@/lib/ranges";
import { deviceStats, deviceTypes, listDevices, type DeviceFilter } from "@/lib/queries/devices";

export const metadata = { title: "Dispositivi" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const STATUSES: Record<DeviceFilter["status"], string> = {
  "": "Tutti",
  new: "Nuovi (24 h)",
  unapproved: "Da approvare",
  active: "Attivi (1 h)",
  inactive: "Inattivi (7 g)",
  alerts: "Con allarmi aperti",
};
const SORTS: Record<DeviceFilter["sort"], string> = {
  last_seen: "Ultima attività",
  first_seen: "Comparsa più recente",
  name: "Nome",
  ip: "Indirizzo",
  traffic: "Traffico",
};

export default async function DevicesPage({ searchParams }: Props) {
  const user = await requireUser();
  const p = await searchParams;
  const status = one(p.status) as DeviceFilter["status"];
  const sort = one(p.sort) as DeviceFilter["sort"];
  const filter: DeviceFilter = {
    q: one(p.q).trim().slice(0, 100),
    type: one(p.type).slice(0, 60),
    vlan: Math.max(0, Math.min(4094, Number(one(p.vlan)) || 0)),
    status: status in STATUSES ? status : "",
    sort: sort in SORTS ? sort : "last_seen",
  };
  const [devices, stats, types] = await Promise.all([listDevices(filter, 1000), deviceStats(), deviceTypes()]);
  const analyst = can(user, "analyst");
  const now = Date.now();

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
            <th>Dispositivo</th>
            <th>Indirizzi</th>
            <th>Tipo</th>
            <th>VLAN</th>
            <th className="num">Traffico</th>
            <th>Ultima attività</th>
            <th>Stato</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => {
            const fresh = now - new Date(d.first_seen).getTime() < 86_400_000;
            const active = now - new Date(d.last_seen).getTime() < 3_600_000;
            return (
              <tr key={d.id}>
                {analyst && (
                  <td className="check-col">
                    <input type="checkbox" name="id" value={d.id} aria-label={`Seleziona ${d.name || d.ip}`} />
                  </td>
                )}
                <td>
                  <Link href={`/dispositivi/${d.id}`} className="strong">
                    {d.name || d.hostname || d.ip || d.mac}
                  </Link>
                  {d.name && d.hostname && <div className="muted small">{d.hostname}</div>}
                  {d.tags.length > 0 && (
                    <div className="tags">
                      {d.tags.map((t) => (
                        <Link key={t} href={`/dispositivi?q=${encodeURIComponent(t)}`} className="tag">
                          {t}
                        </Link>
                      ))}
                    </div>
                  )}
                </td>
                <td className="mono small">
                  {d.ip || "—"}
                  {d.ips.length > 1 && <span className="muted"> +{d.ips.length - 1}</span>}
                  <div className="muted">{d.mac}</div>
                </td>
                <td>
                  {d.type || <span className="muted">Sconosciuto</span>}
                  <div className="muted small ellipsis">{[d.vendor, d.os].filter(Boolean).join(" · ")}</div>
                </td>
                <td className="mono">{d.vlan || "—"}</td>
                <td className="num">
                  {fmtBytes(d.bytes)}
                  <div className="muted small">{fmtNum(d.flows)} flussi</div>
                </td>
                <td>
                  <span className={active ? "text-ok" : "muted"}>{fmtAgo(d.last_seen, now)}</span>
                  <div className="muted small">dal {new Date(d.first_seen).toLocaleDateString("it-IT")}</div>
                </td>
                <td className="nowrap">
                  {d.open_alerts > 0 && (
                    <Link href={`/dispositivi/${d.id}#allarmi`} className="pill pill--bad">
                      {d.open_alerts} allarmi
                    </Link>
                  )}{" "}
                  {d.approved ? (
                    <span className="pill pill--ok">Approvato</span>
                  ) : (
                    <span className="pill pill--accent">{fresh ? "Nuovo" : "Da approvare"}</span>
                  )}
                  {d.criticality !== "normal" && <div className="small muted">Criticità {CRITICALITY_LABELS[d.criticality].toLowerCase()}</div>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );

  return (
    <>
      <PageHead title="Dispositivi" sub="Inventario costruito dal traffico: ogni dispositivo che parla in rete compare qui.">
        <a className="btn btn--small" href="/api/dispositivi.csv">
          Esporta CSV
        </a>
      </PageHead>

      <div className="kpis kpis--small">
        <Kpi label="In inventario" value={fmtNum(stats.total)} href="/dispositivi" />
        <Kpi label="Attivi nell'ultima ora" value={fmtNum(stats.active)} href="/dispositivi?status=active" tone="ok" />
        <Kpi label="Nuovi nelle 24 h" value={fmtNum(stats.new24)} href="/dispositivi?status=new&sort=first_seen" tone={stats.new24 ? "accent" : undefined} />
        <Kpi label="Da approvare" value={fmtNum(stats.unapproved)} href="/dispositivi?status=unapproved" tone={stats.unapproved ? "warn" : undefined} />
      </div>

      <form className="filters" method="get">
        <Field label="Cerca">
          <input name="q" defaultValue={filter.q} placeholder="IP, MAC, nome, produttore, etichetta…" spellCheck={false} className="input--wide" />
        </Field>
        <Field label="Tipo">
          <select name="type" defaultValue={filter.type}>
            <option value="">Tutti</option>
            <option value="-">Sconosciuto</option>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        <Field label="VLAN">
          <select name="vlan" defaultValue={filter.vlan || ""}>
            <option value="">Tutte</option>
            {stats.vlans.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Stato">
          <select name="status" defaultValue={filter.status}>
            {Object.entries(STATUSES).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Ordina per">
          <select name="sort" defaultValue={filter.sort}>
            {Object.entries(SORTS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <div className="filters__actions">
          <button type="submit" className="btn btn--primary">
            Filtra
          </button>
        </div>
      </form>

      <Card title={`${fmtNum(devices.length)} dispositivi${devices.length === 1000 ? " (i primi 1000)" : ""}`}>
        {devices.length === 0 ? (
          <Empty>Nessun dispositivo corrisponde ai filtri.</Empty>
        ) : analyst ? (
          <ActionForm action={approveDevices}>
            <div className="bulkbar">
              <Submit className="btn btn--small">Approva i selezionati</Submit>
              <span className="muted small">Approvare significa: dispositivo conosciuto e atteso in rete.</span>
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
