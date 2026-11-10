import { AutoRefresh } from "@/components/AutoRefresh";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Empty, Field, PageHead } from "@/components/ui";
import { createSensor, deleteSensor, rotateSensorToken, updateSensor } from "@/lib/actions/admin";
import { can, requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum } from "@/lib/format";
import { listSensors, SENSOR_STATE_LABELS, sensorState } from "@/lib/queries/system";

export const metadata = { title: "Sensori" };

const MODE_LABELS: Record<string, string> = { capture: "Cattura", pcap: "File pcap", demo: "Dati di esempio" };
const TONES = { online: "ok", late: "warn", offline: "bad", never: "off", disabled: "off" } as const;

const STAT_LABELS: Record<string, string> = {
  packets: "Pacchetti",
  bytes: "Byte osservati",
  kernel_drops: "Pacchetti persi dal kernel",
  flows_active: "Flussi aperti",
  flow_table_full: "Flussi ignorati (tabella piena)",
  sent: "Record inviati",
  dropped_records: "Record scartati (coda piena)",
  pending_records: "Record in coda",
  spool_records: "Record nella coda su disco",
  spool_bytes: "Byte nella coda su disco",
  spool_dropped: "Record scartati dalla coda su disco",
  ids_events: "Eventi IDS letti",
};

export default async function SensorsPage() {
  const user = await requireUser();
  const sensors = await listSensors();
  const admin = can(user, "admin");
  const now = Date.now();

  return (
    <>
      <AutoRefresh seconds={20} />
      <PageHead title="Sensori" sub="I programmi che osservano il traffico e lo inviano all'hub. Ogni sensore ha un token suo." />
      {sensors.length === 0 && <Empty>Nessun sensore registrato.</Empty>}
      <div className="sensor-grid">
        {sensors.map((s) => {
          const state = sensorState(s, now);
          const stats = Object.entries(s.stats ?? {}).filter(([, v]) => typeof v === "number");
          return (
            <Card
              key={s.id}
              title={
                <>
                  {s.name} <Badge tone={TONES[state]}>{SENSOR_STATE_LABELS[state]}</Badge>
                </>
              }
            >
              <dl className="dl">
                <dt>Sede</dt>
                <dd>{s.site || "—"}</dd>
                <dt>Modalità</dt>
                <dd>{MODE_LABELS[s.mode] ?? (s.mode || "—")}</dd>
                <dt>Host</dt>
                <dd className="mono">{s.hostname || "—"}</dd>
                <dt>Versione</dt>
                <dd className="mono">{s.version || "—"}</dd>
                <dt>Ultimo contatto</dt>
                <dd title={fmtDateTime(s.last_seen)}>{fmtAgo(s.last_seen, now)}</dd>
                <dt>Ultimi dati</dt>
                <dd title={fmtDateTime(s.last_ingest)}>{fmtAgo(s.last_ingest, now)}</dd>
                <dt>Record ricevuti</dt>
                <dd>{fmtNum(s.records)}</dd>
                {stats.map(([k, v]) => (
                  <div key={k} className="dl__row">
                    <dt>{STAT_LABELS[k] ?? k}</dt>
                    <dd className={/drop|full|error/.test(k) && v > 0 ? "text-warn" : undefined}>{fmtNum(v)}</dd>
                  </div>
                ))}
                <dt>Aggiunto</dt>
                <dd>
                  {fmtDateTime(s.created_at)} {s.created_by && `da ${s.created_by}`}
                </dd>
              </dl>
              {admin && (
                <details className="mt">
                  <summary className="btn btn--small btn--ghost">Gestisci</summary>
                  <div className="stack mt">
                    <ActionForm action={updateSensor} className="row">
                      <input type="hidden" name="id" value={s.id} />
                      <input name="site" defaultValue={s.site} placeholder="Sede" maxLength={100} aria-label="Sede" />
                      <label className="check">
                        <input type="checkbox" name="enabled" defaultChecked={s.enabled} /> Attivo
                      </label>
                      <Submit className="btn btn--small">Salva</Submit>
                    </ActionForm>
                    <ActionForm action={rotateSensorToken} className="row">
                      <input type="hidden" name="id" value={s.id} />
                      <ConfirmSubmit label="Nuovo token" confirmLabel="Il vecchio smetterà di funzionare: confermi?" className="btn btn--small" />
                    </ActionForm>
                    <ActionForm action={deleteSensor} className="row">
                      <input type="hidden" name="id" value={s.id} />
                      <ConfirmSubmit label="Elimina sensore" confirmLabel="Conferma eliminazione" />
                    </ActionForm>
                  </div>
                </details>
              )}
            </Card>
          );
        })}
      </div>

      {admin && (
        <Card title="Aggiungi un sensore">
          <ActionForm action={createSensor} resetOnOk className="form-grid">
            <Field label="Nome" hint="Per esempio: sede-milano, dmz, core-switch">
              <input name="name" required maxLength={63} pattern="[\p{L}\p{N}][\p{L}\p{N} ._\-]{0,62}" />
            </Field>
            <Field label="Sede">
              <input name="site" maxLength={100} />
            </Field>
            <div className="field--wide">
              <Submit>Crea sensore e token</Submit>
            </div>
          </ActionForm>
          <div className="help mt">
            <p>
              <strong>Installazione del sensore.</strong> Sul server che vede il traffico (porta in mirror/SPAN dello switch o TAP), copia{" "}
              <code>hw-sensor</code> e imposta:
            </p>
            <pre>{`HW_HUB_URL=https://indirizzo-dell-hub:3121
HW_SENSOR_TOKEN=<token mostrato una sola volta>
HW_IFACE=eth1            # interfaccia in ascolto, anche più di una: eth1,eth2
HW_SURICATA_EVE=/var/log/suricata/eve.json   # facoltativo`}</pre>
            <p className="muted small">
              Il sensore serve le capability CAP_NET_RAW e CAP_NET_ADMIN (l&apos;unità systemd in <code>deploy/systemd</code> le imposta). Per
              analizzare un file: <code>hw-sensor -mode pcap -file cattura.pcapng</code>.
            </p>
          </div>
        </Card>
      )}
    </>
  );
}
