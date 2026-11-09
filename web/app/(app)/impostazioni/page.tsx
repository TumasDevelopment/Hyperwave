import Link from "next/link";
import { ActionForm, Submit } from "@/components/forms";
import { Badge, Card, Field, LoadError, PageHead, safe, Tabs } from "@/components/ui";
import { saveNetworkConfig, setLive } from "@/lib/actions/admin";
import { requireRole } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtDateTime, fmtDuration, fmtNum } from "@/lib/format";
import { hubHealth, pgSize, storageUsage, systemSettings } from "@/lib/queries/system";
import { SETTINGS_TABS } from "@/lib/settings-tabs";

export const metadata = { title: "Impostazioni" };

const TABLE_LABELS: Record<string, string> = {
  flows: "Flussi",
  dns: "DNS",
  tls: "TLS",
  http: "HTTP",
  events: "Eventi IDS",
  rates: "Contatori",
  traffic_1m: "Traffico al minuto",
  hosts_1h: "Host all'ora",
  dns_1h: "DNS all'ora",
};

export default async function SettingsPage() {
  await requireRole("admin");
  const [settings, health, storage, pg] = await Promise.all([
    systemSettings(),
    hubHealth(),
    safe(storageUsage(), [], "spazio ClickHouse"),
    pgSize().catch(() => 0),
  ]);
  const { live, config, vigil, cursor, liveChanged } = settings;
  const lag = cursor ? (Date.now() - cursor) / 1000 : null;
  const totalCompressed = storage.data.reduce((sum, r) => sum + r.compressed, 0);
  const totalRaw = storage.data.reduce((sum, r) => sum + r.bytes, 0);
  const yes = (v: unknown) => (v ? <Badge tone="ok">OK</Badge> : <Badge tone="bad">Non risponde</Badge>);

  return (
    <>
      <PageHead title="Impostazioni" sub="Configurazione dell'installazione, stato dei componenti e accessi." />
      <Tabs current="generale" items={SETTINGS_TABS} />

      <div className="grid-2">
        <Card title="Live">
          <p>
            {live ? <Badge tone="ok">Acceso</Badge> : <Badge tone="warn">Spento</Badge>}{" "}
            {live
              ? "I sensori inviano i dati e il motore cerca le minacce."
              : "I sensori non inviano dati e il motore è fermo. Alla riaccensione i sensori di esempio recuperano il periodo perso."}
          </p>
          {liveChanged?.updated_by && (
            <p className="muted small">
              Ultima modifica: {liveChanged.updated_by}, {fmtDateTime(liveChanged.updated_at)}
            </p>
          )}
          <ActionForm action={setLive}>
            <input type="hidden" name="live" value={live ? "off" : "on"} />
            <Submit className={live ? "btn btn--danger" : "btn btn--primary"}>{live ? "Spegni il live" : "Accendi il live"}</Submit>
          </ActionForm>
        </Card>

        <Card title="Stato dei componenti">
          {health ? (
            <dl className="dl">
              <dt>Hub</dt>
              <dd>
                {yes(health.ok)} <span className="muted mono small">{String(health.version ?? "")}</span>
                <span className="muted small"> · attivo da {fmtDuration(Number(health.uptime_s ?? 0))}</span>
              </dd>
              <dt>PostgreSQL</dt>
              <dd>
                {yes(health.postgres)} <span className="muted small">{fmtBytes(pg)}</span>
              </dd>
              <dt>ClickHouse</dt>
              <dd>
                {yes(health.clickhouse)} <span className="muted small">{fmtBytes(totalCompressed)} su disco</span>
              </dd>
              <dt>NATS</dt>
              <dd>{yes(health.nats)}</dd>
              <dt>Dati ricevuti</dt>
              <dd>
                {fmtNum(Number(health.records ?? 0))} record in {fmtNum(Number(health.batches ?? 0))} invii
                {Number(health.rejected ?? 0) > 0 && <span className="text-warn"> · {fmtNum(Number(health.rejected))} rifiutati</span>}
              </dd>
              {health.last_error ? (
                <>
                  <dt>Ultimo errore</dt>
                  <dd className="text-warn small">{String(health.last_error)}</dd>
                </>
              ) : null}
              <dt>Motore di rilevamento</dt>
              <dd>
                {lag === null ? (
                  <span className="muted">non ancora partito</span>
                ) : lag < 300 ? (
                  <>
                    <Badge tone="ok">Al passo</Badge> <span className="muted small">analizzato fino a {fmtAgo(cursor)}</span>
                  </>
                ) : (
                  <>
                    <Badge tone="warn">In ritardo</Badge> <span className="muted small">{fmtDuration(lag)} indietro</span>
                  </>
                )}
              </dd>
              {vigil && (
                <>
                  <dt>Vigil</dt>
                  <dd>
                    {vigil.ok ? <Badge tone="ok">In linea</Badge> : <Badge tone="bad">Non raggiungibile</Badge>}{" "}
                    <span className="muted small">{vigil.checked ? `controllato ${fmtAgo(vigil.checked)}` : ""}</span>
                  </dd>
                </>
              )}
            </dl>
          ) : (
            <p className="notice notice--error">L&apos;hub non risponde su HW_HUB_URL: senza hub non arrivano dati e non partono i rilevamenti.</p>
          )}
        </Card>
      </div>

      <Card title="Rete">
        <ActionForm action={saveNetworkConfig} className="form-grid">
          <Field label="Reti interne" hint="Separate da virgole. Vuoto = valore di .env (HW_INTERNAL_NETS) o le reti private standard." wide>
            <textarea name="internal_nets" rows={2} defaultValue={(config.internal_nets ?? "").split(",").join(", ")} spellCheck={false} />
          </Field>
          <Field label="Reti sensibili" hint="Server, gestione, pagamenti: un dispositivo nuovo qui genera un allarme grave." wide>
            <textarea name="sensitive_nets" rows={2} defaultValue={(config.sensitive_nets ?? "").split(",").join(", ")} spellCheck={false} />
          </Field>
          <Field label="Ore di apprendimento" hint="Dopo la prima installazione, per quante ore i dispositivi nuovi non generano allarmi. 0 = valore di .env.">
            <input name="learning_hours" type="number" min={0} max={720} defaultValue={config.learning_hours ?? ""} />
          </Field>
          <Field label="Fuso orario" hint="Per le regole notturne. Vuoto = valore di .env (HW_TZ).">
            <input name="timezone" defaultValue={config.timezone ?? ""} placeholder="Europe/Rome" />
          </Field>
          <div className="field--wide">
            <Submit>Salva</Submit>
          </div>
        </ActionForm>
      </Card>

      <Card title="Spazio occupato dai dati">
        {storage.failed ? (
          <LoadError what="lo spazio occupato" />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Tabella</th>
                    <th className="num">Righe</th>
                    <th className="num">Su disco</th>
                    <th className="num">Non compresso</th>
                    <th>Dato più vecchio</th>
                  </tr>
                </thead>
                <tbody>
                  {storage.data.map((r) => (
                    <tr key={r.table}>
                      <td>
                        {TABLE_LABELS[r.table] ?? r.table} <span className="muted mono small">{r.table}</span>
                      </td>
                      <td className="num">{fmtNum(r.rows)}</td>
                      <td className="num">{fmtBytes(r.compressed)}</td>
                      <td className="num muted">{fmtBytes(r.bytes)}</td>
                      <td className="muted">{r.oldest && !r.oldest.startsWith("1970") ? fmtDateTime(r.oldest) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted small">
              Compressione {totalCompressed ? `${fmtNum(Math.round(totalRaw / totalCompressed))}:1` : "—"}. La durata della conservazione si imposta
              in .env (HW_RETENTION_DAYS per i dati grezzi, HW_AGG_RETENTION_DAYS per gli aggregati). <Link href="/sensori">Sensori</Link>
            </p>
          </>
        )}
      </Card>
    </>
  );
}
