import Link from "next/link";
import { AutoRefresh } from "@/components/AutoRefresh";
import { ActionForm, ConfirmSubmit, Submit } from "@/components/forms";
import { Badge, Card, Empty, Field, PageHead } from "@/components/ui";
import { deletePcap, requestPcap } from "@/lib/actions/pcap";
import { can, requireUser, ROLE_LABELS } from "@/lib/auth";
import { fmtAgo, fmtBytes, fmtDateTime, fmtNum } from "@/lib/format";
import { canPcap, listPcapRequests, PCAP_STATUS_LABELS, pcapRole, pcapSensors, type PcapRequest } from "@/lib/queries/pcap";
import { one } from "@/lib/ranges";
import { toLocalInput } from "@/lib/zoned";

export const metadata = { title: "Pacchetti" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const TONES = { pending: "accent", running: "accent", done: "ok", failed: "bad", expired: "off" } as const;
const PROTO_LABELS: Record<string, string> = { "": "Tutti", tcp: "TCP", udp: "UDP", icmp: "ICMP" };

/** Valore in ms da un parametro dell'indirizzo (ms o data ISO). */
function msParam(value: string) {
  if (!value) return 0;
  const n = Number(value);
  if (Number.isFinite(n) && n > 1e11) return n;
  const t = Date.parse(value);
  return Number.isNaN(t) ? 0 : t;
}

function filterText(r: PcapRequest) {
  const parts = [r.ip_b ? `${r.ip_a} ↔ ${r.ip_b}` : `${r.ip_a} ↔ qualsiasi`];
  if (r.port) parts.push(`porta ${r.port}`);
  if (r.proto) parts.push(r.proto.toUpperCase());
  return parts.join(" · ");
}

export default async function PcapPage({ searchParams }: Props) {
  const user = await requireUser();
  const role = await pcapRole();
  if (!(await canPcap(user))) {
    return (
      <>
        <PageHead title="Pacchetti" />
        <Empty>
          Le estrazioni di pacchetti sono riservate al ruolo {ROLE_LABELS[role]}: i pacchetti contengono dati personali. Se ti servono, chiedi a un
          amministratore.
        </Empty>
      </>
    );
  }
  const sp = await searchParams;
  const [sensors, requests] = await Promise.all([pcapSensors(), listPcapRequests()]);
  const now = Date.now();
  const busy = requests.some((r) => r.status === "pending" || r.status === "running");

  // valori iniziali: dai collegamenti di flussi, allarmi e dispositivi, altrimenti gli ultimi 15 minuti
  const to = msParam(one(sp.to)) || now;
  const from = msParam(one(sp.from)) || to - 15 * 60_000;
  const sensorParam = Number(one(sp.sensor));
  const defaultSensor = sensors.find((s) => s.id === sensorParam)?.id ?? sensors.find((s) => s.online)?.id ?? sensors[0]?.id;

  return (
    <>
      {busy && <AutoRefresh seconds={5} />}
      <PageHead
        title="Pacchetti"
        sub="Estrazione dei pacchetti di una conversazione dal buffer circolare dei sensori, da aprire in Wireshark. Ogni richiesta e ogni download finiscono nel registro."
      />

      <Card title="Nuova estrazione">
        {sensors.length === 0 ? (
          <div className="help">
            <p>Nessun sensore conserva pacchetti. Il buffer circolare esiste solo nella modalità di cattura da interfaccia ed è spento finché non lo si accende sul sensore:</p>
            <pre>{`HW_PCAP_DIR=on                 # oppure un percorso, per esempio /var/lib/hyperwave/pacchetti
HW_PCAP_RING_MB=4096           # spazio massimo su disco
HW_PCAP_RING_MINUTES=120       # età massima dei pacchetti`}</pre>
            <p className="muted small">Dopo il riavvio il sensore comunica all&apos;hub il periodo disponibile e compare qui.</p>
          </div>
        ) : (
          <ActionForm action={requestPcap} className="form-grid">
            <Field label="Sensore">
              <select name="sensor" defaultValue={defaultSensor}>
                {sensors.map((s) => (
                  <option key={s.id} value={s.id} disabled={!s.online}>
                    {s.name}
                    {s.site ? ` (${s.site})` : ""} — {s.online ? (s.from ? `dal ${fmtDateTime(s.from)}, ${fmtBytes(s.bytes)}` : "buffer vuoto") : "non raggiungibile"}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Indirizzo" hint="Origine o destinazione dei pacchetti">
              <input name="a" required defaultValue={one(sp.a)} placeholder="192.168.1.20" spellCheck={false} />
            </Field>
            <Field label="Controparte" hint="Facoltativa: solo la conversazione tra i due indirizzi">
              <input name="b" defaultValue={one(sp.b)} spellCheck={false} />
            </Field>
            <Field label="Porta" hint="Facoltativa, origine o destinazione">
              <input name="port" type="number" min={1} max={65535} defaultValue={one(sp.port)} />
            </Field>
            <Field label="Protocollo">
              <select name="proto" defaultValue={one(sp.proto).toLowerCase()}>
                {Object.entries(PROTO_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Dalle">
              <input name="from" type="datetime-local" step={1} required defaultValue={toLocalInput(from)} />
            </Field>
            <Field label="Alle" hint="Al massimo 6 ore">
              <input name="to" type="datetime-local" step={1} required defaultValue={toLocalInput(to)} />
            </Field>
            <Field label="Motivo" hint="Obbligatorio: va nel registro delle attività insieme alla richiesta" wide>
              <input name="reason" required minLength={5} maxLength={500} defaultValue={one(sp.alert) ? `Analisi dell'allarme n. ${one(sp.alert)}` : ""} />
            </Field>
            {one(sp.alert) && <input type="hidden" name="alert" value={one(sp.alert)} />}
            <div className="field--wide">
              <Submit>Chiedi i pacchetti</Submit>
            </div>
          </ActionForm>
        )}
      </Card>

      <Card title="Estrazioni">
        {requests.length === 0 ? (
          <Empty>Nessuna estrazione richiesta.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>N.</th>
                  <th>Richiesta</th>
                  <th>Sensore</th>
                  <th>Filtro</th>
                  <th>Periodo</th>
                  <th>Stato</th>
                  <th className="num">Pacchetti</th>
                  <th className="num">Dimensione</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td>
                      <span title={fmtDateTime(r.created_at)}>{fmtAgo(r.created_at, now)}</span> · {r.requested_by}
                      <div className="muted small">
                        {r.reason}
                        {r.alert_id && (
                          <>
                            {" "}
                            · <Link href={`/allarmi/${r.alert_id}`}>allarme {r.alert_id}</Link>
                          </>
                        )}
                      </div>
                    </td>
                    <td>{r.sensor}</td>
                    <td className="mono small">{filterText(r)}</td>
                    <td className="nowrap small">
                      {fmtDateTime(r.t_from)}
                      <br />
                      {fmtDateTime(r.t_to)}
                    </td>
                    <td>
                      <Badge tone={TONES[r.status]}>{PCAP_STATUS_LABELS[r.status]}</Badge>
                      {r.status === "done" && r.truncated && <div className="text-warn small">Troncato al limite di dimensione</div>}
                      {r.status === "done" && r.expires_at && <div className="muted small">Si cancella {fmtDateTime(r.expires_at)}</div>}
                      {r.error && <div className="muted small">{r.error}</div>}
                    </td>
                    <td className="num">{r.status === "done" || r.status === "expired" ? fmtNum(r.packets) : "—"}</td>
                    <td className="num">{r.status === "done" || r.status === "expired" ? fmtBytes(r.bytes) : "—"}</td>
                    <td className="nowrap">
                      <div className="row">
                        {r.status === "done" && (
                          <a className="btn btn--small" href={`/api/pacchetti/${r.id}`} download title={`SHA-256 ${r.sha256}`}>
                            Scarica .pcap
                          </a>
                        )}
                        {(r.status === "done" || r.status === "pending" || r.status === "running") &&
                          (r.requested_by === user.username || can(user, "admin")) && (
                            <ActionForm action={deletePcap} notices={false}>
                              <input type="hidden" name="id" value={r.id} />
                              <ConfirmSubmit label={r.status === "done" ? "Cancella" : "Annulla"} confirmLabel="Confermi?" />
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
        <p className="muted small mt">
          I file estratti restano sull&apos;hub per il numero di giorni impostato con HW_PCAP_KEEP_DAYS (7 predefiniti), poi si cancellano da soli.
          Ruolo che può usare questa pagina: {ROLE_LABELS[role]} (Impostazioni → Generale).
        </p>
      </Card>
    </>
  );
}
