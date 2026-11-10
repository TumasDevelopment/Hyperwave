import Link from "next/link";
import { BarList, Card, Empty, Kpi, LoadError, PageHead, RangePicker, safe, SeverityBadge, Tabs } from "@/components/ui";
import { requireUser } from "@/lib/auth";
import { fmtAgo, fmtDateTime, fmtNum, fmtPct, fmtTime } from "@/lib/format";
import { PALETTE, SERIES_COLORS } from "@/lib/labels";
import { deviceNames } from "@/lib/names";
import { dnsOverview, httpOverview, idsEvents, newDomains, protocolsOverview, tlsOverview } from "@/lib/queries/analysis";
import { one, parseRange, type RangeKey } from "@/lib/ranges";

export const metadata = { title: "Analisi" };

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const TABS = { dns: "DNS", tls: "TLS e certificati", http: "HTTP in chiaro", proto: "Accessi e protocolli", ids: "Eventi IDS" } as const;
type Tab = keyof typeof TABS;
const RANGE_OPTIONS: RangeKey[] = ["1h", "6h", "24h", "7d"];

export default async function AnalysisPage({ searchParams }: Props) {
  await requireUser();
  const p = await searchParams;
  const tab = (one(p.tab) in TABS ? one(p.tab) : "dns") as Tab;
  const range = parseRange(p.range, "24h");
  const safeRange = RANGE_OPTIONS.includes(range) ? range : "24h";

  return (
    <>
      <PageHead title="Analisi" sub="Cosa dicono i protocolli: nomi richiesti, cifratura, siti visitati senza HTTPS, accessi a Windows e SSH, segnalazioni dell'IDS.">
        <RangePicker current={safeRange} base="/analisi" params={{ tab }} options={RANGE_OPTIONS} />
      </PageHead>
      <Tabs
        current={tab}
        items={Object.entries(TABS).map(([key, label]) => ({ key, label, href: `/analisi?tab=${key}&range=${safeRange}` }))}
      />
      {tab === "dns" && <DnsTab range={safeRange} />}
      {tab === "tls" && <TlsTab range={safeRange} />}
      {tab === "http" && <HttpTab range={safeRange} />}
      {tab === "proto" && <ProtoTab range={safeRange} />}
      {tab === "ids" && <IdsTab range={safeRange} />}
    </>
  );
}

async function DnsTab({ range }: { range: RangeKey }) {
  const [res, fresh, names] = await Promise.all([safe(dnsOverview(range), null, "DNS"), safe(newDomains(range), [], "domini nuovi"), deviceNames()]);
  if (!res.data) return <LoadError what="i dati DNS" />;
  const { totals, domains, nx, clients, types, servers } = res.data;
  const nxRate = totals && totals.queries ? (totals.nx / totals.queries) * 100 : 0;
  return (
    <>
      <div className="kpis kpis--small">
        <Kpi label="Richieste" value={fmtNum(totals?.queries ?? 0)} />
        <Kpi label="Domini diversi" value={fmtNum(totals?.domains ?? 0)} />
        <Kpi label="Risposte «inesistente»" value={fmtPct(nxRate)} sub={`${fmtNum(totals?.nx ?? 0)} richieste`} tone={nxRate > 10 ? "warn" : undefined} />
        <Kpi label="Tempo medio di risposta" value={`${fmtNum(Math.round(totals?.avg_rtt ?? 0))} ms`} sub={`${fmtNum(totals?.clients ?? 0)} client`} />
      </div>
      <div className="grid-2">
        <Card title="Domini più richiesti">
          <BarList format={fmtNum} rows={domains.map((d) => ({ key: d.domain, label: <span className="mono">{d.domain}</span>, value: d.queries, extra: `${d.clients} client`, href: `/flussi?range=${range}&domain=${encodeURIComponent(d.domain)}` }))} />
        </Card>
        <Card title="Domini mai visti prima (rispetto ai 30 giorni precedenti)">
          {fresh.failed ? (
            <LoadError what="i domini nuovi" />
          ) : (
            <BarList color={SERIES_COLORS.other} format={fmtNum} empty="Nessun dominio nuovo nel periodo." rows={fresh.data.map((d) => ({ key: d.domain, label: <span className="mono">{d.domain}</span>, value: d.queries, extra: `dal ${fmtDateTime(d.first)}` }))} />
          )}
        </Card>
        <Card title="Domini inesistenti (NXDOMAIN)">
          <p className="muted small">Molte richieste a nomi inesistenti possono indicare malware che cerca il suo server (DGA) o configurazioni sbagliate.</p>
          <BarList color="var(--warn)" format={fmtNum} empty="Nessuna risposta NXDOMAIN." rows={nx.map((d) => ({ key: d.domain, label: <span className="mono" title={d.example}>{d.domain || d.example}</span>, value: d.queries, extra: `${d.clients} client` }))} />
        </Card>
        <Card title="Client che chiedono di più">
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Client</th>
                  <th className="num">Richieste</th>
                  <th className="num">Nomi diversi</th>
                  <th className="num">Inesistenti</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.client}>
                    <td>
                      <Link href={`/flussi?range=${range}&ip=${c.client}&port=53`} className="mono">
                        {c.client}
                      </Link>{" "}
                      <span className="muted small">{names.get(c.client)?.label}</span>
                    </td>
                    <td className="num">{fmtNum(c.queries)}</td>
                    <td className="num">{fmtNum(c.domains)}</td>
                    <td className={`num ${c.queries && c.nx / c.queries > 0.2 ? "text-warn" : ""}`}>{fmtNum(c.nx)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Server DNS usati">
          <p className="muted small">Un client che usa un resolver diverso da quelli aziendali può aggirare i filtri.</p>
          <BarList color={SERIES_COLORS.internal} format={fmtNum} rows={servers.map((s) => ({ key: s.server, label: <span className="mono">{s.server}</span>, value: s.queries, extra: `${s.clients} client · ${fmtNum(Math.round(s.avg_rtt))} ms` }))} />
        </Card>
        <Card title="Tipi di richiesta">
          <BarList format={fmtNum} rows={types.map((t, i) => ({ key: t.qtype, label: <span className="mono">{t.qtype || "?"}</span>, value: t.queries }))} color={PALETTE[5]} />
        </Card>
      </div>
    </>
  );
}

async function TlsTab({ range }: { range: RangeKey }) {
  const res = await safe(tlsOverview(range), null, "TLS");
  if (!res.data) return <LoadError what="i dati TLS" />;
  const { versions, weak, certs, ja4, sni } = res.data;
  const now = Date.now() / 1000;
  return (
    <>
      <div className="grid-2">
        <Card title="Versioni del protocollo">
          <BarList
            format={fmtNum}
            rows={versions.map((v) => ({ key: v.version, label: v.version, value: v.sessions, extra: `${fmtNum(v.servers)} server` }))}
            color={SERIES_COLORS.in}
          />
          <p className="muted small">TLS 1.0 e 1.1 sono deprecati: chi li usa ancora va aggiornato.</p>
        </Card>
        <Card title="Server con versioni obsolete">
          {weak.length === 0 ? (
            <Empty>Nessun server con SSL, TLS 1.0 o TLS 1.1 nel periodo.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {weak.map((w) => (
                  <tr key={`${w.server}:${w.port}`}>
                    <td>
                      <Link href={`/flussi?range=${range}&ip=${w.server}&port=${w.port}`} className="mono">
                        {w.server}:{w.port}
                      </Link>
                      <div className="muted small">{w.sni}</div>
                    </td>
                    <td>
                      <span className="pill pill--bad">{w.version}</span>
                    </td>
                    <td className="num">{fmtNum(w.sessions)} sessioni</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
      <Card title="Certificati scaduti, in scadenza (30 giorni) o autofirmati">
        {certs.length === 0 ? (
          <Empty>Nessun certificato problematico tra quelli visti nel periodo. Con TLS 1.3 il certificato è cifrato e non si vede.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Server</th>
                  <th>Soggetto</th>
                  <th>Emesso da</th>
                  <th>Scadenza</th>
                  <th className="num">Sessioni</th>
                </tr>
              </thead>
              <tbody>
                {certs.map((c) => (
                  <tr key={`${c.server}:${c.port}`}>
                    <td>
                      <Link href={`/flussi?range=${range}&ip=${c.server}&port=${c.port}`} className="mono">
                        {c.server}:{c.port}
                      </Link>
                      <div className="muted small">{c.sni}</div>
                    </td>
                    <td className="small">{c.subject}</td>
                    <td className="small">
                      {c.issuer} {c.self_signed ? <span className="pill pill--warn">Autofirmato</span> : null}
                    </td>
                    <td className="nowrap">
                      {c.expiry > 0 ? (
                        <span className={c.expiry < now ? "pill pill--bad" : c.expiry < now + 30 * 86400 ? "pill pill--warn" : ""}>
                          {c.expiry < now ? "Scaduto il " : ""}
                          {fmtDateTime(c.expiry * 1000)}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="num">{fmtNum(c.sessions)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="grid-2">
        <Card title="Nomi dei server (SNI) più contattati">
          <BarList format={fmtNum} rows={sni.map((s) => ({ key: s.sni, label: <span className="mono">{s.sni}</span>, value: s.sessions, extra: `${s.clients} client${s.quic ? ` · ${fmtNum(s.quic)} su QUIC` : ""}`, href: `/flussi?range=${range}&domain=${encodeURIComponent(s.sni)}` }))} />
        </Card>
        <Card title="Impronte dei client (JA4) più rare">
          <p className="muted small">Ogni programma che usa TLS ha un&apos;impronta. Un&apos;impronta usata da un solo client merita uno sguardo: può essere uno strumento insolito o malware.</p>
          {ja4.length === 0 ? (
            <Empty>Nessuna impronta nel periodo.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {ja4.map((j) => (
                  <tr key={j.ja4}>
                    <td className="mono small">{j.ja4}</td>
                    <td className="small muted">{j.example_sni}</td>
                    <td className="num">{fmtNum(j.clients)} client</td>
                    <td className="num muted">{fmtNum(j.sessions)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

async function HttpTab({ range }: { range: RangeKey }) {
  const res = await safe(httpOverview(range), null, "HTTP");
  if (!res.data) return <LoadError what="i dati HTTP" />;
  const { hosts, statuses, agents, recent } = res.data;
  return (
    <>
      <p className="notice notice--warn">Tutto quello che compare qui viaggia senza cifratura: password e dati possono essere letti da chiunque sia sul percorso.</p>
      <div className="grid-2">
        <Card title="Siti visitati in chiaro">
          <BarList format={fmtNum} empty="Nessuna richiesta HTTP in chiaro: ottimo." rows={hosts.map((h) => ({ key: h.host, label: <span className="mono">{h.host || "(senza Host)"}</span>, value: h.requests, extra: `${h.clients} client${h.errors ? ` · ${h.errors} errori` : ""}` }))} />
        </Card>
        <Card title="Codici di risposta">
          <BarList format={fmtNum} rows={statuses.map((s) => ({ key: String(s.status), label: <span className="mono">{s.status || "nessuna risposta"}</span>, value: s.requests }))} color={PALETTE[1]} />
        </Card>
      </div>
      <Card title="Programmi (User-Agent) meno comuni">
        {agents.length === 0 ? (
          <Empty>Nessun User-Agent nel periodo.</Empty>
        ) : (
          <table className="table table--compact">
            <tbody>
              {agents.map((a) => (
                <tr key={a.user_agent}>
                  <td className="mono small break">{a.user_agent}</td>
                  <td className="num">{fmtNum(a.clients)} client</td>
                  <td className="num muted">{fmtNum(a.requests)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card title="Ultime richieste">
        {recent.length === 0 ? (
          <Empty>Nessuna richiesta nel periodo.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Ora</th>
                  <th>Client</th>
                  <th>Richiesta</th>
                  <th>Esito</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((r, i) => (
                  <tr key={`${r.ts}-${i}`}>
                    <td className="mono nowrap">{fmtTime(r.ts)}</td>
                    <td className="mono">{r.client}</td>
                    <td className="mono small break">
                      {r.method} http://{r.host}
                      {r.uri}
                    </td>
                    <td className="mono">{r.status || "—"}</td>
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

async function IdsTab({ range }: { range: RangeKey }) {
  const res = await safe(idsEvents(range), [], "eventi IDS");
  if (res.failed) return <LoadError what="gli eventi IDS" />;
  return (
    <Card title="Firme che hanno fatto scattare l'IDS">
      {res.data.length === 0 ? (
        <Empty>
          Nessun evento IDS nel periodo. Se usi Suricata, indica il suo eve.json al sensore con HW_SURICATA_EVE: gli avvisi compariranno qui e
          diventeranno allarmi.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Gravità</th>
                <th>Firma</th>
                <th>Categoria</th>
                <th className="num">Eventi</th>
                <th className="num">Origini</th>
                <th>Ultimo</th>
              </tr>
            </thead>
            <tbody>
              {res.data.map((e) => (
                <tr key={e.signature}>
                  <td>
                    <SeverityBadge severity={e.severity || "info"} />
                  </td>
                  <td>{e.signature}</td>
                  <td className="muted">{e.category}</td>
                  <td className="num">{fmtNum(e.events)}</td>
                  <td className="num">{fmtNum(e.sources)}</td>
                  <td className="muted">{fmtAgo(e.last)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

const PROTO_LABELS: Record<string, string> = { ssh: "SSH", rdp: "Desktop remoto (RDP)", smb: "Condivisioni Windows (SMB)", kerberos: "Kerberos", ntlm: "NTLM" };

async function ProtoTab({ range }: { range: RangeKey }) {
  const [res, names] = await Promise.all([safe(protocolsOverview(range), null, "protocolli"), deviceNames()]);
  if (!res.data) return <LoadError what="i dati dei protocolli" />;
  const { protocols, weak, users, kerberos, ssh, shares } = res.data;
  const who = (ip: string) => (
    <>
      <Link href={`/flussi?range=${range}&ip=${ip}`} className="mono">
        {ip}
      </Link>{" "}
      <span className="muted small">{names.get(ip)?.label}</span>
    </>
  );
  return (
    <>
      <p className="muted small">
        Il sensore legge l&apos;inizio delle connessioni SSH, RDP, SMB e Kerberos e le autenticazioni NTLM, anche dentro HTTP o RPC. Utenti e nomi
        compaiono perché viaggiano in chiaro: le password no.
      </p>
      <div className="grid-2">
        <Card title="Protocolli riconosciuti">
          <BarList
            format={fmtNum}
            empty="Nessuna sessione SSH, RDP, SMB, Kerberos o NTLM nel periodo."
            rows={protocols.map((p) => ({
              key: p.protocol,
              label: PROTO_LABELS[p.protocol] ?? p.protocol,
              value: p.sessions,
              extra: `${fmtNum(p.clients)} client · ${fmtNum(p.servers)} server${p.weak ? ` · ${fmtNum(p.weak)} deboli` : ""}`,
            }))}
          />
        </Card>
        <Card title="Errori Kerberos">
          <p className="muted small">Molte password errate da uno stesso host, o su tanti utenti diversi, indicano un tentativo di indovinare le password.</p>
          {kerberos.length === 0 ? (
            <Empty>Nessun errore Kerberos nel periodo.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {kerberos.map((k) => (
                  <tr key={k.error}>
                    <td className="small">{k.error}</td>
                    <td className="small muted">{k.users.join(", ")}</td>
                    <td className="num">{fmtNum(k.attempts)}</td>
                    <td className="num muted">{fmtNum(k.clients)} host</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
      <Card title="Configurazioni deboli">
        {weak.length === 0 ? (
          <Empty>Nessun protocollo debole nel periodo: niente SMBv1, NTLMv1, RDP senza NLA, ticket RC4 o algoritmi SSH rotti.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Server</th>
                  <th>Protocollo</th>
                  <th>Problema</th>
                  <th>Utenti</th>
                  <th className="num">Sessioni</th>
                  <th>Ultima</th>
                </tr>
              </thead>
              <tbody>
                {weak.map((w) => (
                  <tr key={`${w.server}|${w.protocol}|${w.weak}`}>
                    <td>
                      {who(w.server)}
                      <span className="muted small"> porta {w.port}</span>
                    </td>
                    <td>{PROTO_LABELS[w.protocol] ?? w.protocol}</td>
                    <td>
                      <span className="pill pill--warn">{w.weak}</span>
                    </td>
                    <td className="small">{w.users.join(", ") || "—"}</td>
                    <td className="num">
                      {fmtNum(w.sessions)} <span className="muted small">da {fmtNum(w.clients)} client</span>
                    </td>
                    <td className="muted nowrap">{fmtAgo(w.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Utenti visti in rete">
        {users.length === 0 ? (
          <Empty>Nessun utente nel periodo. Gli utenti compaiono con le autenticazioni NTLM e Kerberos e con i cookie RDP.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Utente</th>
                  <th>Autenticazione</th>
                  <th>Da</th>
                  <th>Protocolli</th>
                  <th className="num">Sessioni</th>
                  <th>Ultima</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.user}>
                    <td>
                      <span className="mono">{u.domain ? `${u.domain}\\${u.user}` : u.user}</span>
                    </td>
                    <td className="small">{u.auth || "—"}</td>
                    <td className="small">
                      {u.clients.map((c, i) => (
                        <span key={c}>
                          {i > 0 && ", "}
                          <Link href={`/flussi?range=${range}&ip=${c}`} className="mono">
                            {names.get(c)?.label ?? c}
                          </Link>
                        </span>
                      ))}
                    </td>
                    <td className="small muted">{u.protocols.map((p) => p.toUpperCase()).join(", ")}</td>
                    <td className="num">{fmtNum(u.sessions)}</td>
                    <td className="muted nowrap">{fmtAgo(u.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="grid-2">
        <Card title="Condivisioni SMB usate">
          {shares.length === 0 ? (
            <Empty>Nessuna condivisione vista nel periodo. Con SMB 3 cifrato le condivisioni non si vedono.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {shares.map((s) => (
                  <tr key={s.server}>
                    <td>{who(s.server)}</td>
                    <td className="mono small">{s.shares}</td>
                    <td className="num">{fmtNum(s.clients)} client</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Software SSH">
          <p className="muted small">Un client SSH insolito, o un server SSH dove non te lo aspetti, merita uno sguardo.</p>
          {ssh.length === 0 ? (
            <Empty>Nessuna connessione SSH nel periodo.</Empty>
          ) : (
            <table className="table table--compact">
              <tbody>
                {ssh.map((s) => (
                  <tr key={`${s.side}|${s.software}`}>
                    <td className="mono small break">{s.software}</td>
                    <td className="small muted">{s.side === "client" ? "client" : "server"}</td>
                    <td className="num">{fmtNum(s.hosts)} host</td>
                    <td className="num muted">{fmtNum(s.sessions)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}
