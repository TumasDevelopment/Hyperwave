import "server-only";
import { AUDIT_LABELS } from "../audit";
import { countryName, fmtBytes, fmtDateTime, fmtDay, fmtDuration, fmtNum, fmtPct, TZ } from "../format";
import { INCIDENT_STATUS_LABELS, SEVERITY_LABELS, STATUS_LABELS } from "../labels";
import { localMidnight } from "../zoned";
import * as data from "./data";
import { type Kpi, ReportDoc, SEVERITY_COLORS } from "./pdf";

export type ReportKind = "executive" | "technical" | "compliance";

export const REPORT_KINDS: Record<ReportKind, { title: string; description: string }> = {
  executive: {
    title: "Rapporto per la direzione",
    description: "Due-tre pagine: numeri principali, andamento, incidenti e cosa serve fare. Per chi non segue la rete ogni giorno.",
  },
  technical: {
    title: "Rapporto tecnico",
    description: "Allarmi per regola, incidenti, traffico, dispositivi nuovi, servizi esposti, sensori, regole ed eccezioni.",
  },
  compliance: {
    title: "Evidenze per NIS2 e ISO 27001",
    description: "Evidenze tecniche ordinate per misura (art. 21 NIS2, allegato A ISO/IEC 27001:2022): inventario, monitoraggio, incidenti, accessi, registro.",
  },
};

export interface ReportInput {
  kind: ReportKind;
  from: number; // ms
  to: number; // ms
  requestedBy: string; // '' = pianificazione
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const ROLE_LABELS: Record<string, string> = { admin: "Amministratore", analyst: "Analista", viewer: "Visualizzatore" };
const dayKey = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" });
const dayLabel = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, weekday: "short", day: "numeric" });
const dayNum = new Intl.DateTimeFormat("it-IT", { timeZone: TZ, day: "numeric" });

const sum = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0);
const serious = (o: Record<string, number>) => (o.critical ?? 0) + (o.high ?? 0);
const sev = (s: string) => SEVERITY_LABELS[s] ?? s;
const ago = (d: Date | null) => (d ? fmtDateTime(d) : "mai");
/** Singolare o plurale; nel plurale "#" diventa il numero. */
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many.replace("#", fmtNum(n)));

/** "+12% rispetto al periodo precedente" (o niente, se prima non c'era nulla da confrontare). */
function delta(now: number, before: number) {
  if (!before) return now ? "nessun dato nel periodo precedente" : "";
  const pct = ((now - before) / before) * 100;
  if (Math.abs(pct) < 1) return "stabile rispetto al periodo precedente";
  return `${pct > 0 ? "+" : "-"}${fmtPct(Math.abs(pct))} rispetto al periodo precedente`;
}

/** Giorni del periodo, ora locale. */
function days(p: data.Period) {
  const out: { key: string; label: string }[] = [];
  const many = (p.t1 - p.t0) / 86400 > 14;
  for (let t = localMidnight(p.t0 * 1000); t < p.t1 * 1000; t = localMidnight(t, 1)) {
    const d = new Date(t + 3600_000); // dentro il giorno anche nei cambi d'ora
    out.push({ key: dayKey.format(d), label: many ? dayNum.format(d) : dayLabel.format(d) });
    if (out.length > 62) break;
  }
  return out;
}

function periodText(input: ReportInput) {
  return `Periodo: ${fmtDay(input.from)} – ${fmtDay(input.to - 1)}`;
}

function coverLines(input: ReportInput) {
  return [
    `Dal ${fmtDateTime(input.from)} al ${fmtDateTime(input.to)} (fuso ${TZ})`,
    `Generato il ${fmtDateTime(Date.now())} ${input.requestedBy ? `su richiesta di ${input.requestedBy}` : "dalla pianificazione settimanale"}`,
  ];
}

function alertChart(r: ReportDoc, p: data.Period, daily: Awaited<ReturnType<typeof data.alertsDaily>>) {
  const ds = days(p);
  const idx = new Map(ds.map((d, i) => [d.key, i]));
  const series = SEVERITIES.map((s) => ({ label: sev(s), color: SEVERITY_COLORS[s], values: ds.map(() => 0) }));
  for (const row of daily) {
    const i = idx.get(row.day);
    const k = SEVERITIES.indexOf(row.severity as (typeof SEVERITIES)[number]);
    if (i !== undefined && k >= 0) series[k].values[i] += row.n;
  }
  r.bars(ds.map((d) => d.label), series.filter((s) => s.values.some(Boolean)), (v) => fmtNum(Math.round(v)));
}

function trafficChart(r: ReportDoc, p: data.Period, t: data.TrafficData) {
  const ds = days(p);
  const byDay = new Map(t.daily.map((d) => [d.day, d]));
  r.bars(
    ds.map((d) => d.label),
    [
      { label: "Da internet", color: "#0891b2", values: ds.map((d) => byDay.get(d.key)?.inB ?? 0) },
      { label: "Verso internet", color: "#7c3aed", values: ds.map((d) => byDay.get(d.key)?.outB ?? 0) },
    ],
    (v) => fmtBytes(v),
  );
}

function sensorState(s: { enabled: boolean; last_seen: Date | null }) {
  if (!s.enabled) return "disattivato";
  if (!s.last_seen) return "mai collegato";
  return Date.now() - new Date(s.last_seen).getTime() < 3 * 60_000 ? "in linea" : `non risponde da ${fmtDuration((Date.now() - new Date(s.last_seen).getTime()) / 1000)}`;
}

// ------------------------------------------------------------------------- direzione

async function executive(input: ReportInput, p: data.Period) {
  const prev = { t0: p.t0 - (p.t1 - p.t0), t1: p.t0 };
  const [bySev, prevSev, openSev, daily, inc, incList, dev, prevDev, risky, sensors, users, traffic, prevTraffic, exposed, supp] = await Promise.all([
    data.alertsBySeverity(p),
    data.alertsBySeverity(prev),
    data.openAlertsBySeverity(),
    data.alertsDaily(p),
    data.incidentCounts(p),
    data.incidents(p, 8),
    data.deviceCounts(p),
    data.deviceCounts(prev),
    data.riskiestSources(p, 6),
    data.sensors(),
    data.users(),
    data.traffic(p, false),
    data.trafficTotalsFor(prev).catch(() => null),
    data.exposedServices(500),
    data.activeSuppressions(),
  ]);
  const enabledSensors = sensors.filter((s) => s.enabled);
  const offline = enabledSensors.filter((s) => sensorState(s) !== "in linea");
  const unapproved = dev.total - dev.approved;
  const internet = traffic.totals.inB + traffic.totals.outB;
  const noMfa = users.filter((u) => !u.disabled && !u.mfa);

  const r = new ReportDoc(REPORT_KINDS.executive.title, periodText(input));
  r.cover(periodText(input), coverLines(input));

  r.h1("In sintesi");
  const summary: string[] = [];
  summary.push(
    sum(bySev)
      ? `${fmtNum(sum(bySev))} allarmi nel periodo (${delta(sum(bySev), sum(prevSev))}), di cui ${fmtNum(serious(bySev))} critici o gravi.`
      : "Nessun allarme nel periodo.",
  );
  summary.push(
    `Incidenti nel periodo: ${fmtNum(inc.opened)} aperti, ${fmtNum(inc.closed)} chiusi. Oggi ancora aperti: ${fmtNum(inc.open_now)}${inc.serious_open ? `, di cui ${fmtNum(inc.serious_open)} critici o gravi` : ""}.`,
  );
  summary.push(`${fmtNum(dev.new_in_period)} dispositivi comparsi per la prima volta; ${fmtNum(unapproved)} dispositivi in rete non sono ancora stati approvati.`);
  if (traffic.ok) summary.push(`Traffico con internet: ${fmtBytes(internet)}${prevTraffic && delta(internet, prevTraffic.inB + prevTraffic.outB) ? ` (${delta(internet, prevTraffic.inB + prevTraffic.outB)})` : ""}.`);
  else summary.push("Dati di traffico non disponibili: ClickHouse non ha risposto durante la generazione.");
  summary.push(
    enabledSensors.length === 0
      ? "Nessun sensore attivo: la rete non è osservata."
      : offline.length
        ? `${offline.length} sensori su ${enabledSensors.length} non comunicano: parte della rete non è osservata.`
        : `Tutti i ${enabledSensors.length} sensori comunicano con l'hub.`,
  );
  r.bullets(summary);

  const openSerious = serious(openSev);
  const kpis: Kpi[] = [
    { label: "Allarmi critici o gravi", value: fmtNum(serious(bySev)), note: delta(serious(bySev), serious(prevSev)), tone: serious(bySev) ? "warn" : "ok" },
    { label: "Ancora aperti (gravi)", value: fmtNum(openSerious), note: "allarmi critici o gravi non chiusi", tone: openSerious ? "bad" : "ok" },
    { label: "Incidenti aperti", value: fmtNum(inc.open_now), note: `${fmtNum(inc.opened)} nuovi nel periodo`, tone: inc.serious_open ? "bad" : undefined },
    { label: "Dispositivi nuovi", value: fmtNum(dev.new_in_period), note: delta(dev.new_in_period, prevDev.new_in_period) },
    { label: "Da approvare", value: fmtNum(unapproved), note: `su ${fmtNum(dev.total)} dispositivi`, tone: unapproved ? "warn" : "ok" },
    { label: "Traffico internet", value: traffic.ok ? fmtBytes(internet) : "—", note: traffic.ok ? `${fmtBytes(traffic.totals.inB)} in · ${fmtBytes(traffic.totals.outB)} out` : "non disponibile" },
  ];
  r.kpis(kpis);

  r.h2("Allarmi al giorno");
  if (sum(bySev)) alertChart(r, p, daily);
  else r.p("Nessun allarme nel periodo.", { muted: true });

  if (traffic.ok && internet > 0) {
    r.h2("Traffico con internet al giorno");
    trafficChart(r, p, traffic);
  }

  r.h1("Incidenti");
  r.table(
    [
      { label: "N.", width: 0.07 },
      { label: "Incidente", width: 0.42 },
      { label: "Gravità", width: 0.11 },
      { label: "Stato", width: 0.14 },
      { label: "Allarmi", width: 0.1, align: "right" },
      { label: "Da", width: 0.16 },
    ],
    incList.map((i) => [String(i.id), i.title, sev(i.severity), INCIDENT_STATUS_LABELS[i.status] ?? i.status, fmtNum(i.alert_count), fmtDay(i.first_seen)]),
    { empty: "Nessun incidente aperto o chiuso nel periodo." },
  );

  r.h2("Indirizzi con più allarmi gravi");
  r.table(
    [
      { label: "Indirizzo", width: 0.25 },
      { label: "Dispositivo", width: 0.35 },
      { label: "Critici", width: 0.13, align: "right" },
      { label: "Gravi", width: 0.13, align: "right" },
      { label: "Totale", width: 0.14, align: "right" },
    ],
    risky.filter((x) => x.critical + x.high > 0).map((x) => [x.ip, x.name, fmtNum(x.critical), fmtNum(x.high), fmtNum(x.n)]),
    { empty: "Nessun allarme critico o grave nel periodo." },
  );

  r.h1("Cosa serve fare");
  const todo: string[] = [];
  if (openSev.critical) todo.push(`Chiudere o assegnare i ${fmtNum(openSev.critical)} allarmi critici ancora aperti.`);
  if (inc.serious_open) todo.push(`Seguire i ${fmtNum(inc.serious_open)} incidenti critici o gravi aperti e valutare se vanno notificati (NIS2, art. 23).`);
  if (unapproved) todo.push(`Verificare e approvare (o togliere dalla rete) i ${fmtNum(unapproved)} dispositivi non approvati.`);
  if (offline.length) todo.push(`Ripristinare i sensori che non comunicano: ${offline.map((s) => s.name).join(", ")}.`);
  if (noMfa.length) todo.push(`Attivare la verifica in due passaggi per ${noMfa.length === 1 ? "l'utente che non la usa" : `i ${noMfa.length} utenti che non la usano`}: ${noMfa.map((u) => u.username).join(", ")}.`);
  if (exposed.length) todo.push(`Controllare che i ${fmtNum(exposed.length)} servizi interni raggiungibili da internet siano tutti voluti.`);
  const forever = supp.filter((s) => !s.expires_at).length;
  if (forever) todo.push(`Rivedere ${plural(forever, "l'eccezione senza scadenza: nasconde", "le # eccezioni senza scadenza: nascondono")} allarmi a tempo indeterminato.`);
  if (todo.length) r.bullets(todo, "warn");
  else r.p("Nessuna azione urgente: niente allarmi critici aperti, dispositivi tutti approvati, sensori in linea.");

  return r.finish();
}

// --------------------------------------------------------------------------- tecnico

async function technical(input: ReportInput, p: data.Period) {
  const [bySev, daily, byRule, top, times, incList, traffic, newDev, exposed, sensors, rules, disabled, supp, feeds] = await Promise.all([
    data.alertsBySeverity(p),
    data.alertsDaily(p),
    data.alertsByRule(p),
    data.topAlerts(p, 30),
    data.resolutionTimes(p),
    data.incidents(p, 40),
    data.traffic(p, true),
    data.newDevicesIn(p, 40),
    data.exposedServices(40),
    data.sensors(),
    data.ruleCounts(),
    data.disabledRules(),
    data.activeSuppressions(),
    data.intelFeeds(),
  ]);

  const r = new ReportDoc(REPORT_KINDS.technical.title, periodText(input));
  r.cover(periodText(input), coverLines(input));

  r.h1("Allarmi");
  r.kpis(SEVERITIES.filter((s) => s !== "info" || bySev.info).map((s) => ({ label: sev(s), value: fmtNum(bySev[s] ?? 0) })));
  if (sum(bySev)) alertChart(r, p, daily);

  r.h2("Per regola");
  r.table(
    [
      { label: "Regola", width: 0.42 },
      { label: "Categoria", width: 0.16 },
      { label: "Gravità max", width: 0.13 },
      { label: "Allarmi", width: 0.1, align: "right" },
      { label: "Aperti", width: 0.09, align: "right" },
      { label: "Origini", width: 0.1, align: "right" },
    ],
    byRule.map((x) => [x.name, x.category, sev(x.severity), fmtNum(x.n), fmtNum(x.open), fmtNum(x.sources)]),
  );

  r.h2("Allarmi più importanti");
  r.table(
    [
      { label: "N.", width: 0.07 },
      { label: "Gravità", width: 0.1 },
      { label: "Allarme", width: 0.37 },
      { label: "Origine", width: 0.15 },
      { label: "Destinazione", width: 0.15 },
      { label: "Volte", width: 0.07, align: "right" },
      { label: "Stato", width: 0.09 },
    ],
    top.map((a) => [String(a.id), sev(a.severity), a.title, a.src_ip, a.dst_ip, fmtNum(a.count), STATUS_LABELS[a.status] ?? a.status]),
  );

  r.h2("Tempi di chiusura");
  r.p("Tempo dalla prima segnalazione alla chiusura, per gli allarmi chiusi nel periodo.", { muted: true, size: 9 });
  r.table(
    [
      { label: "Gravità", width: 0.3 },
      { label: "Chiusi", width: 0.2, align: "right" },
      { label: "Mediana", width: 0.25, align: "right" },
      { label: "90% entro", width: 0.25, align: "right" },
    ],
    times.map((t) => [sev(t.severity), fmtNum(t.n), fmtDuration(t.median), fmtDuration(t.p90)]),
    { empty: "Nessun allarme chiuso nel periodo." },
  );

  r.h1("Incidenti");
  r.table(
    [
      { label: "N.", width: 0.07 },
      { label: "Incidente", width: 0.35 },
      { label: "Gravità", width: 0.1 },
      { label: "Stato", width: 0.12 },
      { label: "Allarmi", width: 0.09, align: "right" },
      { label: "Assegnato a", width: 0.13 },
      { label: "Chiuso", width: 0.14 },
    ],
    incList.map((i) => [String(i.id), i.title, sev(i.severity), INCIDENT_STATUS_LABELS[i.status] ?? i.status, fmtNum(i.alert_count), i.assignee, i.closed_at ? fmtDay(i.closed_at) : ""]),
    { empty: "Nessun incidente nel periodo." },
  );

  r.h1("Traffico");
  if (!traffic.ok) {
    r.p("Dati di traffico non disponibili: ClickHouse non ha risposto durante la generazione.", { muted: true });
  } else if (traffic.totals.flows === 0) {
    r.p("Nessun traffico registrato nel periodo.", { muted: true });
  } else {
    r.kpis([
      { label: "Da internet", value: fmtBytes(traffic.totals.inB) },
      { label: "Verso internet", value: fmtBytes(traffic.totals.outB) },
      { label: "Interno", value: fmtBytes(traffic.totals.intB), note: `${fmtNum(traffic.totals.flows)} flussi in tutto` },
    ]);
    if (traffic.daily.length) trafficChart(r, p, traffic);
    r.h2("Applicazioni");
    r.table(
      [
        { label: "Applicazione", width: 0.5 },
        { label: "Dati", width: 0.25, align: "right" },
        { label: "Flussi", width: 0.25, align: "right" },
      ],
      traffic.apps.map((a) => [a.app, fmtBytes(a.bytes), fmtNum(a.flows)]),
    );
    r.h2("Paesi");
    r.table(
      [
        { label: "Paese", width: 0.5 },
        { label: "Dati", width: 0.25, align: "right" },
        { label: "Flussi", width: 0.25, align: "right" },
      ],
      traffic.countries.map((c) => [countryName(c.country), fmtBytes(c.bytes), fmtNum(c.flows)]),
    );
    r.h2("Host interni con più traffico");
    r.table(
      [
        { label: "Indirizzo", width: 0.34 },
        { label: "Inviati", width: 0.22, align: "right" },
        { label: "Ricevuti", width: 0.22, align: "right" },
        { label: "Flussi", width: 0.22, align: "right" },
      ],
      traffic.hosts.map((h) => [h.ip, fmtBytes(h.sent), fmtBytes(h.recv), fmtNum(h.flows)]),
    );
    r.h2("Destinazioni su internet");
    r.table(
      [
        { label: "Indirizzo", width: 0.18 },
        { label: "Dominio", width: 0.3 },
        { label: "Organizzazione", width: 0.22 },
        { label: "Paese", width: 0.08 },
        { label: "Dati", width: 0.12, align: "right" },
        { label: "Client", width: 0.1, align: "right" },
      ],
      traffic.destinations.map((d) => [d.ip, d.domain, d.org, d.country, fmtBytes(d.bytes), fmtNum(d.clients)]),
      { empty: "Nessun dato (i flussi grezzi si conservano per HW_RETENTION_DAYS giorni)." },
    );
    r.h2("Porte e servizi più usati");
    r.table(
      [
        { label: "Protocollo", width: 0.15 },
        { label: "Porta", width: 0.15, align: "right" },
        { label: "Applicazione", width: 0.3 },
        { label: "Connessioni", width: 0.2, align: "right" },
        { label: "Dati", width: 0.2, align: "right" },
      ],
      traffic.ports.map((x) => [x.proto, String(x.port), x.app, fmtNum(x.flows), fmtBytes(x.bytes)]),
      { empty: "Nessun dato (i flussi grezzi si conservano per HW_RETENTION_DAYS giorni)." },
    );
  }

  r.h1("Dispositivi");
  r.h2("Comparsi nel periodo");
  r.table(
    [
      { label: "Indirizzo", width: 0.14 },
      { label: "MAC", width: 0.18 },
      { label: "Nome", width: 0.2 },
      { label: "Produttore", width: 0.13 },
      { label: "Tipo", width: 0.12 },
      { label: "Visto dal", width: 0.13 },
      { label: "Approvato", width: 0.1 },
    ],
    newDev.map((d) => [d.ip, d.mac, d.name, d.vendor, d.type, fmtDateTime(d.first_seen), d.approved ? "sì" : "no"]),
    { empty: "Nessun dispositivo nuovo nel periodo." },
  );
  r.h2("Servizi raggiungibili da internet");
  r.table(
    [
      { label: "Indirizzo", width: 0.17 },
      { label: "Dispositivo", width: 0.25 },
      { label: "Servizio", width: 0.2 },
      { label: "Dal", width: 0.14 },
      { label: "Ultimo uso", width: 0.14 },
      { label: "Flussi", width: 0.1, align: "right" },
    ],
    exposed.map((s) => [s.ip, s.name, `${s.proto} ${s.port}${s.app ? ` · ${s.app}` : ""}`, fmtDay(s.first_seen), fmtDay(s.last_seen), fmtNum(s.flows)]),
    { empty: "Nessun servizio interno raggiunto da internet." },
  );

  r.h1("Sensori");
  r.table(
    [
      { label: "Sensore", width: 0.18 },
      { label: "Sede", width: 0.14 },
      { label: "Modalità", width: 0.12 },
      { label: "Stato", width: 0.24 },
      { label: "Versione", width: 0.12 },
      { label: "Record", width: 0.1, align: "right" },
      { label: "Persi", width: 0.1, align: "right" },
    ],
    sensors.map((s) => [s.name, s.site, s.mode, sensorState(s), s.version, fmtNum(s.records), fmtNum(s.drops)]),
    { empty: "Nessun sensore registrato." },
  );

  r.h1("Regole ed eccezioni");
  r.p(`${fmtNum(rules.enabled)} regole attive su ${fmtNum(rules.total)}, più ${fmtNum(rules.custom)} regole personalizzate.`);
  if (disabled.length) {
    r.h2("Regole disattivate");
    r.table(
      [
        { label: "Regola", width: 0.5 },
        { label: "Disattivata da", width: 0.25 },
        { label: "Il", width: 0.25 },
      ],
      disabled.map((x) => [x.name, x.updated_by, fmtDateTime(x.updated_at)]),
    );
  }
  r.h2("Eccezioni attive");
  r.table(
    [
      { label: "Regola", width: 0.2 },
      { label: "Origine", width: 0.14 },
      { label: "Destinazione", width: 0.14 },
      { label: "Motivo", width: 0.26 },
      { label: "Scadenza", width: 0.14 },
      { label: "Usata", width: 0.12, align: "right" },
    ],
    supp.map((s) => [s.rule, s.src || "qualsiasi", s.dst || "qualsiasi", `${s.reason} (${s.created_by})`, s.expires_at ? fmtDay(s.expires_at) : "nessuna", fmtNum(s.hits)]),
    { empty: "Nessuna eccezione attiva." },
  );

  if (feeds.length) {
    r.h2("Elenchi di minacce note");
    r.table(
      [
        { label: "Elenco", width: 0.36 },
        { label: "Stato", width: 0.14 },
        { label: "Voci", width: 0.14, align: "right" },
        { label: "Aggiornato", width: 0.18 },
        { label: "Errore", width: 0.18 },
      ],
      feeds.map((f) => [f.name, f.enabled ? "attivo" : "spento", fmtNum(f.entries), ago(f.last_ok), f.last_error]),
    );
  }
  return r.finish();
}

// ------------------------------------------------------------------------ conformità

async function compliance(input: ReportInput, p: data.Period) {
  const [dev, byType, unapproved, newDev, sensors, rules, disabled, supp, inc, incList, times, users, tokens, audits, privileged, logins, pcaps, exposed, feeds, net, bySev] =
    await Promise.all([
      data.deviceCounts(p),
      data.devicesByType(),
      data.unapprovedDevices(30),
      data.newDevicesIn(p, 30),
      data.sensors(),
      data.ruleCounts(),
      data.disabledRules(),
      data.activeSuppressions(),
      data.incidentCounts(p),
      data.incidents(p, 40),
      data.resolutionTimes(p),
      data.users(),
      data.apiTokens(),
      data.auditCounts(p),
      data.privilegedActions(p, 80),
      data.failedLogins(p),
      data.pcapRequests(p),
      data.exposedServices(60),
      data.intelFeeds(),
      data.networkConfig(),
      data.alertsBySeverity(p),
    ]);
  const active = users.filter((u) => !u.disabled);
  const withMfa = active.filter((u) => u.mfa).length;
  const inactive = active.filter((u) => !u.last_login || Date.now() - new Date(u.last_login).getTime() > 90 * 86400_000);
  const enabledSensors = sensors.filter((s) => s.enabled);
  const sensorsOk = enabledSensors.filter((s) => sensorState(s) === "in linea").length;
  const approvedPct = dev.total ? (dev.approved / dev.total) * 100 : 100;
  const forever = supp.filter((s) => !s.expires_at);
  const seriousIncidents = incList.filter((i) => i.severity === "critical" || i.severity === "high");
  const env = (k: string, d: string) => process.env[k] || d;

  const r = new ReportDoc(REPORT_KINDS.compliance.title, periodText(input));
  r.cover(periodText(input), coverLines(input));
  r.p(
    "Questo documento raccoglie le evidenze tecniche prodotte da Hyperwave nel periodo, ordinate secondo le misure di gestione dei rischi dell'art. 21 della direttiva (UE) 2022/2555 (NIS2) e i controlli dell'allegato A della norma ISO/IEC 27001:2022.",
  );
  r.p(
    "Non è un'attestazione di conformità: copre solo ciò che si osserva dalla rete e dalla configurazione di Hyperwave, e va valutato insieme alle politiche, alle procedure e agli altri documenti dell'organizzazione.",
    { muted: true, size: 9 },
  );

  r.h1("Quadro d'insieme");
  const ok = "Evidenza presente";
  const check = "Da verificare";
  r.table(
    [
      { label: "Area", width: 0.24 },
      { label: "Riferimenti", width: 0.22 },
      { label: "Evidenza nel periodo", width: 0.38 },
      { label: "Esito", width: 0.16 },
    ],
    [
      ["1. Inventario dei dispositivi", "NIS2 21(2)(i) · ISO A.5.9", `${fmtNum(dev.total)} dispositivi, ${fmtPct(approvedPct)} approvati, ${fmtNum(dev.new_in_period)} nuovi`, dev.total > 0 && approvedPct >= 95 ? ok : check],
      ["2. Monitoraggio della rete", "NIS2 21(2)(b) · ISO A.8.16", `${sensorsOk} sensori in linea su ${enabledSensors.length}; ${fmtNum(rules.enabled)} regole attive`, enabledSensors.length && sensorsOk === enabledSensors.length ? ok : check],
      ["3. Registrazione degli eventi", "ISO A.8.15", `Flussi per ${env("HW_RETENTION_DAYS", "30")} giorni, aggregati per ${env("HW_AGG_RETENTION_DAYS", "400")}, registro attività per ${env("HW_AUDIT_RETENTION_DAYS", "730")}`, ok],
      ["4. Gestione degli incidenti", "NIS2 21(2)(b), art. 23 · ISO A.5.24-A.5.26", `${fmtNum(sum(bySev))} allarmi, ${fmtNum(inc.opened)} incidenti aperti e ${fmtNum(inc.closed)} chiusi`, inc.serious_open ? check : ok],
      ["5. Accessi e autenticazione", "NIS2 21(2)(i)(j) · ISO A.5.15, A.5.18, A.8.5", `${withMfa} utenti attivi su ${active.length} con 2FA; ${tokens.length} token API attivi`, withMfa === active.length && active.length ? ok : check],
      ["6. Sicurezza della rete", "ISO A.8.20, A.8.22", `${fmtNum(exposed.length)} servizi interni raggiunti da internet`, exposed.length ? check : ok],
      ["7. Informazioni sulle minacce", "ISO A.5.7", `${feeds.filter((f) => f.enabled).length} elenchi di minacce attivi`, feeds.some((f) => f.enabled) ? ok : check],
      ["8. Attività privilegiate", "ISO A.8.2, A.8.15 · A.5.28", `${fmtNum(privileged.length)} operazioni amministrative, ${fmtNum(pcaps.length)} estrazioni di pacchetti`, ok],
    ],
  );

  r.h1("1. Inventario dei dispositivi");
  r.ref("NIS2 art. 21(2)(i) gestione degli attivi · ISO/IEC 27001:2022 A.5.9 Inventario delle informazioni e degli altri beni associati");
  r.p(
    `Hyperwave riconosce i dispositivi dal traffico osservato. Nel periodo erano attivi ${fmtNum(dev.active)} dispositivi su ${fmtNum(dev.total)} conosciuti; ${fmtNum(dev.approved)} sono stati approvati e ${fmtNum(dev.critical)} sono classificati come critici o importanti.`,
  );
  r.table(
    [
      { label: "Tipo", width: 0.5 },
      { label: "Dispositivi", width: 0.25, align: "right" },
      { label: "Approvati", width: 0.25, align: "right" },
    ],
    byType.map((t) => [t.type, fmtNum(t.n), fmtNum(t.approved)]),
    { empty: "Nessun dispositivo conosciuto: senza sensori attivi l'inventario resta vuoto." },
  );
  r.h2("Dispositivi non approvati");
  r.table(
    [
      { label: "Indirizzo", width: 0.17 },
      { label: "MAC", width: 0.2 },
      { label: "Nome", width: 0.23 },
      { label: "Produttore", width: 0.2 },
      { label: "Ultima attività", width: 0.2 },
    ],
    unapproved.map((d) => [d.ip, d.mac, d.name, d.vendor, fmtDateTime(d.last_seen)]),
    { empty: "Tutti i dispositivi sono approvati." },
  );
  r.h2("Dispositivi comparsi nel periodo");
  r.table(
    [
      { label: "Indirizzo", width: 0.17 },
      { label: "MAC", width: 0.2 },
      { label: "Nome", width: 0.23 },
      { label: "Produttore", width: 0.2 },
      { label: "Visto dal", width: 0.2 },
    ],
    newDev.map((d) => [d.ip, d.mac, d.name, d.vendor, fmtDateTime(d.first_seen)]),
    { empty: "Nessun dispositivo nuovo nel periodo." },
  );

  r.h1("2. Monitoraggio della rete");
  r.ref("NIS2 art. 21(2)(b) gestione degli incidenti · ISO/IEC 27001:2022 A.8.16 Attività di monitoraggio");
  r.table(
    [
      { label: "Sensore", width: 0.2 },
      { label: "Sede", width: 0.16 },
      { label: "Modalità", width: 0.14 },
      { label: "Stato", width: 0.3 },
      { label: "Record ricevuti", width: 0.2, align: "right" },
    ],
    sensors.map((s) => [s.name, s.site, s.mode, sensorState(s), fmtNum(s.records)]),
    { empty: "Nessun sensore registrato: la rete non è osservata." },
  );
  r.p(`Regole di rilevamento: ${fmtNum(rules.enabled)} attive su ${fmtNum(rules.total)}, più ${fmtNum(rules.custom)} personalizzate.`);
  if (disabled.length) {
    r.h2("Regole disattivate");
    r.table(
      [
        { label: "Regola", width: 0.5 },
        { label: "Da", width: 0.25 },
        { label: "Il", width: 0.25 },
      ],
      disabled.map((x) => [x.name, x.updated_by, fmtDateTime(x.updated_at)]),
    );
  }
  r.h2("Eccezioni attive");
  r.p(
    forever.length
      ? `${forever.length} eccezioni non hanno scadenza: vanno riviste periodicamente perché nascondono allarmi a tempo indeterminato.`
      : "Tutte le eccezioni attive hanno una scadenza.",
    { muted: true, size: 9 },
  );
  r.table(
    [
      { label: "Regola", width: 0.2 },
      { label: "Origine", width: 0.15 },
      { label: "Destinazione", width: 0.15 },
      { label: "Motivo e autore", width: 0.3 },
      { label: "Scadenza", width: 0.2 },
    ],
    supp.map((s) => [s.rule, s.src || "qualsiasi", s.dst || "qualsiasi", `${s.reason} (${s.created_by}, ${fmtDay(s.created_at)})`, s.expires_at ? fmtDay(s.expires_at) : "nessuna"]),
    { empty: "Nessuna eccezione attiva." },
  );

  r.h1("3. Registrazione degli eventi");
  r.ref("ISO/IEC 27001:2022 A.8.15 Registrazione · A.8.17 Sincronizzazione degli orologi");
  r.bullets([
    `Flussi di rete, DNS, TLS, HTTP ed eventi IDS: conservati ${env("HW_RETENTION_DAYS", "30")} giorni (ClickHouse).`,
    `Aggregati di traffico e servizi dei dispositivi: ${env("HW_AGG_RETENTION_DAYS", "400")} giorni.`,
    `Registro delle attività degli utenti: ${env("HW_AUDIT_RETENTION_DAYS", "730")} giorni (PostgreSQL).`,
    `Orari registrati in UTC e mostrati nel fuso ${TZ}; la sincronizzazione degli orologi di hub e sensori (NTP) va verificata sui server.`,
  ]);
  r.h2("Eventi del registro nel periodo");
  r.table(
    [
      { label: "Attività", width: 0.5 },
      { label: "Codice", width: 0.24 },
      { label: "Volte", width: 0.13, align: "right" },
      { label: "Utenti", width: 0.13, align: "right" },
    ],
    audits.slice(0, 40).map((a) => [AUDIT_LABELS[a.action] ?? a.action, a.action, fmtNum(a.n), fmtNum(a.users)]),
    { empty: "Nessuna attività registrata nel periodo." },
  );

  r.h1("4. Gestione degli incidenti");
  r.ref("NIS2 art. 21(2)(b) e art. 23 obblighi di segnalazione · ISO/IEC 27001:2022 A.5.24, A.5.25, A.5.26");
  r.p(
    `Nel periodo il motore di rilevamento ha generato ${fmtNum(sum(bySev))} allarmi (${fmtNum(serious(bySev))} critici o gravi), raggruppati in incidenti: ${fmtNum(inc.opened)} aperti e ${fmtNum(inc.closed)} chiusi. Oggi restano aperti ${fmtNum(inc.open_now)} incidenti.`,
  );
  r.table(
    [
      { label: "Gravità", width: 0.3 },
      { label: "Allarmi chiusi", width: 0.2, align: "right" },
      { label: "Tempo mediano", width: 0.25, align: "right" },
      { label: "90% entro", width: 0.25, align: "right" },
    ],
    times.map((t) => [sev(t.severity), fmtNum(t.n), fmtDuration(t.median), fmtDuration(t.p90)]),
    { empty: "Nessun allarme chiuso nel periodo." },
  );
  r.h2("Incidenti critici o gravi");
  r.p(
    "Per gli incidenti significativi la NIS2 prevede un preallarme al CSIRT entro 24 ore, una notifica entro 72 ore e una relazione finale entro un mese. Hyperwave non decide se un incidente è significativo: l'elenco serve per la valutazione.",
    { muted: true, size: 9 },
  );
  r.table(
    [
      { label: "N.", width: 0.07 },
      { label: "Incidente", width: 0.41 },
      { label: "Gravità", width: 0.11 },
      { label: "Stato", width: 0.13 },
      { label: "Inizio", width: 0.14 },
      { label: "Chiuso", width: 0.14 },
    ],
    seriousIncidents.map((i) => [String(i.id), i.title, sev(i.severity), INCIDENT_STATUS_LABELS[i.status] ?? i.status, fmtDateTime(i.first_seen), i.closed_at ? fmtDateTime(i.closed_at) : ""]),
    { empty: "Nessun incidente critico o grave nel periodo." },
  );

  r.h1("5. Accessi e autenticazione");
  r.ref("NIS2 art. 21(2)(i) controllo degli accessi e (j) autenticazione a più fattori · ISO/IEC 27001:2022 A.5.15, A.5.18, A.8.5");
  r.p(
    `Utenti attivi: ${active.length}, di cui con verifica in due passaggi (TOTP): ${withMfa}. Nel periodo: ${fmtNum(logins.n)} accessi non riusciti e ${fmtNum(logins.locked)} accessi bloccati per troppi tentativi.`,
  );
  r.table(
    [
      { label: "Utente", width: 0.22 },
      { label: "Ruolo", width: 0.18 },
      { label: "2FA", width: 0.1 },
      { label: "Stato", width: 0.14 },
      { label: "Ultimo accesso", width: 0.2 },
      { label: "Creato", width: 0.16 },
    ],
    users.map((u) => [u.username, ROLE_LABELS[u.role] ?? u.role, u.mfa ? "sì" : "no", u.disabled ? "disattivato" : "attivo", ago(u.last_login), fmtDay(u.created_at)]),
  );
  if (inactive.length) r.p(`Utenti attivi senza accessi da oltre 90 giorni (da valutare la disattivazione): ${inactive.map((u) => u.username).join(", ")}.`, { size: 9 });
  r.h2("Token API attivi");
  r.table(
    [
      { label: "Nome", width: 0.28 },
      { label: "Ruolo", width: 0.17 },
      { label: "Creato da", width: 0.17 },
      { label: "Scadenza", width: 0.19 },
      { label: "Ultimo uso", width: 0.19 },
    ],
    tokens.map((t) => [t.name, ROLE_LABELS[t.role] ?? t.role, t.created_by, t.expires_at ? fmtDay(t.expires_at) : "nessuna", ago(t.last_used)]),
    { empty: "Nessun token API attivo." },
  );

  r.h1("6. Sicurezza della rete");
  r.ref("ISO/IEC 27001:2022 A.8.20 Sicurezza delle reti · A.8.22 Segregazione delle reti");
  r.bullets([
    `Reti interne configurate: ${net.internal_nets ? net.internal_nets.split(",").join(", ") : "valore di .env o reti private standard"}.`,
    `Reti sensibili: ${net.sensitive_nets ? net.sensitive_nets.split(",").join(", ") : "nessuna indicata"}.`,
  ]);
  r.h2("Servizi interni raggiunti da internet");
  r.table(
    [
      { label: "Indirizzo", width: 0.17 },
      { label: "Dispositivo", width: 0.27 },
      { label: "Servizio", width: 0.22 },
      { label: "Dal", width: 0.17 },
      { label: "Ultimo uso", width: 0.17 },
    ],
    exposed.map((s) => [s.ip, s.name, `${s.proto} ${s.port}${s.app ? ` · ${s.app}` : ""}`, fmtDay(s.first_seen), fmtDay(s.last_seen)]),
    { empty: "Nessun servizio interno raggiunto da internet." },
  );

  r.h1("7. Informazioni sulle minacce");
  r.ref("ISO/IEC 27001:2022 A.5.7 Intelligence sulle minacce");
  r.table(
    [
      { label: "Elenco", width: 0.4 },
      { label: "Stato", width: 0.14 },
      { label: "Voci", width: 0.16, align: "right" },
      { label: "Ultimo aggiornamento", width: 0.3 },
    ],
    feeds.map((f) => [f.name, f.enabled ? "attivo" : "spento", fmtNum(f.entries), ago(f.last_ok)]),
    { empty: "Nessun elenco di minacce configurato." },
  );

  r.h1("8. Attività privilegiate");
  r.ref("ISO/IEC 27001:2022 A.8.2 Diritti di accesso privilegiato · A.8.15 Registrazione · A.5.28 Raccolta delle evidenze");
  r.table(
    [
      { label: "Quando", width: 0.18 },
      { label: "Utente", width: 0.14 },
      { label: "Attività", width: 0.3 },
      { label: "Oggetto", width: 0.24 },
      { label: "Indirizzo", width: 0.14 },
    ],
    privileged.map((a) => [fmtDateTime(a.ts), a.username, AUDIT_LABELS[a.action] ?? a.action, a.target, a.ip]),
    { empty: "Nessuna operazione amministrativa nel periodo." },
  );
  r.h2("Estrazioni di pacchetti");
  r.table(
    [
      { label: "N.", width: 0.07 },
      { label: "Quando", width: 0.17 },
      { label: "Utente", width: 0.13 },
      { label: "Conversazione", width: 0.25 },
      { label: "Motivo", width: 0.28 },
      { label: "Esito", width: 0.1 },
    ],
    pcaps.map((x) => [String(x.id), fmtDateTime(x.created_at), x.requested_by, x.ip_b ? `${x.ip_a} - ${x.ip_b}` : x.ip_a, x.reason, x.status]),
    { empty: "Nessuna estrazione di pacchetti nel periodo." },
  );

  r.h1("Revisione");
  r.p("Spazio per chi esamina il documento.", { muted: true, size: 9 });
  r.signature(["Esaminato da", "Ruolo", "Data", "Osservazioni"]);
  return r.finish();
}

/** Crea il PDF di un rapporto. */
export async function buildReport(input: ReportInput): Promise<{ pdf: Buffer; pages: number }> {
  const p = { t0: Math.floor(input.from / 1000), t1: Math.floor(input.to / 1000) };
  if (input.kind === "executive") return executive(input, p);
  if (input.kind === "technical") return technical(input, p);
  return compliance(input, p);
}
