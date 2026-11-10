package hub

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"hyperwave/internal/chx"
)

// catalog elenca tutte le regole. Gli ID non vanno cambiati: sono salvati negli allarmi.
func catalog() []*RuleDef {
	return append(baseCatalog(), protoCatalog()...)
}

func baseCatalog() []*RuleDef {
	return []*RuleDef{
		{
			ID: "portscan", Name: "Scansione di porte", Category: "Ricognizione", Severity: "high", Mitre: "T1046",
			Description: "Un host prova molte porte diverse su uno stesso indirizzo in pochi minuti.",
			Params:      params{"min_ports": 25}, Help: map[string]string{"min_ports": "Porte diverse su uno stesso host in 5 minuti"},
			Every: 1, Window: 5 * time.Minute, Run: rulePortscan,
		},
		{
			ID: "sweep", Name: "Ricerca di host attivi", Category: "Ricognizione", Severity: "medium", Mitre: "T1018",
			Description: "Un host contatta molti indirizzi sulla stessa porta e la maggior parte non risponde.",
			Params:      params{"min_hosts": 30, "ignore_ports": "53,123,137,138,1900,5353,5355"},
			Help:        map[string]string{"min_hosts": "Indirizzi diversi in 5 minuti", "ignore_ports": "Porte da non considerare"},
			Every:       1, Window: 5 * time.Minute, Run: ruleSweep,
		},
		{
			ID: "bruteforce", Name: "Tentativi di accesso ripetuti", Category: "Accesso", Severity: "high", Mitre: "T1110",
			Description: "Molte connessioni da uno stesso indirizzo verso un servizio di autenticazione (SSH, RDP, SMB, database…).",
			Params:      params{"min_attempts": 30, "ports": "21,22,23,25,110,143,389,445,587,993,1433,3306,3389,5432,5900,5985,5986"},
			Help:        map[string]string{"min_attempts": "Connessioni in 5 minuti", "ports": "Porte dei servizi di autenticazione"},
			Every:       1, Window: 5 * time.Minute, Run: ruleBruteforce,
		},
		{
			ID: "lateral", Name: "Movimento laterale", Category: "Movimento laterale", Severity: "high", Mitre: "T1021",
			Description: "Un host interno apre sessioni amministrative (SMB, RDP, WinRM, SSH) verso molti altri host interni.",
			Params:      params{"min_hosts": 6, "ports": "22,135,445,3389,5985,5986", "admins": ""},
			Help:        map[string]string{"min_hosts": "Host interni diversi in 5 minuti", "ports": "Porte amministrative", "admins": "Indirizzi delle postazioni di amministrazione da escludere"},
			Every:       1, Window: 5 * time.Minute, Run: ruleLateral,
		},
		{
			ID: "beacon", Name: "Beacon verso internet", Category: "Comando e controllo", Severity: "high", Mitre: "T1071",
			Description: "Connessioni verso lo stesso indirizzo esterno a intervalli molto regolari, tipiche di un malware che chiede istruzioni.",
			Params:      params{"min_count": 12, "max_jitter": 0.15, "min_interval_s": 10, "ignore_apps": "NTP,DNS,Windows Update", "ignore_domains": ""},
			Help: map[string]string{"min_count": "Connessioni minime in 60 minuti", "max_jitter": "Scarto massimo tra gli intervalli (0,15 = 15%)",
				"min_interval_s": "Intervallo minimo in secondi", "ignore_apps": "Applicazioni da escludere", "ignore_domains": "Domini da escludere"},
			Every: 15, Window: time.Hour, Run: ruleBeacon,
		},
		{
			ID: "exfil", Name: "Invio anomalo di dati verso internet", Category: "Esfiltrazione", Severity: "high", Mitre: "T1048",
			Description: "Un host interno invia verso internet più dati della soglia in un'ora. Di notte la gravità diventa critica.",
			Params:      params{"bytes": 1 << 30, "night_start": 22, "night_end": 6},
			Help:        map[string]string{"bytes": "Byte inviati in 60 minuti", "night_start": "Inizio della notte (ora locale)", "night_end": "Fine della notte (ora locale)"},
			Every:       15, Window: time.Hour, Run: ruleExfil,
		},
		{
			ID: "anomaly_volume", Name: "Volume fuori dal normale", Category: "Esfiltrazione", Severity: "medium", Mitre: "T1041",
			Description: "Un host invia molti più dati del suo solito, confrontato con le stesse ore dei 7 giorni precedenti.",
			Params:      params{"min_bytes": 100 << 20, "sigma": 4, "ratio": 3, "min_hours": 24},
			Help: map[string]string{"min_bytes": "Byte minimi in 60 minuti per considerare l'host", "sigma": "Deviazioni standard sopra la media",
				"ratio": "Multiplo minimo della media oraria", "min_hours": "Ore di storico necessarie"},
			Every: 15, Window: time.Hour, Run: ruleAnomalyVolume,
		},
		{
			ID: "dga", Name: "Domini generati da algoritmo", Category: "Comando e controllo", Severity: "high", Mitre: "T1568.002",
			Description: "Un host cerca molti domini inesistenti dal nome casuale: tipico dei malware che cercano il proprio server.",
			Params:      params{"min_nx": 10, "min_entropy": 3.3, "min_len": 10},
			Help:        map[string]string{"min_nx": "Risposte NXDOMAIN casuali in 5 minuti", "min_entropy": "Entropia minima del nome", "min_len": "Lunghezza minima del nome"},
			Every:       1, Window: 5 * time.Minute, Run: ruleDGA,
		},
		{
			ID: "dns_tunnel", Name: "Tunnel DNS", Category: "Esfiltrazione", Severity: "high", Mitre: "T1071.004",
			Description: "Molte query verso sottodomini sempre diversi e lunghi di uno stesso dominio: dati nascosti nel DNS.",
			Params:      params{"min_unique": 150, "min_long": 40, "min_avg_len": 50, "ignore_domains": ""},
			Help: map[string]string{"min_unique": "Sottodomini diversi in 5 minuti", "min_long": "Query minime per il controllo della lunghezza",
				"min_avg_len": "Lunghezza media sospetta", "ignore_domains": "Domini da escludere"},
			Every: 1, Window: 5 * time.Minute, Run: ruleDNSTunnel,
		},
		{
			ID: "dns_bypass", Name: "DNS esterno al posto di quello aziendale", Category: "Elusione", Severity: "low", Mitre: "T1572",
			Description: "Un host usa direttamente un DNS su internet, DNS su TLS o DNS su HTTPS: salta i filtri e la registrazione aziendali.",
			Params: params{"allowed": "", "resolvers": "",
				"doh_domains": "dns.google,cloudflare-dns.com,mozilla.cloudflare-dns.com,dns.quad9.net,doh.opendns.com,dns.nextdns.io,doh.cleanbrowsing.org"},
			Help: map[string]string{"allowed": "Server DNS esterni ammessi", "resolvers": "Server DNS interni oltre a quelli riconosciuti",
				"doh_domains": "Domini di DNS su HTTPS"},
			Every: 5, Window: 5 * time.Minute, Run: ruleDNSBypass,
		},
		{
			ID: "rare_country", Name: "Paese mai contattato", Category: "Comando e controllo", Severity: "medium",
			Description: "Connessione riuscita verso un paese che non compariva nel traffico dei 7 giorni precedenti, o verso un paese sorvegliato.",
			Params:      params{"watch": "", "min_history_hours": 20},
			Help:        map[string]string{"watch": "Codici dei paesi sempre segnalati (es. KP,IR)", "min_history_hours": "Ore di storico necessarie"},
			Every:       5, Window: 5 * time.Minute, Run: ruleRareCountry,
		},
		{
			ID: "tor", Name: "Traffico Tor", Category: "Comando e controllo", Severity: "high", Mitre: "T1090.003",
			Description: "Connessioni verso la rete Tor, che rende anonimo e non ispezionabile il traffico.",
			Params:      params{"ports": "9001,9030,9050,9051,9150"}, Help: map[string]string{"ports": "Porte tipiche di Tor"},
			Every: 5, Window: 5 * time.Minute, Run: ruleTor,
		},
		{
			ID: "remote_access", Name: "Software di controllo remoto", Category: "Comando e controllo", Severity: "low", Mitre: "T1219",
			Description: "Uso di AnyDesk, TeamViewer e simili: legittimo per l'assistenza, sfruttato anche negli attacchi.",
			Params:      params{"apps": "AnyDesk,TeamViewer,ScreenConnect,RustDesk,Splashtop,LogMeIn"}, Help: map[string]string{"apps": "Applicazioni da segnalare"},
			Every: 5, Window: 5 * time.Minute, Run: ruleRemoteAccess,
		},
		{
			ID: "insecure", Name: "Protocollo in chiaro", Category: "Configurazione", Severity: "medium", Mitre: "T1040",
			Description: "Servizi che trasmettono credenziali e dati senza cifratura (Telnet, FTP, POP3, IMAP…).",
			Params:      params{"apps": "Telnet,FTP,TFTP,POP3,IMAP,VNC"}, Help: map[string]string{"apps": "Applicazioni considerate insicure"},
			Every: 5, Window: 5 * time.Minute, Run: ruleInsecure,
		},
		{
			ID: "tls_weak", Name: "TLS obsoleto", Category: "Configurazione", Severity: "medium", Mitre: "T1557",
			Description: "Server che accettano versioni di TLS o SSL non più sicure.",
			Params:      params{"versions": "SSLv3,TLSv1.0,TLSv1.1"}, Help: map[string]string{"versions": "Versioni da segnalare"},
			Every: 5, Window: 5 * time.Minute, Run: ruleTLSWeak,
		},
		{
			ID: "tls_cert", Name: "Certificato non valido", Category: "Configurazione", Severity: "medium", Mitre: "T1557",
			Description: "Certificati scaduti, in scadenza o autofirmati. Un certificato autofirmato su un sito esterno può indicare un'intercettazione.",
			Params:      params{"warn_days": 14}, Help: map[string]string{"warn_days": "Giorni di preavviso per la scadenza"},
			Every: 5, Window: 5 * time.Minute, Run: ruleTLSCert,
		},
		{
			ID: "ids", Name: "Firma IDS", Category: "IDS", Severity: "medium",
			Description: "Eventi segnalati dal motore IDS del sensore (Suricata o equivalente), raggruppati per firma, origine e destinazione.",
			Every:       1, Window: 5 * time.Minute, Run: ruleIDS,
		},
		{
			ID: "new_device", Name: "Nuovo dispositivo", Category: "Inventario", Severity: "medium",
			Description: "Un dispositivo mai visto compare in rete dopo il periodo di apprendimento. Grave se in una rete sensibile.",
		},
		{
			ID: "new_service", Name: "Nuovo servizio in ascolto", Category: "Inventario", Severity: "low",
			Description: "Un dispositivo già noto inizia a rispondere su una porta che prima non offriva.",
		},
		{
			ID: "exposed_service", Name: "Servizio raggiungibile da internet", Category: "Inventario", Severity: "high", Mitre: "T1190",
			Description: "Una connessione da internet verso un dispositivo interno ha ricevuto risposta.",
		},
		{
			ID: "sensor_offline", Name: "Sensore non raggiungibile", Category: "Sistema", Severity: "high",
			Description: "Un sensore non comunica con l'hub da più di 2 minuti. L'allarme si chiude da solo quando torna.",
		},
	}
}

// ---------------------------------------------------------------- funzioni comuni

func label(ip, name string) string {
	if name == "" || name == ip {
		return ip
	}
	return name + " (" + ip + ")"
}

func humanBytes(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", b, units[i])
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

func (e *Engine) clock(t time.Time) string { return t.In(e.h.state.Location()).Format("15:04") }

func parseCH(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04:05.000", s, time.UTC)
	if err != nil {
		t, _ = time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
	}
	return t
}

func q[T any](ctx context.Context, e *Engine, sql string, p map[string]string) ([]T, error) {
	return chx.Query[T](ctx, e.h.ch, sql, p)
}

// ---------------------------------------------------------------- regole

func rulePortscan(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, TopDst, TopName, Since string
		Hosts, MaxPorts, Failed            uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(sname) AS Sname, count() AS Hosts, max(ports) AS MaxPorts,
		       argMax(dst, ports) AS TopDst, argMax(dname, ports) AS TopName, sum(failed) AS Failed, toString(min(first)) AS Since
		FROM (
			SELECT src, any(src_name) AS sname, dst, any(dst_name) AS dname, uniqExact(dport) AS ports,
			       countIf(est = 0) AS failed, min(ts) AS first
			FROM flows WHERE `+inWindow+` AND proto IN ('TCP', 'UDP')
			GROUP BY src, dst HAVING ports >= {min:UInt32}
		) GROUP BY src ORDER BY MaxPorts DESC LIMIT 200`,
		w.params(map[string]string{"min": chInt(p.num("min_ports"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		sum := fmt.Sprintf("%s ha provato %d porte diverse su %s", who, r.MaxPorts, label(r.TopDst, r.TopName))
		if r.Hosts > 1 {
			sum += fmt.Sprintf(" e scansionato in tutto %d host", r.Hosts)
		}
		sum += fmt.Sprintf(" tra le %s e le %s; %d tentativi senza risposta.", e.clock(w.from), e.clock(w.to), r.Failed)
		out = append(out, Alert{
			DedupKey: "portscan|" + r.Src, Src: r.Src, Dst: r.TopDst, TS: parseCH(r.Since),
			Title: "Scansione di porte da " + who, Summary: sum,
			Detail: map[string]any{"ports": r.MaxPorts, "hosts": r.Hosts, "failed": r.Failed},
		})
	}
	return out, nil
}

func ruleSweep(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Proto, Since string
		Dport                    uint16
		Hosts, Failed, N         uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, proto AS Proto, dport AS Dport, uniqExact(dst) AS Hosts,
		       countIf(est = 0) AS Failed, count() AS N, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction IN ('internal', 'outbound') AND dport NOT IN {ignore:Array(UInt16)}
		GROUP BY src, proto, dport HAVING Hosts >= {min:UInt32} AND Failed * 2 >= N
		ORDER BY Hosts DESC LIMIT 200`,
		w.params(map[string]string{"min": chInt(p.num("min_hosts")), "ignore": chPorts(p.ports("ignore_ports"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		out = append(out, Alert{
			DedupKey: fmt.Sprintf("sweep|%s|%s/%d", r.Src, r.Proto, r.Dport), Src: r.Src, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("Ricerca di host attivi da %s sulla porta %s/%d", who, r.Proto, r.Dport),
			Summary: fmt.Sprintf("%s ha contattato %d indirizzi diversi sulla porta %s/%d in 5 minuti; %d tentativi su %d senza risposta.", who, r.Hosts, r.Proto, r.Dport, r.Failed, r.N),
			Detail:  map[string]any{"hosts": r.Hosts, "port": r.Dport, "proto": r.Proto},
		})
	}
	return out, nil
}

func ruleBruteforce(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Dst, Dname, App, CC, Since string
		Dport                                  uint16
		Attempts, Est                          uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, dst AS Dst, any(dst_name) AS Dname, dport AS Dport, any(app) AS App,
		       any(country) AS CC, count() AS Attempts, countIf(est = 1) AS Est, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND proto = 'TCP' AND dport IN {ports:Array(UInt16)}
		GROUP BY src, dst, dport HAVING Attempts >= {min:UInt32}
		ORDER BY Attempts DESC LIMIT 200`,
		w.params(map[string]string{"min": chInt(p.num("min_attempts")), "ports": chPorts(p.ports("ports"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		svc := fmt.Sprintf("porta %d", r.Dport)
		if r.App != "" {
			svc = fmt.Sprintf("%s (porta %d)", r.App, r.Dport)
		}
		from := label(r.Src, r.Sname)
		if r.CC != "" {
			from += " [" + r.CC + "]"
		}
		out = append(out, Alert{
			DedupKey: fmt.Sprintf("bruteforce|%s|%s|%d", r.Src, r.Dst, r.Dport), Src: r.Src, Dst: r.Dst, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("Tentativi di accesso ripetuti su %s di %s", svc, label(r.Dst, r.Dname)),
			Summary: fmt.Sprintf("%s ha aperto %d connessioni verso %s su %s in 5 minuti (%d stabilite).", from, r.Attempts, label(r.Dst, r.Dname), svc, r.Est),
			Detail:  map[string]any{"attempts": r.Attempts, "established": r.Est, "port": r.Dport, "country": r.CC},
		})
	}
	return out, nil
}

func ruleLateral(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Since string
		Hosts, N          uint64
		Sample            []string
		Ports             []uint16
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, uniqExact(dst) AS Hosts, groupUniqArray(8)(dst) AS Sample,
		       groupUniqArray(dport) AS Ports, count() AS N, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction = 'internal' AND est = 1 AND proto = 'TCP'
		  AND dport IN {ports:Array(UInt16)} AND src NOT IN {admins:Array(String)}
		GROUP BY src HAVING Hosts >= {min:UInt32} ORDER BY Hosts DESC LIMIT 100`,
		w.params(map[string]string{"min": chInt(p.num("min_hosts")), "ports": chPorts(p.ports("ports")), "admins": chStrings(p.list("admins"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		slices.Sort(r.Ports)
		out = append(out, Alert{
			DedupKey: "lateral|" + r.Src, Src: r.Src, TS: parseCH(r.Since),
			Title:   "Possibile movimento laterale da " + who,
			Summary: fmt.Sprintf("%s ha aperto %d sessioni amministrative verso %d host interni (porte %v) in 5 minuti.", who, r.N, r.Hosts, r.Ports),
			Detail:  map[string]any{"hosts": r.Hosts, "sample": r.Sample, "ports": r.Ports},
		})
	}
	return out, nil
}

func ruleBeacon(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Dst, Domain, CC string
		Dport                       uint16
		N                           uint64
		Mean, Sd                    float64
	}
	rows, err := q[row](ctx, e, `
		SELECT Src, Sname, Dst, Dport, Domain, CC, N, arrayAvg(d) AS Mean,
		       sqrt(greatest(arrayAvg(arrayMap(x -> x * x, d)) - Mean * Mean, 0)) AS Sd
		FROM (
			SELECT src AS Src, any(src_name) AS Sname, dst AS Dst, dport AS Dport, any(domain) AS Domain, any(country) AS CC,
			       count() AS N, arrayPopFront(arrayDifference(arraySort(groupArray(toUnixTimestamp64Milli(ts))))) AS d
			FROM flows WHERE `+inWindow+` AND direction = 'outbound'
			  AND app NOT IN {apps:Array(String)} AND domain NOT IN {domains:Array(String)}
			GROUP BY src, dst, dport HAVING N >= {min:UInt32}
		)
		WHERE Mean >= {interval:Float64} AND Sd <= Mean * {jitter:Float64}
		ORDER BY N DESC LIMIT 100`,
		w.params(map[string]string{"min": chInt(p.num("min_count")), "apps": chStrings(p.list("ignore_apps")),
			"domains": chStrings(p.list("ignore_domains")), "interval": chNum(p.num("min_interval_s") * 1000), "jitter": chNum(p.num("max_jitter"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		target := r.Dst
		if r.Domain != "" {
			target = r.Domain + " (" + r.Dst + ")"
		}
		out = append(out, Alert{
			DedupKey: fmt.Sprintf("beacon|%s|%s|%d", r.Src, r.Dst, r.Dport), Src: r.Src, Dst: r.Dst, TS: w.from,
			Title: fmt.Sprintf("Possibile beacon da %s verso %s", who, target),
			Summary: fmt.Sprintf("%s contatta %s sulla porta %d ogni %.0f secondi con regolarità sospetta: %d connessioni in un'ora, scarto %.1f%%.",
				who, target, r.Dport, r.Mean/1000, r.N, 100*r.Sd/math.Max(r.Mean, 1)),
			Detail: map[string]any{"interval_s": math.Round(r.Mean / 1000), "jitter": r.Sd / math.Max(r.Mean, 1), "count": r.N, "port": r.Dport, "domain": r.Domain, "country": r.CC},
		})
	}
	return out, nil
}

func ruleExfil(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, TopDst, TopDomain, CC, Since string
		Sent                                     uint64
		Dsts                                     uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, sum(bytes_out) AS Sent, uniqExact(dst) AS Dsts,
		       argMax(dst, bytes_out) AS TopDst, argMax(domain, bytes_out) AS TopDomain, argMax(country, bytes_out) AS CC,
		       toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction = 'outbound'
		GROUP BY src HAVING Sent >= {bytes:UInt64} ORDER BY Sent DESC LIMIT 50`,
		w.params(map[string]string{"bytes": chInt(p.num("bytes"))}))
	if err != nil {
		return nil, err
	}
	hour := w.to.In(e.h.state.Location()).Hour()
	ns, ne := int(p.num("night_start")), int(p.num("night_end"))
	night := (ns > ne && (hour >= ns || hour < ne)) || (ns < ne && hour >= ns && hour < ne)
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		target := r.TopDst
		if r.TopDomain != "" {
			target = r.TopDomain + " (" + r.TopDst + ")"
		}
		a := Alert{
			DedupKey: "exfil|" + r.Src, Src: r.Src, Dst: r.TopDst, TS: parseCH(r.Since),
			Title: fmt.Sprintf("%s ha inviato %s verso internet in un'ora", who, humanBytes(float64(r.Sent))),
			Summary: fmt.Sprintf("Tra le %s e le %s %s ha inviato %s verso %d destinazioni; la principale è %s.",
				e.clock(w.from), e.clock(w.to), who, humanBytes(float64(r.Sent)), r.Dsts, target),
			Detail: map[string]any{"bytes": r.Sent, "destinations": r.Dsts, "top": r.TopDst, "domain": r.TopDomain, "country": r.CC, "night": night},
		}
		if night {
			a.Severity = "critical"
			a.Summary += " Il trasferimento è avvenuto di notte."
		}
		out = append(out, a)
	}
	return out, nil
}

func ruleAnomalyVolume(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname string
		Sent       uint64
		Mean, Sd   float64
		Hours      uint64
	}
	base := w.to.Truncate(time.Hour)
	rows, err := q[row](ctx, e, `
		SELECT c.Src AS Src, c.Sname AS Sname, c.Sent AS Sent, b.Mean AS Mean, b.Sd AS Sd, b.Hours AS Hours
		FROM (
			SELECT src AS Src, any(src_name) AS Sname, sum(bytes_out) AS Sent
			FROM flows WHERE `+inWindow+` AND direction IN ('outbound', 'internal')
			GROUP BY src HAVING Sent >= {min:UInt64}
		) AS c
		INNER JOIN (
			SELECT ip, avg(s) AS Mean, stddevPop(s) AS Sd, count() AS Hours FROM (
				SELECT hour, ip, sum(bytes_sent) AS s FROM hosts_1h
				WHERE hour >= {h0:DateTime('UTC')} AND hour < {h1:DateTime('UTC')}
				GROUP BY hour, ip
			) GROUP BY ip
		) AS b ON b.ip = c.Src
		WHERE b.Hours >= {hours:UInt32} AND c.Sent > b.Mean + {sigma:Float64} * b.Sd AND c.Sent > b.Mean * {ratio:Float64}
		ORDER BY c.Sent DESC LIMIT 50`,
		w.params(map[string]string{
			"min": chInt(p.num("min_bytes")), "hours": chInt(p.num("min_hours")), "sigma": chNum(p.num("sigma")), "ratio": chNum(p.num("ratio")),
			"h0": base.Add(-7 * 24 * time.Hour).UTC().Format(time.DateTime), "h1": base.Add(-time.Hour).UTC().Format(time.DateTime),
		}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		out = append(out, Alert{
			DedupKey: "anomaly_volume|" + r.Src, Src: r.Src, TS: w.from,
			Title: fmt.Sprintf("Volume fuori dal normale da %s", who),
			Summary: fmt.Sprintf("Nell'ultima ora %s ha inviato %s, contro una media di %s all'ora negli ultimi 7 giorni (%.0f volte tanto).",
				who, humanBytes(float64(r.Sent)), humanBytes(r.Mean), float64(r.Sent)/math.Max(r.Mean, 1)),
			Detail: map[string]any{"bytes": r.Sent, "baseline_mean": r.Mean, "baseline_sd": r.Sd, "hours": r.Hours},
		})
	}
	return out, nil
}

// entropy è l'entropia di Shannon dei caratteri: i nomi generati a caso superano 3,3.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range freq {
		pr := c / n
		h -= pr * math.Log2(pr)
	}
	return h
}

func ruleDGA(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Client, Since string
		Qs            []string
		N             uint64
	}
	minNX := uint64(max(p.num("min_nx"), 1))
	rows, err := q[row](ctx, e, `
		SELECT client AS Client, groupUniqArray(300)(query) AS Qs, count() AS N, toString(min(ts)) AS Since
		FROM dns WHERE `+inWindow+` AND rcode = 'NXDOMAIN' AND client NOT IN {res:Array(String)}
		GROUP BY client HAVING N >= {min:UInt32} LIMIT 200`,
		w.params(map[string]string{"min": chInt(float64(minNX)), "res": chStrings(e.resolverList(ctx, nil))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		var odd []string
		for _, name := range r.Qs {
			first, _, _ := strings.Cut(name, ".")
			if len(first) >= int(p.num("min_len")) && entropy(first) >= p.num("min_entropy") {
				odd = append(odd, name)
			}
		}
		if uint64(len(odd)) < minNX {
			continue
		}
		who := label(r.Client, e.h.enr.device(r.Client).name)
		ex := odd[:min(3, len(odd))]
		out = append(out, Alert{
			DedupKey: "dga|" + r.Client, Src: r.Client, TS: parseCH(r.Since),
			Title:   "Domini generati da algoritmo cercati da " + who,
			Summary: fmt.Sprintf("%s ha cercato %d domini inesistenti dal nome casuale in 5 minuti, per esempio %s.", who, len(odd), strings.Join(ex, ", ")),
			Detail:  map[string]any{"count": len(odd), "examples": odd[:min(20, len(odd))]},
		})
	}
	return out, nil
}

func ruleDNSTunnel(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Client, Base, Since string
		N, Uniq             uint64
		AvgLen              float64
	}
	rows, err := q[row](ctx, e, `
		SELECT client AS Client, cutToFirstSignificantSubdomain(query) AS Base, count() AS N, uniqExact(query) AS Uniq,
		       avg(length(query)) AS AvgLen, toString(min(ts)) AS Since
		FROM dns WHERE `+inWindow+` AND client NOT IN {res:Array(String)}
		GROUP BY client, Base
		HAVING Base != '' AND Base NOT IN {ignore:Array(String)}
		   AND (Uniq >= {uniq:UInt32} OR (N >= {long:UInt32} AND AvgLen >= {len:Float64}))
		ORDER BY Uniq DESC LIMIT 100`,
		w.params(map[string]string{"res": chStrings(e.resolverList(ctx, nil)), "ignore": chStrings(p.list("ignore_domains")),
			"uniq": chInt(p.num("min_unique")), "long": chInt(p.num("min_long")), "len": chNum(p.num("min_avg_len"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Client, e.h.enr.device(r.Client).name)
		out = append(out, Alert{
			DedupKey: "dns_tunnel|" + r.Client + "|" + r.Base, Src: r.Client, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("Possibile tunnel DNS da %s verso %s", who, r.Base),
			Summary: fmt.Sprintf("%s ha inviato %d query verso %d sottodomini diversi di %s in 5 minuti (lunghezza media %.0f caratteri).", who, r.N, r.Uniq, r.Base, r.AvgLen),
			Detail:  map[string]any{"domain": r.Base, "queries": r.N, "unique": r.Uniq, "avg_len": r.AvgLen},
		})
	}
	return out, nil
}

func ruleDNSBypass(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Dst, Domain, Since string
		Dport                          uint16
		N                              uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, dst AS Dst, dport AS Dport, any(domain) AS Domain, count() AS N, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction = 'outbound'
		  AND ((dport = 53 AND proto IN ('UDP', 'TCP')) OR (dport = 853 AND proto = 'TCP') OR (dport = 443 AND domain IN {doh:Array(String)}))
		  AND src NOT IN {res:Array(String)} AND dst NOT IN {allowed:Array(String)}
		GROUP BY src, dst, dport ORDER BY N DESC LIMIT 200`,
		w.params(map[string]string{"doh": chStrings(p.list("doh_domains")), "res": chStrings(e.resolverList(ctx, p.list("resolvers"))),
			"allowed": chStrings(p.list("allowed"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		kind := "DNS"
		switch r.Dport {
		case 853:
			kind = "DNS su TLS"
		case 443:
			kind = "DNS su HTTPS"
		}
		target := r.Dst
		if r.Domain != "" {
			target = r.Domain + " (" + r.Dst + ")"
		}
		out = append(out, Alert{
			DedupKey: "dns_bypass|" + r.Src, Src: r.Src, Dst: r.Dst, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("%s usa un %s esterno", who, kind),
			Summary: fmt.Sprintf("%s ha interrogato direttamente %s (%s, %d connessioni) invece del DNS aziendale.", who, target, kind, r.N),
			Detail:  map[string]any{"server": r.Dst, "kind": kind, "count": r.N},
		})
	}
	return out, nil
}

func ruleRareCountry(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		CC, Src, Sname, Dst, Domain, Org, Since string
		Srcs, BOut, BIn                         uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT country AS CC, any(src) AS Src, any(src_name) AS Sname, any(dst) AS Dst, any(domain) AS Domain, any(as_org) AS Org,
		       uniqExact(src) AS Srcs, sum(bytes_out) AS BOut, sum(bytes_in) AS BIn, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction = 'outbound' AND country != '' AND est = 1
		GROUP BY country`, w.params(nil))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	watch := map[string]bool{}
	for _, c := range p.list("watch") {
		watch[strings.ToUpper(c)] = true
	}
	minHist := time.Duration(p.num("min_history_hours") * float64(time.Hour))
	hs := e.historyStart(ctx)
	enoughHistory := hs > 0 && w.from.Sub(time.UnixMilli(hs)) >= minHist
	seen := map[string]bool{}
	if enoughHistory {
		type c struct{ CC string }
		hist, err := q[c](ctx, e, `SELECT DISTINCT country AS CC FROM traffic_1m
			WHERE minute >= {h0:DateTime('UTC')} AND minute < {h1:DateTime('UTC')} AND direction = 'outbound' AND country != ''`,
			map[string]string{"h0": w.from.Add(-7 * 24 * time.Hour).UTC().Format(time.DateTime), "h1": w.from.UTC().Format(time.DateTime)})
		if err != nil {
			return nil, err
		}
		for _, h := range hist {
			seen[h.CC] = true
		}
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		target := r.Dst
		if r.Domain != "" {
			target = r.Domain + " (" + r.Dst + ")"
		}
		if r.Org != "" {
			target += ", " + r.Org
		}
		a := Alert{Src: r.Src, Dst: r.Dst, TS: parseCH(r.Since),
			Detail: map[string]any{"country": r.CC, "sources": r.Srcs, "bytes_out": r.BOut, "bytes_in": r.BIn, "org": r.Org}}
		switch {
		case watch[r.CC]:
			a.DedupKey, a.Severity = "watch_country|"+r.CC+"|"+r.Src, "high"
			a.Title = fmt.Sprintf("Connessione verso un paese sorvegliato (%s) da %s", r.CC, who)
			a.Summary = fmt.Sprintf("%s ha comunicato con %s, in %s, che è nell'elenco dei paesi sorvegliati.", who, target, r.CC)
		case enoughHistory && !seen[r.CC]:
			a.DedupKey = "rare_country|" + r.CC
			a.Title = fmt.Sprintf("Primo contatto con %s: %s", r.CC, who)
			a.Summary = fmt.Sprintf("Nessun host aveva comunicato con %s nei 7 giorni precedenti. %s ha scambiato %s con %s.",
				r.CC, who, humanBytes(float64(r.BOut+r.BIn)), target)
		default:
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func ruleTor(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Since string
		N, Dsts           uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, count() AS N, uniqExact(dst) AS Dsts, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND direction = 'outbound' AND (app = 'Tor' OR (proto = 'TCP' AND dport IN {ports:Array(UInt16)}))
		GROUP BY src LIMIT 100`,
		w.params(map[string]string{"ports": chPorts(p.ports("ports"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		out = append(out, Alert{
			DedupKey: "tor|" + r.Src, Src: r.Src, TS: parseCH(r.Since),
			Title:   "Traffico Tor da " + who,
			Summary: fmt.Sprintf("%s ha aperto %d connessioni verso %d nodi compatibili con la rete Tor.", who, r.N, r.Dsts),
			Detail:  map[string]any{"connections": r.N, "nodes": r.Dsts},
		})
	}
	return out, nil
}

func ruleRemoteAccess(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, App, Dst, Since string
		N, Bytes                    uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT src AS Src, any(src_name) AS Sname, app AS App, any(dst) AS Dst, count() AS N,
		       sum(bytes_out + bytes_in) AS Bytes, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND app IN {apps:Array(String)}
		GROUP BY src, app LIMIT 200`,
		w.params(map[string]string{"apps": chStrings(p.list("apps"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		who := label(r.Src, r.Sname)
		out = append(out, Alert{
			DedupKey: "remote_access|" + r.Src + "|" + r.App, Src: r.Src, Dst: r.Dst, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("%s su %s", r.App, who),
			Summary: fmt.Sprintf("%s usa %s (%d connessioni, %s). Verificare che sia un'assistenza autorizzata.", who, r.App, r.N, humanBytes(float64(r.Bytes))),
			Detail:  map[string]any{"app": r.App, "connections": r.N, "bytes": r.Bytes},
		})
	}
	return out, nil
}

func ruleInsecure(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Src, Sname, Dst, Dname, App, Dir, Since string
		Dport                                   uint16
		N                                       uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT any(src) AS Src, any(src_name) AS Sname, dst AS Dst, any(dst_name) AS Dname, app AS App, any(dport) AS Dport,
		       any(direction) AS Dir, count() AS N, toString(min(ts)) AS Since
		FROM flows WHERE `+inWindow+` AND est = 1 AND app IN {apps:Array(String)}
		GROUP BY dst, app ORDER BY N DESC LIMIT 200`,
		w.params(map[string]string{"apps": chStrings(p.list("apps"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		srv := label(r.Dst, r.Dname)
		where := ""
		if r.Dir == "outbound" {
			where = " su internet"
		}
		out = append(out, Alert{
			DedupKey: "insecure|" + r.Dst + "|" + r.App, Src: r.Src, Dst: r.Dst, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("%s in chiaro verso %s", r.App, srv),
			Summary: fmt.Sprintf("%s ha usato %s, che non è cifrato, verso %s%s (porta %d): credenziali e dati sono leggibili da chi intercetta il traffico.", label(r.Src, r.Sname), r.App, srv, where, r.Dport),
			Detail:  map[string]any{"app": r.App, "port": r.Dport, "connections": r.N},
		})
	}
	return out, nil
}

func ruleTLSWeak(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Server, SNI, Version, Client, Since string
		Port                                uint16
		Clients                             uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT server AS Server, any(sni) AS SNI, version AS Version, any(port) AS Port, any(client) AS Client,
		       uniqExact(client) AS Clients, toString(min(ts)) AS Since
		FROM tls WHERE `+inWindow+` AND version IN {v:Array(String)}
		GROUP BY server, version LIMIT 200`,
		w.params(map[string]string{"v": chStrings(p.list("versions"))}))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		srv := label(r.Server, firstNonEmpty(e.h.enr.device(r.Server).name, r.SNI))
		out = append(out, Alert{
			DedupKey: "tls_weak|" + r.Server + "|" + r.Version, Src: r.Client, Dst: r.Server, TS: parseCH(r.Since),
			Title:   fmt.Sprintf("%s accetta %s", srv, r.Version),
			Summary: fmt.Sprintf("Il server %s (porta %d) ha negoziato %s con %d client: la versione non è più considerata sicura.", srv, r.Port, r.Version, r.Clients),
			Detail:  map[string]any{"version": r.Version, "port": r.Port, "sni": r.SNI},
		})
	}
	return out, nil
}

func ruleTLSCert(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Server, SNI, Subject, Issuer, Client, Since string
		Port                                        uint16
		Exp                                         int64
		Self                                        uint8
	}
	warn := w.to.Add(time.Duration(p.num("warn_days")*24) * time.Hour).Unix()
	rows, err := q[row](ctx, e, `
		SELECT server AS Server, port AS Port, any(sni) AS SNI, cert_subject AS Subject, any(cert_issuer) AS Issuer,
		       any(cert_expiry) AS Exp, max(self_signed) AS Self, any(client) AS Client, toString(min(ts)) AS Since
		FROM tls WHERE `+inWindow+` AND cert_subject != '' AND (self_signed = 1 OR (cert_expiry > 0 AND cert_expiry < {warn:Int64}))
		GROUP BY server, port, cert_subject LIMIT 200`,
		w.params(map[string]string{"warn": fmt.Sprint(warn)}))
	if err != nil {
		return nil, err
	}
	nets := e.h.state.Internal()
	var out []Alert
	for _, r := range rows {
		srv := label(r.Server, firstNonEmpty(e.h.enr.device(r.Server).name, r.SNI))
		internal := nets.Contains(r.Server)
		a := Alert{Src: r.Client, Dst: r.Server, TS: parseCH(r.Since),
			Detail: map[string]any{"subject": r.Subject, "issuer": r.Issuer, "expiry": r.Exp, "self_signed": r.Self == 1, "port": r.Port}}
		exp := time.Unix(r.Exp, 0)
		switch {
		case r.Exp > 0 && exp.Before(w.to):
			a.DedupKey = fmt.Sprintf("tls_cert|expired|%s|%d|%s", r.Server, r.Port, r.Subject)
			a.Title = "Certificato scaduto su " + srv
			a.Summary = fmt.Sprintf("Il certificato «%s» di %s (porta %d) è scaduto il %s.", r.Subject, srv, r.Port, exp.In(e.h.state.Location()).Format("02/01/2006"))
		case r.Self == 1 && !internal:
			a.DedupKey = fmt.Sprintf("tls_cert|self|%s|%d|%s", r.Server, r.Port, r.Subject)
			a.Title = "Certificato autofirmato su un server esterno: " + srv
			a.Summary = fmt.Sprintf("%s ha presentato un certificato autofirmato («%s»). Su un sito pubblico può indicare un'intercettazione del traffico.", srv, r.Subject)
		case r.Self == 1:
			a.DedupKey, a.Severity = fmt.Sprintf("tls_cert|self|%s|%d|%s", r.Server, r.Port, r.Subject), "low"
			a.Title = "Certificato autofirmato su " + srv
			a.Summary = fmt.Sprintf("Il servizio interno %s (porta %d) usa un certificato autofirmato («%s»): i client non possono verificarne l'identità.", srv, r.Port, r.Subject)
		default:
			a.DedupKey, a.Severity = fmt.Sprintf("tls_cert|expiring|%s|%d|%s", r.Server, r.Port, r.Subject), "low"
			a.Title = "Certificato in scadenza su " + srv
			a.Summary = fmt.Sprintf("Il certificato «%s» di %s (porta %d) scade il %s.", r.Subject, srv, r.Port, exp.In(e.h.state.Location()).Format("02/01/2006"))
		}
		out = append(out, a)
	}
	return out, nil
}

func ruleIDS(ctx context.Context, e *Engine, w window, p params) ([]Alert, error) {
	type row struct {
		Sig, Title, Cat, Src, Dst, Since string
		Dport                            uint16
		Sevs                             []string
		N                                uint64
	}
	rows, err := q[row](ctx, e, `
		SELECT signature AS Sig, any(title) AS Title, any(category) AS Cat, src AS Src, dst AS Dst, any(dport) AS Dport,
		       groupUniqArray(severity) AS Sevs, count() AS N, toString(min(ts)) AS Since
		FROM events WHERE `+inWindow+` AND kind = 'ids'
		GROUP BY signature, src, dst ORDER BY N DESC LIMIT 500`, w.params(nil))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		sev := "info"
		for _, s := range r.Sevs {
			if sevRank[s] > sevRank[sev] {
				sev = s
			}
		}
		src := label(r.Src, e.h.enr.device(r.Src).name)
		dst := label(r.Dst, e.h.enr.device(r.Dst).name)
		title := firstNonEmpty(r.Title, r.Sig)
		out = append(out, Alert{
			DedupKey: "ids|" + r.Sig + "|" + r.Src + "|" + r.Dst, Src: r.Src, Dst: r.Dst, Severity: sev, TS: parseCH(r.Since),
			Title:   "IDS: " + title,
			Summary: fmt.Sprintf("Firma «%s» (%s) da %s verso %s porta %d, %d volte.", r.Sig, firstNonEmpty(r.Cat, "senza categoria"), src, dst, r.Dport, r.N),
			Detail:  map[string]any{"signature": r.Sig, "category": r.Cat, "count": r.N, "port": r.Dport},
		})
	}
	return out, nil
}
