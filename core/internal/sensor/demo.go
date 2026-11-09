package sensor

import (
	"context"
	"encoding/base32"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"strings"
	"time"

	"hyperwave/internal/model"
	"hyperwave/internal/netx"
)

// La demo simula "Azienda Demo": nessun pacchetto viene catturato.
// Gli indirizzi esterni sono in 198.18.0.0/15 (riservata ai test) e nelle reti di documentazione;
// i domini sospetti finiscono in .example. VLAN: 10 uffici, 20 server, 30 ospiti, 40 IoT, 50 DMZ, 99 gestione.

type dHost struct {
	IP, MAC, Name, OS, Type string
	VLAN                    uint16
	Kind                    string  // pc, server, guest, cam, printer, net, dmz
	Rate                    float64 // sessioni al minuto nelle ore di punta
	Hidden                  bool    // compare solo più tardi (scenario Raspberry Pi)
}

type dSvc struct {
	Domain   string
	IP       string
	Port     uint16
	Proto    string
	CC       string
	ASN      uint32
	Org      string
	Out, In  float64 // byte medi inviati e ricevuti dal client
	W        float64
	TLS      string
	Internal bool
}

type demo struct {
	r     *Runner
	rng   *rand.Rand
	loc   *time.Location
	nets  netx.Nets
	hosts []*dHost
	kind  map[string][]*dHost
	svcs  map[string][]*dSvc // per tipo di client
	byIP  map[string]*dHost

	started     int64 // avvio del processo
	liveStart   int64 // inizio della parte live di questo processo
	rpiShown    bool
	rdpShown    bool
	countryDone bool
	lastHosts   int64
}

func extIP(name string) string {
	h := fnv.New32a()
	h.Write([]byte(name))
	v := h.Sum32()
	return fmt.Sprintf("198.%d.%d.%d", 18+v%2, (v>>8)%256, 1+(v>>16)%254)
}

func macFor(prefix, ip string) string {
	var a, b, c, d int
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return fmt.Sprintf("%s:%02x:%02x:%02x", prefix, b, c, d)
}

func ext(domain string, port uint16, cc string, asn uint32, org string, out, in, w float64) *dSvc {
	tls := ""
	if port == 443 {
		tls = "TLSv1.3"
	}
	return &dSvc{Domain: domain, IP: extIP(domain), Port: port, Proto: "TCP", CC: cc, ASN: asn, Org: org, Out: out, In: in, W: w, TLS: tls}
}

func local(ip string, port uint16, proto string, out, in, w float64) *dSvc {
	return &dSvc{IP: ip, Port: port, Proto: proto, Out: out, In: in, W: w, Internal: true}
}

func newDemo(r *Runner) *demo {
	loc, err := time.LoadLocation(r.cfg.Timezone)
	if err != nil {
		loc = time.UTC
	}
	d := &demo{r: r, rng: rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 42)), loc: loc,
		started: time.Now().UnixMilli(), nets: netx.ParseNets("10.0.0.0/8"), kind: map[string][]*dHost{}, svcs: map[string][]*dSvc{}, byIP: map[string]*dHost{}}
	add := func(h *dHost) {
		d.hosts = append(d.hosts, h)
		d.kind[h.Kind] = append(d.kind[h.Kind], h)
		d.byIP[h.IP] = h
	}
	// server (macchine virtuali VMware) e apparati
	for _, s := range []struct{ ip, name, typ, os string }{
		{"10.10.20.10", "DC01", "Domain controller", "Windows Server 2022"},
		{"10.10.20.11", "DC02", "Domain controller", "Windows Server 2022"},
		{"10.10.20.20", "FS01", "File server", "Windows Server 2022"},
		{"10.10.20.30", "DB01", "Database", "Windows Server 2019"},
		{"10.10.20.40", "ERP01", "Server applicativo", "Windows Server 2022"},
		{"10.10.20.45", "MAIL01", "Relay di posta", "Ubuntu 24.04"},
		{"10.10.20.50", "BACKUP01", "Backup", "Ubuntu 24.04"},
		{"10.10.20.60", "PRINT01", "Server di stampa", "Windows Server 2019"},
		{"10.10.20.70", "WSUS01", "Aggiornamenti Windows", "Windows Server 2019"},
		{"10.10.20.90", "NVR01", "Videoregistratore", "Linux"},
		{"10.10.20.95", "NMS01", "Monitoraggio", "Ubuntu 24.04"},
	} {
		add(&dHost{IP: s.ip, MAC: macFor("00:50:56", s.ip), Name: s.name, Type: s.typ, OS: s.os, VLAN: 20, Kind: "server", Rate: 2})
	}
	add(&dHost{IP: "10.10.20.80", MAC: macFor("00:11:32", "10.10.20.80"), Name: "NAS01", Type: "NAS", OS: "DSM 6", VLAN: 20, Kind: "server", Rate: 1})
	add(&dHost{IP: "10.10.20.66", MAC: "b8:27:eb:4c:1a:9e", Name: "raspberrypi", Type: "", OS: "Linux", VLAN: 20, Kind: "rogue", Hidden: true})
	add(&dHost{IP: "10.10.50.10", MAC: macFor("00:50:56", "10.10.50.10"), Name: "WEB-DMZ", Type: "Server web", OS: "Ubuntu 24.04", VLAN: 50, Kind: "dmz", Rate: 1})
	add(&dHost{IP: "10.10.50.20", MAC: macFor("00:50:56", "10.10.50.20"), Name: "VPN-GW", Type: "Gateway VPN", OS: "Linux", VLAN: 50, Kind: "dmz", Rate: 1})
	add(&dHost{IP: "10.10.99.1", MAC: "00:1b:54:0a:63:01", Name: "FW-01", Type: "Firewall", VLAN: 99, Kind: "net"})
	add(&dHost{IP: "10.10.30.1", MAC: "00:1b:54:0a:63:01", Name: "FW-01", Type: "Firewall", VLAN: 30, Kind: "net"})
	for i, n := range []string{"SW-CORE-01", "SW-PIANO1", "SW-PIANO2", "SW-MAGAZZINO"} {
		ip := fmt.Sprintf("10.10.99.%d", 2+i)
		add(&dHost{IP: ip, MAC: macFor("00:1b:54", ip), Name: n, Type: "Switch", VLAN: 99, Kind: "net"})
	}
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("10.10.99.%d", 20+i)
		add(&dHost{IP: ip, MAC: macFor("24:a4:3c", ip), Name: fmt.Sprintf("AP-%02d", i+1), Type: "Access point", VLAN: 99, Kind: "net"})
	}
	// postazioni
	reparti := []struct {
		code string
		n    int
	}{{"AMM", 10}, {"COM", 9}, {"PROD", 12}, {"TEC", 6}, {"DIR", 3}}
	ip := 11
	for _, rp := range reparti {
		for i := 1; i <= rp.n; i++ {
			addr := fmt.Sprintf("10.10.10.%d", ip)
			prefix, name, os := "f8:bc:12", fmt.Sprintf("PC-%s-%02d", rp.code, i), "Windows 11"
			switch {
			case rp.code == "DIR" || i%4 == 0:
				prefix, name = "3c:d9:2b", fmt.Sprintf("NB-%s-%02d", rp.code, i)
			case rp.code == "TEC" && i%3 == 0:
				prefix, os = "f0:18:98", "macOS"
			}
			add(&dHost{IP: addr, MAC: macFor(prefix, addr), Name: name, OS: os, Type: "Postazione", VLAN: 10, Kind: "pc", Rate: 22 + d.rng.Float64()*10})
			ip++
		}
	}
	add(&dHost{IP: "10.10.10.5", MAC: macFor("d4:be:d9", "10.10.10.5"), Name: "PC-IT-01", OS: "Windows 11", Type: "Postazione", VLAN: 10, Kind: "pc", Rate: 20})
	// ospiti: MAC casuali (privacy)
	for i := 0; i < 18; i++ {
		addr := fmt.Sprintf("10.10.30.%d", 100+i)
		mac := fmt.Sprintf("%x2:%02x:%02x:%02x:%02x:%02x", d.rng.IntN(16), d.rng.IntN(256), d.rng.IntN(256), d.rng.IntN(256), d.rng.IntN(256), i)
		add(&dHost{IP: addr, MAC: mac, Name: "", OS: "", VLAN: 30, Kind: "guest", Rate: 8})
	}
	// IoT
	for i := 1; i <= 6; i++ {
		addr := fmt.Sprintf("10.10.40.%d", 10+i)
		add(&dHost{IP: addr, MAC: macFor("44:19:b6", addr), Name: fmt.Sprintf("CAM-%02d", i), Type: "Telecamera", OS: "Embedded", VLAN: 40, Kind: "cam", Rate: 1})
	}
	for i, n := range []string{"STAMPANTE-PIANO1", "STAMPANTE-PIANO2", "STAMPANTE-AMM"} {
		addr := fmt.Sprintf("10.10.40.%d", 21+i)
		add(&dHost{IP: addr, MAC: macFor("00:80:77", addr), Name: n, Type: "Stampante", VLAN: 40, Kind: "printer"})
	}

	ms, goog := "Microsoft Corporation", "Google LLC"
	d.svcs["pc"] = []*dSvc{
		ext("outlook.office365.com", 443, "IE", 8075, ms, 9_000, 60_000, 14),
		ext("teams.microsoft.com", 443, "IE", 8075, ms, 40_000, 220_000, 10),
		ext("yourcompany.sharepoint.com", 443, "NL", 8075, ms, 30_000, 900_000, 7),
		ext("login.microsoftonline.com", 443, "IE", 8075, ms, 4_000, 9_000, 6),
		ext("www.google.com", 443, "US", 15169, goog, 3_000, 45_000, 6),
		ext("fonts.gstatic.com", 443, "US", 15169, goog, 1_000, 30_000, 3),
		ext("www.youtube.com", 443, "US", 15169, goog, 15_000, 4_000_000, 1.2),
		ext("zoom.us", 443, "US", 30103, "Zoom Video Communications", 80_000, 600_000, 1),
		ext("github.com", 443, "US", 36459, "GitHub, Inc.", 8_000, 150_000, 1),
		ext("s3.eu-central-1.amazonaws.com", 443, "DE", 16509, "Amazon.com, Inc.", 20_000, 300_000, 2),
		ext("www.cloudflare.com", 443, "NL", 13335, "Cloudflare, Inc.", 2_000, 25_000, 2),
		ext("www.agenziaentrate.gov.it", 443, "IT", 3269, "Telecom Italia S.p.A.", 6_000, 120_000, 1.5),
		ext("www.aruba.it", 443, "IT", 31034, "Aruba S.p.A.", 4_000, 60_000, 1.5),
		ext("www.intesasanpaolo.com", 443, "IT", 3269, "Telecom Italia S.p.A.", 7_000, 90_000, 1),
		ext("www.linkedin.com", 443, "US", 14413, "LinkedIn Corporation", 5_000, 180_000, 1.5),
		ext("www.salesforce.com", 443, "FR", 14340, "Salesforce.com, Inc.", 9_000, 150_000, 1.2),
		ext("api.dropboxapi.com", 443, "US", 19679, "Dropbox, Inc.", 25_000, 80_000, 0.6),
		ext("www.apple.com", 443, "US", 714, "Apple Inc.", 3_000, 70_000, 0.6),
		ext("slack.com", 443, "US", 16509, "Amazon.com, Inc.", 6_000, 40_000, 0.8),
		ext("www.bbc.co.uk", 443, "GB", 2818, "BBC", 4_000, 300_000, 0.6),
		ext("www.spotify.com", 443, "SE", 8403, "Spotify AB", 6_000, 900_000, 0.5),
		ext("update.microsoft.com", 443, "US", 8075, ms, 8_000, 3_000_000, 0.4),
		ext("ocsp.digicert.com", 80, "US", 15133, "Edgecast Inc.", 500, 1_500, 1),
		ext("legacy-supplier.example", 443, "DE", 64501, "Example Hosting GmbH", 3_000, 20_000, 0.15),
		local("10.10.20.10", 445, "TCP", 3_000, 8_000, 4), local("10.10.20.11", 389, "TCP", 1_500, 4_000, 3),
		local("10.10.20.10", 88, "TCP", 1_400, 1_600, 3), local("10.10.20.20", 445, "TCP", 40_000, 1_800_000, 5),
		local("10.10.20.40", 443, "TCP", 12_000, 90_000, 6), local("10.10.20.30", 1433, "TCP", 6_000, 80_000, 2),
		local("10.10.20.60", 445, "TCP", 90_000, 3_000, 1), local("10.10.40.21", 9100, "TCP", 400_000, 2_000, 0.5),
		local("10.10.20.80", 5001, "TCP", 3_000, 200_000, 0.4),
	}
	d.svcs["guest"] = []*dSvc{
		ext("www.instagram.com", 443, "IE", 32934, "Meta Platforms, Inc.", 20_000, 1_500_000, 5),
		ext("web.whatsapp.com", 443, "NL", 32934, "Meta Platforms, Inc.", 6_000, 30_000, 5),
		ext("www.youtube.com", 443, "US", 15169, goog, 15_000, 6_000_000, 4),
		ext("www.netflix.com", 443, "NL", 2906, "Netflix Streaming Services", 30_000, 15_000_000, 1),
		ext("www.tiktok.com", 443, "IE", 138699, "TikTok Pte. Ltd.", 25_000, 5_000_000, 2),
		ext("www.google.com", 443, "US", 15169, goog, 3_000, 45_000, 4),
		ext("www.icloud.com", 443, "US", 714, "Apple Inc.", 8_000, 60_000, 2),
	}
	d.svcs["server"] = []*dSvc{
		ext("update.microsoft.com", 443, "US", 8075, ms, 9_000, 5_000_000, 1),
		ext("api.ntp.org", 123, "DE", 64502, "NTP Pool", 90, 90, 1),
		ext("archive.ubuntu.com", 80, "GB", 41231, "Canonical Group Limited", 2_000, 2_000_000, 0.4),
	}
	d.svcs["cam"] = []*dSvc{
		ext("api.hik-connect.com", 443, "CN", 37963, "Hangzhou Alibaba Advertising Co.,Ltd.", 4_000, 2_000, 1),
	}
	d.svcs["dmz"] = []*dSvc{ext("archive.ubuntu.com", 80, "GB", 41231, "Canonical Group Limited", 2_000, 2_000_000, 1)}
	for _, list := range d.svcs {
		for _, s := range list {
			if s.Proto == "TCP" && s.Port == 123 {
				s.Proto = "UDP"
			}
		}
	}
	return d
}

// ---------------------------------------------------------------- casualità

func (d *demo) poisson(l float64) int {
	if l <= 0 {
		return 0
	}
	if l > 30 {
		return max(0, int(math.Round(l+math.Sqrt(l)*d.rng.NormFloat64())))
	}
	L, k, p := math.Exp(-l), 0, 1.0
	for {
		p *= d.rng.Float64()
		if p <= L {
			return k
		}
		k++
	}
}

func (d *demo) around(mean float64) uint64 {
	return uint64(max(60, mean*math.Exp(d.rng.NormFloat64()*0.7-0.245)))
}

func (d *demo) eph() uint16 { return uint16(49152 + d.rng.IntN(16000)) }

func (d *demo) pick(list []*dSvc) *dSvc {
	tot := 0.0
	for _, s := range list {
		tot += s.W
	}
	x := d.rng.Float64() * tot
	for _, s := range list {
		if x -= s.W; x <= 0 {
			return s
		}
	}
	return list[len(list)-1]
}

// activity è il carico relativo (0-1) in un momento: giorni feriali 8-18, pausa pranzo, notti e weekend quasi fermi.
func (d *demo) activity(ms int64) float64 {
	t := time.UnixMilli(ms).In(d.loc)
	h := float64(t.Hour()) + float64(t.Minute())/60
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		return 0.06
	}
	switch {
	case h < 7:
		return 0.03
	case h < 9:
		return 0.03 + (h-7)/2*0.97
	case h < 12.5:
		return 1
	case h < 14:
		return 0.55
	case h < 17.5:
		return 0.95
	case h < 20:
		return 0.95 - (h-17.5)/2.5*0.88
	}
	return 0.04
}

func (d *demo) workHours(ms int64) bool {
	t := time.UnixMilli(ms).In(d.loc)
	h := t.Hour()
	return t.Weekday() != time.Saturday && t.Weekday() != time.Sunday && h >= 8 && h < 19
}

func pkts(b uint64) uint32 { return uint32(b/900) + 2 }

func (d *demo) resolver(h *dHost) string {
	if h.VLAN == 30 {
		return "10.10.30.1"
	}
	if d.rng.IntN(3) == 0 {
		return "10.10.20.11"
	}
	return "10.10.20.10"
}

func (d *demo) rtt(s *dSvc) float32 {
	if s.Internal {
		return float32(0.3 + d.rng.Float64())
	}
	base := map[string]float64{"IT": 8, "DE": 18, "FR": 20, "NL": 22, "IE": 30, "GB": 28, "SE": 35, "US": 95, "CN": 210, "SG": 180, "BR": 200, "AR": 230}[s.CC]
	if base == 0 {
		base = 60
	}
	return float32(base * (0.9 + d.rng.Float64()*0.3))
}

// ---------------------------------------------------------------- generazione

func (d *demo) flow(b *model.Batch, ts int64, src string, vlan uint16, s *dSvc, out, in uint64) *model.Flow {
	dur := int64(50 + (out+in)/40_000*10 + uint64(d.rng.IntN(800)))
	f := model.Flow{TS: ts, End: ts + dur, VLAN: vlan, Proto: s.Proto, SrcIP: src, SrcPort: d.eph(), DstIP: s.IP, DstPort: s.Port,
		Domain: s.Domain, BytesOut: out, BytesIn: in, PktsOut: pkts(out), PktsIn: pkts(in), Est: true, RTT: d.rtt(s),
		Country: s.CC, ASN: s.ASN, ASOrg: s.Org}
	if s.Proto == "TCP" {
		f.Flags = "SAPF"
	}
	b.Flows = append(b.Flows, f)
	return &b.Flows[len(b.Flows)-1]
}

func (d *demo) dnsQuery(b *model.Batch, ts int64, h *dHost, name, answer, rcode, qtype string) {
	server := d.resolver(h)
	var ans []string
	if answer != "" {
		ans = []string{answer}
	}
	b.DNS = append(b.DNS, model.DNS{TS: ts, Client: h.IP, Server: server, Query: name, QType: qtype, RCode: rcode, Answers: ans, RTT: float32(0.5 + d.rng.Float64()*20)})
	b.Flows = append(b.Flows, model.Flow{TS: ts, End: ts + 25, VLAN: h.VLAN, Proto: "UDP", SrcIP: h.IP, SrcPort: d.eph(), DstIP: server, DstPort: 53,
		BytesOut: uint64(60 + len(name)), BytesIn: uint64(90 + len(name)*2), PktsOut: 1, PktsIn: 1, Est: true, RTT: 0.6})
}

func (d *demo) session(b *model.Batch, ts int64, h *dHost, s *dSvc) {
	if !s.Internal && s.Domain != "" && d.rng.IntN(4) == 0 {
		d.dnsQuery(b, ts-30, h, s.Domain, s.IP, "NOERROR", "A")
	}
	out, in := d.around(s.Out), d.around(s.In)
	d.flow(b, ts, h.IP, h.VLAN, s, out, in)
	switch {
	case s.Port == 443 && s.TLS != "" && d.rng.IntN(5) == 0:
		ja4 := map[string]string{"Windows 11": "t13d1516h2_8daaf6152771_02713d6af862", "macOS": "t13d1715h2_5b57614c22b0_3d5424432f57"}[h.OS]
		if ja4 == "" {
			ja4 = "t13d1517h2_8daaf6152771_b0da82dd1658"
		}
		t := model.TLS{TS: ts + 40, Client: h.IP, Server: s.IP, Port: s.Port, SNI: s.Domain, Version: s.TLS, ALPN: "h2", JA4: ja4}
		if s.Domain == "legacy-supplier.example" {
			t.Version, t.CertSubject, t.CertIssuer = "TLSv1.2", "CN=legacy-supplier.example", "CN=Example CA"
			t.CertNotAfter = ts/1000 - 34*86400
		}
		b.TLS = append(b.TLS, t)
	case s.Port == 80 && d.rng.IntN(2) == 0:
		b.HTTP = append(b.HTTP, model.HTTP{TS: ts + 30, Client: h.IP, Server: s.IP, Port: 80, Method: "GET", Host: s.Domain, URI: "/", Status: 200,
			UserAgent: "Microsoft-CryptoAPI/10.0"})
	case s.IP == "10.10.20.80" && d.rng.IntN(3) == 0:
		b.TLS = append(b.TLS, model.TLS{TS: ts + 40, Client: h.IP, Server: s.IP, Port: 5001, Version: "TLSv1.0",
			CertSubject: "CN=NAS01", CertIssuer: "CN=NAS01", CertNotAfter: ts/1000 + 400*86400, SelfSigned: true})
	case s.IP == "10.10.20.40" && s.Port == 443 && d.rng.IntN(6) == 0:
		b.TLS = append(b.TLS, model.TLS{TS: ts + 40, Client: h.IP, Server: s.IP, Port: 443, SNI: "erp.azienda.internal", Version: "TLSv1.2",
			CertSubject: "CN=erp.azienda.internal", CertIssuer: "CN=Azienda Demo CA", CertNotAfter: d.started/1000 + 10*86400})
	}
}

func (d *demo) hostRecords(b *model.Batch, ts int64, includeHidden bool) {
	for _, h := range d.hosts {
		if h.Hidden && !includeHidden {
			continue
		}
		src := "arp"
		if h.Kind == "pc" || h.Kind == "guest" {
			src = "dhcp"
		}
		b.Hosts = append(b.Hosts, model.Host{TS: ts, IP: h.IP, MAC: h.MAC, Hostname: h.Name, OS: h.OS, Type: h.Type, VLAN: h.VLAN, Source: src})
	}
}

// generate produce il traffico dell'intervallo [t0, t1).
func (d *demo) generate(b *model.Batch, t0, t1 int64) {
	minutes := float64(t1-t0) / 60_000
	act := d.activity(t0)
	at := func() int64 { return t0 + d.rng.Int64N(max(t1-t0, 1)) }

	for _, h := range d.hosts {
		if h.Hidden {
			continue
		}
		switch h.Kind {
		case "pc":
			for range d.poisson(h.Rate * act * minutes) {
				d.session(b, at(), h, d.pick(d.svcs["pc"]))
			}
		case "guest":
			for range d.poisson(h.Rate * act * minutes * 0.7) {
				d.session(b, at(), h, d.pick(d.svcs["guest"]))
			}
		case "server", "dmz":
			for range d.poisson(h.Rate * (0.3 + act) * minutes * 0.3) {
				d.session(b, at(), h, d.pick(d.svcs[h.Kind]))
			}
		case "cam":
			for range d.poisson(minutes / 5) {
				d.session(b, at(), h, d.svcs["cam"][0])
			}
			// il videoregistratore preleva il flusso video da ogni telecamera
			if d.rng.Float64() < minutes {
				s := local(h.IP, 554, "TCP", 4_000, 18_000_000*minutes, 1)
				d.flow(b, at(), "10.10.20.90", 20, s, d.around(s.Out), d.around(s.In))
			}
		}
	}
	// servizi infrastrutturali sempre attivi
	for range d.poisson(minutes * 3) {
		dc := d.byIP["10.10.20.10"]
		if d.rng.IntN(2) == 0 {
			dc = d.byIP["10.10.20.11"]
		}
		up := &dSvc{IP: extIP("resolver.provider.example"), Port: 53, Proto: "UDP", CC: "IT", ASN: 3269, Org: "Telecom Italia S.p.A.", Out: 80, In: 200}
		d.flow(b, at(), dc.IP, 20, up, d.around(80), d.around(220))
	}
	for _, h := range d.kind["net"] {
		if d.rng.Float64() < minutes {
			s := local(h.IP, 161, "UDP", 300, 1_400, 1)
			d.flow(b, at(), "10.10.20.95", 20, s, d.around(300), d.around(1400))
		}
		if d.rng.Float64() < minutes/3 {
			s := local("10.10.20.95", 514, "UDP", 400, 0, 1)
			f := d.flow(b, at(), h.IP, 99, s, d.around(400), 0)
			f.Est, f.PktsIn = false, 0
		}
	}
	for _, h := range d.kind["server"] {
		if d.rng.Float64() < minutes/10 {
			d.flow(b, at(), "10.10.20.50", 20, local(h.IP, 6160, "TCP", 6_000, 40_000_000, 1), 6_000, d.around(40_000_000))
		}
	}
	// posta in uscita dal relay
	for range d.poisson(act * minutes * 4) {
		s := ext("smtp.provider.example", 587, "IT", 31034, "Aruba S.p.A.", 60_000, 2_000, 1)
		d.flow(b, at(), "10.10.20.45", 20, s, d.around(60_000), 2_000)
	}
	// sito pubblico in DMZ: visitatori da internet
	for range d.poisson(minutes * (2 + 10*act)) {
		visitor := fmt.Sprintf("198.%d.%d.%d", 18+d.rng.IntN(2), d.rng.IntN(256), 1+d.rng.IntN(254))
		s := &dSvc{IP: "10.10.50.10", Port: 443, Proto: "TCP", Out: 2_000, In: 80_000}
		f := d.flow(b, at(), visitor, 50, s, d.around(2_000), d.around(80_000))
		f.Country = []string{"IT", "IT", "IT", "DE", "FR", "US", "GB"}[d.rng.IntN(7)]
	}
	d.scenarios(b, t0, t1)
	d.rates(b, t0, t1)
}

// rates riassume il traffico generato come farebbero i contatori dell'interfaccia.
func (d *demo) rates(b *model.Batch, t0, t1 int64) {
	var in, out, internal, pk, n uint64
	for _, f := range b.Flows {
		if f.TS < t0 || f.TS >= t1 {
			continue
		}
		n++
		pk += uint64(f.PktsIn + f.PktsOut)
		switch d.nets.Direction(f.SrcIP, f.DstIP) {
		case "outbound":
			out, in = out+f.BytesOut, in+f.BytesIn
		case "inbound":
			out, in = out+f.BytesIn, in+f.BytesOut
		default:
			internal += f.BytesIn + f.BytesOut
		}
	}
	b.Rates = append(b.Rates, model.Rate{TS: t0, Seconds: float64(t1-t0) / 1000, BytesIn: in, BytesOut: out, BytesInternal: internal,
		Packets: pk, Flows: n})
}

// ---------------------------------------------------------------- scenari

// every restituisce gli istanti, multipli di period con uno sfasamento fisso, che cadono in [t0, t1).
func every(t0, t1, period, offset int64) []int64 {
	var out []int64
	start := (t0-offset)/period*period + offset
	for t := start; t < t1; t += period {
		if t >= t0 {
			out = append(out, t)
		}
	}
	return out
}

func (d *demo) scenarios(b *model.Batch, t0, t1 int64) {
	const min = 60_000
	pc := func(ip string) *dHost { return d.byIP[ip] }

	// 1. beacon da PC-COM-07 ogni 60 s (±1 s), quando il PC è acceso
	if d.workHours(t0) {
		c2 := &dSvc{Domain: "cdn-update.example", IP: "198.51.100.77", Port: 443, Proto: "TCP", CC: "NL", ASN: 64496, Org: "Bulletproof Hosting Example"}
		for _, t := range every(t0, t1, min, 7_000) {
			d.flow(b, t+d.rng.Int64N(2_000)-1_000, "10.10.10.23", 10, c2, d.around(420), d.around(650))
		}
		for _, t := range every(t0, t1, 4*60*min, 37*min) {
			b.Events = append(b.Events, model.Event{TS: t, Kind: "ids", Severity: "high", Title: "ET MALWARE Possible Cobalt Strike Beacon Observed",
				SrcIP: "10.10.10.23", DstIP: "198.51.100.77", DstPort: 443, Signature: "ET MALWARE Possible Cobalt Strike Beacon Observed", Category: "A Network Trojan was detected"})
		}
	}

	// 2. brute force SSH sul server in DMZ da internet, ogni 45 minuti
	for _, t := range every(t0, t1, 45*min, 11*min) {
		attacker := fmt.Sprintf("203.0.113.%d", 10+d.rng.IntN(200))
		cc := []string{"CN", "RU", "VN", "BR", "US"}[d.rng.IntN(5)]
		n := 60 + d.rng.IntN(80)
		for i := range n {
			s := &dSvc{IP: "10.10.50.10", Port: 22, Proto: "TCP", Out: 1_800, In: 2_600}
			f := d.flow(b, t+int64(i)*int64(1_000+d.rng.IntN(1_500)), attacker, 50, s, d.around(1_800), d.around(2_600))
			f.Country = cc
		}
		b.Events = append(b.Events, model.Event{TS: t + 30_000, Kind: "ids", Severity: "medium", Title: "ET SCAN Potential SSH Scan",
			SrcIP: attacker, DstIP: "10.10.50.10", DstPort: 22, Signature: "ET SCAN Potential SSH Scan", Category: "Attempted Information Leak"})
	}

	// 3. esfiltrazione notturna da DB01: circa 1,4 GB tra le 2:10 e le 2:55
	for _, t := range every(t0, t1, 5*min, 0) {
		lt := time.UnixMilli(t).In(d.loc)
		if lt.Hour() == 2 && lt.Minute() >= 10 && lt.Minute() < 55 {
			s := &dSvc{Domain: "backup-sync.example", IP: "198.51.100.200", Port: 443, Proto: "TCP", CC: "SG", ASN: 64497, Org: "Example Cloud Pte"}
			d.flow(b, t+d.rng.Int64N(60_000), "10.10.20.30", 20, s, uint64(150_000_000+d.rng.IntN(20_000_000)), d.around(90_000))
		}
	}

	// 4. telnet da PC-IT-01 verso lo switch del magazzino, due volte al giorno
	for _, t := range every(t0, t1, 24*60*min, 9*60*min+20*min) {
		for _, tt := range []int64{t, t + 6*60*min} {
			if tt >= t0 && tt < t1 {
				d.flow(b, tt, "10.10.10.5", 10, local("10.10.99.5", 23, "TCP", 2_400, 9_000, 1), 2_400, 9_000)
			}
		}
	}

	// 5. scansione di porte dalla telecamera CAM-03 verso i server, ogni 2 ore
	for _, t := range every(t0, t1, 120*min, 53*min) {
		for _, target := range []string{"10.10.20.10", "10.10.20.20", "10.10.20.30", "10.10.20.40"} {
			for p := 1; p <= 60; p++ {
				port := uint16([]int{21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443}[p%30] + (p/30)*1000)
				f := d.flow(b, t+int64(p)*900, "10.10.40.13", 40, local(target, port, "TCP", 60, 0, 1), 60, 0)
				f.Est, f.Flags, f.PktsIn, f.BytesIn = false, "SR", 1, 0
			}
		}
	}

	// 6. DGA da PC-AMM-04, ogni 45 minuti in orario di lavoro
	if d.workHours(t0) {
		for _, t := range every(t0, t1, 45*min, 29*min) {
			for i := range 25 {
				name := make([]byte, 12+d.rng.IntN(5))
				for j := range name {
					name[j] = "abcdefghijklmnopqrstuvwxyz0123456789"[d.rng.IntN(36)]
				}
				tld := []string{"com", "net", "info", "biz"}[d.rng.IntN(4)]
				d.dnsQuery(b, t+int64(i)*3_000, pc("10.10.10.14"), string(name)+"."+tld, "", "NXDOMAIN", "A")
			}
		}
	}

	// 7. tunnel DNS da PC-PROD-12, ogni 90 minuti in orario di lavoro
	if d.workHours(t0) {
		for _, t := range every(t0, t1, 90*min, 61*min) {
			for i := range 220 {
				chunk := make([]byte, 25)
				for j := range chunk {
					chunk[j] = byte(d.rng.IntN(256))
				}
				label := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(chunk), "="))
				d.dnsQuery(b, t+int64(i)*700, pc("10.10.10.45"), label+".t.tunnel-dns.example", "", "NOERROR", "TXT")
			}
		}
	}

	// 8. AnyDesk su PC-AMM-09, due sessioni al giorno
	for _, t := range every(t0, t1, 24*60*min, 10*60*min+5*min) {
		for _, tt := range []int64{t, t + 5*60*min} {
			if tt >= t0 && tt < t1 {
				s := ext("relay-7.net.anydesk.com", 443, "DE", 64503, "philandro Software GmbH", 3_000_000, 25_000_000, 1)
				d.flow(b, tt, "10.10.10.19", 10, s, 3_000_000, 25_000_000)
			}
		}
	}

	// 9. telefono ospite con DNS privato (DNS su TLS) verso un resolver pubblico
	for range d.poisson(float64(t1-t0) / float64(min) * d.activity(t0) * 0.5) {
		s := &dSvc{Domain: "dns.example-privacy.net", IP: "198.18.53.53", Port: 853, Proto: "TCP", CC: "CH", ASN: 64504, Org: "Example Privacy DNS"}
		d.flow(b, t0+d.rng.Int64N(t1-t0), "10.10.30.105", 30, s, d.around(1_500), d.around(3_000))
	}

	// 10. Tor da un portatile ospite, una volta al giorno alle 16:40
	for _, t := range every(t0, t1, 24*60*min, 15*60*min+40*min) {
		for i := range 6 {
			s := &dSvc{IP: fmt.Sprintf("192.0.2.%d", 40+i), Port: 9001, Proto: "TCP", CC: "DE", ASN: 64505, Org: "Example Relay"}
			d.flow(b, t+int64(i)*20_000, "10.10.30.112", 30, s, d.around(40_000), d.around(400_000))
		}
	}

	// 11. paese mai contattato prima: NB-DIR-01 verso il Brasile, una volta al giorno alle 11:20
	for _, t := range every(t0, t1, 24*60*min, 10*60*min+20*min) {
		s := &dSvc{Domain: "conference-portal.example", IP: "203.0.113.99", Port: 443, Proto: "TCP", CC: "BR", ASN: 64506, Org: "Example Telecom Brasil"}
		d.flow(b, t, "10.10.10.48", 10, s, d.around(300_000), d.around(2_000_000))
	}

	// scenari che partono durante la demo live, una volta per avvio
	if d.liveStart > 0 && t1 > d.liveStart {
		d.liveScenarios(b, t0, t1)
	}
}

func (d *demo) liveScenarios(b *model.Batch, t0, t1 int64) {
	const min = 60_000
	in := func(t int64) bool { return t >= t0 && t < t1 }

	// Raspberry Pi non autorizzato nella VLAN server dopo circa 8 minuti
	rpiAt := d.liveStart + 8*min
	if !d.rpiShown && t1 > rpiAt {
		d.rpiShown = true
		rpi := d.byIP["10.10.20.66"]
		b.Hosts = append(b.Hosts, model.Host{TS: max(rpiAt, t0), IP: rpi.IP, MAC: rpi.MAC, Hostname: rpi.Name, OS: rpi.OS, VLAN: 20, Source: "dhcp"})
	}
	if d.rpiShown {
		// ogni ora: ricerca di host su SSH, scansione del DC e sessioni SMB verso molti server
		for _, t := range every(max(t0, rpiAt+2*min), t1, 60*min, (rpiAt+2*min)%(60*min)) {
			for i := 1; i <= 60; i++ {
				f := d.flow(b, t+int64(i)*400, "10.10.20.66", 20, local(fmt.Sprintf("10.10.20.%d", 100+i), 22, "TCP", 60, 0, 1), 60, 0)
				f.Est, f.Flags, f.PktsIn = false, "S", 0
			}
			for p := 1; p <= 200; p++ {
				f := d.flow(b, t+60_000+int64(p)*250, "10.10.20.66", 20, local("10.10.20.10", uint16(p*5), "TCP", 60, 0, 1), 60, 0)
				f.Est, f.Flags, f.PktsIn = false, "SR", 1
			}
			for i, srv := range []string{"10.10.20.10", "10.10.20.11", "10.10.20.20", "10.10.20.30", "10.10.20.40", "10.10.20.50", "10.10.20.60", "10.10.20.70"} {
				d.flow(b, t+120_000+int64(i)*3_000, "10.10.20.66", 20, local(srv, 445, "TCP", 8_000, 30_000, 1), 8_000, 30_000)
			}
			b.HTTP = append(b.HTTP, model.HTTP{TS: t + 90_000, Client: "10.10.20.66", Server: "10.10.20.40", Port: 80, Method: "GET", Host: "10.10.20.40",
				URI: "/nmaplowercheck1731", Status: 404, UserAgent: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"})
			b.Events = append(b.Events, model.Event{TS: t + 90_000, Kind: "ids", Severity: "high", Title: "ET SCAN Nmap Scripting Engine User-Agent Detected",
				SrcIP: "10.10.20.66", DstIP: "10.10.20.40", DstPort: 80, Signature: "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)", Category: "Web Application Attack"})
		}
	}

	// RDP del server ERP raggiungibile da internet, dopo 15 minuti
	if t := d.liveStart + 15*min; !d.rdpShown && in(t) {
		d.rdpShown = true
		f := d.flow(b, t, "203.0.113.77", 20, local("10.10.20.40", 3389, "TCP", 4_000, 9_000, 1), 4_000, 9_000)
		f.Country = "RU"
	}

	// primo contatto con l'Argentina, dopo 25 minuti
	if t := d.liveStart + 25*min; !d.countryDone && in(t) {
		d.countryDone = true
		s := &dSvc{Domain: "proveedor.example", IP: "203.0.113.150", Port: 443, Proto: "TCP", CC: "AR", ASN: 64507, Org: "Example Proveedor SA"}
		d.flow(b, t, "10.10.10.31", 10, s, d.around(80_000), d.around(400_000))
	}
}

// ---------------------------------------------------------------- ciclo principale

const backfillBatch = 20_000

// runDemo invia prima lo storico mancante (al massimo 24 ore), poi il traffico ogni 5 secondi.
// Con il live spento non genera nulla; alla riaccensione recupera il periodo saltato.
func (r *Runner) runDemo(ctx context.Context) error {
	d := newDemo(r)
	for ctx.Err() == nil {
		if !r.live.Load() {
			r.log.Info("live spento dall'hub: demo in pausa")
			for !r.live.Load() {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(2 * time.Second):
				}
			}
			r.log.Info("live acceso: la demo riprende")
		}
		now := time.Now().UnixMilli()
		from := max(now-24*3_600_000, r.lastIngest.Load()+1)
		from -= from % 60_000
		if now-from > 2*60_000 {
			if err := d.backfill(ctx, from, now-now%60_000); err != nil {
				return err
			}
		}
		if err := d.live(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (d *demo) send(ctx context.Context, b *model.Batch) error {
	if b.Len() == 0 {
		return nil
	}
	b.Demo = true
	rep, err := d.r.cl.Send(ctx, b)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		d.r.log.Warn("batch scartato dall'hub", "err", err, "record", b.Len())
		return nil
	}
	d.r.apply(rep)
	d.r.sent.Add(int64(rep.Accepted))
	return nil
}

func (d *demo) backfill(ctx context.Context, from, to int64) error {
	d.r.log.Info("demo: invio dello storico", "da", time.UnixMilli(from).Format(time.RFC3339), "a", time.UnixMilli(to).Format(time.RFC3339))
	b := &model.Batch{Backfill: true}
	d.hostRecords(b, from, false)
	start := time.Now()
	for t := from; t < to && ctx.Err() == nil; t += 60_000 {
		d.generate(b, t, t+60_000)
		if t%(6*3_600_000) == 0 {
			d.hostRecords(b, t, false) // rinnovi DHCP
		}
		if b.Len() >= backfillBatch {
			if err := d.send(ctx, b); err != nil {
				return err
			}
			b = &model.Batch{Backfill: true}
			if !d.r.live.Load() {
				return nil
			}
		}
	}
	err := d.send(ctx, b)
	d.r.log.Info("demo: storico inviato", "durata", time.Since(start).Round(time.Second))
	return err
}

func (d *demo) live(ctx context.Context) error {
	if d.liveStart == 0 {
		d.liveStart = time.Now().UnixMilli()
	}
	last := time.Now().UnixMilli()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if !d.r.live.Load() {
			return nil
		}
		now := time.Now().UnixMilli()
		b := &model.Batch{}
		if now-d.lastHosts > 10*60_000 {
			d.hostRecords(b, now, d.rpiShown)
			d.lastHosts = now
		}
		d.generate(b, last, now)
		last = now
		if err := d.send(ctx, b); err != nil {
			return err
		}
	}
}
