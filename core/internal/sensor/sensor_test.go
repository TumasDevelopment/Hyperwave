package sensor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"hyperwave/internal/model"
	"hyperwave/internal/netx"
)

// ---------------------------------------------------------------- handshake TLS reale

type teeConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *teeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func selfSigned(t *testing.T, cn string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake restituisce i byte scritti da client e server durante un handshake TLS.
func handshake(t *testing.T, maxVer uint16) (cli, srv []byte) {
	a, b := net.Pipe()
	ct, st := &teeConn{Conn: a}, &teeConn{Conn: b}
	server := tls.Server(st, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "test.example")}, NextProtos: []string{"h2", "http/1.1"}})
	client := tls.Client(ct, &tls.Config{ServerName: "test.example", InsecureSkipVerify: true, MaxVersion: maxVer, NextProtos: []string{"h2", "http/1.1"}})
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	return ct.buf.Bytes(), st.buf.Bytes()
}

var ja4Re = regexp.MustCompile(`^t1[23]d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestTLSHandshake12(t *testing.T) {
	cli, srv := handshake(t, tls.VersionTLS12)
	if !isTLSStart(cli) {
		t.Fatal("ClientHello non riconosciuto")
	}
	var ch *clientHello
	tlsHandshakes(cli, func(typ byte, body []byte) {
		if typ == 1 {
			var err error
			if ch, err = parseClientHello(body); err != nil {
				t.Fatal(err)
			}
		}
	})
	if ch == nil || ch.SNI != "test.example" || len(ch.ALPN) == 0 || ch.ALPN[0] != "h2" {
		t.Fatalf("ClientHello letto male: %+v", ch)
	}
	if !ja4Re.MatchString(ch.JA4) || !strings.HasPrefix(ch.JA4, "t12d") {
		t.Fatalf("JA4 non valido: %s", ch.JA4)
	}
	var sh *serverHello
	var cert *certInfo
	tlsHandshakes(srv, func(typ byte, body []byte) {
		switch typ {
		case 2:
			sh, _ = parseServerHello(body)
		case 11:
			var err error
			if cert, err = parseCertificate(body); err != nil {
				t.Fatal(err)
			}
		}
	})
	if sh == nil || versionName(sh.Version) != "TLSv1.2" || sh.ALPN != "h2" {
		t.Fatalf("ServerHello letto male: %+v", sh)
	}
	if cert == nil || cert.Subject != "CN=test.example" || !cert.SelfSigned || cert.NotAfter < time.Now().Unix() {
		t.Fatalf("certificato letto male: %+v", cert)
	}
}

func TestTLSHandshake13(t *testing.T) {
	cli, srv := handshake(t, tls.VersionTLS13)
	var ch *clientHello
	tlsHandshakes(cli, func(typ byte, body []byte) {
		if typ == 1 {
			ch, _ = parseClientHello(body)
		}
	})
	if ch == nil || versionName(ch.Version) != "TLSv1.3" || !strings.HasPrefix(ch.JA4, "t13d") {
		t.Fatalf("ClientHello 1.3 letto male: %+v", ch)
	}
	var sh *serverHello
	stop := tlsHandshakes(srv, func(typ byte, body []byte) {
		if typ == 2 {
			sh, _ = parseServerHello(body)
		}
	})
	if sh == nil || versionName(sh.Version) != "TLSv1.3" || !stop {
		t.Fatalf("ServerHello 1.3 letto male: %+v stop=%v", sh, stop)
	}
}

func TestJA4Grease(t *testing.T) {
	ch := &clientHello{Version: 0x0304, SNI: "a.example", ALPN: []string{"h2"},
		Ciphers: []uint16{0x0a0a, 0x1301, 0x1302}, Exts: []uint16{0x1a1a, 0x0000, 0x0010, 0x002b, 0x000d}, SigAlgs: []uint16{0x0403}}
	got := ja4(ch, 't')
	if !strings.HasPrefix(got, "t13d0204h2_") {
		t.Fatalf("parte a di JA4 errata: %s", got)
	}
	if got := ja4(&clientHello{Version: 0x0303}, 't'); got != "t12i000000_000000000000_000000000000" {
		t.Fatalf("JA4 vuoto errato: %s", got)
	}
}

// ---------------------------------------------------------------- pacchetti sintetici

func testRunner() *Runner {
	r := &Runner{cfg: Config{MaxPending: 100_000}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), stats: map[string]func() any{}}
	n := netx.ParseNets("10.0.0.0/8")
	r.nets.Store(&n)
	r.live.Store(true)
	return r
}

type pktGen struct {
	t    *testing.T
	p    *proc
	now  time.Time
	mac1 net.HardwareAddr
	mac2 net.HardwareAddr
}

func (g *pktGen) send(ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		g.t.Fatal(err)
	}
	data := buf.Bytes()
	g.now = g.now.Add(2 * time.Millisecond)
	g.p.packet(data, gopacket.CaptureInfo{Timestamp: g.now, CaptureLength: len(data), Length: len(data)}, layers.LinkTypeEthernet)
}

func (g *pktGen) tcp(src, dst string, sp, dp uint16, seq, ack uint32, flags string, payload []byte) {
	eth := &layers.Ethernet{SrcMAC: g.mac1, DstMAC: g.mac2, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: seq, Ack: ack, Window: 65535,
		SYN: strings.Contains(flags, "S"), ACK: strings.Contains(flags, "A"), FIN: strings.Contains(flags, "F"), RST: strings.Contains(flags, "R"), PSH: len(payload) > 0}
	tcp.SetNetworkLayerForChecksum(ip)
	g.send(eth, ip, tcp, gopacket.Payload(payload))
}

func (g *pktGen) udp(src, dst string, sp, dp uint16, payload gopacket.SerializableLayer) {
	eth := &layers.Ethernet{SrcMAC: g.mac1, DstMAC: g.mac2, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
	udp.SetNetworkLayerForChecksum(ip)
	g.send(eth, ip, udp, payload)
}

// stream invia i byte divisi in segmenti da mss, aggiornando il numero di sequenza.
func (g *pktGen) stream(src, dst string, sp, dp uint16, seq *uint32, ack uint32, data []byte, mss int) {
	for len(data) > 0 {
		n := min(mss, len(data))
		g.tcp(src, dst, sp, dp, *seq, ack, "A", data[:n])
		*seq += uint32(n)
		data = data[n:]
	}
}

func TestProcTLSFlow(t *testing.T) {
	cli, srv := handshake(t, tls.VersionTLS12)
	r := testRunner()
	out := newSink(r, false)
	p := newProc(r, out)
	g := &pktGen{t: t, p: p, now: time.Now(), mac1: net.HardwareAddr{0x02, 1, 2, 3, 4, 5}, mac2: net.HardwareAddr{0x02, 9, 8, 7, 6, 5}}

	c, s := "10.1.1.10", "198.51.100.20"
	cseq, sseq := uint32(1000), uint32(5000)
	g.tcp(c, s, 51000, 443, cseq, 0, "S", nil)
	g.tcp(s, c, 443, 51000, sseq, cseq+1, "SA", nil)
	cseq, sseq = cseq+1, sseq+1
	g.tcp(c, s, 51000, 443, cseq, sseq, "A", nil)
	half := len(cli) / 2
	last := half - (half-1)/100*100                                            // lunghezza dell'ultimo segmento della prima metà
	g.stream(c, s, 51000, 443, &cseq, sseq, cli[:half], 100)                   // ClientHello diviso in più segmenti
	g.tcp(c, s, 51000, 443, cseq-uint32(last), sseq, "A", cli[half-last:half]) // ritrasmissione
	g.stream(c, s, 51000, 443, &cseq, sseq, cli[half:], 100)
	g.stream(s, c, 443, 51000, &sseq, cseq, srv, 1400)
	g.tcp(c, s, 51000, 443, cseq, sseq, "FA", nil)
	g.tcp(s, c, 443, 51000, sseq, cseq+1, "FA", nil)
	p.flushAll()

	b := out.take()
	if b == nil || len(b.Flows) != 1 {
		t.Fatalf("atteso un flusso, batch: %+v", b)
	}
	f := b.Flows[0]
	if f.SrcIP != c || f.DstIP != s || f.DstPort != 443 || !f.Est || f.Domain != "test.example" || f.RTT <= 0 || f.Flags != "SAPF" {
		t.Fatalf("flusso errato: %+v", f)
	}
	if f.Retrans != 1 {
		t.Fatalf("ritrasmissioni attese 1, trovate %d", f.Retrans)
	}
	if len(b.TLS) != 1 {
		t.Fatalf("atteso un record TLS, trovati %d", len(b.TLS))
	}
	tl := b.TLS[0]
	if tl.SNI != "test.example" || tl.Version != "TLSv1.2" || tl.ALPN != "h2" || !tl.SelfSigned || tl.CertSubject != "CN=test.example" || !ja4Re.MatchString(tl.JA4) {
		t.Fatalf("record TLS errato: %+v", tl)
	}
}

func TestProcScanDNSHTTP(t *testing.T) {
	r := testRunner()
	out := newSink(r, false)
	p := newProc(r, out)
	g := &pktGen{t: t, p: p, now: time.Now(), mac1: net.HardwareAddr{0x00, 0x50, 0x56, 1, 2, 3}, mac2: net.HardwareAddr{0x00, 0x50, 0x56, 9, 9, 9}}

	// porta chiusa: SYN e RST, il flusso non risulta stabilito
	g.tcp("10.1.1.66", "10.1.1.10", 40000, 3389, 1, 0, "S", nil)
	g.tcp("10.1.1.10", "10.1.1.66", 3389, 40000, 0, 2, "RA", nil)

	// DNS: domanda e risposta
	q := &layers.DNS{ID: 77, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	g.udp("10.1.1.10", "10.1.1.2", 53001, 53, q)
	resp := &layers.DNS{ID: 77, QR: true, RD: true, RA: true, Questions: q.Questions,
		Answers: []layers.DNSResourceRecord{{Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("203.0.113.5").To4()}}}
	g.udp("10.1.1.2", "10.1.1.10", 53, 53001, resp)

	// HTTP in chiaro con risposta
	g.tcp("10.1.1.10", "203.0.113.5", 52000, 80, 1, 0, "S", nil)
	g.tcp("203.0.113.5", "10.1.1.10", 80, 52000, 1, 2, "SA", nil)
	g.tcp("10.1.1.10", "203.0.113.5", 52000, 80, 2, 2, "A", []byte("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/8.0\r\n\r\n"))
	g.tcp("203.0.113.5", "10.1.1.10", 80, 52000, 2, 80, "A", []byte("HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com/\r\n\r\n"))

	// ARP: risposta di un dispositivo
	arp := &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply,
		SourceHwAddress: []byte{0x44, 0x19, 0xb6, 1, 2, 3}, SourceProtAddress: []byte{10, 1, 1, 50}, DstHwAddress: []byte{0, 0x50, 0x56, 1, 2, 3}, DstProtAddress: []byte{10, 1, 1, 10}}
	g.send(&layers.Ethernet{SrcMAC: net.HardwareAddr{0x44, 0x19, 0xb6, 1, 2, 3}, DstMAC: g.mac1, EthernetType: layers.EthernetTypeARP}, arp)

	p.flushAll()
	p.tick(g.now.UnixMilli() + rateEvery + 1)
	b := out.take()
	if b == nil {
		t.Fatal("nessun record")
	}
	var scan, web *model.Flow
	for i := range b.Flows {
		switch b.Flows[i].DstPort {
		case 3389:
			scan = &b.Flows[i]
		case 80:
			web = &b.Flows[i]
		}
	}
	if scan == nil || scan.Est || scan.SrcIP != "10.1.1.66" || scan.Flags != "SAR" {
		t.Fatalf("flusso verso porta chiusa errato: %+v", scan)
	}
	if web == nil || !web.Est || web.Domain != "www.example.com" {
		t.Fatalf("flusso HTTP errato: %+v", web)
	}
	if len(b.DNS) != 1 || b.DNS[0].Client != "10.1.1.10" || b.DNS[0].RCode != "NOERROR" || len(b.DNS[0].Answers) != 1 || b.DNS[0].Answers[0] != "203.0.113.5" || b.DNS[0].QType != "A" {
		t.Fatalf("DNS errato: %+v", b.DNS)
	}
	if len(b.HTTP) != 1 || b.HTTP[0].Status != 301 || b.HTTP[0].Host != "www.example.com" || b.HTTP[0].URI != "/index.html" || b.HTTP[0].UserAgent != "curl/8.0" {
		t.Fatalf("HTTP errato: %+v", b.HTTP)
	}
	if len(b.Hosts) != 1 || b.Hosts[0].IP != "10.1.1.50" || b.Hosts[0].MAC != "44:19:b6:01:02:03" || b.Hosts[0].Source != "arp" {
		t.Fatalf("dispositivo da ARP errato: %+v", b.Hosts)
	}
	if len(b.Rates) != 1 || b.Rates[0].BytesInternal == 0 || b.Rates[0].BytesOut == 0 || b.Rates[0].BytesIn == 0 {
		t.Fatalf("contatori errati: %+v", b.Rates)
	}
}

func TestLiveOffDiscards(t *testing.T) {
	r := testRunner()
	r.live.Store(false)
	s := newSink(r, false)
	s.put(func(b *model.Batch) { b.Flows = append(b.Flows, model.Flow{}) })
	if s.take() != nil {
		t.Fatal("con il live spento i record vanno scartati")
	}
}

func TestSplit(t *testing.T) {
	b := &model.Batch{Backfill: true}
	for range 25 {
		b.Flows = append(b.Flows, model.Flow{})
	}
	b.DNS = make([]model.DNS, 7)
	parts := split(b, 10)
	total := 0
	for _, p := range parts {
		if p.Len() > 10 || !p.Backfill {
			t.Fatalf("parte non valida: %d record", p.Len())
		}
		total += p.Len()
	}
	if total != 32 || len(parts) != 4 {
		t.Fatalf("divisione errata: %d record in %d parti", total, len(parts))
	}
}

func TestParseEve(t *testing.T) {
	line := `{"timestamp":"2026-11-09T10:15:00.123456+0100","flow_id":1,"event_type":"alert","src_ip":"10.0.0.5","src_port":4444,"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","alert":{"action":"allowed","signature_id":2027865,"rev":3,"signature":"ET POLICY Test","category":"Potential Corporate Privacy Violation","severity":2}}`
	ev, ok := parseEve(line)
	if !ok || ev.Severity != "medium" || ev.DstPort != 443 || ev.Signature != "ET POLICY Test" {
		t.Fatalf("evento errato: %+v", ev)
	}
	if want := time.Date(2026, 11, 9, 9, 15, 0, 123456000, time.UTC).UnixMilli(); ev.TS != want {
		t.Fatalf("orario errato: %d invece di %d", ev.TS, want)
	}
	if _, ok := parseEve(`{"event_type":"flow"}`); ok {
		t.Fatal("solo gli alert vanno inoltrati")
	}
}

// ---------------------------------------------------------------- demo

func TestDemoGenerates(t *testing.T) {
	r := testRunner()
	r.cfg.Timezone = "Europe/Rome"
	d := newDemo(r)
	loc, _ := time.LoadLocation("Europe/Rome")
	t0 := time.Date(2026, 11, 10, 10, 0, 0, 0, loc).UnixMilli() // martedì mattina
	b := &model.Batch{}
	for m := int64(0); m < 60; m++ {
		d.generate(b, t0+m*60_000, t0+(m+1)*60_000)
	}
	if len(b.Flows) < 5_000 || len(b.DNS) == 0 || len(b.TLS) == 0 || len(b.Rates) != 60 {
		t.Fatalf("traffico demo troppo scarso: %d flussi, %d DNS, %d TLS, %d contatori", len(b.Flows), len(b.DNS), len(b.TLS), len(b.Rates))
	}
	nets := netx.ParseNets("10.0.0.0/8,198.18.0.0/15,192.0.2.0/24,198.51.100.0/24,203.0.113.0/24")
	for _, f := range b.Flows {
		if !nets.Contains(f.SrcIP) || !nets.Contains(f.DstIP) {
			t.Fatalf("indirizzo fuori dalle reti di test o documentazione: %s -> %s", f.SrcIP, f.DstIP)
		}
	}
	night := &model.Batch{}
	n0 := time.Date(2026, 11, 10, 3, 0, 0, 0, loc).UnixMilli()
	for m := int64(0); m < 60; m++ {
		d.generate(night, n0+m*60_000, n0+(m+1)*60_000)
	}
	if len(night.Flows)*5 > len(b.Flows) {
		t.Fatalf("di notte il traffico dovrebbe calare: %d contro %d", len(night.Flows), len(b.Flows))
	}
}
