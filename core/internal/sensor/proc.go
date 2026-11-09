package sensor

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"hyperwave/internal/model"
	"hyperwave/internal/netx"
)

// proc trasforma i pacchetti in flussi, DNS, TLS, HTTP, dispositivi e contatori.
// È condiviso tra le interfacce osservate e protetto da un mutex.

const (
	tcpIdle      = 120_000 // ms senza pacchetti prima di chiudere un flusso TCP
	tcpClosed    = 5_000   // dopo FIN nei due versi o RST
	udpIdle      = 60_000
	dnsIdle      = 10_000
	icmpIdle     = 30_000
	activeExport = 300_000 // i flussi lunghi vengono riportati ogni 5 minuti
	maxFlows     = 400_000
	tlsClientMax = 16 << 10
	tlsServerMax = 64 << 10
	rateEvery    = 5_000
	hostRepeat   = 10 * 60_000
)

const (
	fFIN = 1 << iota
	fSYN
	fRST
	fPSH
	fACK
	fURG
)

type flowKey struct {
	a, b  netip.AddrPort
	proto uint8
	vlan  uint16
}

type flow struct {
	cli, srv    netip.AddrPort
	proto       uint8
	vlan        uint16
	dport       uint16 // per ICMP: il tipo del primo messaggio
	start, last int64
	bOut, bIn   uint64
	pOut, pIn   uint32
	flags       uint8
	est, closed bool
	fins        uint8
	synUS       int64
	synAckUS    int64
	rtt         float32
	retrans     uint32
	next        [2]uint32
	haveNext    [2]bool
	domain      string

	// TLS: 0 da decidere, 1 in lettura, 2 non TLS o già letto
	tlsState uint8
	tlsBuf   [2][]byte
	tlsNext  [2]uint32
	tlsInit  [2]bool
	tlsDone  [2]bool
	tls      *model.TLS
	tlsSent  bool

	http []model.HTTP // richieste in attesa di risposta
}

type dnsKey struct {
	client, server netip.Addr
	id             uint16
}

type dhcpInfo struct{ host, class string }

type proc struct {
	r      *Runner
	out    *sink
	ignore netx.Nets

	mu      sync.Mutex
	flows   map[flowKey]*flow
	parsers map[gopacket.LayerType]*gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	eth   layers.Ethernet
	sll   layers.LinuxSLL
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
	icmp6 layers.ICMPv6
	arp   layers.ARP
	dns   layers.DNS
	dhcp  layers.DHCPv4

	dnsPending map[dnsKey]int64
	dhcpSeen   map[string]dhcpInfo
	hostSeen   map[string]int64

	rateStart                int64
	rIn, rOut, rInt, rPkts   uint64
	drops                    func() uint64
	packets, bytes, tableFul atomic.Uint64
	lastTick                 int64
}

func newProc(r *Runner, out *sink) *proc {
	p := &proc{r: r, out: out, ignore: netx.ParseNets(r.cfg.IgnoreNets), flows: map[flowKey]*flow{},
		dnsPending: map[dnsKey]int64{}, dhcpSeen: map[string]dhcpInfo{}, hostSeen: map[string]int64{}}
	dec := []gopacket.DecodingLayer{&p.eth, &p.sll, &p.dot1q, &p.ip4, &p.ip6, &p.tcp, &p.udp, &p.icmp4, &p.icmp6, &p.arp}
	p.parsers = map[gopacket.LayerType]*gopacket.DecodingLayerParser{}
	for _, first := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeLinuxSLL, layers.LayerTypeIPv4, layers.LayerTypeIPv6} {
		dp := gopacket.NewDecodingLayerParser(first, dec...)
		dp.IgnoreUnsupported = true
		p.parsers[first] = dp
	}
	r.addStat("packets", func() any { return p.packets.Load() })
	r.addStat("bytes", func() any { return p.bytes.Load() })
	r.addStat("flow_table_full", func() any { return p.tableFul.Load() })
	r.addStat("flows_active", func() any { p.mu.Lock(); defer p.mu.Unlock(); return len(p.flows) })
	return p
}

// firstLayer sceglie il primo livello da decodificare in base al tipo di collegamento.
func firstLayer(lt layers.LinkType, data []byte) gopacket.LayerType {
	switch lt {
	case layers.LinkTypeLinuxSLL:
		return layers.LayerTypeLinuxSLL
	case layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6, 12, 14:
		if len(data) > 0 && data[0]>>4 == 6 {
			return layers.LayerTypeIPv6
		}
		return layers.LayerTypeIPv4
	}
	return layers.LayerTypeEthernet
}

func tcpFlags(t *layers.TCP) uint8 {
	var f uint8
	if t.FIN {
		f |= fFIN
	}
	if t.SYN {
		f |= fSYN
	}
	if t.RST {
		f |= fRST
	}
	if t.PSH {
		f |= fPSH
	}
	if t.ACK {
		f |= fACK
	}
	if t.URG {
		f |= fURG
	}
	return f
}

func flagString(f uint8) string {
	var b strings.Builder
	for _, x := range []struct {
		bit uint8
		c   byte
	}{{fSYN, 'S'}, {fACK, 'A'}, {fPSH, 'P'}, {fFIN, 'F'}, {fRST, 'R'}, {fURG, 'U'}} {
		if f&x.bit != 0 {
			b.WriteByte(x.c)
		}
	}
	return b.String()
}

// packet elabora un pacchetto. data può essere riutilizzato dal chiamante dopo il ritorno.
func (p *proc) packet(data []byte, ci gopacket.CaptureInfo, lt layers.LinkType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packets.Add(1)
	p.bytes.Add(uint64(ci.Length))
	ts := ci.Timestamp.UnixMilli()
	us := ci.Timestamp.UnixMicro()
	if p.rateStart == 0 {
		p.rateStart = ts
	}

	p.decoded = p.decoded[:0]
	p.parsers[firstLayer(lt, data)].DecodeLayers(data, &p.decoded)

	var vlan uint16
	if len(ci.AncillaryData) > 0 {
		if v, ok := ci.AncillaryData[0].(int); ok {
			vlan = uint16(v)
		}
	}
	var (
		mac      net.HardwareAddr
		src, dst netip.Addr
		l4       gopacket.LayerType
		frag     bool
	)
	for _, t := range p.decoded {
		switch t {
		case layers.LayerTypeEthernet:
			mac = p.eth.SrcMAC
		case layers.LayerTypeDot1Q:
			if vlan == 0 {
				vlan = p.dot1q.VLANIdentifier
			}
		case layers.LayerTypeARP:
			p.handleARP(ts)
			return
		case layers.LayerTypeIPv4:
			src, _ = netip.AddrFromSlice(p.ip4.SrcIP)
			dst, _ = netip.AddrFromSlice(p.ip4.DstIP)
			frag = p.ip4.FragOffset != 0
		case layers.LayerTypeIPv6:
			src, _ = netip.AddrFromSlice(p.ip6.SrcIP)
			dst, _ = netip.AddrFromSlice(p.ip6.DstIP)
		case layers.LayerTypeTCP, layers.LayerTypeUDP, layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			l4 = t
		}
	}
	if !src.IsValid() || !dst.IsValid() {
		return
	}
	src, dst = src.Unmap(), dst.Unmap()
	if len(p.ignore) > 0 && (p.ignore.ContainsAddr(src) || p.ignore.ContainsAddr(dst)) {
		return
	}

	// contatori dell'interfaccia
	nets := p.r.Nets()
	si, di := nets.ContainsAddr(src), nets.ContainsAddr(dst)
	n := uint64(ci.Length)
	p.rPkts++
	switch {
	case si && di:
		p.rInt += n
	case si:
		p.rOut += n
	case di:
		p.rIn += n
	}
	if frag || l4 == 0 {
		return
	}

	var (
		sp, dp  uint16
		proto   uint8
		flags   uint8
		payload []byte
		icmpTyp uint8
	)
	switch l4 {
	case layers.LayerTypeTCP:
		sp, dp, proto, flags, payload = uint16(p.tcp.SrcPort), uint16(p.tcp.DstPort), 6, tcpFlags(&p.tcp), p.tcp.Payload
	case layers.LayerTypeUDP:
		sp, dp, proto, payload = uint16(p.udp.SrcPort), uint16(p.udp.DstPort), 17, p.udp.Payload
	case layers.LayerTypeICMPv4:
		proto, icmpTyp = 1, p.icmp4.TypeCode.Type()
	case layers.LayerTypeICMPv6:
		proto, icmpTyp = 58, p.icmp6.TypeCode.Type()
		if icmpTyp >= 133 && icmpTyp <= 137 { // neighbor discovery: non è traffico applicativo
			return
		}
	}

	if proto == 17 {
		switch {
		case sp == 53 || dp == 53:
			p.handleDNS(src, dst, payload, us)
		case sp == 5353 && dp == 5353:
			p.handleMDNS(src, mac, payload, ts)
		case (sp == 67 || sp == 68) && (dp == 67 || dp == 68):
			p.handleDHCP(payload, ts)
		}
	}

	a, b := netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp)
	key := flowKey{a: a, b: b, proto: proto, vlan: vlan}
	if a.Compare(b) > 0 {
		key.a, key.b = b, a
	}
	f := p.flows[key]
	if f == nil {
		if len(p.flows) >= maxFlows {
			p.tableFul.Add(1)
			return
		}
		cliIsSrc := true
		switch {
		case proto == 6 && flags&fSYN != 0:
			cliIsSrc = flags&fACK == 0
		case proto == 1 || proto == 58:
			cliIsSrc = icmpTyp != 0 && icmpTyp != 129 // le risposte all'eco partono dal "server"
		case sp < dp:
			cliIsSrc = false // la porta più bassa è di solito quella del servizio
		}
		f = &flow{cli: a, srv: b, proto: proto, vlan: vlan, start: ts, dport: dp}
		if !cliIsSrc {
			f.cli, f.srv, f.dport = b, a, sp
		}
		if proto == 1 || proto == 58 {
			f.dport = uint16(icmpTyp)
		}
		p.flows[key] = f
	}
	f.last = ts
	dir := 0
	if a != f.cli {
		dir = 1
	}
	if dir == 0 {
		f.bOut += n
		f.pOut++
	} else {
		f.bIn += n
		f.pIn++
	}

	if proto != 6 {
		if dir == 1 {
			f.est = true
		}
		return
	}

	// TCP
	f.flags |= flags
	if dir == 1 && (flags&fRST == 0 || flags&fSYN != 0) {
		f.est = true
	}
	if flags&fRST != 0 {
		f.closed = true
	}
	if flags&fFIN != 0 {
		f.fins |= 1 << dir
		if f.fins == 3 {
			f.closed = true
		}
	}
	switch {
	case dir == 0 && flags&fSYN != 0 && flags&fACK == 0 && f.synUS == 0:
		f.synUS = us
	case dir == 1 && flags&(fSYN|fACK) == fSYN|fACK && f.synUS > 0 && f.synAckUS == 0:
		f.synAckUS = us
	case dir == 0 && flags&fACK != 0 && flags&fSYN == 0 && f.synAckUS > 0 && f.rtt == 0:
		f.rtt = float32(us-f.synUS) / 1000
	}
	if len(payload) == 0 {
		return
	}
	seq := p.tcp.Seq
	end := seq + uint32(len(payload))
	if f.haveNext[dir] && int32(end-f.next[dir]) <= 0 {
		f.retrans++
	} else {
		f.next[dir], f.haveNext[dir] = end, true
	}
	p.dissectTCP(f, dir, seq, payload, ts)
}

// ---------------------------------------------------------------- TCP: TLS e HTTP

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}

func (p *proc) dissectTCP(f *flow, dir int, seq uint32, payload []byte, ts int64) {
	if f.tlsState == 0 && dir == 0 {
		if isTLSStart(payload) {
			f.tlsState = 1
		} else {
			f.tlsState = 2
		}
	}
	if f.tlsState == 1 {
		p.collectTLS(f, dir, seq, payload, ts)
		return
	}
	switch {
	case dir == 0 && len(f.http) < 16:
		for _, m := range httpMethods {
			if bytes.HasPrefix(payload, m) {
				if h, ok := parseHTTPRequest(payload); ok {
					h.TS, h.Client, h.Server, h.Port = ts, f.cli.Addr().String(), f.srv.Addr().String(), f.srv.Port()
					if h.Host == "" {
						h.Host = h.Server
					} else if f.domain == "" && !isIP(h.Host) {
						f.domain = h.Host
					}
					f.http = append(f.http, h)
				}
				break
			}
		}
	case dir == 1 && len(f.http) > 0 && bytes.HasPrefix(payload, []byte("HTTP/1.")) && len(payload) >= 12:
		if code, err := strconv.Atoi(string(payload[9:12])); err == nil {
			h := f.http[0]
			f.http = f.http[1:]
			h.Status = uint16(code)
			p.out.put(func(b *model.Batch) { b.HTTP = append(b.HTTP, h) })
		}
	}
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

func parseHTTPRequest(p []byte) (model.HTTP, bool) {
	if i := bytes.Index(p, []byte("\r\n\r\n")); i >= 0 {
		p = p[:i]
	}
	lines := strings.Split(string(p), "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return model.HTTP{}, false
	}
	h := model.HTTP{Method: parts[0], URI: clip(parts[1], 1024)}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "host":
			host := strings.ToLower(v)
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			h.Host = clip(host, 255)
		case "user-agent":
			h.UserAgent = clip(v, 512)
		}
	}
	return h, true
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// collectTLS ricompone l'inizio dei due versi (in ordine, senza buchi) e ne legge l'handshake.
func (p *proc) collectTLS(f *flow, dir int, seq uint32, payload []byte, ts int64) {
	if f.tlsDone[dir] {
		return
	}
	if !f.tlsInit[dir] {
		f.tlsInit[dir], f.tlsNext[dir] = true, seq
	}
	switch d := int32(seq - f.tlsNext[dir]); {
	case d < 0: // ritrasmissione già vista
		return
	case d > 0: // manca un pezzo: si rinuncia a questo verso
		f.tlsDone[dir], f.tlsBuf[dir] = true, nil
		p.tlsMaybeEmit(f)
		return
	}
	limit := tlsServerMax
	if dir == 0 {
		limit = tlsClientMax
	}
	f.tlsBuf[dir] = append(f.tlsBuf[dir], payload...)
	f.tlsNext[dir] += uint32(len(payload))

	if f.tls == nil {
		f.tls = &model.TLS{TS: ts, Client: f.cli.Addr().String(), Server: f.srv.Addr().String(), Port: f.srv.Port()}
	}
	t := f.tls
	stop := tlsHandshakes(f.tlsBuf[dir], func(typ byte, body []byte) {
		switch {
		case dir == 0 && typ == 1:
			if ch, err := parseClientHello(body); err == nil {
				t.SNI, t.JA4, t.Version = ch.SNI, ch.JA4, versionName(ch.Version)
				if len(ch.ALPN) > 0 {
					t.ALPN = ch.ALPN[0]
				}
				if ch.SNI != "" {
					f.domain = ch.SNI
				}
				f.tlsDone[0] = true
			}
		case dir == 1 && typ == 2:
			if sh, err := parseServerHello(body); err == nil {
				t.Version = versionName(sh.Version)
				if sh.ALPN != "" {
					t.ALPN = sh.ALPN
				}
				if sh.Version == 0x0304 { // il resto è cifrato
					f.tlsDone[1] = true
				}
			}
		case dir == 1 && typ == 11:
			if c, err := parseCertificate(body); err == nil {
				t.CertSubject, t.CertIssuer, t.CertNotAfter, t.SelfSigned = clip(c.Subject, 512), clip(c.Issuer, 512), c.NotAfter, c.SelfSigned
			}
		case dir == 1 && typ == 14: // ServerHelloDone
			f.tlsDone[1] = true
		}
	})
	if stop || len(f.tlsBuf[dir]) >= limit {
		f.tlsDone[dir] = true
	}
	if f.tlsDone[dir] {
		f.tlsBuf[dir] = nil
	}
	p.tlsMaybeEmit(f)
}

func (p *proc) tlsMaybeEmit(f *flow) {
	if f.tlsSent || f.tls == nil || !f.tlsDone[0] || !f.tlsDone[1] {
		return
	}
	p.emitTLS(f)
}

func (p *proc) emitTLS(f *flow) {
	if f.tlsSent || f.tls == nil || (f.tls.SNI == "" && f.tls.JA4 == "" && f.tls.CertSubject == "") {
		return
	}
	f.tlsSent, f.tlsState = true, 2
	f.tlsBuf = [2][]byte{}
	t := *f.tls
	p.out.put(func(b *model.Batch) { b.TLS = append(b.TLS, t) })
}

// ---------------------------------------------------------------- UDP: DNS, mDNS, DHCP

var rcodes = map[layers.DNSResponseCode]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

func dnsType(t layers.DNSType) string {
	s := t.String()
	if s == "" || strings.HasPrefix(s, "Unknown") {
		return "TYPE" + strconv.Itoa(int(t))
	}
	return s
}

func (p *proc) handleDNS(src, dst netip.Addr, payload []byte, us int64) {
	if p.dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback) != nil || len(p.dns.Questions) == 0 {
		return
	}
	d := &p.dns
	if !d.QR {
		if len(p.dnsPending) < 200_000 {
			p.dnsPending[dnsKey{src, dst, d.ID}] = us
		}
		return
	}
	k := dnsKey{dst, src, d.ID}
	var rtt float32
	if t, ok := p.dnsPending[k]; ok {
		rtt = float32(us-t) / 1000
		delete(p.dnsPending, k)
	}
	q := d.Questions[0]
	rc := rcodes[d.ResponseCode]
	if rc == "" {
		rc = "RCODE" + strconv.Itoa(int(d.ResponseCode))
	}
	rec := model.DNS{TS: us / 1000, Client: dst.String(), Server: src.String(), Query: clip(strings.ToLower(string(q.Name)), 255),
		QType: dnsType(q.Type), RCode: rc, RTT: rtt}
	for _, a := range d.Answers {
		if len(rec.Answers) >= 16 {
			break
		}
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				rec.Answers = append(rec.Answers, ip.Unmap().String())
			}
		case layers.DNSTypeCNAME:
			rec.Answers = append(rec.Answers, strings.ToLower(string(a.CNAME)))
		}
	}
	p.out.put(func(b *model.Batch) { b.DNS = append(b.DNS, rec) })
}

// handleMDNS ricava il nome dei dispositivi che si annunciano con mDNS (stampanti, Mac, telefoni...).
func (p *proc) handleMDNS(src netip.Addr, mac net.HardwareAddr, payload []byte, ts int64) {
	if p.dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback) != nil || !p.dns.QR {
		return
	}
	for _, a := range p.dns.Answers {
		if a.Type != layers.DNSTypeA && a.Type != layers.DNSTypeAAAA {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || ip.Unmap() != src {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSuffix(string(a.Name), "."), ".local")
		if name != "" && !strings.Contains(name, ".") {
			p.host(ts, src, mac, name, "", "mdns")
			return
		}
	}
}

func dhcpOS(class string) string {
	c := strings.ToLower(class)
	switch {
	case strings.HasPrefix(c, "msft"):
		return "Windows"
	case strings.HasPrefix(c, "android"):
		return "Android"
	case strings.HasPrefix(c, "dhcpcd"), strings.HasPrefix(c, "udhcp"):
		return "Linux"
	case strings.Contains(c, "cisco"):
		return "Cisco"
	}
	return ""
}

func (p *proc) handleDHCP(payload []byte, ts int64) {
	d := &p.dhcp
	if d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback) != nil {
		return
	}
	var mt layers.DHCPMsgType
	var host, class string
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptMessageType:
			if len(o.Data) == 1 {
				mt = layers.DHCPMsgType(o.Data[0])
			}
		case layers.DHCPOptHostname:
			host = clip(string(o.Data), 64)
		case layers.DHCPOptClassID:
			class = clip(string(o.Data), 128)
		}
	}
	mac := d.ClientHWAddr.String()
	switch mt {
	case layers.DHCPMsgTypeDiscover, layers.DHCPMsgTypeRequest, layers.DHCPMsgTypeInform:
		if host != "" || class != "" {
			if len(p.dhcpSeen) > 50_000 {
				clear(p.dhcpSeen)
			}
			old := p.dhcpSeen[mac]
			p.dhcpSeen[mac] = dhcpInfo{host: firstNonEmpty(host, old.host), class: firstNonEmpty(class, old.class)}
		}
	case layers.DHCPMsgTypeAck:
		ip, _ := netip.AddrFromSlice(d.YourClientIP)
		if !ip.IsValid() || ip.Unmap().IsUnspecified() {
			ip, _ = netip.AddrFromSlice(d.ClientIP)
		}
		info := p.dhcpSeen[mac]
		p.host(ts, ip.Unmap(), d.ClientHWAddr, firstNonEmpty(info.host, host), dhcpOS(info.class), "dhcp")
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- ARP e dispositivi

func (p *proc) handleARP(ts int64) {
	ip, ok := netip.AddrFromSlice(p.arp.SourceProtAddress)
	if !ok || len(p.arp.SourceHwAddress) != 6 {
		return
	}
	p.host(ts, ip.Unmap(), net.HardwareAddr(p.arp.SourceHwAddress), "", "", "arp")
}

// host segnala un dispositivo, al massimo una volta ogni 10 minuti per la stessa combinazione.
func (p *proc) host(ts int64, ip netip.Addr, mac net.HardwareAddr, name, os, source string) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || !p.r.Nets().ContainsAddr(ip) {
		return
	}
	m := ""
	if len(mac) == 6 && !bytes.Equal(mac, []byte{0, 0, 0, 0, 0, 0}) && mac[0]&1 == 0 {
		m = mac.String()
	}
	key := ip.String() + "|" + m + "|" + name
	if last, ok := p.hostSeen[key]; ok && ts-last < hostRepeat {
		return
	}
	if len(p.hostSeen) > 200_000 {
		clear(p.hostSeen)
	}
	p.hostSeen[key] = ts
	h := model.Host{TS: ts, IP: ip.String(), MAC: m, Hostname: name, OS: os, Source: source}
	p.out.put(func(b *model.Batch) { b.Hosts = append(b.Hosts, h) })
}

// ---------------------------------------------------------------- scadenze e contatori

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	}
	return strconv.Itoa(int(p))
}

func (p *proc) export(f *flow, final bool) {
	mf := model.Flow{TS: f.start, End: f.last, VLAN: f.vlan, Proto: protoName(f.proto),
		SrcIP: f.cli.Addr().String(), SrcPort: f.cli.Port(), DstIP: f.srv.Addr().String(), DstPort: f.dport,
		Domain: f.domain, BytesOut: f.bOut, BytesIn: f.bIn, PktsOut: f.pOut, PktsIn: f.pIn, Est: f.est, RTT: f.rtt, Retrans: f.retrans}
	if f.proto == 6 {
		mf.Flags = flagString(f.flags)
	}
	if f.proto == 1 || f.proto == 58 {
		mf.SrcPort = 0
	}
	if f.bOut+f.bIn > 0 {
		p.out.put(func(b *model.Batch) { b.Flows = append(b.Flows, mf) })
	}
	if final {
		p.emitTLS(f)
		for _, h := range f.http {
			p.out.put(func(b *model.Batch) { b.HTTP = append(b.HTTP, h) })
		}
		f.http = nil
		return
	}
	// esportazione parziale di un flusso lungo: i contatori ripartono
	f.start, f.bOut, f.bIn, f.pOut, f.pIn, f.retrans, f.flags = f.last, 0, 0, 0, 0, 0, 0
}

// tick chiude i flussi scaduti e, ogni 5 secondi, invia i contatori. now è in ms
// (orologio di sistema in cattura, tempo dei pacchetti nella lettura di file).
func (p *proc) tick(now int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastTick = now
	for k, f := range p.flows {
		idle := now - f.last
		var limit int64
		switch {
		case f.proto == 6 && f.closed:
			limit = tcpClosed
		case f.proto == 6:
			limit = tcpIdle
		case f.proto == 17 && (f.srv.Port() == 53 || f.srv.Port() == 5353):
			limit = dnsIdle
		case f.proto == 17:
			limit = udpIdle
		default:
			limit = icmpIdle
		}
		if idle > limit {
			p.export(f, true)
			delete(p.flows, k)
		} else if now-f.start > activeExport {
			p.export(f, false)
		}
	}
	for k, t := range p.dnsPending {
		if now*1000-t > 10_000_000 {
			delete(p.dnsPending, k)
		}
	}
	if p.rateStart == 0 {
		p.rateStart = now
	}
	if now-p.rateStart >= rateEvery {
		var drops uint64
		if p.drops != nil {
			drops = p.drops()
		}
		r := model.Rate{TS: p.rateStart, Seconds: float64(now-p.rateStart) / 1000, BytesIn: p.rIn, BytesOut: p.rOut, BytesInternal: p.rInt,
			Packets: p.rPkts, Flows: uint64(len(p.flows)), Drops: drops}
		p.out.put(func(b *model.Batch) { b.Rates = append(b.Rates, r) })
		p.rateStart, p.rIn, p.rOut, p.rInt, p.rPkts = now, 0, 0, 0, 0
	}
}

// flushAll chiude tutti i flussi (fine di un file o arresto del sensore).
func (p *proc) flushAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, f := range p.flows {
		p.export(f, true)
		delete(p.flows, k)
	}
}
