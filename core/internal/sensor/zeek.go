package sensor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperwave/internal/model"
)

// Modalità zeek: il sensore legge i log di un'installazione Zeek esistente invece di catturare.
// Dal vivo segue i file della cartella current; con -file importa log già ruotati (anche .gz)
// come storico. Vanno bene sia il formato TSV classico sia JSON (LogAscii::use_json).

// zeekKinds sono i log letti; gli altri file della cartella vengono ignorati.
var zeekKinds = []string{"conn", "dns", "ssl", "http", "ssh", "rdp", "ntlm", "kerberos", "smb_mapping", "notice", "dhcp"}

// zeekLog interpreta le righe di un file; per il TSV conserva l'intestazione.
type zeekLog struct {
	kind   string
	fields []string
	sep    string
	setSep string
}

func newZeekLog(kind string) *zeekLog { return &zeekLog{kind: kind, sep: "\t", setSep: ","} }

type zrec map[string]any

// parse legge una riga; le righe di intestazione aggiornano lo stato e restituiscono false.
func (z *zeekLog) parse(line string) (zrec, bool) {
	line = strings.TrimRight(line, "\r\n")
	switch {
	case line == "":
		return nil, false
	case line[0] == '{':
		var m zrec
		if json.Unmarshal([]byte(line), &m) != nil {
			return nil, false
		}
		return m, true
	case line[0] == '#':
		key, val, _ := strings.Cut(line[1:], z.sep)
		if key == line[1:] { // "#separator \x09" usa uno spazio
			key, val, _ = strings.Cut(line[1:], " ")
		}
		switch key {
		case "separator":
			if s, err := strconv.Unquote(`"` + strings.TrimSpace(val) + `"`); err == nil && s != "" {
				z.sep = s
			}
		case "set_separator":
			z.setSep = val
		case "fields":
			z.fields = strings.Split(val, z.sep)
		}
		return nil, false
	}
	if z.fields == nil {
		return nil, false // TSV senza intestazione: non si sa a cosa corrispondono le colonne
	}
	vals := strings.Split(line, z.sep)
	m := make(zrec, len(z.fields))
	for i, f := range z.fields {
		if i < len(vals) && vals[i] != "-" && vals[i] != "(empty)" {
			if strings.Contains(vals[i], `\x`) {
				vals[i] = zeekUnescape(vals[i])
			}
			m[f] = vals[i]
		}
	}
	m["_set"] = z.setSep
	return m, true
}

// zeekUnescape decodifica le sequenze \xHH che Zeek usa per i caratteri non stampabili.
func zeekUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (m zrec) s(k string) string {
	switch v := m[k].(type) {
	case string:
		if v == "-" || v == "(empty)" {
			return ""
		}
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "T"
		}
		return "F"
	}
	return ""
}

func (m zrec) n(k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func (m zrec) u(k string) uint64 { return uint64(max(m.n(k), 0)) }

func (m zrec) b(k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "T" || v == "true"
	}
	return false
}

func (m zrec) has(k string) bool { _, ok := m[k]; return ok && m.s(k) != "" }

func (m zrec) list(k string) []string {
	switch v := m[k].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, fmt.Sprint(x))
			}
		}
		return out
	case string:
		if v == "" || v == "-" || v == "(empty)" {
			return nil
		}
		sep, _ := m["_set"].(string)
		if sep == "" {
			sep = ","
		}
		return strings.Split(v, sep)
	}
	return nil
}

// ts restituisce l'ora in ms: Zeek scrive secondi con decimali o, in JSON, anche ISO 8601.
func (m zrec) ts(k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v * 1000)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return int64(f * 1000)
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

func (m zrec) addr(k string) string {
	a, err := netip.ParseAddr(m.s(k))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func (m zrec) port(k string) uint16 { return uint16(m.u(k)) }

var zeekServices = map[string]string{"ssl": "TLS", "http": "HTTP", "dns": "DNS", "ssh": "SSH", "rdp": "RDP", "smb": "SMB",
	"krb": "Kerberos", "krb_tcp": "Kerberos", "quic": "QUIC", "ftp": "FTP", "smtp": "SMTP", "dhcp": "DHCP", "ntp": "NTP",
	"snmp": "SNMP", "mysql": "MySQL", "ldap": "LDAP", "ldap_tcp": "LDAP", "sip": "SIP", "irc": "IRC", "dce_rpc": "DCE/RPC"}

// zeekFlags ricava i flag TCP dalla storia della connessione (campo history).
func zeekFlags(h string) uint8 {
	var f uint8
	for _, c := range strings.ToLower(h) {
		switch c {
		case 's':
			f |= fSYN
		case 'h':
			f |= fSYN | fACK
		case 'a':
			f |= fACK
		case 'd':
			f |= fPSH
		case 'f':
			f |= fFIN
		case 'r':
			f |= fRST
		}
	}
	return f
}

// zeekConn converte una riga di conn.log in un flusso.
func zeekConn(m zrec) (model.Flow, bool) {
	src, dst := m.addr("id.orig_h"), m.addr("id.resp_h")
	if src == "" || dst == "" {
		return model.Flow{}, false
	}
	ts := m.ts("ts")
	f := model.Flow{TS: ts, End: ts + int64(m.n("duration")*1000), SrcIP: src, DstIP: dst,
		SrcPort: m.port("id.orig_p"), DstPort: m.port("id.resp_p"), VLAN: uint16(m.u("vlan")) & 0x0fff}
	switch p := strings.ToLower(m.s("proto")); p {
	case "tcp", "udp":
		f.Proto = strings.ToUpper(p)
	case "icmp":
		f.Proto = "ICMP"
		if strings.Contains(src, ":") {
			f.Proto = "ICMPv6"
		}
		f.DstPort, f.SrcPort = f.SrcPort, 0 // Zeek mette il tipo ICMP nella porta di origine
	default:
		return model.Flow{}, false
	}
	f.BytesOut, f.BytesIn = m.u("orig_ip_bytes"), m.u("resp_ip_bytes")
	if f.BytesOut == 0 && f.BytesIn == 0 {
		f.BytesOut, f.BytesIn = m.u("orig_bytes"), m.u("resp_bytes")
	}
	f.PktsOut, f.PktsIn = uint32(min(m.u("orig_pkts"), 1<<32-1)), uint32(min(m.u("resp_pkts"), 1<<32-1))
	switch m.s("conn_state") {
	case "S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR":
	default:
		f.Est = f.PktsIn > 0 || f.BytesIn > 0
	}
	if f.Proto == "TCP" {
		f.Flags = flagString(zeekFlags(m.s("history")))
	}
	if svc, _, _ := strings.Cut(m.s("service"), ","); svc != "" {
		f.App = zeekServices[strings.ToLower(svc)]
	}
	return f, true
}

func zeekVersion(v string) string {
	if rest, ok := strings.CutPrefix(v, "TLSv"); ok && len(rest) == 2 {
		return "TLSv" + rest[:1] + "." + rest[1:]
	}
	return v
}

func ifThen(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// zeekRecord converte una riga del log kind; restituisce nil se non c'è niente da inviare.
func zeekRecord(kind string, m zrec) func(b *model.Batch) {
	ts := m.ts("ts")
	cli, srv, port := m.addr("id.orig_h"), m.addr("id.resp_h"), m.port("id.resp_p")
	sess := func(proto string) model.Session {
		return model.Session{TS: ts, Client: cli, Server: srv, Port: port, Transport: "tcp", Protocol: proto}
	}
	switch kind {
	case "conn":
		if f, ok := zeekConn(m); ok {
			return func(b *model.Batch) { b.Flows = append(b.Flows, f) }
		}
	case "dns":
		if cli == "" || m.s("query") == "" {
			return nil
		}
		d := model.DNS{TS: ts, Client: cli, Server: srv, Query: clip(strings.ToLower(m.s("query")), 253),
			QType: firstOf(m.s("qtype_name"), m.s("qtype")), RCode: firstOf(m.s("rcode_name"), m.s("rcode")), RTT: float32(m.n("rtt") * 1000)}
		for _, a := range m.list("answers") {
			if len(d.Answers) < 16 {
				d.Answers = append(d.Answers, clip(a, 253))
			}
		}
		return func(b *model.Batch) { b.DNS = append(b.DNS, d) }
	case "ssl":
		if cli == "" {
			return nil
		}
		t := model.TLS{TS: ts, Client: cli, Server: srv, Port: port, SNI: clip(strings.ToLower(m.s("server_name")), 253),
			Version: zeekVersion(m.s("version")), ALPN: clip(m.s("next_protocol"), 64), JA4: clip(m.s("ja4"), 64),
			CertSubject: clip(m.s("subject"), 255), CertIssuer: clip(m.s("issuer"), 255)}
		if strings.EqualFold(m.s("id.proto"), "udp") || strings.Contains(strings.ToLower(m.s("version")), "quic") {
			t.Transport = "quic"
		}
		t.SelfSigned = t.CertSubject != "" && t.CertSubject == t.CertIssuer
		return func(b *model.Batch) { b.TLS = append(b.TLS, t) }
	case "http":
		if cli == "" {
			return nil
		}
		h := model.HTTP{TS: ts, Client: cli, Server: srv, Port: port, Method: clip(m.s("method"), 16), Host: clip(strings.ToLower(m.s("host")), 253),
			URI: clip(m.s("uri"), 1024), Status: uint16(m.u("status_code")), UserAgent: clip(m.s("user_agent"), 512)}
		return func(b *model.Batch) { b.HTTP = append(b.HTTP, h) }
	case "ssh":
		if cli == "" {
			return nil
		}
		s := sess("ssh")
		s.ClientSW, s.ServerSW = clip(m.s("client"), 255), clip(m.s("server"), 255)
		s.Hash, s.ServerHash = clip(m.s("hassh"), 64), clip(m.s("hasshServer"), 64)
		switch {
		case m.has("auth_success") && m.b("auth_success"):
			s.Info = "accesso riuscito"
		case m.has("auth_success"):
			s.Info = fmt.Sprintf("accesso non riuscito (%d tentativi)", m.u("auth_attempts"))
		}
		var weak []string
		for _, k := range []string{"kex_alg", "cipher_alg", "mac_alg", "host_key_alg"} {
			for _, w := range sshWeak {
				if strings.HasPrefix(m.s(k), w) {
					weak = append(weak, m.s(k))
				}
			}
		}
		switch {
		case m.u("version") == 1:
			s.Weak = "SSH versione 1"
		case len(weak) > 0:
			s.Weak = clip("negoziati algoritmi deboli: "+strings.Join(weak, ", "), 255)
		}
		return func(b *model.Batch) { b.Sessions = append(b.Sessions, s) }
	case "rdp":
		if cli == "" {
			return nil
		}
		s := sess("rdp")
		s.User, s.Host = clip(m.s("cookie"), 255), clip(m.s("client_name"), 255)
		sp := m.s("security_protocol")
		var info []string
		if sp != "" {
			info = append(info, "scelto: "+sp)
		}
		if r := m.s("result"); r != "" {
			info = append(info, "esito: "+r)
		}
		s.Info = strings.Join(info, "; ")
		switch sp {
		case "RDP":
			s.Weak = "sicurezza RDP standard, senza TLS"
		case "SSL":
			s.Weak = "TLS senza autenticazione a livello di rete (NLA)"
		}
		return func(b *model.Batch) { b.Sessions = append(b.Sessions, s) }
	case "ntlm":
		if cli == "" || (m.s("username") == "" && m.s("domainname") == "") {
			return nil
		}
		s := sess("ntlm")
		s.Auth, s.User, s.Domain, s.Host = "NTLM", clip(m.s("username"), 255), clip(m.s("domainname"), 255), clip(m.s("hostname"), 255)
		if m.has("success") {
			s.Info = ifThen(m.b("success"), "accesso riuscito", "accesso non riuscito")
		}
		return func(b *model.Batch) { b.Sessions = append(b.Sessions, s) }
	case "kerberos":
		if cli == "" {
			return nil
		}
		s := sess("kerberos")
		if !strings.EqualFold(m.s("id.proto"), "tcp") { // Kerberos viaggia di solito su UDP; kerberos.log non lo dice
			s.Transport = "udp"
		}
		s.Auth = "Kerberos"
		user, realm, _ := strings.Cut(m.s("client"), "/")
		if realm == "" {
			user, realm, _ = strings.Cut(m.s("client"), "@")
		}
		s.User, s.Domain, s.Host = clip(user, 255), clip(realm, 255), clip(m.s("service"), 255)
		req := m.s("request_type") + "-REQ"
		info := []string{req}
		switch {
		case m.has("error_msg"):
			info = append(info, "errore: "+m.s("error_msg"))
		case m.b("success"):
			info = append(info, m.s("request_type")+"-REP"+ifThen(m.s("cipher") != "", ", ticket "+m.s("cipher"), ""))
		}
		s.Info = clip(strings.Join(info, " → "), 512)
		if c := strings.ToLower(m.s("cipher")); strings.HasPrefix(c, "rc4") || strings.HasPrefix(c, "des") {
			s.Weak = "ticket cifrato con " + c
		}
		return func(b *model.Batch) { b.Sessions = append(b.Sessions, s) }
	case "smb_mapping":
		if cli == "" || m.s("path") == "" {
			return nil
		}
		s := sess("smb")
		s.Info = clip("condivisioni: "+m.s("path")+ifThen(m.s("share_type") != "", " ("+m.s("share_type")+")", ""), 512)
		return func(b *model.Batch) { b.Sessions = append(b.Sessions, s) }
	case "notice":
		msg := m.s("msg")
		if msg == "" {
			return nil
		}
		e := model.Event{TS: ts, Kind: "ids", Severity: "medium", Title: clip(msg, 300), SrcIP: firstOf(m.addr("src"), cli),
			DstIP: firstOf(m.addr("dst"), srv), DstPort: uint16(m.u("p")), Signature: clip(m.s("note"), 300), Category: "Zeek notice",
			Detail: map[string]any{"source": "zeek", "sub": clip(m.s("sub"), 300), "uid": m.s("uid")}}
		if e.DstPort == 0 {
			e.DstPort = port
		}
		return func(b *model.Batch) { b.Events = append(b.Events, e) }
	case "dhcp":
		ip := firstOf(m.addr("assigned_addr"), m.addr("client_addr"))
		if ip == "" || ip == "0.0.0.0" {
			return nil
		}
		h := model.Host{TS: ts, IP: ip, MAC: strings.ToLower(m.s("mac")), Hostname: clip(firstOf(m.s("host_name"), m.s("client_fqdn")), 253), Source: "dhcp"}
		return func(b *model.Batch) { b.Hosts = append(b.Hosts, h) }
	}
	return nil
}

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// zeekKind ricava il tipo di log dal nome del file: conn.log, conn.09:00:00-10:00:00.log.gz...
func zeekKind(path string) string {
	k, _, _ := strings.Cut(filepath.Base(path), ".")
	for _, z := range zeekKinds {
		if k == z {
			return k
		}
	}
	return ""
}

// rateAcc calcola i contatori di banda a partire dai flussi conclusi.
type rateAcc struct {
	mu                 sync.Mutex
	start              int64
	in, out, int, pkts uint64
	flows              uint64
}

func (a *rateAcc) add(nets interface{ Contains(string) bool }, f model.Flow) {
	si, di := nets.Contains(f.SrcIP), nets.Contains(f.DstIP)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pkts += uint64(f.PktsOut) + uint64(f.PktsIn)
	a.flows++
	switch {
	case si && di:
		a.int += f.BytesOut + f.BytesIn
	case si:
		a.out += f.BytesOut
		a.in += f.BytesIn
	case di:
		a.in += f.BytesOut
		a.out += f.BytesIn
	}
}

func (a *rateAcc) take(now int64) (model.Rate, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.start == 0 {
		a.start = now
		return model.Rate{}, false
	}
	if now-a.start < rateEvery {
		return model.Rate{}, false
	}
	r := model.Rate{TS: a.start, Seconds: float64(now-a.start) / 1000, BytesIn: a.in, BytesOut: a.out, BytesInternal: a.int, Packets: a.pkts, Flows: a.flows}
	a.start, a.in, a.out, a.int, a.pkts, a.flows = now, 0, 0, 0, 0, 0
	return r, true
}

// openText apre un file di testo, anche compresso con gzip.
func openText(path string) (io.Reader, io.Closer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return zr, f, nil
	}
	return br, f, nil
}

// eachLine chiama fn per ogni riga del file (anche lunghissima); si ferma se ctx viene annullato.
func eachLine(ctx context.Context, path string, fn func(line string)) error {
	rd, closer, err := openText(path)
	if err != nil {
		return err
	}
	defer closer.Close()
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() && ctx.Err() == nil {
		fn(sc.Text())
	}
	return sc.Err()
}

func (r *Runner) runZeek(ctx context.Context) error {
	if len(r.cfg.Files) > 0 {
		return r.importZeek(ctx)
	}
	out := newSink(r, false)
	records := make([]atomic.Uint64, len(zeekKinds))
	for i, k := range zeekKinds {
		r.addStat("zeek_"+k, func() any { return records[i].Load() })
	}
	var rates rateAcc
	dir := r.cfg.ZeekDir
	if _, err := os.Stat(filepath.Join(dir, "conn.log")); err != nil {
		r.log.Warn("conn.log di Zeek non ancora presente: controllare HW_ZEEK_DIR", "cartella", dir)
	}
	r.log.Info("lettura dei log di Zeek", "cartella", dir)
	var wg sync.WaitGroup
	for i, kind := range zeekKinds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			z := newZeekLog(kind)
			r.tailFile(ctx, filepath.Join(dir, kind+".log"), tailOpts{header: true, quiet: true}, func(line string) {
				m, ok := z.parse(line)
				if !ok {
					return
				}
				if kind == "conn" {
					if f, ok := zeekConn(m); ok {
						rates.add(r.Nets(), f)
					}
				}
				if fn := zeekRecord(kind, m); fn != nil {
					records[i].Add(1)
					out.put(fn)
				}
			})
		}()
	}
	if r.cfg.SuricataEve != "" {
		wg.Add(1)
		go func() { defer wg.Done(); r.tailSuricata(ctx, out) }()
	}
	sctx, stopSink := context.WithCancel(context.Background())
	var sinkDone sync.WaitGroup
	sinkDone.Add(1)
	go func() { defer sinkDone.Done(); out.loop(sctx, 5*time.Second) }()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			stopSink()
			sinkDone.Wait()
			fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out.flush(fctx)
			cancel()
			return nil
		case now := <-t.C:
			if rt, ok := rates.take(now.UnixMilli()); ok {
				out.put(func(b *model.Batch) { b.Rates = append(b.Rates, rt) })
			}
		}
	}
}

// importZeek invia come storico i log indicati con -file.
func (r *Runner) importZeek(ctx context.Context) error {
	if !r.live.Load() {
		return fmt.Errorf("il live è spento sull'hub: i dati verrebbero scartati")
	}
	out := newSink(r, true)
	total := 0
	for _, path := range expandDirs(r.cfg.Files) {
		kind := zeekKind(path)
		if kind == "" {
			r.log.Warn("file ignorato: il nome non corrisponde a un log di Zeek supportato", "file", path, "supportati", strings.Join(zeekKinds, ", "))
			continue
		}
		z, n := newZeekLog(kind), 0
		err := eachLine(ctx, path, func(line string) {
			m, ok := z.parse(line)
			if !ok {
				return
			}
			if fn := zeekRecord(kind, m); fn != nil {
				n++
				out.put(fn)
				if pendingLen(out) >= model.MaxBatchRecords/2 {
					out.flush(ctx)
				}
			}
		})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		total += n
		r.log.Info("log di Zeek importato", "file", path, "tipo", kind, "record", n)
	}
	out.flush(ctx)
	r.log.Info("importazione completata", "record", total, "record_inviati", r.sent.Load(), "scartati", out.dropped.Load())
	return ctx.Err()
}

// expandDirs sostituisce ogni cartella con i file che contiene (per importare un giorno intero di log).
func expandDirs(paths []string) []string {
	var out []string
	for _, p := range paths {
		entries, err := os.ReadDir(p)
		if err != nil { // non è una cartella: lo si apre così com'è e l'eventuale errore esce dopo
			out = append(out, p)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && zeekKind(e.Name()) != "" {
				out = append(out, filepath.Join(p, e.Name()))
			}
		}
	}
	return out
}
