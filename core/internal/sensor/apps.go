package sensor

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"

	"hyperwave/internal/classify"
	"hyperwave/internal/model"
)

// Protocolli applicativi oltre a TLS e HTTP: SSH, RDP, SMB, Kerberos e le autenticazioni
// NTLM, ovunque passino. Si leggono solo i primi kilobyte di ogni verso, ricomposti in
// ordine: banner, negoziazioni e autenticazioni viaggiano tutti all'inizio della connessione.
// Il risultato è un record model.Session per flusso.

const (
	appClientMax = 16 << 10
	appServerMax = 8 << 10
	appMaxSegs   = 64     // segmenti con dati esaminati per flusso
	maxAppStates = 50_000 // flussi con buffer aperti nello stesso momento
)

// Nome dell'applicazione da dare al flusso quando il protocollo è riconosciuto dal contenuto.
var appNames = map[string]string{"ssh": "SSH", "rdp": "RDP", "smb": "SMB", "kerberos": "Kerberos", "quic": "QUIC"}

type appState struct {
	buf    [2][]byte
	next   [2]uint32
	init   [2]bool
	done   [2]bool
	closed bool
	kind   string
	s      model.Session
	have   bool // c'è qualcosa da inviare
	sent   bool

	sshBanner [2]bool
	rdpReq    uint32
	rdpSel    int64 // -1 finché il server non risponde
	smbOff    [2]int
	smbDial   uint16
	smbSign   string
	smbV1     bool
	anon      bool
	shares    []string
	krb       krbInfo
}

func (p *proc) appStart(f *flow, kind, transport string, ts int64) *appState {
	if f.app != nil {
		return f.app
	}
	if p.appStates >= maxAppStates {
		return nil
	}
	p.appStates++
	f.app = &appState{kind: kind, rdpSel: -1, s: model.Session{TS: ts, Client: f.cli.Addr().String(), Server: f.srv.Addr().String(),
		Port: f.srv.Port(), Transport: transport, Protocol: kind}}
	if n := appNames[kind]; n != "" {
		f.appName = n
	}
	return f.app
}

// appClose libera i buffer; il record resta per l'invio.
func (p *proc) appClose(f *flow) {
	if a := f.app; a != nil && !a.closed {
		a.closed, a.buf = true, [2][]byte{}
		p.appStates--
	}
}

func (p *proc) appEmit(f *flow) {
	a := f.app
	if a == nil || a.sent || !a.have {
		return
	}
	a.sent = true
	s := a.s
	p.out.put(func(b *model.Batch) { b.Sessions = append(b.Sessions, s) })
}

// appCheck invia il record quando entrambi i versi hanno detto tutto.
func (p *proc) appCheck(f *flow) {
	if a := f.app; a != nil && a.done[0] && a.done[1] {
		p.appEmit(f)
		p.appClose(f)
	}
}

// detectApp riconosce il protocollo dal primo segmento con dati di un verso.
func detectApp(f *flow, dir int, b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("SSH-")):
		return "ssh"
	case dir == 0 && len(b) >= 11 && b[0] == 3 && b[1] == 0 && b[5]&0xf0 == 0xe0:
		return "rdp"
	case len(b) >= 8 && b[0] == 0 && (bytes.Equal(b[4:8], []byte("\xfeSMB")) || bytes.Equal(b[4:8], []byte("\xffSMB"))):
		return "smb"
	case dir == 0 && f.srv.Port() == 88 && len(b) >= 6:
		return "kerberos"
	}
	return ""
}

// appTCP esamina un segmento TCP con dati di un flusso che non è TLS.
func (p *proc) appTCP(f *flow, dir int, seq uint32, payload []byte, ts int64) {
	if f.appSegs >= appMaxSegs {
		return
	}
	f.appSegs++
	a := f.app
	if a == nil {
		if f.appSeen&(1<<dir) != 0 {
			if dir == 0 {
				p.scanNTLM(f, payload, ts)
			}
			return
		}
		f.appSeen |= 1 << dir
		kind := detectApp(f, dir, payload)
		if kind == "" {
			if dir == 0 {
				p.scanNTLM(f, payload, ts)
			}
			return
		}
		if a = p.appStart(f, kind, "tcp", ts); a == nil {
			return
		}
	}
	if a.closed || a.done[dir] {
		return
	}
	if !a.init[dir] {
		a.init[dir], a.next[dir] = true, seq
	}
	switch d := int32(seq - a.next[dir]); {
	case d < 0: // ritrasmissione
		return
	case d > 0: // manca un pezzo
		a.done[dir] = true
		p.appCheck(f)
		return
	}
	limit := appServerMax
	if dir == 0 {
		limit = appClientMax
	}
	a.next[dir] += uint32(len(payload))
	if room := limit - len(a.buf[dir]); len(payload) >= room {
		payload = payload[:max(room, 0)]
		a.done[dir] = true
	}
	a.buf[dir] = append(a.buf[dir], payload...)
	switch a.kind {
	case "ssh":
		parseSSH(a, dir)
	case "rdp":
		if parseRDP(a, dir) && a.rdpSel > 0 {
			f.tlsState = 0 // dopo la negoziazione parte un handshake TLS: lo si legge
		}
	case "smb":
		parseSMB(a, dir)
	case "kerberos":
		b := a.buf[dir]
		if len(b) >= 4 {
			n := int(binary.BigEndian.Uint32(b) & 0x7fffffff)
			if n > limit {
				a.done[dir] = true
			} else if len(b) >= 4+n {
				krbMessage(a, b[4:4+n])
				a.done[dir] = true
			}
		}
	}
	p.appCheck(f)
}

// appUDP esamina un datagramma: Kerberos sulla porta 88, QUIC Initial su qualsiasi porta.
func (p *proc) appUDP(f *flow, dir int, payload []byte, ts int64) {
	if f.appSegs >= appMaxSegs {
		return
	}
	f.appSegs++
	if f.srv.Port() == 88 {
		a := f.app
		if a == nil {
			if dir != 0 {
				return
			}
			if a = p.appStart(f, "kerberos", "udp", ts); a == nil {
				return
			}
		}
		if a.closed || a.done[dir] {
			return
		}
		krbMessage(a, payload)
		a.done[dir] = true
		p.appCheck(f)
		return
	}
	if dir == 0 && (f.quic == nil || !f.quic.done) {
		p.quicPacket(f, payload, ts)
	}
}

// clean toglie i caratteri di controllo e taglia la stringa.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, s)
	return clip(strings.TrimSpace(s), n)
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// ---------------------------------------------------------------- SSH

// Algoritmi rotti: se il server li accetta ancora, è una configurazione da correggere.
var sshWeak = []string{"diffie-hellman-group1-sha1", "arcfour", "3des-cbc", "des-cbc", "blowfish-cbc", "hmac-md5", "hmac-sha1-96", "ssh-dss"}

func parseSSH(a *appState, dir int) {
	b := a.buf[dir]
	for !a.sshBanner[dir] {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if len(b) > 1024 {
				a.done[dir] = true
			}
			return
		}
		line := strings.TrimRight(string(b[:i]), "\r")
		b = b[i+1:]
		a.buf[dir] = b
		if !strings.HasPrefix(line, "SSH-") {
			if dir == 0 || len(a.buf[dir]) > 4096 { // solo il server può mandare righe prima del banner
				a.done[dir] = true
				return
			}
			continue
		}
		sw := clean(line, 255)
		if dir == 0 {
			a.s.ClientSW = sw
		} else {
			a.s.ServerSW = sw
		}
		if strings.HasPrefix(line, "SSH-1.") && !strings.HasPrefix(line, "SSH-1.99") {
			a.s.Weak = "SSH versione 1"
		}
		a.sshBanner[dir], a.have = true, true
	}
	if len(b) < 6 {
		return
	}
	plen := int(binary.BigEndian.Uint32(b))
	if plen < 2 || plen > 35000 {
		a.done[dir] = true
		return
	}
	if len(b) < 4+plen {
		return
	}
	a.done[dir] = true
	pad := int(b[4])
	if 4+plen-pad < 5+17 || b[5] != 20 { // 20 = SSH_MSG_KEXINIT
		return
	}
	r := &reader{b: b[5+17 : 4+plen-pad]}
	var lists [10]string
	for i := range lists {
		n := r.b
		if len(n) < 4 {
			return
		}
		l := int(binary.BigEndian.Uint32(n))
		r.b = n[4:]
		lists[i] = string(r.bytes(l))
		if r.bad {
			return
		}
	}
	kex, enc, mac, comp := lists[0], lists[2], lists[4], lists[6]
	if dir == 1 {
		enc, mac, comp = lists[3], lists[5], lists[7]
	}
	sum := md5.Sum([]byte(kex + ";" + enc + ";" + mac + ";" + comp))
	h := hex.EncodeToString(sum[:])
	if dir == 0 {
		a.s.Hash = h
		return
	}
	a.s.ServerHash = h
	var weak []string
	offered := strings.Split(strings.Join([]string{lists[0], lists[1], lists[3], lists[5]}, ","), ",")
	for _, w := range sshWeak {
		for _, o := range offered {
			if strings.HasPrefix(o, w) && !slices.Contains(weak, o) {
				weak = append(weak, o)
			}
		}
	}
	if len(weak) > 0 && a.s.Weak == "" {
		a.s.Weak = clip("il server accetta algoritmi deboli: "+strings.Join(weak, ", "), 255)
	}
}

// ---------------------------------------------------------------- RDP

var rdpProtos = []struct {
	bit  uint32
	name string
}{{1, "TLS"}, {2, "CredSSP (NLA)"}, {4, "RDSTLS"}, {8, "CredSSP esteso"}, {16, "Azure AD"}}

func rdpNames(v uint32) string {
	if v == 0 {
		return "RDP standard"
	}
	var out []string
	for _, p := range rdpProtos {
		if v&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	return strings.Join(out, ", ")
}

// parseRDP legge la richiesta di connessione X.224 (cookie con l'utente, protocolli
// richiesti) e la conferma del server (protocollo scelto). true quando il server ha risposto.
func parseRDP(a *appState, dir int) bool {
	b := a.buf[dir]
	if len(b) < 4 {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < 11 || n > 4096 {
		a.done[dir] = true
		return false
	}
	if len(b) < n {
		return false
	}
	a.done[dir] = true
	x := b[4:n]
	if dir == 0 {
		if x[1]&0xf0 != 0xe0 {
			return false
		}
		data := x[7:]
		if bytes.HasPrefix(data, []byte("Cookie: ")) {
			end := bytes.Index(data, []byte("\r\n"))
			if end < 0 {
				return false
			}
			if v, ok := bytes.CutPrefix(data[:end], []byte("Cookie: mstshash=")); ok {
				user := clean(string(v), 128)
				if d, u, ok := strings.Cut(user, `\`); ok {
					a.s.Domain, user = d, u
				}
				a.s.User = user
			}
			data = data[end+2:]
		}
		if len(data) >= 8 && data[0] == 1 {
			a.rdpReq = binary.LittleEndian.Uint32(data[4:8])
		}
		a.have = true
		a.s.Info = "richiesti: " + rdpNames(a.rdpReq)
		return false
	}
	if x[1]&0xf0 != 0xd0 {
		return false
	}
	data := x[7:]
	switch {
	case len(data) >= 8 && data[0] == 2:
		a.rdpSel = int64(binary.LittleEndian.Uint32(data[4:8]))
	case len(data) >= 8 && data[0] == 3:
		a.s.Info += fmt.Sprintf("; negoziazione rifiutata (codice %d)", binary.LittleEndian.Uint32(data[4:8]))
		a.have = true
		return true
	default:
		a.rdpSel = 0 // server senza negoziazione: sicurezza RDP standard
	}
	sel := uint32(a.rdpSel)
	a.s.Info += "; scelto: " + rdpNames(sel)
	switch {
	case sel == 0:
		a.s.Weak = "sicurezza RDP standard, senza TLS"
	case sel == 1:
		a.s.Weak = "TLS senza autenticazione a livello di rete (NLA)"
	}
	a.have = true
	return true
}

// ---------------------------------------------------------------- SMB

var smbDialects = map[uint16]string{0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}

func parseSMB(a *appState, dir int) {
	b := a.buf[dir]
	for {
		off := a.smbOff[dir]
		if len(b)-off < 4 {
			return
		}
		if b[off] != 0 {
			a.done[dir] = true
			return
		}
		n := int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
		if len(b)-off-4 < n {
			if n > appClientMax {
				a.done[dir] = true
			}
			return
		}
		a.smbOff[dir] = off + 4 + n
		if !smbMessage(a, dir, b[off+4:off+4+n]) {
			a.done[dir] = true
			return
		}
	}
}

// smbMessage legge un messaggio SMB; false quando il resto della connessione è illeggibile.
func smbMessage(a *appState, dir int, m []byte) bool {
	if len(m) < 4 {
		return false
	}
	switch string(m[:4]) {
	case "\xffSMB":
		a.have = true
		if len(m) > 4 && m[4] == 0x72 && dir == 1 { // il server risponde in SMB1
			a.smbV1 = true
		}
		if dir == 0 && len(m) > 4 && m[4] == 0x73 { // session setup
			ntlmInto(a, m)
		}
	case "\xfeSMB":
		if len(m) < 64 {
			return true
		}
		a.have = true
		cmd := binary.LittleEndian.Uint16(m[12:14])
		resp := binary.LittleEndian.Uint32(m[16:20])&1 != 0
		body := m[64:]
		switch {
		case cmd == 0 && resp && len(body) >= 6:
			if d := binary.LittleEndian.Uint16(body[4:6]); d != 0x02ff {
				a.smbDial = d
				a.smbSign = "firma facoltativa"
				if binary.LittleEndian.Uint16(body[2:4])&2 != 0 {
					a.smbSign = "firma obbligatoria"
				}
				a.done[1] = true
			}
		case cmd == 1 && !resp:
			ntlmInto(a, m)
		case cmd == 3 && !resp && len(body) >= 8:
			off, l := int(binary.LittleEndian.Uint16(body[4:6])), int(binary.LittleEndian.Uint16(body[6:8]))
			if off+l <= len(m) && l > 0 {
				path := utf16le(m[off : off+l])
				server, share, _ := strings.Cut(strings.TrimLeft(path, `\`), `\`)
				if a.s.Host == "" {
					a.s.Host = clean(server, 255)
				}
				if share = clean(share, 80); share != "" && !slices.Contains(a.shares, share) && len(a.shares) < 8 {
					a.shares = append(a.shares, share)
				}
			}
		}
	case "\xfdSMB", "\xfcSMB": // cifrato o compresso: oltre non si legge
		a.have = true
		smbSummary(a)
		return false
	default:
		return false
	}
	smbSummary(a)
	return true
}

func smbSummary(a *appState) {
	var parts []string
	switch {
	case a.smbV1:
		parts = append(parts, "SMB 1")
		a.s.Weak = "SMBv1"
	case a.smbDial != 0:
		d := smbDialects[a.smbDial]
		if d == "" {
			d = fmt.Sprintf("0x%04x", a.smbDial)
		}
		parts = append(parts, "SMB "+d, a.smbSign)
	}
	if len(a.shares) > 0 {
		parts = append(parts, "condivisioni: "+strings.Join(a.shares, ", "))
	}
	if a.anon {
		parts = append(parts, "accesso anonimo")
	}
	a.s.Info = clip(strings.Join(parts, " · "), 512)
}

// ---------------------------------------------------------------- NTLM

type ntlmAuth struct {
	user, domain, host string
	v1, anon           bool
}

var ntlmSig = []byte("NTLMSSP\x00\x03\x00\x00\x00")

// krb5OID è l'OID del meccanismo Kerberos (1.2.840.113554.1.2.2) dentro SPNEGO.
var krb5OID = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}

// findNTLMAuth cerca un messaggio NTLM AUTHENTICATE (tipo 3) e ne legge utente, dominio e
// workstation, che viaggiano in chiaro.
func findNTLMAuth(b []byte) (ntlmAuth, bool) {
	i := bytes.Index(b, ntlmSig)
	if i < 0 || len(b)-i < 64 {
		return ntlmAuth{}, false
	}
	m := b[i:]
	flags := binary.LittleEndian.Uint32(m[60:64])
	field := func(o int) ([]byte, bool) {
		l, off := int(binary.LittleEndian.Uint16(m[o:])), int(binary.LittleEndian.Uint32(m[o+4:]))
		if l == 0 {
			return nil, true
		}
		if off < 0 || off+l > len(m) {
			return nil, false
		}
		return m[off : off+l], true
	}
	str := func(x []byte) string {
		if flags&1 != 0 {
			return clean(utf16le(x), 128)
		}
		return clean(string(x), 128)
	}
	dom, ok1 := field(28)
	usr, ok2 := field(36)
	wks, ok3 := field(44)
	if !ok1 || !ok2 || !ok3 {
		return ntlmAuth{}, false
	}
	nt := int(binary.LittleEndian.Uint16(m[20:]))
	a := ntlmAuth{user: str(usr), domain: str(dom), host: str(wks), v1: nt == 24}
	a.anon = a.user == "" && nt <= 1
	return a, true
}

// ntlmInto riporta nel record un'autenticazione trovata nei dati del client.
func ntlmInto(a *appState, b []byte) {
	if n, ok := findNTLMAuth(b); ok {
		applyNTLM(a, n)
	} else if a.s.Auth == "" && bytes.Contains(b, krb5OID) {
		a.s.Auth = "Kerberos"
	}
}

func applyNTLM(a *appState, n ntlmAuth) {
	a.have = true
	a.s.User, a.s.Domain = n.user, n.domain
	if n.host != "" {
		a.s.Host = n.host
	}
	a.s.Auth = "NTLMv2"
	switch {
	case n.anon:
		a.s.Auth, a.anon = "NTLM", true
	case n.v1:
		a.s.Auth = "NTLMv1"
		if a.s.Weak == "" {
			a.s.Weak = "NTLMv1"
		}
	}
}

// scanNTLM cerca un'autenticazione NTLM in un segmento di un protocollo non riconosciuto
// (RPC, LDAP, SQL Server...): il messaggio di solito sta in un segmento solo.
func (p *proc) scanNTLM(f *flow, payload []byte, ts int64) {
	n, ok := findNTLMAuth(payload)
	if !ok {
		return
	}
	p.ntlmSession(f, n, "", ts)
}

func (p *proc) ntlmSession(f *flow, n ntlmAuth, carrier string, ts int64) {
	a := p.appStart(f, "ntlm", "tcp", ts)
	if a == nil || a.sent {
		return
	}
	if carrier == "" {
		carrier = classify.ByPort("TCP", f.srv.Port())
	}
	applyNTLM(a, n)
	var info []string
	if carrier != "" {
		info = append(info, "su "+carrier)
	}
	if a.anon {
		info = append(info, "accesso anonimo")
	}
	a.s.Info = strings.Join(info, " · ")
	a.done = [2]bool{true, true}
	p.appCheck(f)
}

// httpNTLM legge un'autenticazione NTLM dall'intestazione Authorization di una richiesta HTTP.
func httpNTLM(req []byte) (ntlmAuth, bool) {
	if i := bytes.Index(req, []byte("\r\n\r\n")); i >= 0 {
		req = req[:i]
	}
	for _, l := range bytes.Split(req, []byte("\r\n")) {
		k, v, ok := bytes.Cut(l, []byte(":"))
		if !ok || !strings.EqualFold(string(k), "authorization") {
			continue
		}
		scheme, tok, _ := strings.Cut(strings.TrimSpace(string(v)), " ")
		if !strings.EqualFold(scheme, "NTLM") && !strings.EqualFold(scheme, "Negotiate") {
			return ntlmAuth{}, false
		}
		blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tok))
		if err != nil {
			return ntlmAuth{}, false
		}
		return findNTLMAuth(blob)
	}
	return ntlmAuth{}, false
}

// ---------------------------------------------------------------- Kerberos

type krbInfo struct {
	req, rep        int // tipo dei messaggi: 10 AS-REQ, 12 TGS-REQ, 11 AS-REP, 13 TGS-REP, 30 KRB-ERROR
	etypes          []int
	preauth         bool
	tktEtype, errNo int
}

var krbMsgNames = map[int]string{10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP", 30: "errore"}

var krbErrors = map[int]string{
	6: "utente sconosciuto (KDC_ERR_C_PRINCIPAL_UNKNOWN)", 7: "servizio sconosciuto (KDC_ERR_S_PRINCIPAL_UNKNOWN)",
	12: "negato dai criteri (KDC_ERR_POLICY)", 14: "cifratura non supportata (KDC_ERR_ETYPE_NOSUPP)",
	18: "account disattivato o bloccato (KDC_ERR_CLIENT_REVOKED)", 23: "password scaduta (KDC_ERR_KEY_EXPIRED)",
	24: "password errata (KDC_ERR_PREAUTH_FAILED)", 25: "preautenticazione richiesta (KDC_ERR_PREAUTH_REQUIRED)",
	37: "orologio non allineato (KRB_AP_ERR_SKEW)", 68: "realm sbagliato (KDC_ERR_WRONG_REALM)",
}

var etypeNames = map[int]string{1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128", 18: "aes256", 19: "aes128-sha256",
	20: "aes256-sha384", 23: "rc4-hmac", 24: "rc4-hmac-exp", -128: "rc4-hmac-old", -135: "rc4-hmac-old"}

func weakEtype(e int) bool { return e == 1 || e == 3 || e == 23 || e == 24 || e == -128 || e == -135 }

func etypeName(e int) string {
	if n := etypeNames[e]; n != "" {
		return n
	}
	return fmt.Sprint(e)
}

// Lettura minima di DER: bastano TLV, tag di contesto e qualche tipo semplice.

type der struct {
	class, tag int
	body       []byte
}

func derRead(b []byte) (der, []byte, bool) {
	if len(b) < 2 || b[0]&0x1f == 0x1f {
		return der{}, nil, false
	}
	d := der{class: int(b[0] >> 6), tag: int(b[0] & 0x1f)}
	l := int(b[1])
	b = b[2:]
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < n {
			return der{}, nil, false
		}
		l = 0
		for _, c := range b[:n] {
			l = l<<8 | int(c)
		}
		b = b[n:]
	}
	if l > len(b) {
		return der{}, nil, false
	}
	d.body = b[:l]
	return d, b[l:], true
}

// derUnwrap restituisce il contenuto del primo TLV (per esempio una SEQUENCE).
func derUnwrap(b []byte) []byte {
	d, _, ok := derRead(b)
	if !ok {
		return nil
	}
	return d.body
}

// derFields raccoglie i campi [n] di una SEQUENCE.
func derFields(seq []byte) map[int][]byte {
	out := map[int][]byte{}
	for len(seq) > 0 {
		d, rest, ok := derRead(seq)
		if !ok {
			break
		}
		if d.class == 2 {
			out[d.tag] = d.body
		}
		seq = rest
	}
	return out
}

func derInt(b []byte) (int, bool) {
	d, _, ok := derRead(b)
	if !ok || d.tag != 2 || len(d.body) == 0 || len(d.body) > 4 {
		return 0, false
	}
	v := int(int8(d.body[0]))
	for _, c := range d.body[1:] {
		v = v<<8 | int(c)
	}
	return v, true
}

func derString(b []byte) string { return clean(string(derUnwrap(b)), 255) }

// principal legge un PrincipalName come "nome/istanza".
func principal(b []byte) string {
	f := derFields(derUnwrap(b))
	var parts []string
	list := derUnwrap(f[1])
	for len(list) > 0 {
		d, rest, ok := derRead(list)
		if !ok {
			break
		}
		parts = append(parts, string(d.body))
		list = rest
	}
	return clean(strings.Join(parts, "/"), 255)
}

func krbMessage(a *appState, msg []byte) {
	d, _, ok := derRead(msg)
	if !ok || d.class != 1 {
		return
	}
	k := &a.krb
	f := derFields(derUnwrap(d.body))
	switch d.tag {
	case 10, 12:
		k.req = d.tag
		pa := derUnwrap(f[3])
		for len(pa) > 0 {
			item, rest, ok := derRead(pa)
			if !ok {
				break
			}
			switch t, _ := derInt(derFields(item.body)[1]); t {
			case 2, 14, 15, 16, 136: // timestamp cifrato, PKINIT, FAST
				k.preauth = true
			}
			pa = rest
		}
		body := derFields(derUnwrap(f[4]))
		a.s.User, a.s.Domain, a.s.Host = principal(body[1]), derString(body[2]), principal(body[3])
		list := derUnwrap(body[8])
		for len(list) > 0 && len(k.etypes) < 16 {
			_, rest, ok := derRead(list)
			if !ok {
				break
			}
			if e, ok := derInt(list); ok {
				k.etypes = append(k.etypes, e)
			}
			list = rest
		}
	case 11, 13:
		k.rep = d.tag
		if a.s.User == "" {
			a.s.User, a.s.Domain = principal(f[4]), derString(f[3])
		}
		if t, _, ok := derRead(f[5]); ok { // Ticket [APPLICATION 1]
			tf := derFields(derUnwrap(t.body))
			if a.s.Host == "" {
				a.s.Host = principal(tf[2])
			}
			k.tktEtype, _ = derInt(derFields(derUnwrap(tf[3]))[0])
		}
	case 30:
		k.rep = 30
		k.errNo, _ = derInt(f[6])
		if a.s.User == "" {
			a.s.User = principal(f[8])
		}
		if a.s.Domain == "" {
			a.s.Domain = derString(f[9])
		}
		if a.s.Host == "" {
			a.s.Host = principal(f[10])
		}
	default:
		return
	}
	a.have = true
	a.s.Auth = "Kerberos"
	krbSummary(a)
}

func krbSummary(a *appState) {
	k := &a.krb
	var parts []string
	if k.req != 0 {
		s := krbMsgNames[k.req]
		if len(k.etypes) > 0 {
			names := make([]string, len(k.etypes))
			for i, e := range k.etypes {
				names[i] = etypeName(e)
			}
			s += " (" + strings.Join(names, ", ") + ")"
		}
		parts = append(parts, s)
	}
	switch k.rep {
	case 11, 13:
		s := krbMsgNames[k.rep]
		if k.tktEtype != 0 {
			s += ", ticket " + etypeName(k.tktEtype)
		}
		parts = append(parts, s)
	case 30:
		e := krbErrors[k.errNo]
		if e == "" {
			e = fmt.Sprintf("codice %d", k.errNo)
		}
		parts = append(parts, "errore: "+e)
	}
	a.s.Info = clip(strings.Join(parts, " → "), 512)

	weakOnly := len(k.etypes) > 0
	for _, e := range k.etypes {
		weakOnly = weakOnly && weakEtype(e)
	}
	switch {
	case k.tktEtype != 0 && weakEtype(k.tktEtype):
		a.s.Weak = "ticket cifrato con " + etypeName(k.tktEtype)
	case k.req == 10 && k.rep == 11 && !k.preauth:
		a.s.Weak = "account senza preautenticazione Kerberos"
	case weakOnly:
		a.s.Weak = "il client chiede solo cifrature deboli"
	default:
		a.s.Weak = ""
	}
}
