package sensor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/gopacket/gopacket"

	"hyperwave/internal/model"
)

func newGen(t *testing.T) (*pktGen, *sink) {
	r := testRunner()
	out := newSink(r, false)
	p := newProc(r, out)
	return &pktGen{t: t, p: p, now: time.Now(), mac1: net.HardwareAddr{0x02, 1, 2, 3, 4, 5}, mac2: net.HardwareAddr{0x02, 9, 8, 7, 6, 5}}, out
}

// open apre una connessione TCP e restituisce i numeri di sequenza dei due versi.
func (g *pktGen) open(c, s string, cp, sp uint16) (cseq, sseq uint32) {
	cseq, sseq = 1000, 9000
	g.tcp(c, s, cp, sp, cseq, 0, "S", nil)
	g.tcp(s, c, sp, cp, sseq, cseq+1, "SA", nil)
	cseq, sseq = cseq+1, sseq+1
	g.tcp(c, s, cp, sp, cseq, sseq, "A", nil)
	return
}

func oneSession(t *testing.T, b *model.Batch) model.Session {
	t.Helper()
	if b == nil || len(b.Sessions) != 1 {
		t.Fatalf("attesa una sessione, batch: %+v", b)
	}
	return b.Sessions[0]
}

// ---------------------------------------------------------------- QUIC

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Vettori della RFC 9001, appendice A.1 e A.2.
func TestQUICKeysRFC9001(t *testing.T) {
	key, iv, hp := quicClientSecrets(mustHex(t, "8394c8f03e515708"), false)
	if hex.EncodeToString(key) != "1f369613dd76d5467730efcbe3b1a22d" || hex.EncodeToString(iv) != "fa044b2f42a3fd3b46fb255c" ||
		hex.EncodeToString(hp) != "9f50449e04a0e810283a1e9933adedd2" {
		t.Fatalf("chiavi errate: key %x iv %x hp %x", key, iv, hp)
	}
	b, _ := aes.NewCipher(hp)
	var mask [16]byte
	b.Encrypt(mask[:], mustHex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))
	if hex.EncodeToString(mask[:5]) != "437b9aec36" {
		t.Fatalf("maschera errata: %x", mask[:5])
	}
}

func varint2(v int) []byte { return []byte{0x40 | byte(v>>8), byte(v)} }

func cryptoFrame(off int, data []byte) []byte {
	f := append([]byte{0x06}, varint2(off)...)
	f = append(f, varint2(len(data))...)
	return append(f, data...)
}

// quicSeal costruisce un pacchetto Initial del client protetto come prevede la RFC 9001.
func quicSeal(t *testing.T, dcid, frames []byte, pn uint32) []byte {
	key, iv, hp := quicClientSecrets(dcid, false)
	if pad := 1250 - len(frames) - 40; pad > 0 {
		frames = append(frames, make([]byte, pad)...) // frame PADDING
	}
	hdr := append([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	hdr = append(hdr, 0, 0) // SCID vuoto, nessun token
	hdr = append(hdr, varint2(4+len(frames)+16)...)
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	nonce := append([]byte(nil), iv...)
	for i := range 4 {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	pkt := aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)
	hb, _ := aes.NewCipher(hp)
	var mask [16]byte
	hb.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := range 4 {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func TestQUICInitial(t *testing.T) {
	cli, _ := handshake(t, tls.VersionTLS13)
	n := int(binary.BigEndian.Uint16(cli[3:5]))
	ch := cli[5 : 5+n] // messaggio ClientHello senza l'intestazione del record
	half := len(ch) / 2
	dcid := mustHex(t, "0011223344556677")

	g, out := newGen(t)
	// il ClientHello arriva in due pacchetti, la seconda metà per prima
	g.udp("10.1.1.10", "198.51.100.20", 52000, 443, gopacket.Payload(quicSeal(t, dcid, append([]byte{0x01}, cryptoFrame(half, ch[half:])...), 0)))
	g.udp("10.1.1.10", "198.51.100.20", 52000, 443, gopacket.Payload(quicSeal(t, dcid, cryptoFrame(0, ch[:half]), 1)))
	g.udp("198.51.100.20", "10.1.1.10", 443, 52000, gopacket.Payload(make([]byte, 100)))
	g.p.flushAll()
	b := out.take()
	if b == nil || len(b.TLS) != 1 {
		t.Fatalf("atteso un record TLS da QUIC, batch: %+v", b)
	}
	tl := b.TLS[0]
	if tl.Transport != "quic" || tl.SNI != "test.example" || tl.Port != 443 || tl.Version != "TLSv1.3" || !strings.HasPrefix(tl.JA4, "q13d") {
		t.Fatalf("record QUIC errato: %+v", tl)
	}
	if len(b.Flows) != 1 || b.Flows[0].Domain != "test.example" || b.Flows[0].App != "QUIC" {
		t.Fatalf("flusso QUIC errato: %+v", b.Flows)
	}
}

func TestQUICIgnoresOtherUDP(t *testing.T) {
	g, out := newGen(t)
	junk := bytes.Repeat([]byte{0xc3, 0, 0, 0, 1}, 300)
	g.udp("10.1.1.10", "198.51.100.20", 52001, 443, gopacket.Payload(junk))
	g.p.flushAll()
	if b := out.take(); b == nil || len(b.TLS) != 0 || len(b.Flows) != 1 {
		t.Fatalf("un datagramma non valido non deve produrre TLS: %+v", b)
	}
}

// ---------------------------------------------------------------- SSH

func sshKexinit(lists [10]string) []byte {
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, l := range lists {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(l)))
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	pad := 8 - (len(payload)+5)%8 + 4
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(payload)+pad+1))
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, pad)...)
}

func TestSSH(t *testing.T) {
	g, out := newGen(t)
	c, s := "10.1.1.10", "10.1.1.20"
	cseq, sseq := g.open(c, s, 50000, 2222)
	cl := [10]string{"curve25519-sha256", "ssh-ed25519", "aes256-gcm@openssh.com", "aes256-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""}
	sl := [10]string{"curve25519-sha256,diffie-hellman-group1-sha1", "ssh-ed25519,ssh-rsa", "aes128-ctr", "aes128-ctr,3des-cbc", "hmac-sha2-512", "hmac-sha2-512", "none,zlib@openssh.com", "none,zlib@openssh.com", "", ""}
	g.stream(s, c, 2222, 50000, &sseq, cseq, []byte("SSH-2.0-OpenSSH_9.6\r\n"), 1400)
	g.stream(c, s, 50000, 2222, &cseq, sseq, append([]byte("SSH-2.0-PuTTY_Release_0.81\r\n"), sshKexinit(cl)...), 100)
	g.stream(s, c, 2222, 50000, &sseq, cseq, sshKexinit(sl), 1400)
	g.p.flushAll()
	b := out.take()
	ss := oneSession(t, b)
	sum := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	if ss.Protocol != "ssh" || ss.ClientSW != "SSH-2.0-PuTTY_Release_0.81" || ss.ServerSW != "SSH-2.0-OpenSSH_9.6" ||
		ss.Hash != sum("curve25519-sha256;aes256-gcm@openssh.com;hmac-sha2-256;none") ||
		ss.ServerHash != sum("curve25519-sha256,diffie-hellman-group1-sha1;aes128-ctr,3des-cbc;hmac-sha2-512;none,zlib@openssh.com") {
		t.Fatalf("sessione SSH errata: %+v", ss)
	}
	if !strings.Contains(ss.Weak, "diffie-hellman-group1-sha1") || !strings.Contains(ss.Weak, "3des-cbc") {
		t.Fatalf("algoritmi deboli non segnalati: %q", ss.Weak)
	}
	if b.Flows[0].App != "SSH" {
		t.Fatalf("applicazione del flusso: %q", b.Flows[0].App)
	}
}

// ---------------------------------------------------------------- RDP

func tpkt(x224 []byte) []byte {
	return append([]byte{3, 0, byte((len(x224) + 4) >> 8), byte(len(x224) + 4)}, x224...)
}

func TestRDP(t *testing.T) {
	cliTLS, srvTLS := handshake(t, tls.VersionTLS12)
	for _, tc := range []struct {
		sel  byte
		weak string
		info string
	}{
		{2, "", "richiesti: TLS, CredSSP (NLA); scelto: CredSSP (NLA)"},
		{1, "TLS senza autenticazione a livello di rete (NLA)", "richiesti: TLS, CredSSP (NLA); scelto: TLS"},
	} {
		g, out := newGen(t)
		c, s := "10.1.1.10", "10.1.1.30"
		cseq, sseq := g.open(c, s, 50100, 3389)
		req := append([]byte{0, 0xe0, 0, 0, 0, 0, 0}, "Cookie: mstshash=CORP\\mario\r\n"...)
		req = append(req, 1, 0, 8, 0, 3, 0, 0, 0)
		g.stream(c, s, 50100, 3389, &cseq, sseq, tpkt(req), 1400)
		g.stream(s, c, 3389, 50100, &sseq, cseq, tpkt([]byte{0, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, tc.sel, 0, 0, 0}), 1400)
		g.stream(c, s, 50100, 3389, &cseq, sseq, cliTLS, 1400)
		g.stream(s, c, 3389, 50100, &sseq, cseq, srvTLS, 1400)
		g.p.flushAll()
		b := out.take()
		ss := oneSession(t, b)
		if ss.Protocol != "rdp" || ss.User != "mario" || ss.Domain != "CORP" || ss.Info != tc.info || ss.Weak != tc.weak {
			t.Fatalf("sessione RDP errata: %+v", ss)
		}
		if len(b.TLS) != 1 || b.TLS[0].Port != 3389 || b.TLS[0].SNI != "test.example" {
			t.Fatalf("il TLS dopo la negoziazione RDP va letto: %+v", b.TLS)
		}
	}
}

// ---------------------------------------------------------------- SMB e NTLM

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func ntlmType3(domain, user, host string, ntLen int) []byte {
	d, u, h, nt := utf16Bytes(domain), utf16Bytes(user), utf16Bytes(host), make([]byte, ntLen)
	m := make([]byte, 64)
	copy(m, ntlmSig)
	off := 64
	put := func(o int, data []byte) {
		binary.LittleEndian.PutUint16(m[o:], uint16(len(data)))
		binary.LittleEndian.PutUint16(m[o+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(m[o+4:], uint32(off))
		off += len(data)
	}
	put(12, nil)
	put(20, nt)
	put(28, d)
	put(36, u)
	put(44, h)
	put(52, nil)
	binary.LittleEndian.PutUint32(m[60:], 0x201)
	return bytes.Join([][]byte{m, nt, d, u, h}, nil)
}

func smb2(cmd uint16, resp bool, body []byte) []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	if resp {
		h[16] = 1
	}
	m := append(h, body...)
	return append([]byte{0, byte(len(m) >> 16), byte(len(m) >> 8), byte(len(m))}, m...)
}

func TestSMBWithNTLM(t *testing.T) {
	g, out := newGen(t)
	c, s := "10.1.1.10", "10.1.1.40"
	cseq, sseq := g.open(c, s, 50200, 445)
	g.stream(c, s, 50200, 445, &cseq, sseq, smb2(0, false, make([]byte, 40)), 1400)
	neg := make([]byte, 64)
	binary.LittleEndian.PutUint16(neg[0:], 65)
	binary.LittleEndian.PutUint16(neg[2:], 3)
	binary.LittleEndian.PutUint16(neg[4:], 0x0311)
	g.stream(s, c, 445, 50200, &sseq, cseq, smb2(0, true, neg), 1400)
	g.stream(c, s, 50200, 445, &cseq, sseq, smb2(1, false, append(make([]byte, 24), ntlmType3("CORP", "mario", "PC-01", 120)...)), 1400)
	path := utf16Bytes(`\\fs01\dati`)
	tc := make([]byte, 8)
	binary.LittleEndian.PutUint16(tc[0:], 9)
	binary.LittleEndian.PutUint16(tc[4:], 64+8)
	binary.LittleEndian.PutUint16(tc[6:], uint16(len(path)))
	g.stream(c, s, 50200, 445, &cseq, sseq, smb2(3, false, append(tc, path...)), 1400)
	g.p.flushAll()
	b := out.take()
	ss := oneSession(t, b)
	if ss.Protocol != "smb" || ss.Auth != "NTLMv2" || ss.User != "mario" || ss.Domain != "CORP" || ss.Host != "PC-01" ||
		ss.Info != "SMB 3.1.1 · firma obbligatoria · condivisioni: dati" || ss.Weak != "" {
		t.Fatalf("sessione SMB errata: %+v", ss)
	}
	if b.Flows[0].App != "SMB" {
		t.Fatalf("applicazione del flusso: %q", b.Flows[0].App)
	}
}

func TestNTLMv1OverHTTP(t *testing.T) {
	g, out := newGen(t)
	c, s := "10.1.1.10", "10.1.1.50"
	cseq, sseq := g.open(c, s, 50300, 80)
	tok := base64.StdEncoding.EncodeToString(ntlmType3("CORP", "luigi", "PC-02", 24))
	g.stream(c, s, 50300, 80, &cseq, sseq, []byte("GET /intranet HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: NTLM "+tok+"\r\n\r\n"), 1400)
	g.p.flushAll()
	ss := oneSession(t, out.take())
	if ss.Protocol != "ntlm" || ss.Auth != "NTLMv1" || ss.Weak != "NTLMv1" || ss.User != "luigi" || ss.Info != "su HTTP" {
		t.Fatalf("sessione NTLM errata: %+v", ss)
	}
}

// ---------------------------------------------------------------- Kerberos

func dlen(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func tlvb(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	return append(append([]byte{tag}, dlen(len(body))...), body...)
}

func dctx(n int, parts ...[]byte) []byte { return tlvb(0xa0|byte(n), parts...) }
func dapp(n int, parts ...[]byte) []byte { return tlvb(0x60|byte(n), parts...) }
func dseq(parts ...[]byte) []byte        { return tlvb(0x30, parts...) }
func dstr(s string) []byte               { return tlvb(0x1b, []byte(s)) }
func doct(s string) []byte               { return tlvb(0x04, []byte(s)) }

func dint(v int) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		if v >= -128 && v < 128 {
			break
		}
		v >>= 8
	}
	return tlvb(0x02, b)
}

func dprinc(typ int, names ...string) []byte {
	var ns [][]byte
	for _, n := range names {
		ns = append(ns, dstr(n))
	}
	return dseq(dctx(0, dint(typ)), dctx(1, dseq(ns...)))
}

func krbReq(app int, preauth bool, cname []byte, sname []byte, etypes ...int) []byte {
	var et [][]byte
	for _, e := range etypes {
		et = append(et, dint(e))
	}
	var pa []byte
	if preauth {
		pa = dctx(3, dseq(dseq(dctx(1, dint(2)), dctx(2, doct("ts")))))
	}
	body := dseq(dctx(0, tlvb(0x03, []byte{0, 0x40, 0x81, 0, 0x10})), dctx(1, cname), dctx(2, dstr("CORP.EXAMPLE")), dctx(3, sname),
		dctx(5, tlvb(0x18, []byte("20370913024805Z"))), dctx(7, dint(1234567)), dctx(8, dseq(et...)))
	return dapp(app, dseq(dctx(1, dint(5)), dctx(2, dint(app)), pa, dctx(4, body)))
}

func TestKerberos(t *testing.T) {
	krbtgt := dprinc(2, "krbtgt", "CORP.EXAMPLE")
	mssql := dprinc(2, "MSSQLSvc", "db01.corp.example")

	// AS-REQ con password errata, su UDP
	g, out := newGen(t)
	g.udp("10.1.1.10", "10.1.1.5", 51000, 88, gopacket.Payload(krbReq(10, true, dprinc(1, "mario"), krbtgt, 18, 17, 23)))
	krbErr := dapp(30, dseq(dctx(0, dint(5)), dctx(1, dint(30)), dctx(4, tlvb(0x18, []byte("20261110120000Z"))), dctx(5, dint(0)),
		dctx(6, dint(24)), dctx(9, dstr("CORP.EXAMPLE")), dctx(10, krbtgt)))
	g.udp("10.1.1.5", "10.1.1.10", 88, 51000, gopacket.Payload(krbErr))
	g.p.flushAll()
	ss := oneSession(t, out.take())
	if ss.Protocol != "kerberos" || ss.Transport != "udp" || ss.User != "mario" || ss.Domain != "CORP.EXAMPLE" || ss.Host != "krbtgt/CORP.EXAMPLE" ||
		ss.Info != "AS-REQ (aes256, aes128, rc4-hmac) → errore: password errata (KDC_ERR_PREAUTH_FAILED)" || ss.Weak != "" {
		t.Fatalf("sessione Kerberos errata: %+v", ss)
	}

	// TGS con ticket RC4 (Kerberoasting), su TCP con il prefisso di lunghezza
	g, out = newGen(t)
	c, s := "10.1.1.10", "10.1.1.5"
	cseq, sseq := g.open(c, s, 51001, 88)
	frame := func(m []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(m))), m...) }
	g.stream(c, s, 51001, 88, &cseq, sseq, frame(krbReq(12, true, dprinc(1, "mario"), mssql, 23)), 100)
	ticket := dapp(1, dseq(dctx(0, dint(5)), dctx(1, dstr("CORP.EXAMPLE")), dctx(2, mssql), dctx(3, dseq(dctx(0, dint(23)), dctx(2, doct("cifrato"))))))
	rep := dapp(13, dseq(dctx(0, dint(5)), dctx(1, dint(13)), dctx(3, dstr("CORP.EXAMPLE")), dctx(4, dprinc(1, "mario")), dctx(5, ticket),
		dctx(6, dseq(dctx(0, dint(18)), dctx(2, doct("c"))))))
	g.stream(s, c, 88, 51001, &sseq, cseq, frame(rep), 100)
	g.p.flushAll()
	ss = oneSession(t, out.take())
	if ss.Transport != "tcp" || ss.Host != "MSSQLSvc/db01.corp.example" || ss.Weak != "ticket cifrato con rc4-hmac" ||
		ss.Info != "TGS-REQ (rc4-hmac) → TGS-REP, ticket rc4-hmac" {
		t.Fatalf("sessione Kerberos TGS errata: %+v", ss)
	}
}

func TestDERNegativeInt(t *testing.T) {
	if v, ok := derInt(dint(-135)); !ok || v != -135 {
		t.Fatalf("intero negativo: %d %v", v, ok)
	}
	if v, ok := derInt(dint(1234567)); !ok || v != 1234567 {
		t.Fatalf("intero lungo: %d %v", v, ok)
	}
}
