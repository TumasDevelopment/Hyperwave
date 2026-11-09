package sensor

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// Analisi dell'handshake TLS visto in chiaro: ClientHello (SNI, ALPN, impronta JA4),
// ServerHello (versione scelta) e, fino a TLS 1.2, il certificato del server.

type clientHello struct {
	SNI      string
	ALPN     []string
	Version  uint16 // la più alta proposta
	JA4      string
	Ciphers  []uint16
	Exts     []uint16
	SigAlgs  []uint16
	legacyVs uint16
}

type serverHello struct {
	Version uint16
	ALPN    string
}

type certInfo struct {
	Subject, Issuer string
	NotAfter        int64
	SelfSigned      bool
}

func grease(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func versionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLSv1.3"
	case 0x0303:
		return "TLSv1.2"
	case 0x0302:
		return "TLSv1.1"
	case 0x0301:
		return "TLSv1.0"
	case 0x0300:
		return "SSLv3"
	case 0x0002:
		return "SSLv2"
	}
	return ""
}

// isTLSStart riconosce l'inizio di un record handshake TLS.
func isTLSStart(p []byte) bool {
	return len(p) >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == 0x01
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) u8() uint8 {
	if len(r.b) < 1 {
		r.bad = true
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) u16() uint16 {
	if len(r.b) < 2 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) u24() int {
	if len(r.b) < 3 {
		r.bad = true
		return 0
	}
	v := int(r.b[0])<<16 | int(r.b[1])<<8 | int(r.b[2])
	r.b = r.b[3:]
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.bad = true
		r.b = nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// tlsHandshakes estrae dallo stream i messaggi di handshake completi (anche se divisi tra più record).
// stop è vero quando lo stream passa a dati cifrati: oltre non c'è altro da leggere.
func tlsHandshakes(stream []byte, fn func(typ byte, body []byte)) (stop bool) {
	var hs []byte
	for len(stream) >= 5 {
		typ, n := stream[0], int(binary.BigEndian.Uint16(stream[3:5]))
		if stream[1] != 0x03 || n > 18432 {
			return true // non è (più) TLS
		}
		if len(stream) < 5+n {
			break
		}
		frag := stream[5 : 5+n]
		stream = stream[5+n:]
		switch typ {
		case 22:
			hs = append(hs, frag...)
		case 20, 21, 23:
			stop = true
		}
		if stop {
			break
		}
	}
	for len(hs) >= 4 {
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+n {
			break
		}
		fn(hs[0], hs[4:4+n])
		hs = hs[4+n:]
	}
	return stop
}

func parseClientHello(body []byte) (*clientHello, error) {
	r := &reader{b: body}
	ch := &clientHello{}
	ch.legacyVs = r.u16()
	r.bytes(32)
	r.bytes(int(r.u8()))
	cs := &reader{b: r.bytes(int(r.u16()))}
	for len(cs.b) >= 2 {
		ch.Ciphers = append(ch.Ciphers, cs.u16())
	}
	r.bytes(int(r.u8()))
	if r.bad {
		return nil, fmt.Errorf("ClientHello troncato")
	}
	exts := &reader{b: r.bytes(int(r.u16()))}
	for len(exts.b) >= 4 && !exts.bad {
		typ := exts.u16()
		data := &reader{b: exts.bytes(int(exts.u16()))}
		ch.Exts = append(ch.Exts, typ)
		switch typ {
		case 0x0000: // server_name
			list := &reader{b: data.bytes(int(data.u16()))}
			for len(list.b) > 3 && !list.bad {
				kind := list.u8()
				name := list.bytes(int(list.u16()))
				if kind == 0 && ch.SNI == "" {
					ch.SNI = strings.ToLower(string(name))
				}
			}
		case 0x0010: // ALPN
			list := &reader{b: data.bytes(int(data.u16()))}
			for len(list.b) > 0 && !list.bad {
				if p := list.bytes(int(list.u8())); len(p) > 0 {
					ch.ALPN = append(ch.ALPN, string(p))
				}
			}
		case 0x002b: // supported_versions
			list := &reader{b: data.bytes(int(data.u8()))}
			for len(list.b) >= 2 {
				if v := list.u16(); !grease(v) && v > ch.Version {
					ch.Version = v
				}
			}
		case 0x000d: // signature_algorithms
			list := &reader{b: data.bytes(int(data.u16()))}
			for len(list.b) >= 2 {
				if v := list.u16(); !grease(v) {
					ch.SigAlgs = append(ch.SigAlgs, v)
				}
			}
		}
	}
	if ch.Version == 0 {
		ch.Version = ch.legacyVs
	}
	ch.JA4 = ja4(ch, 't')
	return ch, nil
}

// ja4 calcola l'impronta JA4 del client (FoxIO, licenza BSD 3-Clause per JA4).
func ja4(ch *clientHello, transport byte) string {
	ver := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}[ch.Version]
	if ver == "" {
		ver = "00"
	}
	sni := byte('i')
	if ch.SNI != "" {
		sni = 'd'
	}
	var ciphers, exts []uint16
	for _, c := range ch.Ciphers {
		if !grease(c) {
			ciphers = append(ciphers, c)
		}
	}
	nExt := 0
	for _, e := range ch.Exts {
		if grease(e) {
			continue
		}
		nExt++
		if e != 0x0000 && e != 0x0010 {
			exts = append(exts, e)
		}
	}
	alpn := "00"
	if len(ch.ALPN) > 0 && ch.ALPN[0] != "" {
		a := ch.ALPN[0]
		first, last := a[0], a[len(a)-1]
		if isAlnum(first) && isAlnum(last) {
			alpn = string([]byte{first, last})
		} else {
			h := hex.EncodeToString([]byte(a))
			alpn = string([]byte{h[0], h[len(h)-1]})
		}
	}
	a := fmt.Sprintf("%c%s%c%02d%02d%s", transport, ver, sni, min(len(ciphers), 99), min(nExt, 99), alpn)

	hexList := func(v []uint16) string {
		parts := make([]string, len(v))
		for i, x := range v {
			parts[i] = fmt.Sprintf("%04x", x)
		}
		return strings.Join(parts, ",")
	}
	hash12 := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	b := "000000000000"
	if len(ciphers) > 0 {
		slices.Sort(ciphers)
		b = hash12(hexList(ciphers))
	}
	c := "000000000000"
	if len(exts) > 0 {
		slices.Sort(exts)
		s := hexList(exts)
		if len(ch.SigAlgs) > 0 {
			s += "_" + hexList(ch.SigAlgs)
		}
		c = hash12(s)
	}
	return a + "_" + b + "_" + c
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func parseServerHello(body []byte) (*serverHello, error) {
	r := &reader{b: body}
	sh := &serverHello{Version: r.u16()}
	r.bytes(32)
	r.bytes(int(r.u8()))
	r.u16() // cipher suite scelta
	r.u8()
	if r.bad {
		return nil, fmt.Errorf("ServerHello troncato")
	}
	if len(r.b) < 2 {
		return sh, nil
	}
	exts := &reader{b: r.bytes(int(r.u16()))}
	for len(exts.b) >= 4 && !exts.bad {
		typ := exts.u16()
		data := &reader{b: exts.bytes(int(exts.u16()))}
		switch typ {
		case 0x002b:
			if v := data.u16(); !data.bad {
				sh.Version = v
			}
		case 0x0010:
			list := &reader{b: data.bytes(int(data.u16()))}
			if p := list.bytes(int(list.u8())); len(p) > 0 {
				sh.ALPN = string(p)
			}
		}
	}
	return sh, nil
}

// parseCertificate legge il primo certificato (quello del server) da un messaggio Certificate di TLS 1.2 o precedente.
func parseCertificate(body []byte) (*certInfo, error) {
	r := &reader{b: body}
	list := &reader{b: r.bytes(r.u24())}
	der := list.bytes(list.u24())
	if r.bad || list.bad || len(der) == 0 {
		return nil, fmt.Errorf("messaggio Certificate troncato")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ci := &certInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter.Unix()}
	// firma verificata con la chiave del certificato stesso, anche se non è marcato come CA
	ci.SelfSigned = bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	return ci, nil
}
