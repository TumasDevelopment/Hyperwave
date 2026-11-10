package sensor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"hyperwave/internal/model"
)

// QUIC: i pacchetti Initial sono cifrati con chiavi ricavate dal Destination Connection ID,
// che viaggia in chiaro (RFC 9001 §5.2). Chiunque osservi il traffico può quindi leggere il
// ClientHello, e da lì nome del server, ALPN e impronta JA4 come per TLS su TCP.

const (
	quicMaxTries  = 8        // pacchetti del client esaminati per flusso
	quicCryptoMax = 16 << 10 // byte di handshake ricomposti al massimo
	quicV2        = 0x6b3343cf
)

var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

type quicKeys struct {
	aead cipher.AEAD
	hp   cipher.Block
	iv   []byte
}

type quicState struct {
	tries int
	done  bool
	keys  *quicKeys
	data  []byte // handshake ricomposto
	have  []bool
}

// hkdfExpandLabel è HKDF-Expand-Label di TLS 1.3 con contesto vuoto.
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err) // solo per lunghezze impossibili
	}
	return out
}

// quicClientSecrets ricava chiave, IV e chiave di protezione dell'intestazione del client.
func quicClientSecrets(dcid []byte, v2 bool) (key, iv, hp []byte) {
	salt, prefix := quicSaltV1, "quic "
	if v2 {
		salt, prefix = quicSaltV2, "quicv2 "
	}
	initial, _ := hkdf.Extract(sha256.New, dcid, salt)
	client := hkdfExpandLabel(initial, "client in", 32)
	return hkdfExpandLabel(client, prefix+"key", 16), hkdfExpandLabel(client, prefix+"iv", 12), hkdfExpandLabel(client, prefix+"hp", 16)
}

func newQuicKeys(dcid []byte, v2 bool) *quicKeys {
	key, iv, hp := quicClientSecrets(dcid, v2)
	b, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(b)
	h, _ := aes.NewCipher(hp)
	return &quicKeys{aead: aead, hp: h, iv: iv}
}

func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// quicIsInitial riconosce un datagramma del client che inizia con un pacchetto Initial
// di QUIC v1 o v2 (i datagrammi con un Initial del client sono lunghi almeno 1200 byte).
func quicIsInitial(b []byte) (v2, ok bool) {
	if len(b) < 1200 || b[0]&0xc0 != 0xc0 {
		return false, false
	}
	switch binary.BigEndian.Uint32(b[1:5]) {
	case 1:
		return false, (b[0]>>4)&3 == 0
	case quicV2:
		return true, (b[0]>>4)&3 == 1
	}
	return false, false
}

var errQuic = errors.New("pacchetto QUIC non valido")

// quicOpen toglie la protezione dell'intestazione e decifra il primo pacchetto del datagramma.
func quicOpen(st *quicState, pkt []byte, v2 bool) ([]byte, error) {
	off := 5
	if len(pkt) < off+1 {
		return nil, errQuic
	}
	dl := int(pkt[off])
	off++
	if dl > 20 || len(pkt) < off+dl+1 {
		return nil, errQuic
	}
	dcid := pkt[off : off+dl]
	off += dl
	sl := int(pkt[off])
	off += 1 + sl
	if sl > 20 || len(pkt) < off {
		return nil, errQuic
	}
	tl, n := quicVarint(pkt[off:])
	if n == 0 || uint64(len(pkt)-off-n) < tl {
		return nil, errQuic
	}
	off += n + int(tl)
	length, n := quicVarint(pkt[off:])
	if n == 0 {
		return nil, errQuic
	}
	pnOff := off + n
	if length < 20 || uint64(len(pkt)-pnOff) < length {
		return nil, errQuic
	}
	if st.keys == nil {
		st.keys = newQuicKeys(dcid, v2) // le chiavi Initial dipendono dal primo DCID del client
	}
	k := st.keys
	var mask [16]byte
	k.hp.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	hdr := make([]byte, pnOff+4)
	copy(hdr, pkt)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := range pnLen {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	nonce := make([]byte, 12)
	copy(nonce, k.iv)
	for i := range 8 {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	end := pnOff + int(length)
	return k.aead.Open(nil, nonce, pkt[pnOff+pnLen:end], hdr[:pnOff+pnLen])
}

// quicFrames copia nel buffer di handshake i frame CRYPTO; false se i frame sono illeggibili.
func (st *quicState) quicFrames(b []byte) bool {
	for len(b) > 0 {
		typ := b[0]
		switch {
		case typ == 0x00 || typ == 0x01: // PADDING, PING
			b = b[1:]
		case typ == 0x02 || typ == 0x03: // ACK
			b = b[1:]
			var vals [4]uint64
			for i := range vals {
				v, n := quicVarint(b)
				if n == 0 {
					return false
				}
				vals[i], b = v, b[n:]
			}
			extra := int(vals[2]) * 2
			if typ == 0x03 {
				extra += 3
			}
			if extra > 512 {
				return false
			}
			for range extra {
				_, n := quicVarint(b)
				if n == 0 {
					return false
				}
				b = b[n:]
			}
		case typ == 0x06: // CRYPTO
			b = b[1:]
			o, n := quicVarint(b)
			if n == 0 {
				return false
			}
			b = b[n:]
			l, n := quicVarint(b)
			if n == 0 || uint64(len(b)-n) < l {
				return false
			}
			b = b[n:]
			data := b[:l]
			b = b[l:]
			if o+l > quicCryptoMax {
				continue
			}
			if need := int(o + l); need > len(st.data) {
				st.data = append(st.data, make([]byte, need-len(st.data))...)
				st.have = append(st.have, make([]bool, need-len(st.have))...)
			}
			copy(st.data[o:], data)
			for i := range data {
				st.have[int(o)+i] = true
			}
		default: // CONNECTION_CLOSE o altro: il resto non serve
			return true
		}
	}
	return true
}

// clientHello restituisce il ClientHello quando i suoi byte sono tutti arrivati.
func (st *quicState) clientHello() []byte {
	n := 0
	for n < len(st.have) && st.have[n] {
		n++
	}
	d := st.data[:n]
	if len(d) < 4 || d[0] != 1 {
		return nil
	}
	l := int(d[1])<<16 | int(d[2])<<8 | int(d[3])
	if len(d) < 4+l {
		return nil
	}
	return d[4 : 4+l]
}

func (p *proc) quicPacket(f *flow, pkt []byte, ts int64) {
	v2, ok := quicIsInitial(pkt)
	if !ok {
		return
	}
	st := f.quic
	if st == nil {
		st = &quicState{}
		f.quic = st
		f.appName = "QUIC"
	}
	st.tries++
	if st.tries > quicMaxTries {
		st.done, st.data, st.have = true, nil, nil
		return
	}
	plain, err := quicOpen(st, pkt, v2)
	if err != nil || !st.quicFrames(plain) {
		return
	}
	body := st.clientHello()
	if body == nil {
		return
	}
	st.done, st.data, st.have = true, nil, nil
	ch, err := parseClientHello(body)
	if err != nil {
		return
	}
	t := model.TLS{TS: ts, Client: f.cli.Addr().String(), Server: f.srv.Addr().String(), Port: f.srv.Port(),
		SNI: ch.SNI, Version: versionName(ch.Version), JA4: ja4(ch, 'q'), Transport: "quic"}
	if len(ch.ALPN) > 0 {
		t.ALPN = ch.ALPN[0]
	}
	if ch.SNI != "" {
		f.domain = ch.SNI
	}
	p.out.put(func(b *model.Batch) { b.TLS = append(b.TLS, t) })
}
