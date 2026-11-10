package sensor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"hyperwave/internal/netx"
)

// Modalità flow: il sensore riceve i flussi esportati da router, switch e firewall invece di
// osservare i pacchetti. Formati: NetFlow v5 e v9, IPFIX (RFC 7011, anche bidirezionale
// RFC 5103) e sFlow v5 (pacchetti campionati). Il formato si riconosce da ogni datagramma,
// quindi una porta sola può ricevere tutto.

const (
	maxTemplates = 10_000
	sflowEther   = 1
	sflowIPv4    = 11
	sflowIPv6    = 12
)

var errFlowShort = errors.New("datagramma troppo corto")

type tplField struct {
	id     uint16
	pen    uint32
	length uint16 // 65535 = lunghezza variabile (solo IPFIX)
}

type tplKey struct {
	exporter netip.Addr
	domain   uint32
	id       uint16
}

// flowDecoder conserva i template di NetFlow v9 e IPFIX per esportatore.
type flowDecoder struct {
	mu        sync.Mutex
	templates map[tplKey][]tplField
	sampling  uint64 // moltiplicatore imposto dalla configurazione; 0 = quello dichiarato dall'esportatore
	exporters map[netip.Addr]int64
	bad       atomic.Uint64
	noTpl     atomic.Uint64 // record di dati arrivati prima del loro template
}

func newFlowDecoder(sampling int) *flowDecoder {
	return &flowDecoder{templates: map[tplKey][]tplField{}, exporters: map[netip.Addr]int64{}, sampling: uint64(max(sampling, 0))}
}

func be(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// decode riconosce il formato e restituisce i record. now è l'ora di arrivo (ms).
func (d *flowDecoder) decode(exporter netip.Addr, b []byte, now int64) ([]uniRec, error) {
	if len(b) < 4 {
		return nil, errFlowShort
	}
	d.mu.Lock()
	if _, ok := d.exporters[exporter]; !ok && len(d.exporters) > 10_000 {
		clear(d.exporters)
	}
	d.exporters[exporter] = now
	d.mu.Unlock()
	switch {
	case b[0] == 0 && b[1] == 5:
		return d.netflow5(b)
	case b[0] == 0 && b[1] == 9:
		return d.netflow9(exporter, b)
	case b[0] == 0 && b[1] == 10:
		return d.ipfix(exporter, b)
	case binary.BigEndian.Uint32(b) == 5:
		return d.sflow(b, now)
	}
	return nil, fmt.Errorf("formato sconosciuto (versione %d)", binary.BigEndian.Uint16(b))
}

func (d *flowDecoder) scale(declared uint64) uint64 {
	if d.sampling > 0 {
		return d.sampling
	}
	return max(declared, 1)
}

// ---------------------------------------------------------------- NetFlow v5

func (d *flowDecoder) netflow5(b []byte) ([]uniRec, error) {
	if len(b) < 24 {
		return nil, errFlowShort
	}
	count := int(binary.BigEndian.Uint16(b[2:4]))
	uptime := int64(binary.BigEndian.Uint32(b[4:8]))
	base := int64(binary.BigEndian.Uint32(b[8:12]))*1000 + int64(binary.BigEndian.Uint32(b[12:16]))/1_000_000 - uptime
	rate := d.scale(uint64(binary.BigEndian.Uint16(b[22:24]) & 0x3fff))
	if len(b) < 24+count*48 {
		return nil, errFlowShort
	}
	out := make([]uniRec, 0, count)
	for i := range count {
		r := b[24+i*48:]
		src, _ := netip.AddrFromSlice(r[0:4])
		dst, _ := netip.AddrFromSlice(r[4:8])
		out = append(out, uniRec{
			src: src, dst: dst, pkts: uint64(binary.BigEndian.Uint32(r[16:20])) * rate, bytes: uint64(binary.BigEndian.Uint32(r[20:24])) * rate,
			start: base + int64(binary.BigEndian.Uint32(r[24:28])), end: base + int64(binary.BigEndian.Uint32(r[28:32])),
			sp: binary.BigEndian.Uint16(r[32:34]), dp: binary.BigEndian.Uint16(r[34:36]), flags: r[37], proto: r[38],
		})
	}
	return out, nil
}

// ---------------------------------------------------------------- NetFlow v9 e IPFIX

// fieldsRec raccoglie i campi di un record di dati.
type fieldsRec struct {
	uniRec
	startUp, endUp   int64 // ms dall'avvio dell'esportatore
	haveUp           bool
	startMs, endMs   int64
	initMs           int64
	sampling         uint64
	haveBytes, haveP bool
	totBytes, totP   uint64
}

func (f *fieldsRec) set(id uint16, pen uint32, v []byte) {
	if pen == 29305 { // RFC 5103: elementi del verso opposto
		switch id {
		case 1:
			f.revBytes = be(v)
		case 2:
			f.revPkts = be(v)
		case 6:
			f.revFlags = byte(be(v))
		}
		return
	}
	if pen != 0 {
		return
	}
	switch id {
	case 1, 231: // octetDeltaCount, initiatorOctets
		f.bytes, f.haveBytes = be(v), true
	case 2, 298: // packetDeltaCount, initiatorPackets
		f.pkts, f.haveP = be(v), true
	case 85:
		f.totBytes = be(v)
	case 86:
		f.totP = be(v)
	case 232:
		f.revBytes = be(v)
	case 299:
		f.revPkts = be(v)
	case 4:
		f.proto = byte(be(v))
	case 6:
		f.flags = byte(be(v))
	case 7:
		f.sp = uint16(be(v))
	case 11:
		f.dp = uint16(be(v))
	case 8, 27:
		f.src, _ = netip.AddrFromSlice(v)
	case 12, 28:
		f.dst, _ = netip.AddrFromSlice(v)
	case 58:
		f.vlan = uint16(be(v)) & 0x0fff
	case 21:
		f.endUp, f.haveUp = int64(be(v)), true
	case 22:
		f.startUp, f.haveUp = int64(be(v)), true
	case 150:
		f.startMs = int64(be(v)) * 1000
	case 151:
		f.endMs = int64(be(v)) * 1000
	case 152:
		f.startMs = int64(be(v))
	case 153:
		f.endMs = int64(be(v))
	case 160:
		f.initMs = int64(be(v))
	case 34, 305:
		f.sampling = be(v)
	}
}

// finish converte i tempi e applica il campionamento. upBase è l'ora (ms) dell'avvio
// dell'esportatore, se nota; export è l'ora del messaggio.
func (d *flowDecoder) finish(f *fieldsRec, upBase, export int64) uniRec {
	r := f.uniRec
	if !f.haveBytes {
		r.bytes = f.totBytes
	}
	if !f.haveP {
		r.pkts = f.totP
	}
	switch {
	case f.startMs > 0:
		r.start, r.end = f.startMs, max(f.endMs, f.startMs)
	case f.haveUp && f.initMs > 0:
		r.start, r.end = f.initMs+f.startUp, f.initMs+f.endUp
	case f.haveUp && upBase > 0:
		r.start, r.end = upBase+f.startUp, upBase+f.endUp
	default:
		r.start, r.end = export, export
	}
	if s := d.scale(f.sampling); s > 1 {
		r.bytes, r.pkts, r.revBytes, r.revPkts = r.bytes*s, r.pkts*s, r.revBytes*s, r.revPkts*s
	}
	return r
}

func (d *flowDecoder) addTemplate(k tplKey, fields []tplField) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.templates[k]; !ok && len(d.templates) >= maxTemplates {
		return
	}
	d.templates[k] = fields
}

func (d *flowDecoder) template(k tplKey) []tplField {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.templates[k]
}

func (d *flowDecoder) netflow9(exporter netip.Addr, b []byte) ([]uniRec, error) {
	if len(b) < 20 {
		return nil, errFlowShort
	}
	uptime := int64(binary.BigEndian.Uint32(b[4:8]))
	export := int64(binary.BigEndian.Uint32(b[8:12])) * 1000
	domain := binary.BigEndian.Uint32(b[16:20])
	var out []uniRec
	for s := b[20:]; len(s) >= 4; {
		id, l := binary.BigEndian.Uint16(s[0:2]), int(binary.BigEndian.Uint16(s[2:4]))
		if l < 4 || l > len(s) {
			return out, errFlowShort
		}
		body := s[4:l]
		s = s[l:]
		switch {
		case id == 0: // template
			for len(body) >= 4 {
				tid, n := binary.BigEndian.Uint16(body[0:2]), int(binary.BigEndian.Uint16(body[2:4]))
				body = body[4:]
				if len(body) < n*4 {
					return out, errFlowShort
				}
				fields := make([]tplField, n)
				for i := range n {
					fields[i] = tplField{id: binary.BigEndian.Uint16(body[i*4:]), length: binary.BigEndian.Uint16(body[i*4+2:])}
				}
				body = body[n*4:]
				d.addTemplate(tplKey{exporter, domain, tid}, fields)
			}
		case id >= 256:
			fields := d.template(tplKey{exporter, domain, id})
			if fields == nil {
				d.noTpl.Add(1)
				continue
			}
			out = append(out, d.records(fields, body, false, export-uptime, export)...)
		}
	}
	return out, nil
}

func (d *flowDecoder) ipfix(exporter netip.Addr, b []byte) ([]uniRec, error) {
	if len(b) < 16 {
		return nil, errFlowShort
	}
	if l := int(binary.BigEndian.Uint16(b[2:4])); l <= len(b) && l >= 16 {
		b = b[:l]
	}
	export := int64(binary.BigEndian.Uint32(b[4:8])) * 1000
	domain := binary.BigEndian.Uint32(b[12:16])
	var out []uniRec
	for s := b[16:]; len(s) >= 4; {
		id, l := binary.BigEndian.Uint16(s[0:2]), int(binary.BigEndian.Uint16(s[2:4]))
		if l < 4 || l > len(s) {
			return out, errFlowShort
		}
		body := s[4:l]
		s = s[l:]
		switch {
		case id == 2: // template
			for len(body) >= 4 {
				tid, n := binary.BigEndian.Uint16(body[0:2]), int(binary.BigEndian.Uint16(body[2:4]))
				body = body[4:]
				if n == 0 { // ritiro del template
					continue
				}
				fields := make([]tplField, 0, n)
				for range n {
					if len(body) < 4 {
						return out, errFlowShort
					}
					f := tplField{id: binary.BigEndian.Uint16(body[0:2]), length: binary.BigEndian.Uint16(body[2:4])}
					body = body[4:]
					if f.id&0x8000 != 0 {
						if len(body) < 4 {
							return out, errFlowShort
						}
						f.id &= 0x7fff
						f.pen = binary.BigEndian.Uint32(body[0:4])
						body = body[4:]
					}
					fields = append(fields, f)
				}
				d.addTemplate(tplKey{exporter, domain, tid}, fields)
			}
		case id >= 256:
			fields := d.template(tplKey{exporter, domain, id})
			if fields == nil {
				d.noTpl.Add(1)
				continue
			}
			out = append(out, d.records(fields, body, true, 0, export)...)
		}
	}
	return out, nil
}

// records legge i record di un set di dati secondo il template.
func (d *flowDecoder) records(fields []tplField, body []byte, ipfix bool, upBase, export int64) []uniRec {
	minLen := 0
	for _, f := range fields {
		if f.length != 65535 {
			minLen += int(f.length)
		} else {
			minLen++
		}
	}
	if minLen == 0 {
		return nil
	}
	var out []uniRec
	for len(body) >= minLen {
		var fr fieldsRec
		ok := true
		for _, f := range fields {
			n := int(f.length)
			if ipfix && f.length == 65535 { // lunghezza variabile
				if len(body) < 1 {
					ok = false
					break
				}
				n, body = int(body[0]), body[1:]
				if n == 255 {
					if len(body) < 2 {
						ok = false
						break
					}
					n, body = int(binary.BigEndian.Uint16(body)), body[2:]
				}
			}
			if n > len(body) {
				ok = false
				break
			}
			fr.set(f.id, f.pen, body[:n])
			body = body[n:]
		}
		if !ok {
			break
		}
		if fr.src.IsValid() && fr.dst.IsValid() {
			out = append(out, d.finish(&fr, upBase, export))
		}
	}
	return out
}

// ---------------------------------------------------------------- sFlow v5

func (d *flowDecoder) sflow(b []byte, now int64) ([]uniRec, error) {
	r := &reader{b: b[4:]}
	switch r.u32() {
	case 1:
		r.bytes(4)
	case 2:
		r.bytes(16)
	default:
		return nil, errors.New("sFlow: indirizzo dell'agente non valido")
	}
	r.bytes(12) // sub-agent, sequenza, uptime
	n := int(r.u32())
	if r.bad {
		return nil, errFlowShort
	}
	var out []uniRec
	for range min(n, 1024) {
		format := r.u32() & 0xfff
		body := &reader{b: r.bytes(int(r.u32()))}
		if r.bad {
			break
		}
		var rate uint64
		switch format {
		case 1: // flow sample
			body.bytes(8)
			rate = uint64(body.u32())
			body.bytes(16)
		case 3: // expanded flow sample
			body.bytes(12)
			rate = uint64(body.u32())
			body.bytes(24)
		default: // contatori e altro
			continue
		}
		recs := int(body.u32())
		for range min(recs, 64) {
			rf := body.u32() & 0xfff
			rb := body.bytes(int((body.u32() + 3) &^ 3))
			if body.bad {
				break
			}
			if rf != 1 || len(rb) < 16 { // solo l'intestazione del pacchetto campionato
				continue
			}
			hp := binary.BigEndian.Uint32(rb[0:4])
			frame := binary.BigEndian.Uint32(rb[4:8])
			hl := int(binary.BigEndian.Uint32(rb[12:16]))
			if hl > len(rb)-16 {
				continue
			}
			if u, ok := sampledHeader(hp, rb[16:16+hl]); ok {
				s := d.scale(rate)
				u.bytes, u.pkts, u.start, u.end = uint64(frame)*s, s, now, now
				out = append(out, u)
			}
		}
	}
	return out, nil
}

func (r *reader) u32() uint32 {
	if len(r.b) < 4 {
		r.bad = true
		r.b = nil
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

// sampledHeader ricava la quintupla dall'intestazione di un pacchetto campionato.
func sampledHeader(proto uint32, h []byte) (uniRec, bool) {
	var first gopacket.Decoder
	switch proto {
	case sflowEther:
		first = layers.LayerTypeEthernet
	case sflowIPv4:
		first = layers.LayerTypeIPv4
	case sflowIPv6:
		first = layers.LayerTypeIPv6
	default:
		return uniRec{}, false
	}
	pkt := gopacket.NewPacket(h, first, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	var u uniRec
	if d, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		u.vlan = d.VLANIdentifier
	}
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip.FragOffset != 0 {
			return uniRec{}, false
		}
		u.src, _ = netip.AddrFromSlice(ip.SrcIP)
		u.dst, _ = netip.AddrFromSlice(ip.DstIP)
		u.proto = uint8(ip.Protocol)
	case *layers.IPv6:
		u.src, _ = netip.AddrFromSlice(ip.SrcIP)
		u.dst, _ = netip.AddrFromSlice(ip.DstIP)
		u.proto = uint8(ip.NextHeader)
	default:
		return uniRec{}, false
	}
	switch l := pkt.TransportLayer().(type) {
	case *layers.TCP:
		u.sp, u.dp, u.flags = uint16(l.SrcPort), uint16(l.DstPort), tcpFlags(l)
	case *layers.UDP:
		u.sp, u.dp = uint16(l.SrcPort), uint16(l.DstPort)
	}
	if ic, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		u.dp = uint16(ic.TypeCode)
	}
	if ic, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
		u.dp = uint16(ic.TypeCode)
	}
	return u, u.src.IsValid() && u.dst.IsValid()
}

// ---------------------------------------------------------------- collettore UDP

func (r *Runner) runFlow(ctx context.Context) error {
	out := newSink(r, false)
	agg := newAggregator(r, out)
	dec := newFlowDecoder(r.cfg.FlowSampling)
	allow := netx.ParseNets(r.cfg.FlowAllow)
	var packets, denied atomic.Uint64
	r.addStat("flow_packets", func() any { return packets.Load() })
	r.addStat("flow_bad", func() any { return dec.bad.Load() })
	r.addStat("flow_no_template", func() any { return dec.noTpl.Load() })
	r.addStat("flow_denied", func() any { return denied.Load() })
	r.addStat("flow_exporters", func() any { dec.mu.Lock(); defer dec.mu.Unlock(); return len(dec.exporters) })
	r.addStat("flow_templates", func() any { dec.mu.Lock(); defer dec.mu.Unlock(); return len(dec.templates) })

	var conns []*net.UDPConn
	for _, addr := range r.cfg.FlowListen {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("indirizzo %q non valido: %w", addr, err)
		}
		c, err := net.ListenUDP("udp", ua)
		if err != nil {
			for _, x := range conns {
				x.Close()
			}
			return fmt.Errorf("ascolto su %s: %w", addr, err)
		}
		_ = c.SetReadBuffer(8 << 20)
		conns = append(conns, c)
		r.log.Info("collettore di flussi in ascolto", "indirizzo", c.LocalAddr().String(), "formati", "NetFlow v5/v9, IPFIX, sFlow v5")
	}
	if len(allow) == 0 {
		r.log.Warn("HW_FLOW_ALLOW vuoto: si accettano flussi da qualsiasi indirizzo; limitare gli esportatori con il firewall o con HW_FLOW_ALLOW")
	}
	if r.cfg.SuricataEve != "" {
		go r.tailSuricata(ctx, out)
	}

	sctx, stopSink := context.WithCancel(context.Background())
	var sinkDone sync.WaitGroup
	sinkDone.Add(1)
	go func() { defer sinkDone.Done(); out.loop(sctx, 5*time.Second) }()

	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
					continue
				}
				packets.Add(1)
				ex := from.Addr().Unmap()
				if len(allow) > 0 && !allow.ContainsAddr(ex) {
					denied.Add(1)
					continue
				}
				now := time.Now().UnixMilli()
				recs, err := dec.decode(ex, buf[:n], now)
				if err != nil {
					dec.bad.Add(1)
					r.log.Debug("datagramma di flusso scartato", "esportatore", ex, "err", err)
				}
				for _, u := range recs {
					agg.add(u, now)
				}
			}
		}()
	}

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, c := range conns {
				c.Close()
			}
			wg.Wait()
			agg.flushAll()
			stopSink()
			sinkDone.Wait()
			fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out.flush(fctx)
			cancel()
			return nil
		case now := <-t.C:
			agg.tick(now.UnixMilli(), true)
		}
	}
}
