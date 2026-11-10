package sensor

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"hyperwave/internal/model"
)

// Modalità vpcflow: importa come storico i VPC Flow Logs di AWS (file di testo, anche .gz,
// come quelli consegnati su S3). Il formato predefinito (versione 2) si riconosce da solo; per i
// formati personalizzati serve la riga di intestazione con i nomi dei campi, che AWS scrive in
// testa a ogni file. Ogni record descrive un verso solo per 1-10 minuti: l'aggregatore li riunisce.

var vpcDefault = strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status")

type vpcParser struct {
	idx map[string]int
}

func newVPCParser() *vpcParser {
	p := &vpcParser{}
	p.setFields(vpcDefault)
	return p
}

func (p *vpcParser) setFields(names []string) {
	p.idx = make(map[string]int, len(names))
	for i, n := range names {
		p.idx[strings.TrimPrefix(strings.ToLower(n), "$")] = i
	}
}

// parse legge una riga; l'intestazione aggiorna i campi e restituisce false.
func (p *vpcParser) parse(line string) (uniRec, bool) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return uniRec{}, false
	}
	if f[0] == "version" || strings.Contains(line, "srcaddr") {
		p.setFields(f)
		return uniRec{}, false
	}
	get := func(k string) string {
		if i, ok := p.idx[k]; ok && i < len(f) && f[i] != "-" {
			return f[i]
		}
		return ""
	}
	num := func(k string) uint64 { v, _ := strconv.ParseUint(get(k), 10, 64); return v }
	if s := get("log-status"); s != "" && s != "OK" {
		return uniRec{}, false // NODATA / SKIPDATA
	}
	src, err1 := netip.ParseAddr(get("srcaddr"))
	dst, err2 := netip.ParseAddr(get("dstaddr"))
	if err1 != nil || err2 != nil {
		return uniRec{}, false
	}
	// pkt-srcaddr/pkt-dstaddr sono gli indirizzi originali quando c'è di mezzo un NAT gateway
	if a, err := netip.ParseAddr(get("pkt-srcaddr")); err == nil {
		src = a
	}
	if a, err := netip.ParseAddr(get("pkt-dstaddr")); err == nil {
		dst = a
	}
	r := uniRec{src: src, dst: dst, sp: uint16(num("srcport")), dp: uint16(num("dstport")), proto: uint8(num("protocol")),
		pkts: num("packets"), bytes: num("bytes"), start: int64(num("start")) * 1000, end: int64(num("end")) * 1000,
		rejected: get("action") == "REJECT"}
	// tcp-flags usa gli stessi bit dell'intestazione TCP (SYN=2, ACK=16, SYN-ACK=18)
	r.flags = uint8(num("tcp-flags")) & (fFIN | fSYN | fRST | fPSH | fACK | fURG)
	if r.proto == 1 || r.proto == 58 {
		r.dp <<= 8 // il tipo ICMP finisce nella porta di destinazione, come in NetFlow
	}
	return r, r.start > 0
}

func (r *Runner) runVPCFlow(ctx context.Context) error {
	if !r.live.Load() {
		return fmt.Errorf("il live è spento sull'hub: i dati verrebbero scartati")
	}
	out := newSink(r, true)
	agg := newAggregator(r, out)
	var clock, lastTick int64
	total, rejected := 0, 0
	for _, path := range r.cfg.Files {
		p, n := newVPCParser(), 0
		err := eachLine(ctx, path, func(line string) {
			u, ok := p.parse(line)
			if !ok {
				return
			}
			n++
			if u.rejected {
				rejected++
			}
			clock = max(clock, u.end)
			agg.add(u, clock)
			if clock-lastTick >= 1000 {
				agg.tick(clock, false)
				lastTick = clock
			}
			if pendingLen(out) >= model.MaxBatchRecords/2 {
				out.flush(ctx)
			}
		})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		total += n
		r.log.Info("log di flusso importato", "file", path, "record", n)
	}
	agg.flushAll()
	out.flush(ctx)
	r.log.Info("importazione completata", "record", total, "rifiutati", rejected, "record_inviati", r.sent.Load(), "scartati", out.dropped.Load())
	return ctx.Err()
}
