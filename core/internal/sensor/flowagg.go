package sensor

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"hyperwave/internal/classify"
	"hyperwave/internal/model"
)

// I router, gli switch e i log di flusso del cloud descrivono ogni conversazione con due
// record separati, uno per verso. L'aggregatore li riunisce nello stesso flusso con client e
// server, come quelli che il sensore ricava dai pacchetti, e calcola i contatori di banda.

const (
	aggIdle   = 30_000  // ms senza record prima di chiudere un flusso
	aggActive = 300_000 // i flussi lunghi vengono riportati ogni 5 minuti
	aggMax    = 400_000
)

// uniRec è un record di flusso in un verso solo.
type uniRec struct {
	start, end int64 // ms
	proto      uint8
	src, dst   netip.Addr
	sp, dp     uint16
	vlan       uint16
	bytes      uint64
	pkts       uint64
	flags      uint8
	// alcuni esportatori (IPFIX bidirezionale, firewall) riportano anche il verso opposto
	revBytes, revPkts uint64
	revFlags          uint8
	rejected          bool // log di flusso del cloud: traffico bloccato
}

type aggFlow struct {
	cli, srv    netip.AddrPort
	proto       uint8
	vlan        uint16
	dport       uint16
	start, end  int64
	seen        int64 // orologio dell'aggregatore all'ultimo record
	bOut, bIn   uint64
	pOut, pIn   uint64
	flags       uint8
	revFlags    uint8
	rev         bool
	rejected    bool
	exportStart int64
}

type aggregator struct {
	r   *Runner
	out *sink

	mu    sync.Mutex
	flows map[flowKey]*aggFlow

	rateStart              int64
	rIn, rOut, rInt, rPkts uint64
	records, full          atomic.Uint64
}

func newAggregator(r *Runner, out *sink) *aggregator {
	a := &aggregator{r: r, out: out, flows: map[flowKey]*aggFlow{}}
	r.addStat("flow_records", func() any { return a.records.Load() })
	r.addStat("flow_table_full", func() any { return a.full.Load() })
	r.addStat("flows_active", func() any { a.mu.Lock(); defer a.mu.Unlock(); return len(a.flows) })
	return a
}

// add aggiunge un record; clock è l'orologio usato per le scadenze (ms).
func (a *aggregator) add(rec uniRec, clock int64) {
	if !rec.src.IsValid() || !rec.dst.IsValid() {
		return
	}
	rec.src, rec.dst = rec.src.Unmap(), rec.dst.Unmap()
	if rec.end < rec.start {
		rec.end = rec.start
	}
	if rec.proto == 1 || rec.proto == 58 {
		// NetFlow mette tipo e codice ICMP nella porta di destinazione
		rec.dp, rec.sp = rec.dp>>8, 0
	}
	a.records.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()

	nets := a.r.Nets()
	si, di := nets.ContainsAddr(rec.src), nets.ContainsAddr(rec.dst)
	n := rec.bytes + rec.revBytes
	a.rPkts += rec.pkts + rec.revPkts
	switch {
	case si && di:
		a.rInt += n
	case si:
		a.rOut += rec.bytes
		a.rIn += rec.revBytes
	case di:
		a.rIn += rec.bytes
		a.rOut += rec.revBytes
	}

	s, d := netip.AddrPortFrom(rec.src, rec.sp), netip.AddrPortFrom(rec.dst, rec.dp)
	key := flowKey{a: s, b: d, proto: rec.proto, vlan: rec.vlan}
	if s.Compare(d) > 0 {
		key.a, key.b = d, s
	}
	f := a.flows[key]
	if f == nil {
		if len(a.flows) >= aggMax {
			a.full.Add(1)
			return
		}
		cliIsSrc := true
		switch {
		// i flag dei record di flusso sono cumulativi: solo un SYN senza ACK indica con certezza il client
		case rec.proto == 6 && rec.flags&fSYN != 0 && rec.flags&fACK == 0:
			cliIsSrc = true
		case rec.proto == 1 || rec.proto == 58:
			cliIsSrc = rec.dp != 0 && rec.dp != 129 // le risposte all'eco partono dal "server"
		case servicePort(rec.proto, rec.dp) != servicePort(rec.proto, rec.sp):
			cliIsSrc = servicePort(rec.proto, rec.dp)
		case rec.sp < rec.dp:
			cliIsSrc = false // la porta più bassa è di solito quella del servizio
		}
		f = &aggFlow{cli: s, srv: d, proto: rec.proto, vlan: rec.vlan, start: rec.start, end: rec.end, dport: rec.dp, exportStart: clock}
		if !cliIsSrc {
			f.cli, f.srv, f.dport = d, s, rec.sp
		}
		if rec.proto == 1 || rec.proto == 58 {
			f.dport = rec.dp
		}
		a.flows[key] = f
	}
	f.start, f.end, f.seen = min(f.start, rec.start), max(f.end, rec.end), clock
	f.rejected = f.rejected || rec.rejected
	if s == f.cli {
		f.bOut += rec.bytes
		f.pOut += rec.pkts
		f.flags |= rec.flags
		if rec.revPkts > 0 || rec.revBytes > 0 {
			f.bIn += rec.revBytes
			f.pIn += rec.revPkts
			f.revFlags |= rec.revFlags
			f.rev = true
		}
	} else {
		f.bIn += rec.bytes
		f.pIn += rec.pkts
		f.revFlags |= rec.flags
		f.rev = true
		if rec.revPkts > 0 || rec.revBytes > 0 {
			f.bOut += rec.revBytes
			f.pOut += rec.revPkts
			f.flags |= rec.revFlags
		}
	}
}

func (a *aggregator) export(f *aggFlow) {
	est := f.rev && !f.rejected
	if f.proto == 6 && f.revFlags != 0 && f.revFlags&fRST != 0 && f.revFlags&fSYN == 0 {
		est = false // il server ha solo rifiutato
	}
	mf := model.Flow{TS: f.start, End: f.end, VLAN: f.vlan, Proto: protoName(f.proto),
		SrcIP: f.cli.Addr().String(), SrcPort: f.cli.Port(), DstIP: f.srv.Addr().String(), DstPort: f.dport,
		BytesOut: f.bOut, BytesIn: f.bIn, PktsOut: uint32(min(f.pOut, 1<<32-1)), PktsIn: uint32(min(f.pIn, 1<<32-1)), Est: est}
	if f.proto == 6 {
		mf.Flags = flagString(f.flags | f.revFlags)
	}
	if f.proto == 1 || f.proto == 58 {
		mf.SrcPort = 0
	}
	if f.bOut+f.bIn > 0 || f.pOut+f.pIn > 0 {
		a.out.put(func(b *model.Batch) { b.Flows = append(b.Flows, mf) })
	}
}

// tick chiude i flussi scaduti e, se rates è vero, invia i contatori ogni 5 secondi.
func (a *aggregator) tick(clock int64, rates bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, f := range a.flows {
		switch {
		case clock-f.seen > aggIdle:
			a.export(f)
			delete(a.flows, k)
		case clock-f.exportStart > aggActive:
			a.export(f)
			f.start, f.bOut, f.bIn, f.pOut, f.pIn, f.exportStart = f.end, 0, 0, 0, 0, clock
		}
	}
	if !rates {
		return
	}
	if a.rateStart == 0 {
		a.rateStart = clock
	}
	if clock-a.rateStart >= rateEvery {
		r := model.Rate{TS: a.rateStart, Seconds: float64(clock-a.rateStart) / 1000, BytesIn: a.rIn, BytesOut: a.rOut, BytesInternal: a.rInt,
			Packets: a.rPkts, Flows: uint64(len(a.flows))}
		a.out.put(func(b *model.Batch) { b.Rates = append(b.Rates, r) })
		a.rateStart, a.rIn, a.rOut, a.rInt, a.rPkts = clock, 0, 0, 0, 0
	}
}

func (a *aggregator) flushAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, f := range a.flows {
		a.export(f)
		delete(a.flows, k)
	}
}

// servicePort dice se la porta è di un servizio noto (e quindi probabilmente quella del server).
func servicePort(proto uint8, port uint16) bool {
	return port != 0 && (port < 1024 || classify.ByPort(protoName(proto), port) != "")
}
