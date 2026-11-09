package hub

import (
	"encoding/json"
	"sync"
	"time"

	"hyperwave/internal/model"
)

// livePublisher pubblica su NATS ciò che serve alla vista in tempo reale.
// Soggetti: hw.live.state (ogni 5 s), hw.live.rate, hw.live.flows (campione), hw.live.event.
type livePublisher struct {
	h *Hub

	mu       sync.Mutex
	rates    map[int64]liveRate
	budget   int
	budgetAt time.Time
}

type liveRate struct {
	Sensor   string  `json:"sensor"`
	TS       int64   `json:"ts"`
	BpsIn    float64 `json:"bps_in"`
	BpsOut   float64 `json:"bps_out"`
	BpsInt   float64 `json:"bps_int"`
	Pps      float64 `json:"pps"`
	Flows    uint64  `json:"flows"`
	Drops    uint64  `json:"drops"`
	received time.Time
}

// flussi al secondo inviati al browser: abbastanza per vederli scorrere, pochi per non pesare
const flowSamplePerSecond = 25

func newLivePublisher(h *Hub) *livePublisher {
	return &livePublisher{h: h, rates: map[int64]liveRate{}}
}

func (l *livePublisher) pub(subject string, v any) {
	nc := l.h.nc
	if nc == nil || !nc.IsConnected() {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	nc.Publish(subject, b)
}

func (l *livePublisher) event(kind string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["kind"] = kind
	if _, ok := data["ts"]; !ok {
		data["ts"] = time.Now().UnixMilli()
	}
	l.pub("hw.live.event", data)
}

type liveFlow struct {
	TS     string `json:"t"`
	Src    string `json:"s"`
	Dst    string `json:"d"`
	SName  string `json:"sn,omitempty"`
	DName  string `json:"dn,omitempty"`
	Proto  string `json:"p"`
	DPort  uint16 `json:"dp"`
	App    string `json:"a,omitempty"`
	Domain string `json:"dom,omitempty"`
	Bytes  uint64 `json:"b"`
	CC     string `json:"cc,omitempty"`
	Dir    string `json:"dir"`
}

func (l *livePublisher) batch(s *Sensor, flows []any, b *model.Batch) {
	now := time.Now()
	l.mu.Lock()
	if now.Sub(l.budgetAt) >= time.Second {
		l.budget, l.budgetAt = flowSamplePerSecond, now
	}
	take := min(l.budget, len(flows))
	l.budget -= take
	for _, r := range b.Rates {
		secs := max(r.Seconds, 0.001)
		l.rates[s.ID] = liveRate{Sensor: s.Name, TS: r.TS, BpsIn: float64(r.BytesIn) * 8 / secs, BpsOut: float64(r.BytesOut) * 8 / secs,
			BpsInt: float64(r.BytesInternal) * 8 / secs, Pps: float64(r.Packets) / secs, Flows: r.Flows, Drops: r.Drops, received: now}
	}
	var last *liveRate
	if r, ok := l.rates[s.ID]; ok && len(b.Rates) > 0 {
		last = &r
	}
	l.mu.Unlock()

	if last != nil {
		l.pub("hw.live.rate", last)
	}
	if take > 0 {
		sample := make([]liveFlow, 0, take)
		step := float64(len(flows)) / float64(take)
		for i := 0; i < take; i++ {
			f := flows[int(float64(i)*step)].(FlowRow)
			sample = append(sample, liveFlow{f.TS, f.Src, f.Dst, f.SrcName, f.DstName, f.Proto, f.DPort, f.App, f.Domain, f.BytesOut + f.BytesIn, f.Country, f.Direction})
		}
		l.pub("hw.live.flows", sample)
	}
	for _, ev := range b.Events {
		l.event("ids", map[string]any{"ts": ev.TS, "severity": ev.Severity, "title": ev.Title, "src": ev.SrcIP, "dst": ev.DstIP, "sig": ev.Signature})
	}
}

func (l *livePublisher) publishState() {
	now := time.Now()
	l.mu.Lock()
	var in, out, internal, pps float64
	var flows, drops uint64
	sensors := 0
	for id, r := range l.rates {
		if now.Sub(r.received) > 30*time.Second {
			delete(l.rates, id)
			continue
		}
		in, out, internal, pps = in+r.BpsIn, out+r.BpsOut, internal+r.BpsInt, pps+r.Pps
		flows += r.Flows
		drops += r.Drops
		sensors++
	}
	l.mu.Unlock()
	l.pub("hw.live.state", map[string]any{
		"ts": now.UnixMilli(), "live": l.h.state.Live(), "sensors_sending": sensors,
		"bps_in": in, "bps_out": out, "bps_int": internal, "pps": pps, "flows": flows, "drops": drops,
	})
}
