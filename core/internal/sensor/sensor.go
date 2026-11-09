// Package sensor osserva la rete (o la simula) e invia all'hub flussi, metadati e contatori.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperwave/internal/model"
	"hyperwave/internal/netx"
	"hyperwave/internal/version"
)

// Config raccoglie le impostazioni del sensore (variabili HW_* e opzioni della riga di comando).
type Config struct {
	HubURL   string
	Token    string
	CAFile   string
	Mode     string   // demo | capture | pcap
	Ifaces   []string // capture
	Files    []string // pcap
	Timezone string   // demo: andamento giornaliero

	Snaplen     int
	Promisc     bool
	IgnoreNets  string // traffico da non registrare (per esempio quello del sensore verso l'hub)
	SuricataEve string // eve.json di Suricata da cui leggere gli allarmi IDS
	MaxPending  int    // record in attesa oltre i quali si scarta (hub non raggiungibile)
}

// Runner tiene lo stato condiviso tra raccolta, invio e heartbeat.
type Runner struct {
	cfg      Config
	log      *slog.Logger
	cl       *Client
	hostname string

	live       atomic.Bool
	lastIngest atomic.Int64
	nets       atomic.Pointer[netx.Nets]
	sent       atomic.Int64
	started    time.Time

	statsMu sync.Mutex
	stats   map[string]func() any // contatori aggiuntivi della modalità attiva
}

func New(cfg Config, log *slog.Logger) (*Runner, error) {
	if cfg.HubURL == "" {
		return nil, errors.New("manca HW_HUB_URL")
	}
	if cfg.Token == "" {
		return nil, errors.New("manca HW_SENSOR_TOKEN: registrare il sensore sull'hub (hw-hub sensor-add) e copiarne il token")
	}
	switch cfg.Mode {
	case "demo", "capture", "pcap":
	default:
		return nil, fmt.Errorf("modalità %q sconosciuta: demo, capture o pcap", cfg.Mode)
	}
	if cfg.Mode == "capture" && len(cfg.Ifaces) == 0 {
		return nil, errors.New("indicare l'interfaccia da osservare (-iface o HW_IFACE)")
	}
	if cfg.Mode == "pcap" && len(cfg.Files) == 0 {
		return nil, errors.New("indicare almeno un file pcap (-file)")
	}
	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 65536
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 500_000
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "Europe/Rome"
	}
	cl, err := NewClient(cfg.HubURL, cfg.Token, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	r := &Runner{cfg: cfg, log: log, cl: cl, hostname: host, started: time.Now(), stats: map[string]func() any{}}
	def := netx.ParseNets(netx.DefaultInternal)
	r.nets.Store(&def)
	return r, nil
}

func (r *Runner) Nets() netx.Nets { return *r.nets.Load() }

func (r *Runner) addStat(name string, f func() any) {
	r.statsMu.Lock()
	r.stats[name] = f
	r.statsMu.Unlock()
}

// apply recepisce lo stato comunicato dall'hub: live, reti interne, ultimo dato ricevuto.
func (r *Runner) apply(rep model.HubReply) {
	r.live.Store(rep.Live)
	if len(rep.InternalNets) > 0 {
		n := netx.ParseNets(strings.Join(rep.InternalNets, ","))
		if len(n) > 0 {
			r.nets.Store(&n)
		}
	}
	for {
		cur := r.lastIngest.Load()
		if rep.LastIngest <= cur || r.lastIngest.CompareAndSwap(cur, rep.LastIngest) {
			break
		}
	}
}

func (r *Runner) heartbeat(ctx context.Context) error {
	r.statsMu.Lock()
	st := map[string]any{"sent": r.sent.Load(), "uptime": int64(time.Since(r.started).Seconds()), "goroutines": runtime.NumGoroutine()}
	for k, f := range r.stats {
		st[k] = f()
	}
	r.statsMu.Unlock()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	st["mem_mb"] = m.Alloc >> 20
	hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rep, err := r.cl.Heartbeat(hctx, model.Heartbeat{Version: version.Version, Mode: r.cfg.Mode, Hostname: r.hostname, Stats: st})
	if err != nil {
		return err
	}
	r.apply(rep)
	return nil
}

// Run si presenta all'hub e avvia la modalità scelta. Ritorna quando ctx viene annullato.
func (r *Runner) Run(ctx context.Context) error {
	r.log.Info("sensore avviato", "versione", version.Version, "modalità", r.cfg.Mode, "hub", r.cfg.HubURL)
	// il primo heartbeat serve a sapere se il live è acceso e da dove riprendere
	wait := 2 * time.Second
	for {
		err := r.heartbeat(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrUnauthorized) {
			r.log.Error("token rifiutato: controllare HW_SENSOR_TOKEN e che il sensore sia attivo sull'hub")
			wait = time.Minute
		} else {
			r.log.Warn("hub non raggiungibile", "err", err, "nuovo tentativo tra", wait)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Minute)
	}
	r.log.Info("collegato all'hub", "live", r.live.Load(), "reti_interne", strings.Join(r.Nets().Strings(), ","))

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		was := r.live.Load()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if err := r.heartbeat(ctx); err != nil && ctx.Err() == nil {
				r.log.Warn("heartbeat non riuscito", "err", err)
				continue
			}
			if now := r.live.Load(); now != was {
				was = now
				r.log.Info("stato live cambiato dall'hub", "live", now)
			}
		}
	}()

	switch r.cfg.Mode {
	case "demo":
		return r.runDemo(ctx)
	case "capture":
		return r.runCapture(ctx)
	default:
		return r.runPcap(ctx)
	}
}

// ---------------------------------------------------------------- sink

// sink accumula i record prodotti dalla cattura e li spedisce a intervalli.
// Se l'hub non risponde trattiene fino a MaxPending record, poi scarta i nuovi e lo conta.
type sink struct {
	r        *Runner
	backfill bool

	mu      sync.Mutex
	b       *model.Batch
	dropped atomic.Int64
	kick    chan struct{}
}

func newSink(r *Runner, backfill bool) *sink {
	s := &sink{r: r, backfill: backfill, b: &model.Batch{}, kick: make(chan struct{}, 1)}
	r.addStat("dropped_records", func() any { return s.dropped.Load() })
	r.addStat("pending_records", func() any { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Len() })
	return s
}

// put aggiunge record al batch in corso; con il live spento i dati vengono scartati.
func (s *sink) put(fn func(b *model.Batch)) {
	if !s.r.live.Load() {
		return
	}
	s.mu.Lock()
	n := s.b.Len()
	if n >= s.r.cfg.MaxPending {
		s.mu.Unlock()
		s.dropped.Add(1)
		return
	}
	fn(s.b)
	full := s.b.Len() >= model.MaxBatchRecords/2
	s.mu.Unlock()
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

func (s *sink) take() *model.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b.Len() == 0 {
		return nil
	}
	b := s.b
	s.b = &model.Batch{}
	return b
}

// split divide un batch troppo grande in parti accettate dall'hub.
func split(b *model.Batch, size int) []*model.Batch {
	if b.Len() <= size {
		return []*model.Batch{b}
	}
	var out []*model.Batch
	cur := &model.Batch{Backfill: b.Backfill, Demo: b.Demo}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur)
			cur = &model.Batch{Backfill: b.Backfill, Demo: b.Demo}
		}
	}
	room := func() bool { return cur.Len() < size }
	for _, x := range b.Hosts {
		cur.Hosts = append(cur.Hosts, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.Flows {
		cur.Flows = append(cur.Flows, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.DNS {
		cur.DNS = append(cur.DNS, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.TLS {
		cur.TLS = append(cur.TLS, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.HTTP {
		cur.HTTP = append(cur.HTTP, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.Events {
		cur.Events = append(cur.Events, x)
		if !room() {
			flush()
		}
	}
	for _, x := range b.Rates {
		cur.Rates = append(cur.Rates, x)
		if !room() {
			flush()
		}
	}
	flush()
	return out
}

// flush spedisce tutto ciò che è in attesa; Send riprova da solo finché l'hub risponde.
func (s *sink) flush(ctx context.Context) {
	b := s.take()
	if b == nil {
		return
	}
	b.Backfill = s.backfill
	for _, part := range split(b, model.MaxBatchRecords/2) {
		rep, err := s.r.cl.Send(ctx, part)
		if err != nil {
			if ctx.Err() == nil {
				s.r.log.Warn("batch rifiutato dall'hub", "err", err, "record", part.Len())
				s.dropped.Add(int64(part.Len()))
			}
			continue
		}
		s.r.apply(rep)
		s.r.sent.Add(int64(rep.Accepted))
	}
}

// loop spedisce ogni intervallo, o prima se il batch è pieno, fino all'annullamento di ctx.
func (s *sink) loop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
		s.flush(ctx)
	}
}
