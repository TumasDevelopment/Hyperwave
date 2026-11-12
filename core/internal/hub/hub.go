// Package hub riceve i dati dai sensori, li arricchisce, li scrive nei database,
// mantiene l'inventario, esegue le regole di rilevamento e pubblica gli eventi live.
package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"hyperwave/internal/chx"
	"hyperwave/internal/env"
	"hyperwave/internal/netx"
	"hyperwave/internal/store"
	"hyperwave/internal/version"
)

// Config viene dalle variabili d'ambiente (file .env).
type Config struct {
	DatabaseURL      string
	ClickHouseURL    string
	ClickHouseDB     string
	ClickHouseUser   string
	ClickHousePass   string
	NATSURL          string
	NATSToken        string
	Listen           string
	InternalNets     string
	SensitiveNets    string
	RetentionDays    int
	AggRetentionDays int
	AlertRetention   int // giorni per gli allarmi chiusi
	AuditRetention   int // giorni per il registro delle attività
	GeoIPCity        string
	GeoIPASN         string
	OUIPath          string
	VigilURL         string
	LearningHours    int
	Timezone         string
	LeaderMode       string // auto | never (istanza di sola ricezione)
}

func ConfigFromEnv() Config {
	return Config{
		DatabaseURL:      env.Str("DATABASE_URL", ""),
		ClickHouseURL:    env.Str("CLICKHOUSE_URL", "http://127.0.0.1:8123"),
		ClickHouseDB:     env.Str("CLICKHOUSE_DB", "hyperwave"),
		ClickHouseUser:   env.Str("CLICKHOUSE_USER", "hyperwave"),
		ClickHousePass:   env.Str("CLICKHOUSE_PASSWORD", ""),
		NATSURL:          env.Str("NATS_URL", "nats://127.0.0.1:4222"),
		NATSToken:        env.Str("NATS_TOKEN", ""),
		Listen:           env.Str("HW_HUB_LISTEN", "127.0.0.1:3121"),
		InternalNets:     env.Str("HW_INTERNAL_NETS", netx.DefaultInternal),
		SensitiveNets:    env.Str("HW_SENSITIVE_NETS", ""),
		RetentionDays:    env.Int("HW_RETENTION_DAYS", 30),
		AggRetentionDays: env.Int("HW_AGG_RETENTION_DAYS", 400),
		AlertRetention:   env.Int("HW_ALERT_RETENTION_DAYS", 365),
		AuditRetention:   env.Int("HW_AUDIT_RETENTION_DAYS", 730),
		GeoIPCity:        env.Str("HW_GEOIP_CITY", ""),
		GeoIPASN:         env.Str("HW_GEOIP_ASN", ""),
		OUIPath:          env.Str("HW_OUI_CSV", "/usr/share/ieee-data/oui.csv"),
		VigilURL:         strings.TrimRight(env.Str("VIGIL_URL", ""), "/"),
		LearningHours:    env.Int("HW_LEARNING_HOURS", 24),
		Timezone:         env.Str("HW_TZ", "Europe/Rome"),
		LeaderMode:       env.Str("HW_HUB_LEADER", "auto"),
	}
}

// Hub tiene le connessioni e lo stato condiviso tra ingest, inventario e motore.
type Hub struct {
	cfg        Config
	log        *slog.Logger
	pg         *pgxpool.Pool
	ch         *chx.Client
	nc         *nats.Conn
	state      *State
	enr        *Enricher
	inv        *Inventory
	eng        *Engine
	live       *livePublisher
	auth       *sensorAuth
	lead       *leadership
	supp       *suppressions
	intel      *intel
	customBusy atomic.Bool // prova di una regola personalizzata in corso
	marks      sync.Map    // sensorID → true se il sensore sta mandando storico a questa istanza
	start      time.Time
	ingest     ingestStats
}

// Connect apre i database, applica le migrazioni e si collega a NATS.
func Connect(ctx context.Context, cfg Config, log *slog.Logger) (*Hub, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("DATABASE_URL è vuota")
	}
	h := &Hub{cfg: cfg, log: log, start: time.Now()}

	pg, err := store.OpenPG(ctx, cfg.DatabaseURL, 12)
	if err != nil {
		return nil, err
	}
	h.pg = pg
	if applied, err := store.MigratePG(ctx, pg); err != nil {
		return nil, err
	} else if len(applied) > 0 {
		log.Info("migrazioni PostgreSQL applicate", "file", applied)
	}

	h.ch = chx.New(cfg.ClickHouseURL, cfg.ClickHouseDB, cfg.ClickHouseUser, cfg.ClickHousePass)
	if err := h.ch.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ClickHouse non raggiungibile: %w", err)
	}
	if applied, err := store.MigrateCH(ctx, h.ch, store.CHOptions{RetentionDays: cfg.RetentionDays, AggRetentionDays: cfg.AggRetentionDays}); err != nil {
		return nil, err
	} else if len(applied) > 0 {
		log.Info("migrazioni ClickHouse applicate", "file", applied)
	}

	h.state = newState(cfg)
	if err := h.state.reload(ctx, pg); err != nil {
		return nil, err
	}
	h.enr = newEnricher(cfg, log)
	h.auth = newSensorAuth()
	h.supp = &suppressions{}
	h.inv = newInventory(h)
	if err := h.inv.load(ctx); err != nil {
		return nil, err
	}
	h.eng = newEngine(h)
	if err := h.eng.loadCustom(ctx); err != nil {
		return nil, fmt.Errorf("regole personalizzate: %w", err)
	}
	if err := h.eng.saveCustomSchema(ctx); err != nil {
		return nil, err
	}
	if err := h.eng.syncCatalog(ctx); err != nil {
		return nil, err
	}
	h.intel = newIntel(h)
	if err := h.intel.syncPresets(ctx); err != nil {
		return nil, fmt.Errorf("elenchi di minaccia: %w", err)
	}
	if err := h.intel.load(ctx); err != nil {
		return nil, fmt.Errorf("elenchi di minaccia: %w", err)
	}

	// NATS serve solo alla parte live: se non c'è, l'hub lavora lo stesso e riprova da solo.
	opts := []nats.Option{
		nats.Name("hyperwave-hub " + version.Version),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.RetryOnFailedConnect(true),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn("NATS disconnesso", "err", err)
			}
		}),
		nats.ReconnectHandler(func(*nats.Conn) { log.Info("NATS riconnesso") }),
	}
	if cfg.NATSToken != "" {
		opts = append(opts, nats.Token(cfg.NATSToken))
	}
	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("NATS: %w", err)
	}
	h.nc = nc
	h.live = newLivePublisher(h)
	if h.lead, err = newLeadership(cfg.DatabaseURL, cfg.LeaderMode); err != nil {
		return nil, err
	}
	h.lead.onGain = func() {
		// un'altra istanza può aver fatto avanzare il cursore del motore: si rilegge dal database
		h.eng.resetCursor()
		h.log.Info("questa istanza è ora il capo: motore, correlatore, controllo dei sensori e pulizia girano qui")
	}
	h.lead.onLose = func() { h.log.Warn("questa istanza non è più il capo") }
	return h, nil
}

func (h *Hub) Close() {
	if h.lead != nil {
		h.lead.release()
	}
	if h.nc != nil {
		h.nc.Drain()
	}
	h.enr.close()
	h.pg.Close()
}

// Run avvia il server HTTP e le attività periodiche; termina quando ctx viene annullato.
func (h *Hub) Run(ctx context.Context) error {
	// Il web avvisa l'hub quando cambia qualcosa: niente attesa del giro successivo.
	// Questi comandi arrivano a tutte le istanze, perché ognuna tiene la sua copia delle impostazioni.
	sub, err := h.nc.Subscribe("hw.control.>", func(m *nats.Msg) {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		switch m.Subject {
		case "hw.control.customtest":
			return // va a una sola istanza: sottoscrizione a gruppo qui sotto
		case "hw.control.sensors":
			h.auth.flush()
		case "hw.control.rules":
			if err := h.eng.loadCustom(rctx); err != nil {
				h.log.Warn("regole personalizzate", "err", err)
			}
			if err := h.eng.syncCatalog(rctx); err != nil {
				h.log.Warn("catalogo delle regole", "err", err)
			}
			h.supp.load(rctx, h.pg)
		case "hw.control.intel":
			h.intel.control(rctx, m.Data)
		default:
			if err := h.state.reload(rctx, h.pg); err != nil {
				h.log.Warn("rilettura impostazioni", "err", err)
			}
		}
		h.log.Info("comando ricevuto", "subject", m.Subject)
		h.live.publishState()
	})
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	// la prova di una regola sullo storico la fa una sola istanza, scelta da NATS
	testSub, err := h.nc.QueueSubscribe("hw.control.customtest", "hyperwave-hub", func(m *nats.Msg) {
		h.log.Info("comando ricevuto", "subject", m.Subject)
		h.customTestHandler(ctx, m)
	})
	if err != nil {
		return err
	}
	defer testSub.Unsubscribe()
	// le istanze che non sono capo inviano al capo la banda dei sensori che ricevono
	ratesSub, err := h.nc.Subscribe(liveRatesSubject, func(m *nats.Msg) {
		if h.lead.Is() {
			h.live.mergeRates(m.Data)
		}
	})
	if err != nil {
		return err
	}
	defer ratesSub.Unsubscribe()

	srv := &http.Server{
		Addr:              h.cfg.Listen,
		Handler:           h.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		h.log.Info("hub in ascolto", "addr", h.cfg.Listen, "version", version.Version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	// prima elezione subito, così un'istanza sola parte già come capo
	if err := h.lead.step(ctx); err != nil {
		h.log.Warn("elezione del capo", "err", err)
	}

	var wg sync.WaitGroup
	every := func(name string, d time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(d)
			defer t.Stop()
			for {
				if err := fn(ctx); err != nil && ctx.Err() == nil {
					h.log.Warn("attività periodica", "task", name, "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	// leaderOnly: attività che devono girare su una sola istanza alla volta
	leaderOnly := func(fn func(context.Context) error) func(context.Context) error {
		return func(ctx context.Context) error {
			if !h.lead.Is() {
				return nil
			}
			return fn(ctx)
		}
	}
	every("capo", leaderCheck, h.lead.step)
	every("live", 5*time.Second, func(ctx context.Context) error {
		err := h.state.reload(ctx, h.pg)
		h.live.publishState()
		return err
	})
	// su tutte le istanze: svuotano ciò che ognuna ha raccolto in memoria o aggiornano le sue copie
	every("inventario", 10*time.Second, h.inv.flush)
	every("nomi", 60*time.Second, func(ctx context.Context) error { return h.enr.refreshNames(ctx, h.pg) })
	every("eccezioni", 60*time.Second, func(ctx context.Context) error { return h.supp.load(ctx, h.pg) })
	every("minacce-allarmi", 30*time.Second, h.intel.flushHits)
	every("minacce-copia", 15*time.Minute, h.intel.refresh)
	// solo sul capo
	every("motore", 60*time.Second, leaderOnly(h.eng.tick))
	every("sensori", 20*time.Second, leaderOnly(h.checkSensors))
	every("minacce", 5*time.Minute, leaderOnly(h.intel.tick))
	every("incidenti", 60*time.Second, leaderOnly(h.correlate))
	every("pulizia", time.Hour, leaderOnly(h.cleanup))
	if h.cfg.VigilURL != "" {
		every("vigil", 30*time.Second, leaderOnly(h.checkVigil))
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	wg.Wait()
	// ultimo salvataggio dell'inventario raccolto in memoria
	return h.inv.flush(sctx)
}

// cleanup cancella da PostgreSQL ciò che ha superato la conservazione.
// ClickHouse si pulisce da solo con i TTL.
func (h *Hub) cleanup(ctx context.Context) error {
	stmts := []struct {
		sql  string
		args []any
	}{
		{"DELETE FROM sessions WHERE expires_at < now()", nil},
		{"DELETE FROM login_failures WHERE reset_at < now()", nil},
		{"DELETE FROM backfill_marks WHERE at < now() - interval '1 hour'", nil},
		{"DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < now() - make_interval(days => $1)", []any{h.cfg.AlertRetention}},
		{"DELETE FROM incidents WHERE status = 'closed' AND closed_at < now() - make_interval(days => $1)", []any{h.cfg.AlertRetention}},
		{"DELETE FROM audit_log WHERE ts < now() - make_interval(days => $1)", []any{h.cfg.AuditRetention}},
		{"DELETE FROM suppressions WHERE expires_at < now() - interval '30 days'", nil},
		{"DELETE FROM intel_indicators WHERE expires_at < now() - interval '1 day'", nil},
		{"DELETE FROM device_services WHERE last_seen < now() - make_interval(days => $1)", []any{h.cfg.AggRetentionDays}},
	}
	for _, s := range stmts {
		if _, err := h.pg.Exec(ctx, s.sql, s.args...); err != nil {
			return err
		}
	}
	return nil
}

// checkVigil registra se Vigil (il monitoraggio dei dispositivi) è raggiungibile.
func (h *Hub) checkVigil(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ok, msg := false, ""
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, h.cfg.VigilURL+"/api/salute", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		msg = "non raggiungibile"
	} else {
		res.Body.Close()
		ok = res.StatusCode == http.StatusOK
		if !ok {
			msg = fmt.Sprintf("risposta %d", res.StatusCode)
		}
	}
	return h.state.setVigil(ctx, h.pg, ok, msg)
}
