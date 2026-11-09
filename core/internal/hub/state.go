package hub

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"hyperwave/internal/netx"
)

// RuntimeConfig sono le impostazioni modificabili dall'interfaccia (PG settings.config).
// I campi vuoti valgono come i valori di .env.
type RuntimeConfig struct {
	InternalNets  string `json:"internal_nets,omitempty"`
	SensitiveNets string `json:"sensitive_nets,omitempty"`
	LearningHours int    `json:"learning_hours,omitempty"`
	Timezone      string `json:"timezone,omitempty"`
}

// State contiene le impostazioni lette da PostgreSQL ogni 5 secondi e a ogni comando.
type State struct {
	def  Config
	live atomic.Bool

	mu        sync.RWMutex
	internal  netx.Nets
	sensitive netx.Nets
	learning  time.Duration
	loc       *time.Location
	vigilOK   *bool
	vigilAt   time.Time
}

func newState(cfg Config) *State {
	s := &State{def: cfg}
	s.live.Store(true)
	s.apply(RuntimeConfig{})
	return s
}

func (s *State) apply(rc RuntimeConfig) {
	in := netx.ParseNets(firstNonEmpty(rc.InternalNets, s.def.InternalNets))
	if len(in) == 0 {
		in = netx.ParseNets(netx.DefaultInternal)
	}
	hours := rc.LearningHours
	if hours <= 0 {
		hours = s.def.LearningHours
	}
	loc, err := time.LoadLocation(firstNonEmpty(rc.Timezone, s.def.Timezone))
	if err != nil {
		loc = time.UTC
	}
	s.mu.Lock()
	s.internal = in
	s.sensitive = netx.ParseNets(firstNonEmpty(rc.SensitiveNets, s.def.SensitiveNets))
	s.learning = time.Duration(hours) * time.Hour
	s.loc = loc
	s.mu.Unlock()
}

func (s *State) reload(ctx context.Context, pg *pgxpool.Pool) error {
	rows, err := pg.Query(ctx, "SELECT key, value FROM settings WHERE key IN ('live', 'config')")
	if err != nil {
		return err
	}
	defer rows.Close()
	rc := RuntimeConfig{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return err
		}
		switch key {
		case "live":
			var v bool
			if json.Unmarshal(raw, &v) == nil {
				s.live.Store(v)
			}
		case "config":
			json.Unmarshal(raw, &rc)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.apply(rc)
	return nil
}

func (s *State) Live() bool { return s.live.Load() }

func (s *State) Internal() netx.Nets {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.internal
}

func (s *State) Sensitive() netx.Nets {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sensitive
}

func (s *State) Learning() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.learning
}

func (s *State) Location() *time.Location {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loc
}

// setVigil scrive lo stato di Vigil solo quando cambia o ogni 5 minuti.
func (s *State) setVigil(ctx context.Context, pg *pgxpool.Pool, ok bool, msg string) error {
	s.mu.Lock()
	same := s.vigilOK != nil && *s.vigilOK == ok && time.Since(s.vigilAt) < 5*time.Minute
	if !same {
		s.vigilOK, s.vigilAt = &ok, time.Now()
	}
	s.mu.Unlock()
	if same {
		return nil
	}
	val, _ := json.Marshal(map[string]any{"ok": ok, "error": msg, "checked_at": time.Now().UnixMilli()})
	_, err := pg.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('vigil', $1, now(), 'hub')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, val)
	return err
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
