package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hyperwave/internal/model"
)

// Sensor è un sensore autenticato.
type Sensor struct {
	ID   int64
	Name string
	Site string
}

// sensorAuth tiene in memoria per 30 secondi i token verificati: niente query a ogni batch.
type sensorAuth struct {
	mu    sync.Mutex
	cache map[[32]byte]authEntry
}

type authEntry struct {
	s     *Sensor // nil = token non valido
	until time.Time
}

func newSensorAuth() *sensorAuth { return &sensorAuth{cache: map[[32]byte]authEntry{}} }

func (a *sensorAuth) flush() {
	a.mu.Lock()
	a.cache = map[[32]byte]authEntry{}
	a.mu.Unlock()
}

var errBadToken = errors.New("token del sensore non valido o sensore disattivato")

func (h *Hub) authenticate(ctx context.Context, token string) (*Sensor, error) {
	if len(token) < 20 || len(token) > 200 {
		return nil, errBadToken
	}
	sum := sha256.Sum256([]byte(token))
	now := time.Now()
	h.auth.mu.Lock()
	e, ok := h.auth.cache[sum]
	h.auth.mu.Unlock()
	if ok && now.Before(e.until) {
		if e.s == nil {
			return nil, errBadToken
		}
		return e.s, nil
	}
	s := &Sensor{}
	err := h.pg.QueryRow(ctx, "SELECT id, name, site FROM sensors WHERE token_hash = $1 AND enabled", sum[:]).Scan(&s.ID, &s.Name, &s.Site)
	if errors.Is(err, pgx.ErrNoRows) {
		s = nil
	} else if err != nil {
		return nil, err
	}
	h.auth.mu.Lock()
	if len(h.auth.cache) > 10_000 {
		h.auth.cache = map[[32]byte]authEntry{}
	}
	h.auth.cache[sum] = authEntry{s, now.Add(30 * time.Second)}
	h.auth.mu.Unlock()
	if s == nil {
		return nil, errBadToken
	}
	return s, nil
}

func (h *Hub) heartbeat(ctx context.Context, s *Sensor, hb model.Heartbeat) (lastIngest int64, err error) {
	stats, _ := json.Marshal(hb.Stats)
	if len(stats) > 16<<10 {
		stats = []byte("{}")
	}
	var li *time.Time
	err = h.pg.QueryRow(ctx, `UPDATE sensors SET last_seen = now(), version = left($2, 64), mode = left($3, 32),
		hostname = left($4, 255), stats = $5 WHERE id = $1 RETURNING last_ingest`,
		s.ID, hb.Version, hb.Mode, hb.Hostname, stats).Scan(&li)
	if li != nil {
		lastIngest = li.UnixMilli()
	}
	return lastIngest, err
}

// checkSensors apre un allarme per i sensori che non comunicano da 2 minuti
// e lo chiude da solo quando tornano.
func (h *Hub) checkSensors(ctx context.Context) error {
	rows, err := h.pg.Query(ctx, `SELECT id, name, site, last_seen < now() - interval '2 minutes'
		FROM sensors WHERE enabled AND last_seen IS NOT NULL`)
	if err != nil {
		return err
	}
	type row struct {
		id         int64
		name, site string
		offline    bool
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.site, &r.offline); err != nil {
			rows.Close()
			return err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range list {
		key := fmt.Sprintf("sensor_offline|%d", r.id)
		if r.offline {
			where := r.name
			if r.site != "" {
				where += " (" + r.site + ")"
			}
			_, err := h.raise(ctx, Alert{
				Rule: "sensor_offline", DedupKey: key, SensorID: r.id, TS: time.Now(), NoCount: true,
				Title:   "Sensore non raggiungibile: " + r.name,
				Summary: "Il sensore " + where + " non comunica con l'hub da più di 2 minuti: il traffico che osserva non viene registrato.",
				Detail:  map[string]any{"sensor": r.name, "site": r.site},
			})
			if err != nil {
				return err
			}
		} else {
			tag, err := h.pg.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_by = 'sistema', resolved_at = now(),
				resolution = 'Il sensore ha ripreso a comunicare.' WHERE dedup_key = $1 AND status <> 'resolved'`, key)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				h.live.event("alert_resolved", map[string]any{"rule": "sensor_offline", "sensor": r.name})
			}
		}
	}
	return nil
}

var sensorName = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,62}$`)

// NewSensorToken genera un token: il valore va mostrato una volta sola, nel database resta lo sha256.
func NewSensorToken() (token string, hash []byte) {
	b := make([]byte, 32)
	rand.Read(b)
	token = "hws_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:]
}

// AddSensor registra un sensore e restituisce il suo token.
func AddSensor(ctx context.Context, pg *pgxpool.Pool, name, site, by string) (id int64, token string, err error) {
	name, site = strings.TrimSpace(name), strings.TrimSpace(site)
	if !sensorName.MatchString(name) {
		return 0, "", errors.New("nome del sensore non valido: 1-63 caratteri tra lettere, cifre, spazio, punto, trattino e underscore")
	}
	if len(site) > 100 {
		return 0, "", errors.New("nome della sede troppo lungo")
	}
	token, hash := NewSensorToken()
	err = pg.QueryRow(ctx, "INSERT INTO sensors (name, site, token_hash, created_by) VALUES ($1, $2, $3, $4) RETURNING id",
		name, site, hash, by).Scan(&id)
	if err != nil && strings.Contains(err.Error(), "sensors_name_key") {
		return 0, "", fmt.Errorf("esiste già un sensore chiamato %q", name)
	}
	return id, token, err
}
