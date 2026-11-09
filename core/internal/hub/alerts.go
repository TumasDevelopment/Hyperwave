package hub

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Alert è un allarme da aprire o da aggiornare se ne esiste già uno aperto con la stessa DedupKey.
type Alert struct {
	Rule     string
	Severity string // vuota = quella della regola
	DedupKey string
	Title    string
	Summary  string
	Src, Dst string
	DeviceID int64
	SensorID int64
	Detail   map[string]any
	TS       time.Time // momento dei dati, non dell'analisi
	NoCount  bool      // aggiorna senza incrementare il conteggio (es. sensore offline)
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// raise applica abilitazione, gravità configurata ed eccezioni, poi apre o aggiorna l'allarme.
// Restituisce 0 se l'allarme è stato scartato.
func (h *Hub) raise(ctx context.Context, a Alert) (int64, error) {
	rule, ok := h.eng.rule(a.Rule)
	if ok && !rule.Enabled {
		return 0, nil
	}
	if ok && rule.SeverityOverride != "" {
		a.Severity = rule.SeverityOverride
	}
	if a.Severity == "" {
		a.Severity = "medium"
		if ok {
			a.Severity = rule.Severity
		}
	}
	if _, valid := sevRank[a.Severity]; !valid {
		a.Severity = "medium"
	}
	if id := h.supp.match(a.Rule, a.Src, a.Dst); id != 0 {
		_, err := h.pg.Exec(ctx, "UPDATE suppressions SET hits = hits + 1, last_hit = now() WHERE id = $1", id)
		return 0, err
	}
	if a.DeviceID == 0 && a.Src != "" {
		a.DeviceID = h.enr.device(a.Src).id
	}
	if a.TS.IsZero() {
		a.TS = time.Now()
	}
	if len(a.Title) > 300 {
		a.Title = a.Title[:300]
	}
	detail, _ := json.Marshal(a.Detail)
	if a.Detail == nil {
		detail = []byte("{}")
	}
	mitre := ""
	if ok {
		mitre = rule.Mitre
	}
	inc := 1
	if a.NoCount {
		inc = 0
	}
	var id int64
	var inserted bool
	err := h.pg.QueryRow(ctx, `INSERT INTO alerts (dedup_key, rule, severity, title, summary, src_ip, dst_ip, device_id, sensor_id, mitre, detail, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, 0), NULLIF($9, 0), $10, $11, $12, $12)
		ON CONFLICT (dedup_key) WHERE status <> 'resolved' DO UPDATE SET
			last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen),
			count = alerts.count + $13,
			severity = CASE WHEN array_position(ARRAY['info','low','medium','high','critical'], EXCLUDED.severity)
				> array_position(ARRAY['info','low','medium','high','critical'], alerts.severity) THEN EXCLUDED.severity ELSE alerts.severity END,
			title = EXCLUDED.title, summary = EXCLUDED.summary, detail = EXCLUDED.detail,
			device_id = COALESCE(alerts.device_id, EXCLUDED.device_id)
		RETURNING id, (xmax = 0)`,
		a.DedupKey, a.Rule, a.Severity, a.Title, a.Summary, a.Src, a.Dst, a.DeviceID, a.SensorID, mitre, detail, a.TS, inc,
	).Scan(&id, &inserted)
	if err != nil {
		h.log.Warn("salvataggio allarme", "rule", a.Rule, "err", err)
		return 0, err
	}
	// live solo per ciò che è successo da poco: i dati storici non devono far scattare notifiche
	if time.Since(a.TS) < 10*time.Minute {
		kind := "alert_updated"
		if inserted {
			kind = "alert"
		}
		h.live.event(kind, map[string]any{
			"id": id, "rule": a.Rule, "severity": a.Severity, "title": a.Title, "src": a.Src, "dst": a.Dst, "ts": a.TS.UnixMilli(),
		})
	}
	return id, nil
}

// suppressions sono le eccezioni configurate dalle persone, tenute in memoria.
type suppressions struct {
	mu   sync.RWMutex
	list []suppression
}

type suppression struct {
	id       int64
	rule     string
	src, dst netip.Prefix // non valido = qualsiasi
}

func parseTarget(s string) netip.Prefix {
	if s == "" {
		return netip.Prefix{}
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	// un valore non valido non deve mai diventare "qualsiasi"
	return netip.PrefixFrom(netip.IPv6Unspecified(), 128)
}

func (s *suppressions) load(ctx context.Context, pg *pgxpool.Pool) error {
	rows, err := pg.Query(ctx, "SELECT id, rule, src, dst FROM suppressions WHERE expires_at IS NULL OR expires_at > now()")
	if err != nil {
		return err
	}
	defer rows.Close()
	var list []suppression
	for rows.Next() {
		var id int64
		var rule, src, dst string
		if err := rows.Scan(&id, &rule, &src, &dst); err != nil {
			return err
		}
		list = append(list, suppression{id, rule, parseTarget(src), parseTarget(dst)})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.list = list
	s.mu.Unlock()
	return nil
}

func matchIP(p netip.Prefix, ip string) bool {
	if !p.IsValid() {
		return true
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && p.Contains(a.Unmap())
}

func (s *suppressions) match(rule, src, dst string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, x := range s.list {
		if (x.rule == "" || x.rule == rule) && matchIP(x.src, src) && matchIP(x.dst, dst) {
			return x.id
		}
	}
	return 0
}
