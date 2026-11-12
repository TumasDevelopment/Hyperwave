package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperwave/internal/chx"
)

// RuleDef descrive una regola. Run è nil per le regole valutate altrove (inventario, sensori).
type RuleDef struct {
	ID          string
	Name        string
	Category    string
	Description string
	Severity    string
	Mitre       string
	Params      params
	Help        map[string]string
	Every       int           // ogni quanti minuti
	Window      time.Duration // finestra di dati analizzata
	Run         func(ctx context.Context, e *Engine, w window, p params) ([]Alert, error)
}

// ruleState è la regola con le scelte degli amministratori applicate.
type ruleState struct {
	Enabled          bool
	Severity         string
	SeverityOverride string
	Mitre            string
	Params           params
}

// Engine esegue le regole su finestre di tempo successive.
// Il cursore (PG settings.engine_cursor, in ms) indica fin dove i dati sono stati analizzati.
type Engine struct {
	h      *Hub
	defs   []*RuleDef
	custom atomic.Pointer[[]*RuleDef] // regole personalizzate (custom.go)

	mu     sync.RWMutex
	rules  map[string]ruleState
	cursor int64

	resMu     sync.Mutex
	resolvers []string
	resAt     time.Time

	histMu    sync.Mutex
	histStart int64 // primo minuto con traffico, per le regole che hanno bisogno di storico
	histAt    time.Time
}

type window struct{ from, to time.Time }

func (w window) params(extra map[string]string) map[string]string {
	p := map[string]string{"t0": chx.Time(w.from.UnixMilli()), "t1": chx.Time(w.to.UnixMilli())}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// filtro di tempo comune a tutte le query
const inWindow = "ts >= {t0:DateTime64(3, 'UTC')} AND ts < {t1:DateTime64(3, 'UTC')}"

func newEngine(h *Hub) *Engine {
	e := &Engine{h: h, defs: catalog(), rules: map[string]ruleState{}}
	for _, d := range e.defs {
		e.rules[d.ID] = ruleState{Enabled: true, Severity: d.Severity, Mitre: d.Mitre, Params: d.Params}
	}
	return e
}

// allDefs restituisce il catalogo con le regole personalizzate in fondo.
func (e *Engine) allDefs() []*RuleDef {
	c := e.custom.Load()
	if c == nil || len(*c) == 0 {
		return e.defs
	}
	return append(slices.Clip(e.defs), *c...)
}

func (e *Engine) rule(id string) (ruleState, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r, ok := e.rules[id]
	return r, ok
}

// syncCatalog scrive il catalogo in PostgreSQL: l'interfaccia lo legge da lì.
func (e *Engine) syncCatalog(ctx context.Context) error {
	defs := e.allDefs()
	ids := make([]string, 0, len(defs))
	for _, d := range defs {
		p, _ := json.Marshal(d.Params)
		help, _ := json.Marshal(d.Help)
		if d.Params == nil {
			p = []byte("{}")
		}
		if d.Help == nil {
			help = []byte("{}")
		}
		_, err := e.h.pg.Exec(ctx, `INSERT INTO rule_catalog (id, name, category, description, default_severity, mitre, params, param_help, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, category = EXCLUDED.category, description = EXCLUDED.description,
				default_severity = EXCLUDED.default_severity, mitre = EXCLUDED.mitre, params = EXCLUDED.params,
				param_help = EXCLUDED.param_help, updated_at = now()`,
			d.ID, d.Name, d.Category, d.Description, d.Severity, d.Mitre, p, help)
		if err != nil {
			return err
		}
		ids = append(ids, d.ID)
	}
	if _, err := e.h.pg.Exec(ctx, "DELETE FROM rule_catalog WHERE NOT (id = ANY($1))", ids); err != nil {
		return err
	}
	e.reloadRules(ctx)
	return nil
}

// reloadRules applica le scelte salvate nella tabella rules.
func (e *Engine) reloadRules(ctx context.Context) {
	rows, err := e.h.pg.Query(ctx, "SELECT id, enabled, COALESCE(severity, ''), params FROM rules")
	if err != nil {
		e.h.log.Warn("lettura regole", "err", err)
		return
	}
	defer rows.Close()
	custom := map[string]ruleState{}
	for rows.Next() {
		var id, sev string
		var enabled bool
		var raw []byte
		if err := rows.Scan(&id, &enabled, &sev, &raw); err != nil {
			e.h.log.Warn("lettura regole", "err", err)
			return
		}
		p := params{}
		json.Unmarshal(raw, &p)
		custom[id] = ruleState{Enabled: enabled, SeverityOverride: sev, Params: p}
	}
	next := map[string]ruleState{}
	for _, d := range e.allDefs() {
		st := ruleState{Enabled: true, Severity: d.Severity, Mitre: d.Mitre, Params: params{}}
		for k, v := range d.Params {
			st.Params[k] = v
		}
		if c, ok := custom[d.ID]; ok {
			st.Enabled = c.Enabled
			if _, valid := sevRank[c.SeverityOverride]; valid {
				st.SeverityOverride = c.SeverityOverride
			}
			for k, v := range c.Params {
				if _, known := d.Params[k]; known {
					st.Params[k] = v
				}
			}
		}
		next[d.ID] = st
	}
	e.mu.Lock()
	e.rules = next
	e.mu.Unlock()
}

// lateData segnala che sono arrivati dati vecchi: il capo li rianalizzerà. Il segnale passa
// da PostgreSQL perché il lotto può arrivare a un'istanza diversa da quella che esegue il motore.
// I dati in tempo reale (meno di 5 minuti) li coprono già le finestre mobili; lo storico arriva
// a lotti grandi, quindi una scrittura per lotto non pesa.
func (e *Engine) lateData(ctx context.Context, minTS int64) {
	if minTS <= 0 || minTS > time.Now().Add(-5*time.Minute).UnixMilli() {
		return
	}
	_, err := e.h.pg.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('engine_late', to_jsonb($1::bigint), now(), 'hub')
		ON CONFLICT (key) DO UPDATE SET value = to_jsonb(LEAST(settings.value::bigint, $1::bigint)), updated_at = now()`, minTS)
	if err != nil {
		e.h.log.Warn("segnalazione dei dati in ritardo", "err", err)
	}
}

// takeLate legge e azzera il dato in ritardo più vecchio segnalato da tutte le istanze.
func (e *Engine) takeLate(ctx context.Context) int64 {
	var late int64
	err := e.h.pg.QueryRow(ctx, "DELETE FROM settings WHERE key = 'engine_late' RETURNING value::bigint").Scan(&late)
	if err != nil {
		return 0
	}
	return late
}

// resetCursor fa rileggere il cursore dal database: serve quando un'istanza diventa capo.
func (e *Engine) resetCursor() {
	e.mu.Lock()
	e.cursor = 0
	e.mu.Unlock()
}

func alignMinute(ms int64) int64 { return ms - ms%60_000 }

func (e *Engine) loadCursor(ctx context.Context) (int64, error) {
	e.mu.RLock()
	c := e.cursor
	e.mu.RUnlock()
	if c != 0 {
		return c, nil
	}
	var raw []byte
	err := e.h.pg.QueryRow(ctx, "SELECT value FROM settings WHERE key = 'engine_cursor'").Scan(&raw)
	if err == nil {
		json.Unmarshal(raw, &c)
	}
	if c == 0 {
		// primo avvio: si parte dal primo dato delle ultime 24 ore, o da adesso
		type row struct {
			M int64 `json:"m"`
		}
		r, err := chx.Query[row](ctx, e.h.ch, "SELECT toUnixTimestamp64Milli(min(ts)) AS m FROM flows WHERE ts > now() - INTERVAL 1 DAY", nil)
		if err != nil {
			return 0, err
		}
		if len(r) > 0 && r[0].M > 0 {
			c = alignMinute(r[0].M)
		} else {
			c = alignMinute(time.Now().Add(-2 * time.Minute).UnixMilli())
		}
	}
	return c, nil
}

func (e *Engine) saveCursor(ctx context.Context, c int64) error {
	e.mu.Lock()
	e.cursor = c
	e.mu.Unlock()
	v, _ := json.Marshal(c)
	_, err := e.h.pg.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('engine_cursor', $1, now(), 'hub')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, v)
	return err
}

// limit è il punto fin dove i dati sono completi: 90 secondi fa (i flussi arrivano quando si chiudono),
// oppure prima se un sensore sta ancora inviando lo storico.
func (e *Engine) limit(ctx context.Context) int64 {
	lim := time.Now().Add(-90 * time.Second).UnixMilli()
	// avanzamento dello storico di tutti i sensori, scritto da qualunque istanza lo riceva;
	// un sensore che non manda storico da 2 minuti non trattiene più il motore
	var oldest *int64
	if err := e.h.pg.QueryRow(ctx, "SELECT min(ts) FROM backfill_marks WHERE at > now() - interval '2 minutes'").Scan(&oldest); err == nil && oldest != nil {
		lim = min(lim, *oldest-60_000)
	}
	return alignMinute(lim)
}

// tick analizza i dati nuovi, per al massimo 45 secondi a giro.
func (e *Engine) tick(ctx context.Context) error {
	if !e.h.state.Live() {
		return nil
	}
	cursor, err := e.loadCursor(ctx)
	if err != nil {
		return err
	}
	floor := alignMinute(time.Now().Add(-24 * time.Hour).UnixMilli())
	// Un ritardo di pochi minuti lo coprono già le finestre mobili: si torna indietro solo per lo storico.
	if late := e.takeLate(ctx); late != 0 && late < cursor-3*60_000 {
		cursor = max(alignMinute(late), floor)
	}
	cursor = max(cursor, floor)
	deadline := time.Now().Add(45 * time.Second)
	limit := e.limit(ctx)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		step := int64(60_000)
		if limit-cursor > 10*60_000 {
			step = 5 * 60_000
		}
		end := cursor + step
		if end > limit {
			break
		}
		e.runStep(ctx, cursor, end)
		cursor = end
		if err := e.saveCursor(ctx, cursor); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) runStep(ctx context.Context, from, to int64) {
	for _, d := range e.allDefs() {
		if d.Run == nil {
			continue
		}
		st, _ := e.rule(d.ID)
		if !st.Enabled {
			continue
		}
		every := int64(max(d.Every, 1)) * 60_000
		if to/every == from/every { // nessun multiplo di Every in (from, to]
			continue
		}
		end := time.UnixMilli(to - to%every)
		w := window{from: end.Add(-d.Window), to: end}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		alerts, err := d.Run(rctx, e, w, st.Params)
		cancel()
		e.noteCustom(ctx, d.ID, len(alerts), err)
		if err != nil {
			e.h.log.Warn("regola", "rule", d.ID, "err", err)
			continue
		}
		for _, a := range alerts {
			a.Rule = d.ID
			if _, err := e.h.raise(ctx, a); err != nil {
				break
			}
		}
	}
}

// resolverList restituisce i server DNS interni (offrono la porta 53): inoltrano le query dei client
// e vanno esclusi dalle regole sul DNS. Si aggiungono quelli indicati nel parametro "resolvers".
func (e *Engine) resolverList(ctx context.Context, extra []string) []string {
	e.resMu.Lock()
	defer e.resMu.Unlock()
	if time.Since(e.resAt) > 5*time.Minute {
		rows, err := e.h.pg.Query(ctx, `SELECT DISTINCT d.ip FROM device_services s JOIN devices d ON d.id = s.device_id
			WHERE s.port = 53 AND s.last_seen > now() - interval '7 days' AND d.ip <> ''`)
		if err == nil {
			var list []string
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					list = append(list, ip)
				}
			}
			rows.Close()
			e.resolvers, e.resAt = list, time.Now()
		}
	}
	return append(append([]string{}, e.resolvers...), extra...)
}

// historyStart restituisce il primo minuto di traffico registrato (ms), aggiornato ogni 10 minuti.
func (e *Engine) historyStart(ctx context.Context) int64 {
	e.histMu.Lock()
	defer e.histMu.Unlock()
	if time.Since(e.histAt) > 10*time.Minute || e.histStart == 0 {
		type row struct {
			M int64 `json:"m"`
		}
		r, err := chx.Query[row](ctx, e.h.ch, "SELECT toUnixTimestamp(min(minute)) * 1000 AS m FROM traffic_1m", nil)
		if err == nil && len(r) > 0 {
			e.histStart, e.histAt = r[0].M, time.Now()
		}
	}
	return e.histStart
}

// ---------------------------------------------------------------- parametri

type params map[string]any

func (p params) num(k string) float64 {
	switch v := p[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	}
	return 0
}

func (p params) str(k string) string {
	switch v := p[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// list legge un elenco separato da virgole.
func (p params) list(k string) []string {
	var out []string
	for _, s := range strings.Split(p.str(k), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (p params) ports(k string) []uint16 {
	var out []uint16
	for _, s := range p.list(k) {
		if n, err := strconv.ParseUint(s, 10, 16); err == nil {
			out = append(out, uint16(n))
		}
	}
	return out
}

// chStrings e chPorts formattano un array per i parametri di ClickHouse.
func chStrings(v []string) string {
	q := make([]string, len(v))
	for i, s := range v {
		q[i] = "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	return "[" + strings.Join(q, ",") + "]"
}

func chPorts(v []uint16) string {
	q := make([]string, len(v))
	for i, n := range v {
		q[i] = strconv.Itoa(int(n))
	}
	return "[" + strings.Join(q, ",") + "]"
}

func chNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func chInt(f float64) string { return strconv.FormatInt(int64(math.Max(f, 0)), 10) }
