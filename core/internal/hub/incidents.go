package hub

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Incidenti: il correlatore riunisce gli allarmi che riguardano lo stesso dispositivo interno.
// Un incidente nasce quando, nella finestra scelta, un dispositivo accumula allarmi di almeno
// min_rules regole diverse (per esempio una scansione seguita da accessi ripetuti e da un
// beacon), oppure subito con un allarme critico. Finché l'incidente non viene chiuso, gli
// allarmi nuovi dello stesso dispositivo si aggiungono a lui. La gravità è la più alta tra gli
// allarmi, un livello in più con tre o più regole diverse.

func incidentCatalog() []*RuleDef {
	return []*RuleDef{{
		ID: "incident", Name: "Raggruppamento in incidenti", Category: "Correlazione", Severity: "high",
		Description: "Riunisce in un incidente gli allarmi di regole diverse che riguardano lo stesso dispositivo interno. " +
			"Non produce allarmi: la pagina Incidenti mostra la sequenza e la catena ATT&CK.",
		Params: params{"window_h": 24, "min_rules": 2, "critical_alone": 1},
		Help: map[string]string{
			"window_h":       "Ore entro cui gli allarmi si considerano collegati",
			"min_rules":      "Regole diverse necessarie per aprire un incidente",
			"critical_alone": "1 = un allarme critico apre subito un incidente",
		},
	}}
}

// regole che non descrivono un comportamento del dispositivo
var incidentIgnored = []string{"sensor_offline", "incident"}

type corrAlert struct {
	id               int64
	rule, sev, mitre string
	src, dst         string
	first, last      time.Time
}

// entity sceglie il dispositivo interno coinvolto: l'origine se è interna, altrimenti la
// destinazione (un attacco da internet riguarda chi lo riceve).
func (h *Hub) entity(a corrAlert) string {
	in := h.state.Internal()
	switch {
	case a.src != "" && in.Contains(a.src):
		return a.src
	case a.dst != "" && in.Contains(a.dst):
		return a.dst
	case a.src != "":
		return a.src
	}
	return a.dst
}

// incidentGroup decide se un gruppo di allarmi apre un incidente.
func incidentWorthy(list []corrAlert, minRules int, criticalAlone bool) (rules map[string]bool, ok bool) {
	rules = map[string]bool{}
	critical := false
	for _, a := range list {
		rules[a.rule] = true
		critical = critical || a.sev == "critical"
	}
	return rules, len(rules) >= minRules || (criticalAlone && critical)
}

func (h *Hub) correlate(ctx context.Context) error {
	st, ok := h.eng.rule("incident")
	if !ok || !st.Enabled {
		return nil
	}
	window := time.Duration(max(st.Params.num("window_h"), 1)) * time.Hour
	minRules := int(max(st.Params.num("min_rules"), 1))
	criticalAlone := st.Params.num("critical_alone") >= 1

	rows, err := h.pg.Query(ctx, `SELECT id, rule, severity, mitre, src_ip, dst_ip, first_seen, last_seen FROM alerts
		WHERE incident_id IS NULL AND NOT incident_skip AND status <> 'resolved' AND last_seen > now() - make_interval(secs => $1)
		AND NOT (rule = ANY($2)) ORDER BY first_seen LIMIT 5000`, window.Seconds(), incidentIgnored)
	if err != nil {
		return err
	}
	groups := map[string][]corrAlert{}
	for rows.Next() {
		var a corrAlert
		if err := rows.Scan(&a.id, &a.rule, &a.sev, &a.mitre, &a.src, &a.dst, &a.first, &a.last); err != nil {
			rows.Close()
			return err
		}
		if e := h.entity(a); e != "" {
			groups[e] = append(groups[e], a)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(groups) == 0 {
		return err
	}

	entities := make([]string, 0, len(groups))
	for e := range groups {
		entities = append(entities, e)
	}
	sort.Strings(entities)
	open := map[string]int64{}
	orows, err := h.pg.Query(ctx, "SELECT key_entity, id FROM incidents WHERE status <> 'closed' AND key_entity = ANY($1)", entities)
	if err != nil {
		return err
	}
	for orows.Next() {
		var e string
		var id int64
		if orows.Scan(&e, &id) == nil {
			open[e] = id
		}
	}
	orows.Close()

	names := h.ruleNames()
	var touched, created []int64
	for _, e := range entities {
		list := groups[e]
		rules, worthy := incidentWorthy(list, minRules, criticalAlone)
		id, exists := open[e]
		if !exists && !worthy {
			continue
		}
		ids := make([]int64, len(list))
		for i, a := range list {
			ids[i] = a.id
		}
		ruleList := make([]string, 0, len(rules))
		for r := range rules {
			ruleList = append(ruleList, names.get(r))
		}
		sort.Strings(ruleList)
		if !exists {
			dev := h.enr.device(e)
			err := h.pg.QueryRow(ctx, `INSERT INTO incidents (key_entity, device_id, title, severity, first_seen, last_seen)
				VALUES ($1, NULLIF($2, 0), $3, 'medium', $4, $5)
				ON CONFLICT (key_entity) WHERE status <> 'closed' DO UPDATE SET updated_at = now() RETURNING id`,
				e, dev.id, "Attività sospetta su "+label(e, dev.name), list[0].first, list[len(list)-1].last).Scan(&id)
			if err != nil {
				return err
			}
			created = append(created, id)
			h.log.Info("incidente aperto", "id", id, "entity", e, "allarmi", len(list), "regole", len(rules))
		}
		if _, err := h.pg.Exec(ctx, "UPDATE alerts SET incident_id = $1 WHERE id = ANY($2) AND incident_id IS NULL", id, ids); err != nil {
			return err
		}
		text := fmt.Sprintf("Aggiunti %d allarmi: %s.", len(list), strings.Join(ruleList, ", "))
		if !exists {
			text = fmt.Sprintf("Incidente aperto dall'hub: %d allarmi da %d regole (%s).", len(list), len(rules), strings.Join(ruleList, ", "))
		}
		if _, err := h.pg.Exec(ctx, "INSERT INTO incident_notes (incident_id, username, kind, text) VALUES ($1, 'hub', 'system', $2)", id, text); err != nil {
			return err
		}
		touched = append(touched, id)
	}
	if len(touched) == 0 {
		return nil
	}
	if err := h.refreshIncidents(ctx, touched); err != nil {
		return err
	}
	for _, id := range created {
		var title, sev string
		if h.pg.QueryRow(ctx, "SELECT title, severity FROM incidents WHERE id = $1", id).Scan(&title, &sev) == nil {
			h.live.event("incident", map[string]any{"id": id, "title": title, "severity": sev})
		}
	}
	return nil
}

// refreshIncidents ricalcola conteggi, periodo, tecniche e gravità dagli allarmi collegati.
func (h *Hub) refreshIncidents(ctx context.Context, ids []int64) error {
	_, err := h.pg.Exec(ctx, `
		UPDATE incidents i SET alert_count = s.n, rule_count = s.r, first_seen = s.f, last_seen = s.l, techniques = s.t,
			severity = (ARRAY['info','low','medium','high','critical'])[LEAST(5, s.sev + CASE WHEN s.r >= 3 THEN 1 ELSE 0 END)],
			updated_at = now()
		FROM (
			SELECT incident_id, count(*)::int AS n, count(DISTINCT rule)::int AS r, min(first_seen) AS f, max(last_seen) AS l,
			       coalesce(array_agg(DISTINCT mitre ORDER BY mitre) FILTER (WHERE mitre <> ''), '{}') AS t,
			       max(array_position(ARRAY['info','low','medium','high','critical'], severity)) AS sev
			FROM alerts WHERE incident_id = ANY($1) GROUP BY incident_id
		) s WHERE i.id = s.incident_id`, ids)
	return err
}

type ruleNameMap map[string]string

func (m ruleNameMap) get(id string) string {
	if n, ok := m[id]; ok {
		return n
	}
	return id
}

func (h *Hub) ruleNames() ruleNameMap {
	m := ruleNameMap{}
	for _, d := range h.eng.allDefs() {
		m[d.ID] = d.Name
	}
	return m
}
