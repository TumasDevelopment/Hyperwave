package hub

import "testing"

func TestIncidentEntityAndWorthy(t *testing.T) {
	h := &Hub{state: newState(Config{InternalNets: "10.0.0.0/8"})}
	cases := map[string]corrAlert{
		"10.0.0.5":    {src: "10.0.0.5", dst: "198.51.100.9"}, // in uscita: l'origine
		"10.0.0.8":    {src: "203.0.113.4", dst: "10.0.0.8"},  // in entrata: chi riceve
		"10.0.0.9":    {src: "10.0.0.9", dst: "10.0.0.10"},    // interno: l'origine
		"":            {},                                     // senza indirizzi: niente incidente
		"203.0.113.4": {src: "203.0.113.4"},                   // solo esterno: resta l'origine
	}
	for want, a := range cases {
		if got := h.entity(a); got != want {
			t.Errorf("entity(%+v) = %q, atteso %q", a, got, want)
		}
	}
	two := []corrAlert{{rule: "portscan", sev: "high"}, {rule: "portscan", sev: "high"}}
	if _, ok := incidentWorthy(two, 2, true); ok {
		t.Error("una sola regola ha aperto un incidente")
	}
	two[1].rule = "bruteforce"
	if rules, ok := incidentWorthy(two, 2, true); !ok || len(rules) != 2 {
		t.Error("due regole diverse non hanno aperto un incidente")
	}
	crit := []corrAlert{{rule: "threat_intel", sev: "critical"}}
	if _, ok := incidentWorthy(crit, 2, true); !ok {
		t.Error("un allarme critico non ha aperto un incidente")
	}
	if _, ok := incidentWorthy(crit, 2, false); ok {
		t.Error("critical_alone=0 ignorato")
	}
}
