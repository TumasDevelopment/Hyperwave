package hub

import (
	"math"
	"testing"
	"time"
)

func TestSuppressionMatch(t *testing.T) {
	s := &suppressions{list: []suppression{
		{id: 1, rule: "portscan", src: parseTarget("10.0.0.0/24")},
		{id: 2, rule: "", dst: parseTarget("198.51.100.7")},
		{id: 3, rule: "beacon", src: parseTarget("valore-rovinato")},
	}}
	cases := []struct {
		rule, src, dst string
		want           int64
	}{
		{"portscan", "10.0.0.9", "10.0.1.1", 1},
		{"portscan", "10.0.1.9", "10.0.1.1", 0},
		{"sweep", "10.0.0.9", "10.0.1.1", 0},
		{"qualsiasi", "10.9.9.9", "198.51.100.7", 2},
		{"beacon", "10.0.0.9", "203.0.113.1", 0}, // un valore non valido non diventa mai "qualsiasi"
		{"portscan", "::ffff:10.0.0.9", "x", 1},
	}
	for _, c := range cases {
		if got := s.match(c.rule, c.src, c.dst); got != c.want {
			t.Errorf("match(%s, %s, %s) = %d, atteso %d", c.rule, c.src, c.dst, got, c.want)
		}
	}
}

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	severities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	for _, r := range catalog() {
		if r.ID == "" || seen[r.ID] {
			t.Errorf("ID mancante o duplicato: %q", r.ID)
		}
		seen[r.ID] = true
		if r.Name == "" || r.Category == "" || r.Description == "" {
			t.Errorf("%s: nome, categoria e descrizione sono obbligatori", r.ID)
		}
		if !severities[r.Severity] {
			t.Errorf("%s: gravità %q non valida", r.ID, r.Severity)
		}
		// le regole senza Run scattano da eventi (inventario, sensori); le altre girano a intervalli
		if r.Run != nil && (r.Every <= 0 || r.Window <= 0) {
			t.Errorf("%s: una regola periodica richiede Every e Window", r.ID)
		}
		for k := range r.Params {
			if r.Help[k] == "" {
				t.Errorf("%s: il parametro %s non ha la spiegazione", r.ID, k)
			}
		}
	}
	if len(seen) < 15 {
		t.Errorf("solo %d regole nel catalogo", len(seen))
	}
}

func TestEntropy(t *testing.T) {
	if entropy("") != 0 || entropy("aaaa") != 0 {
		t.Error("entropia di stringhe uniformi")
	}
	if math.Abs(entropy("ab")-1) > 1e-9 {
		t.Error(`entropia di "ab" deve essere 1 bit`)
	}
	if entropy("google") >= 3.3 || entropy("xj4k9q2vz7mw8hp3") <= 3.3 {
		t.Error("la soglia di 3,3 deve separare nomi normali e generati")
	}
}

func TestFormatting(t *testing.T) {
	if got := chStrings([]string{"a", "o'reilly", `c:\x`}); got != `['a','o\'reilly','c:\\x']` {
		t.Errorf("chStrings: %s", got)
	}
	if chStrings(nil) != "[]" || chPorts([]uint16{22, 443}) != "[22,443]" || chPorts(nil) != "[]" {
		t.Error("chStrings/chPorts")
	}
	if chInt(-5) != "0" || chInt(12.9) != "12" || chNum(0.25) != "0.25" {
		t.Error("chInt/chNum")
	}
	for in, want := range map[float64]string{512: "512 B", 2048: "2.0 KB", 5 * 1024 * 1024: "5.0 MB", 3 << 40: "3.0 TB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%v) = %s, atteso %s", in, got, want)
		}
	}
	if label("10.0.0.1", "") != "10.0.0.1" || label("10.0.0.1", "nas") != "nas (10.0.0.1)" {
		t.Error("label")
	}
}

func TestNormMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff", " aa-bb-cc-dd-ee-01 ": "aa:bb:cc:dd:ee:01",
		"00:00:00:00:00:00": "", "ff:ff:ff:ff:ff:ff": "", "rotto": "", "00:11:22:33:44:55:66:77": "",
	} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, atteso %q", in, got, want)
		}
	}
}

func TestParseCH(t *testing.T) {
	want := time.Date(2026, 11, 10, 8, 30, 15, 0, time.UTC)
	if !parseCH("2026-11-10 08:30:15").Equal(want) || !parseCH("2026-11-10 08:30:15.000").Equal(want) {
		t.Error("parseCH")
	}
	if !parseCH("non una data").IsZero() {
		t.Error("una data non valida deve dare il tempo zero")
	}
}
