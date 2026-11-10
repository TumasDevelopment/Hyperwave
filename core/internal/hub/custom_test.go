package hub

import (
	"strings"
	"testing"

	"hyperwave/internal/netx"
)

func TestCompileCustom(t *testing.T) {
	internal := netx.ParseNets("10.0.0.0/8,192.168.0.0/16")
	spec := customSpec{
		Source: "flows",
		Where: []customCond{
			{Field: "src", Op: "internal"},
			{Field: "dport", Op: "in", Value: []string{"22", "3389"}},
			{Field: "dst", Op: "not_in_net", Value: []string{"198.51.100.0/24", "203.0.113.7"}},
			{Field: "app", Op: "contains", Value: []string{"x'); DROP TABLE flows; --"}},
		},
		GroupBy: []string{"src", "dport"}, Metric: "uniq", MetricField: "dst", Threshold: 10, WindowMin: 15,
	}
	c, err := compileCustom(spec, internal)
	if err != nil {
		t.Fatal(err)
	}
	sql := c.sql(false, 100)
	if strings.Contains(sql, "DROP") || strings.Contains(sql, "198.51") {
		t.Fatalf("valori dentro la query: %s", sql)
	}
	for _, want := range []string{"FROM flows", "uniqExact(dst)", "GROUP BY G0, G1", "isIPAddressInRange", "HAVING V >= {thr:Float64}", "positionCaseInsensitiveUTF8(app, {c3:String})"} {
		if !strings.Contains(sql, want) {
			t.Errorf("manca %q in\n%s", want, sql)
		}
	}
	if c.params["c0"] != "['10.0.0.0/8','192.168.0.0/16']" || c.params["c1"] != "[22,3389]" || c.params["c2"] != "['198.51.100.0/24','203.0.113.7/32']" {
		t.Errorf("parametri: %v", c.params)
	}
	if c.params["c3"] != "x'); DROP TABLE flows; --" || c.every != 5 || c.window.Minutes() != 15 {
		t.Errorf("valori: %v every=%d", c.params, c.every)
	}
	if b := c.sql(true, 10); !strings.Contains(b, "toStartOfInterval(ts, INTERVAL {w:UInt32} MINUTE)") || !strings.Contains(b, "GROUP BY Bucket, G0, G1") {
		t.Errorf("prova sullo storico:\n%s", b)
	}
}

func TestCompileCustomRejects(t *testing.T) {
	base := func() customSpec { return customSpec{Source: "dns", Metric: "count", Threshold: 5, WindowMin: 10} }
	cases := map[string]func(*customSpec){
		"sorgente":        func(s *customSpec) { s.Source = "users" },
		"campo":           func(s *customSpec) { s.Where = []customCond{{Field: "password", Op: "eq", Value: []string{"x"}}} },
		"colonna libera":  func(s *customSpec) { s.GroupBy = []string{"query; DROP"} },
		"operatore":       func(s *customSpec) { s.Where = []customCond{{Field: "query", Op: "gt", Value: []string{"1"}}} },
		"valore mancante": func(s *customSpec) { s.Where = []customCond{{Field: "query", Op: "eq"}} },
		"regex":           func(s *customSpec) { s.Where = []customCond{{Field: "query", Op: "regex", Value: []string{"a(b"}}} },
		"ip": func(s *customSpec) {
			s.Where = []customCond{{Field: "client", Op: "in_net", Value: []string{"10.0.0.0/33"}}}
		},
		"numero":         func(s *customSpec) { s.Where = []customCond{{Field: "query_len", Op: "gt", Value: []string{"NaN"}}} },
		"somma di testo": func(s *customSpec) { s.Metric, s.MetricField = "sum", "query" },
		"soglia":         func(s *customSpec) { s.Threshold = 0 },
		"finestra":       func(s *customSpec) { s.WindowMin = 5000 },
		"frequenza":      func(s *customSpec) { s.EveryMin = 30 },
		"gruppi":         func(s *customSpec) { s.GroupBy = []string{"client", "server", "query", "qtype"} },
		"ripetuto":       func(s *customSpec) { s.GroupBy = []string{"client", "client"} },
	}
	if _, err := compileCustom(base(), nil); err != nil {
		t.Fatalf("base: %v", err)
	}
	for name, mod := range cases {
		s := base()
		mod(&s)
		if _, err := compileCustom(s, nil); err == nil {
			t.Errorf("%s: accettata", name)
		}
	}
}

func TestCustomAlert(t *testing.T) {
	c, err := compileCustom(customSpec{Source: "flows", GroupBy: []string{"dport", "src"}, Metric: "sum", MetricField: "bytes_out", Threshold: 1 << 20, WindowMin: 60}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{h: &Hub{state: newState(Config{Timezone: "UTC"})}}
	a := c.alert(e, "custom:7", "Upload grandi", window{}, customRow{G0: "443", G1: "10.0.0.5", V: 3 << 20, N: 12, First: "2026-01-01 10:00:00.000"})
	if a.DedupKey != "custom:7|443|10.0.0.5" || a.Src != "10.0.0.5" || a.Dst != "" {
		t.Fatalf("allarme: %+v", a)
	}
	if !strings.Contains(a.Title, "Porta di destinazione 443") || !strings.Contains(a.Summary, "3.0 MB") || !strings.Contains(a.Summary, "soglia 1.0 MB") {
		t.Fatalf("testo: %s / %s", a.Title, a.Summary)
	}
}
