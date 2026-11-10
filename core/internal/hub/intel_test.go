package hub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"hyperwave/internal/model"
)

func TestParseIndicator(t *testing.T) {
	cases := []struct {
		in       string
		strict   bool
		val, typ string
	}{
		{"198.51.100.7", true, "198.51.100.7", "ip"},
		{"::ffff:198.51.100.7", true, "198.51.100.7", "ip"},
		{"198.51.100.0/24", true, "198.51.100.0/24", "cidr"},
		{"198.51.100.9/24", true, "198.51.100.0/24", "cidr"},
		{"198.51.100.9/32", true, "198.51.100.9", "ip"},
		{"2001:db8:1::/48", true, "2001:db8:1::/48", "cidr"},
		{"Evil.Example.", true, "evil.example", "domain"},
		{"*.evil.example", true, "evil.example", "domain"},
		{"hxxps://bad[.]example/path?x=1", true, "bad.example", "domain"},
		{"http://198.51.100.8:8080/a.exe", true, "198.51.100.8", "ip"},
		{"10.1.2.3", true, "", ""},            // privato: scartato dagli elenchi scaricati
		{"10.1.2.3", false, "10.1.2.3", "ip"}, // ammesso negli elenchi a mano
		{"0.0.0.0/0", false, "", ""},          // troppo ampio
		{"1.0.0.0/7", false, "", ""},
		{"raw.githubusercontent.com", true, "", ""}, // grande piattaforma
		{"raw.githubusercontent.com", false, "raw.githubusercontent.com", "domain"},
		{"evil-github.com", true, "evil-github.com", "domain"},
		{"localhost", true, "", ""},
		{"1.2", true, "", ""},
		{"version-2.0", true, "", ""},
		{"a..b.example", true, "", ""},
	}
	for _, c := range cases {
		v, typ, ok := parseIndicator(c.in, c.strict)
		if ok != (c.val != "") || v != c.val || typ != c.typ {
			t.Errorf("parseIndicator(%q, %v) = %q %q %v, atteso %q %q", c.in, c.strict, v, typ, ok, c.val, c.typ)
		}
	}
}

func TestParseFeedFormats(t *testing.T) {
	feeds := map[string]string{
		"testo": "# Feodo\n198.51.100.1\n198.51.100.2 # commento\n\n; altro commento\n",
		"hosts": "127.0.0.1\tlocalhost\n0.0.0.0 bad.example\n127.0.0.1 evil.example\n",
		"json":  `{"cidr":"198.51.100.0/24","sblid":"SBL1","rir":"ripencc"}` + "\n" + `{"type":"metadata","timestamp":1700000000,"size":2}` + "\n",
		"csv":   "first_seen_utc,dst_ip,dst_port,c2_status\n\"2024-01-01 10:00:00\",\"198.51.100.3\",443,\"online\"\n",
		"url":   "https://bad.example/x.exe\nhttp://203.0.113.9/a\n",
	}
	want := map[string][]string{
		"testo": {"198.51.100.1", "198.51.100.2"},
		"hosts": {"bad.example", "evil.example"},
		"json":  {"198.51.100.0/24"},
		"csv":   {"198.51.100.3"},
		"url":   {"bad.example", "203.0.113.9"},
	}
	for name, body := range feeds {
		got, err := parseFeed(strings.NewReader(body), true)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(want[name]) {
			t.Errorf("%s: %v, attesi %v", name, got, want[name])
		}
		for _, v := range want[name] {
			if _, ok := got[v]; !ok {
				t.Errorf("%s: manca %s in %v", name, v, got)
			}
		}
	}
}

func testIntelSet() *intelSet {
	s := newIntelSet()
	s.feeds[1] = &intelFeed{id: 1, name: "Basso", category: "scanner", severity: "low"}
	s.feeds[2] = &intelFeed{id: 2, name: "Grave", category: "c2", severity: "critical"}
	s.add(1, "198.51.100.7", "ip")
	s.add(2, "198.51.100.7", "ip") // lo stesso indicatore in due elenchi: vale il più grave
	s.add(1, "203.0.113.0/24", "cidr")
	s.add(2, "203.0.113.128/25", "cidr")
	s.add(1, "2001:db8:5::/48", "cidr")
	s.add(2, "evil.example", "domain")
	s.finish()
	return s
}

func TestIntelSetMatch(t *testing.T) {
	s := testIntelSet()
	cases := []struct {
		ip, ind string
		feed    int64
	}{
		{"198.51.100.7", "198.51.100.7", 2},
		{"::ffff:198.51.100.7", "198.51.100.7", 2},
		{"203.0.113.5", "203.0.113.0/24", 1},
		{"203.0.113.200", "203.0.113.128/25", 2}, // il prefisso più specifico
		{"2001:db8:5:1::9", "2001:db8:5::/48", 1},
		{"198.51.100.8", "", 0},
		{"non-un-ip", "", 0},
	}
	for _, c := range cases {
		ind, feed, ok := s.matchIP(c.ip)
		if ok != (c.ind != "") || ind != c.ind || feed != c.feed {
			t.Errorf("matchIP(%s) = %q %d %v, atteso %q %d", c.ip, ind, feed, ok, c.ind, c.feed)
		}
	}
	for name, want := range map[string]string{"evil.example": "evil.example", "a.b.Evil.Example.": "evil.example", "notevil.example": "", "example": ""} {
		if ind, _, _ := s.matchDomain(name); ind != want {
			t.Errorf("matchDomain(%s) = %q, atteso %q", name, ind, want)
		}
	}
}

func TestIntelScanAggregates(t *testing.T) {
	in := &intel{hits: map[hitKey]*hitAgg{}}
	in.set.Store(testIntelSet())
	set := in.set.Load()
	b := &model.Batch{
		Flows: []model.Flow{
			{TS: 1000, SrcIP: "10.0.0.5", DstIP: "198.51.100.7", DstPort: 443, Est: true},
			{TS: 2000, SrcIP: "10.0.0.5", DstIP: "198.51.100.7", DstPort: 8443},
			{TS: 3000, SrcIP: "203.0.113.9", DstIP: "10.0.0.8", DstPort: 22},            // in entrata senza risposta
			{TS: 4000, SrcIP: "203.0.113.9", DstIP: "10.0.0.9", DstPort: 22, Est: true}, // in entrata riuscita
		},
		DNS: []model.DNS{{TS: 5000, Client: "10.0.0.6", Query: "cdn.evil.example"}},
	}
	// stessa logica di scan, senza hub: le connessioni in entrata contano solo se riuscite
	for _, f := range b.Flows {
		if ind, feed, ok := set.matchIP(f.DstIP); ok {
			in.hit(set, feed, ind, f.DstIP, f.SrcIP, f.DstIP, "flusso", f.DstPort, false, f.Est, f.TS, 1, 1, false)
		} else if ind, feed, ok := set.matchIP(f.SrcIP); ok && f.Est {
			in.hit(set, feed, ind, f.SrcIP, f.DstIP, f.SrcIP, "flusso", f.DstPort, true, f.Est, f.TS, 1, 1, false)
		}
	}
	for _, d := range b.DNS {
		if ind, feed, ok := set.matchDomain(d.Query); ok {
			in.hit(set, feed, ind, d.Query, d.Client, "", "DNS", 53, false, true, d.TS, 1, 1, false)
		}
	}
	if len(in.hits) != 3 {
		t.Fatalf("corrispondenze: %d", len(in.hits))
	}
	out := in.hits[hitKey{2, "198.51.100.7", "10.0.0.5", false}]
	if out == nil || out.n != 2 || out.first != 1000 || out.last != 2000 || len(out.ports) != 2 || out.feed.severity != "critical" {
		t.Fatalf("uscita: %+v", out)
	}
	if in.hits[hitKey{1, "203.0.113.0/24", "10.0.0.8", true}] != nil {
		t.Fatal("tentativo in entrata senza risposta contato")
	}
	if a := in.hits[hitKey{1, "203.0.113.0/24", "10.0.0.9", true}]; a == nil || !a.established {
		t.Fatalf("entrata riuscita: %+v", a)
	}
	if a := in.hits[hitKey{2, "evil.example", "10.0.0.6", false}]; a == nil || !a.seen["cdn.evil.example"] {
		t.Fatalf("DNS: %+v", a)
	}
}

func TestIntelClientBlocksInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "198.51.100.1\n") }))
	defer srv.Close()
	if _, err := intelClient(false).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "destinazione interna") {
		t.Fatalf("loopback non bloccato: %v", err)
	}
	resp, err := intelClient(true).Get(srv.URL)
	if err != nil {
		t.Fatalf("con HW_INTEL_ALLOW_PRIVATE: %v", err)
	}
	resp.Body.Close()
	for addr, want := range map[string]bool{"198.51.100.1": true, "10.0.0.1": false, "100.64.1.1": false, "::ffff:127.0.0.1": false, "fd00::1": false, "169.254.169.254": false, "2001:db8::1": true} {
		if got := publicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("publicAddr(%s) = %v", addr, got)
		}
	}
}
