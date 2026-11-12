package store

import (
	"strings"
	"testing"
)

func TestReplicate(t *testing.T) {
	cases := map[string]string{
		"CREATE TABLE t (a UInt8) ENGINE = MergeTree ORDER BY a":        "CREATE TABLE t (a UInt8) ENGINE = ReplicatedMergeTree ORDER BY a",
		") ENGINE = SummingMergeTree\nPARTITION BY toDate(minute)":      ") ENGINE = ReplicatedSummingMergeTree\nPARTITION BY toDate(minute)",
		"ENGINE=ReplacingMergeTree(ver) ORDER BY id":                    "ENGINE = ReplicatedReplacingMergeTree(ver) ORDER BY id",
		"ENGINE = ReplicatedMergeTree ORDER BY a":                       "ENGINE = ReplicatedMergeTree ORDER BY a",
		"CREATE MATERIALIZED VIEW v TO t AS SELECT * FROM flows":        "CREATE MATERIALIZED VIEW v TO t AS SELECT * FROM flows",
		"ALTER TABLE flows MODIFY TTL toDateTime(ts) + INTERVAL 30 DAY": "ALTER TABLE flows MODIFY TTL toDateTime(ts) + INTERVAL 30 DAY",
	}
	for in, want := range cases {
		if got := replicate(in); got != want {
			t.Errorf("replicate(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Tutte le tabelle delle migrazioni devono diventare replicate: un MergeTree rimasto
// semplice terrebbe i dati su un solo nodo senza che nessuno se ne accorga.
func TestReplicateMigrations(t *testing.T) {
	migs, err := load("ch")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migs {
		for _, stmt := range splitSQL(m.body) {
			out := replicate(stmt)
			for _, loc := range mergeTreeEngine.FindAllStringSubmatch(out, -1) {
				if !strings.HasPrefix(loc[1], "Replicated") {
					t.Errorf("%s: motore non replicato in %q", m.name, out)
				}
			}
		}
	}
}
