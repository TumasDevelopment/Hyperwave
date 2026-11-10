package sensor

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hyperwave/internal/model"
)

func batchOf(n int, port uint16) *model.Batch {
	b := &model.Batch{}
	for i := range n {
		b.Flows = append(b.Flows, model.Flow{TS: int64(1_700_000_000_000 + i), Proto: "TCP", SrcIP: "10.0.0.1", DstIP: "198.51.100.7", DstPort: port})
	}
	return b
}

func TestSpoolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sp, err := openSpool(dir, 1<<30, "hws_token-di-prova")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := sp.put(batchOf(10+i, uint16(1000+i))); err != nil {
			t.Fatal(err)
		}
	}
	if files, _, records := sp.stats(); files != 3 || records != 33 {
		t.Fatalf("attesi 3 file e 33 record, trovati %d e %d", files, records)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("permessi della cartella %o, attesi 700", info.Mode().Perm())
	}
	// il contenuto su disco non è leggibile in chiaro
	entries, _ := os.ReadDir(dir)
	raw, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if strings.Contains(string(raw), "198.51.100.7") {
		t.Fatal("il lotto su disco contiene dati in chiaro")
	}

	// riapertura: l'ordine resta dal più vecchio al più recente
	sp2, err := openSpool(dir, 1<<30, "hws_token-di-prova")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		name, b, ok := sp2.oldest()
		if !ok {
			t.Fatalf("lotto %d mancante", i)
		}
		if b.Len() != 10+i || b.Flows[0].DstPort != uint16(1000+i) {
			t.Fatalf("lotto %d: %d record, porta %d", i, b.Len(), b.Flows[0].DstPort)
		}
		sp2.remove(name)
	}
	if _, _, ok := sp2.oldest(); ok {
		t.Fatal("la coda dovrebbe essere vuota")
	}
	if files, bytes, _ := sp2.stats(); files != 0 || bytes != 0 {
		t.Fatalf("contatori non azzerati: %d file, %d byte", files, bytes)
	}
}

func TestSpoolLimitDropsOldest(t *testing.T) {
	sp, err := openSpool(t.TempDir(), 1, "hws_x") // limite minimo: resta solo l'ultimo lotto
	if err != nil {
		t.Fatal(err)
	}
	sp.put(batchOf(5, 1))
	sp.put(batchOf(7, 2))
	sp.put(batchOf(9, 3))
	files, _, records := sp.stats()
	if files != 1 || records != 9 {
		t.Fatalf("attesi 1 file con 9 record, trovati %d con %d", files, records)
	}
	if got := sp.dropped.Load(); got != 12 {
		t.Fatalf("scartati %d record, attesi 12", got)
	}
	_, b, _ := sp.oldest()
	if b.Flows[0].DstPort != 3 {
		t.Fatal("doveva restare il lotto più recente")
	}
}

func TestSpoolWrongKeyAndJunk(t *testing.T) {
	dir := t.TempDir()
	old, _ := openSpool(dir, 1<<30, "hws_vecchio")
	old.put(batchOf(4, 1))
	os.WriteFile(filepath.Join(dir, "lotto-123.tmp"), []byte("interrotto"), 0o600)
	os.WriteFile(filepath.Join(dir, fmt.Sprintf("%019d-000001-3.hws", time.Now().UnixNano())), []byte("HWS1 rovinato"), 0o600)

	sp, err := openSpool(dir, 1<<30, "hws_nuovo") // token rinnovato
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lotto-123.tmp")); !os.IsNotExist(err) {
		t.Fatal("il file temporaneo andava cancellato all'apertura")
	}
	sp.put(batchOf(2, 9))
	_, b, ok := sp.oldest()
	if !ok || b.Flows[0].DstPort != 9 {
		t.Fatal("i file illeggibili vanno saltati fino al primo valido")
	}
	if got := sp.dropped.Load(); got != 7 {
		t.Fatalf("scartati %d record, attesi 7 (4 con la chiave vecchia + 3 rovinati)", got)
	}
}

func TestSpoolState(t *testing.T) {
	sp, _ := openSpool(t.TempDir(), 1<<30, "hws_x")
	if _, ok := sp.loadState(); ok {
		t.Fatal("nessuno stato atteso")
	}
	sp.saveState(savedState{Live: true, InternalNets: []string{"10.0.0.0/8"}})
	st, ok := sp.loadState()
	if !ok || !st.Live || len(st.InternalNets) != 1 || st.Saved == 0 {
		t.Fatalf("stato letto male: %+v", st)
	}
}

// fakeHub accetta o rifiuta i lotti e conta i record ricevuti.
type fakeHub struct {
	mu      sync.Mutex
	up      atomic.Bool
	records int
	ports   []uint16
}

func (h *fakeHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.up.Load() {
		http.Error(w, `{"error":"giù"}`, http.StatusServiceUnavailable)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "gzip", http.StatusBadRequest)
		return
	}
	var b model.Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	h.records += b.Len()
	if len(b.Flows) > 0 {
		h.ports = append(h.ports, b.Flows[0].DstPort)
	}
	h.mu.Unlock()
	json.NewEncoder(w).Encode(model.HubReply{OK: true, Live: true, Accepted: b.Len()})
}

func TestSinkSpoolsWhileHubDown(t *testing.T) {
	hub := &fakeHub{}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	r := testRunner()
	cl, _ := NewClient(srv.URL, "hws_x", "")
	r.cl = cl
	sp, err := openSpool(t.TempDir(), 1<<30, "hws_x")
	if err != nil {
		t.Fatal(err)
	}
	r.sp = sp
	s := newSink(r, false)
	ctx := t.Context()

	// hub giù: i lotti finiscono su disco, nulla viene perso
	s.put(func(b *model.Batch) { *b = *batchOf(100, 1) })
	s.flush(ctx)
	if _, _, n := sp.stats(); n != 100 {
		t.Fatalf("attesi 100 record su disco, trovati %d", n)
	}
	if s.nextTry.IsZero() {
		t.Fatal("dopo un errore serve un'attesa prima di riprovare")
	}
	// durante l'attesa non si contatta l'hub: si scrive direttamente su disco
	s.put(func(b *model.Batch) { *b = *batchOf(50, 2) })
	s.flush(ctx)
	if _, _, n := sp.stats(); n != 150 {
		t.Fatalf("attesi 150 record su disco, trovati %d", n)
	}

	// hub di nuovo su: prima il lotto nuovo, poi la coda dal più vecchio
	hub.up.Store(true)
	s.nextTry = time.Time{}
	s.put(func(b *model.Batch) { *b = *batchOf(10, 3) })
	s.flush(ctx)
	if hub.records != 160 {
		t.Fatalf("l'hub ha ricevuto %d record, attesi 160", hub.records)
	}
	if fmt.Sprint(hub.ports) != "[3 1 2]" {
		t.Fatalf("ordine di consegna %v, atteso [3 1 2]", hub.ports)
	}
	if files, _, _ := sp.stats(); files != 0 {
		t.Fatalf("la coda doveva svuotarsi, restano %d file", files)
	}
	if s.dropped.Load() != 0 || sp.dropped.Load() != 0 {
		t.Fatal("nessun record doveva andare perso")
	}
}
