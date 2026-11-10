package hub

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"hyperwave/internal/chx"
	"hyperwave/internal/model"
	"hyperwave/internal/version"
)

// watermark segue l'avanzamento dello storico inviato da un sensore.
type watermark struct {
	ts atomic.Int64 // dato più recente dell'ultimo batch storico
	at atomic.Int64 // quando è arrivato
}

type ingestStats struct {
	batches  atomic.Int64
	records  atomic.Int64
	rejected atomic.Int64
	lastErr  atomic.Value // string
}

func (h *Hub) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", h.handleHeartbeat)
	mux.HandleFunc("POST /v1/ingest", h.handleIngest)
	mux.HandleFunc("GET /healthz", h.handleHealth)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Hub) sensorFromRequest(w http.ResponseWriter, r *http.Request) *Sensor {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeJSON(w, http.StatusUnauthorized, model.HubReply{Error: "manca il token del sensore"})
		return nil
	}
	s, err := h.authenticate(r.Context(), strings.TrimSpace(token))
	if errors.Is(err, errBadToken) {
		writeJSON(w, http.StatusUnauthorized, model.HubReply{Error: err.Error()})
		return nil
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "database non disponibile"})
		return nil
	}
	return s
}

// decodeBody legge JSON eventualmente compresso, con limiti sia sul compresso sia sul decompresso.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	body := http.MaxBytesReader(w, r.Body, model.MaxBodyBytes)
	var rd io.Reader = body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer zr.Close()
		rd = io.LimitReader(zr, model.MaxPlainBytes)
	}
	return json.NewDecoder(rd).Decode(v)
}

func (h *Hub) reply(s *Sensor, lastIngest int64) model.HubReply {
	return model.HubReply{OK: true, Live: h.state.Live(), InternalNets: h.state.Internal().Strings(),
		ServerTime: time.Now().UnixMilli(), LastIngest: lastIngest}
}

func (h *Hub) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	s := h.sensorFromRequest(w, r)
	if s == nil {
		return
	}
	var hb model.Heartbeat
	if err := decodeBody(w, r, &hb); err != nil {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "heartbeat non valido"})
		return
	}
	li, err := h.heartbeat(r.Context(), s, hb)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "database non disponibile"})
		return
	}
	writeJSON(w, http.StatusOK, h.reply(s, li))
}

func (h *Hub) handleIngest(w http.ResponseWriter, r *http.Request) {
	s := h.sensorFromRequest(w, r)
	if s == nil {
		return
	}
	var b model.Batch
	if err := decodeBody(w, r, &b); err != nil {
		h.ingest.rejected.Add(1)
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "batch non valido: " + err.Error()})
		return
	}
	if b.Len() > model.MaxBatchRecords {
		h.ingest.rejected.Add(1)
		writeJSON(w, http.StatusRequestEntityTooLarge, model.HubReply{Error: "troppi record in un batch"})
		return
	}
	// con il live spento i dati non vengono registrati: il sensore lo sa dalla risposta
	if !h.state.Live() {
		writeJSON(w, http.StatusOK, h.reply(s, 0))
		return
	}
	n, maxTS, err := h.store(r.Context(), s, &b)
	if err != nil {
		h.ingest.lastErr.Store(err.Error())
		h.log.Warn("scrittura batch", "sensor", s.Name, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "scrittura non riuscita, riprovare"})
		return
	}
	var li int64
	if maxTS > 0 {
		var t *time.Time
		h.pg.QueryRow(r.Context(), `UPDATE sensors SET last_seen = now(), records = records + $3,
			last_ingest = GREATEST(last_ingest, $2) WHERE id = $1 RETURNING last_ingest`, s.ID, time.UnixMilli(maxTS), n).Scan(&t)
		if t != nil {
			li = t.UnixMilli()
		}
	}
	rep := h.reply(s, li)
	rep.Accepted = n
	writeJSON(w, http.StatusOK, rep)
}

func (h *Hub) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	pgOK := h.pg.Ping(ctx) == nil
	chOK := h.ch.Ping(ctx) == nil
	natsOK := h.nc != nil && h.nc.IsConnected()
	lastErr, _ := h.ingest.lastErr.Load().(string)
	status := http.StatusOK
	if !pgOK || !chOK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ok": status == http.StatusOK, "version": version.Version, "uptime_s": int(time.Since(h.start).Seconds()),
		"postgres": pgOK, "clickhouse": chOK, "nats": natsOK, "live": h.state.Live(),
		"batches": h.ingest.batches.Load(), "records": h.ingest.records.Load(), "rejected": h.ingest.rejected.Load(),
		"last_error": lastErr,
	})
}

// ---------------------------------------------------------------- scrittura

type dnsRow struct {
	TS       string   `json:"ts"`
	SensorID int64    `json:"sensor_id"`
	Client   string   `json:"client"`
	Server   string   `json:"server"`
	Query    string   `json:"query"`
	QType    string   `json:"qtype"`
	RCode    string   `json:"rcode"`
	Answers  []string `json:"answers"`
	RTT      float32  `json:"rtt"`
	Demo     uint8    `json:"demo"`
}

type tlsRow struct {
	TS          string `json:"ts"`
	SensorID    int64  `json:"sensor_id"`
	Client      string `json:"client"`
	Server      string `json:"server"`
	Port        uint16 `json:"port"`
	Transport   string `json:"transport"`
	SNI         string `json:"sni"`
	Version     string `json:"version"`
	ALPN        string `json:"alpn"`
	JA4         string `json:"ja4"`
	CertSubject string `json:"cert_subject"`
	CertIssuer  string `json:"cert_issuer"`
	CertExpiry  int64  `json:"cert_expiry"`
	SelfSigned  uint8  `json:"self_signed"`
	Demo        uint8  `json:"demo"`
}

type httpRow struct {
	TS        string `json:"ts"`
	SensorID  int64  `json:"sensor_id"`
	Client    string `json:"client"`
	Server    string `json:"server"`
	Port      uint16 `json:"port"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	URI       string `json:"uri"`
	Status    uint16 `json:"status"`
	UserAgent string `json:"user_agent"`
	Demo      uint8  `json:"demo"`
}

type sessionRow struct {
	TS         string `json:"ts"`
	SensorID   int64  `json:"sensor_id"`
	Client     string `json:"client"`
	Server     string `json:"server"`
	Port       uint16 `json:"port"`
	Transport  string `json:"transport"`
	Protocol   string `json:"protocol"`
	Auth       string `json:"auth"`
	User       string `json:"user"`
	Domain     string `json:"domain"`
	Host       string `json:"host"`
	ClientSW   string `json:"client_sw"`
	ServerSW   string `json:"server_sw"`
	Hash       string `json:"hash"`
	ServerHash string `json:"server_hash"`
	Info       string `json:"info"`
	Weak       string `json:"weak"`
	Demo       uint8  `json:"demo"`
}

// transport normalizza il trasporto dichiarato dal sensore.
func transport(s string) string {
	if s == "quic" || s == "udp" {
		return s
	}
	return "tcp"
}

type eventRow struct {
	TS        string `json:"ts"`
	SensorID  int64  `json:"sensor_id"`
	Kind      string `json:"kind"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	DPort     uint16 `json:"dport"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Detail    string `json:"detail"`
	Demo      uint8  `json:"demo"`
}

type rateRow struct {
	TS            string  `json:"ts"`
	SensorID      int64   `json:"sensor_id"`
	Secs          float64 `json:"secs"`
	BytesIn       uint64  `json:"bytes_in"`
	BytesOut      uint64  `json:"bytes_out"`
	BytesInternal uint64  `json:"bytes_internal"`
	Packets       uint64  `json:"packets"`
	Flows         uint64  `json:"flows"`
	Drops         uint64  `json:"drops"`
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// store scrive un batch. Restituisce i record accettati e il tempo del dato più recente.
func (h *Hub) store(ctx context.Context, s *Sensor, b *model.Batch) (n int, maxTS int64, err error) {
	now := time.Now().UnixMilli()
	oldest := now - int64(h.cfg.RetentionDays)*86_400_000
	newest := now + 5*60_000 // tolleranza per gli orologi poco precisi
	minTS := int64(0)
	ok := func(ts int64) bool {
		if ts < oldest || ts > newest {
			return false
		}
		maxTS = max(maxTS, ts)
		if minTS == 0 || ts < minTS {
			minTS = ts
		}
		return true
	}
	demo := b2u(b.Demo)
	nets := h.state.Internal()

	// prima i nomi (DNS, SNI, Host), così i flussi dello stesso batch li trovano
	h.enr.learnBatch(b)

	flows := make([]any, 0, len(b.Flows))
	valid := b.Flows[:0]
	for i := range b.Flows {
		f := b.Flows[i]
		if !validIP(f.SrcIP) || !validIP(f.DstIP) || !ok(f.TS) || f.Proto == "" {
			continue
		}
		f.Proto, f.App, f.Domain, f.Flags = clip(f.Proto, 16), clip(f.App, 64), clip(f.Domain, 253), clip(f.Flags, 16)
		valid = append(valid, f)
		flows = append(flows, h.enr.flow(&f, s, nets, b.Demo))
	}
	b.Flows = valid

	dnsRows := make([]any, 0, len(b.DNS))
	for _, d := range b.DNS {
		if !validIP(d.Client) || !ok(d.TS) {
			continue
		}
		ans := d.Answers
		if len(ans) > 32 {
			ans = ans[:32]
		}
		if ans == nil {
			ans = []string{}
		}
		dnsRows = append(dnsRows, dnsRow{chx.Time(d.TS), s.ID, d.Client, d.Server, clip(strings.ToLower(strings.TrimSuffix(d.Query, ".")), 253),
			clip(d.QType, 16), clip(d.RCode, 16), ans, d.RTT, demo})
	}
	tlsRows := make([]any, 0, len(b.TLS))
	for _, t := range b.TLS {
		if !validIP(t.Server) || !ok(t.TS) {
			continue
		}
		tlsRows = append(tlsRows, tlsRow{chx.Time(t.TS), s.ID, t.Client, t.Server, t.Port, transport(t.Transport), clip(strings.ToLower(t.SNI), 253), clip(t.Version, 16),
			clip(t.ALPN, 32), clip(t.JA4, 64), clip(t.CertSubject, 256), clip(t.CertIssuer, 256), t.CertNotAfter, b2u(t.SelfSigned), demo})
	}
	httpRows := make([]any, 0, len(b.HTTP))
	for _, x := range b.HTTP {
		if !validIP(x.Server) || !ok(x.TS) {
			continue
		}
		httpRows = append(httpRows, httpRow{chx.Time(x.TS), s.ID, x.Client, x.Server, x.Port, clip(x.Method, 16), clip(strings.ToLower(x.Host), 253),
			clip(x.URI, 1024), x.Status, clip(x.UserAgent, 512), demo})
	}
	sessRows := make([]any, 0, len(b.Sessions))
	for _, x := range b.Sessions {
		if !validIP(x.Client) || !validIP(x.Server) || !ok(x.TS) || x.Protocol == "" {
			continue
		}
		sessRows = append(sessRows, sessionRow{chx.Time(x.TS), s.ID, x.Client, x.Server, x.Port, transport(x.Transport), clip(strings.ToLower(x.Protocol), 16),
			clip(x.Auth, 16), clip(x.User, 128), clip(x.Domain, 255), clip(x.Host, 255), clip(x.ClientSW, 255), clip(x.ServerSW, 255),
			clip(x.Hash, 64), clip(x.ServerHash, 64), clip(x.Info, 512), clip(x.Weak, 255), demo})
	}
	evRows := make([]any, 0, len(b.Events))
	for _, ev := range b.Events {
		if !ok(ev.TS) {
			continue
		}
		if _, valid := sevRank[ev.Severity]; !valid {
			ev.Severity = "info"
		}
		det, _ := json.Marshal(ev.Detail)
		evRows = append(evRows, eventRow{chx.Time(ev.TS), s.ID, clip(ev.Kind, 32), ev.Severity, clip(ev.Title, 300), ev.SrcIP, ev.DstIP, ev.DstPort,
			clip(ev.Signature, 300), clip(ev.Category, 100), clip(string(det), 8192), demo})
	}
	rateRows := make([]any, 0, len(b.Rates))
	for _, rt := range b.Rates {
		if !ok(rt.TS) || rt.Seconds <= 0 {
			continue
		}
		rateRows = append(rateRows, rateRow{chx.Time(rt.TS), s.ID, rt.Seconds, rt.BytesIn, rt.BytesOut, rt.BytesInternal, rt.Packets, rt.Flows, rt.Drops})
	}
	hosts := b.Hosts[:0]
	for _, x := range b.Hosts {
		if validIP(x.IP) && ok(x.TS) {
			hosts = append(hosts, x)
		}
	}
	b.Hosts = hosts

	for _, t := range []struct {
		table string
		rows  []any
	}{{"flows", flows}, {"dns", dnsRows}, {"tls", tlsRows}, {"http", httpRows}, {"sessions", sessRows}, {"events", evRows}, {"rates", rateRows}} {
		if err := h.ch.Insert(ctx, t.table, t.rows); err != nil {
			return 0, 0, err
		}
		n += len(t.rows)
	}
	n += len(b.Hosts)
	h.ingest.batches.Add(1)
	h.ingest.records.Add(int64(n))

	h.intel.scan(s, b)
	h.inv.add(s, b, nets)
	if minTS > 0 {
		h.eng.lateData(minTS)
	}
	if b.Backfill {
		v, _ := h.marks.LoadOrStore(s.ID, &watermark{})
		m := v.(*watermark)
		m.ts.Store(maxTS)
		m.at.Store(now)
	} else {
		h.marks.Delete(s.ID)
		h.live.batch(s, flows, b)
	}
	return n, maxTS, nil
}
