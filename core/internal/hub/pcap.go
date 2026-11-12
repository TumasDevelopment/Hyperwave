package hub

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"hyperwave/internal/model"
)

// Estrazioni di pacchetti (tabelle pcap_requests e pcap_chunks, migrazione 008).

const (
	pcapChunk          = 1 << 20
	pcapPendingTimeout = time.Hour        // sensore spento o senza heartbeat
	pcapRunningTimeout = 20 * time.Minute // sensore riavviato durante l'estrazione
)

// pcapJobs consegna al sensore le richieste in attesa e le segna in corso.
func (h *Hub) pcapJobs(ctx context.Context, s *Sensor) []model.PcapJob {
	rows, err := h.pg.Query(ctx, `UPDATE pcap_requests SET status = 'running', started_at = now()
		WHERE id IN (SELECT id FROM pcap_requests WHERE sensor_id = $1 AND status = 'pending'
		             ORDER BY created_at LIMIT 4 FOR UPDATE SKIP LOCKED)
		RETURNING id, host(ip_a), coalesce(host(ip_b), ''), coalesce(port, 0), proto,
		          (extract(epoch FROM t_from) * 1000)::bigint, (extract(epoch FROM t_to) * 1000)::bigint`, s.ID)
	if err != nil {
		h.log.Warn("estrazioni di pacchetti in attesa", "sensor", s.Name, "err", err)
		return nil
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (model.PcapJob, error) {
		var j model.PcapJob
		var port int32
		err := row.Scan(&j.ID, &j.A, &j.B, &port, &j.Proto, &j.From, &j.To)
		j.Port = uint16(port)
		return j, err
	})
	if err != nil {
		h.log.Warn("estrazioni di pacchetti in attesa", "sensor", s.Name, "err", err)
		return nil
	}
	for _, j := range jobs {
		h.log.Info("estrazione di pacchetti consegnata al sensore", "id", j.ID, "sensor", s.Name)
	}
	return jobs
}

func pcapID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// handlePcapResult riceve dal sensore il pcap compresso e lo salva a pezzi.
// Il contenuto si decomprime mentre arriva per controllarne l'integrità e calcolarne lo SHA-256.
func (h *Hub) handlePcapResult(w http.ResponseWriter, r *http.Request) {
	// un file grande da un sensore lontano può richiedere più dei 2 minuti delle altre chiamate
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(15 * time.Minute))
	rc.SetWriteDeadline(time.Now().Add(16 * time.Minute))
	s := h.sensorFromRequest(w, r)
	if s == nil {
		return
	}
	id, ok := pcapID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "richiesta non valida"})
		return
	}
	limit := int64(h.cfg.PcapMaxMB) << 20
	if r.ContentLength > limit {
		writeJSON(w, http.StatusRequestEntityTooLarge, model.HubReply{Error: fmt.Sprintf("file oltre il limite dell'hub (%d MB, HW_PCAP_MAX_MB)", h.cfg.PcapMaxMB)})
		return
	}
	ctx := r.Context()
	tx, err := h.pg.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "database non disponibile"})
		return
	}
	defer tx.Rollback(context.Background())
	var status string
	err = tx.QueryRow(ctx, "SELECT status FROM pcap_requests WHERE id = $1 AND sensor_id = $2 FOR UPDATE", id, s.ID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, model.HubReply{Error: "richiesta sconosciuta"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "database non disponibile"})
		return
	}
	if status != "running" {
		writeJSON(w, http.StatusConflict, model.HubReply{Error: "richiesta non più in corso (" + status + ")"})
		return
	}

	// verifica: decompressione e hash in parallelo alla scrittura dei pezzi
	pr, pw := io.Pipe()
	type check struct {
		sum   string
		plain int64
		err   error
	}
	done := make(chan check, 1)
	go func() {
		zr, err := gzip.NewReader(bufio.NewReader(pr))
		if err != nil {
			io.Copy(io.Discard, pr)
			done <- check{err: err}
			return
		}
		hash := sha256.New()
		n, err := io.Copy(hash, zr)
		io.Copy(io.Discard, pr)
		done <- check{sum: hex.EncodeToString(hash.Sum(nil)), plain: n, err: err}
	}()

	body := http.MaxBytesReader(w, r.Body, limit)
	buf := make([]byte, pcapChunk)
	var stored int64
	seq := 0
	for {
		n, rerr := io.ReadFull(body, buf)
		if n > 0 {
			pw.Write(buf[:n])
			if _, err := tx.Exec(ctx, "INSERT INTO pcap_chunks (request_id, seq, data) VALUES ($1, $2, $3)", id, seq, buf[:n]); err != nil {
				pw.CloseWithError(err)
				<-done
				writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "scrittura non riuscita"})
				return
			}
			seq++
			stored += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			pw.CloseWithError(rerr)
			<-done
			writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "caricamento interrotto o troppo grande"})
			return
		}
	}
	pw.Close()
	c := <-done
	if c.err != nil {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "file compresso non valido: " + c.err.Error()})
		return
	}
	if want := strings.ToLower(r.Header.Get("X-HW-SHA256")); want != "" && want != c.sum {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "SHA-256 diverso da quello dichiarato dal sensore"})
		return
	}
	packets, _ := strconv.ParseInt(r.Header.Get("X-HW-Packets"), 10, 64)
	truncated := r.Header.Get("X-HW-Truncated") == "1"
	_, err = tx.Exec(ctx, `UPDATE pcap_requests SET status = 'done', finished_at = now(), packets = $2, bytes = $3, stored = $4,
		truncated = $5, sha256 = $6, error = '', expires_at = now() + make_interval(days => $7) WHERE id = $1`,
		id, packets, c.plain, stored, truncated, c.sum, h.cfg.PcapKeepDays)
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "scrittura non riuscita"})
		return
	}
	h.log.Info("pacchetti estratti ricevuti", "id", id, "sensor", s.Name, "pacchetti", packets, "byte", c.plain, "troncato", truncated)
	h.live.event("pcap_ready", map[string]any{"id": id, "sensor": s.Name})
	writeJSON(w, http.StatusOK, model.HubReply{OK: true, Live: h.state.Live()})
}

// handlePcapFail registra che il sensore non ha potuto fare l'estrazione.
func (h *Hub) handlePcapFail(w http.ResponseWriter, r *http.Request) {
	s := h.sensorFromRequest(w, r)
	if s == nil {
		return
	}
	id, ok := pcapID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "richiesta non valida"})
		return
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, model.HubReply{Error: "corpo non valido"})
		return
	}
	msg := strings.TrimSpace(body.Error)
	if msg == "" {
		msg = "il sensore non ha indicato il motivo"
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := h.pg.Exec(r.Context(), `UPDATE pcap_requests SET status = 'failed', finished_at = now(), error = $3
		WHERE id = $1 AND sensor_id = $2 AND status IN ('pending', 'running')`, id, s.ID, msg)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, model.HubReply{Error: "database non disponibile"})
		return
	}
	h.log.Info("estrazione di pacchetti non riuscita sul sensore", "id", id, "sensor", s.Name, "motivo", msg)
	writeJSON(w, http.StatusOK, model.HubReply{OK: true, Live: h.state.Live()})
}

// expirePcap chiude le richieste rimaste senza risposta e cancella i file scaduti (solo sul capo).
func (h *Hub) expirePcap(ctx context.Context) error {
	stmts := []struct {
		sql  string
		args []any
	}{
		{`UPDATE pcap_requests SET status = 'failed', finished_at = now(),
			error = 'il sensore non ha preso la richiesta: è spento, non comunica con l''hub o è una versione senza estrazioni'
			WHERE status = 'pending' AND created_at < now() - make_interval(secs => $1)`, []any{pcapPendingTimeout.Seconds()}},
		{`UPDATE pcap_requests SET status = 'failed', finished_at = now(),
			error = 'il sensore non ha completato l''estrazione in tempo (riavviato o bloccato)'
			WHERE status = 'running' AND started_at < now() - make_interval(secs => $1)`, []any{pcapRunningTimeout.Seconds()}},
		{`WITH old AS (UPDATE pcap_requests SET status = 'expired' WHERE status = 'done' AND expires_at < now() RETURNING id)
			DELETE FROM pcap_chunks WHERE request_id IN (SELECT id FROM old)`, nil},
		// le richieste restano nel registro delle estrazioni per la stessa durata del registro attività
		{"DELETE FROM pcap_requests WHERE created_at < now() - make_interval(days => $1)", []any{h.cfg.AuditRetention}},
	}
	for _, s := range stmts {
		if _, err := h.pg.Exec(ctx, s.sql, s.args...); err != nil {
			return err
		}
	}
	return nil
}
