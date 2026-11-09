package sensor

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"hyperwave/internal/model"
)

// tailSuricata segue il file eve.json di Suricata e inoltra gli allarmi all'hub come eventi IDS.
// Parte dalla fine del file (niente allarmi vecchi) e segue la rotazione dei log.
func (r *Runner) tailSuricata(ctx context.Context, out *sink) {
	path := r.cfg.SuricataEve
	var (
		f   *os.File
		rd  *bufio.Reader
		pos int64
	)
	open := func(fromEnd bool) bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		if f != nil {
			f.Close()
		}
		f, pos = nf, 0
		if fromEnd {
			pos, _ = f.Seek(0, io.SeekEnd)
		}
		rd = bufio.NewReaderSize(f, 256<<10)
		return true
	}
	if open(true) {
		r.log.Info("lettura degli allarmi di Suricata", "file", path)
	} else {
		r.log.Warn("eve.json di Suricata non ancora presente, lo attendo", "file", path)
	}
	var forwarded atomic.Int64
	r.addStat("ids_events", func() any { return forwarded.Load() })
	var partial strings.Builder
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-t.C:
		}
		if f == nil {
			if open(false) {
				r.log.Info("eve.json di Suricata trovato", "file", path)
			}
			continue
		}
		for {
			line, err := rd.ReadString('\n')
			pos += int64(len(line))
			if err != nil {
				partial.WriteString(line) // riga non ancora completa
				break
			}
			if partial.Len() > 0 {
				line = partial.String() + line
				partial.Reset()
			}
			if ev, ok := parseEve(line); ok {
				forwarded.Add(1)
				out.put(func(b *model.Batch) { b.Events = append(b.Events, ev) })
			}
		}
		// rotazione: il percorso punta a un altro file, oppure il file è stato troncato
		st, err1 := os.Stat(path)
		cur, err2 := f.Stat()
		if err1 == nil && err2 == nil && (!os.SameFile(st, cur) || st.Size() < pos) {
			partial.Reset()
			open(false)
		}
	}
}

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  uint16 `json:"dest_port"`
	Proto     string `json:"proto"`
	AppProto  string `json:"app_proto"`
	FlowID    uint64 `json:"flow_id"`
	Alert     struct {
		Action    string `json:"action"`
		SID       uint64 `json:"signature_id"`
		Rev       int    `json:"rev"`
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert"`
}

func parseEve(line string) (model.Event, bool) {
	if !strings.Contains(line, `"event_type":"alert"`) {
		return model.Event{}, false
	}
	var e eveRecord
	if json.Unmarshal([]byte(line), &e) != nil || e.EventType != "alert" {
		return model.Event{}, false
	}
	ts := time.Now()
	for _, layout := range []string{"2006-01-02T15:04:05.999999-0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, e.Timestamp); err == nil {
			ts = t
			break
		}
	}
	sev := map[int]string{1: "high", 2: "medium", 3: "low"}[e.Alert.Severity]
	if sev == "" {
		sev = "info"
	}
	return model.Event{TS: ts.UnixMilli(), Kind: "ids", Severity: sev, Title: clip(e.Alert.Signature, 300),
		SrcIP: e.SrcIP, DstIP: e.DestIP, DstPort: e.DestPort, Signature: clip(e.Alert.Signature, 300), Category: clip(e.Alert.Category, 200),
		Detail: map[string]any{"sid": e.Alert.SID, "rev": e.Alert.Rev, "action": e.Alert.Action, "proto": e.Proto, "app_proto": e.AppProto, "flow_id": e.FlowID}}, true
}
