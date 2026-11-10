package sensor

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"hyperwave/internal/model"
)

// tailSuricata segue il file eve.json di Suricata e inoltra gli allarmi all'hub come eventi IDS.
// Parte dalla fine del file (niente allarmi vecchi) e segue la rotazione dei log.
func (r *Runner) tailSuricata(ctx context.Context, out *sink) {
	var forwarded atomic.Int64
	r.addStat("ids_events", func() any { return forwarded.Load() })
	r.log.Info("lettura degli allarmi di Suricata", "file", r.cfg.SuricataEve)
	r.tailFile(ctx, r.cfg.SuricataEve, tailOpts{}, func(line string) {
		if ev, ok := parseEve(line); ok {
			forwarded.Add(1)
			out.put(func(b *model.Batch) { b.Events = append(b.Events, ev) })
		}
	})
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
