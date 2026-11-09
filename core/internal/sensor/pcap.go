package sensor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"hyperwave/internal/model"
)

type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// openPcap apre un file pcap o pcapng, anche compresso con gzip.
func openPcap(path string) (packetSource, io.Closer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	if magic, _ := br.Peek(2); bytes.Equal(magic, []byte{0x1f, 0x8b}) || strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		br = bufio.NewReaderSize(zr, 1<<20)
	}
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%s: file vuoto o illeggibile", path)
	}
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return ng, f, nil
	}
	pr, err := pcapgo.NewReader(br)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%s: non è un file pcap o pcapng: %w", path, err)
	}
	return pr, f, nil
}

// runPcap analizza i file indicati con il tempo dei pacchetti e invia il risultato come storico.
func (r *Runner) runPcap(ctx context.Context) error {
	if !r.live.Load() {
		return fmt.Errorf("il live è spento sull'hub: i dati verrebbero scartati")
	}
	out := newSink(r, true)
	p := newProc(r, out)
	var total int
	for _, path := range r.cfg.Files {
		src, closer, err := openPcap(path)
		if err != nil {
			return err
		}
		start := time.Now()
		n, first, last := 0, int64(0), int64(0)
		for ctx.Err() == nil {
			data, ci, err := src.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				r.log.Warn("pacchetto illeggibile, il resto del file viene ignorato", "file", path, "err", err)
				break
			}
			p.packet(data, ci, src.LinkType())
			ts := ci.Timestamp.UnixMilli()
			if first == 0 {
				first = ts
			}
			last = ts
			n++
			if ts-p.lastTick >= 1000 {
				p.tick(ts)
			}
			if pendingLen(out) >= model.MaxBatchRecords/2 {
				out.flush(ctx)
			}
		}
		closer.Close()
		total += n
		r.log.Info("file analizzato", "file", path, "pacchetti", n, "da", time.UnixMilli(first).Format(time.RFC3339), "a", time.UnixMilli(last).Format(time.RFC3339), "durata", time.Since(start).Round(time.Millisecond))
	}
	p.flushAll()
	p.tick(p.lastTick + rateEvery)
	out.flush(ctx)
	r.log.Info("analisi completata", "pacchetti", total, "record_inviati", r.sent.Load(), "scartati", out.dropped.Load())
	return ctx.Err()
}

func pendingLen(s *sink) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}
