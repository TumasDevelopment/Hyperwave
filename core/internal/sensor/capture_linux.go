//go:build linux

package sensor

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// runCapture legge i pacchetti dalle interfacce (AF_PACKET, senza libpcap) finché ctx non viene annullato.
// Serve la capacità CAP_NET_RAW; l'interfaccia di solito riceve una copia del traffico (porta SPAN o TAP).
func (r *Runner) runCapture(ctx context.Context) error {
	out := newSink(r, false)
	p := newProc(r, out)

	type iface struct {
		name string
		h    *pcapgo.EthernetHandle
	}
	var ifs []iface
	for _, name := range r.cfg.Ifaces {
		h, err := pcapgo.NewEthernetHandle(name)
		if err != nil {
			for _, x := range ifs {
				x.h.Close()
			}
			return fmt.Errorf("apertura di %s: %w (serve CAP_NET_RAW)", name, err)
		}
		if err := h.SetCaptureLength(r.cfg.Snaplen); err != nil {
			r.log.Warn("lunghezza di cattura non impostata", "iface", name, "err", err)
		}
		if r.cfg.Promisc {
			if err := h.SetPromiscuous(true); err != nil {
				r.log.Warn("modalità promiscua non attivata", "iface", name, "err", err)
			}
		}
		ifs = append(ifs, iface{name, h})
	}

	var kernelDrops atomic.Uint64
	p.drops = func() uint64 {
		var d uint64
		for _, x := range ifs {
			if st, err := x.h.Stats(); err == nil && st != nil {
				d += uint64(st.Drops)
			}
		}
		kernelDrops.Add(d)
		return d
	}
	r.addStat("kernel_drops", func() any { return kernelDrops.Load() })

	if r.cfg.SuricataEve != "" {
		go r.tailSuricata(ctx, out)
	}

	sctx, stopSink := context.WithCancel(context.Background())
	var sinkDone sync.WaitGroup
	sinkDone.Add(1)
	go func() { defer sinkDone.Done(); out.loop(sctx, 5*time.Second) }()

	var wg sync.WaitGroup
	for _, x := range ifs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.log.Info("cattura avviata", "iface", x.name)
			for {
				data, ci, err := x.h.ZeroCopyReadPacketData()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					r.log.Warn("lettura pacchetto", "iface", x.name, "err", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				p.packet(data, ci, layers.LinkTypeEthernet)
			}
		}()
	}

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, x := range ifs {
				x.h.Close()
			}
			wg.Wait()
			// ultimi flussi e ultimo invio, con un limite di tempo
			p.flushAll()
			stopSink()
			sinkDone.Wait()
			fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out.flush(fctx)
			cancel()
			return nil
		case now := <-t.C:
			p.tick(now.UnixMilli())
		}
	}
}
