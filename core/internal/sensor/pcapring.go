package sensor

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"hyperwave/internal/model"
)

// pcapRing conserva su disco gli ultimi pacchetti catturati, per estrarne una parte su richiesta.
// I file sono segmenti pcap: "<primo ms>-open.pcap" quello in scrittura, "<primo ms>-<ultimo ms>.pcap"
// quelli chiusi. Si cancellano i più vecchi oltre lo spazio o l'età massimi.
// I pacchetti contengono dati personali: cartella 700, file 600, nessun altro accesso dal sensore.
type pcapRing struct {
	dir      string
	maxBytes int64
	maxAge   time.Duration
	snaplen  int
	segBytes int64
	segAge   time.Duration

	mu    sync.Mutex
	f     *os.File
	bw    *bufio.Writer
	w     *pcapgo.Writer
	first int64 // ms del primo pacchetto del segmento aperto
	last  int64
	size  int64
	dirty bool
	err   error // ultimo errore di scrittura, per non riempire il log
}

type ringSegment struct {
	path        string
	first, last int64
	size        int64
	open        bool
}

const (
	ringSegBytes = 64 << 20
	ringSegAge   = 5 * time.Minute
)

func openPcapRing(dir string, maxMB int, hours float64, snaplen int) (*pcapRing, error) {
	if maxMB < 2*ringSegBytes>>20 {
		return nil, fmt.Errorf("HW_PCAP_RING_MB troppo piccolo: almeno %d", 2*ringSegBytes>>20)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	r := &pcapRing{dir: dir, maxBytes: int64(maxMB) << 20, maxAge: time.Duration(hours * float64(time.Hour)),
		snaplen: snaplen, segBytes: ringSegBytes, segAge: ringSegAge}
	// un segmento rimasto aperto da un arresto improvviso si chiude con l'ora dell'ultima modifica
	segs, err := r.segments()
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if s.open {
			st, err := os.Stat(s.path)
			if err != nil {
				continue
			}
			os.Rename(s.path, filepath.Join(dir, fmt.Sprintf("%d-%d.pcap", s.first, st.ModTime().UnixMilli())))
		}
	}
	r.prune(time.Now())
	return r, nil
}

// write aggiunge un pacchetto. Va chiamata con data valido solo durante la chiamata (zero copy).
func (r *pcapRing) write(ci gopacket.CaptureInfo, data []byte) {
	ts := ci.Timestamp.UnixMilli()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil || r.size >= r.segBytes || ts-r.first >= r.segAge.Milliseconds() {
		if err := r.rotateLocked(ts); err != nil {
			r.fail(err)
			return
		}
	}
	if len(data) > r.snaplen {
		data = data[:r.snaplen]
	}
	ci.CaptureLength = len(data)
	if err := r.w.WritePacket(ci, data); err != nil {
		r.fail(err)
		return
	}
	r.size += int64(16 + len(data))
	r.last = max(r.last, ts)
	r.dirty = true
}

func (r *pcapRing) fail(err error) {
	if r.err == nil || r.err.Error() != err.Error() {
		r.err = err
	}
}

// rotateLocked chiude il segmento aperto e ne apre uno nuovo.
func (r *pcapRing) rotateLocked(ts int64) error {
	r.closeLocked()
	path := filepath.Join(r.dir, fmt.Sprintf("%d-open.pcap", ts))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	w := pcapgo.NewWriterNanos(bw)
	if err := w.WriteFileHeader(uint32(r.snaplen), layers.LinkTypeEthernet); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	r.f, r.bw, r.w, r.first, r.last, r.size = f, bw, w, ts, ts, 24
	go r.prune(time.Now())
	return nil
}

func (r *pcapRing) closeLocked() {
	if r.f == nil {
		return
	}
	r.bw.Flush()
	name := r.f.Name()
	r.f.Close()
	os.Rename(name, filepath.Join(r.dir, fmt.Sprintf("%d-%d.pcap", r.first, r.last)))
	r.f, r.bw, r.w = nil, nil, nil
}

// flush scrive su disco i pacchetti in memoria: chiamata ogni secondo e prima di un'estrazione.
func (r *pcapRing) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil && r.dirty {
		if err := r.bw.Flush(); err != nil {
			r.fail(err)
		}
		r.dirty = false
	}
}

func (r *pcapRing) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked()
}

// segments elenca i segmenti dal più vecchio.
func (r *pcapRing) segments() ([]ringSegment, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	var out []ringSegment
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".pcap")
		if !ok || e.IsDir() {
			continue
		}
		a, b, ok := strings.Cut(name, "-")
		if !ok {
			continue
		}
		first, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			continue
		}
		s := ringSegment{path: filepath.Join(r.dir, e.Name()), first: first}
		if b == "open" {
			s.open, s.last = true, time.Now().UnixMilli()
		} else if s.last, err = strconv.ParseInt(b, 10, 64); err != nil {
			continue
		}
		if info, err := e.Info(); err == nil {
			s.size = info.Size()
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].first < out[j].first })
	return out, nil
}

// prune cancella i segmenti chiusi più vecchi dell'età massima o oltre lo spazio massimo.
func (r *pcapRing) prune(now time.Time) {
	segs, err := r.segments()
	if err != nil {
		return
	}
	var total int64
	for _, s := range segs {
		total += s.size
	}
	cutoff := now.Add(-r.maxAge).UnixMilli()
	for _, s := range segs {
		if s.open || (total <= r.maxBytes && s.last >= cutoff) {
			continue
		}
		if os.Remove(s.path) == nil {
			total -= s.size
		}
	}
}

// window restituisce il periodo coperto dal buffer e lo spazio occupato, per l'heartbeat.
func (r *pcapRing) window() (from, to, bytes int64) {
	r.flush()
	segs, _ := r.segments()
	for _, s := range segs {
		if from == 0 || s.first < from {
			from = s.first
		}
		to = max(to, s.last)
		bytes += s.size
	}
	r.mu.Lock()
	if r.f != nil {
		to = r.last
	}
	r.mu.Unlock()
	return from, to, bytes
}

// ---------------------------------------------------------------- estrazione

// pcapMatcher dice se un pacchetto rientra nella richiesta.
type pcapMatcher struct {
	a, b    netip.Addr // b non valido = qualsiasi controparte
	port    uint16     // 0 = qualsiasi
	proto   string     // "" = qualsiasi
	from    int64      // ms
	to      int64
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
}

func newPcapMatcher(job model.PcapJob) (*pcapMatcher, error) {
	m := &pcapMatcher{port: job.Port, proto: job.Proto, from: job.From, to: job.To}
	var err error
	if m.a, err = netip.ParseAddr(job.A); err != nil {
		return nil, fmt.Errorf("indirizzo non valido: %q", job.A)
	}
	m.a = m.a.Unmap()
	if job.B != "" {
		if m.b, err = netip.ParseAddr(job.B); err != nil {
			return nil, fmt.Errorf("indirizzo non valido: %q", job.B)
		}
		m.b = m.b.Unmap()
	}
	switch job.Proto {
	case "", "tcp", "udp", "icmp":
	default:
		return nil, fmt.Errorf("protocollo non valido: %q", job.Proto)
	}
	if job.To <= job.From {
		return nil, errors.New("periodo non valido")
	}
	m.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &m.eth, &m.dot1q, &m.ip4, &m.ip6, &m.tcp, &m.udp)
	m.parser.IgnoreUnsupported = true
	return m, nil
}

func (m *pcapMatcher) match(data []byte) bool {
	m.decoded = m.decoded[:0]
	m.parser.DecodeLayers(data, &m.decoded)
	var src, dst netip.Addr
	var sport, dport uint16
	proto := ""
	for _, t := range m.decoded {
		switch t {
		case layers.LayerTypeIPv4:
			src, _ = netip.AddrFromSlice(m.ip4.SrcIP)
			dst, _ = netip.AddrFromSlice(m.ip4.DstIP)
			if m.ip4.Protocol == layers.IPProtocolICMPv4 {
				proto = "icmp"
			}
		case layers.LayerTypeIPv6:
			src, _ = netip.AddrFromSlice(m.ip6.SrcIP)
			dst, _ = netip.AddrFromSlice(m.ip6.DstIP)
			if m.ip6.NextHeader == layers.IPProtocolICMPv6 {
				proto = "icmp"
			}
		case layers.LayerTypeTCP:
			proto, sport, dport = "tcp", uint16(m.tcp.SrcPort), uint16(m.tcp.DstPort)
		case layers.LayerTypeUDP:
			proto, sport, dport = "udp", uint16(m.udp.SrcPort), uint16(m.udp.DstPort)
		}
	}
	if !src.IsValid() {
		return false
	}
	src, dst = src.Unmap(), dst.Unmap()
	var other netip.Addr
	switch m.a {
	case src:
		other = dst
	case dst:
		other = src
	default:
		return false
	}
	if m.b.IsValid() && other != m.b {
		return false
	}
	if m.proto != "" && proto != m.proto {
		return false
	}
	if m.port != 0 && sport != m.port && dport != m.port {
		return false
	}
	return true
}

type pcapResult struct {
	path      string // file pcap compresso con gzip
	packets   int64
	bytes     int64 // pcap non compresso
	sha256    string
	truncated bool
}

// extract scrive in un file temporaneo i pacchetti richiesti, compressi, fino a maxBytes non compressi.
func (r *pcapRing) extract(ctx context.Context, job model.PcapJob, maxBytes int64) (*pcapResult, error) {
	m, err := newPcapMatcher(job)
	if err != nil {
		return nil, err
	}
	r.flush()
	segs, err := r.segments()
	if err != nil {
		return nil, err
	}
	out, err := os.CreateTemp(r.dir, "estrazione-*.tmp")
	if err != nil {
		return nil, err
	}
	res := &pcapResult{path: out.Name()}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(res.path)
		}
	}()
	zw, _ := gzip.NewWriterLevel(out, gzip.BestSpeed)
	hash := sha256.New()
	cw := &countWriter{w: io.MultiWriter(zw, hash)}
	w := pcapgo.NewWriterNanos(cw)
	if err := w.WriteFileHeader(uint32(r.snaplen), layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	for _, s := range segs {
		if s.last < job.From || s.first > job.To {
			continue
		}
		done, err := r.extractSegment(ctx, s.path, m, w, cw, res, maxBytes)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := out.Sync(); err != nil {
		return nil, err
	}
	res.bytes = cw.n
	res.sha256 = hex.EncodeToString(hash.Sum(nil))
	ok = true
	return res, nil
}

func (r *pcapRing) extractSegment(ctx context.Context, path string, m *pcapMatcher, w *pcapgo.Writer, cw *countWriter, res *pcapResult, maxBytes int64) (done bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // cancellato dalla rotazione nel frattempo
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	rd, err := pcapgo.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return false, nil // segmento appena creato, ancora senza intestazione
	}
	for n := 0; ; n++ {
		if n%10_000 == 0 && ctx.Err() != nil {
			return true, ctx.Err()
		}
		data, ci, err := rd.ReadPacketData()
		if err != nil {
			// fine del file, o pacchetto scritto a metà nel segmento ancora aperto
			return false, nil
		}
		ts := ci.Timestamp.UnixMilli()
		if ts < m.from {
			continue
		}
		if ts > m.to {
			// con più interfacce i pacchetti possono essere fuori ordine di qualche millisecondo
			if ts > m.to+2000 {
				return true, nil
			}
			continue
		}
		if !m.match(data) {
			continue
		}
		if cw.n+int64(16+len(data)) > maxBytes {
			res.truncated = true
			return true, nil
		}
		if err := w.WritePacket(ci, data); err != nil {
			return true, err
		}
		res.packets++
	}
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ---------------------------------------------------------------- richieste dall'hub

// pcapWorker esegue una richiesta alla volta, nell'ordine in cui arrivano con l'heartbeat.
type pcapWorker struct {
	r       *Runner
	ring    *pcapRing // nil: il sensore non conserva pacchetti
	reason  string    // perché ring è nil, da riferire all'hub
	maxSize int64
	queue   chan model.PcapJob
	seenMu  sync.Mutex
	seen    map[int64]bool
}

func newPcapWorker(r *Runner, ring *pcapRing, reason string, maxMB int) *pcapWorker {
	if maxMB <= 0 {
		maxMB = 200
	}
	return &pcapWorker{r: r, ring: ring, reason: reason, maxSize: int64(maxMB) << 20, queue: make(chan model.PcapJob, 16), seen: map[int64]bool{}}
}

func (pw *pcapWorker) enqueue(jobs []model.PcapJob) {
	for _, j := range jobs {
		pw.seenMu.Lock()
		if len(pw.seen) > 10_000 {
			pw.seen = map[int64]bool{}
		}
		dup := pw.seen[j.ID]
		pw.seen[j.ID] = true
		pw.seenMu.Unlock()
		if dup {
			continue
		}
		select {
		case pw.queue <- j:
		default:
			pw.r.log.Warn("troppe estrazioni di pacchetti in coda, richiesta rifiutata", "id", j.ID)
			go pw.r.cl.PcapFail(context.Background(), j.ID, "il sensore ha troppe estrazioni in coda, riprova più tardi")
		}
	}
}

func (pw *pcapWorker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-pw.queue:
			pw.do(ctx, j)
		}
	}
}

func (pw *pcapWorker) do(ctx context.Context, j model.PcapJob) {
	log := pw.r.log.With("estrazione", j.ID)
	if pw.ring == nil {
		pw.r.cl.PcapFail(ctx, j.ID, pw.reason)
		return
	}
	start := time.Now()
	jctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res, err := pw.ring.extract(jctx, j, pw.maxSize)
	if err != nil {
		log.Warn("estrazione di pacchetti non riuscita", "err", err)
		pw.r.cl.PcapFail(ctx, j.ID, "estrazione non riuscita: "+err.Error())
		return
	}
	defer os.Remove(res.path)
	if err := pw.r.cl.PcapUpload(jctx, j.ID, res); err != nil {
		log.Warn("invio dei pacchetti estratti non riuscito", "err", err)
		pw.r.cl.PcapFail(ctx, j.ID, "invio all'hub non riuscito: "+err.Error())
		return
	}
	log.Info("pacchetti estratti e inviati", "pacchetti", res.packets, "byte", res.bytes, "troncato", res.truncated, "durata", time.Since(start).Round(time.Millisecond))
}
