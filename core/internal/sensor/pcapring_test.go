package sensor

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"hyperwave/internal/model"
)

func testFrame(t *testing.T, src, dst string, proto string, sport, dport uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	var l4 gopacket.SerializableLayer
	switch proto {
	case "tcp":
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: true, Window: 1024}
		tcp.SetNetworkLayerForChecksum(ip)
		l4 = tcp
	case "udp":
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
		udp.SetNetworkLayerForChecksum(ip)
		l4 = udp
	default:
		ip.Protocol = layers.IPProtocolICMPv4
		l4 = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, l4, gopacket.Payload("ciao")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ringWrite(r *pcapRing, ts time.Time, data []byte) {
	r.write(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data)
}

// readExtract decomprime il risultato e restituisce i pacchetti, controllando hash e dimensione.
func readExtract(t *testing.T, res *pcapResult) [][]byte {
	t.Helper()
	f, err := os.Open(res.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != res.sha256 || int64(len(plain)) != res.bytes {
		t.Fatalf("hash o dimensione non corrispondono: %d byte, attesi %d", len(plain), res.bytes)
	}
	f2, _ := os.CreateTemp(t.TempDir(), "x*.pcap")
	f2.Write(plain)
	f2.Seek(0, 0)
	rd, err := pcapgo.NewReader(f2)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for {
		data, _, err := rd.ReadPacketData()
		if err != nil {
			break
		}
		out = append(out, data)
	}
	return out
}

func TestPcapRingExtract(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pacchetti")
	r, err := openPcapRing(dir, 256, 2, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("permessi della cartella: %v", st.Mode().Perm())
	}
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	// 3 segmenti: la rotazione scatta ogni 5 minuti di traffico
	for i := 0; i < 600; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		ringWrite(r, ts, testFrame(t, "198.18.0.10", "198.18.5.5", "tcp", 50000, 443))
		ringWrite(r, ts, testFrame(t, "198.18.5.5", "198.18.0.10", "tcp", 443, 50000))
		ringWrite(r, ts, testFrame(t, "198.18.0.11", "198.18.5.5", "udp", 5353, 53))
		ringWrite(r, ts, testFrame(t, "198.18.0.10", "198.18.9.9", "icmp", 0, 0))
	}
	segs, _ := r.segments()
	if len(segs) < 2 {
		t.Fatalf("attesi più segmenti, trovati %d", len(segs))
	}
	from, to, _ := r.window()
	if from != base.UnixMilli() || to != base.Add(599*time.Second).UnixMilli() {
		t.Fatalf("periodo del buffer: %d-%d", from, to)
	}

	ctx := context.Background()
	ms := func(d time.Duration) int64 { return base.Add(d).UnixMilli() }
	cases := []struct {
		name string
		job  model.PcapJob
		want int
	}{
		{"conversazione nei due versi", model.PcapJob{A: "198.18.0.10", B: "198.18.5.5", From: ms(0), To: ms(599 * time.Second)}, 1200},
		{"tutto un host", model.PcapJob{A: "198.18.0.10", From: ms(0), To: ms(599 * time.Second)}, 1800},
		{"porta", model.PcapJob{A: "198.18.5.5", Port: 53, From: ms(0), To: ms(599 * time.Second)}, 600},
		{"protocollo", model.PcapJob{A: "198.18.0.10", Proto: "icmp", From: ms(0), To: ms(599 * time.Second)}, 600},
		{"finestra a cavallo di due segmenti", model.PcapJob{A: "198.18.0.11", From: ms(290 * time.Second), To: ms(309 * time.Second)}, 20},
		{"nessuna corrispondenza", model.PcapJob{A: "198.18.77.77", From: ms(0), To: ms(599 * time.Second)}, 0},
	}
	for _, c := range cases {
		res, err := r.extract(ctx, c.job, 100<<20)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		pkts := readExtract(t, res)
		if len(pkts) != c.want || res.packets != int64(c.want) || res.truncated {
			t.Errorf("%s: %d pacchetti (dichiarati %d, troncato %v), attesi %d", c.name, len(pkts), res.packets, res.truncated, c.want)
		}
		os.Remove(res.path)
	}

	// limite di dimensione: si ferma e lo dichiara
	res, err := r.extract(ctx, model.PcapJob{A: "198.18.0.10", From: ms(0), To: ms(599 * time.Second)}, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if pkts := readExtract(t, res); !res.truncated || len(pkts) == 0 || res.bytes > 10_000 {
		t.Fatalf("troncamento: %d pacchetti, %d byte, troncato %v", len(pkts), res.bytes, res.truncated)
	}

	// richieste non valide
	for _, j := range []model.PcapJob{{A: "non-un-ip", From: 1, To: 2}, {A: "198.18.0.1", Proto: "sctp", From: 1, To: 2}, {A: "198.18.0.1", From: 5, To: 5}} {
		if _, err := r.extract(ctx, j, 1<<20); err == nil {
			t.Errorf("richiesta %+v accettata", j)
		}
	}
	r.close()

	// riapertura: nessun segmento rimasto "open", i dati restano
	r2, err := openPcapRing(dir, 256, 2, 65536)
	if err != nil {
		t.Fatal(err)
	}
	segs, _ = r2.segments()
	for _, s := range segs {
		if s.open {
			t.Fatalf("segmento ancora aperto dopo la riapertura: %s", s.path)
		}
	}
	if f, _, _ := r2.window(); f != base.UnixMilli() {
		t.Fatalf("dati persi alla riapertura")
	}
}

func TestPcapRingPrune(t *testing.T) {
	dir := t.TempDir()
	r, err := openPcapRing(dir, 256, 0.5, 65536) // 30 minuti
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3 * time.Hour)
	for i := 0; i < 400; i++ {
		ringWrite(r, old.Add(time.Duration(i)*time.Second), testFrame(t, "198.18.0.1", "198.18.0.2", "udp", 1, 2))
	}
	now := time.Now()
	ringWrite(r, now, testFrame(t, "198.18.0.1", "198.18.0.2", "udp", 1, 2))
	r.flush()
	r.prune(now)
	from, _, _ := r.window()
	if from < now.Add(-30*time.Minute).UnixMilli() {
		t.Fatalf("i segmenti oltre l'età massima non sono stati cancellati: primo pacchetto %v", time.UnixMilli(from))
	}
}
