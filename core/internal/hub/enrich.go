package hub

import (
	"context"
	"encoding/csv"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/maxminddb-golang"

	"hyperwave/internal/chx"
	"hyperwave/internal/classify"
	"hyperwave/internal/model"
	"hyperwave/internal/netx"
)

// Enricher aggiunge ai flussi direzione, paese, ASN, dominio, applicazione e nomi dei dispositivi.
type Enricher struct {
	log  *slog.Logger
	city *maxminddb.Reader
	asn  *maxminddb.Reader
	oui  map[string]string // prefisso esadecimale maiuscolo (6, 7 o 9 cifre) → produttore

	mu      sync.RWMutex
	domains map[string]domainEntry // IP → dominio visto in DNS, SNI o Host
	names   map[string]ipInfo      // IP → dispositivo dell'inventario
}

type domainEntry struct {
	name    string
	expires int64
}

type ipInfo struct {
	id   int64
	name string
}

const domainTTL = 2 * time.Hour

func newEnricher(cfg Config, log *slog.Logger) *Enricher {
	e := &Enricher{log: log, domains: map[string]domainEntry{}, names: map[string]ipInfo{}}
	open := func(path, what string) *maxminddb.Reader {
		if path == "" {
			return nil
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			log.Warn("database GeoIP non disponibile: si continua senza", "tipo", what, "file", path, "err", err)
			return nil
		}
		return r
	}
	e.city = open(cfg.GeoIPCity, "paesi")
	e.asn = open(cfg.GeoIPASN, "ASN")
	e.oui = loadOUI(cfg.OUIPath, log)
	return e
}

func (e *Enricher) close() {
	if e.city != nil {
		e.city.Close()
	}
	if e.asn != nil {
		e.asn.Close()
	}
}

// loadOUI legge il registro IEEE (pacchetto ieee-data): MA-L, MA-M e MA-S.
func loadOUI(path string, log *slog.Logger) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		log.Warn("registro OUI non disponibile: i produttori non verranno riconosciuti", "file", path)
		return out
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 || rec[0] == "Registry" {
			continue
		}
		out[strings.ToUpper(rec[1])] = strings.TrimSpace(rec[2])
	}
	return out
}

// Vendor restituisce il produttore della scheda di rete.
func (e *Enricher) Vendor(mac string) string {
	hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(hex) != 12 {
		return ""
	}
	// bit "amministrato localmente": indirizzi casuali di telefoni e PC per la privacy
	if b := hex[1]; b == '2' || b == '6' || b == 'A' || b == 'E' {
		return "MAC casuale (privacy)"
	}
	for _, n := range []int{9, 7, 6} {
		if v, ok := e.oui[hex[:n]]; ok {
			return v
		}
	}
	return ""
}

// learn associa un indirizzo al nome con cui è stato chiamato.
func (e *Enricher) learn(ip, name string, now int64) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if ip == "" || name == "" || len(name) > 253 {
		return
	}
	e.mu.Lock()
	if len(e.domains) > 300_000 {
		for k, v := range e.domains {
			if v.expires < now {
				delete(e.domains, k)
			}
		}
		if len(e.domains) > 300_000 {
			e.domains = map[string]domainEntry{}
		}
	}
	e.domains[ip] = domainEntry{name, now + domainTTL.Milliseconds()}
	e.mu.Unlock()
}

func (e *Enricher) learnBatch(b *model.Batch) {
	now := time.Now().UnixMilli()
	for _, d := range b.DNS {
		if d.RCode != "NOERROR" && d.RCode != "" {
			continue
		}
		for _, a := range d.Answers {
			if _, err := netip.ParseAddr(a); err == nil {
				e.learn(a, d.Query, now)
			}
		}
	}
	for _, t := range b.TLS {
		e.learn(t.Server, t.SNI, now)
	}
	for _, h := range b.HTTP {
		host, _, err := net.SplitHostPort(h.Host)
		if err != nil {
			host = h.Host
		}
		if _, err := netip.ParseAddr(host); err != nil {
			e.learn(h.Server, host, now)
		}
	}
}

func (e *Enricher) domain(ip string) string {
	e.mu.RLock()
	d, ok := e.domains[ip]
	e.mu.RUnlock()
	if ok && d.expires > time.Now().UnixMilli() {
		return d.name
	}
	return ""
}

func (e *Enricher) device(ip string) ipInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.names[ip]
}

// refreshNames rilegge dall'inventario i nomi dei dispositivi (nome dato dalle persone, poi hostname).
func (e *Enricher) refreshNames(ctx context.Context, pg *pgxpool.Pool) error {
	rows, err := pg.Query(ctx, `SELECT id, ip, COALESCE(NULLIF(name, ''), NULLIF(hostname, ''), '')
		FROM devices WHERE ip <> '' AND last_seen > now() - interval '30 days' ORDER BY last_seen`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]ipInfo{}
	for rows.Next() {
		var ip string
		var info ipInfo
		if err := rows.Scan(&info.id, &ip, &info.name); err != nil {
			return err
		}
		m[ip] = info // l'ordine per last_seen fa vincere il dispositivo più recente
	}
	if err := rows.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	e.names = m
	e.mu.Unlock()
	return nil
}

func (e *Enricher) setName(ip string, info ipInfo) {
	e.mu.Lock()
	e.names[ip] = info
	e.mu.Unlock()
}

type geoCity struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type geoASN struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

func (e *Enricher) geo(ip string) (cc string, asn uint32, org string) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return
	}
	if e.city != nil {
		var r geoCity
		if e.city.Lookup(addr, &r) == nil {
			cc = r.Country.ISOCode
		}
	}
	if e.asn != nil {
		var r geoASN
		if e.asn.Lookup(addr, &r) == nil {
			asn, org = r.Number, r.Org
		}
	}
	return
}

// FlowRow è una riga della tabella flows di ClickHouse.
type FlowRow struct {
	TS        string  `json:"ts"`
	TSEnd     string  `json:"ts_end"`
	SensorID  int64   `json:"sensor_id"`
	Site      string  `json:"site"`
	VLAN      uint16  `json:"vlan"`
	Proto     string  `json:"proto"`
	Src       string  `json:"src"`
	SPort     uint16  `json:"sport"`
	Dst       string  `json:"dst"`
	DPort     uint16  `json:"dport"`
	Direction string  `json:"direction"`
	App       string  `json:"app"`
	Domain    string  `json:"domain"`
	BytesOut  uint64  `json:"bytes_out"`
	BytesIn   uint64  `json:"bytes_in"`
	PktsOut   uint32  `json:"pkts_out"`
	PktsIn    uint32  `json:"pkts_in"`
	Flags     string  `json:"flags"`
	Est       uint8   `json:"est"`
	RTT       float32 `json:"rtt"`
	Retrans   uint32  `json:"retrans"`
	Country   string  `json:"country"`
	ASN       uint32  `json:"asn"`
	ASOrg     string  `json:"as_org"`
	SrcName   string  `json:"src_name"`
	DstName   string  `json:"dst_name"`
	Demo      uint8   `json:"demo"`
}

func (e *Enricher) flow(f *model.Flow, s *Sensor, nets netx.Nets, demo bool) FlowRow {
	dir := nets.Direction(f.SrcIP, f.DstIP)
	r := FlowRow{
		TS: chx.Time(f.TS), TSEnd: chx.Time(max(f.End, f.TS)), SensorID: s.ID, Site: s.Site, VLAN: f.VLAN,
		Proto: f.Proto, Src: f.SrcIP, SPort: f.SrcPort, Dst: f.DstIP, DPort: f.DstPort, Direction: dir,
		BytesOut: f.BytesOut, BytesIn: f.BytesIn, PktsOut: f.PktsOut, PktsIn: f.PktsIn, Flags: f.Flags,
		RTT: f.RTT, Retrans: f.Retrans, Country: f.Country, ASN: f.ASN, ASOrg: f.ASOrg,
		Domain: f.Domain, App: f.App,
	}
	if f.Est {
		r.Est = 1
	}
	if demo {
		r.Demo = 1
	}
	// estremo esterno: quello da geolocalizzare e di cui cercare il dominio
	ext := ""
	switch dir {
	case "outbound":
		ext = f.DstIP
	case "inbound":
		ext = f.SrcIP
	}
	if r.Domain == "" {
		if dir == "inbound" {
			r.Domain = e.domain(f.SrcIP)
		} else {
			r.Domain = e.domain(f.DstIP)
		}
	}
	if ext != "" && r.Country == "" && r.ASN == 0 {
		r.Country, r.ASN, r.ASOrg = e.geo(ext)
	}
	if r.App == "" {
		r.App = classify.ByPort(f.Proto, f.DstPort)
	}
	r.App = classify.Refine(r.App, r.Domain)
	r.SrcName = e.device(f.SrcIP).name
	r.DstName = e.device(f.DstIP).name
	return r
}
