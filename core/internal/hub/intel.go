package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"hyperwave/internal/env"
	"hyperwave/internal/model"
	"hyperwave/internal/version"
)

// Elenchi di minaccia: indirizzi IP, reti e domini malevoli presi da elenchi pubblici o
// compilati a mano. L'hub li tiene in memoria e li confronta con ogni lotto in arrivo (flussi,
// DNS, nomi TLS e HTTP); quando un elenco si aggiorna cerca gli indicatori nuovi anche nello
// storico di ClickHouse, così un contatto avvenuto prima della pubblicazione non sfugge.

const (
	intelMaxEntries = 1_000_000 // per elenco
	intelMaxBody    = 128 << 20
	intelRetroIPs   = 50_000
	intelRetroNets  = 2_000
	intelRetroNames = 50_000
)

// intelPresets sono elenchi pubblici e gratuiti, inseriti spenti: li accende un amministratore
// dopo averne letto le condizioni d'uso.
var intelPresets = []struct {
	code, name, url, category, severity, desc string
	hours                                     int
}{
	{"feodo", "Feodo Tracker · server di comando delle botnet", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "c2", "critical",
		"abuse.ch: server di comando e controllo di Dridex, Emotet, QakBot e simili ancora attivi. Pochi falsi positivi.", 1},
	{"urlhaus", "URLhaus · siti che distribuiscono malware", "https://urlhaus.abuse.ch/downloads/hostfile/", "malware", "high",
		"abuse.ch: nomi dei siti usati per distribuire malware, aggiornato di continuo.", 2},
	{"spamhaus_drop4", "Spamhaus DROP · reti criminali (IPv4)", "https://www.spamhaus.org/drop/drop_v4.json", "hijacked", "high",
		"Reti dirottate o gestite da criminali, da non raggiungere mai. Gratuito per uso non commerciale e piccole organizzazioni: verificare le condizioni d'uso.", 12},
	{"spamhaus_drop6", "Spamhaus DROP · reti criminali (IPv6)", "https://www.spamhaus.org/drop/drop_v6.json", "hijacked", "high",
		"Come il precedente, per le reti IPv6.", 12},
	{"et_compromised", "Emerging Threats · host compromessi", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "compromised", "medium",
		"Proofpoint: indirizzi di macchine compromesse che attaccano altre reti.", 12},
	{"cins", "CINS Army · indirizzi con cattiva reputazione", "https://cinsscore.com/list/ci-badguys.txt", "scanner", "low",
		"Sentinel IPS: indirizzi che scansionano e attaccano su internet. Utile soprattutto per le connessioni in entrata.", 12},
	{"blocklist_de", "blocklist.de · attacchi a SSH, posta e siti", "https://lists.blocklist.de/lists/all.txt", "scanner", "low",
		"Indirizzi segnalati negli ultimi giorni per attacchi a SSH, posta, FTP e siti web.", 12},
	{"tor_exit", "Tor Project · nodi di uscita", "https://check.torproject.org/torbulkexitlist", "tor", "low",
		"Nodi da cui esce il traffico della rete Tor: connessioni in entrata anonime.", 6},
}

var intelCategories = map[string]string{"malware": "malware", "c2": "comando e controllo", "phishing": "phishing", "hijacked": "reti criminali",
	"compromised": "host compromessi", "scanner": "scansioni e attacchi", "tor": "Tor", "spam": "spam", "other": "altro"}

// intelProtected sono domini di grandi piattaforme: un elenco scaricato che li contiene (spesso
// perché un utente vi ha caricato un file malevolo) farebbe scattare allarmi per tutto il traffico
// legittimo. Valgono per il dominio e i sottodomini; gli elenchi a mano non hanno questo filtro.
var intelProtected = map[string]bool{}

func init() {
	for _, d := range strings.Fields(`google.com googleapis.com gstatic.com googleusercontent.com googlevideo.com youtube.com gmail.com
		microsoft.com microsoftonline.com windows.net windowsupdate.com office.com office365.com live.com outlook.com sharepoint.com
		onedrive.com azure.com azureedge.net apple.com icloud.com amazon.com amazonaws.com cloudfront.net akamaihd.net akamaized.net
		cloudflare.com github.com githubusercontent.com gitlab.com bitbucket.org dropbox.com dropboxusercontent.com facebook.com
		fbcdn.net whatsapp.net instagram.com linkedin.com twitter.com x.com wikipedia.org mozilla.org zoom.us slack.com
		discord.com discordapp.com telegram.org wordpress.com blogspot.com pastebin.com docker.com docker.io`) {
		intelProtected[d] = true
	}
}

func intelCatalog() []*RuleDef {
	return []*RuleDef{{
		ID: "threat_intel", Name: "Indirizzo o dominio in un elenco di minaccia", Category: "Minacce note", Severity: "high", Mitre: "T1071",
		Description: "Comunicazioni con indirizzi IP, reti o domini presenti negli elenchi di minaccia attivi (pagina Minacce note). " +
			"Il confronto avviene all'arrivo dei dati; quando un elenco si aggiorna, gli indicatori nuovi vengono cercati anche nello storico. " +
			"La gravità è quella dell'elenco, a meno di sceglierne una qui.",
		Params: params{"retro_days": 30, "inbound_established": 1},
		Help: map[string]string{
			"retro_days":          "Giorni di storico in cui cercare gli indicatori nuovi",
			"inbound_established": "Connessioni in entrata: 1 = solo quelle a cui un dispositivo ha risposto, 0 = anche i tentativi",
		},
	}}
}

// ---------------------------------------------------------------- indicatori

var defang = strings.NewReplacer("[.]", ".", "(.)", ".", "{.}", ".", "[:]", ":", "hxxp", "http", "hXXp", "http")

// publicAddr: indirizzo pubblico (né privato, né loopback, né link-local, né CGNAT).
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// parseIndicator riconosce un indicatore: IP, rete CIDR, dominio o URL (se ne prende il nome).
// Con strict (elenchi scaricati) scarta indirizzi privati, reti troppo ampie e grandi piattaforme.
func parseIndicator(tok string, strict bool) (value, typ string, ok bool) {
	tok = strings.TrimSpace(defang.Replace(tok))
	if tok == "" || len(tok) > 2048 {
		return "", "", false
	}
	if i := strings.Index(tok, "://"); i > 0 {
		u, err := url.Parse(tok)
		if err != nil || u.Hostname() == "" {
			return "", "", false
		}
		tok = u.Hostname()
	}
	if a, err := netip.ParseAddr(strings.Trim(tok, "[]")); err == nil {
		a = a.Unmap().WithZone("")
		if strict && !publicAddr(a) {
			return "", "", false
		}
		return a.String(), "ip", true
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		p = p.Masked()
		if a := p.Addr(); a.Is4In6() {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		switch {
		case p.Bits() == p.Addr().BitLen():
			return parseIndicator(p.Addr().String(), strict)
		case p.Addr().Is4() && p.Bits() < 8, p.Addr().Is6() && p.Bits() < 16:
			return "", "", false
		case strict && !publicAddr(p.Addr()):
			return "", "", false
		}
		return p.String(), "cidr", true
	}
	d := strings.TrimSuffix(strings.ToLower(tok), ".")
	d = strings.TrimPrefix(d, "*.")
	if !validDomain(d) {
		return "", "", false
	}
	if strict {
		for s := d; ; {
			if intelProtected[s] {
				return "", "", false
			}
			_, rest, found := strings.Cut(s, ".")
			if !found || !strings.Contains(rest, ".") {
				break
			}
			s = rest
		}
	}
	return d, "domain", true
}

func validDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	_, err := strconv.Atoi(tld)
	return err != nil && len(tld) >= 2
}

func intelSep(r rune) bool {
	switch r {
	case ' ', '\t', ',', ';', '"', '\'', '{', '}', '|', '<', '>':
		return true
	}
	return false
}

var hostsSinks = map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true}

// parseFeed legge un elenco riga per riga: testo semplice, file hosts, CSV o JSON a righe.
// Di ogni riga prende il primo elemento che sia un indicatore valido.
func parseFeed(r io.Reader, strict bool) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '!' || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.Index(line, " #"); i > 0 {
			line = line[:i]
		}
		toks := strings.FieldsFunc(defang.Replace(line), intelSep)
		if len(toks) > 1 && hostsSinks[toks[0]] {
			toks = toks[1:]
		}
		for _, t := range toks {
			t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
			if v, typ, ok := parseIndicator(t, strict); ok {
				out[v] = typ
				break
			}
		}
		if len(out) > intelMaxEntries {
			return nil, fmt.Errorf("l'elenco supera %d indicatori", intelMaxEntries)
		}
	}
	return out, sc.Err()
}

// ---------------------------------------------------------------- confronto

type intelFeed struct {
	id                       int64
	name, category, severity string
}

type intelSet struct {
	feeds   map[int64]*intelFeed
	ips     map[netip.Addr]int64
	nets    map[netip.Prefix]int64
	lens4   []int // lunghezze dei prefissi presenti, dalla più specifica
	lens6   []int
	domains map[string]int64
	size    int
}

func newIntelSet() *intelSet {
	return &intelSet{feeds: map[int64]*intelFeed{}, ips: map[netip.Addr]int64{}, nets: map[netip.Prefix]int64{}, domains: map[string]int64{}}
}

// better: se lo stesso indicatore è in più elenchi vale quello più grave.
func (s *intelSet) better(cur, cand int64) bool {
	a, b := s.feeds[cur], s.feeds[cand]
	return a == nil || b != nil && sevRank[b.severity] > sevRank[a.severity]
}

func (s *intelSet) add(feed int64, value, typ string) {
	switch typ {
	case "ip":
		if a, err := netip.ParseAddr(value); err == nil {
			if cur, ok := s.ips[a]; !ok || s.better(cur, feed) {
				s.ips[a] = feed
			}
		}
	case "cidr":
		if p, err := netip.ParsePrefix(value); err == nil {
			if cur, ok := s.nets[p]; !ok || s.better(cur, feed) {
				s.nets[p] = feed
			}
		}
	case "domain":
		if cur, ok := s.domains[value]; !ok || s.better(cur, feed) {
			s.domains[value] = feed
		}
	}
	s.size++
}

func (s *intelSet) finish() {
	seen4, seen6 := map[int]bool{}, map[int]bool{}
	for p := range s.nets {
		if p.Addr().Is4() {
			seen4[p.Bits()] = true
		} else {
			seen6[p.Bits()] = true
		}
	}
	for b := range seen4 {
		s.lens4 = append(s.lens4, b)
	}
	for b := range seen6 {
		s.lens6 = append(s.lens6, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens4)))
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens6)))
}

func (s *intelSet) matchIP(ip string) (string, int64, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", 0, false
	}
	a = a.Unmap()
	if f, ok := s.ips[a]; ok {
		return a.String(), f, true
	}
	lens := s.lens4
	if a.Is6() {
		lens = s.lens6
	}
	for _, b := range lens {
		p, _ := a.Prefix(b)
		if f, ok := s.nets[p]; ok {
			return p.String(), f, true
		}
	}
	return "", 0, false
}

// matchDomain cerca il nome e i domini che lo contengono (a.b.esempio.it → b.esempio.it → esempio.it).
func (s *intelSet) matchDomain(name string) (string, int64, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if len(s.domains) == 0 || name == "" {
		return "", 0, false
	}
	for d := name; strings.Contains(d, "."); {
		if f, ok := s.domains[d]; ok {
			return d, f, true
		}
		_, d, _ = strings.Cut(d, ".")
	}
	return "", 0, false
}

// ---------------------------------------------------------------- stato

type hitKey struct {
	feed    int64
	ind     string
	local   string
	inbound bool
}

type hitAgg struct {
	feed               intelFeed
	first, last, n     int64
	remote             string
	seen, via          map[string]bool
	ports              map[uint16]bool
	sensor             int64
	retro, established bool
}

type intel struct {
	h        *Hub
	set      atomic.Pointer[intelSet]
	loadedAt atomic.Int64
	client   *http.Client

	mu   sync.Mutex
	hits map[hitKey]*hitAgg

	busy sync.Map // id elenco → in aggiornamento
}

func newIntel(h *Hub) *intel {
	in := &intel{h: h, hits: map[hitKey]*hitAgg{}, client: intelClient(env.Bool("HW_INTEL_ALLOW_PRIVATE", false))}
	in.set.Store(newIntelSet())
	return in
}

// intelClient scarica gli elenchi. Di norma rifiuta le destinazioni interne (loopback, reti
// private, link-local): un indirizzo scritto nella pagina non deve poter raggiungere ClickHouse,
// NATS o altri servizi accanto all'hub. Il controllo avviene alla connessione, quindi vale anche
// dopo i rinvii e qualunque cosa risponda il DNS. HW_INTEL_ALLOW_PRIVATE=1 lo toglie per chi
// pubblica gli elenchi su un server interno o esce verso Internet da un proxy in rete locale.
func intelClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !publicAddr(ip) {
				return fmt.Errorf("destinazione interna %s non ammessa per gli elenchi (HW_INTEL_ALLOW_PRIVATE)", ip)
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialer.DialContext
	return &http.Client{
		Timeout:   3 * time.Minute,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("troppi rinvii")
			}
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return errors.New("rinvio non ammesso")
			}
			return nil
		},
	}
}

// syncPresets inserisce o aggiorna gli elenchi predefiniti senza toccare le scelte degli amministratori.
func (in *intel) syncPresets(ctx context.Context) error {
	for _, p := range intelPresets {
		_, err := in.h.pg.Exec(ctx, `INSERT INTO intel_feeds (name, kind, url, category, severity, description, refresh_hours, preset, created_by)
			VALUES ($1, 'url', $2, $3, $4, $5, $6, $7, 'hyperwave')
			ON CONFLICT (preset) WHERE preset <> '' DO UPDATE SET url = EXCLUDED.url, description = EXCLUDED.description`,
			p.name, p.url, p.category, p.severity, p.desc, p.hours, p.code)
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			continue // un elenco creato a mano ha già quel nome
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// load rilegge dal database gli indicatori degli elenchi attivi.
func (in *intel) load(ctx context.Context) error {
	s := newIntelSet()
	rows, err := in.h.pg.Query(ctx, "SELECT id, name, category, severity FROM intel_feeds WHERE enabled")
	if err != nil {
		return err
	}
	for rows.Next() {
		f := &intelFeed{}
		if err := rows.Scan(&f.id, &f.name, &f.category, &f.severity); err != nil {
			rows.Close()
			return err
		}
		s.feeds[f.id] = f
	}
	rows.Close()
	if len(s.feeds) > 0 {
		rows, err = in.h.pg.Query(ctx, `SELECT i.feed_id, i.value, i.type FROM intel_indicators i JOIN intel_feeds f ON f.id = i.feed_id
			WHERE f.enabled AND (i.expires_at IS NULL OR i.expires_at > now())`)
		if err != nil {
			return err
		}
		var (
			feed       int64
			value, typ string
		)
		for rows.Next() {
			if err := rows.Scan(&feed, &value, &typ); err != nil {
				rows.Close()
				return err
			}
			s.add(feed, value, typ)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	s.finish()
	old := in.set.Swap(s)
	in.loadedAt.Store(time.Now().UnixMilli())
	if old.size != s.size || len(old.feeds) != len(s.feeds) {
		in.h.log.Info("elenchi di minaccia caricati", "elenchi", len(s.feeds), "indicatori", s.size)
	}
	return nil
}

func (in *intel) ruleParams() (params, bool) {
	st, ok := in.h.eng.rule("threat_intel")
	if !ok {
		return params{}, true
	}
	return st.Params, st.Enabled
}

// scan confronta un lotto appena salvato con gli indicatori in memoria.
func (in *intel) scan(s *Sensor, b *model.Batch) {
	set := in.set.Load()
	if set.size == 0 {
		return
	}
	p, enabled := in.ruleParams()
	if !enabled {
		return
	}
	onlyEst := p.num("inbound_established") != 0
	for i := range b.Flows {
		f := &b.Flows[i]
		if ind, feed, ok := set.matchIP(f.DstIP); ok {
			in.hit(set, feed, ind, f.DstIP, f.SrcIP, f.DstIP, "flusso", f.DstPort, false, f.Est, f.TS, s.ID, 1, false)
		} else if ind, feed, ok := set.matchIP(f.SrcIP); ok && (f.Est || !onlyEst) {
			in.hit(set, feed, ind, f.SrcIP, f.DstIP, f.SrcIP, "flusso", f.DstPort, true, f.Est, f.TS, s.ID, 1, false)
		}
	}
	for _, d := range b.DNS {
		if ind, feed, ok := set.matchDomain(d.Query); ok {
			in.hit(set, feed, ind, d.Query, d.Client, "", "DNS", 53, false, true, d.TS, s.ID, 1, false)
		}
	}
	for _, t := range b.TLS {
		if ind, feed, ok := set.matchDomain(t.SNI); ok {
			in.hit(set, feed, ind, t.SNI, t.Client, t.Server, "TLS", t.Port, false, true, t.TS, s.ID, 1, false)
		}
	}
	for _, x := range b.HTTP {
		if ind, feed, ok := set.matchDomain(x.Host); ok {
			in.hit(set, feed, ind, x.Host, x.Client, x.Server, "HTTP", x.Port, false, true, x.TS, s.ID, 1, false)
		}
	}
}

func (in *intel) hit(set *intelSet, feed int64, ind, seen, local, remote, via string, port uint16, inbound, est bool, ts, sensor, n int64, retro bool) {
	f := set.feeds[feed]
	if f == nil {
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	k := hitKey{feed, ind, local, inbound}
	a := in.hits[k]
	if a == nil {
		if len(in.hits) > 50_000 {
			return
		}
		a = &hitAgg{feed: *f, first: ts, last: ts, remote: remote, seen: map[string]bool{}, via: map[string]bool{}, ports: map[uint16]bool{}, sensor: sensor}
		in.hits[k] = a
	}
	a.first, a.last, a.n = min(a.first, ts), max(a.last, ts), a.n+n
	a.retro = a.retro || retro
	a.established = a.established || est
	if a.remote == "" {
		a.remote = remote
	}
	if len(a.seen) < 5 {
		a.seen[seen] = true
	}
	a.via[via] = true
	if len(a.ports) < 5 && port != 0 {
		a.ports[port] = true
	}
}

func keys[K comparable](m map[K]bool) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// flushHits apre o aggiorna gli allarmi per le corrispondenze accumulate.
func (in *intel) flushHits(ctx context.Context) error {
	in.mu.Lock()
	hits := in.hits
	in.hits = map[hitKey]*hitAgg{}
	in.mu.Unlock()
	var firstErr error
	for k, a := range hits {
		if _, err := in.h.raise(ctx, in.alert(k, a)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (in *intel) when(ms int64) string {
	t := time.UnixMilli(ms).In(in.h.state.Location())
	if time.Since(t) > 20*time.Hour {
		return t.Format("02/01 15:04")
	}
	return t.Format("15:04")
}

func (in *intel) alert(k hitKey, a *hitAgg) Alert {
	who := label(k.local, in.h.enr.device(k.local).name)
	seen := keys(a.seen)
	slices.Sort(seen)
	via := keys(a.via)
	slices.Sort(via)
	ports := keys(a.ports)
	slices.Sort(ports)
	target := k.ind
	if len(seen) == 1 && seen[0] != k.ind {
		target = seen[0] + " (" + k.ind + ")"
	}
	cat := firstNonEmpty(intelCategories[a.feed.category], a.feed.category)
	al := Alert{
		Rule: "threat_intel", Severity: a.feed.severity, DedupKey: "threat_intel|" + k.ind + "|" + k.local,
		DeviceID: in.h.enr.device(k.local).id, SensorID: a.sensor, TS: time.UnixMilli(a.first),
		Detail: map[string]any{"indicator": k.ind, "seen": seen, "feed": a.feed.name, "feed_id": a.feed.id, "category": a.feed.category,
			"via": via, "ports": ports, "count": a.n, "inbound": k.inbound, "established": a.established, "retro": a.retro},
	}
	var sum string
	if k.inbound {
		al.Src, al.Dst = a.remote, k.local
		al.Title = fmt.Sprintf("Connessione da %s verso %s (elenco «%s»)", target, who, a.feed.name)
		sum = fmt.Sprintf("%s, presente nell'elenco «%s» (%s), si è collegato %d volte a %s", target, a.feed.name, cat, a.n, who)
		if a.established {
			sum += ", che ha risposto"
		}
	} else {
		al.Src, al.Dst = k.local, a.remote
		al.Title = fmt.Sprintf("%s ha contattato %s (elenco «%s»)", who, target, a.feed.name)
		sum = fmt.Sprintf("%s ha contattato %d volte %s, presente nell'elenco «%s» (%s)", who, a.n, target, a.feed.name, cat)
	}
	if a.first == a.last {
		sum += " alle " + in.when(a.first)
	} else {
		sum += " tra le " + in.when(a.first) + " e le " + in.when(a.last)
	}
	sum += ", visto in " + strings.Join(via, ", ")
	if len(ports) > 0 {
		ps := make([]string, len(ports))
		for i, p := range ports {
			ps[i] = strconv.Itoa(int(p))
		}
		sum += " (porte " + strings.Join(ps, ", ") + ")"
	}
	sum += "."
	if a.retro {
		sum = "Trovato nello storico dopo l'aggiornamento dell'elenco: " + sum
	}
	al.Summary = sum
	return al
}

// ---------------------------------------------------------------- aggiornamento degli elenchi

// tick aggiorna gli elenchi scaduti e rilegge gli indicatori ogni 15 minuti (scadenze, modifiche a mano).
func (in *intel) tick(ctx context.Context) error {
	rows, err := in.h.pg.Query(ctx, `SELECT id FROM intel_feeds WHERE kind = 'url' AND enabled
		AND (last_fetch IS NULL OR last_fetch < now() - make_interval(hours => refresh_hours)) ORDER BY last_fetch NULLS FIRST LIMIT 20`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return nil
		}
		if err := in.fetch(ctx, id); err != nil {
			in.h.log.Warn("aggiornamento elenco di minaccia", "id", id, "err", err)
		}
	}
	if len(ids) == 0 && time.Since(time.UnixMilli(in.loadedAt.Load())) > 15*time.Minute {
		return in.load(ctx)
	}
	return nil
}

// fetch scarica un elenco, ne sostituisce gli indicatori e cerca quelli nuovi nello storico.
func (in *intel) fetch(ctx context.Context, id int64) error {
	if _, running := in.busy.LoadOrStore(id, true); running {
		return nil
	}
	defer in.busy.Delete(id)
	var (
		name, rawURL, etag string
		enabled, hadOK     bool
	)
	err := in.h.pg.QueryRow(ctx, "SELECT name, url, etag, enabled, last_ok IS NOT NULL FROM intel_feeds WHERE id = $1 AND kind = 'url'", id).
		Scan(&name, &rawURL, &etag, &enabled, &hadOK)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		in.h.pg.Exec(ctx, "UPDATE intel_feeds SET last_fetch = now(), last_error = $2 WHERE id = $1", id, clip(err.Error(), 500))
		return err
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fail(errors.New("indirizzo non valido: serve http:// o https://"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("User-Agent", "Hyperwave/"+version.Version+" (elenchi di minaccia)")
	if etag != "" && hadOK {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := in.client.Do(req)
	if err != nil {
		return fail(fmt.Errorf("scaricamento non riuscito: %w", err))
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		_, err := in.h.pg.Exec(ctx, "UPDATE intel_feeds SET last_fetch = now(), last_ok = now(), last_error = '' WHERE id = $1", id)
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("il server ha risposto %s", res.Status))
	}
	lr := &io.LimitedReader{R: res.Body, N: intelMaxBody + 1}
	inds, err := parseFeed(lr, true)
	if err != nil {
		return fail(err)
	}
	if lr.N <= 0 {
		return fail(fmt.Errorf("file più grande di %d MB", intelMaxBody>>20))
	}
	if len(inds) == 0 {
		return fail(errors.New("nessun indirizzo o dominio riconosciuto nel file"))
	}
	added, err := in.replace(ctx, id, inds, res.Header.Get("ETag"))
	if err != nil {
		return fail(err)
	}
	in.h.log.Info("elenco di minaccia aggiornato", "elenco", name, "indicatori", len(inds), "nuovi", len(added))
	if err := in.load(ctx); err != nil {
		return err
	}
	if enabled && len(added) > 0 {
		go in.retro(context.WithoutCancel(ctx), id, added)
	}
	return nil
}

// replace sostituisce gli indicatori di un elenco e restituisce quelli nuovi.
func (in *intel) replace(ctx context.Context, id int64, inds map[string]string, etag string) (map[string]string, error) {
	tx, err := in.h.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE intel_new (value text PRIMARY KEY, type text NOT NULL) ON COMMIT DROP"); err != nil {
		return nil, err
	}
	rows := make([][]any, 0, len(inds))
	for v, t := range inds {
		rows = append(rows, []any{v, t})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"intel_new"}, []string{"value", "type"}, pgx.CopyFromRows(rows)); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM intel_indicators i WHERE i.feed_id = $1
		AND NOT EXISTS (SELECT 1 FROM intel_new n WHERE n.value = i.value)`, id); err != nil {
		return nil, err
	}
	res, err := tx.Query(ctx, `INSERT INTO intel_indicators (feed_id, value, type) SELECT $1, value, type FROM intel_new
		ON CONFLICT (feed_id, value) DO NOTHING RETURNING value, type`, id)
	if err != nil {
		return nil, err
	}
	added := map[string]string{}
	for res.Next() {
		var v, t string
		if err := res.Scan(&v, &t); err != nil {
			res.Close()
			return nil, err
		}
		added[v] = t
	}
	res.Close()
	if err := res.Err(); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE intel_feeds SET entries = $2, etag = $3, last_fetch = now(), last_ok = now(), last_error = '' WHERE id = $1`,
		id, len(inds), clip(etag, 200)); err != nil {
		return nil, err
	}
	return added, tx.Commit(ctx)
}

// retroFeed cerca nello storico tutti gli indicatori di un elenco (richiesta dalla pagina).
func (in *intel) retroFeed(ctx context.Context, id int64) {
	rows, err := in.h.pg.Query(ctx, `SELECT value, type FROM intel_indicators WHERE feed_id = $1 AND (expires_at IS NULL OR expires_at > now())`, id)
	if err != nil {
		in.h.log.Warn("ricerca nello storico", "err", err)
		return
	}
	inds := map[string]string{}
	for rows.Next() {
		var v, t string
		if rows.Scan(&v, &t) == nil {
			inds[v] = t
		}
	}
	rows.Close()
	in.retro(ctx, id, inds)
}

// retro cerca gli indicatori in flussi, DNS, TLS e HTTP degli ultimi giorni.
func (in *intel) retro(ctx context.Context, id int64, inds map[string]string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if _, running := in.busy.LoadOrStore(-id, true); running {
		return
	}
	defer in.busy.Delete(-id)
	set := in.set.Load()
	if set.feeds[id] == nil {
		return // elenco spento
	}
	p, enabled := in.ruleParams()
	if !enabled {
		return
	}
	days := int(min(max(p.num("retro_days"), 1), float64(in.h.cfg.RetentionDays)))
	onlyEst := p.num("inbound_established") != 0
	var ips, cidrs, names []string
	for v, t := range inds {
		switch t {
		case "ip":
			ips = append(ips, v)
		case "cidr":
			cidrs = append(cidrs, v)
		case "domain":
			names = append(names, v)
		}
	}
	truncated := len(ips) > intelRetroIPs || len(cidrs) > intelRetroNets || len(names) > intelRetroNames
	ips, cidrs, names = ips[:min(len(ips), intelRetroIPs)], cidrs[:min(len(cidrs), intelRetroNets)], names[:min(len(names), intelRetroNames)]
	start := time.Now()
	found, err := in.retroSearch(ctx, set, id, days, onlyEst, ips, cidrs, names)
	if err != nil {
		in.h.log.Warn("ricerca nello storico non riuscita", "elenco", set.feeds[id].name, "err", err)
		return
	}
	if err := in.flushHits(ctx); err != nil {
		in.h.log.Warn("allarmi dalla ricerca nello storico", "err", err)
	}
	in.h.pg.Exec(ctx, "UPDATE intel_feeds SET retro_at = now(), retro_hits = $2 WHERE id = $1", id, found)
	in.h.log.Info("ricerca nello storico completata", "elenco", set.feeds[id].name, "giorni", days, "indicatori", len(ips)+len(cidrs)+len(names),
		"troncata", truncated, "corrispondenze", found, "durata", time.Since(start).Round(time.Millisecond))
}

func chunks(v []string, n int) [][]string {
	var out [][]string
	for len(v) > 0 {
		k := min(n, len(v))
		out = append(out, v[:k])
		v = v[k:]
	}
	return out
}

type retroRow struct {
	Ind, Seen, Local, Remote, Via, First, Last string
	N                                          uint64
	Out, Est                                   uint8
	Port                                       uint16
}

func (in *intel) retroSearch(ctx context.Context, set *intelSet, id int64, days int, onlyEst bool, ips, cidrs, names []string) (int, error) {
	since := map[string]string{"d": strconv.Itoa(days)}
	with := func(k, v string) map[string]string {
		m := map[string]string{"d": since["d"], k: v}
		return m
	}
	var rows []retroRow
	run := func(sql string, p map[string]string) error {
		r, err := q[retroRow](ctx, in.h.eng, sql, p)
		rows = append(rows, r...)
		return err
	}
	const flowCols = `count() AS N, toString(min(ts)) AS First, toString(max(ts)) AS Last, max(est) AS Est, any(dport) AS Port`
	for _, c := range chunks(ips, 2000) {
		err := run(`SELECT dst IN {l:Array(String)} AS Out, if(Out, dst, src) AS Ind, Ind AS Seen, if(Out, src, dst) AS Local,
				Ind AS Remote, 'flusso' AS Via, `+flowCols+`
			FROM flows WHERE ts >= now() - INTERVAL {d:UInt32} DAY AND demo = 0 AND (dst IN {l:Array(String)} OR src IN {l:Array(String)})
			GROUP BY Out, Ind, Local LIMIT 5000`, with("l", chStrings(c)))
		if err != nil {
			return 0, err
		}
	}
	for _, c := range chunks(cidrs, 250) {
		err := run(`SELECT Out, arrayFirst(n -> isIPAddressInRange(if(Out, dst, src), n), {l:Array(String)}) AS Ind,
				if(Out, dst, src) AS Seen, if(Out, src, dst) AS Local, Seen AS Remote, 'flusso' AS Via, `+flowCols+`
			FROM (SELECT *, arrayExists(n -> isIPAddressInRange(dst, n), {l:Array(String)}) AS Out FROM flows
			      WHERE ts >= now() - INTERVAL {d:UInt32} DAY AND demo = 0
			        AND (Out OR arrayExists(n -> isIPAddressInRange(src, n), {l:Array(String)})))
			GROUP BY Out, Ind, Seen, Local LIMIT 5000`, with("l", chStrings(c)))
		if err != nil {
			return 0, err
		}
	}
	for _, c := range chunks(names, 2000) {
		for _, src := range []struct{ via, table, col, remote, port string }{
			{"DNS", "dns", "query", "''", "53"}, {"TLS", "tls", "sni", "server", "port"}, {"HTTP", "http", "host", "server", "port"},
		} {
			err := run(`SELECT 1 AS Out, Ind, name AS Seen, client AS Local, any(`+src.remote+`) AS Remote, '`+src.via+`' AS Via,
					count() AS N, toString(min(ts)) AS First, toString(max(ts)) AS Last, 1 AS Est, any(toUInt16(`+src.port+`)) AS Port
				FROM (SELECT ts, client, `+src.remote+`, `+src.port+`, `+src.col+` AS name, splitByChar('.', name) AS parts,
				             arrayFirst(s -> s IN {l:Array(String)}, arrayMap(i -> arrayStringConcat(arraySlice(parts, i), '.'), arrayEnumerate(parts))) AS Ind
				      FROM `+src.table+` WHERE ts >= now() - INTERVAL {d:UInt32} DAY AND demo = 0 AND name != '')
				WHERE Ind != '' GROUP BY Ind, Seen, Local LIMIT 5000`, with("l", chStrings(c)))
			if err != nil {
				return 0, err
			}
		}
	}
	for _, r := range rows {
		inbound := r.Out == 0
		if inbound && onlyEst && r.Est == 0 {
			continue
		}
		in.hit(set, id, r.Ind, r.Seen, r.Local, r.Remote, r.Via, r.Port, inbound, r.Est != 0, parseCH(r.First).UnixMilli(), 0, int64(r.N), true)
		in.hit(set, id, r.Ind, r.Seen, r.Local, r.Remote, r.Via, 0, inbound, r.Est != 0, parseCH(r.Last).UnixMilli(), 0, 0, true)
	}
	return len(rows), nil
}

// control esegue un comando arrivato dalla pagina: {"fetch": id} o {"retro": id}.
func (in *intel) control(ctx context.Context, data []byte) {
	var cmd struct{ Fetch, Retro int64 }
	_ = json.Unmarshal(data, &cmd)
	if err := in.load(ctx); err != nil {
		in.h.log.Warn("rilettura elenchi di minaccia", "err", err)
	}
	bg := context.WithoutCancel(ctx)
	if cmd.Fetch > 0 {
		go func() {
			fctx, cancel := context.WithTimeout(bg, 10*time.Minute)
			defer cancel()
			if err := in.fetch(fctx, cmd.Fetch); err != nil {
				in.h.log.Warn("aggiornamento elenco di minaccia", "id", cmd.Fetch, "err", err)
			}
		}()
	}
	if cmd.Retro > 0 {
		go func() {
			rctx, cancel := context.WithTimeout(bg, 30*time.Minute)
			defer cancel()
			in.retroFeed(rctx, cmd.Retro)
		}()
	}
}
