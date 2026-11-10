package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"hyperwave/internal/netx"
)

// Regole personalizzate: gli amministratori le compongono nella pagina Regole scegliendo una
// sorgente (flussi, DNS, TLS, HTTP, sessioni, eventi IDS), condizioni sui campi, un
// raggruppamento e una soglia. L'hub le traduce in una SELECT di ClickHouse con nomi di colonna
// presi solo da questo catalogo e valori passati come parametri: nessun testo scritto nella
// pagina finisce dentro la query. Girano nel motore come le altre regole, con ID "custom:<n>".

type customField struct {
	ID, Label string
	Col       string // espressione SQL della colonna
	Kind      string // str, ip, num
	Role      string // src o dst: diventa origine o destinazione dell'allarme
	Unit      string // bytes: i valori si mostrano come dimensioni
}

type customSource struct {
	ID, Label, Table string
	Fields           []customField
}

func ipF(id, label, col, role string) customField {
	return customField{ID: id, Label: label, Col: col, Kind: "ip", Role: role}
}
func strF(id, label, col string) customField {
	return customField{ID: id, Label: label, Col: col, Kind: "str"}
}
func numF(id, label, col string) customField {
	return customField{ID: id, Label: label, Col: col, Kind: "num"}
}

var customSources = []customSource{
	{ID: "flows", Label: "Flussi", Table: "flows", Fields: []customField{
		ipF("src", "Origine", "src", "src"),
		ipF("dst", "Destinazione", "dst", "dst"),
		numF("dport", "Porta di destinazione", "dport"),
		numF("sport", "Porta di origine", "sport"),
		strF("proto", "Protocollo (TCP, UDP, ICMP…)", "proto"),
		strF("direction", "Direzione (internal, outbound, inbound)", "direction"),
		strF("app", "Applicazione", "app"),
		strF("domain", "Dominio", "domain"),
		strF("country", "Paese (codice ISO)", "country"),
		numF("asn", "Numero AS", "asn"),
		strF("as_org", "Operatore", "as_org"),
		{ID: "bytes_out", Label: "Byte inviati", Col: "bytes_out", Kind: "num", Unit: "bytes"},
		{ID: "bytes_in", Label: "Byte ricevuti", Col: "bytes_in", Kind: "num", Unit: "bytes"},
		{ID: "bytes", Label: "Byte totali", Col: "(bytes_out + bytes_in)", Kind: "num", Unit: "bytes"},
		numF("pkts", "Pacchetti", "(pkts_out + pkts_in)"),
		numF("est", "Connessione riuscita (1 sì, 0 no)", "est"),
		numF("duration", "Durata in secondi", "(dateDiff('millisecond', ts, ts_end) / 1000)"),
		numF("vlan", "VLAN", "vlan"),
		strF("src_name", "Nome dell'origine", "src_name"),
		strF("dst_name", "Nome della destinazione", "dst_name"),
	}},
	{ID: "dns", Label: "Domande DNS", Table: "dns", Fields: []customField{
		ipF("client", "Client", "client", "src"),
		ipF("server", "Server DNS", "server", "dst"),
		strF("query", "Nome richiesto", "query"),
		numF("query_len", "Lunghezza del nome", "length(query)"),
		strF("qtype", "Tipo (A, AAAA, TXT…)", "qtype"),
		strF("rcode", "Esito (NOERROR, NXDOMAIN…)", "rcode"),
	}},
	{ID: "tls", Label: "Connessioni TLS e QUIC", Table: "tls", Fields: []customField{
		ipF("client", "Client", "client", "src"),
		ipF("server", "Server", "server", "dst"),
		numF("port", "Porta", "port"),
		strF("sni", "Nome del server (SNI)", "sni"),
		strF("version", "Versione", "version"),
		strF("alpn", "ALPN", "alpn"),
		strF("ja4", "Impronta JA4", "ja4"),
		strF("cert_subject", "Soggetto del certificato", "cert_subject"),
		strF("cert_issuer", "Emittente del certificato", "cert_issuer"),
		numF("self_signed", "Autofirmato (1 sì, 0 no)", "self_signed"),
		strF("transport", "Trasporto (tcp, quic)", "transport"),
	}},
	{ID: "http", Label: "Richieste HTTP", Table: "http", Fields: []customField{
		ipF("client", "Client", "client", "src"),
		ipF("server", "Server", "server", "dst"),
		numF("port", "Porta", "port"),
		strF("method", "Metodo", "method"),
		strF("host", "Host", "host"),
		strF("uri", "Percorso", "uri"),
		numF("status", "Codice di risposta", "status"),
		strF("user_agent", "User agent", "user_agent"),
	}},
	{ID: "sessions", Label: "Sessioni (SSH, RDP, SMB, Kerberos, NTLM)", Table: "sessions", Fields: []customField{
		ipF("client", "Client", "client", "src"),
		ipF("server", "Server", "server", "dst"),
		numF("port", "Porta", "port"),
		strF("protocol", "Protocollo", "protocol"),
		strF("auth", "Autenticazione", "auth"),
		strF("user", "Utente", "user"),
		strF("domain", "Dominio", "domain"),
		strF("host", "Nome host", "host"),
		strF("client_sw", "Software del client", "client_sw"),
		strF("server_sw", "Software del server", "server_sw"),
		strF("weak", "Debolezza rilevata", "weak"),
	}},
	{ID: "events", Label: "Eventi IDS", Table: "events", Fields: []customField{
		ipF("src", "Origine", "src", "src"),
		ipF("dst", "Destinazione", "dst", "dst"),
		numF("dport", "Porta di destinazione", "dport"),
		strF("signature", "Firma", "signature"),
		strF("category", "Categoria", "category"),
		strF("severity", "Gravità", "severity"),
		strF("title", "Titolo", "title"),
	}},
}

// Operatori per tipo di campo, con l'etichetta mostrata nella pagina. "list" = più valori.
type customOp struct {
	ID, Label string
	Values    string // "", "one", "list"
}

var customOps = map[string][]customOp{
	"str": {
		{"eq", "è uguale a", "one"}, {"ne", "è diverso da", "one"}, {"in", "è uno di", "list"}, {"not_in", "non è nessuno di", "list"},
		{"contains", "contiene", "one"}, {"not_contains", "non contiene", "one"}, {"prefix", "inizia con", "one"},
		{"suffix", "finisce con", "one"}, {"regex", "corrisponde all'espressione", "one"}, {"empty", "è vuoto", ""}, {"not_empty", "non è vuoto", ""},
	},
	"ip": {
		{"eq", "è", "one"}, {"ne", "non è", "one"}, {"in_net", "è in una di queste reti", "list"}, {"not_in_net", "non è in nessuna di queste reti", "list"},
		{"internal", "è interno", ""}, {"external", "è esterno", ""},
	},
	"num": {
		{"eq", "=", "one"}, {"ne", "≠", "one"}, {"gt", ">", "one"}, {"ge", "≥", "one"}, {"lt", "<", "one"}, {"le", "≤", "one"},
		{"in", "è uno di", "list"}, {"not_in", "non è nessuno di", "list"},
	},
}

type customCond struct {
	Field string   `json:"field"`
	Op    string   `json:"op"`
	Value []string `json:"value"`
}

type customSpec struct {
	Source      string       `json:"source"`
	Where       []customCond `json:"where"`
	GroupBy     []string     `json:"group_by"`
	Metric      string       `json:"metric"` // count, uniq, sum
	MetricField string       `json:"metric_field"`
	Threshold   float64      `json:"threshold"`
	WindowMin   int          `json:"window_min"`
	EveryMin    int          `json:"every_min"`
}

const (
	customMaxConds  = 12
	customMaxGroups = 3
	customMaxValues = 200
	customMaxValue  = 512
)

func findSource(id string) *customSource {
	for i := range customSources {
		if customSources[i].ID == id {
			return &customSources[i]
		}
	}
	return nil
}

func (s *customSource) field(id string) *customField {
	for i := range s.Fields {
		if s.Fields[i].ID == id {
			return &s.Fields[i]
		}
	}
	return nil
}

func findOp(kind, id string) *customOp {
	for i, o := range customOps[kind] {
		if o.ID == id {
			return &customOps[kind][i]
		}
	}
	return nil
}

// compiled è la regola tradotta: frammenti SQL con segnaposto e i valori dei parametri.
type compiled struct {
	spec    customSpec
	src     *customSource
	where   string
	groups  []*customField
	metric  string
	params  map[string]string
	window  time.Duration
	every   int
	metricF *customField
}

// chIPSafe rende un indirizzo accettabile per isIPAddressInRange, che con stringhe vuote o non
// valide interrompe la query: al loro posto un indirizzo che non sta in nessuna rete ammessa.
func chIPSafe(col string) string {
	return fmt.Sprintf("if(isIPv4String(%[1]s) OR isIPv6String(%[1]s), %[1]s, '::')", col)
}

func compileCustom(spec customSpec, internal netx.Nets) (*compiled, error) {
	src := findSource(spec.Source)
	if src == nil {
		return nil, errors.New("sorgente sconosciuta")
	}
	c := &compiled{spec: spec, src: src, params: map[string]string{}}
	if len(spec.Where) > customMaxConds {
		return nil, fmt.Errorf("al massimo %d condizioni", customMaxConds)
	}
	var parts []string
	for i, cond := range spec.Where {
		f := src.field(cond.Field)
		if f == nil {
			return nil, fmt.Errorf("condizione %d: campo sconosciuto", i+1)
		}
		op := findOp(f.Kind, cond.Op)
		if op == nil {
			return nil, fmt.Errorf("condizione %d (%s): operatore non valido", i+1, f.Label)
		}
		vals := make([]string, 0, len(cond.Value))
		for _, v := range cond.Value {
			if v = strings.TrimSpace(v); v != "" {
				if len(v) > customMaxValue {
					return nil, fmt.Errorf("condizione %d (%s): valore troppo lungo", i+1, f.Label)
				}
				vals = append(vals, v)
			}
		}
		switch {
		case op.Values == "one" && len(vals) != 1:
			return nil, fmt.Errorf("condizione %d (%s): serve un valore", i+1, f.Label)
		case op.Values == "list" && (len(vals) == 0 || len(vals) > customMaxValues):
			return nil, fmt.Errorf("condizione %d (%s): da 1 a %d valori", i+1, f.Label, customMaxValues)
		case op.Values == "" && len(vals) > 0:
			vals = nil
		}
		p := "c" + strconv.Itoa(i)
		sql, err := condSQL(f, op.ID, vals, p, c.params, internal)
		if err != nil {
			return nil, fmt.Errorf("condizione %d (%s): %w", i+1, f.Label, err)
		}
		parts = append(parts, sql)
	}
	if len(parts) > 0 {
		c.where = " AND " + strings.Join(parts, " AND ")
	}

	if len(spec.GroupBy) > customMaxGroups {
		return nil, fmt.Errorf("al massimo %d campi di raggruppamento", customMaxGroups)
	}
	for _, g := range spec.GroupBy {
		f := src.field(g)
		if f == nil {
			return nil, errors.New("raggruppamento: campo sconosciuto")
		}
		if slices.Contains(c.groups, f) {
			return nil, errors.New("raggruppamento: campo ripetuto")
		}
		c.groups = append(c.groups, f)
	}

	switch spec.Metric {
	case "count", "":
		c.metric = "toFloat64(count())"
	case "uniq", "sum":
		f := src.field(spec.MetricField)
		if f == nil {
			return nil, errors.New("misura: campo sconosciuto")
		}
		if spec.Metric == "sum" {
			if f.Kind != "num" {
				return nil, errors.New("la somma vale solo per i campi numerici")
			}
			c.metric = "toFloat64(sum(" + f.Col + "))"
		} else {
			c.metric = "toFloat64(uniqExact(" + f.Col + "))"
		}
		c.metricF = f
	default:
		return nil, errors.New("misura non valida")
	}
	if !(spec.Threshold >= 1) || spec.Threshold > 1e15 || math.IsNaN(spec.Threshold) {
		return nil, errors.New("la soglia deve essere almeno 1")
	}
	c.params["thr"] = chNum(spec.Threshold)
	if spec.WindowMin < 1 || spec.WindowMin > 1440 {
		return nil, errors.New("finestra: da 1 a 1440 minuti")
	}
	c.window = time.Duration(spec.WindowMin) * time.Minute
	c.every = spec.EveryMin
	if c.every == 0 {
		c.every = min(spec.WindowMin, 5)
	}
	if c.every < 1 || c.every > 60 || c.every > spec.WindowMin {
		return nil, errors.New("frequenza: da 1 a 60 minuti e non più della finestra")
	}
	return c, nil
}

func condSQL(f *customField, op string, vals []string, p string, params map[string]string, internal netx.Nets) (string, error) {
	col := f.Col
	one := func(typ string) string { return "{" + p + ":" + typ + "}" }
	switch f.Kind {
	case "str":
		if op == "regex" {
			if _, err := regexp.Compile(vals[0]); err != nil || len(vals[0]) > 200 {
				return "", errors.New("espressione non valida (sintassi RE2, al massimo 200 caratteri)")
			}
		}
		switch op {
		case "eq", "ne", "contains", "not_contains", "prefix", "suffix", "regex":
			params[p] = vals[0]
		case "in", "not_in":
			params[p] = chStrings(vals)
		}
		switch op {
		case "eq":
			return col + " = " + one("String"), nil
		case "ne":
			return col + " != " + one("String"), nil
		case "in":
			return col + " IN " + one("Array(String)"), nil
		case "not_in":
			return col + " NOT IN " + one("Array(String)"), nil
		case "contains":
			return "positionCaseInsensitiveUTF8(" + col + ", " + one("String") + ") > 0", nil
		case "not_contains":
			return "positionCaseInsensitiveUTF8(" + col + ", " + one("String") + ") = 0", nil
		case "prefix":
			return "startsWith(" + col + ", " + one("String") + ")", nil
		case "suffix":
			return "endsWith(" + col + ", " + one("String") + ")", nil
		case "regex":
			return "match(" + col + ", " + one("String") + ")", nil
		case "empty":
			return col + " = ''", nil
		case "not_empty":
			return col + " != ''", nil
		}
	case "ip":
		switch op {
		case "eq", "ne":
			a, err := netip.ParseAddr(vals[0])
			if err != nil {
				return "", errors.New("indirizzo IP non valido")
			}
			params[p] = a.Unmap().String()
			if op == "eq" {
				return col + " = " + one("String"), nil
			}
			return col + " != " + one("String"), nil
		case "in_net", "not_in_net", "internal", "external":
			var nets []string
			if op == "internal" || op == "external" {
				nets = internal.Strings()
			} else {
				for _, v := range vals {
					n, err := parseNet(v)
					if err != nil {
						return "", err
					}
					nets = append(nets, n)
				}
			}
			if len(nets) == 0 {
				nets = []string{"::/128"}
			}
			params[p] = chStrings(nets)
			expr := "arrayExists(n -> isIPAddressInRange(" + chIPSafe(col) + ", n), " + one("Array(String)") + ")"
			if op == "not_in_net" || op == "external" {
				return "(" + col + " != '' AND NOT " + expr + ")", nil
			}
			return expr, nil
		}
	case "num":
		nums := make([]string, 0, len(vals))
		for _, v := range vals {
			n, err := strconv.ParseFloat(strings.ReplaceAll(v, ",", "."), 64)
			if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
				return "", fmt.Errorf("%q non è un numero", v)
			}
			nums = append(nums, chNum(n))
		}
		cmp := map[string]string{"eq": "=", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
		if s, ok := cmp[op]; ok {
			params[p] = nums[0]
			return col + " " + s + " " + one("Float64"), nil
		}
		params[p] = "[" + strings.Join(nums, ",") + "]"
		if op == "in" {
			return "has(" + one("Array(Float64)") + ", toFloat64(" + col + "))", nil
		}
		return "NOT has(" + one("Array(Float64)") + ", toFloat64(" + col + "))", nil
	}
	return "", errors.New("operatore non valido")
}

func parseNet(v string) (string, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	return "", fmt.Errorf("%q non è un indirizzo o una rete", v)
}

// sql costruisce la query. bucket > 0 divide il periodo in finestre fisse di quella durata
// (per la prova sullo storico), altrimenti l'intero intervallo è una sola finestra.
func (c *compiled) sql(bucket bool, limit int) string {
	var sel, grp []string
	if bucket {
		sel = append(sel, "toString(toStartOfInterval(ts, INTERVAL {w:UInt32} MINUTE)) AS Bucket")
		grp = append(grp, "Bucket")
	}
	for i := range customMaxGroups {
		name := "G" + strconv.Itoa(i)
		if i < len(c.groups) {
			sel = append(sel, "toString("+c.groups[i].Col+") AS "+name)
			grp = append(grp, name)
		} else {
			sel = append(sel, "'' AS "+name)
		}
	}
	q := "SELECT " + strings.Join(sel, ", ") + ", " + c.metric + " AS V, count() AS N, toString(min(ts)) AS First, toString(max(ts)) AS Last" +
		"\nFROM " + c.src.Table + "\nWHERE " + inWindow + c.where
	if len(grp) > 0 {
		q += "\nGROUP BY " + strings.Join(grp, ", ")
	}
	q += "\nHAVING V >= {thr:Float64}\nORDER BY "
	if bucket {
		q += "Bucket DESC, "
	}
	q += "V DESC\nLIMIT " + strconv.Itoa(limit) + "\nSETTINGS max_execution_time = 25"
	return q
}

type customRow struct {
	Bucket, G0, G1, G2, First, Last string
	V                               float64
	N                               uint64
}

func (r customRow) groups() []string { return []string{r.G0, r.G1, r.G2} }

func (c *compiled) fmtValue(v float64) string {
	if c.metricF != nil && c.metricF.Unit == "bytes" && c.spec.Metric == "sum" {
		return humanBytes(v)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func (c *compiled) metricLabel() string {
	switch c.spec.Metric {
	case "uniq":
		return "valori diversi di «" + c.metricF.Label + "»"
	case "sum":
		return "somma di «" + c.metricF.Label + "»"
	}
	return "record"
}

// ---------------------------------------------------------------- nel motore

type customRule struct {
	id                         int64
	name, description, sev, mt string
	spec                       customSpec
	err                        string // regola non valida: non gira
}

// loadCustom legge le regole personalizzate e ne fa delle RuleDef.
func (e *Engine) loadCustom(ctx context.Context) error {
	rows, err := e.h.pg.Query(ctx, "SELECT id, name, description, severity, mitre, spec FROM custom_rules ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	var defs []*RuleDef
	for rows.Next() {
		var r customRule
		var raw []byte
		if err := rows.Scan(&r.id, &r.name, &r.description, &r.sev, &r.mt, &raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &r.spec); err != nil {
			r.err = "definizione illeggibile"
		}
		defs = append(defs, e.customDef(r))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	e.custom.Store(&defs)
	return nil
}

func (e *Engine) customDef(r customRule) *RuleDef {
	d := &RuleDef{
		ID: fmt.Sprintf("custom:%d", r.id), Name: r.name, Category: "Regole personalizzate", Description: r.description,
		Severity: r.sev, Mitre: r.mt, Every: 5, Window: 5 * time.Minute,
	}
	if _, ok := sevRank[d.Severity]; !ok {
		d.Severity = "medium"
	}
	c, err := compileCustom(r.spec, e.h.state.Internal())
	if r.err == "" && err != nil {
		r.err = err.Error()
	}
	if r.err != "" {
		msg := r.err
		d.Run = func(context.Context, *Engine, window, params) ([]Alert, error) { return nil, errors.New(msg) }
		return d
	}
	d.Every, d.Window = c.every, c.window
	d.Run = func(ctx context.Context, e *Engine, w window, _ params) ([]Alert, error) {
		// si ricompila a ogni giro: le reti interne possono essere cambiate da Impostazioni
		c, err := compileCustom(r.spec, e.h.state.Internal())
		if err != nil {
			return nil, err
		}
		rows, err := q[customRow](ctx, e, c.sql(false, 100), w.params(c.params))
		if err != nil {
			return nil, err
		}
		out := make([]Alert, 0, len(rows))
		for _, row := range rows {
			out = append(out, c.alert(e, d.ID, r.name, w, row))
		}
		return out, nil
	}
	return d
}

func (c *compiled) alert(e *Engine, id, name string, w window, row customRow) Alert {
	a := Alert{DedupKey: id, TS: parseCH(row.First)}
	var labels []string
	groups := map[string]string{}
	for i, f := range c.groups {
		v := row.groups()[i]
		a.DedupKey += "|" + v
		groups[f.ID] = v
		if v == "" {
			v = "(vuoto)"
		}
		labels = append(labels, f.Label+" "+v)
		switch {
		case f.Role == "src" && a.Src == "":
			a.Src = row.groups()[i]
		case f.Role == "dst" && a.Dst == "":
			a.Dst = row.groups()[i]
		}
	}
	a.Title = name
	if len(labels) > 0 {
		a.Title += ": " + strings.Join(labels, " · ")
	}
	who := ""
	if len(labels) > 0 {
		who = " per " + strings.Join(labels, ", ")
	}
	a.Summary = fmt.Sprintf("%s%s: %s %s (soglia %s) tra le %s e le %s, su %d record di «%s».",
		name, who, c.fmtValue(row.V), c.metricLabel(), c.fmtValue(c.spec.Threshold), e.clock(w.from), e.clock(w.to), row.N, c.src.Label)
	a.Detail = map[string]any{"custom": true, "groups": groups, "value": row.V, "threshold": c.spec.Threshold, "records": row.N,
		"window_min": c.spec.WindowMin, "source": c.src.ID, "last": row.Last}
	return a
}

// noteCustom registra l'esito dell'ultimo giro: la pagina mostra errori e allarmi prodotti.
func (e *Engine) noteCustom(ctx context.Context, ruleID string, hits int, err error) {
	id, ok := strings.CutPrefix(ruleID, "custom:")
	if !ok {
		return
	}
	msg := ""
	if err != nil {
		msg = clip(err.Error(), 500)
	}
	if _, xerr := e.h.pg.Exec(ctx, "UPDATE custom_rules SET last_run = now(), last_error = $2, last_hits = $3 WHERE id = $1", id, msg, hits); xerr != nil {
		e.h.log.Warn("esito regola personalizzata", "rule", ruleID, "err", xerr)
	}
}

// ---------------------------------------------------------------- prova sullo storico

type customTestReq struct {
	Spec  customSpec `json:"spec"`
	Hours int        `json:"hours"`
	Check bool       `json:"check"` // solo verifica della definizione
}

type customTestRow struct {
	Bucket string   `json:"bucket"`
	Groups []string `json:"groups"`
	Value  string   `json:"value"`
	N      uint64   `json:"n"`
}

type customTestResp struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	SQL     string          `json:"sql,omitempty"`
	Rows    []customTestRow `json:"rows,omitempty"`
	Windows int             `json:"windows"`
	Groups  int             `json:"groups"`
	More    bool            `json:"more"`
	Ms      int64           `json:"ms"`
	Columns []string        `json:"columns,omitempty"`
}

const customTestLimit = 200

func (e *Engine) customTest(ctx context.Context, data []byte) customTestResp {
	var req customTestReq
	if err := json.Unmarshal(data, &req); err != nil {
		return customTestResp{Error: "richiesta non valida"}
	}
	c, err := compileCustom(req.Spec, e.h.state.Internal())
	if err != nil {
		return customTestResp{Error: err.Error()}
	}
	resp := customTestResp{OK: true, SQL: c.sql(!req.Check, customTestLimit+1)}
	if req.Check {
		resp.SQL = c.sql(false, 100)
		return resp
	}
	hours := min(max(req.Hours, 1), 24*7)
	to := time.Now().Truncate(time.Minute)
	w := window{from: to.Add(-time.Duration(hours) * time.Hour), to: to}
	p := w.params(c.params)
	p["w"] = strconv.Itoa(req.Spec.WindowMin)
	start := time.Now()
	rows, err := q[customRow](ctx, e, resp.SQL, p)
	resp.Ms = time.Since(start).Milliseconds()
	if err != nil {
		return customTestResp{Error: clip(err.Error(), 400), SQL: resp.SQL, Ms: resp.Ms}
	}
	if len(rows) > customTestLimit {
		rows, resp.More = rows[:customTestLimit], true
	}
	seen := map[string]bool{}
	for _, f := range c.groups {
		resp.Columns = append(resp.Columns, f.Label)
	}
	for _, r := range rows {
		g := r.groups()[:len(c.groups)]
		seen[strings.Join(g, "\x00")] = true
		resp.Rows = append(resp.Rows, customTestRow{Bucket: r.Bucket, Groups: g, Value: c.fmtValue(r.V), N: r.N})
	}
	resp.Windows, resp.Groups = len(rows), len(seen)
	return resp
}

// customTestHandler risponde alle richieste della pagina (NATS request-reply) senza bloccare
// gli altri comandi: la query può durare decine di secondi.
func (h *Hub) customTestHandler(ctx context.Context, m *nats.Msg) {
	if m.Reply == "" {
		return
	}
	// la sola verifica della definizione non tocca ClickHouse: risposta immediata
	var probe struct {
		Check bool `json:"check"`
	}
	if json.Unmarshal(m.Data, &probe) == nil && probe.Check {
		b, _ := json.Marshal(h.eng.customTest(ctx, m.Data))
		m.Respond(b)
		return
	}
	if !h.customBusy.CompareAndSwap(false, true) {
		b, _ := json.Marshal(customTestResp{Error: "C'è già una prova in corso: riprova tra poco."})
		m.Respond(b)
		return
	}
	go func() {
		defer h.customBusy.Store(false)
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		b, _ := json.Marshal(h.eng.customTest(rctx, m.Data))
		if err := m.Respond(b); err != nil {
			h.log.Warn("risposta alla prova della regola", "err", err)
		}
	}()
}

// customSchema descrive sorgenti, campi e operatori per il costruttore della pagina: l'hub è
// l'unico a conoscerli, l'interfaccia li legge da settings.
func customSchema() map[string]any {
	type f struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Kind  string `json:"kind"`
	}
	type s struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		Fields []f    `json:"fields"`
	}
	type o struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		Values string `json:"values"`
	}
	var sources []s
	for _, src := range customSources {
		x := s{ID: src.ID, Label: src.Label}
		for _, fl := range src.Fields {
			x.Fields = append(x.Fields, f{fl.ID, fl.Label, fl.Kind})
		}
		sources = append(sources, x)
	}
	ops := map[string][]o{}
	for kind, list := range customOps {
		for _, op := range list {
			ops[kind] = append(ops[kind], o{op.ID, op.Label, op.Values})
		}
	}
	return map[string]any{"sources": sources, "ops": ops, "max_conds": customMaxConds, "max_groups": customMaxGroups}
}

func (e *Engine) saveCustomSchema(ctx context.Context) error {
	b, _ := json.Marshal(customSchema())
	_, err := e.h.pg.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ('custom_rule_schema', $1, now(), 'hub')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, b)
	return err
}
