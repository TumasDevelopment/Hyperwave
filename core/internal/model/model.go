// Package model contiene i record che il sensore invia all'hub.
// I tempi sono in millisecondi Unix, gli indirizzi in forma testuale.
package model

// Batch è il corpo di POST /v1/ingest (JSON compresso con gzip).
type Batch struct {
	Backfill bool    `json:"backfill,omitempty"` // dati storici: niente eventi live
	Demo     bool    `json:"demo,omitempty"`     // dati dimostrativi
	Flows    []Flow  `json:"flows,omitempty"`
	DNS      []DNS   `json:"dns,omitempty"`
	TLS      []TLS   `json:"tls,omitempty"`
	HTTP     []HTTP  `json:"http,omitempty"`
	Hosts    []Host  `json:"hosts,omitempty"`
	Events   []Event `json:"events,omitempty"`
	Rates    []Rate  `json:"rates,omitempty"`
}

func (b *Batch) Len() int {
	return len(b.Flows) + len(b.DNS) + len(b.TLS) + len(b.HTTP) + len(b.Hosts) + len(b.Events) + len(b.Rates)
}

// Flow è una conversazione: il client è chi ha aperto la connessione.
type Flow struct {
	TS       int64   `json:"ts"`
	End      int64   `json:"end"`
	VLAN     uint16  `json:"vlan,omitempty"`
	Proto    string  `json:"proto"`
	SrcIP    string  `json:"src"`
	SrcPort  uint16  `json:"sport,omitempty"`
	DstIP    string  `json:"dst"`
	DstPort  uint16  `json:"dport,omitempty"`
	App      string  `json:"app,omitempty"`
	Domain   string  `json:"domain,omitempty"`
	BytesOut uint64  `json:"bout"` // dal client al server
	BytesIn  uint64  `json:"bin"`  // dal server al client
	PktsOut  uint32  `json:"pout"`
	PktsIn   uint32  `json:"pin"`
	Flags    string  `json:"flags,omitempty"` // unione dei flag TCP visti nei due versi
	Est      bool    `json:"est,omitempty"`   // il server ha risposto: SYN-ACK per TCP, un pacchetto per UDP e ICMP
	RTT      float32 `json:"rtt,omitempty"`   // handshake TCP, ms
	Retrans  uint32  `json:"retrans,omitempty"`
	Country  string  `json:"cc,omitempty"` // dell'estremo esterno, se già noto
	ASN      uint32  `json:"asn,omitempty"`
	ASOrg    string  `json:"asorg,omitempty"`
}

type DNS struct {
	TS      int64    `json:"ts"`
	Client  string   `json:"client"`
	Server  string   `json:"server"`
	Query   string   `json:"q"`
	QType   string   `json:"qtype"`
	RCode   string   `json:"rcode"`
	Answers []string `json:"ans,omitempty"`
	RTT     float32  `json:"rtt,omitempty"`
}

type TLS struct {
	TS           int64  `json:"ts"`
	Client       string `json:"client"`
	Server       string `json:"server"`
	Port         uint16 `json:"port"`
	SNI          string `json:"sni,omitempty"`
	Version      string `json:"ver,omitempty"`
	ALPN         string `json:"alpn,omitempty"`
	JA4          string `json:"ja4,omitempty"`
	CertSubject  string `json:"csub,omitempty"`
	CertIssuer   string `json:"ciss,omitempty"`
	CertNotAfter int64  `json:"cexp,omitempty"` // secondi Unix
	SelfSigned   bool   `json:"cself,omitempty"`
}

type HTTP struct {
	TS        int64  `json:"ts"`
	Client    string `json:"client"`
	Server    string `json:"server"`
	Port      uint16 `json:"port"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	URI       string `json:"uri"`
	Status    uint16 `json:"status,omitempty"`
	UserAgent string `json:"ua,omitempty"`
}

// Host è un dispositivo visto in rete (ARP, DHCP, traffico).
type Host struct {
	TS       int64  `json:"ts"`
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	OS       string `json:"os,omitempty"`
	Type     string `json:"type,omitempty"`
	VLAN     uint16 `json:"vlan,omitempty"`
	Source   string `json:"source"`
}

// Event è una segnalazione nata nel sensore, per esempio un allarme IDS.
type Event struct {
	TS        int64          `json:"ts"`
	Kind      string         `json:"kind"` // ids | notice
	Severity  string         `json:"sev"`  // critical | high | medium | low | info
	Title     string         `json:"title"`
	SrcIP     string         `json:"src,omitempty"`
	DstIP     string         `json:"dst,omitempty"`
	DstPort   uint16         `json:"dport,omitempty"`
	Signature string         `json:"sig,omitempty"`
	Category  string         `json:"cat,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// Rate sono i contatori dell'interfaccia in un intervallo.
type Rate struct {
	TS            int64   `json:"ts"`
	Seconds       float64 `json:"secs"`
	BytesIn       uint64  `json:"in"`  // da internet verso la rete interna
	BytesOut      uint64  `json:"out"` // dalla rete interna verso internet
	BytesInternal uint64  `json:"int"` // tra host interni
	Packets       uint64  `json:"pkts"`
	Flows         uint64  `json:"flows"` // flussi attivi
	Drops         uint64  `json:"drops"`
}

// Heartbeat è il corpo di POST /v1/heartbeat.
type Heartbeat struct {
	Version  string         `json:"version"`
	Mode     string         `json:"mode"`
	Hostname string         `json:"hostname"`
	Stats    map[string]any `json:"stats"`
}

// HubReply è la risposta dell'hub a heartbeat e ingest.
type HubReply struct {
	OK           bool     `json:"ok"`
	Live         bool     `json:"live"`
	Accepted     int      `json:"accepted,omitempty"`
	InternalNets []string `json:"internal_nets,omitempty"`
	ServerTime   int64    `json:"server_time,omitempty"`
	LastIngest   int64    `json:"last_ingest,omitempty"` // ultimo dato ricevuto da questo sensore (ms)
	Error        string   `json:"error,omitempty"`
}

// Limiti del protocollo, uguali per hub e sensore.
const (
	MaxBatchRecords = 50_000
	MaxBodyBytes    = 64 << 20  // corpo compresso
	MaxPlainBytes   = 512 << 20 // corpo decompresso
)
