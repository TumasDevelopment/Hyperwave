package sensor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"hyperwave/internal/model"
)

var exporter = netip.MustParseAddr("10.0.0.1")

func put16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func put32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

func ip4(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

// ---------------------------------------------------------------- NetFlow v5

func TestNetFlow5(t *testing.T) {
	b := put16(nil, 5)
	b = put16(b, 1)
	b = put32(b, 60_000)        // uptime ms
	b = put32(b, 1_700_000_000) // secondi
	b = put32(b, 0)
	b = put32(b, 1) // sequenza
	b = append(b, 0, 0)
	b = put16(b, 0x4000|10) // campionamento 1 su 10
	r := ip4("10.1.1.5")
	r = append(r, ip4("198.18.0.10")...)
	r = append(r, make([]byte, 8)...) // next hop, interfacce
	r = put32(r, 3)                   // pacchetti
	r = put32(r, 180)                 // byte
	r = put32(r, 50_000)              // inizio (uptime)
	r = put32(r, 59_000)              // fine
	r = put16(r, 51000)
	r = put16(r, 443)
	r = append(r, 0, fSYN|fACK, 6, 0)
	r = append(r, make([]byte, 8)...)
	b = append(b, r...)

	recs, err := newFlowDecoder(0).decode(exporter, b, 0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%v %v", recs, err)
	}
	u := recs[0]
	if u.src.String() != "10.1.1.5" || u.dst.String() != "198.18.0.10" || u.sp != 51000 || u.dp != 443 || u.proto != 6 {
		t.Fatalf("record: %+v", u)
	}
	if u.bytes != 1800 || u.pkts != 30 {
		t.Fatalf("campionamento non applicato: %d byte, %d pacchetti", u.bytes, u.pkts)
	}
	if u.start != 1_700_000_000_000-10_000 || u.end != 1_700_000_000_000-1_000 {
		t.Fatalf("tempi: %d %d", u.start, u.end)
	}
}

// ---------------------------------------------------------------- NetFlow v9

func TestNetFlow9Template(t *testing.T) {
	d := newFlowDecoder(0)
	hdr := func(count int) []byte {
		b := put16(nil, 9)
		b = put16(b, uint16(count))
		b = put32(b, 120_000)       // uptime
		b = put32(b, 1_700_000_000) // secondi
		b = put32(b, 7)
		return put32(b, 42) // source id
	}
	// i dati arrivano prima del template: vanno contati e ignorati
	data := put16(nil, 256)
	rec := ip4("10.1.1.9")
	rec = append(rec, ip4("198.18.0.53")...)
	rec = put16(rec, 40000)
	rec = put16(rec, 53)
	rec = append(rec, 17)
	rec = put32(rec, 2)
	rec = put32(rec, 140)
	rec = put32(rec, 100_000)
	rec = put32(rec, 101_000)
	data = put16(data, uint16(4+len(rec)))
	data = append(data, rec...)
	if recs, _ := d.decode(exporter, append(hdr(1), data...), 0); len(recs) != 0 || d.noTpl.Load() != 1 {
		t.Fatalf("dati senza template: %v", recs)
	}

	fields := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {2, 4}, {1, 4}, {22, 4}, {21, 4}}
	tpl := put16(nil, 256)
	tpl = put16(tpl, uint16(len(fields)))
	for _, f := range fields {
		tpl = put16(put16(tpl, f[0]), f[1])
	}
	fs := put16(nil, 0)
	fs = put16(fs, uint16(4+len(tpl)))
	fs = append(fs, tpl...)
	recs, err := d.decode(exporter, append(append(hdr(2), fs...), data...), 0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%v %v", recs, err)
	}
	u := recs[0]
	if u.dst.String() != "198.18.0.53" || u.dp != 53 || u.proto != 17 || u.bytes != 140 || u.pkts != 2 {
		t.Fatalf("record: %+v", u)
	}
	if want := int64(1_700_000_000_000 - 120_000 + 100_000); u.start != want || u.end != want+1000 {
		t.Fatalf("tempi: %d %d, attesi %d", u.start, u.end, want)
	}
	// un altro esportatore con lo stesso id di template non deve usarlo
	if recs, _ := d.decode(netip.MustParseAddr("10.0.0.2"), append(hdr(1), data...), 0); len(recs) != 0 {
		t.Fatal("template condiviso tra esportatori diversi")
	}
}

// ---------------------------------------------------------------- IPFIX bidirezionale

func TestIPFIXBiflowVariableLength(t *testing.T) {
	type fld struct {
		id, length uint16
		pen        uint32
	}
	fields := []fld{{8, 4, 0}, {12, 4, 0}, {7, 2, 0}, {11, 2, 0}, {4, 1, 0}, {1, 8, 0}, {2, 8, 0}, {1, 8, 29305}, {2, 8, 29305},
		{6, 1, 0}, {6, 1, 29305}, {152, 8, 0}, {153, 8, 0}, {82, 65535, 0}} // 82 = interfaceName, lunghezza variabile
	tpl := put16(nil, 300)
	tpl = put16(tpl, uint16(len(fields)))
	for _, f := range fields {
		if f.pen != 0 {
			tpl = put32(put16(put16(tpl, f.id|0x8000), f.length), f.pen)
		} else {
			tpl = put16(put16(tpl, f.id), f.length)
		}
	}
	set := put16(nil, 2)
	set = put16(set, uint16(4+len(tpl)))
	set = append(set, tpl...)

	rec := ip4("10.2.0.7")
	rec = append(rec, ip4("198.18.1.1")...)
	rec = put16(rec, 50123)
	rec = put16(rec, 443)
	rec = append(rec, 6)
	rec = binary.BigEndian.AppendUint64(rec, 1500)
	rec = binary.BigEndian.AppendUint64(rec, 12)
	rec = binary.BigEndian.AppendUint64(rec, 90_000)
	rec = binary.BigEndian.AppendUint64(rec, 70)
	rec = append(rec, fSYN|fACK|fFIN, fSYN|fACK|fFIN)
	rec = binary.BigEndian.AppendUint64(rec, 1_700_000_000_000)
	rec = binary.BigEndian.AppendUint64(rec, 1_700_000_004_000)
	rec = append(rec, 4)
	rec = append(rec, "eth0"...)
	data := put16(nil, 300)
	data = put16(data, uint16(4+len(rec)))
	data = append(data, rec...)

	msg := put16(nil, 10)
	msg = put16(msg, uint16(16+len(set)+len(data)))
	msg = put32(msg, 1_700_000_010)
	msg = put32(msg, 1)
	msg = put32(msg, 0)
	msg = append(append(msg, set...), data...)

	recs, err := newFlowDecoder(0).decode(exporter, msg, 0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%v %v", recs, err)
	}
	u := recs[0]
	if u.bytes != 1500 || u.pkts != 12 || u.revBytes != 90_000 || u.revPkts != 70 || u.revFlags == 0 {
		t.Fatalf("contatori: %+v", u)
	}
	if u.start != 1_700_000_000_000 || u.end != 1_700_000_004_000 {
		t.Fatalf("tempi: %d %d", u.start, u.end)
	}

	// il record bidirezionale diventa un flusso solo, con il traffico nei due versi
	r := testRunner()
	out := newSink(r, false)
	a := newAggregator(r, out)
	a.add(u, 0)
	a.flushAll()
	b := out.take()
	if b == nil || len(b.Flows) != 1 {
		t.Fatalf("flussi: %+v", b)
	}
	f := b.Flows[0]
	if f.SrcIP != "10.2.0.7" || f.DstPort != 443 || f.BytesOut != 1500 || f.BytesIn != 90_000 || !f.Est || f.Proto != "TCP" {
		t.Fatalf("flusso: %+v", f)
	}
}

// ---------------------------------------------------------------- sFlow

func TestSFlowRawHeader(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: 30, Type: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: ip4("10.3.0.4"), DstIP: ip4("198.18.2.2")}
	tcp := &layers.TCP{SrcPort: 52000, DstPort: 22, SYN: true, Window: 1024}
	tcp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, vlan, ip, tcp); err != nil {
		t.Fatal(err)
	}
	hdr := buf.Bytes()

	raw := put32(nil, sflowEther)
	raw = put32(raw, 1514) // lunghezza del frame originale
	raw = put32(raw, 0)
	raw = put32(raw, uint32(len(hdr)))
	raw = append(raw, hdr...)
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	}
	sample := put32(nil, 1)   // sequenza
	sample = put32(sample, 3) // source id
	sample = put32(sample, 512)
	sample = put32(sample, 99) // pool
	sample = put32(sample, 0)  // drops
	sample = put32(sample, 1)  // input
	sample = put32(sample, 2)  // output
	sample = put32(sample, 1)  // record
	sample = put32(put32(sample, 1), uint32(len(raw)))
	sample = append(sample, raw...)

	dg := put32(nil, 5)
	dg = put32(dg, 1)
	dg = append(dg, ip4("10.0.0.1")...)
	dg = put32(dg, 0)
	dg = put32(dg, 1)
	dg = put32(dg, 1000)
	dg = put32(dg, 1)
	dg = put32(put32(dg, 1), uint32(len(sample)))
	dg = append(dg, sample...)

	recs, err := newFlowDecoder(0).decode(exporter, dg, 5000)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%v %v", recs, err)
	}
	u := recs[0]
	if u.src.String() != "10.3.0.4" || u.dp != 22 || u.vlan != 30 || u.flags&fSYN == 0 || u.pkts != 512 || u.bytes != 1514*512 || u.start != 5000 {
		t.Fatalf("campione: %+v", u)
	}
}

// ---------------------------------------------------------------- aggregatore

func TestAggregatorMergesDirections(t *testing.T) {
	r := testRunner()
	out := newSink(r, false)
	a := newAggregator(r, out)
	cli, srv := netip.MustParseAddr("10.4.0.8"), netip.MustParseAddr("198.18.3.3")
	// arriva prima il verso del server: la porta del servizio decide chi è il client
	a.add(uniRec{start: 1000, end: 2000, proto: 6, src: srv, dst: cli, sp: 443, dp: 61000, bytes: 50_000, pkts: 40, flags: fSYN | fACK}, 2000)
	a.add(uniRec{start: 900, end: 2100, proto: 6, src: cli, dst: srv, sp: 61000, dp: 443, bytes: 2_000, pkts: 30, flags: fSYN | fACK | fFIN}, 2100)
	// una scansione rifiutata: solo SYN e RST in risposta
	a.add(uniRec{start: 1000, end: 1000, proto: 6, src: cli, dst: srv, sp: 40000, dp: 3389, bytes: 60, pkts: 1, flags: fSYN}, 2200)
	a.add(uniRec{start: 1000, end: 1000, proto: 6, src: srv, dst: cli, sp: 3389, dp: 40000, bytes: 40, pkts: 1, flags: fRST | fACK}, 2200)
	a.tick(2300, false)
	if b := out.take(); b != nil {
		t.Fatalf("flussi esportati troppo presto: %+v", b.Flows)
	}
	a.tick(2300+aggIdle+1, true)
	b := out.take()
	if b == nil || len(b.Flows) != 2 {
		t.Fatalf("flussi: %+v", b)
	}
	for _, f := range b.Flows {
		if f.SrcIP != "10.4.0.8" {
			t.Fatalf("orientamento sbagliato: %+v", f)
		}
		switch f.DstPort {
		case 443:
			if f.BytesOut != 2000 || f.BytesIn != 50_000 || f.TS != 900 || f.End != 2100 || !f.Est {
				t.Fatalf("HTTPS: %+v", f)
			}
		case 3389:
			if f.Est {
				t.Fatalf("connessione rifiutata segnata come stabilita: %+v", f)
			}
		default:
			t.Fatalf("flusso inatteso: %+v", f)
		}
	}
}

// ---------------------------------------------------------------- Zeek

const zeekConnTSV = "#separator \\x09\n#set_separator\t,\n#path\tconn\n" +
	"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n" +
	"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tcount\tcount\n" +
	"1700000000.250000\tCa1\t10.5.0.2\t50500\t198.18.4.4\t443\ttcp\tssl\t2.5\t900\t15000\tSF\tShADadFf\t12\t1500\t14\t15800\n" +
	"1700000001.000000\tCa2\t10.5.0.2\t50501\t198.18.4.5\t23\ttcp\t-\t-\t-\t-\tS0\tS\t1\t60\t0\t0\n" +
	"1700000002.000000\tCa3\t10.5.0.2\t8\t198.18.4.6\t0\ticmp\t-\t0.01\t56\t56\tOTH\t-\t1\t84\t1\t84\n" +
	"#close\t2023-11-14-22-13-20\n"

func TestZeekConnTSV(t *testing.T) {
	z := newZeekLog("conn")
	var flows []model.Flow
	for _, line := range strings.Split(zeekConnTSV, "\n") {
		if m, ok := z.parse(line); ok {
			b := &model.Batch{}
			zeekRecord("conn", m)(b)
			flows = append(flows, b.Flows...)
		}
	}
	if len(flows) != 3 {
		t.Fatalf("flussi: %+v", flows)
	}
	f := flows[0]
	if f.TS != 1_700_000_000_250 || f.End != 1_700_000_002_750 || f.BytesOut != 1500 || f.BytesIn != 15800 || !f.Est || f.App != "TLS" || f.Proto != "TCP" {
		t.Fatalf("primo flusso: %+v", f)
	}
	if !strings.Contains(f.Flags, "S") || !strings.Contains(f.Flags, "F") {
		t.Fatalf("flag: %q", f.Flags)
	}
	if flows[1].Est || flows[1].DstPort != 23 {
		t.Fatalf("tentativo senza risposta: %+v", flows[1])
	}
	if flows[2].Proto != "ICMP" || flows[2].DstPort != 8 || flows[2].SrcPort != 0 {
		t.Fatalf("ICMP: %+v", flows[2])
	}
}

func TestZeekJSON(t *testing.T) {
	lines := map[string]string{
		"dns":      `{"ts":1700000000.1,"uid":"C1","id.orig_h":"10.5.0.3","id.orig_p":53000,"id.resp_h":"10.5.0.1","id.resp_p":53,"proto":"udp","query":"Example.ORG","qtype_name":"A","rcode_name":"NOERROR","rtt":0.012,"answers":["198.18.5.5"]}`,
		"ssl":      `{"ts":"2023-11-14T22:13:20.5Z","id.orig_h":"10.5.0.3","id.orig_p":50000,"id.resp_h":"198.18.5.5","id.resp_p":443,"version":"TLSv12","server_name":"example.org","next_protocol":"h2"}`,
		"http":     `{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":50001,"id.resp_h":"198.18.5.6","id.resp_p":80,"method":"GET","host":"example.org","uri":"/a","status_code":200,"user_agent":"curl/8"}`,
		"ssh":      `{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":50002,"id.resp_h":"10.5.0.9","id.resp_p":22,"version":2,"auth_success":false,"auth_attempts":3,"client":"SSH-2.0-OpenSSH_9.6","server":"SSH-2.0-OpenSSH_7.4","cipher_alg":"aes128-ctr","mac_alg":"hmac-sha1-96","kex_alg":"diffie-hellman-group1-sha1","host_key_alg":"ssh-rsa","hassh":"abc"}`,
		"rdp":      `{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":50003,"id.resp_h":"10.5.0.10","id.resp_p":3389,"cookie":"mario","result":"Success","security_protocol":"SSL","client_name":"PC-MARIO"}`,
		"ntlm":     `{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":50004,"id.resp_h":"10.5.0.11","id.resp_p":445,"username":"mario","hostname":"PC-MARIO","domainname":"AZIENDA","success":true}`,
		"kerberos": `{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":50005,"id.resp_h":"10.5.0.12","id.resp_p":88,"request_type":"TGS","client":"mario/AZIENDA.EXAMPLE","service":"MSSQLSvc/db01.azienda.example:1433","success":true,"cipher":"rc4-hmac"}`,
		"notice":   `{"ts":1700000000,"note":"Scan::Port_Scan","msg":"10.5.0.3 scanned at least 15 unique ports","src":"10.5.0.3","sub":"local"}`,
		"dhcp":     `{"ts":1700000000,"uids":["C9"],"mac":"AA:BB:CC:00:11:22","assigned_addr":"10.5.0.40","host_name":"stampante"}`,
	}
	b := &model.Batch{}
	for kind, line := range lines {
		m, ok := newZeekLog(kind).parse(line)
		if !ok {
			t.Fatalf("%s: riga non letta", kind)
		}
		fn := zeekRecord(kind, m)
		if fn == nil {
			t.Fatalf("%s: nessun record", kind)
		}
		fn(b)
	}
	if len(b.DNS) != 1 || b.DNS[0].Query != "example.org" || b.DNS[0].RTT != 12 || len(b.DNS[0].Answers) != 1 {
		t.Fatalf("DNS: %+v", b.DNS)
	}
	if len(b.TLS) != 1 || b.TLS[0].Version != "TLSv1.2" || b.TLS[0].TS != 1_700_000_000_500 || b.TLS[0].ALPN != "h2" {
		t.Fatalf("TLS: %+v", b.TLS)
	}
	if len(b.HTTP) != 1 || b.HTTP[0].Status != 200 {
		t.Fatalf("HTTP: %+v", b.HTTP)
	}
	if len(b.Events) != 1 || b.Events[0].Kind != "ids" || b.Events[0].Signature != "Scan::Port_Scan" {
		t.Fatalf("notice: %+v", b.Events)
	}
	if len(b.Hosts) != 1 || b.Hosts[0].MAC != "aa:bb:cc:00:11:22" || b.Hosts[0].Hostname != "stampante" {
		t.Fatalf("DHCP: %+v", b.Hosts)
	}
	got := map[string]model.Session{}
	for _, s := range b.Sessions {
		got[s.Protocol] = s
	}
	if s := got["ssh"]; !strings.Contains(s.Weak, "diffie-hellman-group1-sha1") || !strings.Contains(s.Weak, "hmac-sha1-96") || !strings.Contains(s.Info, "3 tentativi") {
		t.Fatalf("SSH: %+v", s)
	}
	if s := got["rdp"]; s.User != "mario" || !strings.Contains(s.Weak, "NLA") {
		t.Fatalf("RDP: %+v", s)
	}
	if s := got["ntlm"]; s.Domain != "AZIENDA" || s.Host != "PC-MARIO" || s.Info != "accesso riuscito" {
		t.Fatalf("NTLM: %+v", s)
	}
	// stesso formato della cattura: le regole kerberoast e weak_auth funzionano anche con Zeek
	if s := got["kerberos"]; s.User != "mario" || s.Domain != "AZIENDA.EXAMPLE" || !strings.HasPrefix(s.Weak, "ticket cifrato") || s.Transport != "udp" || s.Host == "" {
		t.Fatalf("Kerberos: %+v", s)
	}
}

func TestZeekKerberosFailure(t *testing.T) {
	m, _ := newZeekLog("kerberos").parse(`{"ts":1700000000,"id.orig_h":"10.5.0.3","id.orig_p":1,"id.resp_h":"10.5.0.12","id.resp_p":88,"request_type":"AS","client":"admin/AZIENDA.EXAMPLE","service":"krbtgt/AZIENDA.EXAMPLE","success":false,"error_msg":"KDC_ERR_PREAUTH_FAILED"}`)
	b := &model.Batch{}
	zeekRecord("kerberos", m)(b)
	if s := b.Sessions[0]; !strings.Contains(s.Info, "KDC_ERR_PREAUTH_FAILED") || s.Weak != "" {
		t.Fatalf("%+v", s)
	}
}

func TestZeekKindAndGzip(t *testing.T) {
	for path, want := range map[string]string{"conn.log": "conn", "/x/conn.09:00:00-10:00:00.log.gz": "conn", "smb_mapping.log": "smb_mapping", "weird.log": ""} {
		if got := zeekKind(path); got != want {
			t.Errorf("%s: %q, atteso %q", path, got, want)
		}
	}
	dir := t.TempDir()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(zeekConnTSV))
	w.Close()
	path := filepath.Join(dir, "conn.log.gz")
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	n := 0
	z := newZeekLog("conn")
	if err := eachLine(context.Background(), path, func(l string) {
		if _, ok := z.parse(l); ok {
			n++
		}
	}); err != nil || n != 3 {
		t.Fatalf("righe: %d, %v", n, err)
	}
}

// ---------------------------------------------------------------- VPC Flow Logs

func TestVPCFlowLogs(t *testing.T) {
	p := newVPCParser()
	lines := []string{
		"version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status",
		"2 123456789012 eni-0a1 10.6.0.5 198.18.6.6 49152 443 6 20 4000 1700000000 1700000060 ACCEPT OK",
		"2 123456789012 eni-0a1 198.18.6.6 10.6.0.5 443 49152 6 25 30000 1700000000 1700000060 ACCEPT OK",
		"2 123456789012 eni-0a1 198.18.6.9 10.6.0.5 51515 22 6 1 40 1700000010 1700000070 REJECT OK",
		"2 123456789012 eni-0a1 - - - - - - - 1700000000 1700000060 - NODATA",
	}
	r := testRunner()
	out := newSink(r, true)
	a := newAggregator(r, out)
	n := 0
	for _, l := range lines {
		if u, ok := p.parse(l); ok {
			n++
			a.add(u, u.end)
		}
	}
	if n != 3 {
		t.Fatalf("record letti: %d", n)
	}
	a.flushAll()
	b := out.take()
	if b == nil || len(b.Flows) != 2 {
		t.Fatalf("flussi: %+v", b)
	}
	for _, f := range b.Flows {
		switch f.DstPort {
		case 443:
			if f.SrcIP != "10.6.0.5" || f.BytesOut != 4000 || f.BytesIn != 30000 || !f.Est {
				t.Fatalf("HTTPS: %+v", f)
			}
		case 22:
			if f.SrcIP != "198.18.6.9" || f.Est {
				t.Fatalf("rifiutato: %+v", f)
			}
		default:
			t.Fatalf("inatteso: %+v", f)
		}
	}

	// formato personalizzato con i campi in un altro ordine e gli indirizzi prima del NAT
	p2 := newVPCParser()
	p2.parse("start end srcaddr dstaddr pkt-srcaddr srcport dstport protocol bytes packets tcp-flags action")
	u, ok := p2.parse("1700000000 1700000060 10.6.0.200 198.18.6.6 10.6.0.7 40000 443 6 900 9 2 ACCEPT")
	if !ok || u.src.String() != "10.6.0.7" || u.bytes != 900 || u.pkts != 9 || u.flags != fSYN {
		t.Fatalf("formato personalizzato: %+v", u)
	}
}
