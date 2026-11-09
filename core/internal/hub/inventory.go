package hub

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"hyperwave/internal/model"
	"hyperwave/internal/netx"
)

// Inventory raccoglie in memoria ciò che si vede dei dispositivi interni e lo salva ogni 10 secondi.
type Inventory struct {
	h *Hub

	mu      sync.Mutex
	pending map[string]*obs   // IP → osservazioni dall'ultimo salvataggio
	macOf   map[string]string // IP → MAC, da ARP e DHCP
	newMAC  map[string]string // MAC scoperti dall'ultimo salvataggio
	exposed map[string]bool   // "id/proto/porta" dei servizi già raggiunti da internet

	learnFrom time.Time // primo dato dell'inventario: da qui parte l'apprendimento
}

type obs struct {
	ip, mac, hostname, vendor, os, typ string
	vlan                               uint16
	sensor                             int64
	first, last                        int64
	bytesOut, bytesIn, flows           uint64
	backfill                           bool // tutte le osservazioni vengono da dati storici
	services                           map[svcKey]*svcObs
}

type svcKey struct {
	proto string
	port  uint16
}

type svcObs struct {
	app         string
	first, last int64
	flows       uint64
	external    bool
}

func newInventory(h *Hub) *Inventory {
	return &Inventory{h: h, pending: map[string]*obs{}, macOf: map[string]string{}, newMAC: map[string]string{}, exposed: map[string]bool{}}
}

func (inv *Inventory) load(ctx context.Context) error {
	rows, err := inv.h.pg.Query(ctx, "SELECT ip, mac FROM devices WHERE mac <> '' AND ip <> '' ORDER BY last_seen")
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip, mac string
		if err := rows.Scan(&ip, &mac); err != nil {
			rows.Close()
			return err
		}
		inv.macOf[ip] = mac
	}
	rows.Close()
	rows, err = inv.h.pg.Query(ctx, "SELECT device_id, proto, port FROM device_services WHERE external")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var proto string
		var port int
		if err := rows.Scan(&id, &proto, &port); err != nil {
			rows.Close()
			return err
		}
		inv.exposed[fmt.Sprintf("%d/%s/%d", id, proto, port)] = true
	}
	rows.Close()
	var first *time.Time
	if err := inv.h.pg.QueryRow(ctx, "SELECT min(first_seen) FROM devices").Scan(&first); err != nil {
		return err
	}
	if first != nil {
		inv.learnFrom = *first
	}
	return nil
}

func normMAC(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return ""
	}
	if hw.String() == "00:00:00:00:00:00" || hw.String() == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return hw.String()
}

func (inv *Inventory) get(ip string, sensor, ts int64, backfill bool) *obs {
	o := inv.pending[ip]
	if o == nil {
		o = &obs{ip: ip, sensor: sensor, first: ts, last: ts, backfill: backfill, services: map[svcKey]*svcObs{}}
		inv.pending[ip] = o
	}
	o.first, o.last = min(o.first, ts), max(o.last, ts)
	o.backfill = o.backfill && backfill
	o.sensor = sensor
	return o
}

// add registra le osservazioni di un batch. Contano solo gli indirizzi interni.
func (inv *Inventory) add(s *Sensor, b *model.Batch, nets netx.Nets) {
	isDev := func(ip string) bool { return nets.Contains(ip) && netx.Unicast(ip) }
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for _, hst := range b.Hosts {
		if !isDev(hst.IP) {
			continue
		}
		o := inv.get(hst.IP, s.ID, hst.TS, b.Backfill)
		if mac := normMAC(hst.MAC); mac != "" {
			o.mac = mac
			if inv.macOf[hst.IP] != mac {
				inv.macOf[hst.IP] = mac
				inv.newMAC[hst.IP] = mac
			}
		}
		o.hostname = firstNonEmpty(hst.Hostname, o.hostname)
		o.vendor = firstNonEmpty(hst.Vendor, o.vendor)
		o.os = firstNonEmpty(hst.OS, o.os)
		o.typ = firstNonEmpty(hst.Type, o.typ)
		if hst.VLAN != 0 {
			o.vlan = hst.VLAN
		}
	}
	for i := range b.Flows {
		f := &b.Flows[i]
		if isDev(f.SrcIP) {
			o := inv.get(f.SrcIP, s.ID, f.TS, b.Backfill)
			o.bytesOut += f.BytesOut
			o.bytesIn += f.BytesIn
			o.flows++
			if f.VLAN != 0 {
				o.vlan = f.VLAN
			}
		}
		// la destinazione diventa un dispositivo solo se ha risposto: niente fantasmi dalle scansioni
		if f.Est && isDev(f.DstIP) {
			o := inv.get(f.DstIP, s.ID, f.TS, b.Backfill)
			o.bytesOut += f.BytesIn
			o.bytesIn += f.BytesOut
			o.flows++
			if f.DstPort != 0 && (f.Proto == "TCP" || f.Proto == "UDP") {
				k := svcKey{f.Proto, f.DstPort}
				sv := o.services[k]
				if sv == nil {
					sv = &svcObs{first: f.TS, last: f.TS}
					o.services[k] = sv
				}
				sv.first, sv.last = min(sv.first, f.TS), max(sv.last, f.TS)
				sv.flows++
				sv.app = firstNonEmpty(f.App, sv.app)
				if !nets.Contains(f.SrcIP) {
					sv.external = true
				}
			}
		}
	}
}

// guessType deduce il tipo dai servizi offerti, se il sensore non l'ha indicato.
func guessType(o *obs) string {
	has := func(proto string, ports ...uint16) bool {
		for _, p := range ports {
			if _, ok := o.services[svcKey{proto, p}]; ok {
				return true
			}
		}
		return false
	}
	switch {
	case has("TCP", 88) && has("TCP", 389):
		return "Domain controller"
	case has("TCP", 9100, 631):
		return "Stampante"
	case has("TCP", 554):
		return "Telecamera"
	case has("TCP", 1433, 3306, 5432, 1521):
		return "Database"
	case has("TCP", 445, 2049):
		return "File server"
	case has("UDP", 53) || has("TCP", 53):
		return "Server DNS"
	case has("TCP", 80, 443, 8080, 8443):
		return "Server web"
	case has("TCP", 22, 3389):
		return "Server"
	}
	return ""
}

// flush salva le osservazioni accumulate e genera gli allarmi dell'inventario.
func (inv *Inventory) flush(ctx context.Context) error {
	inv.mu.Lock()
	pend, newMAC := inv.pending, inv.newMAC
	inv.pending, inv.newMAC = map[string]*obs{}, map[string]string{}
	macOf := make(map[string]string, len(pend))
	for ip := range pend {
		if m, ok := inv.macOf[ip]; ok {
			macOf[ip] = m
		}
	}
	inv.mu.Unlock()
	if len(pend) == 0 {
		return nil
	}
	h := inv.h
	for ip, mac := range newMAC {
		if err := inv.mergeIP(ctx, ip, mac); err != nil {
			h.log.Warn("unione dispositivo per MAC", "ip", ip, "err", err)
		}
	}
	if inv.learnFrom.IsZero() {
		for _, o := range pend {
			if t := time.UnixMilli(o.first); inv.learnFrom.IsZero() || t.Before(inv.learnFrom) {
				inv.learnFrom = t
			}
		}
	}
	learned := time.Since(inv.learnFrom) >= h.state.Learning()

	list := make([]*obs, 0, len(pend))
	batch := &pgx.Batch{}
	for _, o := range pend {
		mac := firstNonEmpty(o.mac, macOf[o.ip])
		key := "ip:" + o.ip
		if mac != "" {
			key = "mac:" + mac
		}
		vendor := o.vendor
		if vendor == "" && mac != "" {
			vendor = h.enr.Vendor(mac)
		}
		typ := firstNonEmpty(o.typ, guessType(o))
		list = append(list, o)
		batch.Queue(`INSERT INTO devices (key, mac, ip, ips, hostname, vendor, os, type, vlan, sensor_id, first_seen, last_seen, bytes_out, bytes_in, flows)
			VALUES ($1, $2, $3, ARRAY[$3], $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (key) DO UPDATE SET
				mac = CASE WHEN EXCLUDED.mac <> '' THEN EXCLUDED.mac ELSE devices.mac END,
				ip = CASE WHEN EXCLUDED.last_seen >= devices.last_seen THEN EXCLUDED.ip ELSE devices.ip END,
				ips = CASE WHEN EXCLUDED.ip = ANY(devices.ips) THEN devices.ips ELSE (ARRAY[EXCLUDED.ip] || devices.ips)[1:16] END,
				hostname = COALESCE(NULLIF(EXCLUDED.hostname, ''), devices.hostname),
				vendor = COALESCE(NULLIF(EXCLUDED.vendor, ''), devices.vendor),
				os = COALESCE(NULLIF(EXCLUDED.os, ''), devices.os),
				type = CASE WHEN devices.type = '' THEN EXCLUDED.type ELSE devices.type END,
				vlan = CASE WHEN EXCLUDED.vlan <> 0 THEN EXCLUDED.vlan ELSE devices.vlan END,
				sensor_id = EXCLUDED.sensor_id,
				first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
				bytes_out = devices.bytes_out + EXCLUDED.bytes_out,
				bytes_in = devices.bytes_in + EXCLUDED.bytes_in,
				flows = devices.flows + EXCLUDED.flows
			RETURNING id, (xmax = 0), COALESCE(NULLIF(name, ''), NULLIF(hostname, ''), ''), vendor, type`,
			key, mac, o.ip, o.hostname, vendor, o.os, typ, int(o.vlan), o.sensor,
			time.UnixMilli(o.first), time.UnixMilli(o.last), int64(o.bytesOut), int64(o.bytesIn), int64(o.flows))
	}
	type devResult struct {
		id                int64
		inserted          bool
		name, vendor, typ string
	}
	res := make([]devResult, len(list))
	br := h.pg.SendBatch(ctx, batch)
	for i := range list {
		if err := br.QueryRow().Scan(&res[i].id, &res[i].inserted, &res[i].name, &res[i].vendor, &res[i].typ); err != nil {
			br.Close()
			return fmt.Errorf("salvataggio dispositivo %s: %w", list[i].ip, err)
		}
	}
	if err := br.Close(); err != nil {
		return err
	}

	// servizi offerti
	type svcRef struct {
		o  *obs
		d  devResult
		k  svcKey
		sv *svcObs
	}
	var refs []svcRef
	sb := &pgx.Batch{}
	for i, o := range list {
		if res[i].name != "" {
			h.enr.setName(o.ip, ipInfo{res[i].id, res[i].name})
		}
		for k, sv := range o.services {
			refs = append(refs, svcRef{o, res[i], k, sv})
			sb.Queue(`INSERT INTO device_services (device_id, proto, port, app, first_seen, last_seen, flows, external)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (device_id, proto, port) DO UPDATE SET
					app = COALESCE(NULLIF(EXCLUDED.app, ''), device_services.app),
					first_seen = LEAST(device_services.first_seen, EXCLUDED.first_seen),
					last_seen = GREATEST(device_services.last_seen, EXCLUDED.last_seen),
					flows = device_services.flows + EXCLUDED.flows,
					external = device_services.external OR EXCLUDED.external
				RETURNING (xmax = 0)`,
				res[i].id, k.proto, int(k.port), sv.app, time.UnixMilli(sv.first), time.UnixMilli(sv.last), int64(sv.flows), sv.external)
		}
	}
	newSvc := make([]bool, len(refs))
	if len(refs) > 0 {
		br := h.pg.SendBatch(ctx, sb)
		for i := range refs {
			if err := br.QueryRow().Scan(&newSvc[i]); err != nil {
				br.Close()
				return fmt.Errorf("salvataggio servizi: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	// allarmi: solo su dati live e dopo il periodo di apprendimento
	sensitive := h.state.Sensitive()
	for i, o := range list {
		d := res[i]
		if !d.inserted || o.backfill || !learned {
			continue
		}
		sev := "medium"
		where := ""
		if sensitive.Contains(o.ip) {
			sev, where = "high", " in una rete sensibile"
		}
		label := o.ip
		if d.name != "" {
			label = d.name + " (" + o.ip + ")"
		}
		desc := strings.TrimSpace(strings.Join([]string{d.vendor, d.typ}, " · "))
		desc = strings.Trim(desc, " ·")
		summary := "È comparso" + where + " un dispositivo mai visto prima: " + label + "."
		if desc != "" {
			summary += " Riconosciuto come: " + desc + "."
		}
		h.raise(ctx, Alert{
			Rule: "new_device", Severity: sev, DedupKey: fmt.Sprintf("new_device|%d", d.id), TS: time.UnixMilli(o.first),
			Title: "Nuovo dispositivo: " + label, Summary: summary, Src: o.ip, DeviceID: d.id, SensorID: o.sensor,
			Detail: map[string]any{"mac": firstNonEmpty(o.mac, macOf[o.ip]), "vendor": d.vendor, "type": d.typ, "vlan": o.vlan},
		})
	}
	for i, r := range refs {
		label := r.o.ip
		if r.d.name != "" {
			label = r.d.name + " (" + r.o.ip + ")"
		}
		port := fmt.Sprintf("%s/%d", r.k.proto, r.k.port)
		app := ""
		if r.sv.app != "" {
			app = " (" + r.sv.app + ")"
		}
		ek := fmt.Sprintf("%d/%s/%d", r.d.id, r.k.proto, r.k.port)
		if r.sv.external && !inv.exposed[ek] {
			inv.exposed[ek] = true
			if learned && !r.o.backfill {
				h.raise(ctx, Alert{
					Rule: "exposed_service", DedupKey: "exposed_service|" + ek, TS: time.UnixMilli(r.sv.first),
					Title: "Servizio raggiungibile da internet: " + label + " " + port + app, Src: r.o.ip, DeviceID: r.d.id, SensorID: r.o.sensor,
					Summary: "Una connessione da internet verso " + label + " sulla porta " + port + app + " ha ricevuto risposta. Se il servizio non deve essere pubblico, va chiuso sul firewall.",
					Detail:  map[string]any{"proto": r.k.proto, "port": r.k.port, "app": r.sv.app},
				})
			}
			continue
		}
		if newSvc[i] && !r.d.inserted && learned && !r.o.backfill && r.k.port < 49152 {
			h.raise(ctx, Alert{
				Rule: "new_service", DedupKey: "new_service|" + ek, TS: time.UnixMilli(r.sv.first),
				Title: "Nuovo servizio: " + label + " " + port + app, Src: r.o.ip, DeviceID: r.d.id, SensorID: r.o.sensor,
				Summary: label + " ha iniziato a rispondere sulla porta " + port + app + ", che finora non offriva.",
				Detail:  map[string]any{"proto": r.k.proto, "port": r.k.port, "app": r.sv.app},
			})
		}
	}
	return nil
}

// mergeIP trasforma un dispositivo noto solo per IP in uno con MAC, oppure lo unisce a quello col MAC.
func (inv *Inventory) mergeIP(ctx context.Context, ip, mac string) error {
	return pgx.BeginFunc(ctx, inv.h.pg, func(tx pgx.Tx) error {
		var ipID int64
		err := tx.QueryRow(ctx, "SELECT id FROM devices WHERE key = $1 FOR UPDATE", "ip:"+ip).Scan(&ipID)
		if err == pgx.ErrNoRows {
			return nil
		} else if err != nil {
			return err
		}
		var macID int64
		err = tx.QueryRow(ctx, "SELECT id FROM devices WHERE key = $1 FOR UPDATE", "mac:"+mac).Scan(&macID)
		if err == pgx.ErrNoRows {
			_, err = tx.Exec(ctx, "UPDATE devices SET key = $2, mac = $3 WHERE id = $1", ipID, "mac:"+mac, mac)
			return err
		} else if err != nil {
			return err
		}
		stmts := []string{
			`INSERT INTO device_services (device_id, proto, port, app, first_seen, last_seen, flows, external)
				SELECT $2, proto, port, app, first_seen, last_seen, flows, external FROM device_services WHERE device_id = $1
				ON CONFLICT (device_id, proto, port) DO UPDATE SET
					first_seen = LEAST(device_services.first_seen, EXCLUDED.first_seen),
					last_seen = GREATEST(device_services.last_seen, EXCLUDED.last_seen),
					flows = device_services.flows + EXCLUDED.flows,
					external = device_services.external OR EXCLUDED.external`,
			`UPDATE alerts SET device_id = $2 WHERE device_id = $1`,
			`UPDATE devices d SET first_seen = LEAST(d.first_seen, o.first_seen), last_seen = GREATEST(d.last_seen, o.last_seen),
				bytes_out = d.bytes_out + o.bytes_out, bytes_in = d.bytes_in + o.bytes_in, flows = d.flows + o.flows,
				name = COALESCE(NULLIF(d.name, ''), o.name), owner = COALESCE(NULLIF(d.owner, ''), o.owner),
				notes = COALESCE(NULLIF(d.notes, ''), o.notes), tags = d.tags || o.tags, approved = d.approved OR o.approved
				FROM devices o WHERE o.id = $1 AND d.id = $2`,
			`DELETE FROM devices WHERE id = $1`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s, ipID, macID); err != nil {
				return err
			}
		}
		return nil
	})
}
