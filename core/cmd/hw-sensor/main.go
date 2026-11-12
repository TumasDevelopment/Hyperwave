// hw-sensor osserva una rete e invia all'hub flussi, metadati e contatori.
//
//	hw-sensor -mode capture -iface eth1        cattura da un'interfaccia (porta SPAN o TAP)
//	hw-sensor -mode pcap -file traccia.pcapng   analizza uno o più file (separati da virgole)
//	hw-sensor -mode flow                       riceve NetFlow v5/v9, IPFIX e sFlow da router e switch
//	hw-sensor -mode zeek                       segue i log di Zeek (HW_ZEEK_DIR); con -file li importa
//	hw-sensor -mode vpcflow -file log.gz       importa i VPC Flow Logs di AWS
//	hw-sensor -mode demo                       genera il traffico dimostrativo di "Azienda Demo"
//
// Il token si legge solo da HW_SENSOR_TOKEN (variabile o file .env), mai dalla riga di comando,
// così non compare nell'elenco dei processi.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"hyperwave/internal/env"
	"hyperwave/internal/sensor"
	"hyperwave/internal/version"
)

func main() {
	envFile := env.Str("HW_ENV_FILE", ".env")
	if err := env.Load(envFile); err != nil {
		fmt.Fprintln(os.Stderr, "lettura .env:", err)
		os.Exit(1)
	}
	mode := flag.String("mode", env.Str("HW_SENSOR_MODE", "capture"), "demo | capture | pcap | flow | zeek | vpcflow")
	iface := flag.String("iface", env.Str("HW_IFACE", ""), "interfacce da osservare, separate da virgole")
	file := flag.String("file", "", "file da analizzare o importare (pcap, log di Zeek, VPC Flow Logs), separati da virgole")
	hubURL := flag.String("hub", env.Str("HW_HUB_URL", "http://127.0.0.1:3121"), "indirizzo dell'hub")
	showVersion := flag.Bool("version", false, "mostra la versione")
	flag.Parse()
	if *showVersion {
		fmt.Println("hw-sensor", version.Version)
		return
	}

	level := slog.LevelInfo
	if strings.EqualFold(env.Str("HW_LOG_LEVEL", ""), "debug") {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg := sensor.Config{
		HubURL:       *hubURL,
		Token:        env.Str("HW_SENSOR_TOKEN", ""),
		CAFile:       env.Str("HW_HUB_CA", ""),
		Mode:         *mode,
		Ifaces:       list(*iface),
		Files:        list(*file),
		Timezone:     env.Str("HW_TZ", "Europe/Rome"),
		Snaplen:      env.Int("HW_SNAPLEN", 65536),
		Promisc:      env.Bool("HW_PROMISC", true),
		IgnoreNets:   env.Str("HW_CAPTURE_IGNORE", ""),
		SuricataEve:  env.Str("HW_SURICATA_EVE", ""),
		MaxPending:   env.Int("HW_MAX_PENDING", 500_000),
		SpoolDir:     spoolDir(),
		SpoolMaxMB:   env.Int("HW_SPOOL_MAX_MB", 2048),
		FlowListen:   list(env.Str("HW_FLOW_LISTEN", "0.0.0.0:2055,0.0.0.0:6343")),
		FlowAllow:    env.Str("HW_FLOW_ALLOW", ""),
		FlowSampling: env.Int("HW_FLOW_SAMPLING", 0),
		ZeekDir:      env.Str("HW_ZEEK_DIR", "/opt/zeek/logs/current"),
		PcapDir:      pcapDir(),
		PcapRingMB:   env.Int("HW_PCAP_RING_MB", 4096),
		PcapHours:    float64(env.Int("HW_PCAP_RING_MINUTES", 120)) / 60,
		PcapExportMB: env.Int("HW_PCAP_EXPORT_MB", 200),
	}
	r, err := sensor.New(cfg, log)
	if err != nil {
		log.Error("configurazione non valida", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := r.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("errore", "err", err)
		os.Exit(1)
	}
}

// spoolDir: HW_SPOOL_DIR, altrimenti la cartella di stato data da systemd (StateDirectory=).
// "off" disattiva la coda su disco.
func spoolDir() string {
	dir := env.Str("HW_SPOOL_DIR", "")
	if strings.EqualFold(dir, "off") {
		return ""
	}
	if dir == "" {
		if state := os.Getenv("STATE_DIRECTORY"); state != "" {
			dir = filepath.Join(strings.Split(state, ":")[0], "coda")
		}
	}
	return dir
}

// pcapDir: il buffer dei pacchetti conserva dati personali e occupa disco, quindi è spento finché
// non lo si chiede: HW_PCAP_DIR=on usa la cartella di stato di systemd, altrimenti un percorso.
func pcapDir() string {
	dir := strings.TrimSpace(env.Str("HW_PCAP_DIR", ""))
	switch strings.ToLower(dir) {
	case "", "off":
		return ""
	case "on":
		if state := os.Getenv("STATE_DIRECTORY"); state != "" {
			return filepath.Join(strings.Split(state, ":")[0], "pacchetti")
		}
		return ""
	}
	return dir
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
