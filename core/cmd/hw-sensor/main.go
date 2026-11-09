// hw-sensor osserva una rete e invia all'hub flussi, metadati e contatori.
//
//	hw-sensor -mode capture -iface eth1        cattura da un'interfaccia (porta SPAN o TAP)
//	hw-sensor -mode pcap -file traccia.pcapng   analizza uno o più file (separati da virgole)
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
	mode := flag.String("mode", env.Str("HW_SENSOR_MODE", "capture"), "demo | capture | pcap")
	iface := flag.String("iface", env.Str("HW_IFACE", ""), "interfacce da osservare, separate da virgole")
	file := flag.String("file", "", "file pcap o pcapng da analizzare, separati da virgole")
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
		HubURL:      *hubURL,
		Token:       env.Str("HW_SENSOR_TOKEN", ""),
		CAFile:      env.Str("HW_HUB_CA", ""),
		Mode:        *mode,
		Ifaces:      list(*iface),
		Files:       list(*file),
		Timezone:    env.Str("HW_TZ", "Europe/Rome"),
		Snaplen:     env.Int("HW_SNAPLEN", 65536),
		Promisc:     env.Bool("HW_PROMISC", true),
		IgnoreNets:  env.Str("HW_CAPTURE_IGNORE", ""),
		SuricataEve: env.Str("HW_SURICATA_EVE", ""),
		MaxPending:  env.Int("HW_MAX_PENDING", 500_000),
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

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
