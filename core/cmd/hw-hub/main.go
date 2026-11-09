// hw-hub riceve i dati dei sensori, li analizza e li rende disponibili all'interfaccia.
//
//	hw-hub serve                              avvia l'hub
//	hw-hub migrate                            applica solo le migrazioni dei database
//	hw-hub sensor-add -name N [-site S]       registra un sensore e stampa il token una volta
//	hw-hub sensor-add -name N -env-file F     come sopra, ma scrive il token in F (HW_SENSOR_TOKEN) senza mostrarlo
//	hw-hub version
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
	"time"

	"hyperwave/internal/chx"
	"hyperwave/internal/env"
	"hyperwave/internal/hub"
	"hyperwave/internal/store"
	"hyperwave/internal/version"
)

func main() {
	if err := env.Load(env.Str("HW_ENV_FILE", ".env")); err != nil {
		fmt.Fprintln(os.Stderr, "lettura .env:", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "serve":
		err = serve(ctx, log)
	case "migrate":
		err = migrate(ctx, log)
	case "sensor-add":
		err = sensorAdd(ctx, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("hw-hub", version.Version)
	default:
		fmt.Fprintln(os.Stderr, "uso: hw-hub serve | migrate | sensor-add -name NOME [-site SEDE] [-env-file FILE] | version")
		os.Exit(2)
	}
	if err != nil {
		log.Error("errore", "err", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	if strings.EqualFold(env.Str("HW_LOG_LEVEL", ""), "debug") {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func serve(ctx context.Context, log *slog.Logger) error {
	cfg := hub.ConfigFromEnv()
	var h *hub.Hub
	var err error
	// all'avvio della macchina i database possono arrivare dopo: si riprova per 2 minuti
	for attempt := 1; ; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		h, err = hub.Connect(cctx, cfg, log)
		cancel()
		if err == nil {
			break
		}
		if attempt >= 12 || ctx.Err() != nil {
			return err
		}
		log.Warn("connessione ai servizi non riuscita, nuovo tentativo tra 10 secondi", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	defer h.Close()
	return h.Run(ctx)
}

func migrate(ctx context.Context, log *slog.Logger) error {
	cfg := hub.ConfigFromEnv()
	pg, err := store.OpenPG(ctx, cfg.DatabaseURL, 2)
	if err != nil {
		return err
	}
	defer pg.Close()
	a, err := store.MigratePG(ctx, pg)
	if err != nil {
		return err
	}
	log.Info("PostgreSQL aggiornato", "applicate", a)
	ch := chx.New(cfg.ClickHouseURL, cfg.ClickHouseDB, cfg.ClickHouseUser, cfg.ClickHousePass)
	b, err := store.MigrateCH(ctx, ch, store.CHOptions{RetentionDays: cfg.RetentionDays, AggRetentionDays: cfg.AggRetentionDays})
	if err != nil {
		return err
	}
	log.Info("ClickHouse aggiornato", "applicate", b)
	return nil
}

func sensorAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sensor-add", flag.ExitOnError)
	name := fs.String("name", "", "nome del sensore (obbligatorio)")
	site := fs.String("site", "", "sede o rete osservata")
	envFile := fs.String("env-file", "", "scrive il token in questo file come HW_SENSOR_TOKEN, senza stamparlo")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("indicare -name")
	}
	cfg := hub.ConfigFromEnv()
	pg, err := store.OpenPG(ctx, cfg.DatabaseURL, 2)
	if err != nil {
		return err
	}
	defer pg.Close()
	if _, err := store.MigratePG(ctx, pg); err != nil {
		return err
	}
	who := "riga di comando"
	if u := os.Getenv("USER"); u != "" {
		who += " (" + u + ")"
	}
	id, token, err := hub.AddSensor(ctx, pg, *name, *site, who)
	if err != nil {
		return err
	}
	if *envFile != "" {
		if err := setEnvVar(*envFile, "HW_SENSOR_TOKEN", token); err != nil {
			pg.Exec(ctx, "DELETE FROM sensors WHERE id = $1", id)
			return fmt.Errorf("scrittura del token in %s: %w", *envFile, err)
		}
		fmt.Printf("Sensore %q registrato (id %d). Token scritto in %s come HW_SENSOR_TOKEN.\n", *name, id, *envFile)
		return nil
	}
	fmt.Printf("Sensore %q registrato (id %d).\n\nToken (viene mostrato solo ora):\n%s\n\nSul sensore va in HW_SENSOR_TOKEN.\n", *name, id, token)
	return nil
}

// setEnvVar sostituisce o aggiunge KEY=VALUE mantenendo i permessi del file (600 se nuovo).
func setEnvVar(path, key, value string) error {
	mode := os.FileMode(0o600)
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
		lines = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	} else if !os.IsNotExist(err) {
		return err
	}
	found := false
	for i, l := range lines {
		if strings.HasPrefix(l, key+"=") {
			lines[i], found = key+"="+value, true
		}
	}
	if !found {
		lines = append(lines, key+"="+value)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
