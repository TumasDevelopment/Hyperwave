// Package store apre i database e applica le migrazioni di PostgreSQL e ClickHouse.
package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"hyperwave/internal/chx"
)

//go:embed pg/*.sql ch/*.sql
var files embed.FS

type migration struct {
	version int
	name    string
	body    string
}

func load(dir string) ([]migration, error) {
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil {
			return nil, fmt.Errorf("nome di migrazione non valido: %s", e.Name())
		}
		b, err := files.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{v, e.Name(), string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// OpenPG apre il pool di connessioni e verifica che il database risponda.
func OpenPG(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL non valida: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.ConnConfig.RuntimeParams["application_name"] = "hyperwave-hub"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PostgreSQL non raggiungibile: %w", err)
	}
	return pool, nil
}

// MigratePG applica le migrazioni mancanti in transazione, con un advisory lock:
// due processi avviati insieme non le applicano due volte.
func MigratePG(ctx context.Context, pool *pgxpool.Pool) (applied []string, err error) {
	migs, err := load("pg")
	if err != nil {
		return nil, err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	const lockID = 0x4857_4d49_4752 // "HWMIGR"
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	done := map[int]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		done[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, m := range migs {
		if done[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.body); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migrazione PostgreSQL %s: %w", m.name, err)
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

var statementEnd = regexp.MustCompile(`;[ \t]*(\r?\n|$)`)

// splitSQL divide un file in istruzioni: ClickHouse via HTTP ne accetta una per richiesta.
func splitSQL(body string) []string {
	var out []string
	for _, part := range statementEnd.Split(body, -1) {
		var lines []string
		for _, l := range strings.Split(part, "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "--") {
				lines = append(lines, l)
			}
		}
		if s := strings.TrimSpace(strings.Join(lines, "\n")); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// CHOptions sono i valori sostituiti nei file di ClickHouse.
type CHOptions struct {
	RetentionDays    int // dati grezzi
	AggRetentionDays int // aggregati ed eventi
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// MigrateCH crea il database (se manca) e applica le migrazioni mancanti.
func MigrateCH(ctx context.Context, ch *chx.Client, opt CHOptions) (applied []string, err error) {
	db := ch.DB
	if !identifier.MatchString(db) {
		return nil, fmt.Errorf("CLICKHOUSE_DB non valido: %q", db)
	}
	if opt.RetentionDays < 1 || opt.AggRetentionDays < opt.RetentionDays {
		return nil, fmt.Errorf("conservazione non valida: grezzi %d giorni, aggregati %d", opt.RetentionDays, opt.AggRetentionDays)
	}
	root := ch.WithDB("")
	if err := root.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+db, nil); err != nil {
		return nil, fmt.Errorf("creazione del database ClickHouse: %w", err)
	}
	if err := root.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+db+".hw_migrations (version UInt32, name String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY version", nil); err != nil {
		return nil, err
	}
	type row struct {
		Version int `json:"version"`
	}
	have, err := chx.Query[row](ctx, root, "SELECT version FROM "+db+".hw_migrations", nil)
	if err != nil {
		return nil, err
	}
	done := map[int]bool{}
	for _, r := range have {
		done[r.Version] = true
	}
	migs, err := load("ch")
	if err != nil {
		return nil, err
	}
	repl := strings.NewReplacer("{{db}}", db,
		"{{retention_days}}", strconv.Itoa(opt.RetentionDays),
		"{{agg_retention_days}}", strconv.Itoa(opt.AggRetentionDays))
	for _, m := range migs {
		if done[m.version] {
			continue
		}
		// Le istruzioni usano IF NOT EXISTS: se una migrazione si interrompe a metà, si può ripetere.
		for _, stmt := range splitSQL(repl.Replace(m.body)) {
			if err := root.Exec(ctx, stmt, nil); err != nil {
				return applied, fmt.Errorf("migrazione ClickHouse %s: %w", m.name, err)
			}
		}
		if err := root.Exec(ctx, "INSERT INTO "+db+".hw_migrations (version, name) VALUES ({v:UInt32}, {n:String})",
			map[string]string{"v": strconv.Itoa(m.version), "n": m.name}); err != nil {
			return applied, err
		}
		applied = append(applied, m.name)
	}
	return applied, applyRetention(ctx, root, db, opt)
}

// applyRetention aggiorna i TTL se HW_RETENTION_DAYS o HW_AGG_RETENTION_DAYS sono cambiati.
func applyRetention(ctx context.Context, ch *chx.Client, db string, opt CHOptions) error {
	type tbl struct {
		Name  string `json:"name"`
		Query string `json:"create_table_query"`
	}
	tables, err := chx.Query[tbl](ctx, ch, "SELECT name, create_table_query FROM system.tables WHERE database = {db:String} AND engine LIKE '%MergeTree'", map[string]string{"db": db})
	if err != nil {
		return err
	}
	ttl := map[string]string{
		"flows": "toDateTime(ts)", "dns": "toDateTime(ts)", "tls": "toDateTime(ts)", "http": "toDateTime(ts)", "rates": "toDateTime(ts)",
		"events": "toDateTime(ts)", "sessions": "toDateTime(ts)", "traffic_1m": "minute", "hosts_1h": "hour", "dns_1h": "hour",
	}
	for _, t := range tables {
		expr, ok := ttl[t.Name]
		if !ok {
			continue
		}
		days := opt.RetentionDays
		if expr != "toDateTime(ts)" || t.Name == "events" || t.Name == "sessions" {
			days = opt.AggRetentionDays
		}
		want := fmt.Sprintf("INTERVAL %d DAY", days)
		if strings.Contains(t.Query, want) {
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE %s.%s MODIFY TTL %s + %s", db, t.Name, expr, want)
		if err := ch.Exec(ctx, stmt, nil); err != nil {
			return fmt.Errorf("aggiornamento della conservazione di %s: %w", t.Name, err)
		}
	}
	return nil
}
