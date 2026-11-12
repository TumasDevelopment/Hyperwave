package hub

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Con più istanze dell'hub la ricezione dei dati gira su tutte, mentre il motore delle regole,
// il correlatore, il controllo dei sensori, lo scaricamento degli elenchi e la pulizia girano su
// una sola: quella che tiene il lock consultivo di PostgreSQL. Il lock vive su una connessione
// dedicata, fuori dal pool: se la connessione cade il server lo rilascia e un'altra istanza lo prende.

const leaderLockID = 0x4857_4c45_4144 // "HWLEAD"

// leaderCheck è l'intervallo dei tentativi e dei controlli della connessione del lock.
const leaderCheck = 5 * time.Second

type leadership struct {
	url    string
	never  bool // HW_HUB_LEADER=never: istanza di sola ricezione
	onGain func()
	onLose func()

	mu    sync.Mutex
	conn  *pgx.Conn
	is    atomic.Bool
	since atomic.Int64 // ms dall'ultima elezione, 0 se non è capo
}

func newLeadership(url, mode string) (*leadership, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return &leadership{url: url}, nil
	case "never", "no", "0":
		return &leadership{url: url, never: true}, nil
	default:
		return nil, fmt.Errorf("HW_HUB_LEADER non valido: %q (auto o never)", mode)
	}
}

func (l *leadership) Is() bool { return l != nil && l.is.Load() }

// step prova a prendere il lock, oppure controlla che la connessione che lo tiene sia viva.
func (l *leadership) step(ctx context.Context) error {
	if l.never {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	if l.conn != nil {
		if _, err := l.conn.Exec(cctx, "SELECT 1"); err == nil {
			return nil
		} else {
			l.dropLocked()
			return fmt.Errorf("connessione del lock persa, l'istanza non è più capo: %w", err)
		}
	}

	cfg, err := pgx.ParseConfig(l.url)
	if err != nil {
		return err
	}
	cfg.RuntimeParams["application_name"] = "hyperwave-hub-leader"
	// il server si accorge presto di una connessione morta e libera il lock per le altre istanze
	cfg.RuntimeParams["tcp_keepalives_idle"] = "10"
	cfg.RuntimeParams["tcp_keepalives_interval"] = "5"
	cfg.RuntimeParams["tcp_keepalives_count"] = "3"
	conn, err := pgx.ConnectConfig(cctx, cfg)
	if err != nil {
		return err
	}
	var got bool
	if err := conn.QueryRow(cctx, "SELECT pg_try_advisory_lock($1)", leaderLockID).Scan(&got); err != nil || !got {
		conn.Close(context.Background())
		return err
	}
	l.conn = conn
	l.since.Store(time.Now().UnixMilli())
	l.is.Store(true)
	if l.onGain != nil {
		l.onGain()
	}
	return nil
}

func (l *leadership) dropLocked() {
	if l.conn != nil {
		l.conn.Close(context.Background())
		l.conn = nil
	}
	if l.is.Swap(false) {
		l.since.Store(0)
		if l.onLose != nil {
			l.onLose()
		}
	}
}

// release lascia il lock all'arresto: un'altra istanza diventa capo senza aspettare.
func (l *leadership) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		l.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", leaderLockID)
		cancel()
	}
	l.dropLocked()
}
