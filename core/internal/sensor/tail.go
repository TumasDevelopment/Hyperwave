package sensor

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"time"
)

// tailFile segue un file di testo come tail -F e chiama fn per ogni riga completa.
// Al primo avvio parte dalla fine (niente righe vecchie); se o.header è vero, prima legge
// le righe iniziali che cominciano con '#' (l'intestazione dei log TSV di Zeek). Dopo una
// rotazione o un troncamento il file nuovo si legge dall'inizio.
// tailOpts: header legge l'intestazione all'avvio; quiet non avvisa se il file manca (log facoltativi).
type tailOpts struct{ header, quiet bool }

func (r *Runner) tailFile(ctx context.Context, path string, o tailOpts, fn func(line string)) {
	var (
		f   *os.File
		rd  *bufio.Reader
		pos int64
	)
	open := func(fromEnd bool) bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		if f != nil {
			f.Close()
		}
		f, pos = nf, 0
		if fromEnd {
			if o.header {
				hr := bufio.NewReader(f)
				for {
					line, err := hr.ReadString('\n')
					if err != nil || !strings.HasPrefix(line, "#") {
						break
					}
					fn(strings.TrimRight(line, "\r\n"))
				}
			}
			pos, _ = f.Seek(0, io.SeekEnd)
		}
		rd = bufio.NewReaderSize(f, 256<<10)
		return true
	}
	if !open(true) && !o.quiet {
		r.log.Warn("file non ancora presente, lo attendo", "file", path)
	}
	var partial strings.Builder
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-t.C:
		}
		if f == nil {
			if open(false) && !o.quiet {
				r.log.Info("file trovato", "file", path)
			}
			continue
		}
		for {
			line, err := rd.ReadString('\n')
			pos += int64(len(line))
			if err != nil {
				partial.WriteString(line) // riga non ancora completa
				if partial.Len() > 4<<20 {
					partial.Reset() // riga assurda: si scarta invece di crescere senza limiti
				}
				break
			}
			if partial.Len() > 0 {
				line = partial.String() + line
				partial.Reset()
			}
			fn(strings.TrimRight(line, "\r\n"))
		}
		// rotazione: il percorso punta a un altro file, oppure il file è stato troncato
		st, err1 := os.Stat(path)
		cur, err2 := f.Stat()
		if err1 == nil && err2 == nil && (!os.SameFile(st, cur) || st.Size() < pos) {
			partial.Reset()
			open(false)
		}
	}
}
