package sensor

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hyperwave/internal/model"
)

// La coda su disco conserva i lotti che l'hub non ha potuto ricevere, così un'interruzione
// di rete o un riavvio del sensore non fanno perdere dati.
//
// Ogni lotto è un file "<nanosecondi>-<sequenza>-<record>.hws": JSON compresso con gzip e
// cifrato con AES-256-GCM. La chiave deriva dal token del sensore (HKDF-SHA256): chi copia
// la cartella senza il token non legge il traffico. Rinnovando il token, i file scritti con
// quello vecchio non si possono più leggere e vengono scartati.
//
// La scrittura è atomica (file temporaneo, fsync, rename): un'interruzione di corrente
// lascia al massimo un .tmp, che si cancella all'avvio.

const (
	spoolExt     = ".hws"
	spoolMagic   = "HWS1"
	spoolState   = "stato.json"
	spoolKeyInfo = "hyperwave sensor spool v1"
)

var errSpoolCorrupt = errors.New("file della coda illeggibile")

type spoolFile struct {
	name    string
	size    int64
	records int
}

type spool struct {
	dir      string
	maxBytes int64
	aead     cipher.AEAD

	mu      sync.Mutex
	files   []spoolFile // dal più vecchio al più recente
	bytes   int64
	seq     uint64
	dropped atomic.Int64 // record scartati per spazio o file illeggibili
}

func openSpool(dir string, maxBytes int64, token string) (*spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cartella della coda: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("permessi della cartella della coda: %w", err)
	}
	key, err := hkdf.Key(sha256.New, []byte(token), nil, spoolKeyInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &spool{dir: dir, maxBytes: maxBytes, aead: aead}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".tmp"):
			os.Remove(filepath.Join(dir, name))
		case strings.HasSuffix(name, spoolExt):
			info, err := e.Info()
			if err != nil {
				continue
			}
			s.files = append(s.files, spoolFile{name: name, size: info.Size(), records: recordsOf(name)})
			s.bytes += info.Size()
		}
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].name < s.files[j].name })
	return s, nil
}

// recordsOf legge il numero di record dal nome del file, per contare gli scarti senza decifrare.
func recordsOf(name string) int {
	parts := strings.Split(strings.TrimSuffix(name, spoolExt), "-")
	if len(parts) != 3 {
		return 0
	}
	n, _ := strconv.Atoi(parts[2])
	return n
}

func (s *spool) seal(b *model.Batch) ([]byte, error) {
	var plain bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&plain, gzip.BestSpeed)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(spoolMagic)+len(nonce)+plain.Len()+s.aead.Overhead())
	out = append(out, spoolMagic...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plain.Bytes(), []byte(spoolMagic)), nil
}

func (s *spool) open(data []byte) (*model.Batch, error) {
	ns := s.aead.NonceSize()
	if len(data) < len(spoolMagic)+ns+s.aead.Overhead() || string(data[:len(spoolMagic)]) != spoolMagic {
		return nil, errSpoolCorrupt
	}
	nonce := data[len(spoolMagic) : len(spoolMagic)+ns]
	plain, err := s.aead.Open(nil, nonce, data[len(spoolMagic)+ns:], []byte(spoolMagic))
	if err != nil {
		return nil, errSpoolCorrupt
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, errSpoolCorrupt
	}
	var b model.Batch
	if err := json.NewDecoder(io.LimitReader(zr, 1<<30)).Decode(&b); err != nil {
		return nil, errSpoolCorrupt
	}
	return &b, nil
}

// put salva un lotto. Se lo spazio supera il limite, scarta i file più vecchi.
func (s *spool) put(b *model.Batch) error {
	if b == nil || b.Len() == 0 {
		return nil
	}
	data, err := s.seal(b)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	name := fmt.Sprintf("%019d-%06d-%d%s", time.Now().UnixNano(), s.seq%1_000_000, b.Len(), spoolExt)
	if err := writeAtomic(s.dir, name, data); err != nil {
		return err
	}
	s.files = append(s.files, spoolFile{name: name, size: int64(len(data)), records: b.Len()})
	s.bytes += int64(len(data))
	for s.bytes > s.maxBytes && len(s.files) > 1 {
		old := s.files[0]
		os.Remove(filepath.Join(s.dir, old.name))
		s.files = s.files[1:]
		s.bytes -= old.size
		s.dropped.Add(int64(old.records))
	}
	return nil
}

func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "lotto-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// oldest legge il lotto più vecchio senza toglierlo dalla coda.
// Un file illeggibile (token rinnovato, disco danneggiato) viene scartato e si passa al successivo.
func (s *spool) oldest() (string, *model.Batch, bool) {
	for {
		s.mu.Lock()
		if len(s.files) == 0 {
			s.mu.Unlock()
			return "", nil, false
		}
		f := s.files[0]
		s.mu.Unlock()
		data, err := os.ReadFile(filepath.Join(s.dir, f.name))
		if err == nil {
			var b *model.Batch
			if b, err = s.open(data); err == nil {
				return f.name, b, true
			}
		}
		s.dropped.Add(int64(f.records))
		s.remove(f.name)
	}
}

func (s *spool) remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.files {
		if f.name == name {
			os.Remove(filepath.Join(s.dir, name))
			s.bytes -= f.size
			s.files = append(s.files[:i], s.files[i+1:]...)
			return
		}
	}
}

func (s *spool) stats() (files int, bytes int64, records int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.files {
		records += f.records
	}
	return len(s.files), s.bytes, records
}

// savedState è l'ultimo stato ricevuto dall'hub, per ripartire anche se all'avvio l'hub non risponde.
type savedState struct {
	Live         bool     `json:"live"`
	InternalNets []string `json:"internal_nets"`
	Saved        int64    `json:"saved"`
}

func (s *spool) saveState(st savedState) error {
	st.Saved = time.Now().UnixMilli()
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, spoolState, data)
}

func (s *spool) loadState() (savedState, bool) {
	var st savedState
	data, err := os.ReadFile(filepath.Join(s.dir, spoolState))
	if err != nil || json.Unmarshal(data, &st) != nil {
		return st, false
	}
	return st, true
}
