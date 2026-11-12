package sensor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"hyperwave/internal/model"
	"hyperwave/internal/version"
)

// Client parla con l'hub: heartbeat e invio dei batch.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// ErrUnauthorized indica un token sbagliato o un sensore disattivato: riprovare subito non serve.
var ErrUnauthorized = errors.New("l'hub ha rifiutato il token del sensore")

func NewClient(base, token, caFile string) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 4
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("lettura HW_HUB_CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("HW_HUB_CA non contiene certificati PEM validi")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Timeout: 90 * time.Second, Transport: tr}}, nil
}

func (c *Client) post(ctx context.Context, path string, v any) (model.HubReply, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return model.HubReply{}, err
	}
	zw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, &buf)
	if err != nil {
		return model.HubReply{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "hw-sensor/"+version.Version)
	res, err := c.http.Do(req)
	if err != nil {
		return model.HubReply{}, err
	}
	defer res.Body.Close()
	var rep model.HubReply
	json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&rep)
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return rep, ErrUnauthorized
	case res.StatusCode != http.StatusOK:
		return rep, fmt.Errorf("hub %d: %s", res.StatusCode, rep.Error)
	}
	return rep, nil
}

func (c *Client) Heartbeat(ctx context.Context, hb model.Heartbeat) (model.HubReply, error) {
	return c.post(ctx, "/v1/heartbeat", hb)
}

// SendOnce invia un batch con un solo tentativo: la coda su disco gestisce i nuovi tentativi.
func (c *Client) SendOnce(ctx context.Context, b *model.Batch) (model.HubReply, error) {
	return c.post(ctx, "/v1/ingest", b)
}

// isPermanent indica un rifiuto che non cambia riprovando: lotto malformato o troppo grande.
func isPermanent(err error) bool {
	return err != nil && (strings.HasPrefix(err.Error(), "hub 400") || strings.HasPrefix(err.Error(), "hub 413"))
}

// Send invia un batch e riprova con attese crescenti finché riesce o ctx viene annullato.
func (c *Client) Send(ctx context.Context, b *model.Batch) (model.HubReply, error) {
	wait := time.Second
	for {
		rep, err := c.post(ctx, "/v1/ingest", b)
		if err == nil {
			return rep, nil
		}
		// un batch rifiutato perché malformato non va ripetuto all'infinito
		if isPermanent(err) {
			return rep, err
		}
		select {
		case <-ctx.Done():
			return rep, ctx.Err()
		case <-time.After(wait):
		}
		if errors.Is(err, ErrUnauthorized) {
			wait = time.Minute
		} else {
			wait = min(wait*2, 30*time.Second)
		}
	}
}

// PcapUpload invia all'hub il file dei pacchetti estratti (pcap compresso con gzip).
func (c *Client) PcapUpload(ctx context.Context, id int64, res *pcapResult) error {
	f, err := os.Open(res.path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/pcap/%d/result", c.base, id), f)
	if err != nil {
		return err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/vnd.tcpdump.pcap")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "hw-sensor/"+version.Version)
	req.Header.Set("X-HW-Packets", fmt.Sprint(res.packets))
	req.Header.Set("X-HW-Bytes", fmt.Sprint(res.bytes))
	req.Header.Set("X-HW-SHA256", res.sha256)
	if res.truncated {
		req.Header.Set("X-HW-Truncated", "1")
	}
	// un caricamento grande può richiedere più del limite delle chiamate normali
	hc := *c.http
	hc.Timeout = 15 * time.Minute
	r, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		var rep model.HubReply
		json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&rep)
		return fmt.Errorf("hub %d: %s", r.StatusCode, rep.Error)
	}
	return nil
}

// PcapFail comunica all'hub che un'estrazione non si può fare, con il motivo.
func (c *Client) PcapFail(ctx context.Context, id int64, reason string) {
	fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if len(reason) > 500 {
		reason = reason[:500]
	}
	c.post(fctx, fmt.Sprintf("/v1/pcap/%d/fail", id), map[string]string{"error": reason})
}
