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

// Send invia un batch e riprova con attese crescenti finché riesce o ctx viene annullato.
func (c *Client) Send(ctx context.Context, b *model.Batch) (model.HubReply, error) {
	wait := time.Second
	for {
		rep, err := c.post(ctx, "/v1/ingest", b)
		if err == nil {
			return rep, nil
		}
		// un batch rifiutato perché malformato non va ripetuto all'infinito
		if strings.HasPrefix(err.Error(), "hub 400") || strings.HasPrefix(err.Error(), "hub 413") {
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
