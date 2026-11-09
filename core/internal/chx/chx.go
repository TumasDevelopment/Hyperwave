// Package chx è un client minimo per l'interfaccia HTTP di ClickHouse.
package chx

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	URL, DB, User, Password string
	HTTP                    *http.Client
}

func New(base, db, user, password string) *Client {
	return &Client{URL: strings.TrimRight(base, "/"), DB: db, User: user, Password: password,
		HTTP: &http.Client{Timeout: 60 * time.Second}}
}

func (c *Client) do(ctx context.Context, query string, params map[string]string, body io.Reader, gz bool) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("database", c.DB)
	q.Set("output_format_json_quote_64bit_integers", "0")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/?"+q.Encode(), strings.NewReader(query))
	} else {
		q.Set("query", query)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/?"+q.Encode(), body)
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ClickHouse-User", c.User)
	req.Header.Set("X-ClickHouse-Key", c.Password)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		res.Body.Close()
		return nil, fmt.Errorf("clickhouse %d: %s", res.StatusCode, strings.TrimSpace(string(msg)))
	}
	return res.Body, nil
}

// Exec esegue un'istruzione senza risultato.
func (c *Client) Exec(ctx context.Context, query string, params map[string]string) error {
	rc, err := c.do(ctx, query, params, nil, false)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, rc)
	return rc.Close()
}

// Insert scrive righe in formato JSONEachRow, compresse.
func (c *Client) Insert(ctx context.Context, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	zw.Close()
	rc, err := c.do(ctx, "INSERT INTO "+table+" SETTINGS input_format_skip_unknown_fields=1 FORMAT JSONEachRow", nil, &buf, true)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, rc)
	return rc.Close()
}

// Query decodifica ogni riga del risultato in un valore di tipo T.
func Query[T any](ctx context.Context, c *Client, query string, params map[string]string) ([]T, error) {
	rc, err := c.do(ctx, query+" FORMAT JSONEachRow", params, nil, false)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var out []T
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// Time formatta un tempo per DateTime64(3, 'UTC').
func Time(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05.000")
}
