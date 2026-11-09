//go:build !linux

package sensor

import (
	"context"
	"errors"
)

func (r *Runner) runCapture(ctx context.Context) error {
	return errors.New("la cattura dal vivo è disponibile solo su Linux; usare -mode pcap per analizzare un file")
}
