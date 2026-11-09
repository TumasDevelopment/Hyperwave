// Package netx contiene funzioni sugli indirizzi condivise da hub e sensore.
package netx

import (
	"net/netip"
	"strings"
)

// DefaultInternal sono le reti private: valgono se HW_INTERNAL_NETS è vuoto.
const DefaultInternal = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7,fe80::/10"

// Nets è un elenco di prefissi.
type Nets []netip.Prefix

// ParseNets legge un elenco separato da virgole; ignora le voci non valide.
func ParseNets(s string) Nets {
	var out Nets
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func (n Nets) Contains(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return n.ContainsAddr(a.Unmap())
}

func (n Nets) ContainsAddr(a netip.Addr) bool {
	for _, p := range n {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (n Nets) Strings() []string {
	out := make([]string, len(n))
	for i, p := range n {
		out[i] = p.String()
	}
	return out
}

// Direction classifica un flusso rispetto alla rete interna.
func (n Nets) Direction(src, dst string) string {
	si, di := n.Contains(src), n.Contains(dst)
	switch {
	case si && di:
		return "internal"
	case si:
		return "outbound"
	case di:
		return "inbound"
	}
	return "external"
}

// Unicast dice se l'indirizzo è un host normale (non broadcast, multicast o non specificato).
func Unicast(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b[3] == 255 || b == [4]byte{255, 255, 255, 255} {
			return false
		}
	}
	return true
}
