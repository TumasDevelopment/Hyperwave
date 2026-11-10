package classify

import (
	"strings"
	"testing"
)

func TestByPort(t *testing.T) {
	cases := []struct {
		proto string
		port  uint16
		want  string
	}{
		{"TCP", 443, "HTTPS"}, {"UDP", 443, "QUIC"}, {"TCP", 22, "SSH"}, {"UDP", 53, "DNS"},
		{"UDP", 15000, "RTP"}, {"UDP", 9999, ""}, {"TCP", 15000, ""}, {"ICMP", 0, "ICMP"},
		{"ICMPv6", 0, "ICMPv6"}, {"SCTP", 80, ""},
	}
	for _, c := range cases {
		if got := ByPort(c.proto, c.port); got != c.want {
			t.Errorf("ByPort(%s, %d) = %q, atteso %q", c.proto, c.port, got, c.want)
		}
	}
}

func TestRefine(t *testing.T) {
	cases := []struct{ app, domain, want string }{
		{"HTTPS", "teams.microsoft.com", "Microsoft Teams"}, // il più specifico vince su microsoft.com
		{"HTTPS", "www.microsoft.com", "Microsoft"},
		{"QUIC", "rr3---sn-abc.googlevideo.com.", "YouTube"}, // punto finale ignorato
		{"HTTPS", "WWW.GITHUB.COM", "GitHub"},                // maiuscole ignorate
		{"HTTPS", "notgithub.com", "HTTPS"},                  // il suffisso deve iniziare dopo un punto
		{"SSH", "github.com", "SSH"},                         // applicazione specifica: non si tocca
		{"HTTPS", "", "HTTPS"},
		{"", "zoom.us", "Zoom"},
		{"HTTPS", "sconosciuto.example", "HTTPS"},
	}
	for _, c := range cases {
		if got := Refine(c.app, c.domain); got != c.want {
			t.Errorf("Refine(%q, %q) = %q, atteso %q", c.app, c.domain, got, c.want)
		}
	}
}

// Un suffisso generico non deve stare prima di uno più specifico che lo contiene, o quest'ultimo non verrebbe mai usato.
func TestDomainOrder(t *testing.T) {
	for i, a := range domains {
		for _, b := range domains[i+1:] {
			if strings.HasSuffix(b.suffix, "."+a.suffix) {
				t.Errorf("%q deve stare prima di %q", b.suffix, a.suffix)
			}
		}
	}
}
