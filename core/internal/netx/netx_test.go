package netx

import (
	"slices"
	"testing"
)

func TestParseNets(t *testing.T) {
	n := ParseNets(" 10.1.2.3/8, 192.168.1.10 ,non-valido,, fc00::1/7 ,2001:db8::1")
	want := []string{"10.0.0.0/8", "192.168.1.10/32", "fc00::/7", "2001:db8::1/128"}
	if got := n.Strings(); !slices.Equal(got, want) {
		t.Fatalf("ParseNets: %v, atteso %v", got, want)
	}
	if len(ParseNets("")) != 0 {
		t.Fatal("una stringa vuota non deve dare reti")
	}
}

func TestContainsAndDirection(t *testing.T) {
	n := ParseNets(DefaultInternal)
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.20.30.40", true}, {"172.16.0.1", true}, {"172.32.0.1", false}, {"192.168.255.254", true},
		{"100.64.1.1", true}, {"198.51.100.7", false}, {"fe80::1", true}, {"fd12::1", true},
		{"2001:db8::1", false}, {"::ffff:10.0.0.1", true}, {"non-un-ip", false}, {"", false},
	}
	for _, c := range cases {
		if got := n.Contains(c.ip); got != c.want {
			t.Errorf("Contains(%q) = %v, atteso %v", c.ip, got, c.want)
		}
	}
	dirs := map[[2]string]string{
		{"10.0.0.1", "10.0.0.2"}:        "internal",
		{"10.0.0.1", "198.51.100.7"}:    "outbound",
		{"198.51.100.7", "10.0.0.1"}:    "inbound",
		{"198.51.100.7", "203.0.113.9"}: "external",
	}
	for k, want := range dirs {
		if got := n.Direction(k[0], k[1]); got != want {
			t.Errorf("Direction(%s, %s) = %s, atteso %s", k[0], k[1], got, want)
		}
	}
}

func TestUnicast(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.0.0.5": true, "2001:db8::5": true, "10.0.0.255": false, "255.255.255.255": false,
		"224.0.0.251": false, "ff02::fb": false, "0.0.0.0": false, "::": false, "127.0.0.1": false,
		"::1": false, "::ffff:10.0.0.5": true, "x": false,
	} {
		if got := Unicast(ip); got != want {
			t.Errorf("Unicast(%q) = %v, atteso %v", ip, got, want)
		}
	}
}
