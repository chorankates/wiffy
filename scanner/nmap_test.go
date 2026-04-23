package scanner

import (
	"reflect"
	"testing"
)

func TestParsePortEntries(t *testing.T) {
	raw := `53/open/tcp//domain//dnsmasq 2.15-OpenDNS-1/, 80/open/tcp//tcpwrapped///, 5000/open/tcp//tcpwrapped///`
	got := parsePortEntries(raw)
	want := []PortEntry{
		{Port: 53, Protocol: "tcp", Service: "domain", Product: "dnsmasq 2.15-OpenDNS-1"},
		{Port: 80, Protocol: "tcp", Service: "tcpwrapped", Product: ""},
		{Port: 5000, Protocol: "tcp", Service: "tcpwrapped", Product: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePortEntries mismatch:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestParsePortEntries_ssl_http(t *testing.T) {
	raw := `443/open/tcp//ssl|http//nginx/`
	got := parsePortEntries(raw)
	if len(got) != 1 || got[0].Port != 443 || got[0].Service != "ssl|http" || got[0].Product != "nginx" {
		t.Fatalf("got %#v", got)
	}
}
