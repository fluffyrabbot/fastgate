package httputil

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestForwardedIPTrustBoundary(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	for _, tt := range []struct {
		name, peer, xff, want string
		proxies               []*net.IPNet
	}{
		{"direct default", "192.0.2.1:1234", "203.0.113.1", "192.0.2.1", nil},
		{"untrusted peer", "192.0.2.1:1234", "203.0.113.1", "192.0.2.1", []*net.IPNet{trusted}},
		{"trusted chain", "10.0.0.1:1234", "203.0.113.1, 10.0.0.2", "203.0.113.1", []*net.IPNet{trusted}},
		{"spoofed prefix", "10.0.0.1:1234", "203.0.113.99, 192.0.2.1", "192.0.2.1", []*net.IPNet{trusted}},
		{"malformed chain", "10.0.0.1:1234", "203.0.113.99, garbage", "10.0.0.1", []*net.IPNet{trusted}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			r.Header.Set("X-Forwarded-For", tt.xff)
			if got := ClientIPFromHeadersWithTrustedProxies(r, tt.proxies); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeReturnURLBrowserPaths(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`/\attacker.invalid/path`, "/"},
		{`/%5Cattacker.invalid/path`, "/"},
		{`/%5cattacker.invalid/path`, "/"},
		{`/safe\path`, "/"},
		{`/%2fattacker.invalid/path`, "/"},
		{`//attacker.invalid/path`, "/"},
		{`https://attacker.invalid/path`, "/"},
		{`/%zz`, "/"},
		{`/safe/%20space/%23hash/%3Fquery/%25percent?x=a%2Bb&y=c+d`, `/safe/%20space/%23hash/%3Fquery/%25percent?x=a%2Bb&y=c+d`},
		{`/safe+path?next=%2Fhome`, `/safe+path?next=%2Fhome`},
		{`/%255Cattacker.invalid/path`, `/%255Cattacker.invalid/path`},
		{`/%0A/attacker.invalid/path`, `/%0A/attacker.invalid/path`},
		{`/dashboard?tab=1`, `/dashboard?tab=1`},
		{`/`, `/`},
		{``, `/`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := SanitizeReturnURL(tc.in)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if again := SanitizeReturnURL(got); again != got {
				t.Fatalf("second sanitization changed %q to %q", got, again)
			}
		})
	}
}
