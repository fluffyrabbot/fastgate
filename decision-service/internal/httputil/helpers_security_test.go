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
