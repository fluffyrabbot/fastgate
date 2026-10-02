package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"fastgate/decision-service/internal/authz"
	internalhttp "fastgate/decision-service/internal/httputil"
	"github.com/rs/zerolog"
)

func TestIntegratedAdmissionProxyTrust(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("10.0.0.0/8")
	for _, tc := range []struct {
		name, peer, firstIP, nextIP, want string
		trust                             bool
		first, next                       http.Header
	}{
		{name: "direct XFF", peer: "192.0.2.1:1234", firstIP: "192.0.2.1", nextIP: "192.0.2.1", want: "challenge", next: http.Header{"X-Forwarded-For": {"203.0.113.99"}}},
		{name: "direct real IP", peer: "192.0.2.1:1234", firstIP: "192.0.2.1", nextIP: "192.0.2.1", want: "challenge", next: http.Header{"X-Real-Ip": {"203.0.113.99"}}},
		{name: "direct client IP", peer: "192.0.2.1:1234", firstIP: "192.0.2.1", nextIP: "192.0.2.1", want: "challenge", next: http.Header{"X-Client-Ip": {"203.0.113.99"}}},
		{name: "untrusted peer", peer: "192.0.2.1:1234", trust: true, firstIP: "192.0.2.1", nextIP: "192.0.2.1", want: "challenge", next: http.Header{"X-Forwarded-For": {"203.0.113.99"}}},
		{name: "trusted chain forged prefix", peer: "10.0.0.1:1234", trust: true, firstIP: "192.0.2.1", nextIP: "192.0.2.1", want: "challenge", first: http.Header{"X-Forwarded-For": {"192.0.2.1, 10.0.0.2"}}, next: http.Header{"X-Forwarded-For": {"203.0.113.99, 192.0.2.1", "10.0.0.2"}}},
		{name: "trusted distinct clients", peer: "10.0.0.1:1234", trust: true, firstIP: "192.0.2.1", nextIP: "192.0.2.2", want: "allow", first: http.Header{"X-Forwarded-For": {"192.0.2.1, 10.0.0.2"}}, next: http.Header{"X-Forwarded-For": {"192.0.2.2, 10.0.0.2"}}},
		{name: "malformed trusted chain", peer: "10.0.0.1:1234", trust: true, firstIP: "10.0.0.1", nextIP: "10.0.0.1", want: "challenge", next: http.Header{"X-Forwarded-For": {"203.0.113.99, garbage"}, "X-Real-Ip": {"203.0.113.98"}}},
		{name: "IPv6 peer", peer: "[2001:db8::1]:1234", firstIP: "2001:db8::1", nextIP: "2001:db8::1", want: "challenge", next: http.Header{"X-Forwarded-For": {"203.0.113.99"}}},
		{name: "invalid peer clears forged identity", peer: "invalid", want: "allow", next: http.Header{"X-Client-Ip": {"203.0.113.99"}, "X-Forwarded-For": {"203.0.113.98"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mockConfig()
			cfg.Policy.WSConcurrency.PerIP = 1
			cfg.Policy.ChallengeThreshold = 1000
			cfg.Policy.BlockThreshold = 2000
			cfg.Policy.IPRPSThreshold = 0
			if tc.trust {
				cfg.Server.TrustedProxyCIDRs = []*net.IPNet{trusted}
			}
			az := authz.NewHandler(cfg, mockKeyring(t))
			defer az.Shutdown()
			h, err := NewHandler(cfg, az)
			if err != nil {
				t.Fatal(err)
			}
			// Exercise the production metadata middleware and real authz admission,
			// retaining leases to model open sockets without opening any transport.
			var decision, clientIP string
			handler := internalhttp.RequestIDMiddleware(zerolog.Nop(), cfg.Server.TrustedProxyCIDRs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var lease string
				decision, _, _, lease = h.checkAuthorization(r)
				clientIP = r.Header.Get("X-Client-IP")
				if parsed := authz.ParseWSLeaseHeader(lease); parsed != nil {
					t.Cleanup(func() { az.ReleaseWSLease(parsed) })
				}
			}))
			check := func(headers http.Header, want, wantIP string) {
				t.Helper()
				r := httptest.NewRequest("GET", "/", nil)
				r.RemoteAddr = tc.peer
				if headers != nil {
					r.Header = headers.Clone()
				}
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Connection", "Upgrade")
				handler.ServeHTTP(httptest.NewRecorder(), r)
				if decision != want || clientIP != wantIP {
					t.Fatalf("decision=%s IP=%q; want %s %q", decision, clientIP, want, wantIP)
				}
			}
			check(tc.first, "allow", tc.firstIP)
			if tc.firstIP != "" {
				check(tc.first, "challenge", tc.firstIP)
			}
			check(tc.next, tc.want, tc.nextIP)
		})
	}
}
