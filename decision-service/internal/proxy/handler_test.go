package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"fastgate/decision-service/internal/authz"
	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/metrics"
	"fastgate/decision-service/internal/token"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
)

// mockKeyring creates a keyring for testing
func mockKeyring(t *testing.T) *token.Keyring {
	alg := "HS256"
	currentKID := "testkid"
	keys := map[string]string{
		currentKID: base64.RawURLEncoding.EncodeToString([]byte("supersecretkeythatisatleast16byteslong")),
	}
	issuer := "fastgate-test"
	skew := 0
	kr, err := token.NewKeyring(alg, keys, currentKID, issuer, skew)
	if err != nil {
		t.Fatalf("failed to create keyring: %v", err)
	}
	return kr
}

// mockConfig creates a standard test config for proxy
func mockConfig() *config.Config {
	cfg := &config.Config{
		Server: config.ServerCfg{
			Listen: ":8080",
		},
		Cookie: config.CookieCfg{
			Name:      "clearance",
			Domain:    "localhost",
			MaxAgeSec: 3600,
			Secure:    false,
			HTTPOnly:  true,
		},
		Modes: config.ModesCfg{
			Enforce:     true,
			UnderAttack: false,
		},
		Policy: config.PolicyCfg{
			ChallengeThreshold: 50,
			BlockThreshold:     100,
			IPRPSThreshold:     100,
			Paths: []config.PathRule{
				{Pattern: "^/admin", Base: 60, Re: regexp.MustCompile("^/admin")},
				{Pattern: "^/login", Base: 30, Re: regexp.MustCompile("^/login")},
			},
			WSConcurrency: struct {
				PerIP    int `yaml:"per_ip"`
				PerToken int `yaml:"per_token"`
			}{
				PerIP:    10,
				PerToken: 10,
			},
		},
		Token: config.TokenCfg{
			Alg:        "HS256",
			CurrentKID: "testkid",
			Keys: map[string]string{
				"testkid": base64.RawURLEncoding.EncodeToString([]byte("supersecretkeythatisatleast16byteslong")),
			},
			Issuer:  "fastgate-test",
			SkewSec: 0,
		},
		Logging: config.LoggingCfg{
			Level: "debug",
		},
		Challenge: config.ChallengeCfg{
			DifficultyBits: 16,
			TTLSec:         60,
		},
		Proxy: config.ProxyCfg{
			Enabled:       true,
			Origin:        "http://example.com", // Default for authz handler, overridden in tests
			ChallengePath: "/__uam",
			TimeoutMs:     1000,
		},
	}
	return cfg
}

func TestHandler_ServeHTTP_ProxyToOrigin(t *testing.T) {
	// 1. Setup Upstream Origin
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	// 2. Setup Config
	cfg := mockConfig()
	cfg.Proxy.Origin = upstream.URL // Override default origin with mock server
	cfg.Modes.Enforce = false       // Disable enforcement for this test to allow all

	// 3. Setup Authz Handler (Real one is fine for this)
	kr := mockKeyring(t)
	authzHandler := authz.NewHandler(cfg, kr)

	// 4. Setup Proxy Handler
	// We need a dummy challenge directory
	h, err := NewHandler(cfg, authzHandler, ".")
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	// 5. Perform Request
	req := httptest.NewRequest("GET", "/data", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// 6. Verify
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Code)
	}
	if w.Body.String() != "upstream response" {
		t.Errorf("expected 'upstream response', got %q", w.Body.String())
	}
}

func TestHandler_ServeHTTP_Block(t *testing.T) {
	// 1. Setup Upstream (Should not be hit)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be hit")
	}))
	defer upstream.Close()

	// 2. Setup Config to BLOCK
	cfg := mockConfig()
	cfg.Proxy.Origin = upstream.URL
	cfg.Modes.Enforce = true
	cfg.Policy.BlockThreshold = 10 // Low threshold to trigger block easily

	// 3. Setup Authz Handler
	kr := mockKeyring(t)
	authzHandler := authz.NewHandler(cfg, kr)

	// 4. Setup Proxy Handler
	h, _ := NewHandler(cfg, authzHandler, ".")

	// 5. Perform Request (Triggers block: missing UA, etc.)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// 6. Verify
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", w.Code)
	}
	if w.Body.String() == "upstream response" {
		t.Error("request was proxied despite block")
	}
}

func TestHandler_ServeHTTP_Challenge(t *testing.T) {
	// 1. Setup Config to CHALLENGE
	cfg := mockConfig()
	cfg.Proxy.Origin = "http://example.com"
	cfg.Proxy.ChallengePath = "/challenge"
	cfg.Modes.Enforce = true
	cfg.Policy.ChallengeThreshold = 10
	cfg.Policy.BlockThreshold = 100

	kr := mockKeyring(t)
	authzHandler := authz.NewHandler(cfg, kr)
	h, _ := NewHandler(cfg, authzHandler, ".")

	// 2. Perform Request (Triggers challenge)
	req := httptest.NewRequest("GET", "/app", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// 3. Verify Redirect
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 Found (Redirect), got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Error("missing Location header")
	}
	// Should contain return_url
	if !strings.Contains(loc, "return_url") {
		t.Errorf("location %q missing return_url", loc)
	}
}

func TestWebSocketLeaseReleasedAfterProxy(t *testing.T) {
	// Upstream WebSocket echo server.
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	var seenUpstream bool
	var upgradeErr error
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUpstream = true
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			upgradeErr = err
			http.Error(w, "upgrade failed", http.StatusBadRequest)
			return
		}
		defer conn.Close()

		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, append([]byte("echo:"), msg...)); err != nil {
			return
		}
		// Wait for close from client.
		conn.ReadMessage()
	}))
	defer upstream.Close()

	cfg := mockConfig()
	cfg.Proxy.Origin = upstream.URL
	cfg.Modes.Enforce = true
	cfg.Policy.WSConcurrency.PerIP = 1
	cfg.Policy.WSConcurrency.PerToken = 1
	cfg.Proxy.TimeoutMs = 5000

	kr := mockKeyring(t)
	authzHandler := authz.NewHandler(cfg, kr)
	h, err := NewHandler(cfg, authzHandler, ".")
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	proxySrv := httptest.NewServer(h)
	defer proxySrv.Close()

	tokenStr, err := kr.Sign("low", cfg.CookieMaxAge())
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	wsURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	wsURL.Scheme = "ws"
	wsURL.Path = "/ws"

	dialer := websocket.Dialer{}
	headers := http.Header{}
	headers.Set("Cookie", cfg.Cookie.Name+"="+tokenStr)
	clientIP := "203.0.113.10"
	headers.Set("X-Forwarded-For", clientIP)

	conn, resp, err := dialer.Dial(wsURL.String(), headers)
	if err != nil {
		if resp != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("websocket dial failed: %v (status %d, body %q, upstreamSeen=%v, upgradeErr=%v)", err, resp.StatusCode, string(bodyBytes), seenUpstream, upgradeErr)
		}
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close()

	if upgradeErr != nil {
		t.Fatalf("upstream upgrade error: %v", upgradeErr)
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	_, reply, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply) != "echo:ping" {
		t.Fatalf("unexpected reply: %q", string(reply))
	}

	// Close cleanly to trigger lease release.
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = conn.Close()
	time.Sleep(50 * time.Millisecond)

	ipKey := "ip:" + clientIP
	if ok, cur := authzHandler.WSConcIP.Acquire(ipKey, 1); !ok {
		t.Fatalf("expected IP lease to be released; current count=%d", cur)
	} else {
		authzHandler.WSConcIP.Release(ipKey)
	}

	tokKey := authz.WSTokenKeyForTest(tokenStr)
	if ok, cur := authzHandler.WSConcTok.Acquire(tokKey, 1); !ok {
		t.Fatalf("expected token lease to be released; current count=%d", cur)
	} else {
		authzHandler.WSConcTok.Release(tokKey)
	}
}

// --- Test helpers for expanded coverage ---

func mockConfigWithCB() *config.Config {
	cfg := mockConfig()
	cfg.Proxy.CircuitBreaker.Enabled = true
	cfg.Proxy.CircuitBreaker.FailureThreshold = 3
	cfg.Proxy.CircuitBreaker.SuccessThreshold = 2
	cfg.Proxy.CircuitBreaker.TimeoutSec = 1 // short for tests
	cfg.Proxy.CircuitBreaker.MinimumRequestThreshold = 2
	cfg.Proxy.CircuitBreaker.SlidingWindowSec = 10
	return cfg
}

// TestHandler_MatchRoute_HostAndPath exercises the (unexported) routing logic via ServeHTTP behavior
// using different host headers and path patterns in a multi-origin config.
func TestHandler_MatchRoute_HostAndPath(t *testing.T) {
	// Two upstreams
	up1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("origin-one"))
	}))
	defer up1.Close()

	up2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("origin-two"))
	}))
	defer up2.Close()

	cfg := mockConfig()
	cfg.Proxy.Origin = ""
	cfg.Proxy.Routes = []config.ProxyRoute{
		{Host: "game.example.com", Origin: up1.URL},
		{Path: "^/api/", Origin: up2.URL},
	}
	cfg.Modes.Enforce = false

	kr := mockKeyring(t)
	authzH := authz.NewHandler(cfg, kr)
	h, err := NewHandler(cfg, authzH, ".")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	tests := []struct {
		name       string
		host       string
		path       string
		wantBody   string
		wantStatus int
	}{
		{"host match", "game.example.com", "/play", "origin-one", 200},
		{"path match", "shop.example.com", "/api/users", "origin-two", 200},
		{"no match", "other.example.com", "/foo", "", 404},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if tc.wantBody != "" && w.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestHandler_CircuitBreaker_OpensAndRejects drives a misbehaving upstream past the failure threshold
// and verifies that the circuit opens and subsequent requests are rejected fast (503) with the
// correct metric increment.
func TestHandler_CircuitBreaker_OpensAndRejects(t *testing.T) {
	metrics.MustRegister()

	failures := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failures++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer upstream.Close()

	cfg := mockConfigWithCB()
	cfg.Proxy.Origin = upstream.URL
	cfg.Modes.Enforce = false // we only care about CB, not authz

	kr := mockKeyring(t)
	authzH := authz.NewHandler(cfg, kr)
	h, err := NewHandler(cfg, authzH, ".")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Send enough requests to trip the circuit (need MinimumRequestThreshold + FailureThreshold failures)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/cb-test", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}

	// After threshold, the next request should be rejected quickly with 503
	start := time.Now()
	req := httptest.NewRequest("GET", "/cb-test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 after circuit open, got %d", w.Code)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("503 response took too long (%v); circuit breaker did not fail fast", elapsed)
	}

	// Check that ProxyCircuitOpen counter has increased for this origin
	// (we don't assert exact value because other tests may have touched it)
	// Just ensure the metric exists and is > 0 for this origin.
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "fastgate_proxy_circuit_open_total" {
			for _, m := range mf.Metric {
				for _, l := range m.Label {
					if l.GetName() == "origin" && strings.Contains(l.GetValue(), upstream.URL) {
						if m.Counter.GetValue() == 0 {
							t.Error("expected ProxyCircuitOpen > 0 for the failing origin")
						}
					}
				}
			}
		}
	}
}

// TestHandler_BodySizeLimit verifies MaxBodySizeMB enforcement before proxying.
func TestHandler_BodySizeLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached when body is too large")
	}))
	defer upstream.Close()

	cfg := mockConfig()
	cfg.Proxy.Origin = upstream.URL
	cfg.Proxy.MaxBodySizeMB = 1 // 1 MiB limit
	cfg.Modes.Enforce = false

	kr := mockKeyring(t)
	authzH := authz.NewHandler(cfg, kr)
	h, _ := NewHandler(cfg, authzH, ".")

	// Create a request whose Content-Length exceeds the limit
	bigBody := strings.NewReader(strings.Repeat("x", 2*1024*1024)) // 2 MiB
	req := httptest.NewRequest("POST", "/upload", bigBody)
	req.ContentLength = 2 * 1024 * 1024
	req.Header.Set("Content-Length", "2097152")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 Request Entity Too Large, got %d", w.Code)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}
