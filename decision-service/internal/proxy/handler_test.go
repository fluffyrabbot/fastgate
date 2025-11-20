package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"fastgate/decision-service/internal/authz"
	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/token"
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
	// Upstream that does NOT upgrade; returns 200 to avoid hijack requirements in tests.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := mockConfig()
	cfg.Proxy.Origin = upstream.URL
	cfg.Modes.Enforce = true
	cfg.Policy.WSConcurrency.PerIP = 1
	cfg.Policy.WSConcurrency.PerToken = 0 // focus on IP lease

	kr := mockKeyring(t)
	authzHandler := authz.NewHandler(cfg, kr)
	h, err := NewHandler(cfg, authzHandler, ".")
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	// Attach valid clearance cookie
	tokenStr, err := kr.Sign("low", cfg.CookieMaxAge())
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  cfg.Cookie.Name,
		Value: tokenStr,
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from proxy, got %d", w.Code)
	}
	if body := w.Body.String(); body != "ok" {
		t.Fatalf("unexpected body: %q", body)
	}

	// After proxy completes, the WS lease should be released so we can acquire again.
	clientIP := "ip:192.0.2.1" // httptest default remote addr is 192.0.2.1:1234
	if ok, cur := authzHandler.WSConcIP.Acquire(clientIP, 1); !ok {
		t.Fatalf("expected lease to be released; current count=%d", cur)
	} else {
		// cleanup to avoid leaking state into other tests
		authzHandler.WSConcIP.Release(clientIP)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}
