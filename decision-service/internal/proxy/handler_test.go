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
	"fastgate/decision-service/internal/token"

	"github.com/gorilla/websocket"
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}
