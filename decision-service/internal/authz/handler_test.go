package authz

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/intel"
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

// mockConfig creates a standard test config
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
			IPRPSThreshold:     100, // High threshold to avoid interfering with logic tests
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
			Alg: "HS256",
			CurrentKID: "testkid",
			Keys: map[string]string{
				"testkid": base64.RawURLEncoding.EncodeToString([]byte("supersecretkeythatisatleast16byteslong")),
			},
			Issuer: "fastgate-test",
			SkewSec: 0,
		},
		Logging: config.LoggingCfg{
			Level: "debug",
		},
		Challenge: config.ChallengeCfg{
			DifficultyBits: 16,
			TTLSec:         60,
		},
	}
	return cfg
}

func TestServeHTTP_Allow(t *testing.T) {
	cfg := mockConfig()
	kr := mockKeyring(t)
	h := NewHandler(cfg, kr)
	h.IntelStore = intel.NewStore(10) // Initialize IntelStore with capacity
	defer h.IntelStore.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)") // Valid UA
	req.Header.Set("Accept-Language", "en-US")                                      // Valid Lang
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content, got %d", w.Code)
	}
	// Should receive a cookie
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected clearance cookie, got none")
	}
}

func TestServeHTTP_Block_HighRisk(t *testing.T) {
	cfg := mockConfig()
	kr := mockKeyring(t)
	h := NewHandler(cfg, kr)
	h.IntelStore = intel.NewStore(10) // Initialize IntelStore with capacity
	defer h.IntelStore.Close()

	// Create a request that triggers multiple risk factors
	req := httptest.NewRequest("POST", "/admin/delete", nil) // +15 (POST), +60 (/admin) = 75
	// Missing UA (+15), Missing Lang (+10)
	// Total Score: 75 + 15 + 10 = 100 (Block Threshold)

	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d. Body: %s", w.Code, w.Body.String())
	}
	
	reason := w.Header().Get("X-FastGate-Reason")
	if !strings.Contains(reason, "mutating_method") || !strings.Contains(reason, "path_base") {
		t.Errorf("expected reasons to contain mutating_method and path_base, got %s", reason)
	}
}

func TestServeHTTP_Challenge_MediumRisk(t *testing.T) {
	cfg := mockConfig()
	kr := mockKeyring(t)
	h := NewHandler(cfg, kr)
	h.IntelStore = intel.NewStore(10) // Initialize IntelStore with capacity
	defer h.IntelStore.Close()

	// Create a request that exceeds challenge threshold (50) but not block (100)
	req := httptest.NewRequest("GET", "/admin/view", nil) // +60 (/admin)
	req.Header.Set("User-Agent", "Mozilla/5.0")           // Valid UA
	req.Header.Set("Accept-Language", "en-US")            // Valid Lang
	
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized (Challenge), got %d", w.Code)
	}
	
	body := w.Body.String()
	if !strings.Contains(body, "challenge") {
		t.Errorf("expected body to contain 'challenge', got %s", body)
	}
}

func TestServeHTTP_ValidToken_BypassesChecks(t *testing.T) {
	cfg := mockConfig()
	kr := mockKeyring(t)
	h := NewHandler(cfg, kr)
	h.IntelStore = intel.NewStore(10) // Initialize IntelStore with capacity
	defer h.IntelStore.Close()

	// 1. Get a valid token first
	tokenStr, _ := kr.Sign("low", time.Hour)

	// 2. Make a request that WOULD be blocked without the token
	req := httptest.NewRequest("POST", "/admin/delete", nil) 
	// Missing UA/Lang, POST, /admin -> Score 100 (Block)
	
	// Attach the valid token
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: tokenStr})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should be ALLOWED (204) because token is valid
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content (Token Bypass), got %d", w.Code)
	}
}

func TestServeHTTP_IntelBlocking(t *testing.T) {
	cfg := mockConfig()
	kr := mockKeyring(t)
	h := NewHandler(cfg, kr)
	
	// Initialize Intel Store
	h.IntelStore = intel.NewStore(10) // Initialize IntelStore with capacity
	defer h.IntelStore.Close()
	
	// Add a malicious IP to the store
	badIP := "192.0.2.66"
	h.IntelStore.Add(&intel.Indicator{
		Type:       intel.IndicatorIPv4,
		Value:      badIP,
		Confidence: 100, // High confidence
		ValidUntil: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Client-IP", badIP)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept-Language", "en-US")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// The IP match should add +50 (half of confidence 100) to score.
	// Base score 0. Total 50.
	// Challenge threshold is 50. So it should CHALLENGE or BLOCK depending on exact score.
	// Wait, let's check the code: boost := ind.Confidence / 2. 100/2 = 50.
	// Total score = 50. Challenge Threshold = 50. Result: 401 Challenge.
	
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized (Intel Challenge), got %d", w.Code)
	}
	
	reason := w.Header().Get("X-FastGate-Reason")
	if !strings.Contains(reason, "threat_intel_ip") {
		t.Errorf("expected reason 'threat_intel_ip', got %s", reason)
	}
}
