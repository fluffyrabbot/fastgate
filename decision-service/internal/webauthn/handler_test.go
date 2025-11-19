package webauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/rate"
	"fastgate/decision-service/internal/token"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Test helper to create a handler with test configuration
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	cfg := &config.Config{
		WebAuthn: config.WebAuthnCfg{
			RPID:      "localhost",
			RPName:    "Test FastGate",
			RPOrigins: []string{"http://localhost:8080"},
			TTLSec:    60,
		},
		Cookie: config.CookieCfg{
			Name:      "Clearance",
			Path:      "/",
			MaxAgeSec: 3600,
			Secure:    false,
			HTTPOnly:  true,
			SameSite:  "Lax",
		},
	}

	// Create test keyring with test key
	keys := map[string]string{"v1": "dGhpc2lzYXRlc3RrZXlkb25vdHVzZWlucHJvZHVjdGlvbg"}
	kr, err := token.NewKeyring("HS256", keys, "v1", "test-issuer", 30)
	if err != nil {
		t.Fatalf("failed to create keyring: %v", err)
	}

	rateLimiter := rate.NewSlidingRPS(10)

	h, err := NewHandler(cfg, kr, rateLimiter)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	return h
}

// TestBeginRegistration_HappyPath tests the successful begin registration flow
func TestBeginRegistration_HappyPath(t *testing.T) {
	h := newTestHandler(t)

	reqBody := map[string]string{"return_url": "/dashboard"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BeginRegistration(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ChallengeID string `json:"challenge_id"`
		ReturnURL   string `json:"return_url"`
		PublicKey   struct {
			Challenge string `json:"challenge"`
			RP        struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"rp"`
		} `json:"publicKey"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ChallengeID == "" {
		t.Error("expected challenge_id, got empty string")
	}
	if resp.ReturnURL != "/dashboard" {
		t.Errorf("expected return_url '/dashboard', got %q", resp.ReturnURL)
	}
	if resp.PublicKey.Challenge == "" {
		t.Error("expected challenge, got empty string")
	}
	if resp.PublicKey.RP.ID != "localhost" {
		t.Errorf("expected rp_id 'localhost', got %q", resp.PublicKey.RP.ID)
	}
}

// TestBeginRegistration_MethodNotAllowed tests that GET requests are rejected
func TestBeginRegistration_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/challenge/webauthn", nil)
	w := httptest.NewRecorder()

	h.BeginRegistration(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestBeginRegistration_InvalidJSON tests malformed JSON handling
func TestBeginRegistration_InvalidJSON(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BeginRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "bad_json" {
		t.Errorf("expected error 'bad_json', got %q", resp["error"])
	}
}

// TestBeginRegistration_BodySizeLimit tests that oversized bodies are rejected
func TestBeginRegistration_BodySizeLimit(t *testing.T) {
	h := newTestHandler(t)

	// Create 5KB body (exceeds 4KB limit)
	largeBody := bytes.Repeat([]byte("a"), 5*1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BeginRegistration(w, req)

	// Should fail due to MaxBytesReader
	if w.Code == http.StatusOK {
		t.Error("expected error for oversized body, got 200 OK")
	}
}

// TestBeginRegistration_RateLimiting tests per-IP rate limiting
func TestBeginRegistration_RateLimiting(t *testing.T) {
	h := newTestHandler(t)

	// Send 5 requests rapidly (limit is 3.0 RPS over 10s window)
	for i := 0; i < 5; i++ {
		reqBody := map[string]string{"return_url": "/"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.168.1.100") // Simulate same IP
		w := httptest.NewRecorder()

		h.BeginRegistration(w, req)

		// After 3 requests, should get rate limited
		if i >= 3 && w.Code != http.StatusTooManyRequests {
			t.Errorf("request %d: expected 429 (rate limited), got %d", i+1, w.Code)
		}

		if w.Code == http.StatusTooManyRequests {
			if w.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header on rate limited response")
			}
			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] != "rate_limited" {
				t.Errorf("expected error 'rate_limited', got %q", resp["error"])
			}
			break
		}
	}
}

// TestBeginRegistration_ReturnURLSanitization tests open redirect protection
func TestBeginRegistration_ReturnURLSanitization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"valid path", "/dashboard", "/dashboard"},
		{"protocol relative", "//evil.com", "/"},
		{"absolute URL", "http://evil.com", "/"},
		{"encoded protocol relative", "%2F%2Fevil.com", "/"},
		{"empty string", "", "/"},
		{"query params", "/dashboard?foo=bar", "/dashboard?foo=bar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new handler for each subtest to avoid rate limiting accumulation
			h := newTestHandler(t)

			reqBody := map[string]string{"return_url": tt.input}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			// Use unique IP per subtest to avoid rate limiting
			req.Header.Set("X-Forwarded-For", "192.168.1."+fmt.Sprint(100+len(tt.name)))
			w := httptest.NewRecorder()

			h.BeginRegistration(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}

			var resp struct {
				ReturnURL string `json:"return_url"`
			}
			json.Unmarshal(w.Body.Bytes(), &resp)

			if resp.ReturnURL != tt.expected {
				t.Errorf("expected sanitized URL %q, got %q", tt.expected, resp.ReturnURL)
			}
		})
	}
}

// TestFinishRegistration_MethodNotAllowed tests that GET requests are rejected
func TestFinishRegistration_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/challenge/complete/webauthn?challenge_id=test", nil)
	w := httptest.NewRecorder()

	h.FinishRegistration(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestFinishRegistration_MissingChallengeID tests missing challenge_id parameter
func TestFinishRegistration_MissingChallengeID(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.FinishRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_challenge_id" {
		t.Errorf("expected error 'invalid_challenge_id', got %q", resp["error"])
	}
}

// TestFinishRegistration_ChallengeIDTooLong tests oversized challenge_id
func TestFinishRegistration_ChallengeIDTooLong(t *testing.T) {
	h := newTestHandler(t)

	// Generate 300 character challenge_id (exceeds 256 limit)
	longID := strings.Repeat("a", 300)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn?challenge_id="+longID, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.FinishRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_challenge_id" {
		t.Errorf("expected error 'invalid_challenge_id', got %q", resp["error"])
	}
}

// TestFinishRegistration_ChallengeNotFound tests unknown challenge_id
func TestFinishRegistration_ChallengeNotFound(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn?challenge_id=nonexistent", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.FinishRegistration(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_attestation" {
		// May fail at parsing stage before store lookup
		if resp["error"] != "challenge_not_found" {
			t.Errorf("expected error 'challenge_not_found' or 'invalid_attestation', got %q", resp["error"])
		}
	}
}

// TestFinishRegistration_RateLimiting tests per-IP rate limiting
func TestFinishRegistration_RateLimiting(t *testing.T) {
	h := newTestHandler(t)

	// Send 5 requests rapidly (limit is 3.0 RPS over 10s window)
	for i := 0; i < 5; i++ {
		challengeID := fmt.Sprintf("test%d", i)
		req := httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn?challenge_id="+challengeID, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.168.1.200") // Simulate same IP
		w := httptest.NewRecorder()

		h.FinishRegistration(w, req)

		// After 3 requests, should get rate limited
		if i >= 3 && w.Code != http.StatusTooManyRequests {
			t.Errorf("request %d: expected 429 (rate limited), got %d", i+1, w.Code)
		}

		if w.Code == http.StatusTooManyRequests {
			if w.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header on rate limited response")
			}
			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] != "rate_limited" {
				t.Errorf("expected error 'rate_limited', got %q", resp["error"])
			}
			break
		}
	}
}

// TestFinishRegistration_BodySizeLimit tests that oversized bodies are rejected
func TestFinishRegistration_BodySizeLimit(t *testing.T) {
	h := newTestHandler(t)

	// Create 2MB body (exceeds 1MB limit)
	largeBody := bytes.Repeat([]byte("a"), 2*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn?challenge_id=test", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.FinishRegistration(w, req)

	// Should fail due to MaxBytesReader
	if w.Code == http.StatusOK {
		t.Error("expected error for oversized body, got 200 OK")
	}
}

// TestStore_ChallengeConsumption tests that challenges are single-use
func TestStore_ChallengeConsumption(t *testing.T) {
	store := NewStoreWithCapacity(60*time.Second, 100)

	// Create mock session
	session := &webauthn.SessionData{
		Challenge: "test-challenge",
	}
	userID := []byte("test-user")

	// Store challenge
	challengeID := store.Put(session, userID, "/")
	if challengeID == "" {
		t.Fatal("failed to store challenge")
	}

	// First retrieval should succeed
	_, _, _, ok := store.Get(challengeID)
	if !ok {
		t.Error("first Get failed")
	}

	// Consume challenge
	store.Consume(challengeID)

	// Second retrieval should fail (challenge consumed)
	_, _, _, ok = store.Get(challengeID)
	if ok {
		t.Error("Get succeeded after Consume - challenge was not consumed")
	}
}

// TestStore_ChallengeExpiration tests that expired challenges are rejected
func TestStore_ChallengeExpiration(t *testing.T) {
	// Create store with 100ms TTL for fast testing
	store := NewStoreWithCapacity(100*time.Millisecond, 100)

	session := &webauthn.SessionData{
		Challenge: "test-challenge",
	}
	userID := []byte("test-user")

	// Store challenge
	challengeID := store.Put(session, userID, "/")
	if challengeID == "" {
		t.Fatal("failed to store challenge")
	}

	// Immediate retrieval should succeed
	_, _, _, ok := store.Get(challengeID)
	if !ok {
		t.Error("immediate Get failed")
	}

	// Wait for expiration (150ms > 100ms TTL)
	time.Sleep(150 * time.Millisecond)

	// Retrieval should fail (challenge expired)
	_, _, _, ok = store.Get(challengeID)
	if ok {
		t.Error("Get succeeded after expiration - challenge should have expired")
	}
}

// TestStore_LRUEviction tests that LRU eviction works correctly
func TestStore_LRUEviction(t *testing.T) {
	// Create store with capacity 3
	store := NewStoreWithCapacity(60*time.Second, 3)

	session := &webauthn.SessionData{Challenge: "test"}
	userID := []byte("user")

	// Fill store to capacity
	id1 := store.Put(session, userID, "/")
	id2 := store.Put(session, userID, "/")
	id3 := store.Put(session, userID, "/")

	// Add one more (should evict id1, the oldest)
	id4 := store.Put(session, userID, "/")

	// id1 should be evicted
	_, _, _, ok := store.Get(id1)
	if ok {
		t.Error("id1 should have been evicted but was found")
	}

	// id2, id3, id4 should still exist
	for _, id := range []string{id2, id3, id4} {
		_, _, _, ok := store.Get(id)
		if !ok {
			t.Errorf("id %s should exist but was not found", id)
		}
	}
}

// TestStore_Concurrent tests concurrent access to the store
func TestStore_Concurrent(t *testing.T) {
	store := NewStoreWithCapacity(60*time.Second, 1000)

	session := &webauthn.SessionData{Challenge: "test"}
	userID := []byte("user")

	// Run concurrent Put operations
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			challengeID := store.Put(session, userID, "/")
			if challengeID != "" {
				// Try to get and consume
				store.Get(challengeID)
				store.Consume(challengeID)
			}
		}()
	}

	wg.Wait()

	// No race condition should occur (test with -race flag)
	// If we get here without panic, concurrent access is safe
}

// TestBeginAndFinishFlow_Integration tests the full workflow
// Note: This is a partial integration test. Full e2e testing requires
// actual WebAuthn client implementation, which is in test-webauthn.js
func TestBeginAndFinishFlow_Integration(t *testing.T) {
	h := newTestHandler(t)

	// Step 1: Begin registration
	reqBody := map[string]string{"return_url": "/dashboard"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/webauthn", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.BeginRegistration(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("BeginRegistration failed: %d", w.Code)
	}

	var beginResp struct {
		ChallengeID string `json:"challenge_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &beginResp)

	if beginResp.ChallengeID == "" {
		t.Fatal("no challenge_id returned")
	}

	// Step 2: Verify challenge is in store
	_, _, _, ok := h.Store.Get(beginResp.ChallengeID)
	if !ok {
		t.Error("challenge not found in store after BeginRegistration")
	}

	// Note: FinishRegistration requires actual WebAuthn attestation response
	// which can't be easily mocked. Full testing is done in test-webauthn.js
}

// TestBackgroundCleanup tests that expired entries are cleaned up
func TestBackgroundCleanup(t *testing.T) {
	// Create store with 50ms TTL
	store := NewStoreWithCapacity(50*time.Millisecond, 100)

	session := &webauthn.SessionData{Challenge: "test"}
	userID := []byte("user")

	// Add 10 entries
	for i := 0; i < 10; i++ {
		store.Put(session, userID, "/")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Trigger manual cleanup
	store.cleanupExpired()

	// Store should be empty
	store.mu.Lock()
	count := len(store.data)
	store.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", count)
	}
}
