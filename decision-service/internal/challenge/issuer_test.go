package challenge

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestIssuer_IssueAndVerify(t *testing.T) {
	// 32-byte secret, base64url-encoded
	secret := "YV8zMl9ieXRlX3NlY3JldF9mb3JfdGVzdGluZ18xMjM" // "a_32_byte_secret_for_testing_123"
	issuer, err := NewIssuer(secret)
	if err != nil {
		t.Fatalf("NewIssuer failed: %v", err)
	}

	// Issue
	bits := 12
	ttl := time.Minute
	ip := "1.2.3.4"
	
	token, nonceB64, err := issuer.Issue(bits, ttl, ip)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}
	if token == "" || nonceB64 == "" {
		t.Error("Issue returned empty token or nonce")
	}

	// Solve
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceB64)
	var solution uint32
	found := false
	for i := uint32(0); i < 1000000; i++ {
		if validateSolution(nonce, bits, i) {
			solution = i
			found = true
			break
		}
	}
	if !found {
		t.Fatal("could not find solution")
	}

	// Verify Valid
	ok, reason, err := issuer.Verify(token, solution, ip)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !ok {
		t.Errorf("Verify failed: %s", reason)
	}

	// Verify Invalid IP
	ok, reason, _ = issuer.Verify(token, solution, "5.6.7.8")
	if ok {
		t.Error("Verify passed with wrong IP")
	}
	if reason != "ip_mismatch" {
		t.Errorf("expected ip_mismatch, got %s", reason)
	}

	// Verify Invalid Solution
	ok, reason, _ = issuer.Verify(token, solution+1, ip)
	if ok {
		t.Error("Verify passed with wrong solution")
	}
	if reason != "invalid_solution" {
		t.Errorf("expected invalid_solution, got %s", reason)
	}
}

func TestIssuer_Expired(t *testing.T) {
	secret := "YV8zMl9ieXRlX3NlY3JldF9mb3JfdGVzdGluZ18xMjM"
	issuer, err := NewIssuer(secret)
	if err != nil {
		t.Fatalf("NewIssuer failed: %v", err)
	}

	// Issue with negative TTL (already expired)
	token, nonceB64, _ := issuer.Issue(12, -1*time.Minute, "1.2.3.4")
	
	// Solve (we need a valid solution to pass the nonce check, though expiration is checked by JWT parser usually)
	// Actually, jwt.ParseWithClaims checks exp first.
	
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceB64)
	var solution uint32
	for i := uint32(0); i < 100000; i++ {
		if validateSolution(nonce, 12, i) {
			solution = i
			break
		}
	}

	ok, reason, _ := issuer.Verify(token, solution, "1.2.3.4")
	if ok {
		t.Error("Verify passed for expired token")
	}
	if reason != "invalid_token" { // JWT validation fails -> invalid_token
		t.Errorf("expected invalid_token, got %s", reason)
	}
}
