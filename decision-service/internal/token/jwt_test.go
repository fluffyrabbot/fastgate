package token

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func mockKeyring(t *testing.T) *Keyring {
	alg := "HS256"
	currentKID := "testkid"
	keys := map[string]string{
		currentKID: base64.RawURLEncoding.EncodeToString([]byte("supersecretkeythatisatleast16byteslong")),
	}
	issuer := "fastgate-test"
	skew := 0
	kr, err := NewKeyring(alg, keys, currentKID, issuer, skew)
	if err != nil {
		t.Fatalf("NewKeyring failed: %v", err)
	}
	return kr
}

func TestKeyring_SignAndVerify(t *testing.T) {
	kr := mockKeyring(t)

	// Test: Sign a token
	scope := "user_123"
	duration := time.Minute
	tokenStr, err := kr.Sign(scope, duration)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("Sign returned empty token")
	}

	// Test: Verify the valid token
	claims, ok, _ := kr.Verify(tokenStr, 0)
	if !ok {
		t.Fatal("Verify failed for valid token")
	}
	if claims.Tier != scope {
		t.Errorf("expected claims.Tier %q, got %q", scope, claims.Tier)
	}
}

func TestKeyring_Expiration(t *testing.T) {
	kr := mockKeyring(t)

	// Sign a token that expires instantly (1 nanosecond)
	tokenStr, _ := kr.Sign("expired", 1*time.Nanosecond)
	
	// Sleep just a bit to ensure expiry
	time.Sleep(2 * time.Nanosecond)

	_, ok, _ := kr.Verify(tokenStr, 0)
	if ok {
		t.Error("Verify passed for expired token")
	}
}

func TestKeyring_MinLeft(t *testing.T) {
	kr := mockKeyring(t)

	// Sign a token valid for 1 minute
	tokenStr, _ := kr.Sign("almost_expired", time.Minute)

	// Verify requiring 2 minutes remaining
	_, ok, _ := kr.Verify(tokenStr, 2*time.Minute)
	if ok {
		t.Error("Verify passed despite insufficient time remaining")
	}

	// Verify requiring 30 seconds remaining (should pass)
	_, ok, _ = kr.Verify(tokenStr, 30*time.Second)
	if !ok {
		t.Error("Verify failed for valid token with sufficient time")
	}
}

func TestKeyring_TamperedToken(t *testing.T) {
	kr := mockKeyring(t)

	tokenStr, _ := kr.Sign("test", time.Minute)
	
	// Tamper with the payload (middle part of JWT)
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatal("Invalid JWT format")
	}
	
	// Change one character in the payload
	tamperedPayload := parts[1]
	if tamperedPayload[0] == 'a' {
		tamperedPayload = "b" + tamperedPayload[1:]
	} else {
		tamperedPayload = "a" + tamperedPayload[1:]
	}
	
	tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

	_, ok, _ := kr.Verify(tamperedToken, 0)
	if ok {
		t.Error("Verify passed for tampered token")
	}
}
