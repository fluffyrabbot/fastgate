package webauthn

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
)

// syntheticCreation encodes a software-only, none-attestation response. It uses
// a public curve point, never a hardware authenticator or persistent credential.
func syntheticCreation(t *testing.T, origin, challenge string) []byte {
	t.Helper()
	encode := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	curve := elliptic.P256().Params()
	key := encode(map[int]any{1: 2, 3: -7, -1: 1, -2: curve.Gx.FillBytes(make([]byte, 32)), -3: curve.Gy.FillBytes(make([]byte, 32))})
	rpHash := sha256.Sum256([]byte("localhost"))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, 0x45, 0, 0, 0, 0) // UP, UV, AT; zero signature counter.
	auth = append(auth, make([]byte, 16)...)
	auth = append(auth, 0, 1, 1) // One-byte credential ID.
	auth = append(auth, key...)
	att := encode(map[string]any{"fmt": "none", "authData": auth, "attStmt": map[string]any{}})
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{"id": b64([]byte{1}), "rawId": b64([]byte{1}), "type": "public-key", "response": map[string]any{"clientDataJSON": b64(client), "attestationObject": b64(att)}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func completionFixture(t *testing.T) (*Handler, string, *webauthn.SessionData) {
	t.Helper()
	h := newTestHandler(t)
	h.RateLimiter = nil // Isolate single-use behavior from independent admission limits.
	h.Store = NewStoreWithCapacity(time.Minute, 100)
	user := &User{ID: []byte("synthetic-user"), Name: "test", DisplayName: "test"}
	_, session, err := h.WebAuthn.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}
	id := h.Store.Put(session, user.ID, "https://untrusted.example/redirect")
	if id == "" {
		t.Fatal("empty challenge ID")
	}
	return h, id, session
}

func finishSynthetic(h *Handler, id string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.FinishRegistration(w, httptest.NewRequest(http.MethodPost, "/v1/challenge/complete/webauthn?challenge_id="+id, bytes.NewReader(body)))
	return w
}

func TestFinishRegistrationConcurrentSingleWinner(t *testing.T) {
	h, id, session := completionFixture(t)
	body := syntheticCreation(t, "http://localhost:8080", session.Challenge)
	const attempts = 32
	var ready, done sync.WaitGroup
	ready.Add(attempts)
	done.Add(attempts)
	results := make(chan *httptest.ResponseRecorder, attempts)
	for i := 0; i < attempts; i++ {
		go func() { defer done.Done(); ready.Done(); ready.Wait(); results <- finishSynthetic(h, id, body) }()
	}
	done.Wait()
	close(results)
	winners := 0
	for w := range results {
		if w.Code == http.StatusFound {
			winners++
			if w.Header().Get("Location") != "/" {
				t.Errorf("unsafe redirect: %q", w.Header().Get("Location"))
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("want one clearance cookie, got %d", len(cookies))
			}
			claims, _, err := h.Keyring.Verify(cookies[0].Value, 0)
			if err != nil {
				t.Fatal(err)
			}
			if claims.Tier != "attested" {
				t.Errorf("unexpected tier: %s", claims.Tier)
			}
			if claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) != 12*time.Hour {
				t.Error("unexpected token TTL")
			}
		} else if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte(`"challenge_not_found"`)) {
			t.Errorf("unexpected loser: %d %s", w.Code, w.Body.String())
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful completions, want 1", winners)
	}
	if w := finishSynthetic(h, id, body); w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte(`"challenge_not_found"`)) {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
}

func TestFinishRegistrationFailureConsumesChallenge(t *testing.T) {
	for _, tc := range []struct{ name, origin, challenge, want string }{
		{"origin", "https://untrusted.example", "", "origin_not_allowed"},
		{"verification", "http://localhost:8080", "wrong-challenge", "attestation_failed"},
		{"expired", "http://localhost:8080", "", "challenge_not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, id, session := completionFixture(t)
			challenge := session.Challenge
			if tc.challenge != "" {
				challenge = tc.challenge
			}
			if tc.name == "expired" {
				h.Store.data[id].Value.(*entry).expiresAt = time.Now().Add(-time.Second)
			}
			body := syntheticCreation(t, tc.origin, challenge)
			w := finishSynthetic(h, id, body)
			if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte(`"`+tc.want+`"`)) {
				t.Fatalf("first attempt: %d %s", w.Code, w.Body.String())
			}
			valid := syntheticCreation(t, "http://localhost:8080", session.Challenge)
			w = finishSynthetic(h, id, valid)
			if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte(`"challenge_not_found"`)) {
				t.Fatalf("retry: %d %s", w.Code, w.Body.String())
			}
			if len(w.Result().Cookies()) != 0 {
				t.Error("failed completion issued cookie")
			}
		})
	}
}

func TestFinishRegistrationRedirectBoundary(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`/\attacker.invalid/path`, "/"},
		{`/%5Cattacker.invalid/path`, "/"},
		{`/%5cattacker.invalid/path`, "/"},
		{`/%2Fattacker.invalid/path`, "/"},
		{`/%zz`, "/"},
		{`/dashboard?tab=1`, `/dashboard?tab=1`},
		{`/safe/%23hash/%3Fquery?x=a%2Bb`, `/safe/%23hash/%3Fquery?x=a%2Bb`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			h, _, session := completionFixture(t)
			id := h.Store.Put(session, []byte("synthetic-user"), tc.in)
			body := syntheticCreation(t, "http://localhost:8080", session.Challenge)
			w := finishSynthetic(h, id, body)
			if w.Code != http.StatusFound || w.Header().Get("Location") != tc.want {
				t.Fatalf("completion: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if replay := finishSynthetic(h, id, body); replay.Code != http.StatusBadRequest || len(replay.Result().Cookies()) != 0 {
				t.Fatalf("replay accepted: %d", replay.Code)
			}
		})
	}
}
