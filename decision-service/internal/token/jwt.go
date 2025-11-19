package token

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---- Public types ----

type ClearanceClaims struct {
	Tier string `json:"tier"`
	jwt.RegisteredClaims
}

type Keyring struct {
	Alg        string
	Keys       map[string][]byte // kid -> secret
	CurrentKID string
	Issuer     string
	SkewSec    int
	// MaxTTL caps Sign() to a safe window to avoid very long-lived clearances.
	MaxTTL time.Duration
}

// ---- Errors (exported for potential callers/tests) ----

var (
	ErrEmptyToken     = errors.New("empty token")
	ErrMissingKID     = errors.New("missing kid")
	ErrUnknownKID     = errors.New("unknown kid")
	ErrIssuerMismatch = errors.New("issuer mismatch")
	ErrTTLTooLarge    = errors.New("requested TTL exceeds max")
	ErrExpMissing     = errors.New("exp missing")
	ErrNbfInFuture    = errors.New("nbf in the future")
)

// ---- Constructors ----

// NewKeyring loads base64url secrets and prepares a signing/verification keyring.
// alg must be an HMAC algorithm in MVP ("HS256" recommended).
func NewKeyring(alg string, keys map[string]string, current, iss string, skew int) (*Keyring, error) {
	// Guard against "none" or unsupported algs; parser will also enforce.
	switch alg {
	case "HS256", "HS384", "HS512":
	default:
		return nil, errors.New("unsupported alg (expected HS256/384/512)")
	}
	kr := &Keyring{
		Alg:     alg,
		Keys:    make(map[string][]byte, len(keys)),
		Issuer:  iss,
		SkewSec: skew,
		// Reasonable default max TTL for a clearance cookie.
		MaxTTL: 24 * time.Hour,
	}
	for kid, b64 := range keys {
		dec, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
		if len(dec) < 16 {
			return nil, errors.New("signing key too short; need >=16 bytes")
		}
		kr.Keys[kid] = dec
	}
	if _, ok := kr.Keys[current]; !ok {
		return nil, errors.New("current_kid not found in keys")
	}
	kr.CurrentKID = current
	if kr.Issuer == "" {
		kr.Issuer = "fastgate"
	}
	return kr, nil
}

// ---- Operations ----

// Sign mints a clearance token with bounded TTL and the configured issuer.
// If ttl > MaxTTL, it is clamped to MaxTTL.
func (k *Keyring) Sign(tier string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = time.Hour // safe default
	}
	if ttl > k.MaxTTL {
		ttl = k.MaxTTL // clamp instead of error to avoid caller surprises
	}
	now := time.Now()
	claims := ClearanceClaims{
		Tier: tier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    k.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			// NotBefore intentionally unset for smoother rollout; Verify() will honor it if present.
		},
	}
	t := jwt.NewWithClaims(jwt.GetSigningMethod(k.Alg), claims)
	t.Header["kid"] = k.CurrentKID
	secret := k.Keys[k.CurrentKID]
	if len(secret) == 0 {
		return "", errors.New("missing signing key for current_kid")
	}
	return t.SignedString(secret)
}

// Verify checks signature, issuer, time-based claims, and ensures at least
// minLeft duration remains until expiration. It returns (claims, ok, err).
// ok=false, err=nil indicates the token is valid but within the minLeft window.
func (k *Keyring) Verify(tok string, minLeft time.Duration) (*ClearanceClaims, bool, error) {
	if tok == "" {
		return nil, false, ErrEmptyToken
	}
	// SECURITY: Explicitly reject "none" algorithm and enforce strict validation
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{k.Alg}),
		jwt.WithStrictDecoding(), // Reject malformed tokens
	)

	// Additional safety check: ensure algorithm is not "none"
	if k.Alg == "none" || k.Alg == "" {
		return nil, false, errors.New("algorithm 'none' is not allowed for security reasons")
	}
	var claims ClearanceClaims

	// Signature & alg enforcement via parser; select key by kid.
	token, err := parser.ParseWithClaims(tok, &claims, func(t *jwt.Token) (interface{}, error) {
		kidVal, ok := t.Header["kid"]
		if !ok {
			return nil, ErrMissingKID
		}
		kid, _ := kidVal.(string)
		secret, ok := k.Keys[kid]
		if !ok {
			return nil, ErrUnknownKID
		}
		return secret, nil
	})
	if err != nil || !token.Valid {
		return nil, false, err
	}

	// Issuer check (constant-time).
	if subtle.ConstantTimeCompare([]byte(claims.Issuer), []byte(k.Issuer)) != 1 {
		return nil, false, ErrIssuerMismatch
	}

	// Time-based checks.
	now := time.Now()
	skew := time.Duration(k.SkewSec) * time.Second

	// NotBefore (optional)
	if claims.NotBefore != nil && now.Add(skew).Before(claims.NotBefore.Time) {
		return &claims, false, ErrNbfInFuture
	}

	// ExpiresAt (required)
	if claims.ExpiresAt == nil {
		return &claims, false, ErrExpMissing
	}

	// Enforce maximum life window (defense-in-depth).
	if claims.IssuedAt != nil {
		lifetime := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
		if lifetime > k.MaxTTL+skew {
			// Token lifetime exceeds policy — treat as invalid.
			return &claims, false, ErrTTLTooLarge
		}
	}

	// Ensure we have enough time left (minLeft window).
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < minLeft {
		// Valid but near expiry: caller may want to re-issue.
		return &claims, false, nil
	}

	return &claims, true, nil
}
