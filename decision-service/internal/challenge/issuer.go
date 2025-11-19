package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// StatelessIssuer manages the lifecycle of crypto-signed challenges.
type StatelessIssuer struct {
	secret []byte
}

type ChallengeClaims struct {
	Nonce string `json:"n"`
	Bits  int    `json:"d"`
	IP    string `json:"ip,omitempty"`
	jwt.RegisteredClaims
}

// NewIssuer creates a new stateless issuer using the provided secret (HS256).
// The secret should be shared across the cluster.
func NewIssuer(secret string) (*StatelessIssuer, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 32 {
		return nil, errors.New("secret must be at least 32 bytes")
	}
	return &StatelessIssuer{secret: decoded}, nil
}

// Issue mints a signed challenge token (JWS).
// Returns (token_string, nonce_string, error).
func (i *StatelessIssuer) Issue(bits int, ttl time.Duration, clientIP string) (string, string, error) {
	if bits < 12 || bits > 26 {
		bits = 16
	}
	
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	
	now := time.Now()
	claims := ChallengeClaims{
		Nonce: nonce,
		Bits:  bits,
		IP:    clientIP,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.secret)
	if err != nil {
		return "", "", err
	}

	return signed, nonce, nil
}

// Verify checks the JWS signature, expiry, IP binding (if provided), and PoW solution.
// Returns (ok, reason, error).
func (i *StatelessIssuer) Verify(tokenStr string, solution uint32, clientIP string) (bool, string, error) {
	// 1. Parse & Verify Signature
	token, err := jwt.ParseWithClaims(tokenStr, &ChallengeClaims{}, func(token *jwt.Token) (interface{}, error) {
		return i.secret, nil
	})

	if err != nil || !token.Valid {
		return false, "invalid_token", nil
	}

	claims, ok := token.Claims.(*ChallengeClaims)
	if !ok {
		return false, "invalid_claims", nil
	}

	// 2. Verify IP Binding (if enforced)
	if claims.IP != "" && claims.IP != clientIP {
		return false, "ip_mismatch", nil
	}

	// 3. Verify PoW
	nonceBytes, err := base64.RawURLEncoding.DecodeString(claims.Nonce)
	if err != nil {
		return false, "invalid_nonce", nil
	}

	if validateSolution(nonceBytes, claims.Bits, solution) {
		return true, "ok", nil
	}

	return false, "invalid_solution", nil
}

// Helper (reused from old store)
func validateSolution(nonce []byte, bits int, solution uint32) bool {
	data := make([]byte, len(nonce)+4)
	copy(data, nonce)
	data[len(nonce)] = byte(solution >> 24)
	data[len(nonce)+1] = byte(solution >> 16)
	data[len(nonce)+2] = byte(solution >> 8)
	data[len(nonce)+3] = byte(solution)
	h := sha256.Sum256(data)
	return LeadingZeroBits(h[:]) >= bits
}

// LeadingZeroBits returns the count of leading zero bits in b.
func LeadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		for i := 7; i >= 0; i-- {
			if (by>>uint(i))&1 == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}
