package httputil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"fastgate/decision-service/internal/config"
	"github.com/rs/zerolog"
)

// Context keys for request metadata
type contextKey int

const (
	requestIDKey contextKey = iota
	loggerKey
	trustedProxiesKey
)

// Buffer pool for JSON encoding hot path optimization
var bufferPool = sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}

// GenerateRequestID creates a new random request ID
func GenerateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return hex.EncodeToString([]byte(strings.Replace(http.TimeFormat, " ", "", -1)))
	}
	return hex.EncodeToString(b)
}

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves request ID from context
func GetRequestID(ctx context.Context) string {
	if reqID, ok := ctx.Value(requestIDKey).(string); ok {
		return reqID
	}
	return ""
}

// WithLogger adds logger to context
func WithLogger(ctx context.Context, logger *zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// GetLogger retrieves logger from context
func GetLogger(ctx context.Context) *zerolog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*zerolog.Logger); ok {
		return logger
	}
	// Return a disabled logger if none found (shouldn't happen)
	nopLogger := zerolog.Nop()
	return &nopLogger
}

// WithTrustedProxies adds trusted proxy CIDRs to context
func WithTrustedProxies(ctx context.Context, trustedProxies []*net.IPNet) context.Context {
	return context.WithValue(ctx, trustedProxiesKey, trustedProxies)
}

// GetTrustedProxies retrieves trusted proxy CIDRs from context
func GetTrustedProxies(ctx context.Context) []*net.IPNet {
	if proxies, ok := ctx.Value(trustedProxiesKey).([]*net.IPNet); ok {
		return proxies
	}
	return nil
}

// RequestIDMiddleware extracts or generates request ID and adds it to context and headers
func RequestIDMiddleware(logger zerolog.Logger, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to get request ID from header (for request tracing across services)
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = GenerateRequestID()
			}

			// Add request ID to response header
			w.Header().Set("X-Request-ID", requestID)

			// Create request-scoped logger with request ID
			reqLogger := logger.With().
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Logger()

			// Add request ID, logger, and trusted proxies to context
			ctx := WithRequestID(r.Context(), requestID)
			ctx = WithLogger(ctx, &reqLogger)
			ctx = WithTrustedProxies(ctx, trustedProxies)

			// Continue with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SanitizeReturnURL prevents open redirect attacks by restricting to same-origin paths.
// Accepts: "/", "/path", "/path?query", but NOT "//host", "http://", "https://".
// SanitizeReturnURL validates and sanitizes redirect URLs to prevent open redirect attacks.
// SECURITY: Enhanced to prevent encoding-based bypasses and protocol-relative URLs.
func SanitizeReturnURL(in string) string {
	if in == "" {
		return "/"
	}

	// SECURITY: Decode URL to prevent bypass via encoding (e.g., %2F%2Fevil.com)
	decoded, err := url.QueryUnescape(in)
	if err != nil {
		// If URL unescape fails, it's likely malformed - reject it
		return "/"
	}

	// Check decoded version for attack patterns
	if strings.Contains(decoded, "://") ||
		strings.HasPrefix(decoded, "//") ||
		strings.HasPrefix(decoded, "http://") ||
		strings.HasPrefix(decoded, "https://") {
		return "/"
	}

	// Parse original (not decoded) to verify well-formed
	u, err := url.ParseRequestURI(in)
	if err != nil {
		return "/"
	}

	// SECURITY: Must be a path-only URL (no host or scheme)
	if u.Host != "" || u.Scheme != "" {
		return "/"
	}

	if !strings.HasPrefix(u.Path, "/") {
		return "/"
	}

	// Keep path + raw query; drop fragments (browsers keep them client-side anyway)
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// ClientIPFromHeaders extracts the client IP from request headers.
// SECURITY: Only trusts X-Forwarded-For if request came from a trusted proxy.
// This prevents attackers from spoofing XFF to bypass IP-based rate limiting.
// Uses trusted proxies from context if available.
func ClientIPFromHeaders(r *http.Request) string {
	trustedProxies := GetTrustedProxies(r.Context())
	return ClientIPFromHeadersWithTrustedProxies(r, trustedProxies)
}

// ClientIPFromHeadersWithTrustedProxies extracts client IP with trusted proxy validation.
// If trustedProxies is nil/empty, falls back to unsafe XFF trust (legacy behavior).
// If trustedProxies is set, only trusts XFF if r.RemoteAddr is in the trusted list.
func ClientIPFromHeadersWithTrustedProxies(r *http.Request, trustedProxies []*net.IPNet) string {
	// Extract the actual remote address (the immediate peer)
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If we can't parse RemoteAddr, fall back to it as-is
		remoteHost = r.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil {
		return ""
	}

	// If no trusted proxies configured, use legacy unsafe behavior (trust XFF blindly)
	// In production, this should always be configured!
	if len(trustedProxies) == 0 {
		// LEGACY UNSAFE PATH: Trust X-Forwarded-For without validation
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				cand := strings.TrimSpace(parts[0])
				if ip := net.ParseIP(cand); ip != nil {
					return ip.String()
				}
			}
		}
		// Fall back to RemoteAddr
		return remoteIP.String()
	}

	// SECURE PATH: Validate that request came from trusted proxy
	isTrusted := false
	for _, ipNet := range trustedProxies {
		if ipNet.Contains(remoteIP) {
			isTrusted = true
			break
		}
	}

	// If request came from trusted proxy, use X-Forwarded-For (left-most IP is real client)
	if isTrusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				cand := strings.TrimSpace(parts[0])
				if ip := net.ParseIP(cand); ip != nil {
					return ip.String()
				}
			}
		}
	}

	// Otherwise, use RemoteAddr directly (don't trust XFF from untrusted sources)
	return remoteIP.String()
}

// WriteJSON writes a JSON response with proper headers and error handling.
// Uses sync.Pool for buffers to reduce hot path allocations.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	// Get buffer from pool
	buf := bufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()

	// Create encoder and encode to buffer
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)

	// Encode to buffer first to handle errors gracefully
	if err := enc.Encode(v); err != nil {
		log.Printf("ERROR: JSON encode failed: %v", err)
		return
	}

	// Write buffered output
	w.Write(buf.Bytes())
}

// BuildCookie creates a cookie with the configured security settings.
func BuildCookie(cfg *config.Config, value string) *http.Cookie {
	c := &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    value,
		Path:     cfg.Cookie.Path,
		MaxAge:   cfg.Cookie.MaxAgeSec,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: cfg.Cookie.HTTPOnly,
	}
	switch strings.ToLower(cfg.Cookie.SameSite) {
	case "none":
		c.SameSite = http.SameSiteNoneMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}
	if cfg.Cookie.Domain != "" {
		c.Domain = cfg.Cookie.Domain
	}
	return c
}
