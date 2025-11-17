package httputil

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// SanitizeReturnURL prevents open redirect attacks by restricting to same-origin paths.
// Accepts: "/", "/path", "/path?query", but NOT "//host", "http://", "https://".
func SanitizeReturnURL(in string) string {
	if in == "" {
		return "/"
	}
	// Quick rejects
	if strings.HasPrefix(in, "//") || strings.HasPrefix(in, "http://") || strings.HasPrefix(in, "https://") {
		return "/"
	}
	u, err := url.ParseRequestURI(in)
	if err != nil {
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
// Prefers the left-most IP in X-Forwarded-For, then falls back to RemoteAddr.
func ClientIPFromHeaders(r *http.Request) string {
	// Prefer the left-most IP in X-Forwarded-For, then fall back to RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			cand := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(cand); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return ""
}

// WriteJSON writes a JSON response with proper headers and error handling.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		log.Printf("ERROR: JSON encode failed: %v", err)
	}
}
