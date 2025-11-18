package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"fastgate/decision-service/internal/authz"
	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/metrics"
)

// Handler is an integrated reverse proxy that performs authorization checks inline
type Handler struct {
	cfg              *config.Config
	authzHandler     *authz.Handler
	proxies          map[string]*httputil.ReverseProxy
	proxiesMu        sync.RWMutex
	challengePageDir string
}

// NewHandler creates a new integrated proxy handler
func NewHandler(cfg *config.Config, authzHandler *authz.Handler, challengePageDir string) (*Handler, error) {
	if !cfg.Proxy.Enabled {
		return nil, fmt.Errorf("proxy mode not enabled in config")
	}

	h := &Handler{
		cfg:              cfg,
		authzHandler:     authzHandler,
		proxies:          make(map[string]*httputil.ReverseProxy),
		challengePageDir: challengePageDir,
	}

	return h, nil
}

// ServeHTTP handles incoming requests with integrated authorization and proxying
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Handle challenge page requests
	if h.isChallengePage(r.URL.Path) {
		h.serveChallengePage(w, r)
		return
	}

	// 2. Match route to get origin
	origin := h.matchRoute(r)
	if origin == "" {
		http.Error(w, "no route matched", http.StatusNotFound)
		return
	}

	// 3. Run authorization check inline
	decision, statusCode, cookies := h.checkAuthorization(r)

	// 4. Propagate any cookies from authz (clearance cookies)
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}

	// 5. Handle decision
	switch decision {
	case "block":
		metrics.AuthzDecision.WithLabelValues("block").Inc()
		http.Error(w, "blocked", statusCode)
		return

	case "challenge":
		metrics.AuthzDecision.WithLabelValues("challenge").Inc()
		// Redirect to challenge page with return URL
		returnURL := r.URL.String()
		challengeURL := fmt.Sprintf("%s?return_url=%s", h.cfg.Proxy.ChallengePath, url.QueryEscape(returnURL))
		http.Redirect(w, r, challengeURL, http.StatusFound)
		return

	case "allow":
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		// Proxy to origin
		h.proxyToOrigin(w, r, origin)
		return

	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

// isChallengePage checks if the request path is for the challenge page
func (h *Handler) isChallengePage(path string) bool {
	challengePath := h.cfg.Proxy.ChallengePath
	return path == challengePath ||
		   path == challengePath+"/" ||
		   strings.HasPrefix(path, challengePath+"/")
}

// matchRoute finds the appropriate origin for the request
func (h *Handler) matchRoute(r *http.Request) string {
	// Simple single-origin mode
	if h.cfg.Proxy.Origin != "" {
		return h.cfg.Proxy.Origin
	}

	// Multi-origin routing
	host := r.Host
	path := r.URL.Path

	// Try to match routes in order
	for _, route := range h.cfg.Proxy.Routes {
		// Host-based routing (exact match)
		if route.Host != "" {
			if host == route.Host {
				return route.Origin
			}
		}

		// Path-based routing (regex match)
		if route.PathRe != nil {
			if route.PathRe.MatchString(path) {
				return route.Origin
			}
		}
	}

	// No match found
	return ""
}

// checkAuthorization runs the authorization logic and returns the decision and any cookies
func (h *Handler) checkAuthorization(r *http.Request) (decision string, statusCode int, cookies []*http.Cookie) {
	// Create a response recorder to capture authz handler output
	recorder := &authzRecorder{
		header: make(http.Header),
	}

	// Prepare headers for authz handler (mimic NGINX auth_request format)
	r.Header.Set("X-Original-Method", r.Method)
	r.Header.Set("X-Original-URI", r.URL.RequestURI())

	// Get client IP from various headers
	clientIP := getClientIP(r)
	if clientIP != "" {
		r.Header.Set("X-Client-IP", clientIP)
	}

	// Check for WebSocket upgrade
	if isWebSocketUpgrade(r) {
		r.Header.Set("X-WS-Upgrade", "websocket")
	}

	// Call authz handler
	h.authzHandler.ServeHTTP(recorder, r)

	// Extract cookies from authz response
	cookies = parseCookies(recorder.header)

	// Map status codes to decisions
	switch recorder.statusCode {
	case http.StatusNoContent: // 204 = ALLOW
		return "allow", http.StatusOK, cookies
	case http.StatusUnauthorized: // 401 = CHALLENGE
		return "challenge", http.StatusUnauthorized, cookies
	case http.StatusForbidden: // 403 = BLOCK
		return "block", http.StatusForbidden, cookies
	default:
		// Fail open or closed based on config
		if h.cfg.Modes.FailOpen {
			return "allow", http.StatusOK, cookies
		}
		return "block", http.StatusForbidden, cookies
	}
}

// proxyToOrigin forwards the request to the upstream origin
func (h *Handler) proxyToOrigin(w http.ResponseWriter, r *http.Request, originURL string) {
	// Get or create reverse proxy for this origin
	proxy := h.getOrCreateProxy(originURL)
	if proxy == nil {
		http.Error(w, "invalid origin", http.StatusInternalServerError)
		return
	}

	// Clean up auth-request headers before proxying
	r.Header.Del("X-Original-Method")
	r.Header.Del("X-Original-URI")
	r.Header.Del("X-Client-IP")
	r.Header.Del("X-WS-Upgrade")

	// Proxy the request
	proxy.ServeHTTP(w, r)
}

// getOrCreateProxy returns a reverse proxy for the given origin URL
func (h *Handler) getOrCreateProxy(originURL string) *httputil.ReverseProxy {
	// Check if we already have a proxy for this origin
	h.proxiesMu.RLock()
	if proxy, ok := h.proxies[originURL]; ok {
		h.proxiesMu.RUnlock()
		return proxy
	}
	h.proxiesMu.RUnlock()

	// Create new proxy
	target, err := url.Parse(originURL)
	if err != nil {
		log.Printf("Failed to parse origin URL %s: %v", originURL, err)
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure proxy transport
	proxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     time.Duration(h.cfg.Proxy.IdleTimeoutMs) * time.Millisecond,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	// Configure director to preserve host header and add X-Forwarded-* headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Set X-Forwarded-* headers
		if clientIP := getClientIP(req); clientIP != "" {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
		req.Header.Set("X-Forwarded-Proto", getScheme(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error for %s: %v", originURL, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	// Cache the proxy
	h.proxiesMu.Lock()
	h.proxies[originURL] = proxy
	h.proxiesMu.Unlock()

	return proxy
}

// serveChallengePage serves the challenge page and its assets
func (h *Handler) serveChallengePage(w http.ResponseWriter, r *http.Request) {
	// Strip challenge path prefix to get the file path
	path := strings.TrimPrefix(r.URL.Path, h.cfg.Proxy.ChallengePath)
	if path == "" || path == "/" {
		path = "/index.html"
	}

	// Serve from challenge page directory
	fs := http.FileServer(http.Dir(h.challengePageDir))

	// Strip the challenge path prefix before serving
	http.StripPrefix(h.cfg.Proxy.ChallengePath, fs).ServeHTTP(w, r)
}

// Helper functions

// authzRecorder captures the response from the authz handler
type authzRecorder struct {
	header     http.Header
	statusCode int
}

func (r *authzRecorder) Header() http.Header {
	return r.header
}

func (r *authzRecorder) Write(b []byte) (int, error) {
	return len(b), nil
}

func (r *authzRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

// getClientIP extracts the client IP from various headers
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// getScheme returns the scheme (http or https) for the request
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

// parseCookies extracts cookies from Set-Cookie headers
func parseCookies(header http.Header) []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookieStr := range header["Set-Cookie"] {
		if parsed := parseCookie(cookieStr); parsed != nil {
			cookies = append(cookies, parsed)
		}
	}
	return cookies
}

// parseCookie parses a single Set-Cookie header value
func parseCookie(setCookie string) *http.Cookie {
	// Use a dummy request to parse the Set-Cookie header
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{setCookie},
		},
	}
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		return cookies[0]
	}
	return nil
}
